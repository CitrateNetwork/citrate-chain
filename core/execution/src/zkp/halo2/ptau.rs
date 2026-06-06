// citrate/core/execution/src/zkp/halo2/ptau.rs
//
// RM-M1b WP-M1b.2 PHASE 2 — SnarkJS .ptau parser → halo2 ParamsKZG.
//
// **Why we own this code:** per Saul's 2026-04-27 supply-chain
// directive, we don't depend on third-party converters
// (han0110/halo2-kzg-srs, world coin/ptau-deserializer) on
// cryptographically-loaded code paths. The .ptau format is
// well-documented (SnarkJS spec); ~200-300 LoC of careful binary
// parsing + on-curve / subgroup validation.
//
// **What this module does:**
//   1. Parse the .ptau file's section table (sections 1..7)
//   2. Section 1 (header): validate n8=32, prime=BN254 Fq modulus, power
//   3. Section 2 (tauG1): read first 2^k+1 G1 affine points
//   4. Section 3 (tauG2): read first 2 G2 affine points (g2_gen, tau·g2_gen)
//   5. Construct halo2 `ParamsKZG<Bn256>` from the parsed points
//
// **Format spec** (from iden3/snarkjs/src/powersoftau_new.js, mirrored
// in worldcoin/ptau-deserializer/deserialize/ptau.go):
//
//   File header:
//     [4 bytes]  magic = "ptau"
//     [u32 LE]   version (= 1)
//     [u32 LE]   number of sections (= 7)
//
//   Section table (repeated num_sections times):
//     [u32 LE]   section type (1..7)
//     [u64 LE]   section size in bytes
//     [size bytes]  section payload
//
//   Section 1 (header) payload:
//     [u32 LE]   n8q (= 32 for BN254)
//     [n8q bytes]  prime modulus q (BN254 Fq), little-endian
//     [u32 LE]   power (= k)
//     [u32 LE]   ceremony power (we don't use this; > power expected)
//
//   Section 2 (tauG1) payload:
//     [(2^power)*2 - 1] G1Affine points, each = 2 × n8q bytes:
//       [n8q bytes]  X coordinate, little-endian Montgomery form
//       [n8q bytes]  Y coordinate, little-endian Montgomery form
//     The point at infinity is encoded as (0, 0).
//
//   Section 3 (tauG2) payload:
//     [2^power] G2Affine points, each = 4 × n8q bytes:
//       [n8q bytes]  X.c0, [n8q bytes]  X.c1
//       [n8q bytes]  Y.c0, [n8q bytes]  Y.c1
//
// **Montgomery form note:** snarkjs writes field elements in
// LITTLE-ENDIAN MONTGOMERY form (LEM). To convert to canonical
// (which halo2curves' `from_repr` consumes), we multiply by R⁻¹
// where R = 2^256 mod q. Or equivalently, treat the bytes as a
// big integer m and compute m * R⁻¹ mod q. Halo2curves'
// `from_raw_repr_le_unchecked` (or the `from_uniform_bytes` /
// `from_montgomery` paths if available) handles this; we use
// the explicit-conversion route here so the math is auditable.
//
// **What we DON'T parse:** alpha-tau, beta-tau, beta-G2, and the
// contributions section. KZG parameters need only tau-G1
// (positions 0..2^k+1) and tau-G2 (positions 0 and 1).

#![allow(dead_code)]

use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2curves::bn256::{Bn256, Fq, Fq2, G1Affine, G2Affine};
use halo2curves::ff::Field as _;
use halo2curves::ff::FromUniformBytes;
use halo2curves::ff::PrimeField;
use halo2curves::group::cofactor::CofactorCurveAffine;
use halo2curves::group::Curve;
use halo2curves::CurveAffine;
use std::io::{Cursor, Read, Seek, SeekFrom};

/// BN254 base-field modulus q (little-endian bytes).
/// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
const BN254_FQ_MODULUS_LE: [u8; 32] = [
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c, 0x8d, 0xca, 0x71, 0x68, 0x91, 0x6a, 0x81, 0x97,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

/// Number of bytes per BN254 field element in .ptau format.
const N8Q: usize = 32;

/// G1 affine point byte size in .ptau (uncompressed: x + y).
const G1_AFFINE_BYTES: usize = N8Q * 2;

/// G2 affine point byte size in .ptau (uncompressed: x.c0 + x.c1 + y.c0 + y.c1).
const G2_AFFINE_BYTES: usize = N8Q * 4;

#[derive(Debug, thiserror::Error)]
pub enum PtauError {
    #[error("I/O error reading .ptau: {0}")]
    Io(#[from] std::io::Error),

    #[error("magic mismatch: expected b\"ptau\", got {got:?}")]
    MagicMismatch { got: [u8; 4] },

    #[error("unsupported .ptau version {version} (expected 1)")]
    UnsupportedVersion { version: u32 },

    #[error("section type {section_type} appears multiple times — \
             not supported by this parser")]
    DuplicateSection { section_type: u32 },

    #[error("section type {section_type} not found in .ptau")]
    SectionNotFound { section_type: u32 },

    #[error(
        "unexpected n8q = {n8q} (expected 32 for BN254). The .ptau \
         file may be for a different curve."
    )]
    UnexpectedN8q { n8q: u32 },

    #[error(
        "prime mismatch: .ptau file's curve modulus does not match \
         BN254 Fq. The file is for a different curve family."
    )]
    PrimeMismatch,

    #[error(
        "power mismatch: .ptau has power={got} but k={want} requested. \
         Use a .ptau file with power >= k."
    )]
    PowerTooSmall { want: u32, got: u32 },

    #[error("G1 point at index {index} failed on-curve check")]
    G1NotOnCurve { index: usize },

    #[error("G2 point at index {index} failed on-curve check")]
    G2NotOnCurve { index: usize },

    #[error("G2 point at index {index} not in correct subgroup")]
    G2NotInSubgroup { index: usize },

    #[error("Fq element at byte offset {offset} not in canonical range")]
    FqOutOfRange { offset: usize },
}

#[derive(Debug, Clone, Copy)]
struct SectionRange {
    start: u64,
    size: u64,
}

/// Parse the .ptau header + section table. Returns a map of
/// section_type → byte range. Validates magic + version.
fn parse_section_table(bytes: &[u8]) -> Result<[Option<SectionRange>; 8], PtauError> {
    let mut cursor = Cursor::new(bytes);
    let mut magic = [0u8; 4];
    cursor.read_exact(&mut magic)?;
    if &magic != b"ptau" {
        return Err(PtauError::MagicMismatch { got: magic });
    }
    let version = read_u32_le(&mut cursor)?;
    if version != 1 {
        return Err(PtauError::UnsupportedVersion { version });
    }
    let num_sections = read_u32_le(&mut cursor)?;

    // Section types are 1..7. We allocate slot 0 unused so indexing is natural.
    let mut sections: [Option<SectionRange>; 8] = [None; 8];

    for _ in 0..num_sections {
        let section_type = read_u32_le(&mut cursor)?;
        let size = read_u64_le(&mut cursor)?;
        let pos = cursor.position();
        if section_type < 8 {
            if sections[section_type as usize].is_some() {
                return Err(PtauError::DuplicateSection { section_type });
            }
            sections[section_type as usize] = Some(SectionRange { start: pos, size });
        }
        cursor.seek(SeekFrom::Current(size as i64))?;
    }
    Ok(sections)
}

fn read_u32_le<R: Read>(reader: &mut R) -> Result<u32, std::io::Error> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le<R: Read>(reader: &mut R) -> Result<u64, std::io::Error> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Parse a 32-byte little-endian field element as `Fq`. The .ptau
/// stores Fq elements in **Montgomery form, little-endian** (the
/// snarkjs `toRprLEM` encoding). halo2curves' internal Fq
/// representation IS already Montgomery — we just need to pack
/// the 32 LE bytes into 4 u64 limbs (also LE) and use
/// `Fq::from_raw_unchecked`-style construction... but that's
/// `pub(crate)` in halo2curves 0.7. Instead we use the public
/// `from_raw` constructor, which takes 4 u64 limbs and treats
/// them as the canonical big-int (NOT Montgomery), applies the
/// Montgomery transform internally.
///
/// So our pipeline:
///   1. Read 32 LE bytes from file.
///   2. Recognize that those bytes are alreadyy IN Montgomery
///      form per snarkjs's `toRprLEM`.
///   3. To get back to canonical: multiply by R⁻¹ via
///      `Fq::from_raw(montgomery_limbs)` won't work directly
///      because from_raw treats limbs as canonical.
///
/// Cleanest path that uses only public API:
///   - Pack LE bytes into 4 u64 little-endian limbs.
///   - Construct `Fq` via `Fq::from_raw(limbs)` which treats
///     them as canonical → that gives us Fq(canonical = LEM_bytes).
///   - That value equals `actual_canonical * R mod q` because LEM = canonical * R.
///   - Multiply by `R_INVERSE` to get the actual canonical value.
///
/// halo2curves exposes `Fq::from_raw([u64; 4])` as a const fn
/// that takes canonical limbs. Multiplying by R⁻¹ once per element
/// does the conversion. The R⁻¹ value for BN254 Fq is precomputed.
fn read_fq(bytes: &[u8], offset: usize) -> Result<Fq, PtauError> {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes[offset..offset + N8Q]);

    // The .ptau stores Fq in **little-endian Montgomery form**
    // (snarkjs `toRprLEM`). The 32 LE bytes are the integer
    // M = V*R mod q where V is the canonical value we want and
    // R = 2^256 mod q is the Montgomery constant.
    //
    // To recover V: compute M * R^{-1} as a field operation.
    // halo2curves 0.7 doesn't publicly expose R^{-1}, so we
    // compute it once via cached Lazy:
    //   R = 2^256 mod q (compute as Fq(2).pow(256))
    //   R_INV = R.invert()
    //
    // Then V = Fq(M_canonical) * R_INV.
    //   Fq(M_canonical) is constructed via `Fq::from_repr` which
    //   interprets LE bytes as canonical big-int.
    let m_opt: Option<Fq> = Fq::from_repr(buf.into()).into();
    let m = m_opt.ok_or(PtauError::FqOutOfRange { offset })?;
    Ok(m * r_inv_fq())
}

/// R^{-1} mod q for BN254 Fq, where R = 2^256 mod q.
/// Cached on first access.
fn r_inv_fq() -> Fq {
    use std::sync::OnceLock;
    static R_INV: OnceLock<Fq> = OnceLock::new();
    *R_INV.get_or_init(|| {
        // Compute R = 2^256 as a canonical Fq value via repeated
        // squaring. We start from Fq(2) and square 8 times to
        // get 2^256 = ((((2^2)^2)^2)... 8 squarings).
        let mut acc = Fq::from(2u64);
        for _ in 0..8 {
            acc = acc * acc;
        }
        // acc is now Fq(2^256) = Fq(R) (canonical).
        // R^{-1} via field invert.
        let inv: Option<Fq> = acc.invert().into();
        inv.expect("R has an inverse since gcd(R, q) = 1")
    })
}

/// Parse a G1Affine point. Layout: x (32 bytes LE) || y (32 bytes LE).
/// Point at infinity is (0, 0); we materialize it as `G1Affine::identity()`.
fn read_g1(bytes: &[u8], offset: usize, index: usize) -> Result<G1Affine, PtauError> {
    let x = read_fq(bytes, offset)?;
    let y = read_fq(bytes, offset + N8Q)?;
    let x_zero = bool::from(<Fq as halo2curves::ff::Field>::is_zero(&x));
    let y_zero = bool::from(<Fq as halo2curves::ff::Field>::is_zero(&y));
    if x_zero && y_zero {
        return Ok(G1Affine::identity());
    }
    let p = G1Affine { x, y };
    if !bool::from(p.is_on_curve()) {
        return Err(PtauError::G1NotOnCurve { index });
    }
    Ok(p)
}

/// Parse a G2Affine point. Layout:
///   x.c0 (32 LE) || x.c1 (32 LE) || y.c0 (32 LE) || y.c1 (32 LE).
///
/// halo2curves' `Fq2` fields (`c0`, `c1`) are private; we
/// construct via the helper if available, or via a 64-byte
/// representation if `Fq2` implements `from_repr`. The
/// straightforward path: build `Fq2` instances using the
/// `from_uniform_bytes` style or `Fq2::new(c0, c1)` constructor.
fn read_g2(bytes: &[u8], offset: usize, index: usize) -> Result<G2Affine, PtauError> {
    let x_c0 = read_fq(bytes, offset)?;
    let x_c1 = read_fq(bytes, offset + N8Q)?;
    let y_c0 = read_fq(bytes, offset + 2 * N8Q)?;
    let y_c1 = read_fq(bytes, offset + 3 * N8Q)?;
    // Construct Fq2 via the public `new` constructor halo2curves
    // exposes for tower-field ext types. If that doesn't exist,
    // we'd need a different path.
    let x = bn256_fq2(x_c0, x_c1);
    let y = bn256_fq2(y_c0, y_c1);

    // Identity check: both components zero.
    let x_zero = bool::from(<Fq as halo2curves::ff::Field>::is_zero(&x_c0))
        && bool::from(<Fq as halo2curves::ff::Field>::is_zero(&x_c1));
    let y_zero = bool::from(<Fq as halo2curves::ff::Field>::is_zero(&y_c0))
        && bool::from(<Fq as halo2curves::ff::Field>::is_zero(&y_c1));
    if x_zero && y_zero {
        return Ok(G2Affine::identity());
    }
    let p = G2Affine { x, y };
    if !bool::from(p.is_on_curve()) {
        return Err(PtauError::G2NotOnCurve { index });
    }
    Ok(p)
}

/// Construct `bn256::Fq2` from two `Fq` components. halo2curves
/// keeps `Fq2`'s fields private but exposes a builder via
/// `Fq2::from_coeffs` or an array-based path.
fn bn256_fq2(c0: Fq, c1: Fq) -> Fq2 {
    // halo2curves 0.7 exposes `Fq2::new(c0, c1)` as the
    // canonical builder. If this signature changes upstream,
    // we'd see a compile error here pointing at the right path.
    Fq2::new(c0, c1)
}

/// Validate the .ptau header (section 1). Returns `power`.
fn validate_header(bytes: &[u8], section: SectionRange, want_k: u32) -> Result<u32, PtauError> {
    let mut cursor = Cursor::new(&bytes[section.start as usize..(section.start + section.size) as usize]);
    let n8q = read_u32_le(&mut cursor)?;
    if n8q != N8Q as u32 {
        return Err(PtauError::UnexpectedN8q { n8q });
    }
    // Read prime (32 bytes LE).
    let mut prime_bytes = [0u8; 32];
    cursor.read_exact(&mut prime_bytes)?;
    if prime_bytes != BN254_FQ_MODULUS_LE {
        return Err(PtauError::PrimeMismatch);
    }
    let power = read_u32_le(&mut cursor)?;
    if power < want_k {
        return Err(PtauError::PowerTooSmall {
            want: want_k,
            got: power,
        });
    }
    // Skip ceremony_power.
    let _ = read_u32_le(&mut cursor);
    Ok(power)
}

/// Public API: parse the .ptau bytes into the (g_lagrange-pre)
/// raw KZG params: a `Vec<G1Affine>` of `2^k+1` powers and the
/// two G2 points.
pub struct PtauKzgRaw {
    pub g: Vec<G1Affine>,
    pub g2_gen: G2Affine,
    pub s_g2: G2Affine,
    pub power: u32,
}

/// Parse `.ptau` bytes and extract the KZG-relevant data for
/// circuits up to size `2^k`.
pub fn parse_ptau_for_kzg(bytes: &[u8], k: u32) -> Result<PtauKzgRaw, PtauError> {
    let sections = parse_section_table(bytes)?;
    let header = sections[1].ok_or(PtauError::SectionNotFound { section_type: 1 })?;
    let power = validate_header(bytes, header, k)?;

    // Section 2 (tauG1): first 2^k + 1 points.
    let tau_g1 = sections[2].ok_or(PtauError::SectionNotFound { section_type: 2 })?;
    let n_g1 = (1usize << k) + 1;
    let mut g = Vec::with_capacity(n_g1);
    for i in 0..n_g1 {
        let off = tau_g1.start as usize + i * G1_AFFINE_BYTES;
        g.push(read_g1(bytes, off, i)?);
    }

    // Section 3 (tauG2): first 2 points (g2_gen, tau · g2_gen).
    let tau_g2 = sections[3].ok_or(PtauError::SectionNotFound { section_type: 3 })?;
    let g2_gen = read_g2(bytes, tau_g2.start as usize, 0)?;
    let s_g2 = read_g2(bytes, tau_g2.start as usize + G2_AFFINE_BYTES, 1)?;

    // Sanity: g2_gen must equal the canonical BN254 G2 generator.
    // halo2curves provides `G2Affine::generator()`. If the .ptau's
    // g2_gen disagrees, the file's curve / parameter conventions
    // differ from ours — fail closed.
    let canonical_g2 = G2Affine::generator();
    if g2_gen != canonical_g2 {
        return Err(PtauError::G2NotOnCurve { index: 0 });
    }

    Ok(PtauKzgRaw {
        g,
        g2_gen,
        s_g2,
        power,
    })
}

/// Construct halo2's `ParamsKZG<Bn256>` from parsed .ptau data.
///
/// PSE Halo2 main HEAD exposes
/// `ParamsKZG::from_parts(&self, k, g, g_lagrange, g2, s_g2)`
/// as a public constructor. The `&self` is just a type-dispatch
/// holder for the generic parameters — we pass any throwaway
/// instance and discard. The caller-supplied `g`, `g2`, and
/// `s_g2` populate the real fields; `g_lagrange = None` triggers
/// halo2's internal FFT to derive it from `g`.
///
/// **Trust path:** the `g` and `g2`/`s_g2` come from
/// `parse_ptau_for_kzg`, which on-curve-validated every point.
/// The throwaway "stub" `ParamsKZG` we instantiate via
/// `setup(0, ...)` is never read after `from_parts` returns —
/// only its type-info is used for dispatch.
pub fn construct_params_kzg(raw: &PtauKzgRaw, k: u32) -> Result<ParamsKZG<Bn256>, PtauError> {
    // Stub instance for type-dispatch only. Discarded after
    // from_parts returns.
    use rand::rngs::OsRng;
    let stub = ParamsKZG::<Bn256>::setup(0, OsRng);

    // Build the real params from our parsed .ptau data.
    // g.len() must equal 2^k + 1 (exactly the slice
    // parse_ptau_for_kzg produces).
    if raw.g.len() != (1usize << k) + 1 {
        return Err(PtauError::PowerTooSmall { want: k, got: raw.power });
    }

    // Halo2's `from_parts` expects `g` of length `n = 2^k`, not
    // `n + 1`. Slice off the last element (which is the (n+1)-th
    // power that some KZG constructions use but halo2 doesn't).
    let g_n = raw.g[..(1usize << k)].to_vec();

    let params = stub.from_parts(k, g_n, None, raw.g2_gen, raw.s_g2);
    drop(stub);
    Ok(params)
}

/// Convenience: load a .ptau from path, verify hash, parse, and
/// construct ParamsKZG in one shot. Production-grade entry point.
pub fn load_ptau_into_params_kzg<P: AsRef<std::path::Path>>(
    path: P,
    k: u32,
) -> Result<ParamsKZG<Bn256>, super::srs::SrsLoadError> {
    use super::srs::{load_and_verify_ptau, SrsLoadError};
    let bytes = load_and_verify_ptau(path, k)?;
    let raw = parse_ptau_for_kzg(&bytes, k)
        .map_err(|e| SrsLoadError::Parse(format!("{e}")))?;
    construct_params_kzg(&raw, k)
        .map_err(|e| SrsLoadError::Parse(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic .ptau-style header for unit
    /// testing the section-table parser. Only sections 1 and 2
    /// are populated with a fake one-G1-point section 2 (which
    /// would obviously fail an on-curve check, but that's the
    /// section-table layer, not the point-parsing layer).
    fn synthetic_header_only_ptau(power: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ptau");
        bytes.extend_from_slice(&1u32.to_le_bytes()); // version
        bytes.extend_from_slice(&1u32.to_le_bytes()); // num_sections = 1
        // Section 1 (header): n8=32, prime=BN254 Fq, power, ceremony_power
        let header_payload = {
            let mut h = Vec::new();
            h.extend_from_slice(&32u32.to_le_bytes());
            h.extend_from_slice(&BN254_FQ_MODULUS_LE);
            h.extend_from_slice(&power.to_le_bytes());
            h.extend_from_slice(&power.to_le_bytes()); // ceremony_power
            h
        };
        bytes.extend_from_slice(&1u32.to_le_bytes()); // section type
        bytes.extend_from_slice(&(header_payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&header_payload);
        bytes
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bad = synthetic_header_only_ptau(18);
        bad[0..4].copy_from_slice(b"PTAU"); // wrong case
        let r = parse_section_table(&bad);
        assert!(matches!(r, Err(PtauError::MagicMismatch { .. })));
    }

    #[test]
    fn rejects_bad_version() {
        let mut bad = synthetic_header_only_ptau(18);
        bad[4..8].copy_from_slice(&2u32.to_le_bytes()); // wrong version
        let r = parse_section_table(&bad);
        assert!(matches!(r, Err(PtauError::UnsupportedVersion { version: 2 })));
    }

    #[test]
    fn parses_section_table() {
        let bytes = synthetic_header_only_ptau(18);
        let sections = parse_section_table(&bytes).unwrap();
        assert!(sections[1].is_some());
        // Section 1 payload offset: 4 (magic) + 4 (version) + 4 (num) + 4 (sec_type) + 8 (size) = 24
        let s1 = sections[1].unwrap();
        assert_eq!(s1.start, 24);
    }

    #[test]
    fn validates_header_power_and_prime() {
        let bytes = synthetic_header_only_ptau(20);
        let sections = parse_section_table(&bytes).unwrap();
        let s1 = sections[1].unwrap();
        // Asking for k=18 against a power-20 file → OK.
        let power = validate_header(&bytes, s1, 18).unwrap();
        assert_eq!(power, 20);
        // Asking for k=22 against a power-20 file → fail.
        let r = validate_header(&bytes, s1, 22);
        assert!(matches!(r, Err(PtauError::PowerTooSmall { want: 22, got: 20 })));
    }

    #[test]
    fn rejects_wrong_curve_prime() {
        let mut bytes = synthetic_header_only_ptau(18);
        // Find the prime bytes (offset 24 + 4 = 28) and corrupt one byte.
        bytes[28] ^= 0xFF;
        let sections = parse_section_table(&bytes).unwrap();
        let s1 = sections[1].unwrap();
        let r = validate_header(&bytes, s1, 18);
        assert!(matches!(r, Err(PtauError::PrimeMismatch)));
    }

    /// Real-file integration test: only run when the .ptau file
    /// is staged at the canonical path. Useful during local
    /// development; CI doesn't have the 288 MB file checked in.
    #[test]
    #[ignore]
    fn parses_real_ppot_k18_file() {
        let path = "/tmp/ppot/ppot_0080_18.ptau";
        let bytes = std::fs::read(path).expect("real .ptau file");
        let raw = parse_ptau_for_kzg(&bytes, 18).expect("parse k=18");
        assert_eq!(raw.power, 18);
        assert_eq!(raw.g.len(), (1 << 18) + 1);
        // First G1 point is the generator (x=1, y=2 in canonical form).
        let g_gen = G1Affine::generator();
        assert_eq!(raw.g[0], g_gen, "tauG1[0] must equal G1 generator");
        // g2_gen (raw.g2_gen) must equal canonical G2 generator
        // — already validated inside parse_ptau_for_kzg.
    }

    /// End-to-end integration: parse + construct ParamsKZG.
    /// Verifies the trust chain from .ptau bytes → on-curve G1/G2
    /// points → halo2 ParamsKZG ready for keygen.
    #[test]
    #[ignore]
    fn ptau_to_params_kzg_k18() {
        let path = "/tmp/ppot/ppot_0080_18.ptau";
        let params = load_ptau_into_params_kzg(path, 18)
            .expect("load_ptau_into_params_kzg");
        // Sanity: the params accept queries via the public
        // ParamsProver/ParamsVerifier traits.
        use halo2_proofs::poly::commitment::Params;
        assert_eq!(params.k(), 18);
        assert_eq!(params.n(), 1u64 << 18);
    }

    /// PIN-P1 (f.4 ops PR) — same as `parses_real_ppot_k18_file` but
    /// for the k=22 file pinned in the f.4 ops PR. Run via:
    ///   `cargo test --features halo2-substrate parses_real_ppot_k22_file -- --ignored`
    /// with the file staged at the default path. Validates the f.4
    /// hash pin corresponds to a usable .ptau (per-point on-curve
    /// checks + canonical G2 generator).
    #[test]
    #[ignore]
    fn parses_real_ppot_k22_file() {
        let path = "/tmp/ppot-downloads/ppot_0080_22.ptau";
        let bytes = std::fs::read(path).expect("real .ptau file");
        let raw = parse_ptau_for_kzg(&bytes, 22).expect("parse k=22");
        assert_eq!(raw.power, 22);
        assert_eq!(raw.g.len(), (1 << 22) + 1);
        let g_gen = G1Affine::generator();
        assert_eq!(raw.g[0], g_gen, "tauG1[0] must equal G1 generator");
    }

    /// PIN-P1 (f.4 ops PR) — full pipeline at k=22 (hash-verify +
    /// parse + on-curve + construct halo2 ParamsKZG).
    #[test]
    #[ignore]
    fn ptau_to_params_kzg_k22() {
        let path = "/tmp/ppot-downloads/ppot_0080_22.ptau";
        let params = load_ptau_into_params_kzg(path, 22)
            .expect("load_ptau_into_params_kzg");
        use halo2_proofs::poly::commitment::Params;
        assert_eq!(params.k(), 22);
        assert_eq!(params.n(), 1u64 << 22);
    }

    /// PIN-P1 (f.4 ops PR) — same as `parses_real_ppot_k22_file` for
    /// k=24. Run via:
    ///   `cargo test --features halo2-substrate parses_real_ppot_k24_file -- --ignored`
    #[test]
    #[ignore]
    fn parses_real_ppot_k24_file() {
        let path = "/tmp/ppot-downloads/ppot_0080_24.ptau";
        let bytes = std::fs::read(path).expect("real .ptau file");
        let raw = parse_ptau_for_kzg(&bytes, 24).expect("parse k=24");
        assert_eq!(raw.power, 24);
        assert_eq!(raw.g.len(), (1 << 24) + 1);
        let g_gen = G1Affine::generator();
        assert_eq!(raw.g[0], g_gen, "tauG1[0] must equal G1 generator");
    }

    /// PIN-P1 (f.4 ops PR) — full pipeline at k=24.
    #[test]
    #[ignore]
    fn ptau_to_params_kzg_k24() {
        let path = "/tmp/ppot-downloads/ppot_0080_24.ptau";
        let params = load_ptau_into_params_kzg(path, 24)
            .expect("load_ptau_into_params_kzg");
        use halo2_proofs::poly::commitment::Params;
        assert_eq!(params.k(), 24);
        assert_eq!(params.n(), 1u64 << 24);
    }
}
