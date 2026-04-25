// citrate/core/consensus/src/ecvrf.rs
//
// WP-S.2: ECVRF-P256-SHA256-TAI implementation per RFC 9381.
// Provides verifiable random function using NIST P-256 curve.

use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::ops::ReduceNonZero;
use p256::elliptic_curve::PrimeField;
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Create an HMAC-SHA256 instance from the given key.
///
/// HMAC-SHA256 accepts any key length, so `new_from_slice` is infallible for
/// a well-formed byte slice.  We surface this as a helper to avoid `.expect()`
/// in hot paths while keeping the code readable.
#[inline]
fn hmac_sha256(key: &[u8]) -> HmacSha256 {
    HmacSha256::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"))
}

/// ECVRF suite string for P256-SHA256-TAI (RFC 9381 Section 5.5).
const SUITE_STRING: u8 = 0x01;

/// Challenge length in bytes (n = 128 bits / 8).
const C_LEN: usize = 16;

/// Proof: pk_p256(33) || Gamma(33) || c(16) || s(32) = 114 bytes.
/// The P-256 public key is included so the verifier can verify without
/// needing the prover's secret key material.
const PROOF_LEN: usize = 114;

/// ECVRF proof structure.
#[derive(Debug, Clone)]
pub struct EcvrfProof {
    /// P-256 public key of the prover (for verification).
    pub pk_p256: Vec<u8>,
    pub gamma: AffinePoint,
    pub c: [u8; C_LEN],
    pub s: Scalar,
}

impl EcvrfProof {
    /// Encode proof as 114 bytes: pk_p256(33) || Gamma(33) || c(16) || s(32).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PROOF_LEN);
        buf.extend_from_slice(&self.pk_p256);
        let gamma_compressed = self.gamma.to_encoded_point(true);
        buf.extend_from_slice(gamma_compressed.as_bytes());
        buf.extend_from_slice(&self.c);
        buf.extend_from_slice(&self.s.to_bytes());
        buf
    }

    /// Decode proof from 114 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcvrfError> {
        if bytes.len() != PROOF_LEN {
            return Err(EcvrfError::InvalidProofLength(bytes.len()));
        }

        let pk_p256 = bytes[0..33].to_vec();
        let gamma_bytes = &bytes[33..66];
        let c_bytes = &bytes[66..82];
        let s_bytes = &bytes[82..114];

        let encoded_point = EncodedPoint::from_bytes(gamma_bytes)
            .map_err(|_| EcvrfError::InvalidPoint)?;
        let gamma_opt: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded_point).into();
        let gamma = gamma_opt.ok_or(EcvrfError::InvalidPoint)?;

        let mut c = [0u8; C_LEN];
        c.copy_from_slice(c_bytes);

        let s_field = p256::FieldBytes::from_slice(s_bytes);
        let s_opt: Option<Scalar> = Scalar::from_repr(*s_field).into();
        let s = s_opt.ok_or(EcvrfError::InvalidScalar)?;

        Ok(Self { pk_p256, gamma, c, s })
    }
}

/// ECVRF errors.
#[derive(Debug, thiserror::Error)]
pub enum EcvrfError {
    #[error("invalid proof length: {0}")]
    InvalidProofLength(usize),

    #[error("invalid elliptic curve point")]
    InvalidPoint,

    #[error("invalid scalar value")]
    InvalidScalar,

    #[error("hash to curve failed")]
    HashToCurveFailed,

    #[error("invalid secret key")]
    InvalidSecretKey,
}

/// Derive a P-256 scalar from 32 bytes of key material.
/// Reduces mod n (the curve order) to ensure validity.
fn secret_to_scalar(secret: &[u8; 32]) -> Scalar {
    // Hash the secret to get uniform bytes, then reduce mod n.
    let mut hasher = Sha256::new();
    hasher.update(b"ECVRF-P256-KEY-DERIVATION");
    hasher.update(secret);
    let hash = hasher.finalize();
    let field_bytes = p256::FieldBytes::from_slice(&hash);
    // reduce_nonzero_bytes: reduce mod n and ensure non-zero
    Scalar::reduce_nonzero_bytes(field_bytes)
}

/// Derive the P-256 public key (point) from a scalar.
fn scalar_to_pubkey_point(sk: &Scalar) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * sk
}

/// RFC 9381 Section 5.4.1.1: ECVRF_hash_to_try_and_increment.
/// Hash alpha to a curve point using try-and-increment.
fn hash_to_try_and_increment(
    pk_bytes: &[u8],
    alpha: &[u8],
) -> Result<ProjectivePoint, EcvrfError> {
    for ctr in 0u8..=255 {
        let mut hasher = Sha256::new();
        hasher.update([SUITE_STRING]);
        hasher.update([0x01]); // hash_to_curve flag
        hasher.update(pk_bytes);
        hasher.update(alpha);
        hasher.update([ctr]);
        hasher.update([0x00]); // trailing zero per RFC
        let hash_result = hasher.finalize();

        // Try to decompress as a point with 0x02 prefix (even y)
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..33].copy_from_slice(&hash_result);

        let encoded = match EncodedPoint::from_bytes(compressed) {
            Ok(ep) => ep,
            Err(_) => continue,
        };

        let point_opt: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
        if let Some(affine) = point_opt {
            return Ok(ProjectivePoint::from(affine));
        }
    }

    Err(EcvrfError::HashToCurveFailed)
}

/// RFC 9381 Section 5.4.3: ECVRF_hash_points.
/// Hashes a sequence of curve points to produce a challenge scalar (first C_LEN bytes).
fn hash_points(points: &[ProjectivePoint]) -> [u8; C_LEN] {
    let mut hasher = Sha256::new();
    hasher.update([SUITE_STRING]);
    hasher.update([0x02]); // hash_points flag
    for p in points {
        let affine = p.to_affine();
        let encoded = affine.to_encoded_point(true);
        hasher.update(encoded.as_bytes());
    }
    hasher.update([0x00]); // trailing zero per RFC
    let hash = hasher.finalize();

    let mut c = [0u8; C_LEN];
    c.copy_from_slice(&hash[..C_LEN]);
    c
}

/// Convert a C_LEN-byte challenge to a Scalar.
fn challenge_to_scalar(c: &[u8; C_LEN]) -> Scalar {
    let mut padded = [0u8; 32];
    // Place c in the least significant bytes (big-endian)
    padded[32 - C_LEN..].copy_from_slice(c);
    let field_bytes = p256::FieldBytes::from_slice(&padded);
    let opt: Option<Scalar> = Scalar::from_repr(*field_bytes).into();
    // RM-B1 / WP-B5.6 (audit L-03): pre-fix used `unwrap_or(Scalar::ZERO)`
    // here. The fallback to zero scalar in the verification equation
    // `c * pk` produces the identity element — a forger-passes case
    // if reachable. `c` is C_LEN = 16 bytes which is always < curve
    // order (P-256 order is ~256 bits), so `from_repr` ALWAYS
    // succeeds. `.expect()` documents the invariant and panics
    // loudly if a future C_LEN bump invalidates it.
    opt.expect("c is C_LEN bytes (≤ 16); always fits in P-256 scalar field")
}

/// RFC 6979-style deterministic nonce generation using HMAC-DRBG.
///
/// M-05: HMAC-DRBG state `(k, v)` and the secret-key bytes are wrapped in
/// `Zeroizing<>` so the buffers are erased when this function returns.
/// The returned `Scalar` is owned by the caller, who is responsible for
/// dropping it under `Zeroizing` (p256's `Scalar` implements `Zeroize`
/// via the `zeroize` feature flag, so a stack drop also wipes).
fn nonce_generation(sk: &Scalar, h_point: &ProjectivePoint) -> Scalar {
    // sk_bytes mirrors the secret scalar; wipe on scope exit.
    let sk_bytes: Zeroizing<p256::FieldBytes> = Zeroizing::new(sk.to_bytes());
    let h_encoded = h_point.to_affine().to_encoded_point(true);
    let h_bytes = h_encoded.as_bytes();

    // HMAC-DRBG state `(k, v)` per RFC 6979 §3.2 — both wiped on drop.
    let mut v: Zeroizing<[u8; 32]> = Zeroizing::new([0x01u8; 32]);
    let mut k: Zeroizing<[u8; 32]> = Zeroizing::new([0x00u8; 32]);

    // Step D
    let mut mac = hmac_sha256(k.as_ref());
    mac.update(v.as_ref());
    mac.update(&[0x00]);
    mac.update(sk_bytes.as_ref());
    mac.update(h_bytes);
    *k = mac.finalize().into_bytes().into();

    // Step E
    let mut mac = hmac_sha256(k.as_ref());
    mac.update(v.as_ref());
    *v = mac.finalize().into_bytes().into();

    // Step F
    let mut mac = hmac_sha256(k.as_ref());
    mac.update(v.as_ref());
    mac.update(&[0x01]);
    mac.update(sk_bytes.as_ref());
    mac.update(h_bytes);
    *k = mac.finalize().into_bytes().into();

    // Step G
    let mut mac = hmac_sha256(k.as_ref());
    mac.update(v.as_ref());
    *v = mac.finalize().into_bytes().into();

    // Step H: generate candidates until we get a valid scalar
    loop {
        let mut mac = hmac_sha256(k.as_ref());
        mac.update(v.as_ref());
        *v = mac.finalize().into_bytes().into();

        let field_bytes = p256::FieldBytes::from_slice(v.as_ref());
        let opt: Option<Scalar> = Scalar::from_repr(*field_bytes).into();
        if let Some(scalar) = opt {
            if scalar != Scalar::ZERO {
                return scalar;
            }
        }

        // Update k, v for next iteration
        let mut mac = hmac_sha256(k.as_ref());
        mac.update(v.as_ref());
        mac.update(&[0x00]);
        *k = mac.finalize().into_bytes().into();

        let mut mac = hmac_sha256(k.as_ref());
        mac.update(v.as_ref());
        *v = mac.finalize().into_bytes().into();
    }
}

/// RFC 9381 Section 5.2: ECVRF_proof_to_hash.
/// Converts Gamma to a 32-byte VRF output (beta string).
pub fn proof_to_hash(gamma: &AffinePoint) -> [u8; 32] {
    // For P-256, cofactor h=1, so cofactor_mult is identity
    let encoded = gamma.to_encoded_point(true);
    let mut hasher = Sha256::new();
    hasher.update([SUITE_STRING]);
    hasher.update([0x03]); // proof_to_hash flag
    hasher.update(encoded.as_bytes());
    hasher.update([0x00]); // trailing zero per RFC
    hasher.finalize().into()
}

/// RFC 9381 Section 5.1: ECVRF_prove.
///
/// Generates an ECVRF proof and output for the given secret key and alpha string.
/// The `secret` is 32 bytes of key material (e.g., the node's ed25519 private key bytes),
/// which is deterministically derived to a P-256 scalar.
///
/// **Caller contract (M-05)**: the `secret` slice is borrowed; callers
/// MUST hold their copy in a `Zeroizing<[u8; 32]>` (or equivalent) so
/// the bytes are erased when their owner is dropped. This function
/// wraps the *derived* `Scalar` and the nonce locally, but cannot
/// reach back into the caller's buffer.
pub fn prove(secret: &[u8; 32], alpha: &[u8]) -> Result<(EcvrfProof, [u8; 32]), EcvrfError> {
    // M-05: the derived scalar is the actual signing material. p256's
    // Scalar implements Zeroize via the `zeroize` feature; wrapping in
    // Zeroizing<Scalar> is a belt-and-suspenders that also forces drop
    // ordering.
    let sk: Zeroizing<Scalar> = Zeroizing::new(secret_to_scalar(secret));
    let pk_point = scalar_to_pubkey_point(&sk);
    let pk_affine = pk_point.to_affine();
    let pk_encoded = pk_affine.to_encoded_point(true);
    let pk_bytes = pk_encoded.as_bytes();

    // Step 1: Hash to curve
    let h = hash_to_try_and_increment(pk_bytes, alpha)?;

    // Step 2: Gamma = sk * H
    let gamma_proj = h * *sk;
    let gamma = gamma_proj.to_affine();

    // Step 3: Nonce k — derived from sk, also a secret. Wrap.
    let k: Zeroizing<Scalar> = Zeroizing::new(nonce_generation(&sk, &h));

    // Step 4: U = k * B (generator)
    let u = ProjectivePoint::GENERATOR * *k;

    // Step 5: V = k * H
    let v = h * *k;

    // Step 6: Challenge c = hash_points(H, Gamma, U, V) — public.
    let c = hash_points(&[h, gamma_proj, u, v]);

    // Step 7: s = (k + c * sk) mod q — published in the proof, not secret.
    let c_scalar = challenge_to_scalar(&c);
    let s = *k + c_scalar * *sk;

    // Step 8: beta = proof_to_hash(Gamma)
    let beta = proof_to_hash(&gamma);

    Ok((EcvrfProof { pk_p256: pk_bytes.to_vec(), gamma, c, s }, beta))
}

/// RFC 9381 Section 5.3: ECVRF_verify.
///
/// Verifies an ECVRF proof and returns the VRF output (beta) if valid.
/// Uses the P-256 public key embedded in the proof.
pub fn verify(
    alpha: &[u8],
    proof: &EcvrfProof,
) -> Result<[u8; 32], EcvrfError> {
    let pk_bytes_33 = &proof.pk_p256;

    // Decode public key
    let encoded_point = EncodedPoint::from_bytes(pk_bytes_33)
        .map_err(|_| EcvrfError::InvalidPoint)?;
    let pk_opt: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded_point).into();
    let pk_affine = pk_opt.ok_or(EcvrfError::InvalidPoint)?;
    let pk_proj = ProjectivePoint::from(pk_affine);

    // Step 1: Hash to curve
    let h = hash_to_try_and_increment(pk_bytes_33, alpha)?;

    let gamma_proj = ProjectivePoint::from(proof.gamma);
    let c_scalar = challenge_to_scalar(&proof.c);

    // Step 2: U = s * B - c * Y (where Y = pk)
    let u = ProjectivePoint::GENERATOR * proof.s - pk_proj * c_scalar;

    // Step 3: V = s * H - c * Gamma
    let v = h * proof.s - gamma_proj * c_scalar;

    // Step 4: c' = hash_points(H, Gamma, U, V)
    let c_prime = hash_points(&[h, gamma_proj, u, v]);

    // Step 5: Check c == c'
    if proof.c != c_prime {
        return Err(EcvrfError::InvalidPoint); // proof failed verification
    }

    // Return beta = proof_to_hash(Gamma)
    Ok(proof_to_hash(&proof.gamma))
}

/// Derive the compressed P-256 public key bytes (33 bytes) from a 32-byte secret.
/// This is the public key that peers need for verification.
pub fn derive_public_key(secret: &[u8; 32]) -> Vec<u8> {
    let sk = secret_to_scalar(secret);
    let pk = scalar_to_pubkey_point(&sk).to_affine();
    pk.to_encoded_point(true).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate proof, verify succeeds.
    #[test]
    fn test_ecvrf_prove_verify() {
        let secret = [42u8; 32];
        let alpha = b"test alpha string";

        let (proof, beta) = prove(&secret, alpha).expect("prove should succeed");

        let verified_beta = verify(alpha, &proof).expect("verify should succeed");

        assert_eq!(beta, verified_beta);
    }

    /// Tampered proof fails verification.
    #[test]
    fn test_ecvrf_tampered_proof_fails() {
        let secret = [42u8; 32];
        let alpha = b"test alpha string";

        let (mut proof, _) = prove(&secret, alpha).unwrap();

        // Tamper with the challenge
        proof.c[0] ^= 0xFF;

        assert!(verify(alpha, &proof).is_err());
    }

    /// Wrong public key fails verification.
    #[test]
    fn test_ecvrf_wrong_pubkey_fails() {
        let secret = [42u8; 32];
        let wrong_secret = [99u8; 32];
        let alpha = b"test alpha string";

        let (mut proof, _) = prove(&secret, alpha).unwrap();

        // Replace pk_p256 with a different key's public key
        proof.pk_p256 = derive_public_key(&wrong_secret);

        assert!(verify(alpha, &proof).is_err());
    }

    /// Determinism: same (sk, alpha) → same (proof, output).
    #[test]
    fn test_ecvrf_determinism() {
        let secret = [42u8; 32];
        let alpha = b"determinism test";

        let (proof1, beta1) = prove(&secret, alpha).unwrap();
        let (proof2, beta2) = prove(&secret, alpha).unwrap();

        assert_eq!(beta1, beta2);
        assert_eq!(proof1.c, proof2.c);
        assert_eq!(proof1.s, proof2.s);
        assert_eq!(proof1.to_bytes(), proof2.to_bytes());
    }

    /// Proof serialization round-trip.
    #[test]
    fn test_ecvrf_proof_serialization() {
        let secret = [42u8; 32];
        let alpha = b"serialization test";

        let (proof, beta) = prove(&secret, alpha).unwrap();

        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), PROOF_LEN);

        let decoded = EcvrfProof::from_bytes(&bytes).unwrap();

        // Verify decoded proof still validates
        let verified_beta = verify(alpha, &decoded).unwrap();
        assert_eq!(beta, verified_beta);
    }

    /// Different alpha strings produce different outputs.
    #[test]
    fn test_ecvrf_different_alpha_different_output() {
        let secret = [42u8; 32];

        let (_, beta1) = prove(&secret, b"alpha one").unwrap();
        let (_, beta2) = prove(&secret, b"alpha two").unwrap();

        assert_ne!(beta1, beta2);
    }

    // M-05 regression: p256 Scalar must implement Zeroize so that the
    // signing scalars derived inside `prove` actually erase on drop.
    // This is a type-level assertion — a future bump to a p256 version
    // that drops the Zeroize impl breaks compilation.
    #[test]
    fn test_m05_scalar_implements_zeroize() {
        fn assert_impls_zeroize<T: zeroize::Zeroize>(_: &T) {}
        let s = Scalar::ZERO;
        assert_impls_zeroize(&s);
    }

    // M-05 regression: prove() runs end-to-end and produces stable output.
    // Cross-check that wrapping sk and k in Zeroizing<> didn't perturb
    // the determinism guarantee.
    #[test]
    fn test_m05_zeroizing_does_not_perturb_proof_determinism() {
        let secret = [0xABu8; 32];
        let alpha = b"m-05 determinism check";
        let (proof1, beta1) = prove(&secret, alpha).expect("prove");
        let (proof2, beta2) = prove(&secret, alpha).expect("prove repeat");
        assert_eq!(beta1, beta2, "M-05: ECVRF must remain deterministic");
        assert_eq!(
            proof1.s, proof2.s,
            "M-05: signature scalar s must remain deterministic"
        );
    }
}
