// citrate/core/execution/src/precompiles/memory_anchor.rs
//
// HUP-S7.2 / federation F-3: 0x0121 MEMORY_ANCHOR_VERIFY (agent precompile fork,
// `crate::agent_fork`). Spec: `docs/precompiles/AGENT_PRECOMPILES.md`.
//
// An agent's decision records are batched per UTC day into an RFC 6962 Merkle
// tree, and one value per day, the day commitment, is anchored in
// `AnchorRegistry` (kind NightlyMerkle). This precompile checks an inclusion
// proof for one record and returns the day commitment it proves membership in,
// so a contract can then ask `AnchorRegistry.isAnchored(commitment)`.
//
// It is the on-chain twin of `citrate-agent-anchor::verify_proof` in
// citrate-agent-runtime, byte for byte:
//
//   leaf       = SHA-256(0x00 || record_hash)
//   node       = SHA-256(0x01 || left || right)
//   commitment = SHA-256("citrate.agent-anchor.nightly.v1\n" || be32(v) || be64(day)
//                        || be64(first_seq) || be64(last_seq) || be64(count) || tree_root)
//
// and a proof is valid iff: v == 1, count > 0, last_seq - first_seq == count - 1,
// leaf_index < count, first_seq + leaf_index == seq, and the RFC 9162 §2.1.3.2
// path walk from `record_hash` at `leaf_index` in a tree of `count` leaves ends at
// `tree_root` with every path element used. The shared vectors in the tests are
// produced by the runtime crate and by an independent re-implementation.
//
// Output: the 32-byte commitment when the proof is valid, 32 zero bytes when it
// is not (SHA-256 of the domain-prefixed header is never zero in practice, so
// zero cannot be confused with a real commitment). Malformed input (wrong
// length, path longer than 64) is an error, which fails the calling frame.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

use super::PrecompileResult;

/// 0x0121 MEMORY_ANCHOR_VERIFY.
pub const MEMORY_ANCHOR_VERIFY: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x21,
];

/// Domain prefix of the day commitment (citrate-agent-anchor `COMMITMENT_DOMAIN`).
pub const COMMITMENT_DOMAIN: &[u8] = b"citrate.agent-anchor.nightly.v1\n";

/// Batch header version this precompile accepts (citrate-agent-anchor `BATCH_VERSION`).
pub const BATCH_VERSION: u32 = 1;

/// Longest audit path accepted (a tree of up to 2^64 leaves).
pub const MAX_PATH: usize = 64;

/// Fixed part of the input: v(4) day(8) first_seq(8) last_seq(8) count(8) tree_root(32)
/// seq(8) leaf_index(8) record_hash(32) path_len(1).
pub const FIXED_LEN: usize = 4 + 8 + 8 + 8 + 8 + 32 + 8 + 8 + 32 + 1;

/// Gas schedule. Conservative placeholder values, pending owner sign-off. Priced
/// above the 0x02 SHA256 precompile rate (60 + 12 per word) for the commitment,
/// the leaf hash and one node hash per path element.
pub mod gas_costs {
    pub const BASE: u64 = 1_500;
    pub const PER_PATH_ELEMENT: u64 = 150;
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn leaf_hash(data: &[u8; 32]) -> [u8; 32] {
    sha(&[&[0u8], data])
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    sha(&[&[1u8], l, r])
}

/// The day commitment over a batch header.
pub fn day_commitment(
    v: u32,
    day: u64,
    first_seq: u64,
    last_seq: u64,
    count: u64,
    tree_root: &[u8; 32],
) -> [u8; 32] {
    sha(&[
        COMMITMENT_DOMAIN,
        &v.to_be_bytes(),
        &day.to_be_bytes(),
        &first_seq.to_be_bytes(),
        &last_seq.to_be_bytes(),
        &count.to_be_bytes(),
        tree_root,
    ])
}

/// RFC 9162 §2.1.3.2 inclusion verification (identical to
/// `citrate_agent_records::merkle::verify_path`).
pub fn verify_path(
    leaf: &[u8; 32],
    index: u64,
    size: u64,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if index >= size {
        return false;
    }
    // index < size, so size >= 1.
    let (mut fnode, mut snode) = (index, size.saturating_sub(1));
    let mut r = leaf_hash(leaf);
    for p in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && &r == root
}

fn be_u32(b: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        b.try_into().map_err(|_| anyhow!("u32 field"))?,
    ))
}

fn be_u64(b: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        b.try_into().map_err(|_| anyhow!("u64 field"))?,
    ))
}

fn h32(b: &[u8]) -> Result<[u8; 32]> {
    b.try_into().map_err(|_| anyhow!("32-byte field"))
}

/// 0x0121 MEMORY_ANCHOR_VERIFY. See the module docs for the input layout.
/// **Gas:** `1500 + 150 * path_len`.
pub fn execute(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let Some((fixed, path_bytes)) = input.split_at_checked(FIXED_LEN) else {
        return Err(anyhow!(
            "MEMORY_ANCHOR_VERIFY: input {} bytes, need at least {FIXED_LEN}",
            input.len()
        ));
    };
    let path_len = usize::from(fixed.last().copied().unwrap_or_default());
    if path_len > MAX_PATH {
        return Err(anyhow!(
            "MEMORY_ANCHOR_VERIFY: path length {path_len} exceeds {MAX_PATH}"
        ));
    }
    // path_len <= MAX_PATH, so these cannot saturate.
    let path_bytes_len = path_len.saturating_mul(32);
    let expected = FIXED_LEN.saturating_add(path_bytes_len);
    if path_bytes.len() != path_bytes_len {
        return Err(anyhow!(
            "MEMORY_ANCHOR_VERIFY: input {} bytes, path length {path_len} needs exactly {expected}",
            input.len()
        ));
    }
    let gas_used =
        gas_costs::BASE.saturating_add(gas_costs::PER_PATH_ELEMENT.saturating_mul(path_len as u64));
    if gas_limit < gas_used {
        return Err(anyhow!(
            "Insufficient gas for MEMORY_ANCHOR_VERIFY: need {gas_used}, have {gas_limit}"
        ));
    }

    let field = |start: usize, len: usize| -> Result<&[u8]> {
        start
            .checked_add(len)
            .and_then(|end| fixed.get(start..end))
            .ok_or_else(|| anyhow!("MEMORY_ANCHOR_VERIFY: field at {start}"))
    };
    let v = be_u32(field(0, 4)?)?;
    let day = be_u64(field(4, 8)?)?;
    let first_seq = be_u64(field(12, 8)?)?;
    let last_seq = be_u64(field(20, 8)?)?;
    let count = be_u64(field(28, 8)?)?;
    let tree_root = h32(field(36, 32)?)?;
    let seq = be_u64(field(68, 8)?)?;
    let leaf_index = be_u64(field(76, 8)?)?;
    let record_hash = h32(field(84, 32)?)?;
    let path = path_bytes
        .chunks_exact(32)
        .map(h32)
        .collect::<Result<Vec<[u8; 32]>>>()?;

    let well_formed = v == BATCH_VERSION
        && count > 0
        && last_seq >= first_seq
        && last_seq.checked_sub(first_seq) == count.checked_sub(1);
    let valid = well_formed
        && leaf_index < count
        && first_seq.checked_add(leaf_index) == Some(seq)
        && verify_path(&record_hash, leaf_index, count, &path, &tree_root);

    let output = if valid {
        day_commitment(v, day, first_seq, last_seq, count, &tree_root).to_vec()
    } else {
        vec![0u8; 32]
    };
    Ok(PrecompileResult {
        output,
        gas_used,
        success: true,
    })
}

/// Build the precompile input (used by tests, tooling and the spec examples).
#[allow(clippy::too_many_arguments)]
pub fn encode_input(
    v: u32,
    day: u64,
    first_seq: u64,
    last_seq: u64,
    count: u64,
    tree_root: &[u8; 32],
    seq: u64,
    leaf_index: u64,
    record_hash: &[u8; 32],
    path: &[[u8; 32]],
) -> Result<Vec<u8>> {
    let path_len = u8::try_from(path.len())
        .ok()
        .filter(|n| usize::from(*n) <= MAX_PATH)
        .ok_or_else(|| anyhow!("path longer than {MAX_PATH}"))?;
    let mut out = Vec::with_capacity(FIXED_LEN.saturating_add(path.len().saturating_mul(32)));
    out.extend_from_slice(&v.to_be_bytes());
    out.extend_from_slice(&day.to_be_bytes());
    out.extend_from_slice(&first_seq.to_be_bytes());
    out.extend_from_slice(&last_seq.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(tree_root);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&leaf_index.to_be_bytes());
    out.extend_from_slice(record_hash);
    out.push(path_len);
    for p in path {
        out.extend_from_slice(p);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> [u8; 32] {
        let v = hex::decode(s).expect("hex");
        v.as_slice().try_into().expect("32 bytes")
    }

    fn rec(i: u32) -> [u8; 32] {
        sha(&[format!("rec-{i}").as_bytes()])
    }

    // Shared vector: a 5-record day (day 20362, seq 40..=44), record hashes
    // SHA-256("rec-<i>"). Produced by citrate-agent-anchor `build_day_batch` (runtime
    // origin/main 01a32ed) and by an independent Python re-implementation; both agree.
    const ROOT: &str = "e31cc748d04dce3c6ecfcb00dff52dd853d551e0f57bf3f2e516c2f65882a8e4";
    const COMMITMENT: &str = "26f10b854266080ba2d272d4042ef80c9a9eb85a90de744e71b4b10c7f9998e8";
    const PATH_3: [&str; 3] = [
        "dd6b83ae1d8223d23ed4869464289c9952b6caf38b53cc4da7c87cc1f2462717",
        "196bea1e49292cc96d0437940e2437d904130a222cb6812e6bfa53aae78871da",
        "2fa07631df4d01d859eb3e78061cfb4b17ed553b410ce58c7d2b76a04d0c87cf",
    ];
    const PATH_4: [&str; 1] = ["30af241fae54672159f14dc94f297530d3d37b69b5f9b0b81d35c1ce9e4c1491"];

    fn input(seq: u64, idx: u64, record: [u8; 32], path: &[&str]) -> Vec<u8> {
        let p: Vec<[u8; 32]> = path.iter().map(|s| hx(s)).collect();
        encode_input(1, 20_362, 40, 44, 5, &hx(ROOT), seq, idx, &record, &p).expect("encode")
    }

    #[test]
    fn shared_vector_commitment_matches_runtime() {
        assert_eq!(
            day_commitment(1, 20_362, 40, 44, 5, &hx(ROOT)),
            hx(COMMITMENT)
        );
    }

    #[test]
    fn valid_proofs_return_the_commitment() {
        let r = execute(&input(43, 3, rec(3), &PATH_3), 10_000).expect("ok");
        assert_eq!(r.output, hx(COMMITMENT).to_vec());
        assert_eq!(r.gas_used, 1_500 + 3 * 150);
        // The promoted last leaf has a one-element path.
        let r = execute(&input(44, 4, rec(4), &PATH_4), 10_000).expect("ok");
        assert_eq!(r.output, hx(COMMITMENT).to_vec());
    }

    #[test]
    fn invalid_proofs_return_zero() {
        let zero = vec![0u8; 32];
        // Wrong record.
        assert_eq!(
            execute(&input(43, 3, rec(2), &PATH_3), 10_000)
                .expect("ok")
                .output,
            zero
        );
        // seq not bound to the leaf position (replaying record 3's proof as seq 42).
        assert_eq!(
            execute(&input(42, 3, rec(3), &PATH_3), 10_000)
                .expect("ok")
                .output,
            zero
        );
        // Leaf index out of range.
        assert_eq!(
            execute(&input(45, 5, rec(3), &PATH_3), 10_000)
                .expect("ok")
                .output,
            zero
        );
        // Truncated path (an unused-path / short-path forgery).
        assert_eq!(
            execute(&input(43, 3, rec(3), &PATH_3[..2]), 10_000)
                .expect("ok")
                .output,
            zero
        );
        // Extra path element.
        let mut long: Vec<&str> = PATH_3.to_vec();
        long.push(PATH_3[0]);
        assert_eq!(
            execute(&input(43, 3, rec(3), &long), 10_000)
                .expect("ok")
                .output,
            zero
        );
        // Header not well formed: count does not match the seq range.
        let p: Vec<[u8; 32]> = PATH_3.iter().map(|s| hx(s)).collect();
        let bad = encode_input(1, 20_362, 40, 45, 5, &hx(ROOT), 43, 3, &rec(3), &p).expect("enc");
        assert_eq!(execute(&bad, 10_000).expect("ok").output, zero);
        // Unknown header version.
        let v2 = encode_input(2, 20_362, 40, 44, 5, &hx(ROOT), 43, 3, &rec(3), &p).expect("enc");
        assert_eq!(execute(&v2, 10_000).expect("ok").output, zero);
    }

    #[test]
    fn malformed_input_and_gas_are_errors() {
        let good = input(43, 3, rec(3), &PATH_3);
        assert!(
            execute(&good[..good.len() - 1], 10_000).is_err(),
            "length must match path_len"
        );
        let mut extra = good.clone();
        extra.push(0);
        assert!(execute(&extra, 10_000).is_err());
        assert!(execute(&good[..10], 10_000).is_err());
        let mut too_long = good.clone();
        too_long[FIXED_LEN - 1] = 65;
        assert!(execute(&too_long, 1_000_000).is_err());
        // A correctly sized 65-element path is still refused (the cap, not the length check).
        let mut sized = good[..FIXED_LEN].to_vec();
        sized[FIXED_LEN - 1] = 65;
        sized.extend(std::iter::repeat_n(0u8, 32 * 65));
        let err = execute(&sized, u64::MAX).expect_err("path cap");
        assert!(err.to_string().contains("exceeds"), "{err}");
        assert!(execute(&good, 1_500 + 3 * 150 - 1).is_err());
    }

    #[test]
    fn single_leaf_day() {
        let solo = sha(&[b"solo"]);
        let root = leaf_hash(&solo);
        let i = encode_input(1, 20_362, 7, 7, 1, &root, 7, 0, &solo, &[]).expect("enc");
        let r = execute(&i, 10_000).expect("ok");
        assert_eq!(
            r.output,
            hx("9a2e4054f3eb8e5c46776fc845a8a182daa766ee721c31faeae628c1fa3ef720").to_vec()
        );
        assert_eq!(r.gas_used, 1_500);
    }
}
