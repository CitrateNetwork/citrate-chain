// citrate/core/execution/src/precompiles/verify.rs
//
// RM-M1: AI Verification Precompiles (Track 1).
//
// Three precompiles at addresses 0x0107–0x0109 that let on-chain
// contracts trustlessly check claims about off-chain AI work without
// re-running the work themselves.
//
// - 0x0107 TENSOR_COMMIT: Poseidon commitment over a canonical-format
//   tensor. Returns 32-byte field element.
// - 0x0108 INFERENCE_PROOF_VERIFY: Groth16 verifier for the
//   InferenceProof circuit family. Returns 32-byte 0/1 bool.
// - 0x0109 MERKLE_VERIFY_TENSOR: verify a tensor element is part of a
//   committed tensor via a Merkle path. Returns 32-byte 0/1 bool.
//
// All three are deterministic by construction (hash + pairing + integer
// math). No floating-point, no platform-dependent behavior.
//
// **Stability invariant:** the byte-level output of these precompiles
// is FROZEN. Drift forks the chain and silently invalidates every
// prior commitment. The frozen-vector test
// `tests/poseidon_frozen_v1.rs` is the canary; do not "fix" that test
// to make it pass. See its top-of-file procedure block.

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};

use super::tensor_format::{self, TensorFormatError};
use super::PrecompileResult;
use crate::types::Address;
use crate::zkp::poseidon::poseidon_hash;

/// Precompile addresses for AI verification operations.
pub mod addresses {
    /// 0x0107 — Poseidon commitment over a canonical-format tensor.
    pub const TENSOR_COMMIT: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 7];

    /// 0x0108 — Groth16 verifier for inference proofs.
    pub const INFERENCE_PROOF_VERIFY: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 8];

    /// 0x0109 — Merkle inclusion check over a Poseidon-committed tensor.
    pub const MERKLE_VERIFY_TENSOR: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 9];
}

/// Gas costs.
pub mod gas_costs {
    /// TENSOR_COMMIT base cost. Validates header, sets up sponge.
    pub const TENSOR_COMMIT_BASE: u64 = 3_000;

    /// TENSOR_COMMIT per-32-byte-word cost. Each word becomes one Fr
    /// absorb (or fraction of one with rate=2). 30 gas/word matches the
    /// existing zkp/poseidon costing.
    pub const TENSOR_COMMIT_PER_WORD: u64 = 30;

    // INFERENCE_PROOF_VERIFY and MERKLE_VERIFY_TENSOR costs are added
    // when their precompiles ship in WP-M1.3 / WP-M1.4.
}

/// Route to the right precompile by address.
pub fn execute(address: &Address, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let addr = address.as_fixed_bytes();
    if addr == &addresses::TENSOR_COMMIT {
        tensor_commit(input, gas_limit)
    } else if addr == &addresses::INFERENCE_PROOF_VERIFY {
        Err(anyhow!(
            "INFERENCE_PROOF_VERIFY (0x0108) lands in WP-M1.3"
        ))
    } else if addr == &addresses::MERKLE_VERIFY_TENSOR {
        Err(anyhow!("MERKLE_VERIFY_TENSOR (0x0109) lands in WP-M1.4"))
    } else {
        Err(anyhow!("Unknown verification precompile address"))
    }
}

/// 0x0107 TENSOR_COMMIT — Poseidon commitment over a canonical-format
/// tensor.
///
/// **Input:** raw bytes produced by `tensor_format::encode`. The
/// precompile decodes the header to validate well-formedness, then
/// commits over the FULL input bytes (header + data). Including the
/// header is intentional: it binds the commitment to the (rank, shape,
/// dtype) of the tensor, so two byte-identical data payloads with
/// different shapes produce different commitments.
///
/// **Output:** 32 bytes = the squeezed Fr field element, big-endian.
/// Big-endian matches the on-chain convention (H256, ABI-encoded
/// addresses, ECRECOVER output).
///
/// **Gas:** `3000 + 30 × ceil(input_len / 32)`. Calibrated against the
/// existing zkp/poseidon costing; one Fr absorb per 31-byte chunk plus
/// the header path overhead.
///
/// **Determinism:** Poseidon over BLS12-381 Fr is bit-deterministic
/// across all hardware. The frozen-vectors test in
/// `tests/poseidon_frozen_v1.rs` locks the byte output of six
/// reference inputs; this precompile inherits that guarantee.
pub fn tensor_commit(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    // Validate the canonical-format header before computing gas. A
    // malformed input pays only the parse cost (which is cheap) and
    // returns a structured error rather than charging the caller for
    // useless work. The decoded view is discarded — we hash the input
    // bytes themselves so the commitment binds to the byte
    // representation, not just the field-element representation.
    let _view = tensor_format::decode_exact(input).map_err(map_format_error)?;

    // Gas: per-32-byte-word + base. `div_ceil` so a 1-byte input still
    // costs at least one word.
    let words = (input.len() as u64).div_ceil(32);
    let gas_used = gas_costs::TENSOR_COMMIT_BASE + gas_costs::TENSOR_COMMIT_PER_WORD * words;
    if gas_limit < gas_used {
        return Err(anyhow!(
            "Insufficient gas for TENSOR_COMMIT: need {gas_used}, have {gas_limit}"
        ));
    }

    // Pack the input bytes into Fr field elements, 31 bytes per Fr.
    // BLS12-381 Fr is ~255 bits ≈ 31.875 bytes; using 31 bytes guarantees
    // every chunk fits below the modulus without reduction. The last
    // chunk is implicitly zero-padded by `from_le_bytes_mod_order` — the
    // length prefix in the canonical format already disambiguates
    // padding from real data.
    let chunks: Vec<Fr> = input
        .chunks(31)
        .map(Fr::from_le_bytes_mod_order)
        .collect();

    let h = poseidon_hash(&chunks);

    // Convert Fr → 32-byte big-endian.
    let bigint = h.into_bigint();
    let mut bytes_le = bigint.to_bytes_le();
    bytes_le.reverse();
    let mut out = vec![0u8; 32];
    let off = 32 - bytes_le.len().min(32);
    out[off..].copy_from_slice(&bytes_le[..bytes_le.len().min(32)]);

    Ok(PrecompileResult {
        output: out,
        gas_used,
        success: true,
    })
}

/// Map a TensorFormatError into an anyhow error with a stable prefix
/// so contracts can reason about the failure class without parsing
/// the message.
fn map_format_error(e: TensorFormatError) -> anyhow::Error {
    anyhow!("TENSOR_FORMAT_ERROR: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tensor_format::{encode, Dtype};

    /// Build a valid Q16 encoded tensor for use in tests.
    fn q16_tensor(shape: &[u32], values: &[i32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(values.len() * 4);
        for &v in values {
            data.extend_from_slice(&v.to_le_bytes());
        }
        encode(shape, Dtype::Q16_16, &data).expect("encode")
    }

    #[test]
    fn tensor_commit_returns_32_bytes() {
        let t = q16_tensor(&[3], &[1, 2, 3]);
        let r = tensor_commit(&t, 1_000_000).unwrap();
        assert_eq!(r.output.len(), 32, "output must be 32 bytes");
        assert!(r.success);
    }

    #[test]
    fn tensor_commit_is_deterministic() {
        let t = q16_tensor(&[3], &[1, 2, 3]);
        let r1 = tensor_commit(&t, 1_000_000).unwrap();
        let r2 = tensor_commit(&t, 1_000_000).unwrap();
        assert_eq!(r1.output, r2.output);
        assert_eq!(r1.gas_used, r2.gas_used);
    }

    #[test]
    fn tensor_commit_distinguishes_data() {
        // Same shape, different data → different commitment.
        let a = q16_tensor(&[3], &[1, 2, 3]);
        let b = q16_tensor(&[3], &[1, 2, 4]);
        let ra = tensor_commit(&a, 1_000_000).unwrap();
        let rb = tensor_commit(&b, 1_000_000).unwrap();
        assert_ne!(ra.output, rb.output);
    }

    #[test]
    fn tensor_commit_distinguishes_shape() {
        // Same data bytes, different shape → different commitment.
        // [1,2,3,4,5,6] as a flat vector (rank 1, shape=[6]) vs as a
        // 2×3 matrix (rank 2, shape=[2,3]). Same 24 data bytes,
        // different headers, must differ.
        let flat = q16_tensor(&[6], &[1, 2, 3, 4, 5, 6]);
        let matrix = q16_tensor(&[2, 3], &[1, 2, 3, 4, 5, 6]);
        let r_flat = tensor_commit(&flat, 1_000_000).unwrap();
        let r_matrix = tensor_commit(&matrix, 1_000_000).unwrap();
        assert_ne!(
            r_flat.output, r_matrix.output,
            "shape must bind to commitment"
        );
    }

    #[test]
    fn tensor_commit_distinguishes_dtype() {
        // Encode the same logical bytes once as Q16 (rank 1, n=8), once
        // as Field32 (rank 1, n=1, 32 bytes). Different headers, same
        // payload bytes — commitment must differ.
        let q16 = encode(&[8], Dtype::Q16_16, &[1u8; 32]).unwrap();
        let f32_t = encode(&[1], Dtype::Field32, &[1u8; 32]).unwrap();
        let r_q = tensor_commit(&q16, 1_000_000).unwrap();
        let r_f = tensor_commit(&f32_t, 1_000_000).unwrap();
        assert_ne!(r_q.output, r_f.output);
    }

    #[test]
    fn tensor_commit_rejects_malformed_truncated() {
        // rank=2, no shape bytes
        let bad = vec![2u8];
        let r = tensor_commit(&bad, 1_000_000);
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("TENSOR_FORMAT_ERROR"));
    }

    #[test]
    fn tensor_commit_rejects_malformed_unknown_dtype() {
        let mut bad = vec![1u8];
        bad.extend_from_slice(&1u32.to_be_bytes());
        bad.push(0xff); // unknown dtype
        let r = tensor_commit(&bad, 1_000_000);
        assert!(r.is_err());
    }

    #[test]
    fn tensor_commit_rejects_trailing_bytes() {
        let mut t = q16_tensor(&[2], &[1, 2]);
        t.push(0xff);
        let r = tensor_commit(&t, 1_000_000);
        assert!(r.is_err(), "decode_exact should reject trailing bytes");
    }

    #[test]
    fn tensor_commit_gas_metering() {
        let t = q16_tensor(&[2], &[1, 2]); // 1+8+1+8 = 18 bytes
        let words = (18u64).div_ceil(32); // = 1
        let expected_gas = gas_costs::TENSOR_COMMIT_BASE + gas_costs::TENSOR_COMMIT_PER_WORD * words;

        // Exactly enough gas → succeeds.
        let r = tensor_commit(&t, expected_gas).unwrap();
        assert_eq!(r.gas_used, expected_gas);

        // One less than needed → fails.
        let r2 = tensor_commit(&t, expected_gas - 1);
        assert!(r2.is_err());
        assert!(
            format!("{}", r2.unwrap_err()).contains("Insufficient gas"),
            "should be a gas error, not a format error"
        );
    }

    #[test]
    fn tensor_commit_rejects_oversize_via_format() {
        // 2048×2048 Q16 = 4M elements > MAX_ELEMENTS=1M → rejected
        // at the format layer. Header-only is 1+8+1=10 bytes.
        let mut bad = vec![2u8];
        bad.extend_from_slice(&2048u32.to_be_bytes());
        bad.extend_from_slice(&2048u32.to_be_bytes());
        bad.push(Dtype::Q16_16.to_byte());
        let r = tensor_commit(&bad, 100_000_000);
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("TENSOR_FORMAT_ERROR"));
    }

    /// Larger sanity test: commitments over different "tensor identity"
    /// inputs all produce distinct outputs. Rough avalanche check.
    #[test]
    fn tensor_commit_avalanche_rough() {
        let mut commits = std::collections::HashSet::new();
        for i in 0u32..256 {
            let t = q16_tensor(&[1], &[i as i32]);
            let r = tensor_commit(&t, 1_000_000).unwrap();
            assert!(
                commits.insert(r.output),
                "collision at i={i} — Poseidon broken or shape-encoding broken"
            );
        }
        assert_eq!(commits.len(), 256);
    }
}
