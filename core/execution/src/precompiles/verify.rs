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
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use super::tensor_format::{self, TensorFormatError};
use super::PrecompileResult;
use crate::types::Address;
use crate::zkp::poseidon_bn254::poseidon_hash;

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

    /// MERKLE_VERIFY_TENSOR base cost — header parsing + leaf hash.
    pub const MERKLE_VERIFY_BASE: u64 = 3_000;

    /// MERKLE_VERIFY_TENSOR per-level cost — one Poseidon permutation
    /// per tree level walked. 200 gas/level is conservative against
    /// the zkp/poseidon-2 costing of ~30 gas / 32-byte word with the
    /// rate=2 sponge.
    pub const MERKLE_VERIFY_PER_LEVEL: u64 = 200;

    /// Maximum Merkle proof depth accepted by 0x0109. 32 levels covers
    /// 2³² leaves, which is more than enough for any practical
    /// tensor-element addressing scheme; tighter caps live at the
    /// caller-contract level.
    pub const MERKLE_VERIFY_MAX_DEPTH: u8 = 32;

    /// INFERENCE_PROOF_VERIFY base cost — wire-format parse + VK lookup.
    /// The bulk of cost is the KZG pairing in the verifier (single
    /// pairing per proof in SHPLONK).
    pub const INFERENCE_PROOF_VERIFY_BASE: u64 = 500_000;

    /// INFERENCE_PROOF_VERIFY per-byte proof cost — proof transcript
    /// scanning + commitment opening checks scale with proof length.
    /// Calibrated as a placeholder; RM-M1b WP-M1b.6 calibrates against
    /// real proof bench numbers.
    pub const INFERENCE_PROOF_VERIFY_PER_BYTE: u64 = 50;
}

/// Route to the right precompile by address.
pub fn execute(address: &Address, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let addr = address.as_fixed_bytes();
    if addr == &addresses::TENSOR_COMMIT {
        tensor_commit(input, gas_limit)
    } else if addr == &addresses::INFERENCE_PROOF_VERIFY {
        // RM-M1b WP-M1b.4: 0x0108 is LIVE behind the
        // `halo2-substrate` feature flag. The build without that
        // flag still returns the stub message — both the binary
        // size and the dependency surface stay clean for nodes
        // that don't host the verifier.
        //
        // **SRS source:** RM-M1b v1 uses a deterministic
        // `ParamsKZG::setup` with a hardcoded seed (see
        // `halo2::inference_kzg_artifacts_v1`). This is INSECURE
        // for production — the toxic waste from setup is
        // reproducible — but DETERMINISTIC across nodes so they
        // agree on proof validity. RM-M1b WP-M1b.7 (testnet
        // enable) replaces this with the .ptau-derived ParamsKZG.
        //
        // **Anti-rug carry-forward:** ADR-RM-M1b-1 + SPRINT.md +
        // CURRENT.md document the migration path. The CI verifier
        // `check_m1_verification_precompiles.py` flips its
        // expected-state for 0x0108 from STUB to LIVE in this
        // commit.
        inference_proof_verify(input, gas_limit)
    } else if addr == &addresses::MERKLE_VERIFY_TENSOR {
        merkle_verify_tensor(input, gas_limit)
    } else {
        Err(anyhow!("Unknown verification precompile address"))
    }
}

/// 0x0107 TENSOR_COMMIT — Poseidon commitment over a canonical-format
/// tensor. **BN254 Fr** as of RM-M1b WP-M1b.3 (migrated from
/// BLS12-381 Fr to align with 0x0108 INFERENCE_PROOF_VERIFY's
/// in-circuit Poseidon).
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
/// **Determinism:** Poseidon over BN254 Fr is bit-deterministic
/// across all hardware. The frozen-vectors test in
/// `tests/tensor_commit_frozen_v1.rs` locks the byte output of four
/// reference inputs; this precompile inherits that guarantee.
///
/// **Curve migration note (2026-04-27):** v1 commitments derived
/// from BLS12-381 Fr remain in the git history (commit `045dd59c`
/// frozen vectors). The migration to BN254 was made BEFORE any
/// production commitments were stored — the testnet soak in
/// progress at the time predates 0x0107 use by any contract. So
/// no on-chain commitments need a versioning byte to disambiguate
/// curves; a single curve forever, BN254. Per ADR-RM-M1-1's
/// versioning rule, if we ever need to migrate again the new
/// commitment scheme ships at a new precompile address (0x0110+).
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

/// 0x0109 MERKLE_VERIFY_TENSOR — Poseidon Merkle inclusion check.
///
/// Verifies that a `(leaf_index, leaf_value)` pair is included in a
/// Poseidon-Merkle tree whose root is `commitment`. The proof is the
/// sequence of sibling hashes from leaf to root.
///
/// This is a **generic** Poseidon-tree primitive — it is intentionally
/// independent of how `commitment` was produced. A typical use:
///
///   1. Off-chain, build a binary Merkle tree where leaf i is
///      `Poseidon(i, value_i)` and each internal node is
///      `Poseidon(left, right)`.
///   2. Anchor the root on-chain (could be via a contract storage
///      slot, or anchored via a separate commitment scheme).
///   3. Later, prove a single `(i, value_i)` belongs to that tree by
///      sending `(root, i, value_i, sibling_path)` to 0x0109.
///
/// Note: this primitive does NOT recover a tensor element from a
/// `TENSOR_COMMIT` output. `TENSOR_COMMIT` packs encoded-tensor bytes
/// into a single sponge digest with no per-element addressing; for
/// Merkle-style streaming you build a separate Merkle tree first.
///
/// **Input format (binary, big-endian where multi-byte):**
/// ```text
/// | 32B  commitment (Fr, BE)              |
/// | 32B  leaf_index (zero-padded BE u32 actually used; lower 32 bits)
/// | 32B  leaf_value (Fr, BE; the committed leaf field element)
/// |  1B  proof_depth (u8, 0..=32)         |
/// | proof_depth × 32B  sibling[i] (Fr, BE; bottom-up: sibling at level i) |
/// ```
///
/// The leaf hash itself is `Poseidon(leaf_index_as_fr, leaf_value)` —
/// binding the element's position into the leaf prevents a malicious
/// prover from claiming the same value lives at a different index.
///
/// **Output:** 32 bytes — `0x...01` on valid inclusion, `0x...00`
/// otherwise. The fixed shape lets contracts compare against the
/// canonical "true" word `bytes32(uint256(1))` directly.
///
/// **Gas:** `MERKLE_VERIFY_BASE + MERKLE_VERIFY_PER_LEVEL × proof_depth`.
/// Cap: `proof_depth ≤ MERKLE_VERIFY_MAX_DEPTH`.
pub fn merkle_verify_tensor(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    // Header: 32 + 32 + 32 + 1 = 97 bytes minimum.
    if input.len() < 97 {
        return Err(anyhow!(
            "MERKLE_VERIFY_TENSOR input too short: need ≥ 97 bytes, got {}",
            input.len()
        ));
    }

    let commitment_bytes: [u8; 32] = input[0..32].try_into().expect("32 bytes");
    let leaf_index_bytes: [u8; 32] = input[32..64].try_into().expect("32 bytes");
    let leaf_value_bytes: [u8; 32] = input[64..96].try_into().expect("32 bytes");
    let proof_depth = input[96];

    if proof_depth > gas_costs::MERKLE_VERIFY_MAX_DEPTH {
        return Err(anyhow!(
            "MERKLE_VERIFY_TENSOR proof_depth {} exceeds MAX_DEPTH ({})",
            proof_depth,
            gas_costs::MERKLE_VERIFY_MAX_DEPTH
        ));
    }

    let expected_input_len = 97usize + (proof_depth as usize) * 32;
    if input.len() != expected_input_len {
        return Err(anyhow!(
            "MERKLE_VERIFY_TENSOR input length mismatch: expected {}, got {}",
            expected_input_len,
            input.len()
        ));
    }

    let gas_used = gas_costs::MERKLE_VERIFY_BASE
        + gas_costs::MERKLE_VERIFY_PER_LEVEL * proof_depth as u64;
    if gas_limit < gas_used {
        return Err(anyhow!(
            "Insufficient gas for MERKLE_VERIFY_TENSOR: need {gas_used}, have {gas_limit}"
        ));
    }

    // Decode field elements (big-endian on the wire). `from_be_bytes_mod_order`
    // never panics — it folds any 32-byte input into Fr modulo the field
    // order. Inputs above the modulus are accepted and reduced; that
    // matches Ethereum convention for ECRECOVER / SHA256 outputs which
    // can also exceed Fr's modulus.
    let leaf_index_fr = Fr::from_be_bytes_mod_order(&leaf_index_bytes);
    let leaf_value_fr = Fr::from_be_bytes_mod_order(&leaf_value_bytes);
    let target_root_fr = Fr::from_be_bytes_mod_order(&commitment_bytes);

    // Leaf hash binds index AND value: prevents a prover from claiming
    // the same `value` at a different `index`.
    let mut current = poseidon_hash(&[leaf_index_fr, leaf_value_fr]);

    // Walk the path bottom-up. At level i, bit i of leaf_index decides
    // whether `current` is the left or right child of the next-up node.
    //
    // `leaf_index` field-element semantics: the proof depth is bounded
    // at 32 levels, so only the low 32 bits of the 256-bit field
    // element matter for path direction. We extract those from the
    // big-endian bytes (bytes 28..32 are the low 32 bits in BE order).
    let leaf_index_lo32 = u32::from_be_bytes(
        leaf_index_bytes[28..32]
            .try_into()
            .expect("4 bytes by slice"),
    );

    for level in 0..(proof_depth as usize) {
        let off = 97 + level * 32;
        let sibling_bytes: [u8; 32] = input[off..off + 32]
            .try_into()
            .expect("32 bytes");
        let sibling_fr = Fr::from_be_bytes_mod_order(&sibling_bytes);

        let bit = (leaf_index_lo32 >> level) & 1;
        current = if bit == 0 {
            // current is left child
            poseidon_hash(&[current, sibling_fr])
        } else {
            // current is right child
            poseidon_hash(&[sibling_fr, current])
        };
    }

    // Compare reconstructed root to expected commitment.
    let valid = current == target_root_fr;

    let mut output = vec![0u8; 32];
    if valid {
        output[31] = 1;
    }

    Ok(PrecompileResult {
        output,
        gas_used,
        success: true, // success=true means "the precompile ran"; the bool result is in `output`.
    })
}

/// 0x0108 INFERENCE_PROOF_VERIFY — Halo2-KZG verifier for the
/// InferenceCircuit family.
///
/// **Input format (binary):**
/// ```text
/// | 32B  input_commitment   (BE Fr)
/// | 32B  model_commitment   (BE Fr)
/// | 32B  output_commitment  (BE Fr)
/// |  4B  circuit_version    (BE u32; v1 = 1)
/// |  4B  chain_id           (BE u32; advisory in v1)
/// | proof_bytes (variable)
/// ```
///
/// **Output:** 32-byte big-endian word, value 1 if proof verifies,
/// 0 if rejected. Returns Err on structural problems (truncated
/// input, unknown circuit_version).
///
/// **Gas:** `INFERENCE_PROOF_VERIFY_BASE + per_byte * input.len()`.
/// The per-byte component covers transcript scanning. Calibration
/// is RM-M1b WP-M1b.6 follow-up.
///
/// **Determinism:** the SRS + VK are deterministically derived
/// (RM-M1b v1: from a fixed seed; production: from the .ptau
/// file). The Halo2-KZG verifier itself is bit-deterministic.
pub fn inference_proof_verify(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    // Gas charge first — covers parsing + verification effort.
    let gas_used = gas_costs::INFERENCE_PROOF_VERIFY_BASE
        .saturating_add(gas_costs::INFERENCE_PROOF_VERIFY_PER_BYTE * input.len() as u64);
    if gas_limit < gas_used {
        return Err(anyhow!(
            "Insufficient gas for INFERENCE_PROOF_VERIFY: need {gas_used}, have {gas_limit}"
        ));
    }

    #[cfg(feature = "halo2-substrate")]
    let result = match crate::zkp::halo2::verify_inference_proof(input) {
        Ok(b) => b,
        Err(e) => {
            return Err(anyhow!("INFERENCE_PROOF_VERIFY error: {e}"));
        }
    };
    #[cfg(not(feature = "halo2-substrate"))]
    let result = {
        // Without the feature flag, the verifier is absent. The CI
        // verifier `check_m1_verification_precompiles.py` enforces
        // that this branch only ships when the feature is gated off
        // intentionally (e.g., light-node binary that doesn't host
        // proofs). Production validator binaries MUST build with
        // halo2-substrate.
        let _ = input;
        return Err(anyhow!(
            "INFERENCE_PROOF_VERIFY (0x0108) requires halo2-substrate \
             feature flag. Rebuild with --features halo2-substrate."
        ));
    };

    let mut output = vec![0u8; 32];
    if result {
        output[31] = 1;
    }

    Ok(PrecompileResult {
        output,
        gas_used,
        success: true,
    })
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

    // ------------------------------------------------------------------
    // 0x0109 MERKLE_VERIFY_TENSOR tests.
    // ------------------------------------------------------------------

    /// Convert an Fr field element to a 32-byte big-endian buffer.
    /// Mirrors the wire format used by 0x0109.
    fn fr_to_be_bytes(f: &Fr) -> [u8; 32] {
        let bigint = f.into_bigint();
        let mut le = bigint.to_bytes_le();
        le.reverse();
        let mut out = [0u8; 32];
        let off = 32 - le.len().min(32);
        out[off..].copy_from_slice(&le[..le.len().min(32)]);
        out
    }

    /// Build an off-chain Poseidon-Merkle tree over `leaves`. Returns
    /// `(root, sibling_path_for_each_leaf)`. Each sibling path is
    /// bottom-up: index 0 = sibling at the leaf level.
    ///
    /// Tree shape: leaves are `Poseidon(leaf_index, leaf_value)`. The
    /// number of leaves must be a power of two.
    fn build_merkle_tree(leaves: &[Fr]) -> (Fr, Vec<Vec<Fr>>) {
        assert!(
            leaves.len().is_power_of_two(),
            "test fixture must have power-of-two leaves; got {}",
            leaves.len()
        );

        // Hash each leaf as `Poseidon(index, value)`.
        let mut nodes: Vec<Fr> = leaves
            .iter()
            .enumerate()
            .map(|(i, v)| poseidon_hash(&[Fr::from(i as u64), *v]))
            .collect();
        let leaf_hashes = nodes.clone();

        // Build levels bottom-up; record each level so we can extract
        // sibling paths afterwards.
        let mut levels: Vec<Vec<Fr>> = vec![nodes.clone()];
        while nodes.len() > 1 {
            let mut next = Vec::with_capacity(nodes.len() / 2);
            for pair in nodes.chunks(2) {
                next.push(poseidon_hash(&[pair[0], pair[1]]));
            }
            levels.push(next.clone());
            nodes = next;
        }
        let root = nodes[0];

        // Extract sibling path for each leaf.
        let depth = levels.len() - 1;
        let mut paths = Vec::with_capacity(leaf_hashes.len());
        for leaf_idx in 0..leaf_hashes.len() {
            let mut path = Vec::with_capacity(depth);
            let mut idx = leaf_idx;
            for level in 0..depth {
                let sibling_idx = idx ^ 1;
                path.push(levels[level][sibling_idx]);
                idx /= 2;
            }
            paths.push(path);
        }

        (root, paths)
    }

    /// Build the wire-format input bytes for 0x0109.
    fn merkle_input(
        commitment: &Fr,
        leaf_index: u32,
        leaf_value: &Fr,
        siblings: &[Fr],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(97 + siblings.len() * 32);
        out.extend_from_slice(&fr_to_be_bytes(commitment));
        // leaf_index: zero-padded BE u32 in the low 4 bytes of a 32-byte field
        let mut idx_buf = [0u8; 32];
        idx_buf[28..32].copy_from_slice(&leaf_index.to_be_bytes());
        out.extend_from_slice(&idx_buf);
        out.extend_from_slice(&fr_to_be_bytes(leaf_value));
        out.push(siblings.len() as u8);
        for s in siblings {
            out.extend_from_slice(&fr_to_be_bytes(s));
        }
        out
    }

    fn extract_bool(out: &[u8]) -> bool {
        assert_eq!(out.len(), 32, "bool output must be 32 bytes");
        out[..31].iter().all(|&b| b == 0) && out[31] == 1
    }

    #[test]
    fn merkle_verify_accepts_valid_proof_depth_1() {
        // 2-leaf tree.
        let leaves = vec![Fr::from(10u64), Fr::from(20u64)];
        let (root, paths) = build_merkle_tree(&leaves);

        for (idx, path) in paths.iter().enumerate() {
            let value = leaves[idx];
            let input = merkle_input(&root, idx as u32, &value, path);
            let r = merkle_verify_tensor(&input, 1_000_000).unwrap();
            assert!(
                extract_bool(&r.output),
                "valid proof for leaf {} must verify",
                idx
            );
        }
    }

    #[test]
    fn merkle_verify_accepts_valid_proof_depth_3() {
        // 8-leaf tree.
        let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(100u64 + i)).collect();
        let (root, paths) = build_merkle_tree(&leaves);

        for (idx, path) in paths.iter().enumerate() {
            let input = merkle_input(&root, idx as u32, &leaves[idx], path);
            let r = merkle_verify_tensor(&input, 1_000_000).unwrap();
            assert!(
                extract_bool(&r.output),
                "valid proof for leaf {} (depth-3 tree) must verify",
                idx
            );
        }
    }

    #[test]
    fn merkle_verify_rejects_tampered_sibling() {
        let leaves = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let (root, paths) = build_merkle_tree(&leaves);

        let mut bad_path = paths[0].clone();
        bad_path[0] = Fr::from(999u64); // tamper

        let input = merkle_input(&root, 0, &leaves[0], &bad_path);
        let r = merkle_verify_tensor(&input, 1_000_000).unwrap();
        assert!(!extract_bool(&r.output), "tampered sibling must reject");
    }

    #[test]
    fn merkle_verify_rejects_wrong_leaf_index() {
        let leaves = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let (root, paths) = build_merkle_tree(&leaves);

        // Use leaf 0's value+path but claim it's at leaf 1.
        let input = merkle_input(&root, 1, &leaves[0], &paths[0]);
        let r = merkle_verify_tensor(&input, 1_000_000).unwrap();
        assert!(
            !extract_bool(&r.output),
            "wrong index (with value/path from another leaf) must reject"
        );
    }

    #[test]
    fn merkle_verify_rejects_wrong_value() {
        let leaves = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
        let (root, paths) = build_merkle_tree(&leaves);

        // Correct index + path, wrong value.
        let input = merkle_input(&root, 0, &Fr::from(999u64), &paths[0]);
        let r = merkle_verify_tensor(&input, 1_000_000).unwrap();
        assert!(!extract_bool(&r.output), "wrong value must reject");
    }

    #[test]
    fn merkle_verify_rejects_wrong_commitment() {
        let leaves = vec![Fr::from(1u64), Fr::from(2u64)];
        let (_root, paths) = build_merkle_tree(&leaves);

        let input = merkle_input(&Fr::from(0xDEADBEEFu64), 0, &leaves[0], &paths[0]);
        let r = merkle_verify_tensor(&input, 1_000_000).unwrap();
        assert!(!extract_bool(&r.output), "wrong commitment must reject");
    }

    #[test]
    fn merkle_verify_rejects_proof_depth_above_cap() {
        // Header with proof_depth = 33 (one above MAX_DEPTH=32).
        let mut input = vec![0u8; 97];
        input[96] = 33;
        // Don't bother filling siblings — parser must reject before hashing.
        let r = merkle_verify_tensor(&input, 100_000_000);
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("exceeds MAX_DEPTH"));
    }

    #[test]
    fn merkle_verify_rejects_truncated_input() {
        // Header says proof_depth = 4 but only 1 sibling provided.
        let mut input = vec![0u8; 97 + 32];
        input[96] = 4;
        let r = merkle_verify_tensor(&input, 100_000_000);
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("input length mismatch"));
    }

    #[test]
    fn merkle_verify_rejects_short_input_below_header() {
        let input = vec![0u8; 50]; // < 97
        let r = merkle_verify_tensor(&input, 100_000_000);
        assert!(r.is_err());
        assert!(format!("{}", r.unwrap_err()).contains("input too short"));
    }

    #[test]
    fn merkle_verify_gas_metering() {
        let leaves: Vec<Fr> = (0..4).map(Fr::from).collect();
        let (root, paths) = build_merkle_tree(&leaves);
        let input = merkle_input(&root, 0, &leaves[0], &paths[0]);

        // depth=2 → expected gas = 3000 + 200×2 = 3400.
        let expected_gas = gas_costs::MERKLE_VERIFY_BASE
            + gas_costs::MERKLE_VERIFY_PER_LEVEL * 2;
        assert_eq!(expected_gas, 3_400);

        let r = merkle_verify_tensor(&input, expected_gas).unwrap();
        assert_eq!(r.gas_used, expected_gas);
        assert!(extract_bool(&r.output));

        // One short → fails.
        let r2 = merkle_verify_tensor(&input, expected_gas - 1);
        assert!(r2.is_err());
        assert!(format!("{}", r2.unwrap_err()).contains("Insufficient gas"));
    }

    #[test]
    fn merkle_verify_zero_depth_means_leaf_is_root() {
        // Depth-0: the leaf hash IS the root. Useful sanity for the
        // sponge-leaf-binding (leaf hash uses index too).
        let leaf_value = Fr::from(42u64);
        let leaf_hash = poseidon_hash(&[Fr::from(0u64), leaf_value]);

        let input = merkle_input(&leaf_hash, 0, &leaf_value, &[]);
        let r = merkle_verify_tensor(&input, 1_000_000).unwrap();
        assert!(extract_bool(&r.output), "depth-0 (root == leaf hash) must verify");
    }
}
