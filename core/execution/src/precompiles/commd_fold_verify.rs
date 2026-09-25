// 0x0130 FOLD_COMMD_VERIFY — the recursive-fold CommD proof verifier precompile (citrate-chain#170,
// M3). Verifies a Nova/Spartan `CompressedSNARK` that a file's leaves fold to a canonical `commD`
// (Poseidon-BN254 Merkle root) AND a `dataCommit` (domain-separated sponge), both bound to ONE leaf
// stream. `IPFSIncentivesV3.challengeWrongCommD` calls this via the `IFoldVerifier` interface and
// slashes iff `dataCommit == reg.dataCommit` and `trueCommD != reg.commD`.
//
// FEATURE-GATED / NOT YET CONSENSUS-ACTIVE. The verifier links Nova (validated to coexist with the
// pinned PSE-halo2 stack) and embeds the SINGLE baked verifier key (see `crates/citrate-commd-fold`'s
// `bake_vk` tool) — both only under `--features commd-fold-verify`. The default build returns a
// discoverable `feature absent` error, exactly like 0x0108 without `halo2-substrate`. Enabling this
// feature is a CONSENSUS change: every node must agree, so it ships behind a coordinated activation.
//
// ADDRESS NOTE: 0x0107–0x0109 are taken (tensor-commit / halo2-proof / merkle-tensor); this new
// verification family starts at 0x0130. The Solidity side defaults `foldVerifier` to `address(0x0130)`.

use anyhow::{anyhow, Result};

use crate::precompiles::PrecompileResult;

/// 0x0130 — recursive-fold CommD proof verifier.
pub const FOLD_COMMD_VERIFY: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x30,
];

pub mod gas_costs {
    /// Base cost — Nova `CompressedSNARK` verification (Spartan sumcheck + HyperKZG opening on the
    /// primary, IPA on the secondary): several MSMs + pairings, materially heavier than 0x0108's
    /// single-pairing SHPLONK verify. Placeholder pending calibration against real verify benches.
    pub const FOLD_VERIFY_BASE: u64 = 2_000_000;
    /// Per-byte cost — transcript scanning scales with the (few-KB) proof + public-input length.
    pub const FOLD_VERIFY_PER_BYTE: u64 = 50;
}

/// The decoded `verifyCommDFold(bytes proof, uint256 numSteps, uint256 depth, uint256[] z0)` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeInput {
    pub proof: Vec<u8>,
    pub num_steps: usize,
    pub depth: usize,
    pub z0: Vec<[u8; 32]>,
}

fn word(input: &[u8], at: usize) -> Result<[u8; 32]> {
    // EXEC-01/CHAIN-B-B003: `at` is an attacker-controlled ABI offset up to usize::MAX; `at + 32`
    // must be checked or it overflows and (with `overflow-checks = true`) PANICS the validator.
    let end = at
        .checked_add(32)
        .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: word offset overflow at {at}"))?;
    input
        .get(at..end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: input truncated at word offset {at}"))
}

/// A 32-byte big-endian word as a `usize`, rejecting values that don't fit (offsets/lengths only).
fn word_as_usize(w: [u8; 32]) -> Result<usize> {
    if w[..24].iter().any(|&b| b != 0) {
        return Err(anyhow!("FOLD_COMMD_VERIFY: length/offset exceeds usize"));
    }
    Ok(u64::from_be_bytes(w[24..32].try_into().expect("8B")) as usize)
}

/// Decode the standard Solidity ABI encoding of
/// `verifyCommDFold(bytes, uint256, uint256, uint256[])` — a 4-byte selector followed by the head
/// (`offset_proof`, `numSteps`, `depth`, `offset_z0`) and the two dynamic tails. Pure + panic-free
/// (every malformed input is an `Err`), so it is unit-tested without the verifier feature.
pub fn decode_challenge_input(input: &[u8]) -> Result<ChallengeInput> {
    // 4-byte selector + 4 head words.
    if input.len() < 4 + 4 * 32 {
        return Err(anyhow!(
            "FOLD_COMMD_VERIFY: input too short for the call head"
        ));
    }
    let args = &input[4..]; // offsets in the ABI are relative to the start of the args

    let off_proof = word_as_usize(word(args, 0)?)?;
    let num_steps = word_as_usize(word(args, 32)?)?;
    let depth = word_as_usize(word(args, 64)?)?;
    let off_z0 = word_as_usize(word(args, 96)?)?;

    // proof: [len][data], data zero-padded to a multiple of 32.
    let proof_len = word_as_usize(word(args, off_proof)?)?;
    let proof_start = off_proof
        .checked_add(32)
        .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: proof offset overflow"))?;
    // EXEC-01: `proof_start + proof_len` must be checked — an attacker sets proof_len near
    // usize::MAX to overflow it (panic under overflow-checks).
    let proof_end = proof_start
        .checked_add(proof_len)
        .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: proof range overflow"))?;
    let proof = args
        .get(proof_start..proof_end)
        .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: proof bytes out of range"))?
        .to_vec();

    // z0: [len][word_0 .. word_{len-1}]. EXEC-01/CHAIN-B-B003: `z0_len` is attacker-controlled up
    // to usize::MAX; `Vec::with_capacity(z0_len)` allocates z0_len*32 bytes BEFORE the loop reads a
    // single word, so a ~100-byte tx can request a 32-TiB allocation and abort the validator. Bound
    // it to what the input can actually contain (each word is 32 bytes at off_z0 + 32) and reject a
    // length that cannot fit — so the capacity hint is provably ≤ the input size.
    let z0_len = word_as_usize(word(args, off_z0)?)?;
    let z0_base = off_z0
        .checked_add(32)
        .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: z0 offset overflow"))?;
    let z0_bytes = z0_len
        .checked_mul(32)
        .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: z0 length overflow"))?;
    let z0_end = z0_base
        .checked_add(z0_bytes)
        .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: z0 range overflow"))?;
    if z0_end > args.len() {
        return Err(anyhow!("FOLD_COMMD_VERIFY: z0 words out of range"));
    }
    let mut z0 = Vec::with_capacity(z0_len);
    for i in 0..z0_len {
        let at = off_z0
            .checked_add(32)
            .and_then(|b| b.checked_add(i.checked_mul(32)?))
            .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: z0 offset overflow"))?;
        z0.push(word(args, at)?);
    }

    Ok(ChallengeInput {
        proof,
        num_steps,
        depth,
        z0,
    })
}

/// Charge gas for a verification of `input_len` bytes; `Err` if the limit is insufficient.
fn charge_gas(input_len: usize, gas_limit: u64) -> Result<u64> {
    let gas_used = gas_costs::FOLD_VERIFY_BASE
        .saturating_add(gas_costs::FOLD_VERIFY_PER_BYTE.saturating_mul(input_len as u64));
    if gas_limit < gas_used {
        return Err(anyhow!(
            "Insufficient gas for FOLD_COMMD_VERIFY: need {gas_used}, have {gas_limit}"
        ));
    }
    Ok(gas_used)
}

/// 0x0130 entry point. Decodes the challenge call, verifies the fold proof against the baked VK, and
/// returns `abi.encode(trueCommD, dataCommit)` (64 bytes). Reverts (via `Err`) on an invalid proof —
/// which the Solidity `staticcall` bubbles, so a bad proof cannot slash.
pub fn execute(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let gas_used = charge_gas(input.len(), gas_limit)?;
    // Decode is always compiled (and unit-tested) so the wire format is validated regardless of the
    // verifier feature.
    let call = decode_challenge_input(input)?;

    #[cfg(not(feature = "commd-fold-verify"))]
    {
        let _ = (call, gas_used);
        Err(anyhow!(
            "FOLD_COMMD_VERIFY (0x0130) requires the `commd-fold-verify` feature (Nova verifier + \
             baked VK). This is a consensus-gated activation; rebuild with --features commd-fold-verify."
        ))
    }

    #[cfg(feature = "commd-fold-verify")]
    {
        // PBA-L1a-015: verify against the baked key decoded ONCE per process
        // (it used to be bincode-deserialized from 27 MB on every call, for a
        // flat gas price). Same verification relation and results.
        let vk = baked_vk_decoded()
            .ok_or_else(|| anyhow!("FOLD_COMMD_VERIFY: baked verifier key failed to decode"))?;
        let (comm_d, data_commit) = citrate_commd_verify::verify_fold_proof_with_key(
            vk,
            &call.proof,
            call.num_steps,
            call.depth,
            &call.z0,
        )
        .map_err(|e| anyhow!("FOLD_COMMD_VERIFY invalid proof: {e}"))?;

        // abi.encode(bytes32 trueCommD, bytes32 dataCommit) — the (bytes32, bytes32) the interface returns.
        let mut output = Vec::with_capacity(64);
        output.extend_from_slice(&comm_d);
        output.extend_from_slice(&data_commit);
        Ok(PrecompileResult {
            output,
            gas_used,
            success: true,
        })
    }
}

/// PBA-L1a-015: the baked key, decoded once and shared by every call.
#[cfg(feature = "commd-fold-verify")]
fn baked_vk_decoded() -> Option<&'static citrate_commd_verify::FoldVerifierKey> {
    static VK: std::sync::OnceLock<Option<citrate_commd_verify::FoldVerifierKey>> =
        std::sync::OnceLock::new();
    VK.get_or_init(|| citrate_commd_verify::decode_verifier_key(baked_vk()).ok())
        .as_ref()
}

/// The SINGLE baked verifier key (one key verifies every file — fixed-arity circuit), committed as
/// `artifacts/commd_fold_vk.bin`. The build fails if it is missing — you cannot enable the verifier
/// without a key.
///
/// PROVENANCE (audit these — re-bake and compare to confirm the key was not tampered with):
///   * SRS: the PSE Perpetual Powers of Tau, `ppot_0080_17.ptau`
///     (sha256 `f807e065fde53f72f4bf4d57140fab85b26daa6cc95bdfec7cce93622b3a367c`), from
///     <https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/> — the community
///     ceremony (80+ contributors) trusted across the ecosystem. NOT the insecure `--dev` SRS.
///   * Baked by `crates/citrate-commd-fold`'s `bake_vk --ptau-dir <dir>` over the fixed-arity circuit.
///   * BLAKE3(commd_fold_vk.bin) = `1e20b9244a63f4323fc7b5b6e3770c586a3122e7c43e520d601edbebd6c6e2d4`.
///
/// A prover's proof only verifies against this key if it used the SAME ptau — challenger tooling must
/// build its `PublicParams` via `fixed_public_params_ptau(<same ppot dir>)`, not the dev path.
#[cfg(feature = "commd-fold-verify")]
fn baked_vk() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/artifacts/commd_fold_vk.bin"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip the ABI decoder against a hand-built `verifyCommDFold` encoding: selector + head
    /// (offset_proof, numSteps, depth, offset_z0) + the two dynamic tails. Exercises the wire format
    /// the Solidity `IFoldVerifier` produces, independent of the verifier feature.
    #[test]
    fn decodes_verify_commd_fold_abi() {
        // Build: proof = 5 bytes [1,2,3,4,5]; numSteps = 7; depth = 3; z0 = [w_a, w_b].
        let mut input = Vec::new();
        input.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // selector (ignored)

        // head: 4 words. Dynamic tails laid out after the 4 head words (offsets are arg-relative).
        let head_words = 4usize;
        let off_proof = head_words * 32; // 128
                                         // proof tail = 1 len word + ceil(5/32)=1 data word = 64 bytes → z0 starts at 128+64=192
        let off_z0 = off_proof + 32 + 32;

        let mut w = |v: usize| {
            let mut x = [0u8; 32];
            x[24..].copy_from_slice(&(v as u64).to_be_bytes());
            input.extend_from_slice(&x);
        };
        w(off_proof); // offset_proof
        w(7); // numSteps
        w(3); // depth
        w(off_z0); // offset_z0

        // proof tail: len=5, then 5 bytes zero-padded to 32.
        let mut lenw = [0u8; 32];
        lenw[31] = 5;
        input.extend_from_slice(&lenw);
        let mut data = [0u8; 32];
        data[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        input.extend_from_slice(&data);

        // z0 tail: len=2, then 2 words.
        let mut zlen = [0u8; 32];
        zlen[31] = 2;
        input.extend_from_slice(&zlen);
        let wa = [0x11u8; 32];
        let wb = [0x22u8; 32];
        input.extend_from_slice(&wa);
        input.extend_from_slice(&wb);

        let decoded = decode_challenge_input(&input).expect("decode");
        assert_eq!(decoded.proof, vec![1, 2, 3, 4, 5]);
        assert_eq!(decoded.num_steps, 7);
        assert_eq!(decoded.depth, 3);
        assert_eq!(decoded.z0, vec![wa, wb]);
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(decode_challenge_input(&[0u8; 10]).is_err());
        assert!(decode_challenge_input(&[]).is_err());
    }

    // EXEC-01 / CHAIN-B-B003: a ~130-byte call must NOT be able to halt the validator. Each of
    // these encodes an attacker-controlled offset/length that (pre-fix) overflows or over-allocates.
    fn head(off_proof: u64, off_z0: u64) -> Vec<u8> {
        let mut input = vec![0xAAu8, 0xBB, 0xCC, 0xDD]; // selector
        let mut w = |v: u64| {
            let mut x = [0u8; 32];
            x[24..].copy_from_slice(&v.to_be_bytes());
            input.extend_from_slice(&x);
        };
        w(off_proof);
        w(0); // numSteps
        w(0); // depth
        w(off_z0);
        input
    }

    #[test]
    fn decode_rejects_an_overflowing_proof_offset_without_panicking() {
        // off_proof = u64::MAX → word(args, off_proof) computes off_proof + 32, which overflows.
        // Pre-fix (overflow-checks = true) this PANICS the process = chain halt. Now it is an Err.
        let input = head(u64::MAX, 128);
        assert!(decode_challenge_input(&input).is_err());
    }

    #[test]
    fn decode_bounds_a_huge_z0_len_instead_of_allocating() {
        // A valid empty proof, then z0_len = 2^40 words (32 TiB via Vec::with_capacity pre-fix).
        // Now the length is checked against the input BEFORE any allocation → Err, no OOM.
        let off_proof = 128u64;
        let off_z0 = 128u64 + 32; // proof len word only
        let mut input = head(off_proof, off_z0);
        input.extend_from_slice(&[0u8; 32]); // proof len = 0
        let mut zlen = [0u8; 32];
        zlen[24..].copy_from_slice(&(1u64 << 40).to_be_bytes()); // z0_len = 2^40
        input.extend_from_slice(&zlen);
        let err = decode_challenge_input(&input).unwrap_err().to_string();
        assert!(err.contains("z0 words out of range"), "got: {err}");
    }

    #[test]
    fn address_is_0x0130() {
        assert_eq!(FOLD_COMMD_VERIFY[18], 0x01);
        assert_eq!(FOLD_COMMD_VERIFY[19], 0x30);
    }

    #[test]
    fn feature_absent_build_charges_gas_then_errors() {
        // Default (no feature): a well-formed call decodes but the verifier is absent → discoverable
        // error. (With the feature on, this path verifies instead — covered by the verify crate.)
        #[cfg(not(feature = "commd-fold-verify"))]
        {
            // Minimal well-formed empty-proof / empty-z0 call.
            let mut input = vec![0u8; 4];
            let mut w = |v: usize| {
                let mut x = [0u8; 32];
                x[24..].copy_from_slice(&(v as u64).to_be_bytes());
                input.extend_from_slice(&x);
            };
            w(128); // offset_proof
            w(1); // numSteps
            w(0); // depth
            w(160); // offset_z0
            input.extend_from_slice(&[0u8; 32]); // proof len 0
            input.extend_from_slice(&[0u8; 32]); // z0 len 0
            let err = execute(&input, u64::MAX).unwrap_err().to_string();
            assert!(err.contains("commd-fold-verify"), "got: {err}");
            // Insufficient gas is surfaced too.
            assert!(execute(&input, 1).is_err());
        }
    }

    /// PBA-L1a-015 regression: a call carrying a canonical initial state but a garbage proof must
    /// be rejected WITHOUT re-deserializing the 27 MB baked verifier key. Before the fix every call
    /// bincode-decoded the key first (seconds per call in a debug build) for a flat ~2M gas; now the
    /// proof is decoded first and the key is decoded once per process.
    #[cfg(feature = "commd-fold-verify")]
    #[test]
    fn l1a_015_garbage_proof_does_not_redecode_the_baked_vk() {
        let z0 = citrate_commd_verify::canonical_initial_state_be(1, 0).expect("canonical z0");
        let proof = [0xFFu8; 8];
        // ABI: selector + head(offset_proof, numSteps, depth, offset_z0) + tails.
        let mut input = vec![0u8; 4];
        let w = |buf: &mut Vec<u8>, v: usize| {
            let mut x = [0u8; 32];
            x[24..].copy_from_slice(&(v as u64).to_be_bytes());
            buf.extend_from_slice(&x);
        };
        let off_proof = 128usize;
        let off_z0 = off_proof + 32 + 32;
        w(&mut input, off_proof);
        w(&mut input, 1);
        w(&mut input, 0);
        w(&mut input, off_z0);
        w(&mut input, proof.len());
        let mut data = [0u8; 32];
        data[..proof.len()].copy_from_slice(&proof);
        input.extend_from_slice(&data);
        w(&mut input, z0.len());
        for word in &z0 {
            input.extend_from_slice(word);
        }
        // Warm-up: the first call pays the one-time key decode.
        let _ = execute(&input, u64::MAX);
        let start = std::time::Instant::now();
        for _ in 0..8 {
            let err = execute(&input, u64::MAX).expect_err("garbage proof must be rejected");
            assert!(err.to_string().contains("FOLD_COMMD_VERIFY"), "{err}");
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "8 garbage-proof calls took {elapsed:?}: the baked VK is being re-decoded per call"
        );
    }

    /// Feature-ON smoke test (the reroll gate): with `commd-fold-verify` built, `0x0130` is LIVE — it
    /// gets PAST the feature gate into the real verify path. A malformed call must fail with a
    /// decode/verify error, NOT the "feature absent" message. This is what the reroll's post-build
    /// check asserts (an eth_call to 0x0130 must not say "requires the `commd-fold-verify` feature").
    #[cfg(feature = "commd-fold-verify")]
    #[test]
    fn feature_on_reaches_the_verifier_not_the_absent_stub() {
        // A well-formed head but an empty (invalid) proof → the verifier rejects it; the point is the
        // error is NOT the feature-absent stub, proving the baked VK + Nova verifier are wired in.
        let mut input = vec![0u8; 4];
        let mut w = |v: usize| {
            let mut x = [0u8; 32];
            x[24..].copy_from_slice(&(v as u64).to_be_bytes());
            input.extend_from_slice(&x);
        };
        w(128); // offset_proof
        w(1); // numSteps
        w(0); // depth
        w(160); // offset_z0
        input.extend_from_slice(&[0u8; 32]); // proof len 0
        input.extend_from_slice(&[0u8; 32]); // z0 len 0
        let err = execute(&input, u64::MAX).unwrap_err().to_string();
        assert!(
            !err.contains("requires the `commd-fold-verify` feature"),
            "0x0130 hit the absent stub despite the feature being on: {err}"
        );
        assert!(
            err.contains("invalid proof") || err.contains("FOLD_COMMD_VERIFY"),
            "expected a verifier-path error, got: {err}"
        );
    }
}
