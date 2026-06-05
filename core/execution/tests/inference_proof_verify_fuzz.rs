// citrate_v0.01.1/core/execution/tests/inference_proof_verify_fuzz.rs
//
// RM-M1b WP-M1b.6 — proptest-driven fuzz harness for the 0x0108
// INFERENCE_PROOF_VERIFY wire-format parser.
//
// **Goal:** verify that the precompile NEVER panics on any input
// — short, long, malformed, all-zero, random bytes — and always
// returns either:
//   - Ok(PrecompileResult { output, gas_used, success: true }) where
//     output[31] is 0 or 1, OR
//   - Err(_) with a structured message (truncated / unknown
//     circuit_version / insufficient gas / parse failure).
//
// Panics in a precompile are catastrophic: they crash the executor
// thread mid-block and create non-determinism (some nodes panic
// before others depending on machine state). This harness is the
// belt-and-suspenders gate against that class of bug.
//
// **Note:** the proof-acceptance logic is exercised by the e2e
// tests with real proofs. This harness only fuzzes the PARSER
// and dispatcher's robustness. A proof that's structurally
// well-formed but cryptographically invalid surfaces as
// `output[31] == 0`, not as a panic.

#![cfg(feature = "halo2-substrate")]

use citrate_execution::precompiles::verify::{addresses, execute};
use citrate_execution::types::Address;
use proptest::prelude::*;

const MAX_INPUT: usize = 4096; // bound the harness; real proofs are ~5KB
const GAS_LIMIT: u64 = 500_000_000;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 1000,
        ..ProptestConfig::default()
    })]

    /// Property: 0x0108 NEVER panics on any input.
    /// It either returns Ok with a 32-byte output or Err with a
    /// structured anyhow::Error.
    #[test]
    fn precompile_0x0108_never_panics_on_arbitrary_bytes(
        input in prop::collection::vec(any::<u8>(), 0..MAX_INPUT)
    ) {
        let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
        let _ = execute(&addr, &input, GAS_LIMIT);
        // No assertion — the test body completing without panic is
        // the property. cargo test catches panics automatically.
    }

    /// Property: when input length < HEADER_LEN (104 bytes), the
    /// dispatcher must surface a Truncated-style error, never an
    /// Ok(success).
    #[test]
    fn precompile_0x0108_truncated_input_always_errors(
        input in prop::collection::vec(any::<u8>(), 0..104)
    ) {
        let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
        let r = execute(&addr, &input, GAS_LIMIT);
        prop_assert!(
            r.is_err(),
            "input of {} bytes (< 104B header) must return Err",
            input.len()
        );
    }

    /// Property: when circuit_version field (bytes 96..100, BE u32)
    /// is an UNKNOWN version (not 1 = inference, not 2 = reduced PoRep),
    /// the dispatcher must surface a structured error.
    ///
    /// PIN-P1 step (a): version 2 is now a REGISTERED circuit (reduced
    /// PoRep), so it is excluded from this "unknown version" range —
    /// it has its own happy-path + domain-separation coverage in
    /// `porep_proof_verify_e2e.rs`. The reserved PoSt version 3 stays in
    /// range (reserved-but-unimplemented ⇒ rejected as unknown). We
    /// build a 200-byte buffer with random commitments + a chosen
    /// unknown version, ensuring the >= 104B header gate is passed and
    /// the version check is the rejection point.
    #[test]
    fn precompile_0x0108_unknown_circuit_version_always_errors(
        commits in prop::array::uniform32(any::<u8>()),
        version_seed in 3u32..=u32::MAX,
        proof_bytes in prop::collection::vec(any::<u8>(), 0..256)
    ) {
        let mut wire = Vec::with_capacity(200 + proof_bytes.len());
        // Three 32-byte commitments (well-formed for the parser
        // even if they don't decode to valid Fr).
        wire.extend_from_slice(&commits);
        wire.extend_from_slice(&commits);
        wire.extend_from_slice(&commits);
        wire.extend_from_slice(&version_seed.to_be_bytes());
        wire.extend_from_slice(&40_204u32.to_be_bytes());
        wire.extend_from_slice(&proof_bytes);

        let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
        let r = execute(&addr, &wire, GAS_LIMIT);
        prop_assert!(
            r.is_err(),
            "circuit_version {} (≠ 1) must return Err, got: {:?}",
            version_seed,
            r.as_ref().map(|x| x.output[31])
        );
    }

    /// Property: when gas_limit is below INFERENCE_PROOF_VERIFY_BASE
    /// + per-byte cost, the dispatcher rejects with an "Insufficient
    /// gas" error before doing any cryptographic work.
    #[test]
    fn precompile_0x0108_insufficient_gas_always_errors(
        input in prop::collection::vec(any::<u8>(), 104..512),
        gas in 0u64..400_000
    ) {
        let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
        let r = execute(&addr, &input, gas);
        prop_assert!(
            r.is_err(),
            "gas={} (< INFERENCE_PROOF_VERIFY_BASE=500_000) must return Err",
            gas
        );
        let err_msg = r.unwrap_err().to_string();
        prop_assert!(
            err_msg.contains("Insufficient gas") || err_msg.contains("gas"),
            "error must mention gas: {}",
            err_msg
        );
    }
}
