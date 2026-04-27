// Aggregate regression tests for RM-B5 audit findings:
//   C-01 (CRITICAL) — AI inference precompile gating
//   M-02 (MEDIUM)   — deploy_model size guard against U256 truncation
//   L-02 (LOW)      — explicit match arms replace unsafe transmute in evm_opcodes
//   L-03 (LOW)      — challenge_to_scalar uses .expect, not .unwrap_or(ZERO)
//
// H-03 is exercised through the existing MVCC test suite plus the
// `journal.requires_serial_commit()` gate in commit.rs.

use citrate_execution::precompiles::inference::{InferenceMode, InferencePrecompile, addresses as iaddr};
use citrate_execution::types::Address;
use citrate_execution::inference::metal_runtime::MetalRuntime;
use citrate_execution::executor::Executor;
use std::sync::Arc;

fn make_inference(strict: bool) -> InferencePrecompile {
    let runtime = Arc::new(MetalRuntime::new().expect("metal runtime"));
    let p = InferencePrecompile::new(runtime);
    if strict {
        p.with_strict_inference()
    } else {
        p
    }
}

/// C-01.1: with strict-inference enabled, MODEL_INFERENCE returns
/// an error rather than running non-deterministic FP inference.
#[test]
fn c01_strict_inference_disables_model_inference_precompile() {
    let mut precompile = make_inference(true);
    let addr = Address(iaddr::MODEL_INFERENCE);
    let input = vec![0u8; 64];
    let result = precompile.execute(&addr, &input, 100_000);
    assert!(result.is_err(), "C-01: strict mode must disable 0x0101");
    let err_msg = match result {
        Ok(_) => panic!("expected Err"),
        Err(e) => format!("{}", e),
    };
    assert!(
        err_msg.contains("C-01") && err_msg.contains("0x0101"),
        "C-01: error must reference the finding ID and address; got {}",
        err_msg
    );
}

/// C-01.2: same gate for BATCH_INFERENCE (0x0102).
#[test]
fn c01_strict_inference_disables_batch_inference_precompile() {
    let mut precompile = make_inference(true);
    let addr = Address(iaddr::BATCH_INFERENCE);
    let input = vec![0u8; 64];
    let result = precompile.execute(&addr, &input, 100_000);
    assert!(result.is_err(), "C-01: strict mode must disable 0x0102");
    let err_msg = match result {
        Ok(_) => panic!("expected Err"),
        Err(e) => format!("{}", e),
    };
    assert!(err_msg.contains("0x0102"));
}

/// C-01.3: lenient mode (default) still allows the inference path.
/// (We call MODEL_DEPLOY rather than MODEL_INFERENCE to avoid
/// invoking actual ML hardware in CI; the gate change is path-
/// specific to the two non-deterministic addresses.)
#[test]
fn c01_lenient_mode_does_not_block_deploy_path() {
    let mut precompile = make_inference(false);
    let addr = Address(iaddr::MODEL_DEPLOY);
    // Not enough input — deploy will reject with InvalidInput.
    // What matters is we DON'T hit the C-01 gate first.
    let input = vec![0u8; 4];
    let result = precompile.execute(&addr, &input, 100_000);
    if let Err(e) = result {
        let msg = format!("{}", e);
        assert!(
            !msg.contains("C-01") && !msg.contains("disabled"),
            "C-01: deploy_model must not be C-01-gated; got {}",
            msg
        );
    }
}

/// M-02.1: deploy_model rejects forged sizes that overflow usize.
/// Pre-fix `model_size.as_u64() as usize` would silently truncate.
#[test]
fn m02_deploy_model_rejects_oversized_size_field() {
    use primitive_types::U256;
    let mut precompile = make_inference(false);
    let addr = Address(iaddr::MODEL_DEPLOY);

    // Build input with model_size = u128::MAX-equivalent (won't fit
    // in usize on this platform). Note this also implies the post-
    // truncation arithmetic could pass — the M-02 fix uses
    // checked_add to also reject the size sum.
    let model_size_u256 = U256::from(u128::MAX);
    let metadata_size_u256 = U256::from(0u64);
    let mut input = vec![0u8; 64];
    let mut size_bytes = [0u8; 32];
    model_size_u256.to_big_endian(&mut size_bytes);
    input[0..32].copy_from_slice(&size_bytes);
    metadata_size_u256.to_big_endian(&mut size_bytes);
    input[32..64].copy_from_slice(&size_bytes);

    let result = precompile.execute(&addr, &input, 1_000_000);
    assert!(
        result.is_err(),
        "M-02: oversized model_size field must be rejected"
    );
}

/// L-03.1: challenge_to_scalar.expect path is exercised at every
/// ECVRF verification. We can't directly test the panic case
/// (the C_LEN <= 16 invariant means it's unreachable under spec),
/// but we pin the structural property that ECVRF prove + verify
/// round-trips don't panic.
#[test]
fn l03_ecvrf_round_trip_does_not_panic() {
    use citrate_consensus::ecvrf;
    let mut secret = [0u8; 32];
    secret[0] = 0x77;
    secret[31] = 0x33;
    let alpha = b"test-alpha-binding";
    let (proof, beta) = ecvrf::prove(&secret, alpha).expect("prove");
    let beta_check = ecvrf::verify(alpha, &proof).expect("verify");
    assert_eq!(beta, beta_check);
}

/// L-02.1: every byte in the PUSH range round-trips through the
/// opcode decoder (no UB from a removed enum variant). Pre-fix
// l02_push_range_round_trips_safely was removed in RM-M2 WP-M2.11
// (2026-04-27) along with `core/execution/src/vm/evm_opcodes.rs`.
// The simple Citrate EVM the test exercised is no longer in the
// tree — production execution uses REVM via `revm_adapter.rs`,
// which has its own opcode safety. The L-02 finding's spirit
// (safe opcode discrimination) is now satisfied by REVM's
// well-audited dispatch.

/// REM-N-03 / WP-H1.2: the production `Executor` constructor MUST default
/// to strict-inference mode. Pre-fix, `Executor::with_chain_id` built the
/// `InferencePrecompile` via `InferencePrecompile::new()` only, leaving
/// `allow_nondeterministic_inference = true` — meaning the C-01 gate
/// shipped a mechanism but never engaged it on mainnet. This test pins
/// the production default at the API surface so the gate cannot regress
/// silently.
#[test]
fn test_rem_n_03_inference_disabled_in_production() {
    // The canonical production constructor used by `node-app/src/main.rs`
    // (via `Executor::new`) and `core/economics/src/genesis.rs` is
    // `with_chain_id`. Its production default for the inference mode
    // must be Strict.
    let mode = Executor::production_inference_mode();
    assert_eq!(
        mode,
        InferenceMode::Strict,
        "REM-N-03: production Executor must default to InferenceMode::Strict; \
         devnet must opt-in via with_chain_id_and_inference_mode"
    );

    // Belt + suspenders: build a precompile via the same construction path
    // the executor uses for production, then invoke 0x0101 directly. It
    // must short-circuit before any non-deterministic FP work runs.
    let runtime = Arc::new(MetalRuntime::new().expect("metal runtime"));
    let mut precompile = InferencePrecompile::new_with_mode(runtime, mode);
    let addr = Address(iaddr::MODEL_INFERENCE);
    let input = vec![0u8; 64];
    let result = precompile.execute(&addr, &input, 100_000);
    let err = match result {
        Ok(_) => panic!("REM-N-03: 0x0101 must be disabled under the production default"),
        Err(e) => e,
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("C-01") && msg.contains("0x0101"),
        "REM-N-03: error must reference the C-01 gate; got {}",
        msg
    );
}

/// REM-N-03 / WP-H1.2: the explicit lenient constructor must remain
/// available for devnet and tests, but it requires a deliberate opt-in.
#[test]
fn test_rem_n_03_devnet_opt_in_still_works() {
    let runtime = Arc::new(MetalRuntime::new().expect("metal runtime"));
    let p = InferencePrecompile::new_with_mode(runtime, InferenceMode::AllowNonDeterministic);
    assert!(
        !p.is_strict(),
        "REM-N-03: AllowNonDeterministic mode must yield a non-strict precompile"
    );
}

/// REM-N-03 / WP-H1.2: `is_strict()` must be a faithful predicate over
/// the gate state — guards against an inverted boolean regressing the
/// production default.
#[test]
fn test_rem_n_03_is_strict_predicate() {
    let runtime = Arc::new(MetalRuntime::new().expect("metal runtime"));
    let strict = InferencePrecompile::new_with_mode(runtime.clone(), InferenceMode::Strict);
    assert!(strict.is_strict());
    let lenient = InferencePrecompile::new_with_mode(runtime, InferenceMode::AllowNonDeterministic);
    assert!(!lenient.is_strict());
}

// l02_dup_swap_log_ranges_round_trip_safely was removed alongside
// l02_push_range_round_trips_safely in RM-M2 WP-M2.11 — same reason
// (simple Citrate EVM module deleted; production uses REVM).
