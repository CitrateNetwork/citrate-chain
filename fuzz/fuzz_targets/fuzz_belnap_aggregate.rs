// RM-FL-1 / WP-1.7 — Belnap aggregation fuzzer.
//
// The Belnap precompile (0x0110) MUST never panic on arbitrary input
// bytes. Decode failures are fine; arithmetic surprises are fine
// (Q16 saturates); panics are not — a panic in a precompile is a
// chain-halt vector.
//
// Targets (per RM-FL-1 planset §RM-FL-1.7):
//   - Overflow (max-magnitude Q16 inputs in weighted sum)
//   - Dimension mismatch (caller-controlled dim/n)
//   - Weight = 0 edge cases
//   - Threshold-edge confidence
//   - Truncated / oversize / pathological lengths
//
// Two surfaces are fuzzed:
//   1. `belnap::aggregate(input)` directly (parses + aggregates)
//   2. `PrecompileExecutor::execute(BELNAP_AGGREGATE, input, gas)`
//      (full dispatcher path; same input can also exercise the gas
//       pre-charge / dim_hint clamp).
//
// Canonical 10M run (per planset):
//   cargo install cargo-fuzz
//   cd citrate_v0.01.1
//   cargo +nightly fuzz run fuzz_belnap_aggregate -- -runs=10000000
//
// Smaller in-session sweep is the test
// `precompiles::q16::belnap::tests::deterministic_sweep_100k_no_panic`
// in core/execution which runs 100,000 iterations under a seeded
// PRNG every workspace test run.

#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_execution::precompiles::PrecompileExecutor;
use citrate_execution::precompiles::q16::belnap;
use citrate_execution::types::Address;

fuzz_target!(|data: &[u8]| {
    // Surface 1: direct aggregate call.
    let _ = belnap::aggregate(data);

    // Surface 2: full dispatcher path.
    let mut executor = PrecompileExecutor::new();
    let addr = Address(belnap::BELNAP_AGGREGATE);
    let _ = executor.execute(&addr, data, 1_000_000);
});
