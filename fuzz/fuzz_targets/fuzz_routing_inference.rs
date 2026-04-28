// RM-FL-2 / WP-2.9 — Routing-model inference fuzzer.
//
// The routing-model precompile (0x0111) MUST never panic on arbitrary
// input bytes. Decode failures are fine; Q16 saturation is fine; gas
// rejection is fine; panics are not — a panic in a precompile is a
// chain-halt vector.
//
// Targets (per RM-FL-2 planset §FL-2.9):
//   - Malformed weights (random bytes in the W1/W2/W3 slots)
//   - Edge-case inputs (max-magnitude, all-zero, alternating)
//   - Dimension mismatches (caller-controlled dims that don't match
//     the canonical v1 shape)
//   - Version-downgrade attempts (arch_version=0, arch_version=999)
//   - Truncated / oversize / pathological lengths
//
// Two surfaces are fuzzed:
//   1. `routing::forward(input)` directly (parses + runs forward pass)
//   2. `PrecompileExecutor::execute(ROUTING_INFERENCE, input, gas)`
//      (full dispatcher + gas pre-charge path)
//
// Canonical 10M run (per planset):
//   cargo install cargo-fuzz
//   cd citrate_v0.01.1
//   cargo +nightly fuzz run fuzz_routing_inference -- -runs=10000000
//
// In-process sibling test (every workspace test invocation):
//   precompiles::q16::routing::tests::deterministic_sweep_50k_no_panic

#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_execution::precompiles::PrecompileExecutor;
use citrate_execution::precompiles::q16::routing;
use citrate_execution::types::Address;

fuzz_target!(|data: &[u8]| {
    // Surface 1: direct forward call.
    let _ = routing::forward(data);

    // Surface 2: full dispatcher path. Use a generous gas_limit so
    // we exercise the post-gas-check branches; small inputs that
    // fail decode short-circuit through the gas pre-charge anyway.
    let mut executor = PrecompileExecutor::new();
    let addr = Address(routing::ROUTING_INFERENCE);
    let _ = executor.execute(&addr, data, 10_000_000);
});
