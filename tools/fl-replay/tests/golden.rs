//! The golden 0x0110 vector every FL_ROUND_V1 implementation pins.
//!
//! The same input and output appear in citrate-compute-pool
//! (`training-worker/src/fl/belnap_tests.rs`, `training-coordinator/src/fl_round_tests.rs`)
//! and in `contracts/test/FederatedRoundLedger.t.sol`. The output was first
//! observed from the live precompile on a local devnet; this test pins it to
//! the kernel the precompile runs, so a kernel change that moved it would fail
//! here before it could split the implementations.

use citrate_fl_replay::{chunk_input, kernel};

const ROWS: [[i64; 4]; 3] = [
    [65536, -32768, 0, 100],
    [32768, -32768, 0, 50],
    [-16384, 16384, 0, 25],
];
const OUTPUT_HEX: &str = "0000000000006aa9ffffffffffffbfff0000000000000000000000000000003903030001";

#[test]
fn the_kernel_produces_the_golden_output() {
    let rows: Vec<&[i64]> = ROWS.iter().map(|r| r.as_slice()).collect();
    let input = chunk_input(&rows, 32768, -32768);
    assert_eq!(input.len(), 24 + 16 * 3 * 4 + 8 * 3);
    let out = kernel(&input).expect("kernel");
    assert_eq!(hex::encode(out), OUTPUT_HEX);
}

#[test]
fn the_precompile_entry_point_agrees_with_the_kernel_after_hardening() {
    let rows: Vec<&[i64]> = ROWS.iter().map(|r| r.as_slice()).collect();
    let input = chunk_input(&rows, 32768, -32768);
    let r = citrate_execution::precompiles::q16::belnap::execute_at(&input, 1_000_000, true)
        .expect("precompile");
    assert!(r.success);
    assert_eq!(hex::encode(&r.output), OUTPUT_HEX);
    // Hardened gas: 2000 + 50 * dim * n.
    assert_eq!(r.gas_used, 2000 + 50 * 4 * 3);
}
