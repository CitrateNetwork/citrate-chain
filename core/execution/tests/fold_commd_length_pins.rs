//! Pins the 0x0130 decoder's proof-length bound at the pure-precompile entry
//! point (`precompiles::execute_pure_at`, the function the REVM bridge calls).
//!
//! The decoder's own unit tests cover an oversized proof OFFSET. A proof
//! LENGTH word near `u64::MAX` takes a different arithmetic path
//! (`proof_start + proof_len`), which no existing test reached. The call must
//! come back as an ordinary error on both sides of the activation height,
//! never as a panic.

use citrate_execution::precompiles::commd_fold_verify::FOLD_COMMD_VERIFY;
use citrate_execution::precompiles::execute_pure_at;
use citrate_execution::types::Address;

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// `verifyCommDFold(bytes proof, uint256, uint256, uint256[] z0)` with a
/// well-formed head and a proof length word of `len`.
fn call_with_proof_len(len: u64) -> Vec<u8> {
    let mut input = vec![0xAB, 0xCD, 0xEF, 0x01]; // selector (not checked)
    for v in [128u64, 1, 0, 160] {
        input.extend_from_slice(&word(v)); // head: off_proof, steps, depth, off_z0
    }
    input.extend_from_slice(&word(len)); // proof length at args[128]
    input.extend_from_slice(&word(0)); // z0 length at args[160]
    input
}

fn assert_rejected_without_panic(len: u64, hardened: bool) {
    let input = call_with_proof_len(len);
    let outcome = std::panic::catch_unwind(|| {
        execute_pure_at(&Address(FOLD_COMMD_VERIFY), &input, 30_000_000, hardened)
    });
    let result = match outcome {
        Ok(r) => r,
        Err(_) => panic!("0x0130 panicked on proof length {len:#x} (hardened={hardened})"),
    };
    let err = match result {
        Ok(r) => panic!("an out-of-range proof length must not succeed: {r:?}"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("FOLD_COMMD_VERIFY"),
        "expected a decoder error, got: {err}"
    );
}

#[test]
fn proof_length_near_u64_max_is_an_error_not_a_panic() {
    for len in [u64::MAX, u64::MAX - 159, u64::MAX - 160, u64::MAX / 2] {
        for hardened in [false, true] {
            assert_rejected_without_panic(len, hardened);
        }
    }
}
