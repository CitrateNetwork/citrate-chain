// Pins the 0x0130 decoder's proof-range overflow check at the precompile
// entry points.
//
// The existing decoder test overflows the proof OFFSET, which the word reader
// already rejects, so removing the separate `proof_start + proof_len` check
// left it green. Here the offset is valid and the proof LENGTH is u64::MAX:
// only that check stops the addition from overflowing (a panic under
// overflow-checks, which this workspace enables in every profile). Both entry
// points decode before anything else, so both are driven. Pure computation.

use citrate_execution::precompiles::commd_fold_verify::{
    decode_challenge_input, execute, execute_at,
};

/// `verifyCommDFold(bytes proof, uint256, uint256, uint256[] z0)` calldata whose
/// proof tail claims `proof_len` bytes. The offsets themselves are in range.
fn call_with_proof_len(proof_len: u64) -> Vec<u8> {
    let word = |v: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    };
    let mut input = vec![0u8; 4]; // selector (not checked by the decoder)
    input.extend_from_slice(&word(128)); // offset of proof (relative to args)
    input.extend_from_slice(&word(0)); // numSteps
    input.extend_from_slice(&word(0)); // depth
    input.extend_from_slice(&word(160)); // offset of z0
    input.extend_from_slice(&word(proof_len)); // proof length word at args[128]
    input.extend_from_slice(&word(0)); // z0 length = 0 at args[160]
    input
}

fn no_panic<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> T {
    std::panic::catch_unwind(f).unwrap_or_else(|_| {
        panic!("the decoder panicked on an oversized proof length instead of returning Err")
    })
}

#[test]
fn decoder_rejects_a_proof_length_that_overflows_the_range() {
    for len in [u64::MAX, u64::MAX - 159, u64::MAX - 100] {
        let input = call_with_proof_len(len);
        let r = no_panic(|| decode_challenge_input(&input));
        let err = r
            .expect_err("an impossible proof length must be refused")
            .to_string();
        assert!(
            err.contains("proof range overflow") || err.contains("out of range"),
            "len {len}: unexpected error: {err}"
        );
    }
}

#[test]
fn both_0x0130_entry_points_refuse_it_without_panicking() {
    let input = call_with_proof_len(u64::MAX);
    assert!(
        no_panic(|| execute(&input, u64::MAX)).is_err(),
        "legacy entry point"
    );
    assert!(
        no_panic(|| execute_at(&input, u64::MAX, true)).is_err(),
        "hardened entry point"
    );
}

#[test]
fn a_well_formed_empty_call_still_decodes() {
    let call = decode_challenge_input(&call_with_proof_len(0)).expect("empty proof decodes");
    assert!(call.proof.is_empty());
    assert!(call.z0.is_empty());
}
