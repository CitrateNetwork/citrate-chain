// citrate/core/execution/tests/poseidon_frozen_v1.rs
//
// **TRIPWIRE.** This test freezes the byte-level output of
// `citrate_execution::zkp::poseidon::poseidon_hash` against six
// reference test vectors. If any of these change, every commitment
// ever made via 0x0107 TENSOR_COMMIT silently shifts — which would
// invalidate every on-chain commitment and every zk proof anchored
// to those commitments. That class of regression must NEVER ship
// silently. This test is the canary.
//
// Pre-RM-M1 the Poseidon configuration in `zkp/poseidon.rs` was used
// only by ZK circuits (`zkp/inference_proof.rs` etc.). Those circuits
// produced proofs whose output bytes don't escape; a Poseidon ARK / MDS
// drift would produce verification failures that someone would notice
// during testing. With RM-M1 the Poseidon output bytes are written
// directly to the precompile return slot at 0x0107 and read by
// every contract that stores or compares commitments. A drift now
// silently changes those return bytes — contracts that stored
// commitments via the old constants would compare unequal to fresh
// commitments computed by the new constants, breaking every audit /
// dispute / verification flow that depends on a stable hash.
//
// **Procedure if this test fails:**
//
// 1. STOP. Do not "regenerate" the fixture to make the test pass.
// 2. Identify what changed: a `cargo update` of `ark-crypto-primitives`,
//    a Rust toolchain bump that affects `find_poseidon_ark_and_mds`'s
//    LFSR, or a deliberate change to `POSEIDON_CONFIG` parameters in
//    `zkp/poseidon.rs`.
// 3. Decide: is this a bug, or a deliberate Poseidon-version bump?
//    - If a bug: revert the change. The Poseidon family the chain
//      committed to is `(rate=2, capacity=1, full_rounds=8,
//      partial_rounds=56, alpha=5)` over BLS12-381 Fr.
//    - If deliberate: this requires a new commitment-scheme version
//      (e.g. allocate a new precompile address 0x0110+ for Poseidon-v2,
//      keep 0x0107 emitting v1 forever) AND a governance ADR.
// 4. ONLY after #3 is settled, update the fixture vectors below
//    AND increment the `FIXTURE_VERSION` constant AND drop a CHANGELOG
//    entry referencing the new ADR.
//
// The fixture values were derived from the implementation at
// commit `4ef90deb` (RM-M planset prep) on `rustc 1.93.0`. They are
// stable across rustc versions — `find_poseidon_ark_and_mds` is
// deterministic over its parameters, not over the toolchain — so a
// rustc upgrade is not a valid reason for the values to change.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use citrate_execution::zkp::poseidon::poseidon_hash;

const FIXTURE_VERSION: u32 = 1;

/// Convert an Fr element to a 32-byte big-endian hex string.
/// Big-endian is the on-chain convention (matches H256, ABI-encoded
/// addresses, ECRECOVER output, etc.).
fn fr_hex_be(f: &Fr) -> String {
    let bigint = f.into_bigint();
    let mut bytes_le = bigint.to_bytes_le();
    bytes_le.reverse(); // → big-endian
    // Fr fits in 32 bytes. Pad on the left if shorter.
    let mut out = [0u8; 32];
    let off = 32 - bytes_le.len().min(32);
    out[off..].copy_from_slice(&bytes_le[..bytes_le.len().min(32)]);
    format!("0x{}", hex::encode(out))
}

#[test]
fn poseidon_frozen_vectors_v1() {
    assert_eq!(FIXTURE_VERSION, 1, "fixture version must remain v1 unless a deliberate ADR-tracked bump");

    // Vector 1: empty input → field zero (sentinel for absent commitment).
    let h0 = poseidon_hash(&[]);
    assert_eq!(
        fr_hex_be(&h0),
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "poseidon_hash(empty) must remain field zero"
    );

    // Vector 2: single element [1].
    let h1 = poseidon_hash(&[Fr::from(1u64)]);
    assert_eq!(
        fr_hex_be(&h1),
        "0x34c20a907b34ed3961938d0ffbafc6390c281b21964867d9269004f9faaec44b",
        "poseidon_hash([1]) drifted — see procedure at top of file"
    );

    // Vector 3: two-element [1, 2] — exercises the rate=2 absorb boundary.
    let h12 = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64)]);
    assert_eq!(
        fr_hex_be(&h12),
        "0x43fe5dfa886bfae59d015ed8b2a8c9328230f299203c89b9c78d8b40ccdc7dda",
        "poseidon_hash([1,2]) drifted"
    );

    // Vector 4: three elements [1, 2, 3] — straddles a permutation.
    let h123 = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
    assert_eq!(
        fr_hex_be(&h123),
        "0x2d7416f0ce6a84704cf2f1b0d33a2c571aa5b99edd9bab02aa9f8c41ea547b37",
        "poseidon_hash([1,2,3]) drifted"
    );

    // Vector 5: order sensitivity — [2, 1] differs from [1, 2].
    let h21 = poseidon_hash(&[Fr::from(2u64), Fr::from(1u64)]);
    assert_eq!(
        fr_hex_be(&h21),
        "0x6d63a6a0a8d5cd4665685e86f0ad989330b9270eba69fa0976d2d5b85325b857",
        "poseidon_hash([2,1]) drifted"
    );
    assert_ne!(
        fr_hex_be(&h21),
        fr_hex_be(&h12),
        "poseidon_hash([2,1]) must differ from poseidon_hash([1,2])"
    );

    // Vector 6: large input (10 elements) — exercises multi-permutation sponge.
    let big: Vec<Fr> = (1u64..=10).map(Fr::from).collect();
    let h_big = poseidon_hash(&big);
    assert_eq!(
        fr_hex_be(&h_big),
        "0x525086aa56c0a5b5e74e2ea00209975296d84b339d03434cb118bd65d092a816",
        "poseidon_hash([1..=10]) drifted"
    );

    // Determinism: same input → same output, twice.
    let h12_again = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64)]);
    assert_eq!(
        fr_hex_be(&h12), fr_hex_be(&h12_again),
        "poseidon_hash is non-deterministic — STOP"
    );
}
