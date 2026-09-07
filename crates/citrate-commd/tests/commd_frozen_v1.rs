// crates/citrate-commd/tests/commd_frozen_v1.rs
//
// FROZEN vectors for the canonical Citrate CommD (ADR-2026-08-27, citrate-chain#170).
// The byte output of `compute_comm_d` / `compute_data_commit` is a commitment substrate:
// the IPFSIncentivesV3 challenge circuit, the sealer/PoRep circuit, and the CX-S2.2 client
// all rely on it agreeing byte-for-byte. Drift in the underlying Poseidon constants, the
// 31-byte pack, the Merkle padding, or the dataCommit domain separator silently invalidates
// every CommD/dataCommit ever registered.
//
// DO NOT regenerate these to make the test pass. If a change here is intentional (a new
// CommD version), bump the crate's commitment version, publish new vectors alongside these,
// and coordinate the circuit + contract + client — a contract already deployed against v1
// vectors cannot be slashed correctly under v2.
//
// ── v2 (CHAIN-B-B006) ────────────────────────────────────────────────────────────────────
// These vectors are the v2 commitment: `pack_bytes` now appends a byte-length leaf so the
// commitment is INJECTIVE over bytes (v1 mapped the empty file, every all-zero file ≤31B,
// and any F / F‖0x00… to the SAME value, and the empty file to the 0x00..00 "absent"
// sentinel — the wrong-CommD bond was unsound). This is a HELD change: it rides the
// coordinated reroll together with the on-chain challenge circuit, the sealer/PoRep circuit,
// and the CX-S2.2 client, which must all recompute against v2. The old v1 vectors are
// retained as comments beside each case as the audit trail of the values that were unsound.

use citrate_commd::{compute_comm_d, compute_data_commit};

fn h(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

#[test]
fn commd_frozen_vectors_v2() {
    // (label, input, expected commD (v2), expected dataCommit (v2))
    let cases: &[(&str, Vec<u8>, &str, &str)] = &[
        // v1 collided empty == 31_zeros == 0x00..00; v2 distinguishes all three.
        (
            "empty",
            vec![],
            // v1 commD was 0x00..00 (== absent sentinel) — the core soundness break.
            "221b3ba83d3ba29c81faf792c0456758b3a085bcdb02254e0ab72fb22a4904f7",
            "1765de73ee6ec17e6013ee48ab97ec71f8ef5fa8f7ab35fd704af8a3912c44c0",
        ),
        (
            "one_byte_0x01",
            vec![1],
            // v1 commD was 0x00..01 (plaintext leaked as the commitment for ≤31B).
            "1a52c1c2a744f6ae53557e48efa6d62f4483338b8c415dc4a6bf81a4dbf1c4bc",
            "0746beb1bcd5f26df6b6c7187ec08853263b266099291003ab2d8d2fef896d4e",
        ),
        (
            "31_zeros",
            vec![0u8; 31],
            // v1 commD collided with empty (0x00..00); v2 binds len=31.
            "1470eeb39e0ab3667bfcb483f393a49a68148c5e61e74b6f8a589b3771650690",
            "265be5ce4909502b4067910e432af0525a3e7c70a6a735924789470d4a01ea0a",
        ),
        (
            "32_zeros",
            vec![0u8; 32],
            "232e09229a5a4b60169ff211bff7fbdca2a18f6e4f66cef2e434be1f50a7dc9a",
            "233469b1023a084188e76f616da7ce2eb33310957f1b4b397b4d30c03fcb16c1",
        ),
        (
            "hello_pin",
            b"hello pin".to_vec(),
            // v1 commD was 0x..6e6970206f6c6c6568 (the plaintext "hello pin" little-endian).
            "135ab2dc065b8ba028ada33af58513ca03b241f8096c70be71042c0b538c97ae",
            "1e563f8e1bbb82a3ee40be50e20e0ae4ee7cc5fc8aab00bc29df27c8b33114c5",
        ),
        (
            "100_incrementing",
            (0..100u32).map(|i| i as u8).collect(),
            "1fd3a6682060b92357b2f3225e84a20d53a6a145f56199dca7d98444df4219e9",
            "0fae803ef6fb71921ce5d661e79204d612d4d4660f27ba7d232be0821da754c0",
        ),
    ];
    for (label, data, commd, datacommit) in cases {
        assert_eq!(compute_comm_d(data), h(commd), "commD drift at {label}");
        assert_eq!(
            compute_data_commit(data),
            h(datacommit),
            "dataCommit drift at {label}"
        );
    }
    // The v1 soundness break, pinned as a regression: empty must never again be the
    // 0x00..00 absent-commitment sentinel, and must differ from any all-zero file.
    assert_ne!(compute_comm_d(&[]), [0u8; 32]);
    assert_ne!(compute_comm_d(&[]), compute_comm_d(&[0u8; 31]));
}
