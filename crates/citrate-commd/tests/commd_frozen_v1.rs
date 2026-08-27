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

use citrate_commd::{compute_comm_d, compute_data_commit};

fn h(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

#[test]
fn commd_frozen_vectors_v1() {
    // (label, input, expected commD, expected dataCommit)
    let cases: &[(&str, Vec<u8>, &str, &str)] = &[
        // empty and 31 zero bytes both pack to a single zero leaf -> identical (documented).
        (
            "empty",
            vec![],
            "0000000000000000000000000000000000000000000000000000000000000000",
            "294d5514bcdc323b146ef99c58c637945d2d3b43a5cb5efc0b0c057c36f28d3a",
        ),
        (
            "one_byte_0x01",
            vec![1],
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0403682fea89ee0ec92726d683e023ebd8c5b78f6ab3098175e81455620f48b7",
        ),
        (
            "31_zeros_one_leaf",
            vec![0u8; 31],
            "0000000000000000000000000000000000000000000000000000000000000000",
            "294d5514bcdc323b146ef99c58c637945d2d3b43a5cb5efc0b0c057c36f28d3a",
        ),
        (
            "32_zeros_two_leaves",
            vec![0u8; 32],
            "221b3ba83d3ba29c81faf792c0456758b3a085bcdb02254e0ab72fb22a4904f7",
            "1765de73ee6ec17e6013ee48ab97ec71f8ef5fa8f7ab35fd704af8a3912c44c0",
        ),
        (
            "hello_pin",
            b"hello pin".to_vec(),
            "00000000000000000000000000000000000000000000006e6970206f6c6c6568",
            "2b0894c438660404477b872ced1b10a5ebc3d83263238cb38eae09355c202d7f",
        ),
        (
            "100_incrementing",
            (0..100u32).map(|i| i as u8).collect(),
            "02765621f5f7e5c569458c89aff1f46adf4d6bf58a135d66eb2dc9c3a6e64290",
            "03f2fcdf67adea13e3d76eed02265bc432473b09c5bd89d26b7d6a275ffe1216",
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
}
