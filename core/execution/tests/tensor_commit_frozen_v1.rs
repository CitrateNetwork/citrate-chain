// citrate/core/execution/tests/tensor_commit_frozen_v1.rs
//
// **TRIPWIRE.** This test freezes the byte-level output of
// `0x0107 TENSOR_COMMIT` against four reference tensor inputs.
//
// 0x0107 chains together:
//   1. tensor_format::decode_exact (header validation)
//   2. 31-byte chunking + Fr::from_le_bytes_mod_order (input → Fr seq)
//   3. poseidon_hash (Fr seq → Fr digest)
//   4. Fr → 32-byte big-endian
//
// Each step is independently locked elsewhere (proptest for #1,
// poseidon_frozen_v1.rs for #3). This test locks the END-TO-END
// composition. If a future contributor changes any of the steps in a
// way that shifts the byte output of the precompile (different chunk
// size, different padding scheme, different endianness), this test
// catches it.
//
// **Procedure on failure:** see poseidon_frozen_v1.rs's procedure
// block. The same rules apply: never regenerate to make the test
// pass; identify the cause; if deliberate, allocate a new precompile
// address (0x0110+) and keep 0x0107 emitting v1 forever.

use citrate_execution::precompiles::{
    tensor_format::{encode, Dtype},
    verify::tensor_commit,
};

fn q16(shape: &[u32], values: &[i32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(values.len() * 4);
    for &v in values {
        data.extend_from_slice(&v.to_le_bytes());
    }
    encode(shape, Dtype::Q16_16, &data).unwrap()
}

fn hex_be(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[test]
fn tensor_commit_frozen_vectors_v1() {
    // Vector 1: single-element Q16 vector [0].
    // BN254 Fr (RM-M1b WP-M1b.3 migration). v1 BLS12-381 hashes
    // are in git history; pre-mainnet, no production commitments
    // depended on the old hashes.
    let h1 = tensor_commit(&q16(&[1], &[0]), 1_000_000).unwrap();
    assert_eq!(
        hex_be(&h1.output),
        "0x1ce5538e037b84f02d37f2c162ca9c5268e4489e4704516766cf3917f5461618",
        "TENSOR_COMMIT(Q16, [1], [0]) drifted"
    );

    // Vector 2: small vector [1, 2, 3].
    let h2 = tensor_commit(&q16(&[3], &[1, 2, 3]), 1_000_000).unwrap();
    assert_eq!(
        hex_be(&h2.output),
        "0x2cf29c993ba8432a07811f765fada910b99cc477b56ac57b6e6197706a65a496",
        "TENSOR_COMMIT(Q16, [3], [1,2,3]) drifted"
    );

    // Vector 3: 2×2 matrix [[1,2],[3,4]].
    let h3 = tensor_commit(&q16(&[2, 2], &[1, 2, 3, 4]), 1_000_000).unwrap();
    assert_eq!(
        hex_be(&h3.output),
        "0x18dfcf46ab947af444fa6b1a025f8c4dbd4002659431a7cbe3d5660338ef88db",
        "TENSOR_COMMIT(Q16, [2,2], [1,2,3,4]) drifted"
    );

    // Vector 4: Field32 single 32-byte element (commit-of-commit usage).
    let f = encode(&[1], Dtype::Field32, &[0xAA; 32]).unwrap();
    let h4 = tensor_commit(&f, 1_000_000).unwrap();
    assert_eq!(
        hex_be(&h4.output),
        "0x1e41d834581a6bd1801f690b8dc306c85aea21825a7499fdc8decfa696176d10",
        "TENSOR_COMMIT(Field32, [1], 0xAA…) drifted"
    );
}
