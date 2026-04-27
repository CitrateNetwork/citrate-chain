// citrate/core/execution/tests/merkle_verify_frozen_v1.rs
//
// **TRIPWIRE.** Locks the byte-level output of `0x0109
// MERKLE_VERIFY_TENSOR` against a 4-leaf reference tree.
//
// 0x0109 chains:
//   1. parse the wire format (97-byte header + sibling list)
//   2. leaf hash = Poseidon(leaf_index_as_fr, leaf_value)
//   3. walk path bottom-up, alternating left/right by leaf-index bits
//   4. compare reconstructed root to commitment
//
// Each step has unit-test coverage in `precompiles::verify::tests`;
// this file locks the END-TO-END byte output of valid + invalid
// fixtures so a future contributor can't change the path-walk
// direction (left/right alternation), the leaf-hash construction
// (index || value), or the output shape (32-byte 0/1 word) without
// being caught.
//
// **Procedure on failure:** see poseidon_frozen_v1.rs's procedure
// block. Same rules: never regenerate to make pass; identify the
// cause; if deliberate, allocate a new precompile and keep 0x0109
// emitting v1 forever.

use citrate_execution::precompiles::verify::merkle_verify_tensor;

/// Build the wire-format input (matches verify.rs::tests::merkle_input).
fn merkle_input_hex(
    commitment_hex: &str,
    leaf_index: u32,
    leaf_value_hex: &str,
    siblings_hex: &[&str],
) -> Vec<u8> {
    let commitment = hex::decode(commitment_hex.trim_start_matches("0x")).unwrap();
    assert_eq!(commitment.len(), 32);
    let leaf_value = hex::decode(leaf_value_hex.trim_start_matches("0x")).unwrap();
    assert_eq!(leaf_value.len(), 32);

    let mut out = Vec::with_capacity(97 + siblings_hex.len() * 32);
    out.extend_from_slice(&commitment);
    let mut idx = [0u8; 32];
    idx[28..32].copy_from_slice(&leaf_index.to_be_bytes());
    out.extend_from_slice(&idx);
    out.extend_from_slice(&leaf_value);
    out.push(siblings_hex.len() as u8);
    for s in siblings_hex {
        let sib = hex::decode(s.trim_start_matches("0x")).unwrap();
        assert_eq!(sib.len(), 32);
        out.extend_from_slice(&sib);
    }
    out
}

/// Big-endian Fr encoding of a u64. Mirrors how the wire format
/// expects field elements.
fn u64_as_be_bytes_32(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

#[test]
fn merkle_verify_frozen_4_leaf_tree_v1() {
    // 4-leaf tree, leaves = [100, 101, 102, 103]. **BN254 Fr**
    // (RM-M1b WP-M1b.3 migration; v1 BLS12-381 hashes are in
    // git history at commit 97b828ab).
    let root = "0x129aeadd5df2aef48856bcbbf814a616e2f084314a9eda1d0dead1e20a46167c";

    // Leaf values as 32-byte big-endian u64s.
    let leaf_values = [
        format!("0x{}", hex::encode(u64_as_be_bytes_32(100))),
        format!("0x{}", hex::encode(u64_as_be_bytes_32(101))),
        format!("0x{}", hex::encode(u64_as_be_bytes_32(102))),
        format!("0x{}", hex::encode(u64_as_be_bytes_32(103))),
    ];

    let paths = [
        // leaf 0
        [
            "0x0ab59ff4a0e6c38bec2c8cab5d66f766c4117eb394fee9665239d62cb0c30f3c",
            "0x1687b2f746f7ab9bc635713fb7b2490dd973d6afe014ee522f145e26e506fd14",
        ],
        // leaf 1
        [
            "0x1ed40e00f8476dfc6a27d8cfd8a72b32940cf92065db6c9bda31391d8c9cc510",
            "0x1687b2f746f7ab9bc635713fb7b2490dd973d6afe014ee522f145e26e506fd14",
        ],
        // leaf 2
        [
            "0x197106d2802ce0bb82ba16ce2f6934d274ea26aac4e380b03ced9571efd67eed",
            "0x15ff70245acce3c47e450ee6955a4b0e55661c8975ccc6aa8959c60be1a79997",
        ],
        // leaf 3
        [
            "0x2e1a24b8daaf4d92fb8fa9bda069950a1812d8454bfd349503cfa83595e2d6cd",
            "0x15ff70245acce3c47e450ee6955a4b0e55661c8975ccc6aa8959c60be1a79997",
        ],
    ];

    // All four leaves must verify with their captured paths.
    for (i, path) in paths.iter().enumerate() {
        let input = merkle_input_hex(root, i as u32, &leaf_values[i], path);
        let r = merkle_verify_tensor(&input, 1_000_000).unwrap();
        let expected: [u8; 32] = {
            let mut out = [0u8; 32];
            out[31] = 1;
            out
        };
        assert_eq!(
            r.output[..],
            expected[..],
            "leaf {} valid path must produce frozen 0x...01 output",
            i
        );
    }

    // Invalid: leaf 0 value with leaf 1 path → must produce frozen 0x...00.
    let bad = merkle_input_hex(root, 0, &leaf_values[0], &paths[1]);
    let r_bad = merkle_verify_tensor(&bad, 1_000_000).unwrap();
    assert_eq!(r_bad.output, vec![0u8; 32], "invalid path must produce frozen all-zero output");

    // Invalid: tampered root → must produce frozen 0x...00.
    let tampered_root = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let bad2 = merkle_input_hex(tampered_root, 0, &leaf_values[0], &paths[0]);
    let r_bad2 = merkle_verify_tensor(&bad2, 1_000_000).unwrap();
    assert_eq!(
        r_bad2.output,
        vec![0u8; 32],
        "tampered root must produce frozen all-zero output"
    );
}
