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
    // 4-leaf tree, leaves = [100, 101, 102, 103].
    // Root + sibling paths captured from the reference impl at HEAD ~01c7ab9d.
    let root = "0x137a5f3c67f58b3db5d929fbaf607db59e88d57c71c61bd556940d61e90fa0a6";

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
            "0x057dcfba52fb9ad6a6ee81da799da5c7ba26c977ef22f29d4948ea5d8390f7d2",
            "0x36ffe8e43bbbb9605833ed837f0dfb6e16ec0cd6644363c77e84a6d50bf502de",
        ],
        // leaf 1
        [
            "0x3aed6acce1fd95e3a4add627e0fae8625d82444dd189f265f90a18fba8a8ff1a",
            "0x36ffe8e43bbbb9605833ed837f0dfb6e16ec0cd6644363c77e84a6d50bf502de",
        ],
        // leaf 2
        [
            "0x054f9b833ab9ec5273752be2d687d6bcba781c641647f30dc1ee84b866015057",
            "0x70ab928a377974ca02a48b9579d475db2b8aa273959f277307040b31369a4f28",
        ],
        // leaf 3
        [
            "0x0ee5640302b91ea2636892b7a826bbef49b95dcdab4d1456a332a7e506cf9072",
            "0x70ab928a377974ca02a48b9579d475db2b8aa273959f277307040b31369a4f28",
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
