// citrate/core/execution/tests/poseidon_bn254_frozen_v1.rs
//
// **TRIPWIRE.** Locks the byte-level output of
// `zkp::poseidon_bn254::poseidon_hash` against six reference
// vectors. Parallel to `poseidon_frozen_v1.rs` (which locks the
// BLS12-381 variant); the BN254 outputs are DIFFERENT because
// the Grain LFSR generates different ARK constants per field.
//
// **Why this matters:** 0x0107 TENSOR_COMMIT (after WP-M1b.3
// migration) hashes via this function. RM-M1b's in-circuit
// Poseidon chip will produce the same byte output for the same
// input — that's the load-bearing soundness invariant tying
// 0x0107 to 0x0108. If THIS test fails (i.e., the off-chain
// hash drifts), every 0x0107 commitment ever made is invalid
// AND the in-circuit chip's differential test will start failing
// against a moving target.
//
// **Procedure on failure:** see poseidon_frozen_v1.rs's procedure
// block — same rules apply. Don't regenerate to make the test
// pass; identify cause; deliberate Poseidon bumps require new
// commitment-scheme version (new precompile address) and a
// governance ADR.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use citrate_execution::zkp::poseidon_bn254::poseidon_hash;

const FIXTURE_VERSION: u32 = 1;

fn fr_hex_be(f: &Fr) -> String {
    let bigint = f.into_bigint();
    let mut bytes_le = bigint.to_bytes_le();
    bytes_le.reverse();
    let mut out = [0u8; 32];
    let off = 32 - bytes_le.len().min(32);
    out[off..].copy_from_slice(&bytes_le[..bytes_le.len().min(32)]);
    format!("0x{}", hex::encode(out))
}

#[test]
fn poseidon_bn254_frozen_vectors_v1() {
    assert_eq!(FIXTURE_VERSION, 1, "fixture version locked");

    // Vector 1: empty input → field zero (sentinel).
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
        "0x2af2ed1c9b2652bd81834197d0cee2fffa753302ebecf13c7984da368b272389",
        "poseidon_bn254([1]) drifted"
    );

    // Vector 3: two-element [1, 2] — exercises the rate=2 absorb boundary.
    let h12 = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64)]);
    assert_eq!(
        fr_hex_be(&h12),
        "0x01d23eabcf873cf73fb12b28cb99bc88f27e7fc4ef7076bd18462d4efc907340",
        "poseidon_bn254([1,2]) drifted"
    );

    // Vector 4: three elements [1, 2, 3] — straddles a permutation.
    let h123 = poseidon_hash(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
    assert_eq!(
        fr_hex_be(&h123),
        "0x0dcc361c9cfe7cdc5f41ca7fe536125522beefbbac44d1027ebc82806b443be7",
        "poseidon_bn254([1,2,3]) drifted"
    );

    // Vector 5: order sensitivity — [2, 1] differs from [1, 2].
    let h21 = poseidon_hash(&[Fr::from(2u64), Fr::from(1u64)]);
    assert_eq!(
        fr_hex_be(&h21),
        "0x04137b2c54dcf2586987b4c6ec555a6402d892a5fc59d394f79cfbe19c5d9b34",
        "poseidon_bn254([2,1]) drifted"
    );
    assert_ne!(
        fr_hex_be(&h21),
        fr_hex_be(&h12),
        "poseidon_bn254 must be order-sensitive"
    );

    // Vector 6: large input (10 elements) — exercises multi-permutation sponge.
    let big: Vec<Fr> = (1u64..=10).map(Fr::from).collect();
    let h_big = poseidon_hash(&big);
    assert_eq!(
        fr_hex_be(&h_big),
        "0x1e6b60e2b4acc9c474666904e77de4fc6ca36f781fbcf86fad7ff3fa5ede17f4",
        "poseidon_bn254([1..=10]) drifted"
    );
}
