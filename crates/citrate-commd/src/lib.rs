//! citrate-commd — the canonical Citrate CommD over file bytes.
//!
//! Per `ADR-2026-08-27-pin-commd-bond-zk-challenge` (citrate-chain#170), the model-owner
//! CommD bond needs ONE `compute_comm_d(bytes) -> [u8; 32]` shared, byte-identically, by:
//!   1. the `IPFSIncentivesV3` wrong-CommD **challenge circuit** (proves `trueCommD`),
//!   2. the **sealer / PoRep** circuit (`citrate-execution`), and
//!   3. the **CX-S2.2 desktop client** (computes the CommD it registers).
//!
//! Construction (D2 = Citrate-native, keeps the 0x0108 Poseidon-BN254 circuit):
//!   * `leaves = pack_bytes(data)` — 31-byte chunks -> BN254 `Fr` (injective; no reduction),
//!   * `commD  = poseidon_merkle(leaves)` — Poseidon-BN254 binary Merkle root, leaves padded
//!     up to the next power of two with the zero element,
//!   * `dataCommit = poseidon_sponge(leaves)` — the flat sponge used as the challenge's
//!     binding anchor (an independent commitment over the same leaves; see the ADR soundness
//!     argument).
//!
//! External encoding is 32-byte **big-endian** of the field element (on-chain `bytes32`).
//! This crate is lean on purpose (ark-bn254 + Poseidon only, no halo2), so the desktop
//! client can depend on it without the proving stack.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};

mod poseidon;
pub use poseidon::{poseidon_config, poseidon_hash};

/// Bytes per leaf. 31 < ceil(BN254 modulus bits / 8) so every 31-byte chunk is strictly
/// below the field modulus and maps injectively (no modular reduction / no collisions).
pub const BYTES_PER_LEAF: usize = 31;

/// Pack arbitrary bytes into BN254 field-element leaves via 31-byte chunks. Empty input
/// yields a single zero leaf (so `compute_comm_d(&[])` is well-defined, not a panic).
/// Identical pack to `citrate-execution`'s `chunk_bytes_into_fr` / `tensor_commit`.
pub fn pack_bytes(bytes: &[u8]) -> Vec<Fr> {
    if bytes.is_empty() {
        return vec![Fr::zero()];
    }
    bytes
        .chunks(BYTES_PER_LEAF)
        .map(Fr::from_le_bytes_mod_order)
        .collect()
}

/// Poseidon-BN254 binary Merkle root over `leaves`, padded up to the next power of two
/// with the zero field element. `[]` -> zero; `[x]` -> `x`. For exactly 4 leaves this is
/// byte-identical to `citrate-execution`'s `porep::merkle_root_4` (guarded by a
/// differential test there).
pub fn poseidon_merkle(leaves: &[Fr]) -> Fr {
    if leaves.is_empty() {
        return Fr::zero();
    }
    let mut level: Vec<Fr> = leaves.to_vec();
    level.resize(level.len().next_power_of_two(), Fr::zero());
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| poseidon_hash(&[pair[0], pair[1]]))
            .collect();
    }
    level[0]
}

/// Domain separator for `dataCommit`, so the sponge can NEVER coincide with a Merkle
/// node/root (which are bare `poseidon_hash([a, b])` with no domain). Without this, a
/// small input (e.g. exactly 2 leaves) would give `dataCommit == commD`, collapsing the
/// two independent commitments the ZK-challenge soundness argument relies on. Frozen tag.
fn data_commit_domain() -> Fr {
    Fr::from_le_bytes_mod_order(b"CTZ/dataCommit/v1")
}

/// Flat Poseidon sponge over `[domain, len, leaves...]` — the `dataCommit` binding anchor
/// (ADR-2026-08-27). Domain-separated and length-bound so it is an INDEPENDENT commitment
/// from the Merkle `commD` over the same leaves; this independence is what makes the
/// wrong-CommD challenge sound (a slash requires a sponge collision — infeasible).
pub fn poseidon_sponge(leaves: &[Fr]) -> Fr {
    let mut inputs = Vec::with_capacity(leaves.len() + 2);
    inputs.push(data_commit_domain());
    inputs.push(Fr::from(leaves.len() as u64));
    inputs.extend_from_slice(leaves);
    poseidon_hash(&inputs)
}

/// The canonical CommD of `data`: big-endian bytes of `poseidon_merkle(pack_bytes(data))`.
pub fn compute_comm_d(data: &[u8]) -> [u8; 32] {
    fr_to_be_bytes(poseidon_merkle(&pack_bytes(data)))
}

/// The `dataCommit` anchor of `data`: big-endian bytes of `poseidon_sponge(pack_bytes(data))`.
pub fn compute_data_commit(data: &[u8]) -> [u8; 32] {
    fr_to_be_bytes(poseidon_sponge(&pack_bytes(data)))
}

/// Canonical BN254 `Fr` -> 32-byte big-endian (`bytes32` on-chain / uint256 public input).
pub fn fr_to_be_bytes(f: Fr) -> [u8; 32] {
    let be = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    // BN254 is 254-bit -> to_bytes_be yields <= 32 bytes; right-align into the fixed buffer.
    let start = 32 - be.len();
    out[start..].copy_from_slice(&be);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_is_31_byte_chunks_and_injective() {
        assert_eq!(pack_bytes(&[]).len(), 1); // empty -> one zero leaf
        assert_eq!(pack_bytes(&[0u8; 31]).len(), 1);
        assert_eq!(pack_bytes(&[0u8; 32]).len(), 2); // 32 bytes -> 2 leaves
        assert_eq!(pack_bytes(&[0u8; 62]).len(), 2);
        assert_eq!(pack_bytes(&[0u8; 63]).len(), 3);
    }

    #[test]
    fn merkle_edge_cases() {
        assert_eq!(poseidon_merkle(&[]), Fr::zero());
        let x = Fr::from(7u64);
        assert_eq!(poseidon_merkle(&[x]), x, "single leaf is its own root");
        // 4 leaves must equal the hand-rolled depth-2 tree (matches porep::merkle_root_4).
        let l = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let l01 = poseidon_hash(&[l[0], l[1]]);
        let l23 = poseidon_hash(&[l[2], l[3]]);
        let root = poseidon_hash(&[l01, l23]);
        assert_eq!(poseidon_merkle(&l), root);
    }

    #[test]
    fn merkle_pads_non_power_of_two() {
        // 3 leaves pad to 4 with a zero leaf: root = H(H(l0,l1), H(l2,0)).
        let l = [Fr::from(5u64), Fr::from(6u64), Fr::from(7u64)];
        let expect = poseidon_hash(&[
            poseidon_hash(&[l[0], l[1]]),
            poseidon_hash(&[l[2], Fr::zero()]),
        ]);
        assert_eq!(poseidon_merkle(&l), expect);
    }

    #[test]
    fn commd_and_datacommit_differ_and_are_deterministic() {
        let data = b"the quick brown fox jumps over the lazy dog, then pins it";
        let c1 = compute_comm_d(data);
        let c2 = compute_comm_d(data);
        assert_eq!(c1, c2, "deterministic");
        // Merkle root != flat sponge for the same leaves (the two commitments are distinct).
        assert_ne!(
            compute_comm_d(data),
            compute_data_commit(data),
            "commD (Merkle) must differ from dataCommit (sponge)"
        );
    }

    #[test]
    fn datacommit_differs_from_commd_even_for_two_leaves() {
        // Regression: for exactly 2 leaves a bare sponge == the Merkle root. The domain +
        // length separation must keep dataCommit distinct from commD at every size.
        for n in [1usize, 2, 3, 4, 8, 100] {
            let data = vec![0xABu8; n * BYTES_PER_LEAF];
            assert_ne!(
                compute_comm_d(&data),
                compute_data_commit(&data),
                "commD == dataCommit at {n} leaves — domain separation failed"
            );
        }
    }

    #[test]
    fn commd_is_collision_sensitive_to_bytes() {
        assert_ne!(compute_comm_d(b"alpha"), compute_comm_d(b"beta"));
        // a one-byte change in a later leaf changes the root
        let mut a = vec![0u8; 100];
        let mut b = a.clone();
        b[80] = 1;
        assert_ne!(compute_comm_d(&a), compute_comm_d(&b));
        a[80] = 1;
        assert_eq!(compute_comm_d(&a), compute_comm_d(&b));
    }

    #[test]
    fn fr_to_be_bytes_is_big_endian_32() {
        assert_eq!(fr_to_be_bytes(Fr::zero()), [0u8; 32]);
        let one = fr_to_be_bytes(Fr::from(1u64));
        let mut expect = [0u8; 32];
        expect[31] = 1;
        assert_eq!(one, expect, "1 -> 0x00..01 big-endian");
    }
}
