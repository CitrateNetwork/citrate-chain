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
use sha3::Digest as _;

mod poseidon;
pub use poseidon::{poseidon_config, poseidon_hash, poseidon_permute};

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

/// The `dataCommit` sponge state AFTER the fixed preamble — absorbing `[domain, len]` into the two
/// rate lanes and running one permutation — for a file of `n_leaves` leaves. This is exactly the
/// sponge state the leaf stream is folded into (the recursive prover seeds its `dataCommit` fold with
/// this, then absorbs one leaf per step). `len` is public (bound into the commitment), so this is a
/// pure function of the leaf count. Returns the full 3-lane state `[capacity, rate0, rate1]`.
pub fn data_commit_preamble_state(n_leaves: usize) -> [Fr; 3] {
    let s = poseidon_permute(&[Fr::zero(), data_commit_domain(), Fr::from(n_leaves as u64)]);
    [s[0], s[1], s[2]]
}

/// The canonical CommD of `data`: big-endian bytes of `poseidon_merkle(pack_bytes(data))`.
pub fn compute_comm_d(data: &[u8]) -> [u8; 32] {
    fr_to_be_bytes(poseidon_merkle(&pack_bytes(data)))
}

/// The `dataCommit` anchor of `data`: big-endian bytes of `poseidon_sponge(pack_bytes(data))`.
pub fn compute_data_commit(data: &[u8]) -> [u8; 32] {
    fr_to_be_bytes(poseidon_sponge(&pack_bytes(data)))
}

/// Streaming (fold-friendly) `dataCommit`, byte-identical to [`compute_data_commit`], computed the
/// way the recursive circuit does it: seed with [`data_commit_preamble_state`] (the sponge after
/// `[domain, len]` + one permutation), then absorb ONE leaf per step into the current rate lane,
/// permuting whenever a rate-pair (2 leaves) completes; finally squeeze — one extra permutation iff a
/// half-pair is pending (odd leaf count). The recursive `dataCommit` fold step mirrors this exactly,
/// so matching it here (`data_commit_streaming_matches_batch`) de-risks the circuit before it is built.
pub fn compute_data_commit_streaming(data: &[u8]) -> [u8; 32] {
    let leaves = pack_bytes(data);
    let mut state = data_commit_preamble_state(leaves.len());
    let mut pos = 0usize; // which rate lane (0 or 1) the next leaf lands in
    for leaf in &leaves {
        state[1 + pos] += leaf; // absorb = ADD into the current rate lane
        if pos == 1 {
            let p = poseidon_permute(&state);
            state = [p[0], p[1], p[2]];
            pos = 0;
        } else {
            pos = 1;
        }
    }
    // Squeeze: a pending half-pair (odd leaf count, pos==1) triggers the final permutation. An even
    // count already permuted when its last pair completed above.
    if pos == 1 {
        let p = poseidon_permute(&state);
        state = [p[0], p[1], p[2]];
    }
    fr_to_be_bytes(state[1])
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

// ─────────────────────────────────────────────────────────────────────────────
// M0 (ADR-2026-08-27 recursive path) — the FOLD-FRIENDLY streaming accumulator.
//
// The recursive proof cannot recompute the whole Merkle tree in one circuit; it folds the file in
// fixed-size steps. `IncrementalMerkle` is the off-circuit REFERENCE the fold step must mirror: a
// bounded state (`filled`, one cached left-sibling per height) updated one leaf at a time, whose
// `root()` equals the batch `poseidon_merkle` (padded-to-2^depth) exactly. Proving `insert`-then-
// `root` == the batch root (see `streaming_matches_batch`) de-risks the whole recursion: the step
// circuit is correct iff it matches this reference.
// ─────────────────────────────────────────────────────────────────────────────

/// A left-to-right append-only Poseidon-BN254 incremental Merkle tree of fixed `depth`. Empty
/// positions default to the zero-subtree roots, so after appending N ≤ 2^depth leaves the root is
/// the perfect-tree root with the rest zero — identical to `poseidon_merkle(&leaves)` when
/// `depth = ceil(log2(N))`. State is O(depth) (fold-friendly).
pub struct IncrementalMerkle {
    depth: u32,
    zeros: Vec<Fr>,  // zeros[h] = root of an all-zero subtree of height h
    filled: Vec<Fr>, // filled[h] = cached left sibling at height h for the current path
    index: u64,
    root: Fr, // running root of leaves[0..index] with the rest zero (updated per insert)
}

impl IncrementalMerkle {
    /// A tree of the given depth (all positions empty; root = the all-zero root).
    pub fn new(depth: u32) -> Self {
        let d = depth as usize;
        let mut zeros = Vec::with_capacity(d + 1);
        zeros.push(Fr::zero());
        for h in 1..=d {
            let z = zeros[h - 1];
            zeros.push(poseidon_hash(&[z, z]));
        }
        let root = zeros[d];
        Self {
            depth,
            filled: zeros.clone(),
            zeros,
            index: 0,
            root,
        }
    }

    /// Append one leaf (the fold step over a single element; a real step folds a batch). `cur` at
    /// the top of the path IS the root of the tree with this leaf placed and the remainder zero —
    /// correct for both partial and FULL trees — so we cache it (a plain re-walk breaks when full).
    pub fn insert(&mut self, leaf: Fr) {
        let _ = self.insert_returning_siblings(leaf);
    }

    /// Insert `leaf` and return the sibling value hashed with the running node at each height
    /// (`zeros[h]` when the current index bit is 0, else the cached `filled[h]`). These are exactly
    /// the witness a step circuit needs to reconstruct the new root via a `cond_swap`-per-level
    /// Merkle recompute (`SwapMerkleChip::merkle_root_generic`): `root == fold(leaf, index_bits, siblings)`.
    pub fn insert_returning_siblings(&mut self, leaf: Fr) -> Vec<Fr> {
        let mut sibs = Vec::with_capacity(self.depth as usize);
        let mut cur = leaf;
        let mut idx = self.index;
        for h in 0..self.depth as usize {
            if idx & 1 == 0 {
                sibs.push(self.zeros[h]);
                self.filled[h] = cur;
                cur = poseidon_hash(&[cur, self.zeros[h]]);
            } else {
                sibs.push(self.filled[h]);
                cur = poseidon_hash(&[self.filled[h], cur]);
            }
            idx >>= 1;
        }
        self.root = cur;
        self.index += 1;
        sibs
    }

    /// The current append index (number of leaves inserted so far).
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The root of the tree with `index` leaves appended and the rest zero.
    pub fn root(&self) -> Fr {
        self.root
    }
}

/// Streaming (fold-friendly) computation of the SAME CommD as [`compute_comm_d`], via
/// [`IncrementalMerkle`]. The recursive circuit mirrors this exactly. Degenerate `N ≤ 1` returns
/// the single leaf (matching `poseidon_merkle`, which does no hashing for a 1-element tree).
pub fn compute_comm_d_streaming(data: &[u8]) -> [u8; 32] {
    let leaves = pack_bytes(data);
    let n = leaves.len();
    if n <= 1 {
        return fr_to_be_bytes(leaves.into_iter().next().unwrap_or(Fr::zero()));
    }
    let depth = (n.next_power_of_two()).trailing_zeros();
    let mut acc = IncrementalMerkle::new(depth);
    for leaf in &leaves {
        acc.insert(*leaf);
    }
    fr_to_be_bytes(acc.root())
}

/// M1a — the combined streaming state the recursive proof folds: the Poseidon Merkle root (`commD`)
/// AND the content identity (`dataHash = keccak256(data)`, the existing IPFSIncentivesV3 field) over
/// the SAME byte stream. A valid recursive proof exposing both public outputs binds `commD` to the
/// content-identified data — the property that makes the bond sound and closes the content residual.
/// This native reference is what the step circuit (M1b) mirrors; `finalize` == (`compute_comm_d`,
/// keccak256) proven by `fold_matches_batch`.
pub struct CommDFold {
    merkle: IncrementalMerkle,
    keccak: sha3::Keccak256,
    carry: Vec<u8>, // bytes not yet forming a full 31-byte leaf (fed to the merkle at finalize)
}

impl CommDFold {
    /// Start a fold for a file of exactly `total_len` bytes (fixes the Merkle depth up front, as a
    /// real proof does — the size is known to the prover).
    pub fn new(total_len: usize) -> Self {
        let n_leaves = if total_len == 0 {
            1
        } else {
            total_len.div_ceil(BYTES_PER_LEAF)
        };
        let depth = n_leaves.next_power_of_two().trailing_zeros();
        Self {
            merkle: IncrementalMerkle::new(depth),
            keccak: sha3::Keccak256::new(),
            carry: Vec::with_capacity(BYTES_PER_LEAF),
        }
    }

    /// Fold in one batch of bytes (a proof step covers B bytes). Updates keccak over the raw bytes
    /// and inserts every completed 31-byte leaf into the Merkle accumulator.
    pub fn absorb(&mut self, bytes: &[u8]) {
        use sha3::Digest as _;
        self.keccak.update(bytes);
        self.carry.extend_from_slice(bytes);
        while self.carry.len() >= BYTES_PER_LEAF {
            let leaf = Fr::from_le_bytes_mod_order(&self.carry[..BYTES_PER_LEAF]);
            self.merkle.insert(leaf);
            self.carry.drain(..BYTES_PER_LEAF);
        }
    }

    /// Finish: (commD, dataHash). The trailing partial leaf (and the empty-input single zero leaf)
    /// are handled to match `compute_comm_d` / `keccak256` exactly.
    pub fn finalize(mut self) -> ([u8; 32], [u8; 32]) {
        use sha3::Digest as _;
        if !self.carry.is_empty() {
            let leaf = Fr::from_le_bytes_mod_order(&self.carry);
            self.merkle.insert(leaf);
        } else if self.merkle.index == 0 {
            // empty input packs to a single zero leaf (matches pack_bytes(&[])).
            self.merkle.insert(Fr::zero());
        }
        let comm_d = fr_to_be_bytes(self.merkle.root());
        let data_hash: [u8; 32] = self.keccak.finalize().into();
        (comm_d, data_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Digest as KeccakDigest; // Keccak256::digest in the fold test

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
    fn fold_matches_batch() {
        // The combined fold state (M1a) must yield BOTH the batch commD and keccak256(data), fed in
        // arbitrary batch sizes — the reference the recursive step circuit (M1b) is verified against.
        for n_bytes in [0usize, 1, 30, 31, 62, 100, 1000, 3000] {
            for batch in [1usize, 7, 31, 64, 999] {
                let data: Vec<u8> = (0..n_bytes).map(|i| (i * 13 + 5) as u8).collect();
                let mut fold = CommDFold::new(data.len());
                for chunk in data.chunks(batch) {
                    fold.absorb(chunk);
                }
                let (comm_d, data_hash) = fold.finalize();
                assert_eq!(
                    comm_d,
                    compute_comm_d(&data),
                    "fold commD != batch at {n_bytes}B / batch {batch}"
                );
                let expect_kh: [u8; 32] = sha3::Keccak256::digest(&data).into();
                assert_eq!(
                    data_hash, expect_kh,
                    "fold dataHash != keccak256 at {n_bytes}B / batch {batch}"
                );
            }
        }
    }

    #[test]
    fn streaming_matches_batch() {
        // The fold reference (M0) must produce the byte-identical CommD to the batch computation
        // for every N — this is what makes the recursive step circuit's correctness checkable.
        for n_bytes in [0usize, 1, 31, 32, 63, 100, 200, 1000, 2048, 3000] {
            let data: Vec<u8> = (0..n_bytes).map(|i| (i * 7 + 1) as u8).collect();
            assert_eq!(
                compute_comm_d_streaming(&data),
                compute_comm_d(&data),
                "streaming != batch CommD at {n_bytes} bytes"
            );
        }
    }

    #[test]
    fn data_commit_streaming_matches_batch() {
        // The per-step dataCommit model the circuit mirrors must equal the batch sponge for every N —
        // spanning odd/even leaf counts and the single-leaf case. This is the sponge analogue of
        // `streaming_matches_batch` and gates the M2b-cont binding circuit's correctness.
        for n_bytes in [0usize, 1, 30, 31, 32, 62, 63, 100, 200, 1000, 2048, 3000] {
            let data: Vec<u8> = (0..n_bytes).map(|i| (i * 11 + 3) as u8).collect();
            assert_eq!(
                compute_data_commit_streaming(&data),
                compute_data_commit(&data),
                "streaming dataCommit != batch at {n_bytes} bytes"
            );
        }
    }

    #[test]
    fn incremental_root_matches_merkle_for_partial_trees() {
        // Directly: an incremental tree of depth k with N<=2^k leaves == poseidon_merkle over the
        // same N leaves (batch pads to next_power_of_two).
        let leaves: Vec<Fr> = (1..=5u64).map(Fr::from).collect(); // N=5 -> next_pow2 8 -> depth 3
        let depth = leaves.len().next_power_of_two().trailing_zeros();
        let mut acc = IncrementalMerkle::new(depth);
        for l in &leaves {
            acc.insert(*l);
        }
        assert_eq!(acc.root(), poseidon_merkle(&leaves));
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
