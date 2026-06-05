// citrate/core/execution/src/zkp/halo2/porep.rs
//
// PIN-P1 — Stacked-DRG PoRep circuit (REDUCED instance).
//
// First code of PIN-P1. Resolves red-team BLOCKER 1.1: the seal must be
// **keyed by `replicaID` inside the labeling, per node, per layer** — not
// merely labeled afterward — so a pinner cannot reuse another pinner's
// sealed replica. Spec:
//   `.agentile/gtm-spine/design/PIN-P1-sdr-replicaid-construction.md`
//
// **Scope of THIS module — a COMPLETE, WORKING circuit for a REDUCED
// instance**, not a placeholder. The reduced topology is exactly the
// spec's "Test vectors" tiny instance:
//
//   N = 4 nodes, L = 2 layers, d_DRG = 1, d_EXP = 1.
//
// Every relation the full circuit needs (labeling keyed by replicaID,
// encoding, and Poseidon-Merkle inclusion of D/R/columns) is enforced
// in-circuit here for that reduced instance. The path to full size
// (real DRG/expander samplers, Filecoin's d_DRG≈6 / d_EXP≈8 / L=11,
// real sector size, aggregation, randomness-precompile nonce binding,
// K>1 challenges) is tracked as PIN-P1 follow-up step (c2) — NOT as
// TODOs in this code.
//
// ---------------------------------------------------------------------------
// PIN-P1 step (c) part 1 — index-agnostic circuit + parent soundness.
// ---------------------------------------------------------------------------
//
// This module was hardened in PIN-P1 step (c1) to close two gaps:
//
//   (1) SINGLE VK (kills TD-18, the per-challenge VK cache). Previously the
//       VK depended on the challenge index because (a) the Merkle branch
//       directions (`sibling_is_left`) were baked host-side into the gate
//       shape, and (b) the v=0 vs v≥1 labeling seed used a different copy
//       constraint, and `v` was a hard circuit constant. Now the challenge
//       index is a WITNESS, bit-decomposed in-circuit (boolean-constrained,
//       recompose-constrained to equal the public `challengeNonce`), and
//       each Merkle level conditionally swaps (current, sibling) using the
//       level's index bit — so ONE circuit structure verifies ANY index and
//       ONE VK suffices. See `SwapMerkleChip`.
//
//   (2) PARENT SOUNDNESS. Previously the DRG parent labels feeding the
//       labeling relation were UNCONSTRAINED witnesses: a prover could pick
//       arbitrary parent labels, derive labels/column/replica from them, and
//       build a *fresh* CommC/CommR over that garbage — the proof would
//       still pass. Now each DRG parent is proven to be the correct included
//       node: the parent's COLUMN (= Poseidon(parent_l1, parent_l2)) is
//       Merkle-included in CommC at the parent's index (drg_parent(v)=v-1,
//       same layer), via the same index-agnostic Merkle. The base case
//       (v=0, no DRG parent) is handled uniformly + soundly: a witnessed
//       `has_drg_parent` boolean is CONSTRAINED to (challengeNonce ≠ 0) by
//       an inverse-or-zero gadget; `prev_same` is mux'd to `replicaID` when
//       false, and the parent inclusion's root-equality is gated by `has`
//       so the circuit SHAPE is identical for every index (single VK).
//
// **What is reused (not re-implemented):**
//   - `PoseidonChip` (chips.rs) — the hand-rolled in-circuit Poseidon-2
//     over BN254 Fr, byte-identical to native `poseidon_bn254::poseidon_hash`.
//   - `poseidon_bn254::poseidon_hash` — native, for off-chain witness gen.
//   - The MockProver + KZG prove+verify harness pattern from `circuits.rs`.
//
// **What is net-new in step (c1):** the `SwapMerkleChip` (boolean /
// bit-decompose / conditional-swap / mux / inverse-or-zero / conditional
// equality gates), the index-agnostic Merkle inclusion, and the parent
// column inclusion. NO new Poseidon chip was needed.
//
// ---------------------------------------------------------------------------
// Reduced topology (deterministic, public params)
// ---------------------------------------------------------------------------
//
// Node indices v ∈ {0,1,2,3}. Two layers l ∈ {1,2}.
//
// DRG parents (same layer), d_DRG = 1: a chain predecessor
//   drg_parent(v) = v - 1   for v ≥ 1;   node 0 has NO same-layer parent.
// This is a depth-robust toy (a path graph): deleting any node forces
// recomputation of all successors. The full circuit replaces this with
// Filecoin's Bucket/ChungDRG sampler (PIN-P1 step (c2)).
//
// Expander parents (previous layer), d_EXP = 1:
//   exp_parent(v) = v        (node v in layer l-1).
// Layer 1 has no previous layer, so it has no expander parent.
//
// Labeling (replicaID enters EVERY label):
//   replicaID = Poseidon(pinnerIdentity, cid, sectorIndex)   // KYC-bound
//
//   Layer 1 (no previous layer, DRG parent only):
//     v = 0:  label(1,0) = Poseidon(replicaID, 1, 0, replicaID)
//     v ≥ 1:  label(1,v) = Poseidon(replicaID, 1, v, label(1, v-1))
//
//   Layer 2 (DRG parent same layer + expander parent previous layer):
//     v = 0:  label(2,0) = Poseidon(replicaID, 2, 0, replicaID,      label(1,0))
//     v ≥ 1:  label(2,v) = Poseidon(replicaID, 2, v, label(2, v-1),  label(1,v))
//
//   So every label's Poseidon preimage starts with (replicaID, l, v):
//   changing replicaID changes EVERY label (the finding-1.1 property).
//
// Encoding (data → sealed replica), L = 2:
//   R[v] = D[v] + label(2, v)   (mod p)
//
// Commitments — depth-2 binary Poseidon-Merkle over the N=4 leaves:
//   node_hash(a, b) = Poseidon(a, b)
//   CommD = root over leaves D[0..4]
//   CommR = root over leaves R[0..4]
//   CommC = root over the per-node COLUMN commitments, where
//           column(v) = Poseidon(label(1,v), label(2,v))   (L=2 column)
//
// Public inputs (instance column), in this fixed layout:
//   [0] replicaID
//   [1] cid
//   [2] sectorIndex
//   [3] CommD
//   [4] CommR
//   [5] CommC
//   [6] challengeNonce      (challenged node index v*, WITNESSED + bound)
//   [7] epoch

#![allow(clippy::too_many_arguments)]

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr as Halo2Fr;
use halo2curves::ff::{Field as _, PrimeField as _};

use super::chips::{PoseidonChip, PoseidonChipConfig};
use crate::zkp::poseidon_bn254::poseidon_hash;

// ---------------------------------------------------------------------------
// Reduced-instance constants (public params).
// ---------------------------------------------------------------------------

/// Nodes in the reduced sector.
pub const N: usize = 4;
/// Layers in the reduced SDR.
pub const L: usize = 2;
/// Merkle depth for N=4 leaves (binary): log2(4) = 2.
pub const MERKLE_DEPTH: usize = 2;

/// Public-input slot indices (the documented layout above).
pub mod pi {
    pub const REPLICA_ID: usize = 0;
    pub const CID: usize = 1;
    pub const SECTOR_INDEX: usize = 2;
    pub const COMM_D: usize = 3;
    pub const COMM_R: usize = 4;
    pub const COMM_C: usize = 5;
    pub const CHALLENGE_NONCE: usize = 6;
    pub const EPOCH: usize = 7;
    /// Total number of public inputs exposed by the reduced PoRep circuit.
    pub const COUNT: usize = 8;
}

// ---------------------------------------------------------------------------
// Native witness builder — the off-chain "sealing" of a reduced replica.
// ---------------------------------------------------------------------------

/// A fully-sealed reduced replica: all the field values the circuit's
/// public inputs and witnesses are derived from.
#[derive(Clone, Debug)]
pub struct SealedReplica {
    pub replica_id: Halo2Fr,
    pub cid: Halo2Fr,
    pub sector_index: Halo2Fr,
    pub epoch: Halo2Fr,
    /// Unsealed data, one Fr per node.
    pub data: [Halo2Fr; N],
    /// Sealed replica, R[v] = D[v] + label(L, v).
    pub replica: [Halo2Fr; N],
    /// labels[l-1][v] = label(l, v). Outer index is layer-1 (0-based).
    pub labels: [[Halo2Fr; N]; L],
    /// Per-node column commitment, column(v) = Poseidon(label(1,v), label(2,v)).
    pub columns: [Halo2Fr; N],
    pub comm_d: Halo2Fr,
    pub comm_r: Halo2Fr,
    pub comm_c: Halo2Fr,
}

/// DRG (same-layer) parent rule for the reduced instance: a path graph.
/// Returns `Some(v-1)` for v ≥ 1, `None` for v = 0.
#[inline]
pub fn drg_parent(v: usize) -> Option<usize> {
    if v == 0 {
        None
    } else {
        Some(v - 1)
    }
}

/// Expander (previous-layer) parent rule for the reduced instance:
/// identity. Node v in layer l draws from node v in layer l-1.
#[inline]
pub fn exp_parent(v: usize) -> usize {
    v
}

/// Native Poseidon over halo2 Fr inputs, routed through the ark field so
/// the output is byte-identical to the in-circuit `PoseidonChip`.
fn native_hash(inputs: &[Halo2Fr]) -> Halo2Fr {
    use ark_bn254::Fr as ArkFr;
    use ark_ff::PrimeField as _;
    let ark_inputs: Vec<ArkFr> = inputs
        .iter()
        .map(|h| ArkFr::from_le_bytes_mod_order(h.to_repr().as_ref()))
        .collect();
    let out = poseidon_hash(&ark_inputs);
    // ArkFr → Halo2Fr via canonical LE bytes.
    use ark_ff::BigInteger as _;
    let mut le = out.into_bigint().to_bytes_le();
    le.resize(32, 0);
    let arr: [u8; 32] = le.try_into().expect("32 bytes");
    Option::<Halo2Fr>::from(Halo2Fr::from_repr(arr.into())).expect("canonical Fr")
}

/// The fixed-arity labeling preimage for `label(l, v)`. Returns the exact
/// input vector to Poseidon, matching the spec formula and the in-circuit
/// `label_in_circuit` layout.
fn label_preimage(
    replica_id: Halo2Fr,
    layer: usize,
    v: usize,
    prev_same: Halo2Fr,
    prev_layer: Option<Halo2Fr>,
) -> Vec<Halo2Fr> {
    let layer_fr = Halo2Fr::from(layer as u64);
    let v_fr = Halo2Fr::from(v as u64);
    match prev_layer {
        // Layer 1: Poseidon(replicaID, l, v, prev_same)
        None => vec![replica_id, layer_fr, v_fr, prev_same],
        // Layer ≥2: Poseidon(replicaID, l, v, prev_same, prev_layer)
        Some(pl) => vec![replica_id, layer_fr, v_fr, prev_same, pl],
    }
}

/// Compute the Merkle root of 4 leaves with the depth-2 binary
/// Poseidon-Merkle (node_hash = Poseidon(left, right)). Returns the root.
fn merkle_root_4(leaves: &[Halo2Fr; N]) -> Halo2Fr {
    let l01 = native_hash(&[leaves[0], leaves[1]]);
    let l23 = native_hash(&[leaves[2], leaves[3]]);
    native_hash(&[l01, l23])
}

/// The Merkle authentication path for `leaf_index` in a depth-2 binary
/// tree of 4 leaves. Returns just the sibling VALUES from leaf level up to
/// (but excluding) the root — the directions are derived IN-CIRCUIT from
/// the witnessed index bits (no host-side `is_left` baked into the VK).
pub fn merkle_siblings_4(leaves: &[Halo2Fr; N], leaf_index: usize) -> [Halo2Fr; MERKLE_DEPTH] {
    debug_assert!(leaf_index < N);
    let l01 = native_hash(&[leaves[0], leaves[1]]);
    let l23 = native_hash(&[leaves[2], leaves[3]]);
    // Level 0 sibling (within the pair).
    let sib0 = if leaf_index % 2 == 0 {
        leaves[leaf_index + 1]
    } else {
        leaves[leaf_index - 1]
    };
    // Level 1 sibling (the other internal node).
    let sib1 = if leaf_index < 2 { l23 } else { l01 };
    [sib0, sib1]
}

// Test-only re-exports of the native primitives so sibling circuit tests
// (e.g. post.rs's parent-forgery negative) can reconstruct forged witnesses
// using the SAME Poseidon/Merkle the seal uses.
#[cfg(test)]
pub(crate) fn label_hash_for_test(
    replica_id: Halo2Fr,
    layer: usize,
    v: usize,
    prev_same: Halo2Fr,
    prev_layer: Option<Halo2Fr>,
) -> Halo2Fr {
    native_hash(&label_preimage(replica_id, layer, v, prev_same, prev_layer))
}

#[cfg(test)]
pub(crate) fn pair_hash_for_test(a: Halo2Fr, b: Halo2Fr) -> Halo2Fr {
    native_hash(&[a, b])
}

#[cfg(test)]
pub(crate) fn merkle_root_4_for_test(leaves: &[Halo2Fr; N]) -> Halo2Fr {
    merkle_root_4(leaves)
}

/// Seal a reduced replica from `data` and the identity tuple. This is the
/// authoritative native computation; the circuit must reproduce it.
pub fn seal_reduced(
    pinner_identity: Halo2Fr,
    cid: Halo2Fr,
    sector_index: Halo2Fr,
    epoch: Halo2Fr,
    data: [Halo2Fr; N],
) -> SealedReplica {
    // replicaID = Poseidon(pinnerIdentity, cid, sectorIndex)
    let replica_id = native_hash(&[pinner_identity, cid, sector_index]);

    // Labeling.
    let mut labels = [[Halo2Fr::from(0u64); N]; L];
    for layer in 1..=L {
        for v in 0..N {
            let prev_same = match drg_parent(v) {
                Some(p) => labels[layer - 1][p],
                None => replica_id, // seed slot for v=0 (bound to replicaID)
            };
            let prev_layer = if layer >= 2 {
                Some(labels[layer - 2][exp_parent(v)])
            } else {
                None
            };
            let preimage = label_preimage(replica_id, layer, v, prev_same, prev_layer);
            labels[layer - 1][v] = native_hash(&preimage);
        }
    }

    // Encoding: R[v] = D[v] + label(L, v).
    let mut replica = [Halo2Fr::from(0u64); N];
    for v in 0..N {
        replica[v] = data[v] + labels[L - 1][v];
    }

    // Columns: column(v) = Poseidon(label(1,v), label(2,v)).
    let mut columns = [Halo2Fr::from(0u64); N];
    for v in 0..N {
        columns[v] = native_hash(&[labels[0][v], labels[1][v]]);
    }

    let comm_d = merkle_root_4(&data);
    let comm_r = merkle_root_4(&replica);
    let comm_c = merkle_root_4(&columns);

    SealedReplica {
        replica_id,
        cid,
        sector_index,
        epoch,
        data,
        replica,
        labels,
        columns,
        comm_d,
        comm_r,
        comm_c,
        // pinner_identity is intentionally NOT stored: it is the private
        // pre-image of replica_id and never leaves the witness.
    }
}

// ===========================================================================
// SwapMerkleChip — the index-agnostic arithmetic gadget (step (c1)).
// ===========================================================================
//
// A small fixed set of advice columns + selectors that, together with the
// shared `PoseidonChip`, give us EVERYTHING the single-VK + parent-sound
// construction needs, with a circuit shape that does NOT depend on the
// challenge index:
//
//   * boolean constraint            b·(1−b) = 0
//   * 2-bit recompose               idx = b0 + 2·b1
//   * conditional swap              (lo,hi) = b ? (sib,cur) : (cur,sib)
//   * 2-to-1 mux                    out = b ? y : x
//   * inverse-or-zero "is-nonzero"  has = (idx ≠ 0), soundly
//   * gated equality                sel·(a − b) = 0
//
// All gates are degree ≤ 3. The columns are reused across every region.

/// Shared arithmetic config for the index-agnostic Merkle + parent gadget.
#[derive(Clone, Debug)]
pub struct SwapMerkleConfig {
    /// Three general-purpose advice columns the gadget gates read at
    /// `Rotation::cur()`. They are equality-enabled so results copy out.
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    /// `s_bool·b·(1−b)` — boolean-constrains the cell in column `b`.
    s_bool: Selector,
    /// `s_recompose·(a − (b + 2·c))` — a = b + 2·c (2-bit recompose).
    s_recompose: Selector,
    /// Conditional swap: with bit in `c`, value pair in... handled by two
    /// selectors over a 2-row region; see `cond_swap`.
    s_swap_lo: Selector,
    s_swap_hi: Selector,
    /// `s_mux·(out − ((1−bit)·x + bit·y))`.
    s_mux: Selector,
    /// `s_ioz_a·(idx·inv − has)` and `s_ioz_b·((1−has)·idx)`.
    s_ioz_a: Selector,
    s_ioz_b: Selector,
    /// `s_geq·(sel·(lhs − rhs))` — gated equality.
    s_geq: Selector,
}

impl SwapMerkleConfig {
    /// Configure the gadget's advice columns + gates.
    pub fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        for col in [a, b, c] {
            meta.enable_equality(col);
        }
        // Fixed column for pinning true constants (used by `add_one` so the
        // `1/2` factor cannot be tampered).
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let s_bool = meta.selector();
        let s_recompose = meta.selector();
        let s_swap_lo = meta.selector();
        let s_swap_hi = meta.selector();
        let s_mux = meta.selector();
        let s_ioz_a = meta.selector();
        let s_ioz_b = meta.selector();
        let s_geq = meta.selector();

        // boolean: b·(1−b) = 0, read on column `b`.
        meta.create_gate("swapmerkle_bool", |meta| {
            let s = meta.query_selector(s_bool);
            let bit = meta.query_advice(b, Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Halo2Fr::ONE);
            vec![s * bit.clone() * (one - bit)]
        });

        // recompose: a = b + 2·c  (idx = bit0 + 2·bit1).
        meta.create_gate("swapmerkle_recompose", |meta| {
            let s = meta.query_selector(s_recompose);
            let idx = meta.query_advice(a, Rotation::cur());
            let b0 = meta.query_advice(b, Rotation::cur());
            let b1 = meta.query_advice(c, Rotation::cur());
            let two = halo2_proofs::plonk::Expression::Constant(Halo2Fr::from(2u64));
            vec![s * (idx - (b0 + two * b1))]
        });

        // conditional swap, expressed across two rows of one region:
        //   row 0: a=cur, b=sib, c=bit
        //   row 1: a=lo,  b=hi
        // lo = bit ? sib : cur = cur + bit·(sib − cur)
        // hi = bit ? cur : sib = sib + bit·(cur − sib) = cur + sib − lo
        meta.create_gate("swapmerkle_swap_lo", |meta| {
            let s = meta.query_selector(s_swap_lo);
            let cur = meta.query_advice(a, Rotation::cur());
            let sib = meta.query_advice(b, Rotation::cur());
            let bit = meta.query_advice(c, Rotation::cur());
            let lo = meta.query_advice(a, Rotation::next());
            // lo − (cur + bit·(sib − cur)) = 0
            vec![s * (lo - (cur.clone() + bit * (sib - cur)))]
        });
        meta.create_gate("swapmerkle_swap_hi", |meta| {
            let s = meta.query_selector(s_swap_hi);
            let cur = meta.query_advice(a, Rotation::cur());
            let sib = meta.query_advice(b, Rotation::cur());
            let lo = meta.query_advice(a, Rotation::next());
            let hi = meta.query_advice(b, Rotation::next());
            // hi − (cur + sib − lo) = 0
            vec![s * (hi - (cur + sib - lo))]
        });

        // mux: out = (1−bit)·x + bit·y, layout a=x, b=y, c=bit, out at a@next.
        meta.create_gate("swapmerkle_mux", |meta| {
            let s = meta.query_selector(s_mux);
            let x = meta.query_advice(a, Rotation::cur());
            let y = meta.query_advice(b, Rotation::cur());
            let bit = meta.query_advice(c, Rotation::cur());
            let out = meta.query_advice(a, Rotation::next());
            let one = halo2_proofs::plonk::Expression::Constant(Halo2Fr::ONE);
            // out − ((1−bit)·x + bit·y) = 0
            vec![s * (out - ((one - bit.clone()) * x + bit * y))]
        });

        // inverse-or-zero, part a: idx·inv − has = 0, layout a=idx, b=inv, c=has.
        meta.create_gate("swapmerkle_ioz_a", |meta| {
            let s = meta.query_selector(s_ioz_a);
            let idx = meta.query_advice(a, Rotation::cur());
            let inv = meta.query_advice(b, Rotation::cur());
            let has = meta.query_advice(c, Rotation::cur());
            vec![s * (idx * inv - has)]
        });
        // inverse-or-zero, part b: (1−has)·idx = 0, layout a=idx, c=has.
        meta.create_gate("swapmerkle_ioz_b", |meta| {
            let s = meta.query_selector(s_ioz_b);
            let idx = meta.query_advice(a, Rotation::cur());
            let has = meta.query_advice(c, Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Halo2Fr::ONE);
            vec![s * (one - has) * idx]
        });

        // gated equality: sel·(lhs − rhs) = 0, layout a=lhs, b=rhs, c=sel.
        meta.create_gate("swapmerkle_geq", |meta| {
            let s = meta.query_selector(s_geq);
            let lhs = meta.query_advice(a, Rotation::cur());
            let rhs = meta.query_advice(b, Rotation::cur());
            let sel = meta.query_advice(c, Rotation::cur());
            vec![s * sel * (lhs - rhs)]
        });

        SwapMerkleConfig {
            a,
            b,
            c,
            s_bool,
            s_recompose,
            s_swap_lo,
            s_swap_hi,
            s_mux,
            s_ioz_a,
            s_ioz_b,
            s_geq,
        }
    }

    /// Witness `idx` and its 2 bits, boolean-constrain each bit, and
    /// recompose-constrain `idx = bit0 + 2·bit1`. Returns the idx cell and
    /// the per-level bit cells (low bit first) for the conditional swaps.
    pub(crate) fn decompose_index(
        &self,
        layouter: &mut impl Layouter<Halo2Fr>,
        idx: Value<Halo2Fr>,
    ) -> Result<
        (
            AssignedCell<Halo2Fr, Halo2Fr>,
            [AssignedCell<Halo2Fr, Halo2Fr>; MERKLE_DEPTH],
        ),
        ErrorFront,
    > {
        let bit_vals: [Value<Halo2Fr>; MERKLE_DEPTH] = {
            // Extract the two low bits from the (canonical, small) index.
            let low = idx.map(|f| f.to_repr().as_ref()[0]);
            [
                low.map(|byte| Halo2Fr::from((byte & 1) as u64)),
                low.map(|byte| Halo2Fr::from(((byte >> 1) & 1) as u64)),
            ]
        };
        layouter.assign_region(
            || "decompose_index",
            |mut region| {
                let idx_cell = region.assign_advice(|| "idx", self.a, 0, || idx)?;
                let b0 = region.assign_advice(|| "bit0", self.b, 0, || bit_vals[0])?;
                let b1 = region.assign_advice(|| "bit1", self.c, 0, || bit_vals[1])?;
                // recompose: idx = bit0 + 2·bit1.
                self.s_recompose.enable(&mut region, 0)?;
                // boolean-constrain bit0 (on column b @ row 0).
                self.s_bool.enable(&mut region, 0)?;
                // boolean-constrain bit1: put it on column b @ row 1 and
                // copy from the c-cell.
                let b1_again =
                    b1.copy_advice(|| "bit1 for bool", &mut region, self.b, 1)?;
                self.s_bool.enable(&mut region, 1)?;
                Ok((idx_cell, [b0, b1_again]))
            },
        )
    }

    /// Conditional swap of (cur, sib) by `bit`: returns (lo, hi).
    fn cond_swap(
        &self,
        layouter: &mut impl Layouter<Halo2Fr>,
        cur: &AssignedCell<Halo2Fr, Halo2Fr>,
        sib: &AssignedCell<Halo2Fr, Halo2Fr>,
        bit: &AssignedCell<Halo2Fr, Halo2Fr>,
    ) -> Result<
        (
            AssignedCell<Halo2Fr, Halo2Fr>,
            AssignedCell<Halo2Fr, Halo2Fr>,
        ),
        ErrorFront,
    > {
        layouter.assign_region(
            || "cond_swap",
            |mut region| {
                let cur_c = cur.copy_advice(|| "cur", &mut region, self.a, 0)?;
                let sib_c = sib.copy_advice(|| "sib", &mut region, self.b, 0)?;
                bit.copy_advice(|| "bit", &mut region, self.c, 0)?;
                let lo_val = cur_c.value().copied()
                    + bit.value().copied() * (sib_c.value().copied() - cur_c.value().copied());
                let lo = region.assign_advice(|| "lo", self.a, 1, || lo_val)?;
                let hi_val = cur_c.value().copied() + sib_c.value().copied() - lo_val;
                let hi = region.assign_advice(|| "hi", self.b, 1, || hi_val)?;
                self.s_swap_lo.enable(&mut region, 0)?;
                self.s_swap_hi.enable(&mut region, 0)?;
                Ok((lo, hi))
            },
        )
    }

    /// 2-to-1 mux: returns `bit ? y : x`.
    pub(crate) fn mux(
        &self,
        layouter: &mut impl Layouter<Halo2Fr>,
        x: &AssignedCell<Halo2Fr, Halo2Fr>,
        y: &AssignedCell<Halo2Fr, Halo2Fr>,
        bit: &AssignedCell<Halo2Fr, Halo2Fr>,
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        layouter.assign_region(
            || "mux",
            |mut region| {
                let x_c = x.copy_advice(|| "x", &mut region, self.a, 0)?;
                let y_c = y.copy_advice(|| "y", &mut region, self.b, 0)?;
                let bit_c = bit.copy_advice(|| "bit", &mut region, self.c, 0)?;
                let out_val = (Value::known(Halo2Fr::ONE) - bit_c.value().copied())
                    * x_c.value().copied()
                    + bit_c.value().copied() * y_c.value().copied();
                let out = region.assign_advice(|| "out", self.a, 1, || out_val)?;
                self.s_mux.enable(&mut region, 0)?;
                Ok(out)
            },
        )
    }

    /// Inverse-or-zero "is-nonzero": returns a boolean `has` cell that is
    /// CONSTRAINED to equal `(idx ≠ 0)`. Soundness:
    ///   idx·inv − has = 0    ⇒  has = idx·inv
    ///   (1−has)·idx   = 0    ⇒  has=0 forces idx=0
    /// Honest prover sets inv = idx⁻¹ (so has=1) when idx≠0, and inv=0
    /// (so has=0) when idx=0. A cheating prover cannot make has=0 while
    /// idx≠0 (second gate), nor has=1 while idx=0 (first gate ⇒ 0·inv=1).
    pub(crate) fn is_nonzero(
        &self,
        layouter: &mut impl Layouter<Halo2Fr>,
        idx: &AssignedCell<Halo2Fr, Halo2Fr>,
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        layouter.assign_region(
            || "is_nonzero",
            |mut region| {
                let idx_c = idx.copy_advice(|| "idx", &mut region, self.a, 0)?;
                let inv_val = idx_c
                    .value()
                    .copied()
                    .map(|f| f.invert().unwrap_or(Halo2Fr::ZERO));
                region.assign_advice(|| "inv", self.b, 0, || inv_val)?;
                let has_val = idx_c.value().copied() * inv_val;
                let has = region.assign_advice(|| "has", self.c, 0, || has_val)?;
                self.s_ioz_a.enable(&mut region, 0)?;
                self.s_ioz_b.enable(&mut region, 0)?;
                // has is boolean (it equals idx·inv ∈ {0,1} given the two
                // gates); pin it explicitly so downstream mux/eq are sound.
                let has_b = has.copy_advice(|| "has bool", &mut region, self.b, 1)?;
                self.s_bool.enable(&mut region, 1)?;
                Ok(has_b)
            },
        )
    }

    /// Gated equality: enforce `sel·(lhs − rhs) = 0` (when `sel`=1, lhs==rhs;
    /// when sel=0, vacuous). `sel` must be a boolean cell.
    pub(crate) fn gated_eq(
        &self,
        layouter: &mut impl Layouter<Halo2Fr>,
        lhs: &AssignedCell<Halo2Fr, Halo2Fr>,
        rhs: &AssignedCell<Halo2Fr, Halo2Fr>,
        sel: &AssignedCell<Halo2Fr, Halo2Fr>,
    ) -> Result<(), ErrorFront> {
        layouter.assign_region(
            || "gated_eq",
            |mut region| {
                lhs.copy_advice(|| "lhs", &mut region, self.a, 0)?;
                rhs.copy_advice(|| "rhs", &mut region, self.b, 0)?;
                sel.copy_advice(|| "sel", &mut region, self.c, 0)?;
                self.s_geq.enable(&mut region, 0)?;
                Ok(())
            },
        )
    }

    /// Compute `out = x + 1` in a fresh equality-enabled cell, enforced
    /// soundly by the recompose gate `a = b + 2·c` instantiated as
    /// `out = x + 2·half`, where `half = 1/2` (the field inverse of 2) is
    /// pinned as a TRUE constant via `assign_advice_from_constant`. A prover
    /// cannot tamper `half` (it is fixed-column-bound), so `out` is exactly
    /// `x + 1`. No index dependence is introduced.
    pub(crate) fn add_one(
        &self,
        layouter: &mut impl Layouter<Halo2Fr>,
        x: &AssignedCell<Halo2Fr, Halo2Fr>,
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        let half = Halo2Fr::from(2u64).invert().expect("2 invertible");
        layouter.assign_region(
            || "add_one",
            |mut region| {
                let out_val = x.value().copied() + Value::known(Halo2Fr::ONE);
                let out = region.assign_advice(|| "out", self.a, 0, || out_val)?;
                x.copy_advice(|| "x", &mut region, self.b, 0)?;
                region.assign_advice_from_constant(|| "half=1/2", self.c, 0, half)?;
                self.s_recompose.enable(&mut region, 0)?;
                Ok(out)
            },
        )
    }

    /// Witness a known constant into a fresh equality-enabled cell.
    pub(crate) fn assign_const(
        &self,
        layouter: &mut impl Layouter<Halo2Fr>,
        c: Halo2Fr,
        name: &'static str,
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        layouter.assign_region(
            || name,
            |mut region| region.assign_advice(|| name, self.a, 0, || Value::known(c)),
        )
    }

    /// Witness a private value into a fresh equality-enabled cell.
    pub(crate) fn assign_value(
        &self,
        layouter: &mut impl Layouter<Halo2Fr>,
        v: Value<Halo2Fr>,
        name: &'static str,
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        layouter.assign_region(
            || name,
            |mut region| region.assign_advice(|| name, self.a, 0, || v),
        )
    }

    /// Index-agnostic depth-2 Merkle: recompute the root of `leaf` given the
    /// per-level `bits` (low bit first) and `siblings`, conditionally
    /// swapping at each level. Returns the recomputed root cell. ONE shape
    /// for any index → single VK.
    pub(crate) fn merkle_root(
        &self,
        poseidon: &PoseidonChipConfig,
        layouter: &mut impl Layouter<Halo2Fr>,
        leaf: AssignedCell<Halo2Fr, Halo2Fr>,
        bits: &[AssignedCell<Halo2Fr, Halo2Fr>; MERKLE_DEPTH],
        siblings: &[AssignedCell<Halo2Fr, Halo2Fr>; MERKLE_DEPTH],
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        let mut cur = leaf;
        for level in 0..MERKLE_DEPTH {
            // (lo, hi) = bit ? (sib, cur) : (cur, sib).
            // With bit=0 ⇒ lo=cur (left), hi=sib (right): node = H(cur, sib).
            // With bit=1 ⇒ lo=sib (left), hi=cur (right): node = H(sib, cur).
            let (lo, hi) = self.cond_swap(layouter, &cur, &siblings[level], &bits[level])?;
            cur = PoseidonChip::hash_n_from_cells(poseidon, layouter, &[lo, hi])?;
        }
        Ok(cur)
    }
}

// ---------------------------------------------------------------------------
// PoRepCircuit — the reduced in-circuit relation (index-agnostic).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PoRepCircuitConfig {
    poseidon: PoseidonChipConfig,
    swap: SwapMerkleConfig,
    /// Witness column for private scalars that must be cell-bound.
    witness: Column<Advice>,
    /// Three-column add gate enforcing `add_c = add_a + add_b`, used for
    /// the encoding relation `R[v] = D[v] + label(L, v)`.
    add_a: Column<Advice>,
    add_b: Column<Advice>,
    add_c: Column<Advice>,
    s_add: Selector,
    instance: Column<Instance>,
}

/// Reduced-instance PoRep circuit. Carries the full sealed witness for the
/// challenged node `challenge_index` plus the Merkle siblings (CommD/CommR/
/// CommC) and the DRG-parent column's siblings (CommC at index v-1).
///
/// **Index-agnostic:** `challenge_index` is carried only to derive the
/// honest WITNESS values (bits, siblings, parent path). It is NOT baked into
/// the circuit SHAPE — the synthesis is identical for every index, so one VK
/// verifies all of them.
#[derive(Clone, Default)]
pub struct PoRepCircuit {
    // Private identity pre-image of replicaID.
    pub pinner_identity: Value<Halo2Fr>,
    pub cid: Value<Halo2Fr>,
    pub sector_index: Value<Halo2Fr>,
    pub epoch: Value<Halo2Fr>,

    /// The challenged node index v* (public via challengeNonce). Witnessed.
    pub challenge_index: usize,

    /// Data leaf D[v*] and the layer labels for v* (label(1,v*), label(2,v*)).
    pub data_challenged: Value<Halo2Fr>,
    pub label_l1: Value<Halo2Fr>,
    pub label_l2: Value<Halo2Fr>,

    /// The DRG-same-layer parent labels (label(1,v*-1), label(2,v*-1)).
    /// For v*=0 they are unused (mux'd out by `has_drg_parent`=false).
    pub drg_parent_l1: Value<Halo2Fr>,
    pub drg_parent_l2: Value<Halo2Fr>,

    /// Merkle sibling values for the three inclusions of node v* (CommD,
    /// CommR, CommC). Directions are derived in-circuit from v*'s bits.
    pub sib_d: [Value<Halo2Fr>; MERKLE_DEPTH],
    pub sib_r: [Value<Halo2Fr>; MERKLE_DEPTH],
    pub sib_c: [Value<Halo2Fr>; MERKLE_DEPTH],

    /// Merkle sibling values for the DRG-PARENT column inclusion (CommC at
    /// index v*-1). Used to prove the parent labels are the committed ones.
    /// For v*=0 the values are dummy (the inclusion's root-equality is gated
    /// off by `has_drg_parent`=false), but the gates still run (single VK).
    pub sib_parent_c: [Value<Halo2Fr>; MERKLE_DEPTH],
}

impl PoRepCircuit {
    /// Build the circuit witness for the challenged node from a fully
    /// sealed replica. This is the honest-prover constructor.
    pub fn from_sealed(
        sealed: &SealedReplica,
        pinner_identity: Halo2Fr,
        challenge_index: usize,
    ) -> Self {
        let v = challenge_index;
        let (drg_l1, drg_l2) = match drg_parent(v) {
            Some(p) => (sealed.labels[0][p], sealed.labels[1][p]),
            None => (Halo2Fr::from(0u64), Halo2Fr::from(0u64)),
        };
        // Parent column inclusion: parent index p = v-1 (for v≥1). For v=0
        // there is no parent; use index 0's siblings as benign dummy (the
        // inclusion is gated off, so the values are irrelevant to soundness).
        let parent_index = drg_parent(v).unwrap_or(0);
        let sib_parent_c = merkle_siblings_4(&sealed.columns, parent_index).map(Value::known);

        let sib_d = merkle_siblings_4(&sealed.data, v).map(Value::known);
        let sib_r = merkle_siblings_4(&sealed.replica, v).map(Value::known);
        let sib_c = merkle_siblings_4(&sealed.columns, v).map(Value::known);

        Self {
            pinner_identity: Value::known(pinner_identity),
            cid: Value::known(sealed.cid),
            sector_index: Value::known(sealed.sector_index),
            epoch: Value::known(sealed.epoch),
            challenge_index: v,
            data_challenged: Value::known(sealed.data[v]),
            label_l1: Value::known(sealed.labels[0][v]),
            label_l2: Value::known(sealed.labels[1][v]),
            drg_parent_l1: Value::known(drg_l1),
            drg_parent_l2: Value::known(drg_l2),
            sib_d,
            sib_r,
            sib_c,
            sib_parent_c,
        }
    }

    /// The public-input vector for a sealed replica + challenge index.
    pub fn public_inputs(sealed: &SealedReplica, challenge_index: usize) -> Vec<Halo2Fr> {
        let mut pis = vec![Halo2Fr::from(0u64); pi::COUNT];
        pis[pi::REPLICA_ID] = sealed.replica_id;
        pis[pi::CID] = sealed.cid;
        pis[pi::SECTOR_INDEX] = sealed.sector_index;
        pis[pi::COMM_D] = sealed.comm_d;
        pis[pi::COMM_R] = sealed.comm_r;
        pis[pi::COMM_C] = sealed.comm_c;
        pis[pi::CHALLENGE_NONCE] = Halo2Fr::from(challenge_index as u64);
        pis[pi::EPOCH] = sealed.epoch;
        pis
    }
}

impl Circuit<Halo2Fr> for PoRepCircuit {
    type Config = PoRepCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        // Index-agnostic: the shape no longer depends on the index, so the
        // witness-free circuit carries nothing index-specific.
        Self {
            pinner_identity: Value::unknown(),
            cid: Value::unknown(),
            sector_index: Value::unknown(),
            epoch: Value::unknown(),
            challenge_index: 0,
            data_challenged: Value::unknown(),
            label_l1: Value::unknown(),
            label_l2: Value::unknown(),
            drg_parent_l1: Value::unknown(),
            drg_parent_l2: Value::unknown(),
            sib_d: [Value::unknown(); MERKLE_DEPTH],
            sib_r: [Value::unknown(); MERKLE_DEPTH],
            sib_c: [Value::unknown(); MERKLE_DEPTH],
            sib_parent_c: [Value::unknown(); MERKLE_DEPTH],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self::Config {
        let poseidon = PoseidonChip::configure(meta);
        let swap = SwapMerkleConfig::configure(meta);
        let witness = meta.advice_column();
        meta.enable_equality(witness);

        let add_a = meta.advice_column();
        let add_b = meta.advice_column();
        let add_c = meta.advice_column();
        for col in [add_a, add_b, add_c] {
            meta.enable_equality(col);
        }
        let s_add = meta.selector();
        meta.create_gate("porep_encode_add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(add_a, Rotation::cur());
            let b = meta.query_advice(add_b, Rotation::cur());
            let c = meta.query_advice(add_c, Rotation::cur());
            vec![s * (c - a - b)]
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);
        PoRepCircuitConfig {
            poseidon,
            swap,
            witness,
            add_a,
            add_b,
            add_c,
            s_add,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Halo2Fr>,
    ) -> Result<(), ErrorFront> {
        let swap = &config.swap;

        // ---- Step 1: witness the private scalars as canonical cells. ----
        let (pid_cell, cid_cell, sector_cell, epoch_cell, data_cell, drg1_cell, drg2_cell) =
            layouter.assign_region(
                || "porep_witness",
                |mut region| {
                    let pid = region.assign_advice(
                        || "pinner_identity",
                        config.witness,
                        0,
                        || self.pinner_identity,
                    )?;
                    let cid = region.assign_advice(|| "cid", config.witness, 1, || self.cid)?;
                    let sector = region.assign_advice(
                        || "sector_index",
                        config.witness,
                        2,
                        || self.sector_index,
                    )?;
                    let epoch =
                        region.assign_advice(|| "epoch", config.witness, 3, || self.epoch)?;
                    let data = region.assign_advice(
                        || "data[v*]",
                        config.witness,
                        4,
                        || self.data_challenged,
                    )?;
                    let drg1 = region.assign_advice(
                        || "drg_parent_l1",
                        config.witness,
                        5,
                        || self.drg_parent_l1,
                    )?;
                    let drg2 = region.assign_advice(
                        || "drg_parent_l2",
                        config.witness,
                        6,
                        || self.drg_parent_l2,
                    )?;
                    Ok((pid, cid, sector, epoch, data, drg1, drg2))
                },
            )?;

        // ---- Step 2: replicaID = Poseidon(pinnerIdentity, cid, sectorIndex). ----
        let replica_id_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[pid_cell.clone(), cid_cell.clone(), sector_cell.clone()],
        )?;
        layouter.constrain_instance(replica_id_cell.cell(), config.instance, pi::REPLICA_ID)?;
        layouter.constrain_instance(cid_cell.cell(), config.instance, pi::CID)?;
        layouter.constrain_instance(sector_cell.cell(), config.instance, pi::SECTOR_INDEX)?;
        layouter.constrain_instance(epoch_cell.cell(), config.instance, pi::EPOCH)?;

        // ---- Step 2b: witness + bind the challenge index (index-agnostic). ----
        // The index is a WITNESS, bit-decomposed in-circuit, and constrained
        // to equal the public challengeNonce. This + the conditional-swap
        // Merkle is what collapses the per-index VK to a single VK.
        let idx_val = Value::known(Halo2Fr::from(self.challenge_index as u64));
        let (idx_cell, bits) = swap.decompose_index(&mut layouter, idx_val)?;
        layouter.constrain_instance(idx_cell.cell(), config.instance, pi::CHALLENGE_NONCE)?;

        // has_drg_parent = (challengeNonce ≠ 0), CONSTRAINED (not host-only).
        let has_drg = swap.is_nonzero(&mut layouter, &idx_cell)?;

        // Constant cells for layer indices used in the labeling pre-images.
        let layer1_cell = swap.assign_const(&mut layouter, Halo2Fr::from(1u64), "layer=1")?;
        let layer2_cell = swap.assign_const(&mut layouter, Halo2Fr::from(2u64), "layer=2")?;

        // ---- Step 3: labeling relation (the finding-1.1 core). ----
        // prev_same = has_drg ? drg_parent : replicaID  (mux, not host branch).
        let prev_same1_cell =
            swap.mux(&mut layouter, &replica_id_cell, &drg1_cell, &has_drg)?;
        let label1_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[
                replica_id_cell.clone(),
                layer1_cell.clone(),
                idx_cell.clone(),
                prev_same1_cell,
            ],
        )?;

        let prev_same2_cell =
            swap.mux(&mut layouter, &replica_id_cell, &drg2_cell, &has_drg)?;
        let label2_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[
                replica_id_cell.clone(),
                layer2_cell.clone(),
                idx_cell.clone(),
                prev_same2_cell,
                label1_cell.clone(),
            ],
        )?;

        // ---- Step 4: encoding. R[v*] = D[v*] + label(2, v*). ----
        let replica_leaf_cell = layouter.assign_region(
            || "encode_R",
            |mut region| {
                let d = data_cell.copy_advice(|| "D[v*]", &mut region, config.add_a, 0)?;
                let lab2 = label2_cell.copy_advice(|| "label2", &mut region, config.add_b, 0)?;
                let r_val = d.value().copied() + lab2.value().copied();
                let r = region.assign_advice(|| "R[v*]", config.add_c, 0, || r_val)?;
                config.s_add.enable(&mut region, 0)?;
                Ok(r)
            },
        )?;

        // ---- Step 5: column commitment. column(v*) = Poseidon(label1, label2). ----
        let column_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[label1_cell.clone(), label2_cell.clone()],
        )?;

        // ---- Step 6: index-agnostic Merkle inclusions of v* in D/R/C. ----
        // Each recomputes the root from the leaf + v*'s bits + siblings, then
        // equality-checks against the public root.
        let sib_d = self.assign_siblings(swap, &mut layouter, &self.sib_d, "sib_d")?;
        let root_d = swap.merkle_root(&config.poseidon, &mut layouter, data_cell.clone(), &bits, &sib_d)?;
        layouter.constrain_instance(root_d.cell(), config.instance, pi::COMM_D)?;

        let sib_r = self.assign_siblings(swap, &mut layouter, &self.sib_r, "sib_r")?;
        let root_r = swap.merkle_root(&config.poseidon, &mut layouter, replica_leaf_cell, &bits, &sib_r)?;
        layouter.constrain_instance(root_r.cell(), config.instance, pi::COMM_R)?;

        let sib_c = self.assign_siblings(swap, &mut layouter, &self.sib_c, "sib_c")?;
        let root_c = swap.merkle_root(&config.poseidon, &mut layouter, column_cell, &bits, &sib_c)?;
        layouter.constrain_instance(root_c.cell(), config.instance, pi::COMM_C)?;

        // ---- Step 7: PARENT SOUNDNESS — prove the DRG parent labels are the
        // committed node at index v*-1. The parent's COLUMN
        // (= Poseidon(drg_parent_l1, drg_parent_l2)) must be included in
        // CommC at the parent index. This binds BOTH parent labels to CommC.
        //
        // parent_index is a WITNESS, constrained (when has_drg) to v*-1, then
        // bit-decomposed for the conditional-swap Merkle. The inclusion's
        // root-equality is GATED by has_drg, so at v*=0 the gates still run
        // (single VK) but the equality is vacuous.
        let parent_col = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[drg1_cell.clone(), drg2_cell.clone()],
        )?;
        // Witness parent_index, bit-decompose it (boolean + recompose
        // constrained), and compute p+1 with the encoding add gate
        // (add_c = add_a + add_b ⇒ p+1 = p + 1). Then bind
        // has_drg·((p+1) − v*) = 0 so that, whenever a DRG parent exists,
        // the proven parent index is exactly v*-1.
        let parent_index_val = self
            .challenge_index
            .checked_sub(1)
            .map(|p| Halo2Fr::from(p as u64))
            .unwrap_or(Halo2Fr::ZERO);
        let (parent_idx_cell, parent_bits) =
            swap.decompose_index(&mut layouter, Value::known(parent_index_val))?;
        let parent_idx_plus1 = swap.add_one(&mut layouter, &parent_idx_cell)?;
        // has_drg·((p+1) − v*) = 0.
        swap.gated_eq(&mut layouter, &parent_idx_plus1, &idx_cell, &has_drg)?;

        // Recompute the parent column's CommC root and gate-equate to CommC.
        let sib_parent =
            self.assign_siblings(swap, &mut layouter, &self.sib_parent_c, "sib_parent_c")?;
        let parent_root = swap.merkle_root(
            &config.poseidon,
            &mut layouter,
            parent_col,
            &parent_bits,
            &sib_parent,
        )?;
        // has_drg·(parent_root − CommC) = 0. We gate-equate against `root_c`,
        // which is already `constrain_instance`'d to the public CommC, so the
        // parent column must hash up to the SAME public CommC root.
        swap.gated_eq(&mut layouter, &parent_root, &root_c, &has_drg)?;

        Ok(())
    }
}

impl PoRepCircuit {
    /// Assign a level's worth of Merkle sibling values into fresh
    /// equality-enabled cells via the swap gadget's advice column.
    fn assign_siblings(
        &self,
        swap: &SwapMerkleConfig,
        layouter: &mut impl Layouter<Halo2Fr>,
        sibs: &[Value<Halo2Fr>; MERKLE_DEPTH],
        name: &'static str,
    ) -> Result<[AssignedCell<Halo2Fr, Halo2Fr>; MERKLE_DEPTH], ErrorFront> {
        let s0 = swap.assign_value(layouter, sibs[0], name)?;
        let s1 = swap.assign_value(layouter, sibs[1], name)?;
        Ok([s0, s1])
    }
}

// ---------------------------------------------------------------------------
// Tests — the soundness net (real prove+verify with KZG + MockProver).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    /// k for the reduced PoRep instance. The index-agnostic circuit runs
    /// more Poseidon permutations than before (now 8 Merkle-node hashes
    /// across D/R/C + the parent column inclusion, plus replicaID + 2 labels
    /// + 2 columns), so it is a bit larger; k=14 (16384 rows) is comfortable.
    const K: u32 = 14;

    fn sample_data() -> [Halo2Fr; N] {
        [
            Halo2Fr::from(1001u64),
            Halo2Fr::from(2002u64),
            Halo2Fr::from(3003u64),
            Halo2Fr::from(4004u64),
        ]
    }

    fn seal_sample(pinner: Halo2Fr) -> SealedReplica {
        seal_reduced(
            pinner,
            Halo2Fr::from(0xC1Du64), // cid
            Halo2Fr::from(7u64),     // sectorIndex
            Halo2Fr::from(42u64),    // epoch
            sample_data(),
        )
    }

    /// Positive — a correctly-sealed tiny replica proves and verifies for
    /// every challenge index, via MockProver.
    #[test]
    fn porep_reduced_positive_mockprover_all_nodes() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        for v in 0..N {
            let circuit = PoRepCircuit::from_sealed(&sealed, pinner, v);
            let pis = PoRepCircuit::public_inputs(&sealed, v);
            let prover = MockProver::run(K, &circuit, vec![pis]).expect("mockprover setup");
            assert_eq!(
                prover.verify(),
                Ok(()),
                "honest reduced PoRep must verify for challenge v={v}"
            );
        }
    }

    /// Positive — full KZG prove+verify round trip (the real cryptographic
    /// pipeline the 0x0108 PoRep circuit_version=2 runs).
    #[test]
    fn porep_reduced_positive_kzg_round_trip() {
        use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof_multi};
        use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
        use halo2_proofs::poly::kzg::strategy::SingleStrategy;
        use halo2_proofs::transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        };
        use halo2curves::bn256::{Bn256, G1Affine};
        use rand::rngs::OsRng;

        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 2usize;
        let circuit = PoRepCircuit::from_sealed(&sealed, pinner, v);
        let pis = PoRepCircuit::public_inputs(&sealed, v);

        let mut rng = OsRng;
        let params = ParamsKZG::<Bn256>::setup(K, &mut rng);
        let vk = keygen_vk(&params, &circuit.without_witnesses()).expect("keygen_vk");
        let pk = keygen_pk(&params, vk.clone(), &circuit.without_witnesses()).expect("keygen_pk");

        let public_inputs: Vec<Vec<Halo2Fr>> = vec![pis];
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[public_inputs.clone()],
            rng,
            &mut transcript,
        )
        .expect("create_proof");
        let proof_bytes = transcript.finalize();

        let verifier_params = params.verifier_params();
        let mut vt = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_bytes[..]);
        let ok = verify_proof_multi::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<Bn256>,
            _,
            _,
            SingleStrategy<_>,
        >(&verifier_params, &vk, &[public_inputs], &mut vt);
        assert!(ok, "honest reduced PoRep KZG proof must verify");
        eprintln!(
            "PIN-P1 reduced PoRep proof (N={N}, L={L}, v={v}): {} bytes (k={K})",
            proof_bytes.len()
        );
    }

    /// SINGLE-VK (TD-18 killed): ONE keygen'd VK verifies honest proofs for
    /// ALL 4 challenge indices. This is the proof that the circuit is
    /// index-agnostic — previously each index needed its own VK.
    #[test]
    fn porep_single_vk_verifies_all_indices() {
        use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof_multi};
        use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
        use halo2_proofs::poly::kzg::strategy::SingleStrategy;
        use halo2_proofs::transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        };
        use halo2curves::bn256::{Bn256, G1Affine};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);

        // ONE params + ONE VK derived from the index-agnostic shape.
        let mut params_rng = StdRng::from_seed([0x4D; 32]);
        let params = ParamsKZG::<Bn256>::setup(K, &mut params_rng);
        let shape = PoRepCircuit::default().without_witnesses();
        let vk = keygen_vk(&params, &shape).expect("single keygen_vk");
        let pk = keygen_pk(&params, vk.clone(), &shape).expect("single keygen_pk");

        for v in 0..N {
            let circuit = PoRepCircuit::from_sealed(&sealed, pinner, v);
            let pis = PoRepCircuit::public_inputs(&sealed, v);
            let public_inputs: Vec<Vec<Halo2Fr>> = vec![pis];

            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            let prover_rng = StdRng::from_seed([0xAB; 32]);
            create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
                &params,
                &pk,
                &[circuit],
                &[public_inputs.clone()],
                prover_rng,
                &mut transcript,
            )
            .expect("create_proof");
            let proof_bytes = transcript.finalize();

            let verifier_params = params.verifier_params();
            let mut vt = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_bytes[..]);
            let ok = verify_proof_multi::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<Bn256>,
                _,
                _,
                SingleStrategy<_>,
            >(&verifier_params, &vk, &[public_inputs], &mut vt);
            assert!(ok, "the SINGLE PoRep VK must verify challenge index v={v}");
        }
    }

    /// Finding 1.1 — wrong replicaID. Take A's honestly-sealed replica but
    /// present B's replicaID. The in-circuit labeling recomputes from the
    /// PUBLIC replicaID (B's) → no longer matches A's leaves/commitments.
    #[test]
    fn porep_reduced_negative_wrong_replica_id() {
        let pinner_a = Halo2Fr::from(0xA11CEu64);
        let pinner_b = Halo2Fr::from(0xB0Bu64);
        let sealed_a = seal_sample(pinner_a);
        let sealed_b = seal_sample(pinner_b);
        let v = 1usize;

        let mut circuit = PoRepCircuit::from_sealed(&sealed_a, pinner_a, v);
        circuit.pinner_identity = Value::known(pinner_b);

        let mut pis = PoRepCircuit::public_inputs(&sealed_a, v);
        pis[pi::REPLICA_ID] = sealed_b.replica_id;

        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoRep with B's replicaID over A's replica MUST fail (finding 1.1)"
        );
    }

    /// Tampered label — perturb the DRG parent label feeding label(2,v*)
    /// WITHOUT rebuilding the commitments. The recomputed label diverges →
    /// fails encoding + column + R-inclusion.
    #[test]
    fn porep_reduced_negative_tampered_label() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 1usize;

        let mut circuit = PoRepCircuit::from_sealed(&sealed, pinner, v);
        circuit.drg_parent_l2 = Value::known(sealed.labels[1][0] + Halo2Fr::from(1u64));

        let pis = PoRepCircuit::public_inputs(&sealed, v);
        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoRep with a tampered label MUST fail the labeling relation"
        );
    }

    /// PARENT FORGERY (the new soundness test — closes step-1(a) gap).
    ///
    /// A prover supplies a WRONG-but-relation-satisfying parent label. The
    /// attack: pick an arbitrary forged parent (drg_parent_l1/l2), recompute
    /// labels/column/replica for v* from it, build a FRESH CommC/CommR/CommD
    /// over a leaf set that contains the forged column/replica at v*, and
    /// present those as public inputs. The labeling relation + the v*
    /// inclusions all pass (they are internally consistent). The ONLY thing
    /// that rejects this is the PARENT inclusion: the forged parent column is
    /// NOT the committed column at index v*-1 in the (honest-parent) CommC.
    ///
    /// We simulate the strongest form: keep the honest sealed replica but
    /// FORGE the parent label in the witness AND patch the v* leaves so the
    /// v* inclusions still pass; the parent inclusion against the real CommC
    /// must catch it.
    #[test]
    fn porep_parent_forgery_rejected() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let mut sealed = seal_sample(pinner);
        let v = 1usize; // has a DRG parent (index 0)

        // Forge the parent labels (node 0's labels) to garbage.
        let forged_p1 = sealed.labels[0][0] + Halo2Fr::from(777u64);
        let forged_p2 = sealed.labels[1][0] + Halo2Fr::from(888u64);

        // Recompute v*'s labels/column/replica from the FORGED parents so the
        // labeling relation + v* inclusions are internally consistent.
        let l1 = native_hash(&label_preimage(
            sealed.replica_id,
            1,
            v,
            forged_p1,
            None,
        ));
        let l2 = native_hash(&label_preimage(
            sealed.replica_id,
            2,
            v,
            forged_p2,
            Some(l1),
        ));
        let col = native_hash(&[l1, l2]);
        let r = sealed.data[v] + l2;

        // Patch ONLY the v* leaves in the commitment trees (the attacker
        // rebuilds the trees with the forged v* column/replica but keeps the
        // honest parent column at index v*-1 — i.e. CommC still commits the
        // honest node-0 column, NOT the forged parent).
        sealed.labels[0][v] = l1;
        sealed.labels[1][v] = l2;
        sealed.columns[v] = col;
        sealed.replica[v] = r;
        sealed.comm_c = merkle_root_4(&sealed.columns);
        sealed.comm_r = merkle_root_4(&sealed.replica);

        // Build the witness with the forged parents.
        let mut circuit = PoRepCircuit::from_sealed(&sealed, pinner, v);
        circuit.drg_parent_l1 = Value::known(forged_p1);
        circuit.drg_parent_l2 = Value::known(forged_p2);

        let pis = PoRepCircuit::public_inputs(&sealed, v);
        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoRep with a forged (relation-satisfying) parent label MUST be \
             rejected by the parent-column inclusion against CommC"
        );
    }

    /// INDEX-BINDING negative: witnessed index ≠ public challengeNonce →
    /// rejects (the recompose/instance binding catches the mismatch).
    #[test]
    fn porep_index_binding_negative() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 2usize;

        // Honest witness for v=2 but claim challengeNonce=1 publicly.
        let circuit = PoRepCircuit::from_sealed(&sealed, pinner, v);
        let mut pis = PoRepCircuit::public_inputs(&sealed, v);
        pis[pi::CHALLENGE_NONCE] = Halo2Fr::from(1u64);

        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "witnessed index must equal public challengeNonce or proof rejects"
        );
    }

    /// Wrong stored node value — present a data leaf that is not committed in
    /// CommD. The Merkle inclusion of D[v*] against CommD MUST fail.
    #[test]
    fn porep_reduced_negative_wrong_node_value() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 3usize;

        let mut circuit = PoRepCircuit::from_sealed(&sealed, pinner, v);
        circuit.data_challenged = Value::known(sealed.data[v] + Halo2Fr::from(99u64));

        let pis = PoRepCircuit::public_inputs(&sealed, v);
        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoRep with a non-stored node value MUST fail Merkle inclusion"
        );
    }

    /// Sanity — different replicaIDs produce DIFFERENT labels for EVERY
    /// (l, v) and therefore different CommR.
    #[test]
    fn porep_reduced_replicaid_changes_every_label() {
        let sealed_a = seal_sample(Halo2Fr::from(0xA11CEu64));
        let sealed_b = seal_sample(Halo2Fr::from(0xB0Bu64));
        assert_ne!(sealed_a.replica_id, sealed_b.replica_id);
        for l in 0..L {
            for v in 0..N {
                assert_ne!(
                    sealed_a.labels[l][v],
                    sealed_b.labels[l][v],
                    "label(l={},v={}) must differ across replicaIDs",
                    l + 1,
                    v
                );
            }
        }
        assert_ne!(sealed_a.comm_r, sealed_b.comm_r, "CommR must be per-pinner");
        assert_eq!(
            sealed_a.comm_d, sealed_b.comm_d,
            "CommD binds to content only"
        );
    }

    /// The reduced public-input layout has 8 slots — distinct from the
    /// inference circuit's 3-commitment shape.
    #[test]
    fn porep_reduced_public_input_shape() {
        assert_eq!(pi::COUNT, 8);
        let sealed = seal_sample(Halo2Fr::from(1u64));
        let pis = PoRepCircuit::public_inputs(&sealed, 0);
        assert_eq!(pis.len(), 8);
    }
}
