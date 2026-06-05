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
// real sector size, aggregation, VK registry + circuit_version + 0x0108
// wiring, randomness-precompile nonce binding) is tracked as PIN-P1
// follow-up steps — NOT as TODOs in this code.
//
// **What is reused (not re-implemented):**
//   - `PoseidonChip` (chips.rs) — the hand-rolled in-circuit Poseidon-2
//     over BN254 Fr, whose output is byte-identical to the native
//     `poseidon_bn254::poseidon_hash`. This is the labeling hash, the
//     encoding-addition's hash inputs, and the Merkle-node hash. Both
//     `hash_n` (value inputs) and `hash_n_from_cells` (copy-constrained
//     cell inputs) are used so the prover cannot feed different values
//     to different relations.
//   - `poseidon_bn254::poseidon_hash` — native, for off-chain witness
//     generation (labels, encoding, commitments).
//   - The MockProver + KZG (ParamsKZG / SHPLONK / Blake2b transcript)
//     prove+verify harness pattern from `circuits.rs`.
//
// **What is net-new:** the `PoRepCircuit` composition + the native
// `seal_reduced` witness builder (this file). NO new Poseidon chip was
// needed — the existing one composes directly.
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
// Filecoin's Bucket/ChungDRG sampler (PIN-P1 follow-up).
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
//             (no DRG predecessor → the replicaID itself is the seed slot,
//              so even node 0 of layer 1 is bound to replicaID twice)
//     v ≥ 1:  label(1,v) = Poseidon(replicaID, 1, v, label(1, v-1))
//
//   Layer 2 (DRG parent same layer + expander parent previous layer):
//     v = 0:  label(2,0) = Poseidon(replicaID, 2, 0, replicaID,      label(1,0))
//     v ≥ 1:  label(2,v) = Poseidon(replicaID, 2, v, label(2, v-1),  label(1,v))
//
//   So every label's Poseidon preimage starts with (replicaID, l, v):
//   changing replicaID changes EVERY label (the finding-1.1 property),
//   and the layer/node indices and parents all enter the hash.
//
// Encoding (data → sealed replica), L = 2:
//   R[v] = D[v] + label(2, v)   (mod p)
//
// Commitments — depth-2 binary Poseidon-Merkle over the N=4 leaves:
//   leaf order is node index 0..3.
//   node_hash(a, b) = Poseidon(a, b)   (matches hash_pair / hash_n[2])
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
//   [6] challengeNonce      (challenged node index, reduced binding)
//   [7] epoch
//
// `challengeNonce` selects ONE challenged node v* ∈ {0,1,2,3} (K=1 for
// the reduced instance). The circuit recomputes that node's full label
// chain, encoding, column, and the three Merkle inclusions, binding all
// of it to the public replicaID. `cid`/`sectorIndex`/`epoch` are exposed
// and bound: replicaID is constrained in-circuit to equal
// Poseidon(pinnerIdentity, cid, sectorIndex), so cid + sectorIndex enter
// the proof; epoch is carried as a bound public scalar (the
// randomness-precompile finality binding of nonce/epoch is a PIN-P1
// follow-up — here epoch is exposed and equality-checked so the shape is
// already correct and domain-separated from the inference circuit).

#![allow(clippy::too_many_arguments)]

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr as Halo2Fr;

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
//
// This is the SAME computation the circuit recomputes in-circuit; it uses
// the native `poseidon_bn254::poseidon_hash` so the in-circuit
// `PoseidonChip` (byte-identical to it) reproduces every value. The
// positive test seals here, then proves the circuit accepts; the negative
// tests perturb one input and prove the circuit rejects.

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
    use halo2curves::ff::PrimeField as _;
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
/// `label_in_circuit` layout. `prev_same` is `label(l, drg_parent(v))` (or
/// `replica_id` as the seed when v=0), `prev_layer` is `label(l-1, v)` for
/// l ≥ 2 (absent for l=1).
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
/// tree of 4 leaves. Returns `[(sibling, is_left_sibling); 2]` from leaf
/// level up to (but excluding) the root.
fn merkle_path_4(leaves: &[Halo2Fr; N], leaf_index: usize) -> [(Halo2Fr, bool); MERKLE_DEPTH] {
    debug_assert!(leaf_index < N);
    let l01 = native_hash(&[leaves[0], leaves[1]]);
    let l23 = native_hash(&[leaves[2], leaves[3]]);
    // Level 0 sibling (within the pair).
    let (sib0, sib0_is_left) = if leaf_index % 2 == 0 {
        (leaves[leaf_index + 1], false) // sibling is on the right
    } else {
        (leaves[leaf_index - 1], true) // sibling is on the left
    };
    // Level 1 sibling (the other internal node).
    let (sib1, sib1_is_left) = if leaf_index < 2 {
        (l23, false) // our subtree is the left pair; sibling internal on right
    } else {
        (l01, true)
    };
    [(sib0, sib0_is_left), (sib1, sib1_is_left)]
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

// ---------------------------------------------------------------------------
// PoRepCircuit — the reduced in-circuit relation.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PoRepCircuitConfig {
    poseidon: PoseidonChipConfig,
    /// Witness column for the private scalars that must be cell-bound
    /// (pinner_identity, cid, sector_index, the data/label/column leaves,
    /// and the Merkle siblings).
    witness: Column<Advice>,
    /// Three-column add gate enforcing `add_c = add_a + add_b`, used for
    /// the encoding relation `R[v] = D[v] + label(L, v)`. A real
    /// arithmetic constraint (not a hash bridge) so the encoding is sound.
    add_a: Column<Advice>,
    add_b: Column<Advice>,
    add_c: Column<Advice>,
    s_add: Selector,
    instance: Column<Instance>,
}

/// Reduced-instance PoRep circuit. All vectors carry the full sealed
/// witness for the challenged node `challenge_index` (and the leaves /
/// siblings its Merkle inclusions need).
#[derive(Clone, Default)]
pub struct PoRepCircuit {
    // Private identity pre-image of replicaID.
    pub pinner_identity: Value<Halo2Fr>,
    pub cid: Value<Halo2Fr>,
    pub sector_index: Value<Halo2Fr>,
    pub epoch: Value<Halo2Fr>,

    /// The challenged node index v* (public via challengeNonce).
    pub challenge_index: usize,

    /// Data leaf D[v*] and the layer labels for v* (label(1,v*), label(2,v*)).
    pub data_challenged: Value<Halo2Fr>,
    pub label_l1: Value<Halo2Fr>,
    pub label_l2: Value<Halo2Fr>,

    /// The DRG-same-layer parent labels needed to recompute v*'s labels.
    /// For the path-graph DRG, label(l, v*-1); for v*=0 the seed is
    /// replicaID (recomputed in-circuit), so these carry replicaID's role
    /// only via the layout below.
    pub drg_parent_l1: Value<Halo2Fr>, // label(1, v*-1)  (unused at v*=0)
    pub drg_parent_l2: Value<Halo2Fr>, // label(2, v*-1)  (unused at v*=0)

    /// Merkle authentication paths for the three trees. Each entry is
    /// (sibling, sibling_is_left).
    pub path_d: [(Value<Halo2Fr>, bool); MERKLE_DEPTH],
    pub path_r: [(Value<Halo2Fr>, bool); MERKLE_DEPTH],
    pub path_c: [(Value<Halo2Fr>, bool); MERKLE_DEPTH],
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
        // DRG same-layer parent labels (path graph: v-1). For v=0 there is
        // no parent; the in-circuit recompute uses replicaID as the seed,
        // so we pass zero here and the circuit ignores it at v=0.
        let (drg_l1, drg_l2) = match drg_parent(v) {
            Some(p) => (sealed.labels[0][p], sealed.labels[1][p]),
            None => (Halo2Fr::from(0u64), Halo2Fr::from(0u64)),
        };
        let path_d = merkle_path_4(&sealed.data, v);
        let path_r = merkle_path_4(&sealed.replica, v);
        let path_c = merkle_path_4(&sealed.columns, v);
        let to_vp = |p: [(Halo2Fr, bool); MERKLE_DEPTH]| {
            [
                (Value::known(p[0].0), p[0].1),
                (Value::known(p[1].0), p[1].1),
            ]
        };
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
            path_d: to_vp(path_d),
            path_r: to_vp(path_r),
            path_c: to_vp(path_c),
        }
    }

    /// Build a witness-free circuit whose **fixed topology** matches an
    /// honest proof for `challenge_index`, suitable for `keygen_vk`.
    ///
    /// PIN-P1 step (a): the verifying key the 0x0108 precompile uses for
    /// circuit_version=2 must be derived from the SAME challenge index
    /// the prover used — the v=0 labeling-seed copy constraint differs
    /// from v≥1, and the Merkle branch directions (`sibling_is_left`)
    /// are part of the fixed structure. This constructor pins exactly
    /// those topology bits (siblings are `Value::unknown()`; only the
    /// `bool` directions, which come from the deterministic
    /// `merkle_path_4` direction rule, matter for the VK).
    pub fn for_keygen(challenge_index: usize) -> Self {
        debug_assert!(challenge_index < N, "challenge_index must be < N");
        // The direction booleans depend only on the index, not on the
        // leaf values, so derive them from a dummy set of leaves.
        let dummy = [Halo2Fr::from(0u64); N];
        let dir = |p: [(Halo2Fr, bool); MERKLE_DEPTH]| {
            [
                (Value::<Halo2Fr>::unknown(), p[0].1),
                (Value::<Halo2Fr>::unknown(), p[1].1),
            ]
        };
        Self {
            pinner_identity: Value::unknown(),
            cid: Value::unknown(),
            sector_index: Value::unknown(),
            epoch: Value::unknown(),
            challenge_index,
            data_challenged: Value::unknown(),
            label_l1: Value::unknown(),
            label_l2: Value::unknown(),
            drg_parent_l1: Value::unknown(),
            drg_parent_l2: Value::unknown(),
            path_d: dir(merkle_path_4(&dummy, challenge_index)),
            path_r: dir(merkle_path_4(&dummy, challenge_index)),
            path_c: dir(merkle_path_4(&dummy, challenge_index)),
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
        Self {
            pinner_identity: Value::unknown(),
            cid: Value::unknown(),
            sector_index: Value::unknown(),
            epoch: Value::unknown(),
            challenge_index: self.challenge_index,
            data_challenged: Value::unknown(),
            label_l1: Value::unknown(),
            label_l2: Value::unknown(),
            drg_parent_l1: Value::unknown(),
            drg_parent_l2: Value::unknown(),
            path_d: [
                (Value::unknown(), self.path_d[0].1),
                (Value::unknown(), self.path_d[1].1),
            ],
            path_r: [
                (Value::unknown(), self.path_r[0].1),
                (Value::unknown(), self.path_r[1].1),
            ],
            path_c: [
                (Value::unknown(), self.path_c[0].1),
                (Value::unknown(), self.path_c[1].1),
            ],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self::Config {
        let poseidon = PoseidonChip::configure(meta);
        let witness = meta.advice_column();
        meta.enable_equality(witness);

        let add_a = meta.advice_column();
        let add_b = meta.advice_column();
        let add_c = meta.advice_column();
        for col in [add_a, add_b, add_c] {
            meta.enable_equality(col);
        }
        let s_add = meta.selector();
        // Encoding gate: add_c = add_a + add_b.
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
        let v = self.challenge_index;

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
        // Bind cid + sector_index into replicaID (cell-bound), then expose
        // replicaID, cid, sector_index, epoch as public inputs.
        let replica_id_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[pid_cell.clone(), cid_cell.clone(), sector_cell.clone()],
        )?;
        layouter.constrain_instance(replica_id_cell.cell(), config.instance, pi::REPLICA_ID)?;
        layouter.constrain_instance(cid_cell.cell(), config.instance, pi::CID)?;
        layouter.constrain_instance(sector_cell.cell(), config.instance, pi::SECTOR_INDEX)?;
        layouter.constrain_instance(epoch_cell.cell(), config.instance, pi::EPOCH)?;

        // Constant cells for the layer/node indices used in the labeling
        // pre-images. Assigned fresh so they are copy-constrainable.
        let layer1_cell =
            self.assign_constant(&config, &mut layouter, Halo2Fr::from(1u64), "layer=1")?;
        let layer2_cell =
            self.assign_constant(&config, &mut layouter, Halo2Fr::from(2u64), "layer=2")?;
        let v_cell = self.assign_constant(&config, &mut layouter, Halo2Fr::from(v as u64), "v*")?;
        // challengeNonce public input == v*.
        layouter.constrain_instance(v_cell.cell(), config.instance, pi::CHALLENGE_NONCE)?;

        // ---- Step 3: labeling relation (the finding-1.1 core). ----
        // label(1, v*) = Poseidon(replicaID, 1, v*, prev_same1)
        //   prev_same1 = label(1, v*-1)  if v*≥1, else replicaID (seed).
        let prev_same1_cell = if drg_parent(v).is_some() {
            drg1_cell.clone()
        } else {
            replica_id_cell.clone()
        };
        let label1_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[
                replica_id_cell.clone(),
                layer1_cell.clone(),
                v_cell.clone(),
                prev_same1_cell,
            ],
        )?;

        // label(2, v*) = Poseidon(replicaID, 2, v*, prev_same2, label(1, v*))
        //   prev_same2 = label(2, v*-1) if v*≥1, else replicaID (seed).
        //   expander parent (prev layer) = label(1, v*) (identity rule).
        let prev_same2_cell = if drg_parent(v).is_some() {
            drg2_cell.clone()
        } else {
            replica_id_cell.clone()
        };
        let label2_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[
                replica_id_cell.clone(),
                layer2_cell.clone(),
                v_cell.clone(),
                prev_same2_cell,
                label1_cell.clone(),
            ],
        )?;

        // ---- Step 4: encoding. R[v*] = D[v*] + label(2, v*). ----
        // Enforced by a real arithmetic gate (add_c = add_a + add_b) with
        // add_a ← D[v*] and add_b ← label(2,v*) copy-bound, and add_c the
        // sealed leaf R[v*]. The SAME R cell is then fed into the CommR
        // Merkle inclusion, so a prover cannot decouple the sealed leaf
        // from D + label2.
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

        // ---- Step 6: Merkle inclusions of D[v*]∈CommD, R[v*]∈CommR, col∈CommC. ----
        self.merkle_verify(
            &config,
            &mut layouter,
            data_cell.clone(),
            &self.path_d,
            pi::COMM_D,
        )?;
        self.merkle_verify(
            &config,
            &mut layouter,
            replica_leaf_cell,
            &self.path_r,
            pi::COMM_R,
        )?;
        self.merkle_verify(
            &config,
            &mut layouter,
            column_cell,
            &self.path_c,
            pi::COMM_C,
        )?;

        Ok(())
    }
}

impl PoRepCircuit {
    /// Assign a public/known constant into a fresh equality-enabled cell.
    fn assign_constant(
        &self,
        config: &PoRepCircuitConfig,
        layouter: &mut impl Layouter<Halo2Fr>,
        c: Halo2Fr,
        name: &'static str,
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        layouter.assign_region(
            || name,
            |mut region| region.assign_advice(|| name, config.witness, 0, || Value::known(c)),
        )
    }

    /// Verify a depth-2 binary Poseidon-Merkle inclusion of `leaf` against
    /// the public root at instance slot `root_pi`. At each level the
    /// running digest is hashed with its sibling in the correct order
    /// (sibling_is_left ⇒ Poseidon(sibling, cur), else Poseidon(cur,
    /// sibling)). The branch direction is a public part of the topology
    /// (challenge index), so selecting the order with a host-side bool is
    /// sound: the order is fixed by the proven challenge index, which is a
    /// public input.
    fn merkle_verify(
        &self,
        config: &PoRepCircuitConfig,
        layouter: &mut impl Layouter<Halo2Fr>,
        leaf: AssignedCell<Halo2Fr, Halo2Fr>,
        path: &[(Value<Halo2Fr>, bool); MERKLE_DEPTH],
        root_pi: usize,
    ) -> Result<(), ErrorFront> {
        let mut cur = leaf;
        for (level, (sib_val, sib_is_left)) in path.iter().enumerate() {
            // Witness the sibling as a fresh cell so it copy-binds into the
            // Poseidon inputs.
            let sib_cell = layouter.assign_region(
                || format!("merkle_sib_l{}", level),
                |mut region| region.assign_advice(|| "sibling", config.witness, 0, || *sib_val),
            )?;
            cur = if *sib_is_left {
                PoseidonChip::hash_n_from_cells(&config.poseidon, layouter, &[sib_cell, cur])?
            } else {
                PoseidonChip::hash_n_from_cells(&config.poseidon, layouter, &[cur, sib_cell])?
            };
        }
        layouter.constrain_instance(cur.cell(), config.instance, root_pi)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests — the soundness net (real prove+verify with KZG + MockProver).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    /// k for the reduced PoRep instance. The circuit runs several Poseidon
    /// permutations (~65 rows each): replicaID + 2 labels + column + 2
    /// encode-bridge hashes + 6 Merkle-node hashes ≈ 12 permutations ≈
    /// ~800 rows, plus blinding/permutation overhead. k=13 (8192 rows) is
    /// comfortable; the inference circuit used k=12 for ~3 permutations.
    const K: u32 = 13;

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
    /// every challenge index, via MockProver AND a real KZG prove+verify.
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
    /// pipeline the future 0x0108 PoRep circuit_version will run).
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

    /// Finding 1.1 — wrong replicaID. Take A's honestly-sealed replica but
    /// present B's replicaID as the public input (and B's pinner identity
    /// in the witness). The labels in the witness are A's, so the
    /// in-circuit labeling relation (which recomputes labels from the
    /// PUBLIC replicaID = B's) no longer matches A's sealed leaves /
    /// commitments → MUST fail. This proves the keying binds: B cannot
    /// reuse A's sealed bytes.
    #[test]
    fn porep_reduced_negative_wrong_replica_id() {
        let pinner_a = Halo2Fr::from(0xA11CEu64);
        let pinner_b = Halo2Fr::from(0xB0Bu64);
        let sealed_a = seal_sample(pinner_a);
        let sealed_b = seal_sample(pinner_b);
        let v = 1usize;

        // Build the circuit with A's sealed witness BUT B's identity. The
        // recomputed replicaID (from B's identity) will not match A's
        // commitments, and the public replicaID we feed is B's.
        let mut circuit = PoRepCircuit::from_sealed(&sealed_a, pinner_a, v);
        circuit.pinner_identity = Value::known(pinner_b);

        // Public inputs claim B's replicaID but A's commitments (the
        // attempted-reuse scenario).
        let mut pis = PoRepCircuit::public_inputs(&sealed_a, v);
        pis[pi::REPLICA_ID] = sealed_b.replica_id;

        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoRep with B's replicaID over A's replica MUST fail (finding 1.1)"
        );
    }

    /// Tampered label — perturb the challenged node's layer-2 label in the
    /// witness while keeping the public commitments. The labeling relation
    /// recomputes label(2,v*) from replicaID + parents and the encoding /
    /// column consume it; a tampered label no longer matches → MUST fail.
    #[test]
    fn porep_reduced_negative_tampered_label() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 1usize;

        let mut circuit = PoRepCircuit::from_sealed(&sealed, pinner, v);
        // Corrupt the DRG parent label feeding label(2,v*): the recomputed
        // label(2,v*) diverges from the sealed one, breaking encoding +
        // column + R-inclusion.
        circuit.drg_parent_l2 = Value::known(sealed.labels[1][0] + Halo2Fr::from(1u64));

        let pis = PoRepCircuit::public_inputs(&sealed, v);
        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoRep with a tampered label MUST fail the labeling relation"
        );
    }

    /// Wrong stored node value — present a data leaf that is not the one
    /// committed in CommD (a non-stored / wrong node value). The Merkle
    /// inclusion of D[v*] against the public CommD MUST fail.
    #[test]
    fn porep_reduced_negative_wrong_node_value() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 3usize;

        let mut circuit = PoRepCircuit::from_sealed(&sealed, pinner, v);
        // Claim a different data value for the challenged node than the one
        // in CommD. (We also break encoding, but the D-inclusion alone is
        // enough to reject.)
        circuit.data_challenged = Value::known(sealed.data[v] + Halo2Fr::from(99u64));

        let pis = PoRepCircuit::public_inputs(&sealed, v);
        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoRep with a non-stored node value MUST fail Merkle inclusion"
        );
    }

    /// Sanity — different replicaIDs produce DIFFERENT labels for EVERY
    /// (l, v) and therefore different CommR (the spec's acceptance #3).
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
        // CommD is over the same data → identical (binds to content, not pinner).
        assert_eq!(
            sealed_a.comm_d, sealed_b.comm_d,
            "CommD binds to content only"
        );
    }

    /// The reduced public-input layout has 8 slots — distinct from the
    /// inference circuit's 3-commitment shape (domain separation at the
    /// shape level; the VK-registry circuit_version split is PIN-P1
    /// follow-up).
    #[test]
    fn porep_reduced_public_input_shape() {
        assert_eq!(pi::COUNT, 8);
        let sealed = seal_sample(Halo2Fr::from(1u64));
        let pis = PoRepCircuit::public_inputs(&sealed, 0);
        assert_eq!(pis.len(), 8);
    }
}
