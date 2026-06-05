//! PIN-P1 (f.2c) — K-fold PoRep composition in ONE circuit.
//!
//! Replicates the f.2b per-challenge gate-set K times within a single
//! Halo2 Circuit, sharing the shared identity-tuple witnessing
//! (`pinnerIdentity`, `cid`, `sectorIndex`, `epoch`, `replicaID`) and
//! the public CommD/R/C bindings across all K challenges. Soundness for
//! the K-fold proof reduces to `f^K` where `f` is the storage-fraction
//! an adversary can shortcut per single challenge (Filecoin's analysed
//! bound).
//!
//! ## Scope (v0)
//!
//! - **K challenge indices as PUBLIC INPUTS.** Layout is 8 base +
//!   K trailing (replicaID, cid, sectorIndex, CommD, CommR, CommC,
//!   challengeNonce_seed, epoch, idx_0, idx_1, …, idx_{K-1}). The
//!   verifier is expected to compute the K indices off-chain (or in the
//!   precompile dispatcher) from
//!   `(challengeNonce_seed, epoch, replicaID, sectorIndex)` via the
//!   same Poseidon expansion as
//!   [`super::porep_generic::derive_challenge_indices`] and pass them
//!   alongside.
//! - **In-circuit derivation is f.2c.1** (follow-up). Once it lands, the
//!   K trailing PIs collapse and the ABI returns to 8 elements — at a
//!   NEW circuit_version (v4 / v5).
//! - **NEW circuit version.** v2's 8-element ABI is untouched. This
//!   circuit ships as v4 (v3 is PoSt). The on-chain dispatcher gains a
//!   v4 arm in [`super::mod::verify_proof_dispatch`] only when the v4
//!   VK lands in (f.6).
//! - **Reduced `porep::PoRepCircuit` + parameterised `porep_circuit_generic`
//!   untouched.** Both stay as fast dev/test fixtures; this module is
//!   additive.
//! - **`v* < d_DRG` mux deferred** (same edge-case as f.2b). Tests
//!   constrain `v ≥ d_DRG` for all K challenges.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr as Halo2Fr;

use super::chips::{PoseidonChip, PoseidonChipConfig};
use super::porep::{pi as porep_pi, SwapMerkleConfig};
use super::porep_generic::{GenericChallenge, GenericSealedReplica, PoRepParams};

// ---------------------------------------------------------------------------
// Public-input layout (v4 — K-fold PoRep).
// ---------------------------------------------------------------------------

/// Slot indices for the K-fold public-input layout. The first 8 slots
/// match the v2 ABI byte-for-byte (replicaID, cid, sectorIndex, CommD,
/// CommR, CommC, challengeNonce_seed, epoch); slots `8..8+K` are the K
/// per-challenge indices.
pub mod pi_kfold {
    use super::porep_pi;
    pub use porep_pi::{
        CHALLENGE_NONCE as CHALLENGE_NONCE_SEED, CID, COMM_C, COMM_D, COMM_R, EPOCH, REPLICA_ID,
        SECTOR_INDEX,
    };
    /// Index of the first per-challenge index slot in the PI vector.
    pub const FIRST_CHALLENGE_IDX: usize = 8;
    /// Total PI count for a K-fold instance: 8 base + K challenge indices.
    #[inline]
    pub const fn count(k: usize) -> usize {
        FIRST_CHALLENGE_IDX + k
    }
}

// ---------------------------------------------------------------------------
// Config.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PoRepKFoldConfig {
    poseidon: PoseidonChipConfig,
    swap: SwapMerkleConfig,
    /// Three-column add gate enforcing `add_c = add_a + add_b`, used for
    /// the per-challenge encoding relation `R[v] = D[v] + label(L, v)`.
    add_a: Column<Advice>,
    add_b: Column<Advice>,
    add_c: Column<Advice>,
    s_add: Selector,
    instance: Column<Instance>,
}

// ---------------------------------------------------------------------------
// Circuit.
// ---------------------------------------------------------------------------

/// K-fold parameterised in-circuit PoRep at arbitrary `(N, L, K)`. Same
/// per-challenge relation as [`super::porep_circuit_generic::PoRepCircuitGeneric`]
/// (replicaID hash → bit-decompose v → per-layer labeling → encoding →
/// column → 3 arbitrary-depth Merkle inclusions → per-parent column
/// inclusion against CommC), replicated K times.
#[derive(Clone)]
pub struct PoRepCircuitKFold {
    /// Public params (carried so configure + synthesize know the
    /// per-layer arities + the Merkle depth + K). Frozen at keygen time.
    pub params: PoRepParams,

    // Private identity pre-image of replicaID.
    pub pinner_identity: Value<Halo2Fr>,
    pub cid: Value<Halo2Fr>,
    pub sector_index: Value<Halo2Fr>,
    pub epoch: Value<Halo2Fr>,

    /// The K per-challenge witness bundles (length = `params.k`).
    pub challenges: Vec<KFoldChallengeWitness>,
}

/// Per-challenge witness, mirroring
/// [`super::porep_generic::GenericChallenge`] with `Value`-typed cells
/// for in-circuit consumption.
#[derive(Clone)]
pub struct KFoldChallengeWitness {
    pub challenge_index: usize,
    pub data_challenged: Value<Halo2Fr>,
    pub labels_at_v: Vec<Value<Halo2Fr>>,
    pub drg_parent_columns: Vec<Vec<Value<Halo2Fr>>>,
    pub exp_parent_columns: Vec<Vec<Value<Halo2Fr>>>,
    pub drg_parent_indices: Vec<usize>,
    pub exp_parent_indices: Vec<usize>,
    pub sib_d: Vec<Value<Halo2Fr>>,
    pub sib_r: Vec<Value<Halo2Fr>>,
    pub sib_c: Vec<Value<Halo2Fr>>,
    pub drg_parent_sib_c: Vec<Vec<Value<Halo2Fr>>>,
    pub exp_parent_sib_c: Vec<Vec<Value<Halo2Fr>>>,
}

impl KFoldChallengeWitness {
    pub fn from_challenge(challenge: &GenericChallenge) -> Self {
        Self {
            challenge_index: challenge.v,
            data_challenged: Value::known(challenge.data_leaf),
            labels_at_v: challenge
                .labels_at_v
                .iter()
                .copied()
                .map(Value::known)
                .collect(),
            drg_parent_columns: challenge
                .drg_parent_columns
                .iter()
                .map(|col| col.iter().copied().map(Value::known).collect())
                .collect(),
            exp_parent_columns: challenge
                .exp_parent_columns
                .iter()
                .map(|col| col.iter().copied().map(Value::known).collect())
                .collect(),
            drg_parent_indices: challenge.drg_parent_indices.clone(),
            exp_parent_indices: challenge.exp_parent_indices.clone(),
            sib_d: challenge.sib_d.iter().copied().map(Value::known).collect(),
            sib_r: challenge.sib_r.iter().copied().map(Value::known).collect(),
            sib_c: challenge.sib_c.iter().copied().map(Value::known).collect(),
            drg_parent_sib_c: challenge
                .drg_parent_sib_c
                .iter()
                .map(|sibs| sibs.iter().copied().map(Value::known).collect())
                .collect(),
            exp_parent_sib_c: challenge
                .exp_parent_sib_c
                .iter()
                .map(|sibs| sibs.iter().copied().map(Value::known).collect())
                .collect(),
        }
    }

    fn unknown_for_params(params: &PoRepParams) -> Self {
        let l = params.l;
        let depth = params.merkle_depth();
        let drg_d = params.d_drg;
        let exp_d = params.d_exp;
        Self {
            challenge_index: 0,
            data_challenged: Value::unknown(),
            labels_at_v: vec![Value::unknown(); l],
            drg_parent_columns: (0..drg_d).map(|_| vec![Value::unknown(); l]).collect(),
            exp_parent_columns: (0..exp_d).map(|_| vec![Value::unknown(); l]).collect(),
            drg_parent_indices: vec![0; drg_d],
            exp_parent_indices: vec![0; exp_d],
            sib_d: vec![Value::unknown(); depth],
            sib_r: vec![Value::unknown(); depth],
            sib_c: vec![Value::unknown(); depth],
            drg_parent_sib_c: (0..drg_d).map(|_| vec![Value::unknown(); depth]).collect(),
            exp_parent_sib_c: (0..exp_d).map(|_| vec![Value::unknown(); depth]).collect(),
        }
    }
}

impl PoRepCircuitKFold {
    /// Honest-prover constructor — assemble from a sealed replica + the
    /// K challenge bundles produced by
    /// [`super::porep_generic::build_challenges`].
    pub fn from_sealed(
        sealed: &GenericSealedReplica,
        pinner_identity: Halo2Fr,
        challenges: &[GenericChallenge],
    ) -> Self {
        assert_eq!(
            challenges.len(),
            sealed.params.k,
            "from_sealed: expected K={} challenges, got {}",
            sealed.params.k,
            challenges.len()
        );
        Self {
            params: sealed.params.clone(),
            pinner_identity: Value::known(pinner_identity),
            cid: Value::known(sealed.cid),
            sector_index: Value::known(sealed.sector_index),
            epoch: Value::known(sealed.epoch),
            challenges: challenges
                .iter()
                .map(KFoldChallengeWitness::from_challenge)
                .collect(),
        }
    }

    /// Empty (unknown-witness) circuit for keygen. Carries `params` so
    /// the gate count covers `(L, d_DRG, d_EXP, depth, K)` at the WORST
    /// case (full-degree parents, K challenges).
    pub fn empty_for_params(params: PoRepParams) -> Self {
        let k = params.k;
        Self {
            challenges: (0..k)
                .map(|_| KFoldChallengeWitness::unknown_for_params(&params))
                .collect(),
            params,
            pinner_identity: Value::unknown(),
            cid: Value::unknown(),
            sector_index: Value::unknown(),
            epoch: Value::unknown(),
        }
    }

    /// The public-input vector for a sealed replica + K challenge
    /// indices. Layout: 8 base (matching v2) + K challenge indices.
    pub fn public_inputs(
        sealed: &GenericSealedReplica,
        challenge_seed: Halo2Fr,
        challenge_indices: &[usize],
    ) -> Vec<Halo2Fr> {
        assert_eq!(challenge_indices.len(), sealed.params.k);
        let mut pis = vec![Halo2Fr::from(0u64); pi_kfold::count(sealed.params.k)];
        pis[pi_kfold::REPLICA_ID] = sealed.replica_id;
        pis[pi_kfold::CID] = sealed.cid;
        pis[pi_kfold::SECTOR_INDEX] = sealed.sector_index;
        pis[pi_kfold::COMM_D] = sealed.comm_d;
        pis[pi_kfold::COMM_R] = sealed.comm_r;
        pis[pi_kfold::COMM_C] = sealed.comm_c;
        pis[pi_kfold::CHALLENGE_NONCE_SEED] = challenge_seed;
        pis[pi_kfold::EPOCH] = sealed.epoch;
        for (i, &v) in challenge_indices.iter().enumerate() {
            pis[pi_kfold::FIRST_CHALLENGE_IDX + i] = Halo2Fr::from(v as u64);
        }
        pis
    }
}

impl Circuit<Halo2Fr> for PoRepCircuitKFold {
    type Config = PoRepKFoldConfig;
    type FloorPlanner = SimpleFloorPlanner;

    #[cfg(feature = "circuit-params")]
    type Params = PoRepParams;

    fn without_witnesses(&self) -> Self {
        Self::empty_for_params(self.params.clone())
    }

    fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self::Config {
        let poseidon = PoseidonChip::configure(meta);
        let swap = SwapMerkleConfig::configure(meta);

        let add_a = meta.advice_column();
        let add_b = meta.advice_column();
        let add_c = meta.advice_column();
        for col in [add_a, add_b, add_c] {
            meta.enable_equality(col);
        }
        let s_add = meta.selector();
        meta.create_gate("porep_kfold_encode_add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(add_a, Rotation::cur());
            let b = meta.query_advice(add_b, Rotation::cur());
            let c = meta.query_advice(add_c, Rotation::cur());
            vec![s * (c - a - b)]
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);
        PoRepKFoldConfig {
            poseidon,
            swap,
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
        let l = self.params.l;
        let k = self.params.k;

        // ───────────────────────────────────────────────────────────────
        // Shared (once per proof): identity-tuple + replicaID + base PIs.
        // ───────────────────────────────────────────────────────────────
        let pid_cell = swap.assign_value(&mut layouter, self.pinner_identity, "pinner_id")?;
        let cid_cell = swap.assign_value(&mut layouter, self.cid, "cid")?;
        let sector_cell = swap.assign_value(&mut layouter, self.sector_index, "sector_idx")?;
        let epoch_cell = swap.assign_value(&mut layouter, self.epoch, "epoch")?;

        let replica_id_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[pid_cell.clone(), cid_cell.clone(), sector_cell.clone()],
        )?;
        layouter.constrain_instance(
            replica_id_cell.cell(),
            config.instance,
            pi_kfold::REPLICA_ID,
        )?;
        layouter.constrain_instance(cid_cell.cell(), config.instance, pi_kfold::CID)?;
        layouter.constrain_instance(sector_cell.cell(), config.instance, pi_kfold::SECTOR_INDEX)?;
        layouter.constrain_instance(epoch_cell.cell(), config.instance, pi_kfold::EPOCH)?;

        // Layer constants used in every challenge's labeling preimages.
        let mut layer_consts: Vec<AssignedCell<Halo2Fr, Halo2Fr>> = Vec::with_capacity(l);
        for layer in 1..=l {
            let name: &'static str = match layer {
                1 => "layer=1",
                2 => "layer=2",
                3 => "layer=3",
                4 => "layer=4",
                5 => "layer=5",
                _ => "layer=k",
            };
            layer_consts.push(swap.assign_const(
                &mut layouter,
                Halo2Fr::from(layer as u64),
                name,
            )?);
        }

        // ───────────────────────────────────────────────────────────────
        // Per-challenge (K times): the f.2b gate-set, one v* at a time.
        // Each recomputed CommD/R/C root is `constrain_instance`d to the
        // SAME public PI slot, so all K instances must reconstruct to the
        // same public commitments (consistency).
        // ───────────────────────────────────────────────────────────────
        for (i, ch) in self.challenges.iter().enumerate() {
            per_challenge_synthesize(
                &config,
                &mut layouter,
                &replica_id_cell,
                &layer_consts,
                ch,
                i,
                l,
            )?;
        }
        // K invariant — sanity guard for self.challenges length at honest
        // prover time (defensive; the honest constructor asserts this too).
        debug_assert_eq!(self.challenges.len(), k);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-challenge body — extracted so it reads as ONE relation, K times.
// ---------------------------------------------------------------------------

fn per_challenge_synthesize(
    config: &PoRepKFoldConfig,
    layouter: &mut impl Layouter<Halo2Fr>,
    replica_id_cell: &AssignedCell<Halo2Fr, Halo2Fr>,
    layer_consts: &[AssignedCell<Halo2Fr, Halo2Fr>],
    ch: &KFoldChallengeWitness,
    challenge_slot: usize,
    l: usize,
) -> Result<(), ErrorFront> {
    let swap = &config.swap;

    // Per-challenge witnesses.
    let data_cell = swap.assign_value(layouter, ch.data_challenged, "data[v*]")?;
    let mut label_cells: Vec<AssignedCell<Halo2Fr, Halo2Fr>> = Vec::with_capacity(l);
    for (layer_idx, lbl) in ch.labels_at_v.iter().enumerate() {
        let name: &'static str = match layer_idx {
            0 => "label@l=1[v*]",
            1 => "label@l=2[v*]",
            2 => "label@l=3[v*]",
            3 => "label@l=4[v*]",
            4 => "label@l=5[v*]",
            _ => "label@l=k[v*]",
        };
        label_cells.push(swap.assign_value(layouter, *lbl, name)?);
    }
    let drg_columns_cells: Vec<Vec<AssignedCell<Halo2Fr, Halo2Fr>>> =
        assign_columns(swap, layouter, &ch.drg_parent_columns, "drg_col")?;
    let exp_columns_cells: Vec<Vec<AssignedCell<Halo2Fr, Halo2Fr>>> =
        assign_columns(swap, layouter, &ch.exp_parent_columns, "exp_col")?;

    let depth = ch.sib_d.len();
    let idx_val = Value::known(Halo2Fr::from(ch.challenge_index as u64));
    let (idx_cell, bits) = swap.decompose_index_generic(layouter, idx_val, depth)?;
    layouter.constrain_instance(
        idx_cell.cell(),
        config.instance,
        pi_kfold::FIRST_CHALLENGE_IDX + challenge_slot,
    )?;

    // Labeling relation per layer (mirrors f.2b).
    for layer in 1..=l {
        let mut preimage: Vec<AssignedCell<Halo2Fr, Halo2Fr>> =
            Vec::with_capacity(3 + drg_columns_cells.len() + exp_columns_cells.len());
        preimage.push(replica_id_cell.clone());
        preimage.push(layer_consts[layer - 1].clone());
        preimage.push(idx_cell.clone());
        for col in &drg_columns_cells {
            preimage.push(col[layer - 1].clone());
        }
        if layer >= 2 {
            for col in &exp_columns_cells {
                preimage.push(col[layer - 2].clone());
            }
        }
        let recomputed = PoseidonChip::hash_n_from_cells(&config.poseidon, layouter, &preimage)?;
        layouter.assign_region(
            || "label_relation_eq",
            |mut region| {
                let lhs = recomputed.copy_advice(|| "lhs", &mut region, swap.a(), 0)?;
                let rhs = label_cells[layer - 1].copy_advice(|| "rhs", &mut region, swap.b(), 0)?;
                region.constrain_equal(lhs.cell(), rhs.cell())?;
                Ok(())
            },
        )?;
    }

    // Encoding: R[v*] = D[v*] + label(L, v*).
    let replica_leaf_cell = layouter.assign_region(
        || "encode_R",
        |mut region| {
            let d = data_cell.copy_advice(|| "D[v*]", &mut region, config.add_a, 0)?;
            let last =
                label_cells[l - 1].copy_advice(|| "label(L,v*)", &mut region, config.add_b, 0)?;
            let r_val = d.value().copied() + last.value().copied();
            let r = region.assign_advice(|| "R[v*]", config.add_c, 0, || r_val)?;
            config.s_add.enable(&mut region, 0)?;
            Ok(r)
        },
    )?;

    // column(v*) = Poseidon(label(1, v*), …, label(L, v*)).
    let column_cell = PoseidonChip::hash_n_from_cells(&config.poseidon, layouter, &label_cells)?;

    // Three index-agnostic arbitrary-depth Merkle inclusions of v*.
    // Each recomputed root is constrain_instance'd to the SAME public PI
    // slot across all K challenges — Halo2 PSE allows many-to-one
    // bindings, so K cells anchored to the same instance cell are valid.
    let sib_d = assign_sibs(swap, layouter, &ch.sib_d, "sib_d")?;
    let root_d =
        swap.merkle_root_generic(&config.poseidon, layouter, data_cell.clone(), &bits, &sib_d)?;
    layouter.constrain_instance(root_d.cell(), config.instance, pi_kfold::COMM_D)?;

    let sib_r = assign_sibs(swap, layouter, &ch.sib_r, "sib_r")?;
    let root_r =
        swap.merkle_root_generic(&config.poseidon, layouter, replica_leaf_cell, &bits, &sib_r)?;
    layouter.constrain_instance(root_r.cell(), config.instance, pi_kfold::COMM_R)?;

    let sib_c = assign_sibs(swap, layouter, &ch.sib_c, "sib_c")?;
    let root_c =
        swap.merkle_root_generic(&config.poseidon, layouter, column_cell, &bits, &sib_c)?;
    layouter.constrain_instance(root_c.cell(), config.instance, pi_kfold::COMM_C)?;

    // Per-parent column inclusions against root_c (= public CommC).
    for (col_cells, (p, sibs)) in drg_columns_cells
        .iter()
        .zip(ch.drg_parent_indices.iter().zip(ch.drg_parent_sib_c.iter()))
    {
        assert_parent_inclusion(
            config,
            layouter,
            col_cells,
            *p,
            sibs,
            &root_c,
            "drg_parent_inclusion",
        )?;
    }
    for (col_cells, (e, sibs)) in exp_columns_cells
        .iter()
        .zip(ch.exp_parent_indices.iter().zip(ch.exp_parent_sib_c.iter()))
    {
        assert_parent_inclusion(
            config,
            layouter,
            col_cells,
            *e,
            sibs,
            &root_c,
            "exp_parent_inclusion",
        )?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn assign_sibs(
    swap: &SwapMerkleConfig,
    layouter: &mut impl Layouter<Halo2Fr>,
    sibs: &[Value<Halo2Fr>],
    name: &'static str,
) -> Result<Vec<AssignedCell<Halo2Fr, Halo2Fr>>, ErrorFront> {
    let mut out = Vec::with_capacity(sibs.len());
    for s in sibs {
        out.push(swap.assign_value(layouter, *s, name)?);
    }
    Ok(out)
}

fn assign_columns(
    swap: &SwapMerkleConfig,
    layouter: &mut impl Layouter<Halo2Fr>,
    columns: &[Vec<Value<Halo2Fr>>],
    name: &'static str,
) -> Result<Vec<Vec<AssignedCell<Halo2Fr, Halo2Fr>>>, ErrorFront> {
    let mut out = Vec::with_capacity(columns.len());
    for col in columns {
        let mut cell_col = Vec::with_capacity(col.len());
        for c in col {
            cell_col.push(swap.assign_value(layouter, *c, name)?);
        }
        out.push(cell_col);
    }
    Ok(out)
}

fn assert_parent_inclusion(
    config: &PoRepKFoldConfig,
    layouter: &mut impl Layouter<Halo2Fr>,
    column_cells: &[AssignedCell<Halo2Fr, Halo2Fr>],
    parent_index: usize,
    parent_sibs: &[Value<Halo2Fr>],
    root_c: &AssignedCell<Halo2Fr, Halo2Fr>,
    label: &'static str,
) -> Result<(), ErrorFront> {
    let col_at_p = PoseidonChip::hash_n_from_cells(&config.poseidon, layouter, column_cells)?;
    let depth = parent_sibs.len();
    let (_p_idx_cell, p_bits) = config.swap.decompose_index_generic(
        layouter,
        Value::known(Halo2Fr::from(parent_index as u64)),
        depth,
    )?;
    let p_sibs = assign_sibs(&config.swap, layouter, parent_sibs, label)?;
    let recomputed =
        config
            .swap
            .merkle_root_generic(&config.poseidon, layouter, col_at_p, &p_bits, &p_sibs)?;
    layouter.assign_region(
        || label,
        |mut region| {
            let lhs = recomputed.copy_advice(|| "lhs", &mut region, config.swap.a(), 0)?;
            let rhs = root_c.copy_advice(|| "rhs", &mut region, config.swap.b(), 0)?;
            region.constrain_equal(lhs.cell(), rhs.cell())?;
            Ok(())
        },
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::halo2::porep_generic::{build_challenge, seal_generic, PoRepParams};
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr as Halo2Fr;

    /// k for the K-fold MockProver. (N=16, L=3, K=3) needs the same gate
    /// budget as f.2b's K_MEDIUM (k=17) per challenge, scaled by K. Bumping
    /// to k=18 (262144 rows) is comfortable for K=3.
    const K_DEG_KFOLD: u32 = 18;

    fn seed_zero() -> [u8; 32] {
        [0u8; 32]
    }

    fn one_through(n: usize) -> Vec<Halo2Fr> {
        (1..=n as u64).map(Halo2Fr::from).collect()
    }

    /// f.2c happy path — K=3 honest challenges at (N=16, L=3) all pick
    /// `v ≥ d_DRG` so the variable-arity edge case is avoided. The K
    /// CommD/R/C bindings to the SAME public PI slot must all hold.
    #[test]
    fn kfold_porep_verifies_at_k3_n16_l3() {
        let params = PoRepParams {
            n: 16,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 3,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA1u64),
            Halo2Fr::from(0xB2u64),
            Halo2Fr::from(0xC3u64),
            Halo2Fr::from(0xD4u64),
            one_through(16),
        )
        .expect("seal");

        // Hand-pick K=3 challenges with v ≥ d_DRG.
        let indices = [9usize, 12, 14];
        let challenges: Vec<_> = indices
            .iter()
            .map(|&v| build_challenge(&sealed, v).expect("ch"))
            .collect();
        let circuit = PoRepCircuitKFold::from_sealed(&sealed, Halo2Fr::from(0xA1u64), &challenges);
        let pis = PoRepCircuitKFold::public_inputs(
            &sealed,
            Halo2Fr::from(0xFEu64), // challengeNonce_seed — not yet bound to the indices in v0
            &indices,
        );
        let prover = MockProver::run(K_DEG_KFOLD, &circuit, vec![pis]).expect("setup");
        assert_eq!(
            prover.verify(),
            Ok(()),
            "honest K=3 PoRep must verify at (N=16,L=3)"
        );
    }

    /// f.2c negative — tamper with the SECOND challenge's data leaf. The
    /// second iteration's CommD inclusion no longer reconstructs the
    /// public CommD (the first + third reconstruct correctly, but the
    /// many-to-one PI binding requires ALL K to match — so the proof
    /// must reject).
    #[test]
    fn kfold_porep_rejects_tampered_challenge_data() {
        let params = PoRepParams {
            n: 16,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 3,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA1u64),
            Halo2Fr::from(0xB2u64),
            Halo2Fr::from(0xC3u64),
            Halo2Fr::from(0xD4u64),
            one_through(16),
        )
        .expect("seal");

        let indices = [9usize, 12, 14];
        let challenges: Vec<_> = indices
            .iter()
            .map(|&v| build_challenge(&sealed, v).expect("ch"))
            .collect();
        let mut circuit =
            PoRepCircuitKFold::from_sealed(&sealed, Halo2Fr::from(0xA1u64), &challenges);
        // Tamper the second challenge's witnessed data leaf.
        circuit.challenges[1].data_challenged =
            Value::known(sealed.data[indices[1]] + Halo2Fr::from(777u64));

        let pis = PoRepCircuitKFold::public_inputs(&sealed, Halo2Fr::from(0xFEu64), &indices);
        let prover = MockProver::run(K_DEG_KFOLD, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "tampered data leaf in one of K challenges MUST be rejected"
        );
    }

    /// f.2c negative — mismatch between witnessed challenge index and
    /// the PUBLIC index slot. The PI binding for `idx_cell` to
    /// `pi_kfold::FIRST_CHALLENGE_IDX + i` should reject when the prover
    /// witnesses a DIFFERENT index than the public-input slot.
    #[test]
    fn kfold_porep_rejects_index_mismatch() {
        let params = PoRepParams {
            n: 16,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 3,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA1u64),
            Halo2Fr::from(0xB2u64),
            Halo2Fr::from(0xC3u64),
            Halo2Fr::from(0xD4u64),
            one_through(16),
        )
        .expect("seal");

        let indices = [9usize, 12, 14];
        let challenges: Vec<_> = indices
            .iter()
            .map(|&v| build_challenge(&sealed, v).expect("ch"))
            .collect();
        let circuit = PoRepCircuitKFold::from_sealed(&sealed, Halo2Fr::from(0xA1u64), &challenges);

        // Public-input vector advertises a DIFFERENT first challenge
        // index than what the witness builder used.
        let mut bad_indices = indices;
        bad_indices[0] = 11; // witness was 9
        let pis = PoRepCircuitKFold::public_inputs(&sealed, Halo2Fr::from(0xFEu64), &bad_indices);
        let prover = MockProver::run(K_DEG_KFOLD, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "challenge-index mismatch with PI slot MUST be rejected"
        );
    }
}
