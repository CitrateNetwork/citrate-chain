//! PIN-P1 (f.2b) — Parameterised in-circuit PoRep lift.
//!
//! The Halo2 Circuit impl at arbitrary `(N, L)` for ONE challenge per
//! proof. Consumes the shape contract from
//! [`super::porep_generic`] (`PoRepParams`, `GenericSealedReplica`,
//! `GenericChallenge`) and reuses [`super::porep::SwapMerkleConfig`]'s
//! index-agnostic gadgets — extended with `merkle_root_generic` +
//! `decompose_index_generic` so a SINGLE VK covers any `(N, L, depth)`
//! choice.
//!
//! ## Scope
//!
//! - **Single-challenge** (`K = 1`). K-fold in-circuit composition is a
//!   clean follow-on (f.2c) — the per-challenge gate-set is the
//!   architectural piece, K-fold is mechanical replication.
//! - **Reduced `porep::PoRepCircuit` untouched.** Per the DGX handoff
//!   §0(2), the reduced circuit stays as the fast dev/test fixture.
//!   This module ships as `PoRepCircuitGeneric` beside it.
//! - **v2 + v3 on-chain VKs unchanged.** The v2 verifier in `mod.rs`
//!   keeps pointing at the reduced circuit's VK until **f.6** discharges
//!   TD-19.
//!
//! ## Public-input layout
//!
//! Identical to the reduced circuit (`porep::pi`) at K=1:
//!
//! ```text
//!   [0] replicaID  [1] cid     [2] sectorIndex
//!   [3] CommD      [4] CommR   [5] CommC
//!   [6] challengeNonce         [7] epoch
//! ```
//!
//! The K-fold variant in f.2c will keep the same 8-element ABI — only
//! `challengeNonce` carries the seed; the K per-challenge indices are
//! derived in-circuit (via the same Poseidon expansion as
//! `porep_generic::derive_challenge_indices`).
//!
//! ## In-circuit relation (mirrors `porep_generic`'s native sealer)
//!
//! For the witnessed challenge index `v*`:
//!
//! 1. `replicaID = Poseidon(pinnerIdentity, cid, sectorIndex)`
//! 2. For each layer `l ∈ [1, L]`:
//!    ```text
//!      label(l, v*) = Poseidon( replicaID, l, v*,
//!                              parents_same_layer...,    (d_DRG parents at THIS layer)
//!                              parents_prev_layer... )   (d_EXP at layer-1, empty at l=1)
//!    ```
//!    Where `parents_same_layer[i] = labels_at_parent[drg_p_i][l-1]` and
//!    `parents_prev_layer[j] = labels_at_parent[exp_p_j][l-2]`. The
//!    parent labels are witnessed *with* their column inclusions against
//!    `CommC` (step 6 below), so a cheating prover cannot supply
//!    arbitrary parent labels.
//! 3. `R[v*] = D[v*] + label(L, v*)` (encoding).
//! 4. `column(v*) = Poseidon(label(1, v*), …, label(L, v*))`.
//! 5. Three Merkle inclusions against `CommD`, `CommR`, `CommC` at index
//!    `v*` (arbitrary depth via `merkle_root_generic`).
//! 6. For every DRG parent + every expander parent: prove the parent's
//!    column is committed in `CommC` at that parent's index. Soundness
//!    contract from ADR-PIN-P1.

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
// Circuit config — shares `SwapMerkleConfig` + adds the encoding add gate.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PoRepGenericConfig {
    poseidon: PoseidonChipConfig,
    swap: SwapMerkleConfig,
    /// Three-column add gate enforcing `add_c = add_a + add_b`, used for
    /// the encoding relation `R[v] = D[v] + label(L, v)`.
    add_a: Column<Advice>,
    add_b: Column<Advice>,
    add_c: Column<Advice>,
    s_add: Selector,
    instance: Column<Instance>,
}

// ---------------------------------------------------------------------------
// Circuit.
// ---------------------------------------------------------------------------

/// Parameterised in-circuit PoRep at arbitrary `(N, L)`, single-challenge.
///
/// Witnesses the full per-challenge bundle from
/// [`super::porep_generic::GenericChallenge`] plus the four identity-
/// tuple scalars + the challenge index.
///
/// **Index-agnostic + topology-agnostic.** The witness is the only
/// thing that varies between proofs — the gate shape depends ONLY on
/// `(N, L, d_DRG, d_EXP)` (compile-time-like via `Params` carried into
/// the empty circuit), so a single VK covers every challenge index AND
/// every sealing instance with matching params.
#[derive(Clone)]
pub struct PoRepCircuitGeneric {
    /// Public params (carried so `configure` + `synthesize` know the
    /// per-layer arities + the Merkle depth). Frozen at keygen time.
    pub params: PoRepParams,

    // Private identity pre-image of replicaID.
    pub pinner_identity: Value<Halo2Fr>,
    pub cid: Value<Halo2Fr>,
    pub sector_index: Value<Halo2Fr>,
    pub epoch: Value<Halo2Fr>,

    /// The challenged node index v* (public via challengeNonce). Witnessed.
    pub challenge_index: usize,

    /// Per-layer labels at v*: `labels_at_v[l-1] = label(l, v*)`. Length L.
    pub labels_at_v: Vec<Value<Halo2Fr>>,

    /// Data leaf at v*.
    pub data_challenged: Value<Halo2Fr>,

    /// DRG (same-layer) parent column witnesses (one per parent), each
    /// `[label(1,p), …, label(L,p)]`. Length matches the sampler's output
    /// at v* (ALWAYS length `d_DRG` per the v*<d_DRG mux; padded slots
    /// carry zero placeholder columns and are gated off via `drg_valid`).
    pub drg_parent_columns: Vec<Vec<Value<Halo2Fr>>>,
    /// Same for expander parents (length d_EXP).
    pub exp_parent_columns: Vec<Vec<Value<Halo2Fr>>>,
    /// PIN-P1 v*<d_DRG mux — per-slot REAL/PADDED boolean. `true` = real
    /// DRG parent (column included in CommC, slot value = honest label).
    /// `false` = PADDED (column-inclusion gate OFF, slot value muxed to
    /// `replicaID`). ALWAYS length `d_DRG`.
    pub drg_valid: Vec<Value<Halo2Fr>>,
    /// Parent indices (witnesses — bound by Merkle inclusion for REAL
    /// slots; sentinel `0` for padded slots).
    pub drg_parent_indices: Vec<usize>,
    pub exp_parent_indices: Vec<usize>,

    /// Merkle sibling values for the three inclusions of node v*. Each is
    /// `params.merkle_depth()` siblings.
    pub sib_d: Vec<Value<Halo2Fr>>,
    pub sib_r: Vec<Value<Halo2Fr>>,
    pub sib_c: Vec<Value<Halo2Fr>>,

    /// Per-parent column-inclusion paths against CommC. Each inner Vec is
    /// `merkle_depth` siblings.
    pub drg_parent_sib_c: Vec<Vec<Value<Halo2Fr>>>,
    pub exp_parent_sib_c: Vec<Vec<Value<Halo2Fr>>>,
}

impl PoRepCircuitGeneric {
    /// Honest-prover constructor — assemble from a sealed replica + a
    /// challenge bundle. The challenge bundle is produced by
    /// [`super::porep_generic::build_challenge`] from the same sealed
    /// replica.
    pub fn from_sealed(
        sealed: &GenericSealedReplica,
        pinner_identity: Halo2Fr,
        challenge: &GenericChallenge,
    ) -> Self {
        Self {
            params: sealed.params.clone(),
            pinner_identity: Value::known(pinner_identity),
            cid: Value::known(sealed.cid),
            sector_index: Value::known(sealed.sector_index),
            epoch: Value::known(sealed.epoch),
            challenge_index: challenge.v,
            labels_at_v: challenge
                .labels_at_v
                .iter()
                .copied()
                .map(Value::known)
                .collect(),
            data_challenged: Value::known(challenge.data_leaf),
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
            drg_valid: challenge
                .drg_valid
                .iter()
                .map(|&b| Value::known(Halo2Fr::from(b as u64)))
                .collect(),
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

    /// Empty (unknown-witness) circuit for keygen. Carries `params`
    /// because the GATE COUNT depends on them (per-layer parent arity).
    pub fn empty_for_params(params: PoRepParams) -> Self {
        let depth = params.merkle_depth();
        let l = params.l;
        // For keygen we need parent counts at the WORST CASE so the gate
        // shape covers any v*. That is `d_DRG` + `d_EXP` (full degree).
        let drg_d = params.d_drg;
        let exp_d = params.d_exp;
        let unknown_col = |_| -> Vec<Value<Halo2Fr>> { vec![Value::unknown(); l] };
        let unknown_sib = || -> Vec<Value<Halo2Fr>> { vec![Value::unknown(); depth] };
        Self {
            params,
            pinner_identity: Value::unknown(),
            cid: Value::unknown(),
            sector_index: Value::unknown(),
            epoch: Value::unknown(),
            challenge_index: 0,
            labels_at_v: vec![Value::unknown(); l],
            data_challenged: Value::unknown(),
            drg_parent_columns: (0..drg_d).map(unknown_col).collect(),
            exp_parent_columns: (0..exp_d).map(unknown_col).collect(),
            drg_valid: vec![Value::unknown(); drg_d],
            drg_parent_indices: vec![0; drg_d],
            exp_parent_indices: vec![0; exp_d],
            sib_d: unknown_sib(),
            sib_r: unknown_sib(),
            sib_c: unknown_sib(),
            drg_parent_sib_c: (0..drg_d).map(|_| unknown_sib()).collect(),
            exp_parent_sib_c: (0..exp_d).map(|_| unknown_sib()).collect(),
        }
    }

    /// The public-input vector for a sealed replica + challenge index.
    /// Matches the v2 ABI byte-for-byte.
    pub fn public_inputs(sealed: &GenericSealedReplica, challenge_index: usize) -> Vec<Halo2Fr> {
        let mut pis = vec![Halo2Fr::from(0u64); porep_pi::COUNT];
        pis[porep_pi::REPLICA_ID] = sealed.replica_id;
        pis[porep_pi::CID] = sealed.cid;
        pis[porep_pi::SECTOR_INDEX] = sealed.sector_index;
        pis[porep_pi::COMM_D] = sealed.comm_d;
        pis[porep_pi::COMM_R] = sealed.comm_r;
        pis[porep_pi::COMM_C] = sealed.comm_c;
        pis[porep_pi::CHALLENGE_NONCE] = Halo2Fr::from(challenge_index as u64);
        pis[porep_pi::EPOCH] = sealed.epoch;
        pis
    }
}

impl Circuit<Halo2Fr> for PoRepCircuitGeneric {
    type Config = PoRepGenericConfig;
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
        meta.create_gate("porep_generic_encode_add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(add_a, Rotation::cur());
            let b = meta.query_advice(add_b, Rotation::cur());
            let c = meta.query_advice(add_c, Rotation::cur());
            vec![s * (c - a - b)]
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);
        PoRepGenericConfig {
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
        let depth = self.params.merkle_depth();

        // ---- Step 1: witness the private scalars + per-layer labels. ----
        let pid_cell = swap.assign_value(&mut layouter, self.pinner_identity, "pinner_id")?;
        let cid_cell = swap.assign_value(&mut layouter, self.cid, "cid")?;
        let sector_cell = swap.assign_value(&mut layouter, self.sector_index, "sector_idx")?;
        let epoch_cell = swap.assign_value(&mut layouter, self.epoch, "epoch")?;
        let data_cell = swap.assign_value(&mut layouter, self.data_challenged, "data[v*]")?;

        // Per-layer label witnesses at v*.
        let mut label_cells: Vec<AssignedCell<Halo2Fr, Halo2Fr>> = Vec::with_capacity(l);
        for (layer_idx, lbl) in self.labels_at_v.iter().enumerate() {
            let name: &'static str = match layer_idx {
                0 => "label@l=1[v*]",
                1 => "label@l=2[v*]",
                2 => "label@l=3[v*]",
                3 => "label@l=4[v*]",
                4 => "label@l=5[v*]",
                _ => "label@l=k[v*]",
            };
            let c = swap.assign_value(&mut layouter, *lbl, name)?;
            label_cells.push(c);
        }

        // Per-parent column witnesses (one column = L cells).
        let drg_columns_cells: Vec<Vec<AssignedCell<Halo2Fr, Halo2Fr>>> =
            assign_columns(swap, &mut layouter, &self.drg_parent_columns, "drg_col")?;
        let exp_columns_cells: Vec<Vec<AssignedCell<Halo2Fr, Halo2Fr>>> =
            assign_columns(swap, &mut layouter, &self.exp_parent_columns, "exp_col")?;

        // PIN-P1 v*<d_DRG mux: assign + boolean-constrain `drg_valid` for
        // each DRG slot. The `is_nonzero` gadget is soundly equal to its
        // input when the input is in {0, 1} (idx·inv − has = 0 forces
        // has = idx), so we use it to enforce booleanness without
        // adding a new gate.
        let drg_valid_cells: Vec<AssignedCell<Halo2Fr, Halo2Fr>> = {
            let mut out = Vec::with_capacity(self.drg_valid.len());
            for v in &self.drg_valid {
                let cell = swap.assign_value(&mut layouter, *v, "drg_valid")?;
                // Boolean-constrain via is_nonzero: returns a soundly-
                // boolean has-cell equal to `(cell ≠ 0)`. For honest
                // {0,1} input the returned has == input; we equate them.
                let has = swap.is_nonzero(&mut layouter, &cell)?;
                layouter.assign_region(
                    || "drg_valid_bool",
                    |mut region| {
                        let lhs = cell.copy_advice(|| "v", &mut region, swap.a(), 0)?;
                        let rhs = has.copy_advice(|| "has", &mut region, swap.b(), 0)?;
                        region.constrain_equal(lhs.cell(), rhs.cell())?;
                        Ok(())
                    },
                )?;
                out.push(cell);
            }
            out
        };

        // ---- Step 2: replicaID = Poseidon(pinnerIdentity, cid, sectorIndex). ----
        let replica_id_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[pid_cell.clone(), cid_cell.clone(), sector_cell.clone()],
        )?;
        layouter.constrain_instance(
            replica_id_cell.cell(),
            config.instance,
            porep_pi::REPLICA_ID,
        )?;
        layouter.constrain_instance(cid_cell.cell(), config.instance, porep_pi::CID)?;
        layouter.constrain_instance(sector_cell.cell(), config.instance, porep_pi::SECTOR_INDEX)?;
        layouter.constrain_instance(epoch_cell.cell(), config.instance, porep_pi::EPOCH)?;

        // ---- Step 2b: witness + bind the challenge index. ----
        let idx_val = Value::known(Halo2Fr::from(self.challenge_index as u64));
        let (idx_cell, bits) = swap.decompose_index_generic(&mut layouter, idx_val, depth)?;
        layouter.constrain_instance(idx_cell.cell(), config.instance, porep_pi::CHALLENGE_NONCE)?;

        // Layer constants used in the labeling preimages.
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

        // ---- Step 3: labeling relation per layer. ----
        // For each layer ℓ in [1, L]:
        //   preimage = [replicaID, ℓ, v*,
        //               drg_columns[*][ℓ-1] ...,    (same-layer DRG parents)
        //               exp_columns[*][ℓ-2] ... ]   (prev-layer expander parents; empty at ℓ=1)
        //   labels_at_v[ℓ-1] == Poseidon(preimage)
        for layer in 1..=l {
            let mut preimage: Vec<AssignedCell<Halo2Fr, Halo2Fr>> = Vec::with_capacity(
                3 + self.drg_parent_columns.len() + self.exp_parent_columns.len(),
            );
            preimage.push(replica_id_cell.clone());
            preimage.push(layer_consts[layer - 1].clone());
            preimage.push(idx_cell.clone());
            // PIN-P1 v*<d_DRG mux: each DRG slot value is
            // `valid_i ? col[layer-1] : replicaID`. Real slots
            // contribute the honest parent label; padded slots contribute
            // `replicaID` (matching the native sealer's padding).
            for (col, valid) in drg_columns_cells.iter().zip(drg_valid_cells.iter()) {
                let muxed = swap.mux(&mut layouter, &replica_id_cell, &col[layer - 1], valid)?;
                preimage.push(muxed);
            }
            if layer >= 2 {
                for col in &exp_columns_cells {
                    preimage.push(col[layer - 2].clone());
                }
            }
            let recomputed =
                PoseidonChip::hash_n_from_cells(&config.poseidon, &mut layouter, &preimage)?;
            // Constrain witnessed label to equal the recomputed Poseidon.
            layouter.assign_region(
                || "label_relation_eq",
                |mut region| {
                    let lhs = recomputed.copy_advice(|| "lhs", &mut region, swap.a(), 0)?;
                    let rhs =
                        label_cells[layer - 1].copy_advice(|| "rhs", &mut region, swap.b(), 0)?;
                    region.constrain_equal(lhs.cell(), rhs.cell())?;
                    Ok(())
                },
            )?;
        }

        // ---- Step 4: encoding. R[v*] = D[v*] + label(L, v*). ----
        let replica_leaf_cell = layouter.assign_region(
            || "encode_R",
            |mut region| {
                let d = data_cell.copy_advice(|| "D[v*]", &mut region, config.add_a, 0)?;
                let last = label_cells[l - 1].copy_advice(
                    || "label(L,v*)",
                    &mut region,
                    config.add_b,
                    0,
                )?;
                let r_val = d.value().copied() + last.value().copied();
                let r = region.assign_advice(|| "R[v*]", config.add_c, 0, || r_val)?;
                config.s_add.enable(&mut region, 0)?;
                Ok(r)
            },
        )?;

        // ---- Step 5: column(v*) = Poseidon(label(1, v*), ..., label(L, v*)). ----
        let column_cell =
            PoseidonChip::hash_n_from_cells(&config.poseidon, &mut layouter, &label_cells)?;

        // ---- Step 6: index-agnostic arbitrary-depth Merkle inclusions. ----
        let sib_d = assign_sibs(swap, &mut layouter, &self.sib_d, "sib_d")?;
        let root_d = swap.merkle_root_generic(
            &config.poseidon,
            &mut layouter,
            data_cell.clone(),
            &bits,
            &sib_d,
        )?;
        layouter.constrain_instance(root_d.cell(), config.instance, porep_pi::COMM_D)?;

        let sib_r = assign_sibs(swap, &mut layouter, &self.sib_r, "sib_r")?;
        let root_r = swap.merkle_root_generic(
            &config.poseidon,
            &mut layouter,
            replica_leaf_cell,
            &bits,
            &sib_r,
        )?;
        layouter.constrain_instance(root_r.cell(), config.instance, porep_pi::COMM_R)?;

        let sib_c = assign_sibs(swap, &mut layouter, &self.sib_c, "sib_c")?;
        let root_c =
            swap.merkle_root_generic(&config.poseidon, &mut layouter, column_cell, &bits, &sib_c)?;
        layouter.constrain_instance(root_c.cell(), config.instance, porep_pi::COMM_C)?;

        // ---- Step 7: PARENT SOUNDNESS — every parent's column included in CommC. ----
        // For each DRG parent + each expander parent: hash the column (the L
        // labels at the parent), bit-decompose the parent index, reconstruct
        // CommC via the witnessed `sib_*_parent_c` path, and equate to
        // `root_c` (= the public CommC).
        //
        // Soundness rationale: column(p) = Poseidon(L labels at p). The
        // labeling preimage at v* uses those L labels. If the prover lies
        // about any parent's labels, the recomputed column won't match the
        // committed column at the parent's index — but the prover can't
        // forge a new (column, sib_path) pair for the SAME CommC without
        // breaking Poseidon's collision resistance. Hence the prover is
        // forced to use the HONEST parent labels.
        // DRG parent column inclusions — GATED by `drg_valid[j]` per the
        // v*<d_DRG mux. Padded slots have no real column in CommC; the
        // gate enforces inclusion only when the slot is real.
        for ((col_cells, (p, sibs)), valid) in drg_columns_cells
            .iter()
            .zip(
                self.drg_parent_indices
                    .iter()
                    .zip(self.drg_parent_sib_c.iter()),
            )
            .zip(drg_valid_cells.iter())
        {
            assert_parent_inclusion_gated(
                &config,
                &mut layouter,
                col_cells,
                *p,
                sibs,
                &root_c,
                valid,
                "drg_parent_inclusion",
            )?;
        }
        for (col_cells, (e, sibs)) in exp_columns_cells.iter().zip(
            self.exp_parent_indices
                .iter()
                .zip(self.exp_parent_sib_c.iter()),
        ) {
            assert_parent_inclusion(
                &config,
                &mut layouter,
                col_cells,
                *e,
                sibs,
                &root_c,
                "exp_parent_inclusion",
            )?;
        }

        Ok(())
    }
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
    config: &PoRepGenericConfig,
    layouter: &mut impl Layouter<Halo2Fr>,
    column_cells: &[AssignedCell<Halo2Fr, Halo2Fr>],
    parent_index: usize,
    parent_sibs: &[Value<Halo2Fr>],
    root_c: &AssignedCell<Halo2Fr, Halo2Fr>,
    label: &'static str,
) -> Result<(), ErrorFront> {
    // column(p) = Poseidon(label(1,p), ..., label(L,p)).
    let col_at_p = PoseidonChip::hash_n_from_cells(&config.poseidon, layouter, column_cells)?;
    // Bit-decompose the parent index, recompute CommC via the swap-Merkle.
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
    // recomputed root == root_c (the public CommC).
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

/// PIN-P1 v*<d_DRG mux variant of `assert_parent_inclusion` — the root
/// equality is GATED by `valid` (the per-slot drg_valid bit). When
/// `valid = 1`, enforce `recomputed_root == root_c`; when `valid = 0`,
/// the gate is vacuous (column-inclusion check skipped for padded
/// slots). The Poseidon column-hash + Merkle pathing still RUN
/// in-circuit at every slot — same shape, single VK.
fn assert_parent_inclusion_gated(
    config: &PoRepGenericConfig,
    layouter: &mut impl Layouter<Halo2Fr>,
    column_cells: &[AssignedCell<Halo2Fr, Halo2Fr>],
    parent_index: usize,
    parent_sibs: &[Value<Halo2Fr>],
    root_c: &AssignedCell<Halo2Fr, Halo2Fr>,
    valid: &AssignedCell<Halo2Fr, Halo2Fr>,
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
    // valid·(recomputed − root_c) = 0
    config.swap.gated_eq(layouter, &recomputed, root_c, valid)?;
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

    /// k for the parameterised circuit. Bigger than reduced's k=14 because
    /// (a) arbitrary-depth Merkle does `depth` Poseidon perms per inclusion
    /// (and at N=16 that's 4 each, vs 2 at N=4), (b) per-layer labeling
    /// uses Poseidon at arity 3 + d_DRG + d_EXP, (c) every parent gets its
    /// own column inclusion. k=15 (32768 rows) is comfortable for the
    /// (N=4, L=2, K=1) parity test; (N=16, L=3, K=1) wants k=17.
    const K_SMALL: u32 = 15;
    const K_MEDIUM: u32 = 17;

    fn one_through(n: usize) -> Vec<Halo2Fr> {
        (1..=n as u64).map(Halo2Fr::from).collect()
    }

    fn seed_zero() -> [u8; 32] {
        [0u8; 32]
    }

    /// f.2a parity: the parameterised circuit, configured for (N=4, L=2)
    /// with reduced-equivalent samplers, must verify for every challenge
    /// index `v* ≥ d_DRG` (where the topology is full-degree). The
    /// `v* < d_DRG` edge case follows a separate mux pattern (the reduced
    /// circuit's `has_drg` boolean generalised to per-slot booleans) and
    /// is a clean follow-up; this PR ships the full-degree path.
    #[test]
    fn generic_porep_verifies_at_n4_l2() {
        let params = PoRepParams {
            n: 4,
            l: 2,
            d_drg: 1,
            d_exp: 1,
            k: 1,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA11CEu64),
            Halo2Fr::from(0xC1Du64),
            Halo2Fr::from(7u64),
            Halo2Fr::from(42u64),
            one_through(4),
        )
        .expect("seal");

        // PIN-P1 v*<d_DRG mux now lands — iterate the FULL range
        // including v < d_DRG. Padded slots are gated off via
        // `drg_valid` and muxed to `replicaID` in the labeling preimage.
        for v in 0..params.n {
            let challenge = build_challenge(&sealed, v).expect("challenge");
            let circuit =
                PoRepCircuitGeneric::from_sealed(&sealed, Halo2Fr::from(0xA11CEu64), &challenge);
            let pis = PoRepCircuitGeneric::public_inputs(&sealed, v);
            let prover = MockProver::run(K_SMALL, &circuit, vec![pis]).expect("mockprover setup");
            assert_eq!(
                prover.verify(),
                Ok(()),
                "honest generic PoRep must verify at (N=4,L=2,v={v})"
            );
        }
    }

    /// f.2 acceptance target — (N=16, L=3, K=1) with real-degree samplers
    /// (d_DRG=3, d_EXP=3). Confirms the parameterised circuit shape covers
    /// real-size topologies, not just the reduced fixture.
    #[test]
    fn generic_porep_verifies_at_n16_l3_with_real_degrees() {
        let params = PoRepParams {
            n: 16,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 1,
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

        // Pick a v* in the interior so all DRG + expander parents are full
        // degree (avoids the v*<d_DRG reduced-degree edge case).
        let v = 12usize;
        let challenge = build_challenge(&sealed, v).expect("challenge");
        let circuit = PoRepCircuitGeneric::from_sealed(&sealed, Halo2Fr::from(0xA1u64), &challenge);
        let pis = PoRepCircuitGeneric::public_inputs(&sealed, v);
        let prover = MockProver::run(K_MEDIUM, &circuit, vec![pis]).expect("setup");
        assert_eq!(
            prover.verify(),
            Ok(()),
            "honest generic PoRep must verify at (N=16,L=3,v={v})"
        );
    }

    /// Negative — wrong replicaID, parameterised. The in-circuit
    /// replicaID = Poseidon(pinnerIdentity, cid, sectorIndex) is
    /// constrained equal to the public PI[0]; presenting B's replicaID
    /// over A's sealed witness must fail.
    #[test]
    fn generic_porep_rejects_wrong_replica_id() {
        let params = PoRepParams {
            n: 4,
            l: 2,
            d_drg: 1,
            d_exp: 1,
            k: 1,
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA11CEu64),
            Halo2Fr::from(0xC1Du64),
            Halo2Fr::from(7u64),
            Halo2Fr::from(42u64),
            one_through(4),
        )
        .expect("seal");
        let v = 1usize;
        let challenge = build_challenge(&sealed, v).expect("challenge");
        let mut circuit =
            PoRepCircuitGeneric::from_sealed(&sealed, Halo2Fr::from(0xA11CEu64), &challenge);
        circuit.pinner_identity = Value::known(Halo2Fr::from(0xB0Bu64));

        let mut pis = PoRepCircuitGeneric::public_inputs(&sealed, v);
        // Use B's replicaID = Poseidon(B, cid, sector).
        let b_sealed = seal_generic(
            params,
            Halo2Fr::from(0xB0Bu64),
            Halo2Fr::from(0xC1Du64),
            Halo2Fr::from(7u64),
            Halo2Fr::from(42u64),
            one_through(4),
        )
        .expect("b_seal");
        pis[porep_pi::REPLICA_ID] = b_sealed.replica_id;

        let prover = MockProver::run(K_SMALL, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "wrong replicaID over honest replica MUST fail"
        );
    }

    /// Negative — a forged DRG parent column. The parent inclusion gate
    /// must reject: column(p) recomputed from the forged labels does not
    /// reconstruct the committed CommC via the witnessed sib_path.
    #[test]
    fn generic_porep_rejects_forged_drg_parent_column() {
        let params = PoRepParams {
            n: 16,
            l: 3,
            d_drg: 3,
            d_exp: 3,
            k: 1,
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
        let v = 12usize;
        let challenge = build_challenge(&sealed, v).expect("challenge");
        let mut circuit =
            PoRepCircuitGeneric::from_sealed(&sealed, Halo2Fr::from(0xA1u64), &challenge);

        // Forge the FIRST DRG parent's layer-1 label. The labeling preimage
        // at v* uses this; the recomputed label won't match the witnessed
        // labels_at_v[0] (label equality gate fails), AND the column
        // inclusion at the parent's index won't reconstruct CommC.
        if !circuit.drg_parent_columns.is_empty() {
            circuit.drg_parent_columns[0][0] =
                Value::known(challenge.drg_parent_columns[0][0] + Halo2Fr::from(777u64));
        }

        let pis = PoRepCircuitGeneric::public_inputs(&sealed, v);
        let prover = MockProver::run(K_MEDIUM, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "forged DRG parent column MUST be rejected"
        );
    }
}
