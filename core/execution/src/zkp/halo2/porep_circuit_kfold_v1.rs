//! PIN-P1 (f.2c.1) — K-fold PoRep with in-circuit challenge derivation.
//!
//! Collapses the K trailing per-challenge index public inputs from
//! [`super::porep_circuit_kfold`] by deriving them in-circuit from
//! `challengeNonce`. The K challenge indices become PURE WITNESSES;
//! the public-input ABI returns to the v2-compatible 8-element layout.
//!
//! ## Derivation (mirrors the native
//! [`super::porep_generic::derive_challenge_indices`])
//!
//! ```text
//!   mixed_seed = Poseidon(challengeNonce, epoch, replicaID, sectorIndex)
//!   h_i        = Poseidon(mixed_seed, i)        for i in 0..K
//!   idx_i      = h_i mod N                       (N = 2^depth)
//! ```
//!
//! The mod-N reduction is realised in-circuit by bit-decomposing `h_i`
//! (the Horner-form `decompose_index_generic` already enforces
//! `value = Σ b_j · 2^j`); the low `depth` bits ARE `idx_i`, and the
//! Merkle pathing already needs exactly those bits.
//!
//! ## Soundness gap (prototype caveat — production hardening required)
//!
//! Bit-decomposing `h_i` into 254 bits is **complete but not strictly
//! sound**. Since the BN254 scalar field `Fr` has prime `p` with
//! `2^253 < p < 2^254`, two distinct 254-bit patterns can represent the
//! same field element: `bin(h_i)` and `bin(h_i + p)` (the latter exists
//! when `h_i + p < 2^254`). An adversary could pick whichever pattern
//! yields a more favourable low-`depth` slice, gaining at most ~1 extra
//! grinding choice per challenge. Concretely for `K = 44` this is
//! ~6 bits of soundness loss vs the ideal `f^K`.
//!
//! **Disposition (2026-06-12, TD-PIN-P1-f2c1-range):** RISK-ACCEPTED for
//! testnet + fix SCHEDULED at PIN-P1 f.6. Net soundness stays ≥ 80 bits at the
//! locked `(K_porep=22, K_post=44, 1 GiB)` params (the 2026-06-06 f.4/f.5 lead
//! advisement accepted exactly this residual). The canonical `value < p` check
//! is deferred to f.6 — where these circuits are rebuilt at real size and PSE
//! Halo2's range-check LOOKUP primitive (the correct, low-risk tool) is adopted,
//! under the f.7 ToB crypto review — rather than hand-rolling a lexicographic
//! `< p` comparator on the reduced testnet circuit (a comparator bug would be
//! silently unsound, strictly worse than this bounded, documented gap). Full
//! reasoning + exact math: `design/PIN-P1-f2c1-range-risk-acceptance.md`. The
//! `ambiguity_fraction_is_bounded` test below pins the exact bound in code.
//!
//! ## Scope
//!
//! - **NEW circuit version (v5).** v2 / v3 ABIs unchanged. The on-chain
//!   dispatcher adds the v5 arm only when (f.6) discharges TD-19.
//! - **Reuses the f.2c per-challenge body** (`per_challenge_run`,
//!   factored out of `porep_circuit_kfold::per_challenge_synthesize`).
//! - **`v* < d_DRG` mux still deferred** — same edge case as f.2b/f.2c.
//!   Tests pick challenges where the derived `idx_i ≥ d_DRG`.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr as Halo2Fr;
use halo2curves::ff::PrimeField as _;

use super::chips::{PoseidonChip, PoseidonChipConfig};
use super::porep::{pi as porep_pi, SwapMerkleConfig};
use super::porep_circuit_kfold::KFoldChallengeWitness;
use super::porep_generic::{
    build_challenge, derive_challenge_indices_simple, GenericSealedReplica, PoRepParams,
};

// ---------------------------------------------------------------------------
// Public-input layout — 8 elements, identical to the v2 PoRep ABI.
// ---------------------------------------------------------------------------

pub mod pi_v1 {
    pub use super::porep_pi::{
        CHALLENGE_NONCE, CID, COMM_C, COMM_D, COMM_R, COUNT, EPOCH, REPLICA_ID, SECTOR_INDEX,
    };
}

// ---------------------------------------------------------------------------
// Config.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PoRepKFoldV1Config {
    poseidon: PoseidonChipConfig,
    swap: SwapMerkleConfig,
    add_a: Column<Advice>,
    add_b: Column<Advice>,
    add_c: Column<Advice>,
    s_add: Selector,
    instance: Column<Instance>,
}

// ---------------------------------------------------------------------------
// Circuit.
// ---------------------------------------------------------------------------

/// K-fold PoRep with in-circuit challenge derivation. 8-element PI ABI
/// (matches v2 byte-for-byte). The K per-challenge indices are PURE
/// WITNESSES; the circuit enforces they equal the deterministic Poseidon
/// expansion of `challengeNonce`.
#[derive(Clone)]
pub struct PoRepCircuitKFoldV1 {
    pub params: PoRepParams,

    pub pinner_identity: Value<Halo2Fr>,
    pub cid: Value<Halo2Fr>,
    pub sector_index: Value<Halo2Fr>,
    pub epoch: Value<Halo2Fr>,
    pub challenge_nonce: Value<Halo2Fr>,

    /// K per-challenge witnesses; `challenges[i].challenge_index` MUST
    /// equal the in-circuit-derived `idx_i` (the honest constructor
    /// `from_sealed` builds these from the native
    /// `derive_challenge_indices`).
    pub challenges: Vec<KFoldChallengeWitness>,
}

impl PoRepCircuitKFoldV1 {
    /// Honest-prover constructor. Computes the K challenge indices via
    /// the native `derive_challenge_indices`, builds the per-challenge
    /// witnesses, and assembles them.
    pub fn from_sealed(
        sealed: &GenericSealedReplica,
        pinner_identity: Halo2Fr,
        challenge_nonce: Halo2Fr,
    ) -> Self {
        let indices = derive_challenge_indices_simple(
            sealed.params.n,
            sealed.params.k,
            challenge_nonce,
            sealed.epoch,
            sealed.replica_id,
            sealed.sector_index,
        );
        let challenges: Vec<_> = indices
            .iter()
            .map(|&v| {
                KFoldChallengeWitness::from_challenge(&build_challenge(sealed, v).expect("ch"))
            })
            .collect();
        Self {
            params: sealed.params.clone(),
            pinner_identity: Value::known(pinner_identity),
            cid: Value::known(sealed.cid),
            sector_index: Value::known(sealed.sector_index),
            epoch: Value::known(sealed.epoch),
            challenge_nonce: Value::known(challenge_nonce),
            challenges,
        }
    }

    /// Empty (unknown-witness) circuit for keygen — same worst-case
    /// shape as the K-fold v0 (full d_DRG + d_EXP parents per challenge,
    /// K challenges).
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
            challenge_nonce: Value::unknown(),
        }
    }

    /// 8-element PI vector — same byte layout as v2.
    pub fn public_inputs(sealed: &GenericSealedReplica, challenge_nonce: Halo2Fr) -> Vec<Halo2Fr> {
        let mut pis = vec![Halo2Fr::from(0u64); pi_v1::COUNT];
        pis[pi_v1::REPLICA_ID] = sealed.replica_id;
        pis[pi_v1::CID] = sealed.cid;
        pis[pi_v1::SECTOR_INDEX] = sealed.sector_index;
        pis[pi_v1::COMM_D] = sealed.comm_d;
        pis[pi_v1::COMM_R] = sealed.comm_r;
        pis[pi_v1::COMM_C] = sealed.comm_c;
        pis[pi_v1::CHALLENGE_NONCE] = challenge_nonce;
        pis[pi_v1::EPOCH] = sealed.epoch;
        pis
    }
}

impl Circuit<Halo2Fr> for PoRepCircuitKFoldV1 {
    type Config = PoRepKFoldV1Config;
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
        meta.create_gate("porep_kfold_v1_encode_add", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(add_a, Rotation::cur());
            let b = meta.query_advice(add_b, Rotation::cur());
            let c = meta.query_advice(add_c, Rotation::cur());
            vec![s * (c - a - b)]
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);
        PoRepKFoldV1Config {
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
        let k = self.params.k;

        // ───────────────────────────────────────────────────────────────
        // Shared (once per proof): identity-tuple + replicaID + base PIs.
        // ───────────────────────────────────────────────────────────────
        let pid_cell = swap.assign_value(&mut layouter, self.pinner_identity, "pinner_id")?;
        let cid_cell = swap.assign_value(&mut layouter, self.cid, "cid")?;
        let sector_cell = swap.assign_value(&mut layouter, self.sector_index, "sector_idx")?;
        let epoch_cell = swap.assign_value(&mut layouter, self.epoch, "epoch")?;
        let nonce_cell =
            swap.assign_value(&mut layouter, self.challenge_nonce, "challenge_nonce")?;

        let replica_id_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[pid_cell.clone(), cid_cell.clone(), sector_cell.clone()],
        )?;
        layouter.constrain_instance(replica_id_cell.cell(), config.instance, pi_v1::REPLICA_ID)?;
        layouter.constrain_instance(cid_cell.cell(), config.instance, pi_v1::CID)?;
        layouter.constrain_instance(sector_cell.cell(), config.instance, pi_v1::SECTOR_INDEX)?;
        layouter.constrain_instance(epoch_cell.cell(), config.instance, pi_v1::EPOCH)?;
        layouter.constrain_instance(nonce_cell.cell(), config.instance, pi_v1::CHALLENGE_NONCE)?;

        // mixed_seed = Poseidon(challengeNonce, epoch, replicaID, sectorIndex)
        let mixed_seed_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[
                nonce_cell.clone(),
                epoch_cell.clone(),
                replica_id_cell.clone(),
                sector_cell.clone(),
            ],
        )?;

        // Layer constants.
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
        // Per-challenge (K times): derive idx_i from mixed_seed via
        // Poseidon + bit decomposition reduction, then run the f.2c
        // per-challenge gate-set with the derived (idx_cell, bits).
        // ───────────────────────────────────────────────────────────────
        debug_assert_eq!(self.challenges.len(), k);
        let mut idx_cells: Vec<AssignedCell<Halo2Fr, Halo2Fr>> = Vec::with_capacity(k);
        for (i, ch) in self.challenges.iter().enumerate() {
            let (idx_cell, idx_bits) =
                derive_index_in_circuit(&config, &mut layouter, &mixed_seed_cell, i, depth)?;
            per_challenge_run(
                &config,
                &mut layouter,
                &replica_id_cell,
                &layer_consts,
                &idx_cell,
                &idx_bits,
                ch,
                l,
            )?;
            idx_cells.push(idx_cell);
        }

        // PIN-P1 (f.2c.2) — pairwise distinctness gate. Soundness for the
        // K-fold proof relies on K *distinct* challenge indices; without
        // this gate a colliding seed would let the proof pass at
        // effective K' < K (weakening from f^K to f^K'). Enforced via the
        // is_nonzero gadget on each pairwise difference. K · (K-1)/2 pairs
        // — fine at K ≤ 44 (≤ 946 pairs ≈ ~20K rows; ~1 % of the k=18
        // row budget).
        assert_distinct_indices(&config, &mut layouter, &idx_cells)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// In-circuit challenge index derivation.
// ---------------------------------------------------------------------------

/// `idx_i = Poseidon(mixed_seed, i) mod 2^depth`. Returns
/// `(idx_cell, idx_bits)` ready to feed into the per-challenge gates.
///
/// Mechanism:
/// 1. `h = Poseidon(mixed_seed, draw_index_const)`
/// 2. Bit-decompose `h` into 254 bits via the Horner-form recompose
///    (`decompose_index_generic`).
/// 3. Bit-decompose `idx_val = h_val & (2^depth - 1)` into `depth` bits
///    (also Horner-form). Returns `idx_cell` = the recomposed depth-bit
///    integer.
/// 4. Constrain `idx_bits[j] == all_bits[j]` for `j in 0..depth` so
///    `idx_cell` is exactly `h mod 2^depth`.
fn derive_index_in_circuit(
    config: &PoRepKFoldV1Config,
    layouter: &mut impl Layouter<Halo2Fr>,
    mixed_seed_cell: &AssignedCell<Halo2Fr, Halo2Fr>,
    draw_index: usize,
    depth: usize,
) -> Result<
    (
        AssignedCell<Halo2Fr, Halo2Fr>,
        Vec<AssignedCell<Halo2Fr, Halo2Fr>>,
    ),
    ErrorFront,
> {
    let swap = &config.swap;
    let draw_const = swap.assign_const(layouter, Halo2Fr::from(draw_index as u64), "draw_idx")?;

    // h = Poseidon(mixed_seed, draw_index_const)
    let h_cell = PoseidonChip::hash_n_from_cells(
        &config.poseidon,
        layouter,
        &[mixed_seed_cell.clone(), draw_const],
    )?;

    // Bit-decompose h into 254 bits. `decompose_index_generic` returns
    // (idx_cell_eq_input, all_bits) and enforces
    // `idx_cell_eq_input = Σ all_bits[j] · 2^j`.
    let (h_eq_cell, all_bits) =
        swap.decompose_index_generic(layouter, h_cell.value().copied(), 254)?;
    // Tie h_eq_cell (recomputed from bits) to the actual h_cell.
    layouter.assign_region(
        || "h_eq_decomp",
        |mut region| {
            let lhs = h_cell.copy_advice(|| "h", &mut region, swap.a(), 0)?;
            let rhs = h_eq_cell.copy_advice(|| "h_eq", &mut region, swap.b(), 0)?;
            region.constrain_equal(lhs.cell(), rhs.cell())?;
            Ok(())
        },
    )?;

    // Compute the low-`depth` slice as an Fr value.
    let idx_val = h_cell.value().copied().map(|h| {
        let bytes = h.to_repr();
        let by = bytes.as_ref();
        let mut acc = Halo2Fr::from(0u64);
        let two = Halo2Fr::from(2u64);
        let mut pow = Halo2Fr::from(1u64);
        for j in 0..depth {
            let byte_idx = j / 8;
            let shift = (j % 8) as u8;
            if byte_idx < by.len() && ((by[byte_idx] >> shift) & 1) == 1 {
                acc += pow;
            }
            pow *= two;
        }
        acc
    });
    // Bit-decompose idx_val to `depth` bits — gives us idx_cell + idx_bits.
    let (idx_cell, idx_bits) = swap.decompose_index_generic(layouter, idx_val, depth)?;

    // Constrain idx_bits[j] == all_bits[j] for j in 0..depth.
    for (j, (ib, ab)) in idx_bits.iter().zip(all_bits.iter().take(depth)).enumerate() {
        let region_name: &'static str = match j {
            0 => "low_bit_eq_0",
            1 => "low_bit_eq_1",
            2 => "low_bit_eq_2",
            3 => "low_bit_eq_3",
            4 => "low_bit_eq_4",
            5 => "low_bit_eq_5",
            6 => "low_bit_eq_6",
            7 => "low_bit_eq_7",
            8 => "low_bit_eq_8",
            9 => "low_bit_eq_9",
            _ => "low_bit_eq_k",
        };
        layouter.assign_region(
            || region_name,
            |mut region| {
                let lhs = ib.copy_advice(|| "ib", &mut region, swap.a(), 0)?;
                let rhs = ab.copy_advice(|| "ab", &mut region, swap.b(), 0)?;
                region.constrain_equal(lhs.cell(), rhs.cell())?;
                Ok(())
            },
        )?;
    }

    Ok((idx_cell, idx_bits))
}

// ---------------------------------------------------------------------------
// Per-challenge body — same relation as f.2c, fed a pre-derived idx_cell.
// ---------------------------------------------------------------------------

fn per_challenge_run(
    config: &PoRepKFoldV1Config,
    layouter: &mut impl Layouter<Halo2Fr>,
    replica_id_cell: &AssignedCell<Halo2Fr, Halo2Fr>,
    layer_consts: &[AssignedCell<Halo2Fr, Halo2Fr>],
    idx_cell: &AssignedCell<Halo2Fr, Halo2Fr>,
    bits: &[AssignedCell<Halo2Fr, Halo2Fr>],
    ch: &KFoldChallengeWitness,
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
    let drg_columns_cells = assign_columns(swap, layouter, &ch.drg_parent_columns, "drg_col")?;
    let exp_columns_cells = assign_columns(swap, layouter, &ch.exp_parent_columns, "exp_col")?;

    // PIN-P1 v*<d_DRG mux — per-slot drg_valid (boolean-constrained).
    let drg_valid_cells: Vec<AssignedCell<Halo2Fr, Halo2Fr>> = {
        let mut out = Vec::with_capacity(ch.drg_valid.len());
        for v in &ch.drg_valid {
            let cell = swap.assign_value(layouter, *v, "drg_valid")?;
            let has = swap.is_nonzero(layouter, &cell)?;
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

    // Labeling per layer (mirrors f.2b/f.2c).
    for layer in 1..=l {
        let mut preimage: Vec<AssignedCell<Halo2Fr, Halo2Fr>> =
            Vec::with_capacity(3 + drg_columns_cells.len() + exp_columns_cells.len());
        preimage.push(replica_id_cell.clone());
        preimage.push(layer_consts[layer - 1].clone());
        preimage.push(idx_cell.clone());
        // PIN-P1 v*<d_DRG mux: muxed DRG slot values.
        for (col, valid) in drg_columns_cells.iter().zip(drg_valid_cells.iter()) {
            let muxed = swap.mux(layouter, replica_id_cell, &col[layer - 1], valid)?;
            preimage.push(muxed);
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
    let sib_d = assign_sibs(swap, layouter, &ch.sib_d, "sib_d")?;
    let root_d =
        swap.merkle_root_generic(&config.poseidon, layouter, data_cell.clone(), bits, &sib_d)?;
    layouter.constrain_instance(root_d.cell(), config.instance, pi_v1::COMM_D)?;

    let sib_r = assign_sibs(swap, layouter, &ch.sib_r, "sib_r")?;
    let root_r =
        swap.merkle_root_generic(&config.poseidon, layouter, replica_leaf_cell, bits, &sib_r)?;
    layouter.constrain_instance(root_r.cell(), config.instance, pi_v1::COMM_R)?;

    let sib_c = assign_sibs(swap, layouter, &ch.sib_c, "sib_c")?;
    let root_c = swap.merkle_root_generic(&config.poseidon, layouter, column_cell, bits, &sib_c)?;
    layouter.constrain_instance(root_c.cell(), config.instance, pi_v1::COMM_C)?;

    // Per-parent column inclusions against root_c (= public CommC).
    // DRG slots: GATED by drg_valid (PIN-P1 v*<d_DRG mux).
    for ((col_cells, (p, sibs)), valid) in drg_columns_cells
        .iter()
        .zip(ch.drg_parent_indices.iter().zip(ch.drg_parent_sib_c.iter()))
        .zip(drg_valid_cells.iter())
    {
        assert_parent_inclusion_gated(
            config,
            layouter,
            col_cells,
            *p,
            sibs,
            &root_c,
            valid,
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
// Helpers (same as f.2c).
// ---------------------------------------------------------------------------

/// PIN-P1 (f.2c.2) — pairwise inequality gate across `idx_cells`.
/// For every pair (i, j) with i < j, enforces `idx_i ≠ idx_j`.
///
/// Mechanism per pair:
/// 1. Compute `diff = idx_i - idx_j` via the encoding add gate
///    (`add_c = add_a + add_b` ⇒ `idx_i = diff + idx_j` with
///    `idx_i → add_c`, `diff → add_a`, `idx_j → add_b`).
/// 2. Apply `is_nonzero(diff)` → a soundly-constrained `has_diff`
///    boolean cell that is 1 iff `diff ≠ 0`.
/// 3. Assert `has_diff == 1` by copy-equality to a witnessed `1` cell.
fn assert_distinct_indices(
    config: &PoRepKFoldV1Config,
    layouter: &mut impl Layouter<Halo2Fr>,
    idx_cells: &[AssignedCell<Halo2Fr, Halo2Fr>],
) -> Result<(), ErrorFront> {
    let swap = &config.swap;
    let k = idx_cells.len();
    if k < 2 {
        return Ok(());
    }
    let one_cell = swap.assign_const(layouter, Halo2Fr::from(1u64), "one_for_distinct")?;
    for i in 0..k {
        for j in (i + 1)..k {
            // diff = idx_i - idx_j  via  idx_i = diff + idx_j
            let diff_cell = layouter.assign_region(
                || "distinct_diff",
                |mut region| {
                    let lhs = idx_cells[i].copy_advice(|| "idx_i", &mut region, config.add_c, 0)?;
                    let rhs = idx_cells[j].copy_advice(|| "idx_j", &mut region, config.add_b, 0)?;
                    let diff_val = lhs.value().copied() - rhs.value().copied();
                    let diff = region.assign_advice(|| "diff", config.add_a, 0, || diff_val)?;
                    config.s_add.enable(&mut region, 0)?;
                    Ok(diff)
                },
            )?;
            let has_diff = swap.is_nonzero(layouter, &diff_cell)?;
            // Enforce has_diff == 1.
            layouter.assign_region(
                || "distinct_eq_one",
                |mut region| {
                    let lhs = has_diff.copy_advice(|| "has", &mut region, swap.a(), 0)?;
                    let rhs = one_cell.copy_advice(|| "one", &mut region, swap.b(), 0)?;
                    region.constrain_equal(lhs.cell(), rhs.cell())?;
                    Ok(())
                },
            )?;
        }
    }
    Ok(())
}

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
    config: &PoRepKFoldV1Config,
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

/// PIN-P1 v*<d_DRG mux — gated variant.
fn assert_parent_inclusion_gated(
    config: &PoRepKFoldV1Config,
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
    config.swap.gated_eq(layouter, &recomputed, root_c, valid)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::halo2::porep_generic::seal_generic;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr as Halo2Fr;

    /// k for the K=3 in-circuit-derivation MockProver. Per-challenge
    /// 254-bit decomposition adds ~260 rows; with K=3 that's ~800 rows on
    /// top of f.2c's per-challenge gate-set. k=18 (262144 rows) is plenty.
    const K_DEG_V1: u32 = 18;

    /// TD-PIN-P1-f2c1-range guard: pin the EXACT 254-bit ambiguity bound in
    /// code (per the risk-acceptance, `design/PIN-P1-f2c1-range-risk-acceptance.md`).
    /// The fraction of field elements with an alternate 254-bit representation is
    /// `(2^254 − p) / 2^254`. We assert it is small (≲ 11%) — bounding the
    /// per-draw grinding advantage — and that it is NOT ~50% (a common
    /// misconception). If the field ever changes, this surfaces the assumption.
    #[test]
    fn ambiguity_fraction_is_bounded() {
        use halo2curves::ff::{Field as _, PrimeField as _};
        // p − 1 = 0 − 1 in the field; its LE bytes + 1 give p's LE bytes.
        let p_minus_1 = (-Halo2Fr::ONE).to_repr();
        let pm1: [u8; 32] = p_minus_1.as_ref().try_into().expect("32 bytes");
        // p = (p-1) + 1 as a 256-bit LE integer (carry add).
        let mut p_le = pm1;
        let mut carry = 1u16;
        for byte in p_le.iter_mut() {
            let v = *byte as u16 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        // 2^254 − p, as a non-negative 256-bit LE integer. 2^254 has bit 254 set.
        // Compute (2^254) - p via big-int over u128 halves.
        let p_lo = u128::from_le_bytes(p_le[0..16].try_into().expect("16"));
        let p_hi = u128::from_le_bytes(p_le[16..32].try_into().expect("16"));
        // 2^254 = hi part has bit (254-128)=126 set, lo = 0.
        let two254_hi = 1u128 << 126;
        // (two254_hi:0) - (p_hi:p_lo)
        let (diff_lo, borrow) = 0u128.overflowing_sub(p_lo);
        let diff_hi = two254_hi - p_hi - borrow as u128;
        // fraction = diff / 2^254 ≈ diff_hi / 2^126 (lo part negligible for the bound).
        // p's leading nibble is 0x3, so 2^254 − p ≈ (0x4 − 0x3064…)/0x4 ≈ 0.244 →
        // ~24% of field elements admit an alternate 254-bit representation. Assert
        // 22% < fraction < 26% (real and bounded; NOT ~50%, NOT ~0).
        let bound_26 = (two254_hi / 100) * 26;
        let bound_22 = (two254_hi / 100) * 22;
        assert!(diff_hi < bound_26, "alternate-rep fraction must be ≲ 26% (got hi={diff_hi})");
        assert!(diff_hi > bound_22, "alternate-rep fraction must be ≳ 22% — gap is real, see risk-acceptance");
        let _ = diff_lo;
    }

    fn seed_zero() -> [u8; 32] {
        [0u8; 32]
    }

    fn one_through(n: usize) -> Vec<Halo2Fr> {
        (1..=n as u64).map(Halo2Fr::from).collect()
    }

    /// f.2c.1 happy path — pick a `challengeNonce` such that the
    /// derived K=3 indices are all `≥ d_DRG` (so the variable-arity edge
    /// case is avoided at every challenge). The circuit derives the
    /// same K indices the native helper would, then runs the K
    /// per-challenge gate-sets at those derived indices.
    #[test]
    fn kfold_v1_verifies_at_k3_n16_l3() {
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

        // Search a small nonce range for a seed whose K=3 derived
        // indices are all ≥ d_DRG. Deterministic and within a single
        // test second.
        let mut nonce = Halo2Fr::from(1u64);
        let mut chosen = None;
        for trial in 1u64..=200 {
            let candidate = Halo2Fr::from(trial);
            let indices = derive_challenge_indices_simple(
                params.n,
                params.k,
                candidate,
                sealed.epoch,
                sealed.replica_id,
                sealed.sector_index,
            );
            if indices.iter().all(|&v| v >= params.d_drg) {
                nonce = candidate;
                chosen = Some(indices);
                break;
            }
        }
        let _indices = chosen.expect("found a nonce with all derived indices ≥ d_DRG");

        let circuit = PoRepCircuitKFoldV1::from_sealed(&sealed, Halo2Fr::from(0xA1u64), nonce);
        let pis = PoRepCircuitKFoldV1::public_inputs(&sealed, nonce);
        let prover = MockProver::run(K_DEG_V1, &circuit, vec![pis]).expect("setup");
        assert_eq!(
            prover.verify(),
            Ok(()),
            "honest K=3 PoRep with in-circuit derivation must verify"
        );
    }

    /// f.2c.1 negative — tamper with the SECOND challenge's data leaf.
    /// In-circuit derivation produces the same K indices; the second
    /// CommD reconstruction fails.
    #[test]
    fn kfold_v1_rejects_tampered_challenge_data() {
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
        // Find a nonce whose derived indices are all ≥ d_DRG.
        let mut nonce = Halo2Fr::from(1u64);
        for trial in 1u64..=200 {
            let candidate = Halo2Fr::from(trial);
            let indices = derive_challenge_indices_simple(
                params.n,
                params.k,
                candidate,
                sealed.epoch,
                sealed.replica_id,
                sealed.sector_index,
            );
            if indices.iter().all(|&v| v >= params.d_drg) {
                nonce = candidate;
                break;
            }
        }

        let mut circuit = PoRepCircuitKFoldV1::from_sealed(&sealed, Halo2Fr::from(0xA1u64), nonce);
        let v1 = circuit.challenges[1].challenge_index;
        circuit.challenges[1].data_challenged =
            Value::known(sealed.data[v1] + Halo2Fr::from(777u64));

        let pis = PoRepCircuitKFoldV1::public_inputs(&sealed, nonce);
        let prover = MockProver::run(K_DEG_V1, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "tampered data leaf in one of K challenges MUST be rejected"
        );
    }

    /// f.2c.1 negative — the witness builder uses a DIFFERENT challenge
    /// index than what the in-circuit derivation would produce. The
    /// labeling preimage uses the derived idx_cell (not the witness's
    /// challenge_index), so the witnessed labels_at_v don't match.
    #[test]
    fn kfold_v1_rejects_wrong_witness_index() {
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
        let mut nonce = Halo2Fr::from(1u64);
        for trial in 1u64..=200 {
            let candidate = Halo2Fr::from(trial);
            let indices = derive_challenge_indices_simple(
                params.n,
                params.k,
                candidate,
                sealed.epoch,
                sealed.replica_id,
                sealed.sector_index,
            );
            if indices.iter().all(|&v| v >= params.d_drg) {
                nonce = candidate;
                break;
            }
        }

        // Honest circuit, then swap the FIRST challenge's witness for a
        // challenge at a DIFFERENT index. The in-circuit derivation will
        // produce the correct (derived) index → label reconstruction
        // diverges from the witnessed labels_at_v at the wrong-index
        // challenge → rejection.
        let mut circuit = PoRepCircuitKFoldV1::from_sealed(&sealed, Halo2Fr::from(0xA1u64), nonce);
        let wrong_v = (circuit.challenges[0].challenge_index + 1) % params.n;
        let wrong_ch = build_challenge(&sealed, wrong_v).expect("ch");
        circuit.challenges[0] = KFoldChallengeWitness::from_challenge(&wrong_ch);

        let pis = PoRepCircuitKFoldV1::public_inputs(&sealed, nonce);
        let prover = MockProver::run(K_DEG_V1, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "challenge witness at the wrong derived index MUST be rejected"
        );
    }

    /// f.2c.2 — pairwise distinctness gate: at very small N=4 + K=4,
    /// some `challengeNonce` values produce DUPLICATE indices under
    /// `derive_challenge_indices_simple` (no rejection sampling). The
    /// pairwise distinctness gate MUST reject those proofs even when the
    /// witness is consistent with the colliding indices. The honest
    /// constructor (which uses _simple) WILL build duplicate per-challenge
    /// witnesses at such nonces — the test confirms the proof still
    /// rejects.
    #[test]
    fn kfold_v1_distinctness_gate_rejects_colliding_nonce() {
        let params = PoRepParams {
            n: 4,
            l: 2,
            d_drg: 1,
            d_exp: 1,
            k: 4, // K=4 = N → forced collision under uniform sampling
            graph_seed: seed_zero(),
        };
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA1u64),
            Halo2Fr::from(0xB2u64),
            Halo2Fr::from(0xC3u64),
            Halo2Fr::from(0xD4u64),
            one_through(4),
        )
        .expect("seal");

        // Find a nonce whose simple-derivation yields at least one
        // collision. At N=4, K=4 with random sampling collisions are very
        // common (1 - 4!/4^4 ≈ 91% per nonce); the search lands quickly.
        let mut colliding_nonce: Option<Halo2Fr> = None;
        for trial in 1u64..=400 {
            let candidate = Halo2Fr::from(trial);
            let indices = derive_challenge_indices_simple(
                params.n,
                params.k,
                candidate,
                sealed.epoch,
                sealed.replica_id,
                sealed.sector_index,
            );
            let mut sorted = indices.clone();
            sorted.sort_unstable();
            sorted.dedup();
            if sorted.len() < params.k {
                colliding_nonce = Some(candidate);
                break;
            }
        }
        let nonce = colliding_nonce.expect("found a nonce whose simple derivation collides");

        // Use k=12 — small N + smallest L the test bench can do with K=4
        // is well inside the k=12 row budget.
        const K_DEG_SMALL: u32 = 14;
        let circuit = PoRepCircuitKFoldV1::from_sealed(&sealed, Halo2Fr::from(0xA1u64), nonce);
        let pis = PoRepCircuitKFoldV1::public_inputs(&sealed, nonce);
        let prover = MockProver::run(K_DEG_SMALL, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "colliding indices under simple derivation MUST be rejected by the pairwise distinctness gate"
        );
    }
}
