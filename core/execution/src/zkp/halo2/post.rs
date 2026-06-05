// citrate/core/execution/src/zkp/halo2/post.rs
//
// PIN-P1 step (b) — Proof-of-Spacetime (PoSt) circuit (REDUCED instance).
//
// Second circuit of PIN-P1. Where PoRep (`porep.rs`) proves a replica was
// SEALED CORRECTLY from data D at seal time (one-time, heavy: it touches
// CommD + the encoding relation R = D + label), PoSt proves the SEALED
// replica is STILL HELD over time (recurring, LIGHT): no CommD, no
// encoding. It re-derives the challenged node's layer-L label from the
// public `replicaID` and proves the sealed leaf R[v] and the column(v)
// are still committed under CommR / CommC.
//
// Spec: `.agentile/gtm-spine/design/PIN-P1-sdr-replicaid-construction.md`
//
// ---------------------------------------------------------------------------
// PIN-P1 step (c) part 1 — index-agnostic circuit + parent soundness.
// ---------------------------------------------------------------------------
//
// PoSt was hardened alongside PoRep in step (c1) with the SAME mechanism:
//
//   (1) SINGLE VK (kills TD-18): the challenge index is a WITNESS,
//       bit-decomposed in-circuit and bound to the public `challengeNonce`;
//       each Merkle level conditionally swaps (current, sibling) by the
//       level's index bit (via the shared `SwapMerkleChip` from porep.rs).
//       ONE circuit structure verifies ANY index → ONE VK.
//
//   (2) PARENT SOUNDNESS: the DRG parent labels (which previously were
//       unconstrained witnesses) are now proven to be the committed node at
//       index v*-1 — the parent's COLUMN (= Poseidon(parent_l1, parent_l2))
//       is Merkle-included in CommC at the parent index. The base case
//       (v*=0, no DRG parent) is handled uniformly: a CONSTRAINED
//       `has_drg_parent = (challengeNonce ≠ 0)` boolean muxes `prev_same` to
//       `replicaID` and gates the parent inclusion's root-equality off, so
//       the circuit SHAPE is identical for every index.
//
// **What is REUSED from porep.rs:** the native `seal_reduced` /
// `SealedReplica` (a PoSt and a PoRep proof over the SAME replica agree on
// replicaID/CommR/CommC), the `SwapMerkleConfig` index-agnostic gadget,
// topology helpers (`drg_parent`, `merkle_siblings_4`), constants
// (`N`, `L`, `MERKLE_DEPTH`), and `PoseidonChip`.
//
// **What is net-new:** the `PoStCircuit` composition — a strict SUBSET of
// PoRep's relations (drops the encoding gate + the CommD inclusion).
//
// Public inputs (instance column), in this fixed layout (NO CommD):
//   [0] replicaID
//   [1] cid
//   [2] sectorIndex
//   [3] CommR
//   [4] CommC
//   [5] challengeNonce      (challenged node index v*, WITNESSED + bound)
//   [6] epoch

#![allow(clippy::too_many_arguments)]

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
};
use halo2curves::bn256::Fr as Halo2Fr;
use halo2curves::ff::Field as _;

use super::chips::{PoseidonChip, PoseidonChipConfig};
// Reuse the PoRep topology + native sealing + the index-agnostic gadget.
use super::porep::{drg_parent, merkle_siblings_4, SealedReplica, SwapMerkleConfig, MERKLE_DEPTH, N};

// ---------------------------------------------------------------------------
// Public-input slot indices — the documented 7-slot PoSt layout (NO CommD).
// ---------------------------------------------------------------------------

pub mod pi {
    pub const REPLICA_ID: usize = 0;
    pub const CID: usize = 1;
    pub const SECTOR_INDEX: usize = 2;
    pub const COMM_R: usize = 3;
    pub const COMM_C: usize = 4;
    pub const CHALLENGE_NONCE: usize = 5;
    pub const EPOCH: usize = 6;
    /// Total number of public inputs exposed by the reduced PoSt circuit.
    pub const COUNT: usize = 7;
}

// ---------------------------------------------------------------------------
// PoStCircuit — the reduced in-circuit relation (index-agnostic, lighter).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PoStCircuitConfig {
    poseidon: PoseidonChipConfig,
    swap: SwapMerkleConfig,
    /// Witness column for the private scalars that must be cell-bound.
    witness: Column<Advice>,
    instance: Column<Instance>,
}

/// Reduced-instance PoSt circuit. Carries the sealed witness for the
/// challenged node `challenge_index` plus the Merkle siblings for the CommR
/// and CommC inclusions of v*, and the DRG-parent column's CommC siblings.
///
/// **Index-agnostic:** `challenge_index` is carried only to derive honest
/// WITNESS values; it is NOT baked into the circuit SHAPE → one VK.
#[derive(Clone, Default)]
pub struct PoStCircuit {
    // Private identity pre-image of replicaID.
    pub pinner_identity: Value<Halo2Fr>,
    pub cid: Value<Halo2Fr>,
    pub sector_index: Value<Halo2Fr>,
    pub epoch: Value<Halo2Fr>,

    /// The challenged node index v* (public via challengeNonce). Witnessed.
    pub challenge_index: usize,

    /// The sealed replica leaf R[v*] — proven to be in CommR.
    pub replica_challenged: Value<Halo2Fr>,

    /// The two layer labels for v* (label(1,v*), label(2,v*)).
    pub label_l1: Value<Halo2Fr>,
    pub label_l2: Value<Halo2Fr>,

    /// The DRG-same-layer parent labels (label(1,v*-1), label(2,v*-1)).
    /// For v*=0 they are unused (mux'd out by `has_drg_parent`=false).
    pub drg_parent_l1: Value<Halo2Fr>,
    pub drg_parent_l2: Value<Halo2Fr>,

    /// Merkle sibling values for the CommR and CommC inclusions of node v*.
    /// Directions are derived in-circuit from v*'s bits.
    pub sib_r: [Value<Halo2Fr>; MERKLE_DEPTH],
    pub sib_c: [Value<Halo2Fr>; MERKLE_DEPTH],

    /// Merkle sibling values for the DRG-PARENT column inclusion (CommC at
    /// index v*-1). For v*=0 these are benign dummies (gated off).
    pub sib_parent_c: [Value<Halo2Fr>; MERKLE_DEPTH],
}

impl PoStCircuit {
    /// Build the PoSt circuit witness for the challenged node from a fully
    /// sealed replica (the SAME `SealedReplica` PoRep seals).
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
        let parent_index = drg_parent(v).unwrap_or(0);
        let sib_parent_c = merkle_siblings_4(&sealed.columns, parent_index).map(Value::known);
        let sib_r = merkle_siblings_4(&sealed.replica, v).map(Value::known);
        let sib_c = merkle_siblings_4(&sealed.columns, v).map(Value::known);
        Self {
            pinner_identity: Value::known(pinner_identity),
            cid: Value::known(sealed.cid),
            sector_index: Value::known(sealed.sector_index),
            epoch: Value::known(sealed.epoch),
            challenge_index: v,
            replica_challenged: Value::known(sealed.replica[v]),
            label_l1: Value::known(sealed.labels[0][v]),
            label_l2: Value::known(sealed.labels[1][v]),
            drg_parent_l1: Value::known(drg_l1),
            drg_parent_l2: Value::known(drg_l2),
            sib_r,
            sib_c,
            sib_parent_c,
        }
    }

    /// The public-input vector for a sealed replica + challenge index, in
    /// the 7-slot PoSt layout (NO CommD).
    pub fn public_inputs(sealed: &SealedReplica, challenge_index: usize) -> Vec<Halo2Fr> {
        let mut pis = vec![Halo2Fr::from(0u64); pi::COUNT];
        pis[pi::REPLICA_ID] = sealed.replica_id;
        pis[pi::CID] = sealed.cid;
        pis[pi::SECTOR_INDEX] = sealed.sector_index;
        pis[pi::COMM_R] = sealed.comm_r;
        pis[pi::COMM_C] = sealed.comm_c;
        pis[pi::CHALLENGE_NONCE] = Halo2Fr::from(challenge_index as u64);
        pis[pi::EPOCH] = sealed.epoch;
        pis
    }
}

impl Circuit<Halo2Fr> for PoStCircuit {
    type Config = PoStCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            pinner_identity: Value::unknown(),
            cid: Value::unknown(),
            sector_index: Value::unknown(),
            epoch: Value::unknown(),
            challenge_index: 0,
            replica_challenged: Value::unknown(),
            label_l1: Value::unknown(),
            label_l2: Value::unknown(),
            drg_parent_l1: Value::unknown(),
            drg_parent_l2: Value::unknown(),
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
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        // NOTE: NO encoding (add) gate — PoSt does not enforce R = D + label.
        PoStCircuitConfig {
            poseidon,
            swap,
            witness,
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
        let (pid_cell, cid_cell, sector_cell, epoch_cell, replica_cell, drg1_cell, drg2_cell) =
            layouter.assign_region(
                || "post_witness",
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
                    let replica = region.assign_advice(
                        || "R[v*]",
                        config.witness,
                        4,
                        || self.replica_challenged,
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
                    Ok((pid, cid, sector, epoch, replica, drg1, drg2))
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
        let idx_val = Value::known(Halo2Fr::from(self.challenge_index as u64));
        let (idx_cell, bits) = swap.decompose_index(&mut layouter, idx_val)?;
        layouter.constrain_instance(idx_cell.cell(), config.instance, pi::CHALLENGE_NONCE)?;

        // has_drg_parent = (challengeNonce ≠ 0), CONSTRAINED.
        let has_drg = swap.is_nonzero(&mut layouter, &idx_cell)?;

        let layer1_cell = swap.assign_const(&mut layouter, Halo2Fr::from(1u64), "layer=1")?;
        let layer2_cell = swap.assign_const(&mut layouter, Halo2Fr::from(2u64), "layer=2")?;

        // ---- Step 3: layer-L labeling relation (the finding-1.1 core). ----
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

        // ---- Step 4: column commitment. column(v*) = Poseidon(label1, label2). ----
        let column_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[label1_cell.clone(), label2_cell.clone()],
        )?;

        // ---- Step 5: index-agnostic Merkle inclusions R[v*]∈CommR, col∈CommC. ----
        let sib_r = self.assign_siblings(swap, &mut layouter, &self.sib_r, "sib_r")?;
        let root_r = swap.merkle_root(&config.poseidon, &mut layouter, replica_cell, &bits, &sib_r)?;
        layouter.constrain_instance(root_r.cell(), config.instance, pi::COMM_R)?;

        let sib_c = self.assign_siblings(swap, &mut layouter, &self.sib_c, "sib_c")?;
        let root_c = swap.merkle_root(&config.poseidon, &mut layouter, column_cell, &bits, &sib_c)?;
        layouter.constrain_instance(root_c.cell(), config.instance, pi::COMM_C)?;

        // ---- Step 6: PARENT SOUNDNESS — parent column ∈ CommC at v*-1. ----
        let parent_col = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[drg1_cell.clone(), drg2_cell.clone()],
        )?;
        let parent_index_val = self
            .challenge_index
            .checked_sub(1)
            .map(|p| Halo2Fr::from(p as u64))
            .unwrap_or(Halo2Fr::ZERO);
        let (parent_idx_cell, parent_bits) =
            swap.decompose_index(&mut layouter, Value::known(parent_index_val))?;
        // p+1 via a small add region using the swap gadget's columns + a
        // gated_eq: has_drg·((p+1) − v*) = 0. We compute p+1 with the
        // recompose gate is not a fit; use a dedicated add through the swap
        // mux gate's add-like form is also awkward, so we enforce p+1 = v*
        // (when has_drg) by gate-equating `parent_idx + 1` to `idx` using an
        // explicit add region anchored on the swap gadget's `a/b` columns.
        let parent_idx_plus1 = swap.add_one(&mut layouter, &parent_idx_cell)?;
        swap.gated_eq(&mut layouter, &parent_idx_plus1, &idx_cell, &has_drg)?;

        let sib_parent =
            self.assign_siblings(swap, &mut layouter, &self.sib_parent_c, "sib_parent_c")?;
        let parent_root = swap.merkle_root(
            &config.poseidon,
            &mut layouter,
            parent_col,
            &parent_bits,
            &sib_parent,
        )?;
        // has_drg·(parent_root − CommC) = 0, gate-equated against `root_c`
        // (already constrained to the public CommC).
        swap.gated_eq(&mut layouter, &parent_root, &root_c, &has_drg)?;

        Ok(())
    }
}

impl PoStCircuit {
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
    use crate::zkp::halo2::porep::{seal_reduced, L};
    use halo2_proofs::dev::MockProver;

    /// k for the reduced PoSt instance. PoSt is LIGHTER than PoRep (no
    /// encoding bridge, no CommD inclusion) but the index-agnostic Merkle +
    /// parent inclusion add Poseidon permutations; k=14 keeps it uniform
    /// with PoRep's k so the v2/v3 SRS sizing stays uniform.
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

    /// Positive — a correctly-sealed tiny replica's PoSt proof verifies for
    /// every challenge index, via MockProver.
    #[test]
    fn post_reduced_positive_mockprover_all_nodes() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        for v in 0..N {
            let circuit = PoStCircuit::from_sealed(&sealed, pinner, v);
            let pis = PoStCircuit::public_inputs(&sealed, v);
            let prover = MockProver::run(K, &circuit, vec![pis]).expect("mockprover setup");
            assert_eq!(
                prover.verify(),
                Ok(()),
                "honest reduced PoSt must verify for challenge v={v}"
            );
        }
    }

    /// Positive — full KZG prove+verify round trip.
    #[test]
    fn post_reduced_positive_kzg_round_trip() {
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
        let circuit = PoStCircuit::from_sealed(&sealed, pinner, v);
        let pis = PoStCircuit::public_inputs(&sealed, v);

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
        assert!(ok, "honest reduced PoSt KZG proof must verify");
        eprintln!(
            "PIN-P1 reduced PoSt proof (N={N}, L={L}, v={v}): {} bytes (k={K})",
            proof_bytes.len()
        );
    }

    /// SINGLE-VK (TD-18 killed): ONE keygen'd VK verifies honest PoSt proofs
    /// for ALL 4 challenge indices.
    #[test]
    fn post_single_vk_verifies_all_indices() {
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

        let mut params_rng = StdRng::from_seed([0x4D; 32]);
        let params = ParamsKZG::<Bn256>::setup(K, &mut params_rng);
        let shape = PoStCircuit::default().without_witnesses();
        let vk = keygen_vk(&params, &shape).expect("single keygen_vk");
        let pk = keygen_pk(&params, vk.clone(), &shape).expect("single keygen_pk");

        for v in 0..N {
            let circuit = PoStCircuit::from_sealed(&sealed, pinner, v);
            let pis = PoStCircuit::public_inputs(&sealed, v);
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
            assert!(ok, "the SINGLE PoSt VK must verify challenge index v={v}");
        }
    }

    /// Soundness — wrong replicaID. B's identity + B's replicaID over A's
    /// held replica → labeling recomputes from B's replicaID → mismatch.
    #[test]
    fn post_reduced_negative_wrong_replica_id() {
        let pinner_a = Halo2Fr::from(0xA11CEu64);
        let pinner_b = Halo2Fr::from(0xB0Bu64);
        let sealed_a = seal_sample(pinner_a);
        let sealed_b = seal_sample(pinner_b);
        let v = 1usize;

        let mut circuit = PoStCircuit::from_sealed(&sealed_a, pinner_a, v);
        circuit.pinner_identity = Value::known(pinner_b);

        let mut pis = PoStCircuit::public_inputs(&sealed_a, v);
        pis[pi::REPLICA_ID] = sealed_b.replica_id;

        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoSt with B's replicaID over A's held replica MUST fail (finding 1.1)"
        );
    }

    /// Soundness — tampered label (without rebuilding commitments).
    #[test]
    fn post_reduced_negative_tampered_label() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 1usize;

        let mut circuit = PoStCircuit::from_sealed(&sealed, pinner, v);
        circuit.drg_parent_l2 = Value::known(sealed.labels[1][0] + Halo2Fr::from(1u64));

        let pis = PoStCircuit::public_inputs(&sealed, v);
        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoSt with a tampered label MUST fail the labeling/column relation"
        );
    }

    /// PARENT FORGERY (new soundness test) — supply a forged but
    /// relation-satisfying parent label; the parent-column inclusion against
    /// CommC must reject.
    #[test]
    fn post_parent_forgery_rejected() {
        use crate::zkp::halo2::porep::merkle_root_4_for_test;
        let pinner = Halo2Fr::from(0xA11CEu64);
        let mut sealed = seal_sample(pinner);
        let v = 1usize;

        let forged_p1 = sealed.labels[0][0] + Halo2Fr::from(777u64);
        let forged_p2 = sealed.labels[1][0] + Halo2Fr::from(888u64);

        // Recompute v*'s labels/column/replica from the forged parents.
        let l1 = crate::zkp::halo2::porep::label_hash_for_test(
            sealed.replica_id,
            1,
            v,
            forged_p1,
            None,
        );
        let l2 = crate::zkp::halo2::porep::label_hash_for_test(
            sealed.replica_id,
            2,
            v,
            forged_p2,
            Some(l1),
        );
        let col = crate::zkp::halo2::porep::pair_hash_for_test(l1, l2);
        let r = sealed.data[v] + l2;

        sealed.labels[0][v] = l1;
        sealed.labels[1][v] = l2;
        sealed.columns[v] = col;
        sealed.replica[v] = r;
        sealed.comm_c = merkle_root_4_for_test(&sealed.columns);
        sealed.comm_r = merkle_root_4_for_test(&sealed.replica);

        let mut circuit = PoStCircuit::from_sealed(&sealed, pinner, v);
        circuit.drg_parent_l1 = Value::known(forged_p1);
        circuit.drg_parent_l2 = Value::known(forged_p2);

        let pis = PoStCircuit::public_inputs(&sealed, v);
        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoSt with a forged (relation-satisfying) parent label MUST be \
             rejected by the parent-column inclusion against CommC"
        );
    }

    /// Index-binding negative: witnessed index ≠ public challengeNonce.
    #[test]
    fn post_index_binding_negative() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 2usize;

        let circuit = PoStCircuit::from_sealed(&sealed, pinner, v);
        let mut pis = PoStCircuit::public_inputs(&sealed, v);
        pis[pi::CHALLENGE_NONCE] = Halo2Fr::from(1u64);

        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "witnessed index must equal public challengeNonce or proof rejects"
        );
    }

    /// Soundness — wrong/non-stored node value (R leaf not in CommR).
    #[test]
    fn post_reduced_negative_wrong_node_value() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 3usize;

        let mut circuit = PoStCircuit::from_sealed(&sealed, pinner, v);
        circuit.replica_challenged = Value::known(sealed.replica[v] + Halo2Fr::from(99u64));

        let pis = PoStCircuit::public_inputs(&sealed, v);
        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoSt with a non-stored node value MUST fail CommR inclusion"
        );
    }

    /// Soundness — tampered public input (flip CommR).
    #[test]
    fn post_reduced_negative_tampered_public_input() {
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 0usize;

        let circuit = PoStCircuit::from_sealed(&sealed, pinner, v);
        let mut pis = PoStCircuit::public_inputs(&sealed, v);
        pis[pi::COMM_R] = sealed.comm_r + Halo2Fr::from(1u64);

        let prover = MockProver::run(K, &circuit, vec![pis]).expect("setup");
        assert!(
            prover.verify().is_err(),
            "PoSt with a tampered public CommR MUST fail"
        );
    }

    /// The reduced PoSt public-input layout has 7 slots — distinct from
    /// PoRep's 8 (no CommD).
    #[test]
    fn post_reduced_public_input_shape() {
        assert_eq!(pi::COUNT, 7);
        let sealed = seal_sample(Halo2Fr::from(1u64));
        let pis = PoStCircuit::public_inputs(&sealed, 0);
        assert_eq!(pis.len(), 7);
        assert_eq!(pi::COMM_R, 3);
        assert_eq!(super::super::porep::pi::COMM_D, 3);
    }

    /// PoSt reuses PoRep's sealing.
    #[test]
    fn post_shares_sealing_with_porep() {
        use crate::zkp::halo2::porep::PoRepCircuit;
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 2usize;

        let post_pis = PoStCircuit::public_inputs(&sealed, v);
        let porep_pis = PoRepCircuit::public_inputs(&sealed, v);

        assert_eq!(
            post_pis[pi::REPLICA_ID],
            porep_pis[crate::zkp::halo2::porep::pi::REPLICA_ID]
        );
        assert_eq!(
            post_pis[pi::COMM_R],
            porep_pis[crate::zkp::halo2::porep::pi::COMM_R]
        );
        assert_eq!(
            post_pis[pi::COMM_C],
            porep_pis[crate::zkp::halo2::porep::pi::COMM_C]
        );
    }
}
