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
//   "PoSt proof (recurring, light) — public inputs":
//     { replicaID, cid, sectorIndex, CommR, CommC, challengeNonce, epoch }
//   For K random nodes: prove R[v]∈CommR, column(v)∈CommC, and the
//   layer-L labeling relation re-derives label(L,v) (touches the node +
//   its parents, not the whole sector).
//
// **Scope of THIS module — a COMPLETE, WORKING circuit for the REDUCED
// instance** (same N=4, L=2, d_DRG=1, d_EXP=1 topology as PoRep), not a
// placeholder. Every relation PoSt needs (replicaID-keyed labeling of v +
// parents, Poseidon-Merkle inclusion of R/column) is enforced in-circuit.
// The path to full size mirrors PoRep's PIN-P1 follow-ups.
//
// **What is REUSED from porep.rs (not re-implemented):**
//   - The native witness builder: `seal_reduced` produces the identical
//     `SealedReplica` (labels, replica leaves, columns, CommR, CommC).
//     PoSt's honest-prover constructor consumes that struct directly — a
//     PoSt proof and a PoRep proof over the SAME sealed replica use the
//     SAME labels/commitments, only the in-circuit relations differ.
//   - Topology helpers `drg_parent`, `exp_parent`, `merkle_path_4`,
//     `merkle_root_4` (via `SealedReplica`), the constants `N`, `L`,
//     `MERKLE_DEPTH`.
//   - `PoseidonChip` (chips.rs) — same in-circuit Poseidon-2 used for the
//     labeling hash, the column hash, and the Merkle-node hash, byte-
//     identical to the native `poseidon_bn254::poseidon_hash`.
//   - The MockProver + KZG prove/verify harness pattern.
//
// **What is net-new:** the `PoStCircuit` composition (this file) — a
// strict SUBSET of PoRepCircuit's synthesis (it drops the encoding gate
// and the CommD inclusion). NO new chip, NO new native sealing routine.
//
// ---------------------------------------------------------------------------
// Labeling relation re-derived in-circuit (the finding-1.1 core, light form)
// ---------------------------------------------------------------------------
//
// Identical keying to PoRep — every label's Poseidon preimage starts with
// (replicaID, l, v), so changing replicaID changes EVERY label:
//
//   replicaID = Poseidon(pinnerIdentity, cid, sectorIndex)
//   label(1, v) = Poseidon(replicaID, 1, v, prev_same1)
//       prev_same1 = label(1, v-1)  (v≥1)  | replicaID (seed, v=0)
//   label(2, v) = Poseidon(replicaID, 2, v, prev_same2, label(1, v))
//       prev_same2 = label(2, v-1)  (v≥1)  | replicaID (seed, v=0)
//
// PoSt re-derives BOTH layers for the challenged node (label(1,v) is an
// input to label(2,v), and column(v) = Poseidon(label(1,v), label(2,v))),
// then checks:
//   - R[v] ∈ CommR     (Poseidon-Merkle inclusion; R[v] is a witness leaf)
//   - column(v) ∈ CommC (Poseidon-Merkle inclusion)
//
// It does NOT check D[v]∈CommD and does NOT enforce R[v] = D[v]+label(2,v)
// (that is PoRep's seal-time relation). PoSt only needs to show the held
// replica's leaf and column are still the committed ones AND were derived
// under THIS replicaID's labeling — proving continued possession of the
// correctly-sealed bytes without re-opening the data.
//
// Public inputs (instance column), in this fixed layout (NO CommD):
//   [0] replicaID
//   [1] cid
//   [2] sectorIndex
//   [3] CommR
//   [4] CommC
//   [5] challengeNonce      (challenged node index, reduced binding)
//   [6] epoch
//
// Domain separation from PoRep is structural: PoRep exposes 8 public
// inputs (with CommD at slot 3), PoSt exposes 7 (CommR at slot 3) — a
// PoRep proof's instance column cannot satisfy the PoSt VK and vice
// versa, and both differ from the inference circuit's 3-commitment shape.

#![allow(clippy::too_many_arguments)]

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
};
use halo2curves::bn256::Fr as Halo2Fr;

use super::chips::{PoseidonChip, PoseidonChipConfig};
// Reuse the PoRep topology + native sealing wholesale.
use super::porep::{drg_parent, merkle_path_4, SealedReplica, MERKLE_DEPTH, N};

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
// PoStCircuit — the reduced in-circuit relation (lighter than PoRep).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PoStCircuitConfig {
    poseidon: PoseidonChipConfig,
    /// Witness column for the private scalars that must be cell-bound
    /// (pinner_identity, cid, sector_index, the sealed leaf R[v*], the
    /// label/Merkle-sibling values).
    witness: Column<Advice>,
    instance: Column<Instance>,
}

/// Reduced-instance PoSt circuit. Carries the sealed witness for the
/// challenged node `challenge_index` (and the Merkle siblings its two
/// inclusions need). No data leaf, no encoding gate — PoSt is a strict
/// subset of PoRep's relations.
#[derive(Clone, Default)]
pub struct PoStCircuit {
    // Private identity pre-image of replicaID.
    pub pinner_identity: Value<Halo2Fr>,
    pub cid: Value<Halo2Fr>,
    pub sector_index: Value<Halo2Fr>,
    pub epoch: Value<Halo2Fr>,

    /// The challenged node index v* (public via challengeNonce).
    pub challenge_index: usize,

    /// The sealed replica leaf R[v*] — proven to be in CommR. Unlike PoRep
    /// there is NO data leaf and NO encoding gate: PoSt takes R[v*] as the
    /// held leaf and proves its inclusion + that it sits under a column
    /// derived from this replicaID's labeling.
    pub replica_challenged: Value<Halo2Fr>,

    /// The two layer labels for v* (label(1,v*), label(2,v*)).
    pub label_l1: Value<Halo2Fr>,
    pub label_l2: Value<Halo2Fr>,

    /// The DRG-same-layer parent labels needed to recompute v*'s labels.
    /// For v*=0 the seed is replicaID (recomputed in-circuit); these are
    /// then ignored.
    pub drg_parent_l1: Value<Halo2Fr>, // label(1, v*-1)  (unused at v*=0)
    pub drg_parent_l2: Value<Halo2Fr>, // label(2, v*-1)  (unused at v*=0)

    /// Merkle authentication paths for CommR and CommC. Each entry is
    /// (sibling, sibling_is_left).
    pub path_r: [(Value<Halo2Fr>, bool); MERKLE_DEPTH],
    pub path_c: [(Value<Halo2Fr>, bool); MERKLE_DEPTH],
}

impl PoStCircuit {
    /// Build the PoSt circuit witness for the challenged node from a fully
    /// sealed replica (the SAME `SealedReplica` PoRep seals). This is the
    /// honest-prover constructor for the recurring proof.
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
            replica_challenged: Value::known(sealed.replica[v]),
            label_l1: Value::known(sealed.labels[0][v]),
            label_l2: Value::known(sealed.labels[1][v]),
            drg_parent_l1: Value::known(drg_l1),
            drg_parent_l2: Value::known(drg_l2),
            path_r: to_vp(path_r),
            path_c: to_vp(path_c),
        }
    }

    /// Build a witness-free circuit whose **fixed topology** matches an
    /// honest PoSt proof for `challenge_index`, suitable for `keygen_vk`.
    ///
    /// Per the per-challenge VK pattern PoRep established: the v=0
    /// labeling-seed copy constraint differs from v≥1, and the Merkle
    /// branch directions (`sibling_is_left`) are part of the fixed
    /// structure. This constructor pins exactly those topology bits
    /// (siblings are `Value::unknown()`; only the deterministic `bool`
    /// directions, derived from `merkle_path_4`, matter for the VK).
    pub fn for_keygen(challenge_index: usize) -> Self {
        debug_assert!(challenge_index < N, "challenge_index must be < N");
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
            replica_challenged: Value::unknown(),
            label_l1: Value::unknown(),
            label_l2: Value::unknown(),
            drg_parent_l1: Value::unknown(),
            drg_parent_l2: Value::unknown(),
            path_r: dir(merkle_path_4(&dummy, challenge_index)),
            path_c: dir(merkle_path_4(&dummy, challenge_index)),
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
            challenge_index: self.challenge_index,
            replica_challenged: Value::unknown(),
            label_l1: Value::unknown(),
            label_l2: Value::unknown(),
            drg_parent_l1: Value::unknown(),
            drg_parent_l2: Value::unknown(),
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
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        // NOTE: NO encoding (add) gate — PoSt does not enforce R = D + label.
        PoStCircuitConfig {
            poseidon,
            witness,
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

        // Constant cells for the layer/node indices used in labeling preimages.
        let layer1_cell =
            self.assign_constant(&config, &mut layouter, Halo2Fr::from(1u64), "layer=1")?;
        let layer2_cell =
            self.assign_constant(&config, &mut layouter, Halo2Fr::from(2u64), "layer=2")?;
        let v_cell = self.assign_constant(&config, &mut layouter, Halo2Fr::from(v as u64), "v*")?;
        // challengeNonce public input == v*.
        layouter.constrain_instance(v_cell.cell(), config.instance, pi::CHALLENGE_NONCE)?;

        // ---- Step 3: layer-L labeling relation (the finding-1.1 core). ----
        // label(1, v*) = Poseidon(replicaID, 1, v*, prev_same1)
        //   prev_same1 = label(1, v*-1) if v*≥1, else replicaID (seed).
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

        // ---- Step 4: column commitment. column(v*) = Poseidon(label1, label2). ----
        let column_cell = PoseidonChip::hash_n_from_cells(
            &config.poseidon,
            &mut layouter,
            &[label1_cell.clone(), label2_cell.clone()],
        )?;

        // ---- Step 5: Merkle inclusions R[v*]∈CommR, column(v*)∈CommC. ----
        // NO CommD inclusion — that is PoRep-only (data is not re-opened in
        // the recurring PoSt). The R leaf is the witnessed sealed leaf; the
        // column is the recomputed one (bound to label1/label2 above), so a
        // prover cannot present a column that does not match the labeling.
        self.merkle_verify(
            &config,
            &mut layouter,
            replica_cell,
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

impl PoStCircuit {
    /// Assign a public/known constant into a fresh equality-enabled cell.
    fn assign_constant(
        &self,
        config: &PoStCircuitConfig,
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
    /// the public root at instance slot `root_pi`. Identical topology to
    /// PoRep's `merkle_verify`: at each level the running digest is hashed
    /// with its sibling in the correct order; the branch direction is a
    /// public part of the topology (challenge index).
    fn merkle_verify(
        &self,
        config: &PoStCircuitConfig,
        layouter: &mut impl Layouter<Halo2Fr>,
        leaf: AssignedCell<Halo2Fr, Halo2Fr>,
        path: &[(Value<Halo2Fr>, bool); MERKLE_DEPTH],
        root_pi: usize,
    ) -> Result<(), ErrorFront> {
        let mut cur = leaf;
        for (level, (sib_val, sib_is_left)) in path.iter().enumerate() {
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
    use crate::zkp::halo2::porep::{seal_reduced, L};
    use halo2_proofs::dev::MockProver;

    /// k for the reduced PoSt instance. PoSt is LIGHTER than PoRep (no
    /// encoding bridge hashes, no CommD Merkle inclusion): replicaID + 2
    /// labels + column + 4 Merkle-node hashes ≈ 8 permutations, fewer than
    /// PoRep's ~12. k=13 (8192 rows) is comfortable; we keep it equal to
    /// PoRep's K so the v2/v3 SRS sizing stays uniform.
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

    /// Positive — full KZG prove+verify round trip (the real pipeline the
    /// 0x0108 circuit_version=3 path runs).
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

    /// Soundness — wrong replicaID. Present pinner B's identity + B's
    /// replicaID as public input, but A's sealed witness (labels/leaves).
    /// The in-circuit labeling recomputes from the PUBLIC replicaID (B's),
    /// so the recomputed column no longer matches A's CommC and the R-leaf
    /// inclusion is against A's CommR while the proof claims B's replicaID
    /// → MUST fail. B cannot reuse A's held replica.
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

    /// Soundness — tampered label. Corrupt the DRG parent label feeding
    /// label(2,v*): the recomputed label(2,v*) (and thus column(v*))
    /// diverges from the sealed one → column inclusion against CommC fails.
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

    /// Soundness — wrong/non-stored node value. Present an R leaf that is
    /// not the one committed in CommR (a node the pinner no longer holds).
    /// The Merkle inclusion of R[v*] against the public CommR MUST fail —
    /// this is the core "is the replica STILL held" check.
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

    /// Soundness — tampered public input. Keep the honest witness but flip
    /// the public CommR to a wrong root; the R-inclusion's recomputed root
    /// can no longer equal the (tampered) public CommR → MUST fail.
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
    /// PoRep's 8 (no CommD) and from the inference circuit's 3-commitment
    /// shape. Domain separation at the shape level.
    #[test]
    fn post_reduced_public_input_shape() {
        assert_eq!(pi::COUNT, 7);
        let sealed = seal_sample(Halo2Fr::from(1u64));
        let pis = PoStCircuit::public_inputs(&sealed, 0);
        assert_eq!(pis.len(), 7);
        // CommR sits at slot 3 where PoRep has CommD — the structural
        // domain-separation point.
        assert_eq!(pi::COMM_R, 3);
        assert_eq!(super::super::porep::pi::COMM_D, 3);
    }

    /// PoSt reuses PoRep's sealing: a PoSt proof and a PoRep proof over the
    /// SAME replica agree on replicaID/CommR/CommC. This pins that the
    /// recurring proof checks the SAME sealed bytes the one-time proof did.
    #[test]
    fn post_shares_sealing_with_porep() {
        use crate::zkp::halo2::porep::PoRepCircuit;
        let pinner = Halo2Fr::from(0xA11CEu64);
        let sealed = seal_sample(pinner);
        let v = 2usize;

        let post_pis = PoStCircuit::public_inputs(&sealed, v);
        let porep_pis = PoRepCircuit::public_inputs(&sealed, v);

        // Same replicaID, CommR, CommC across the two proof systems.
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
