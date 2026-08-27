// core/execution/src/zkp/halo2/commd_step.rs
//
// M1b — the CommD fold STEP circuit (ADR-2026-08-27 recursive path, citrate-chain#170).
//
// One incremental-Merkle insert, in-circuit. The recursive proof cannot recompute the whole Merkle
// tree in one circuit; it FOLDS the file, and this is the Merkle half of one fold step: given the
// appended `leaf` at append `index` and the path `siblings` (both produced by the `citrate-commd`
// fold reference, `IncrementalMerkle::insert_returning_siblings`), prove the resulting `root` via the
// audited `SwapMerkleChip::merkle_root_generic`. Because that gadget is `cond_swap`-per-level, it
// reconstructs exactly the reference's `root = fold(leaf, index_bits, siblings)`; the differential
// test below pins the two together.
//
// The IVC layer (M2) threads the running state (filled[] / index / keccak) across steps; this circuit
// proves ONE step's Merkle transition. `depth` fixes the circuit shape (one VK per depth); the append
// index is index-agnostic (single VK for every index at a given depth), mirroring the PoRep circuit.
//
// Public inputs: [root, index]. Private: leaf, siblings.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance},
};
use halo2curves::bn256::Fr as Halo2Fr;
use halo2curves::ff::Field as _;

use super::chips::{PoseidonChip, PoseidonChipConfig};
use super::porep::SwapMerkleConfig;

/// Public-input layout for the step circuit.
pub mod pi {
    pub const ROOT: usize = 0;
    pub const INDEX: usize = 1;
    pub const COUNT: usize = 2;
}

#[derive(Clone, Debug)]
pub struct CommDStepConfig {
    poseidon: PoseidonChipConfig,
    swap: SwapMerkleConfig,
    witness: Column<Advice>,
    instance: Column<Instance>,
}

/// One fold step: append `leaf` at `index` into a depth-`depth` incremental Merkle tree and prove the
/// resulting `root`. `siblings.len() == depth`.
#[derive(Clone)]
pub struct CommDStepCircuit {
    pub leaf: Value<Halo2Fr>,
    pub index: u64,
    pub siblings: Vec<Value<Halo2Fr>>,
    pub depth: usize,
}

impl CommDStepCircuit {
    /// The public-input vector `[root, index]`.
    pub fn public_inputs(root: Halo2Fr, index: u64) -> Vec<Halo2Fr> {
        let mut pis = vec![Halo2Fr::ZERO; pi::COUNT];
        pis[pi::ROOT] = root;
        pis[pi::INDEX] = Halo2Fr::from(index);
        pis
    }
}

impl Circuit<Halo2Fr> for CommDStepCircuit {
    type Config = CommDStepConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        // `depth` (and `index`, whose bit-decomposition shape is fixed by `depth`) define the circuit
        // shape; the leaf and sibling VALUES are hidden for VK keygen.
        Self {
            leaf: Value::unknown(),
            index: self.index,
            siblings: vec![Value::unknown(); self.depth],
            depth: self.depth,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self::Config {
        let poseidon = PoseidonChip::configure(meta);
        let swap = SwapMerkleConfig::configure(meta);
        let witness = meta.advice_column();
        meta.enable_equality(witness);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        CommDStepConfig {
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
        // Witness the appended leaf.
        let leaf_cell = layouter.assign_region(
            || "commd_step_leaf",
            |mut region| region.assign_advice(|| "leaf", config.witness, 0, || self.leaf),
        )?;

        // Boolean-constrained bit decomposition of the append index (sound; single VK per depth).
        let idx_val = Value::known(Halo2Fr::from(self.index));
        let (idx_cell, bits) =
            config
                .swap
                .decompose_index_generic(&mut layouter, idx_val, self.depth)?;

        // Witness the path siblings.
        let sibling_cells: Vec<AssignedCell<Halo2Fr, Halo2Fr>> = layouter.assign_region(
            || "commd_step_siblings",
            |mut region| {
                let mut v = Vec::with_capacity(self.depth);
                for (h, s) in self.siblings.iter().enumerate() {
                    v.push(region.assign_advice(|| "sib", config.witness, h, || *s)?);
                }
                Ok(v)
            },
        )?;

        // Recompute the root via the audited cond-swap Merkle gadget.
        let root_cell = config.swap.merkle_root_generic(
            &config.poseidon,
            &mut layouter,
            leaf_cell,
            &bits,
            &sibling_cells,
        )?;

        // Bind the public root + index.
        layouter.constrain_instance(root_cell.cell(), config.instance, pi::ROOT)?;
        layouter.constrain_instance(idx_cell.cell(), config.instance, pi::INDEX)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2curves::ff::PrimeField as _;

    /// ark-bn254 Fr (citrate-commd) -> halo2 Fr, via the canonical BE bytes citrate-commd exposes.
    fn ark_be_to_h(be: [u8; 32]) -> Halo2Fr {
        let mut le = be;
        le.reverse();
        Option::<Halo2Fr>::from(Halo2Fr::from_repr(le.into())).expect("canonical Fr")
    }

    #[test]
    fn commd_step_proves_incremental_insert() {
        // Build the reference fold, capture the witness for one insert, prove it in-circuit, and
        // check the public root matches the reference — pinning the step circuit to citrate-commd.
        const K: u32 = 13;
        let data: Vec<u8> = (0..300u32).map(|i| (i * 3 + 1) as u8).collect(); // ~10 leaves
        let leaves = citrate_commd::pack_bytes(&data);
        let depth = leaves.len().next_power_of_two().trailing_zeros();

        let mut acc = citrate_commd::IncrementalMerkle::new(depth);
        // Populate filled[] with all but the last leaf, then prove the final insert.
        for leaf in &leaves[..leaves.len() - 1] {
            acc.insert(*leaf);
        }
        let index = acc.index();
        let last = leaves[leaves.len() - 1];
        let sibs = acc.insert_returning_siblings(last);
        let root = acc.root();

        let leaf_h = ark_be_to_h(citrate_commd::fr_to_be_bytes(last));
        let sibs_h: Vec<Value<Halo2Fr>> = sibs
            .into_iter()
            .map(|s| Value::known(ark_be_to_h(citrate_commd::fr_to_be_bytes(s))))
            .collect();
        let root_h = ark_be_to_h(citrate_commd::fr_to_be_bytes(root));

        let circuit = CommDStepCircuit {
            leaf: Value::known(leaf_h),
            index,
            siblings: sibs_h,
            depth: depth as usize,
        };
        let pis = CommDStepCircuit::public_inputs(root_h, index);

        let prover = MockProver::run(K, &circuit, vec![pis]).expect("mock prover runs");
        assert_eq!(
            prover.verify(),
            Ok(()),
            "step circuit must verify the honest insert"
        );
    }

    #[test]
    fn commd_step_rejects_wrong_root() {
        const K: u32 = 13;
        let data: Vec<u8> = (0..128u32).map(|i| i as u8).collect();
        let leaves = citrate_commd::pack_bytes(&data);
        let depth = leaves.len().next_power_of_two().trailing_zeros();
        let mut acc = citrate_commd::IncrementalMerkle::new(depth);
        for leaf in &leaves[..leaves.len() - 1] {
            acc.insert(*leaf);
        }
        let index = acc.index();
        let last = leaves[leaves.len() - 1];
        let sibs = acc.insert_returning_siblings(last);
        let root = acc.root();

        let leaf_h = ark_be_to_h(citrate_commd::fr_to_be_bytes(last));
        let sibs_h: Vec<Value<Halo2Fr>> = sibs
            .into_iter()
            .map(|s| Value::known(ark_be_to_h(citrate_commd::fr_to_be_bytes(s))))
            .collect();
        // A WRONG claimed root (root + 1) must fail.
        let bad_root = ark_be_to_h(citrate_commd::fr_to_be_bytes(root)) + Halo2Fr::ONE;

        let circuit = CommDStepCircuit {
            leaf: Value::known(leaf_h),
            index,
            siblings: sibs_h,
            depth: depth as usize,
        };
        let pis = CommDStepCircuit::public_inputs(bad_root, index);
        let prover = MockProver::run(K, &circuit, vec![pis]).expect("mock prover runs");
        assert!(prover.verify().is_err(), "a wrong root must NOT verify");
    }
}
