// citrate/core/execution/src/zkp/halo2/circuits.rs
//
// RM-M1b WP-M1b.3 — InferenceCircuit composition.
//
// Composes the three chips that land in `chips.rs`:
//   1. PoseidonChip   — in-circuit Poseidon-2 hash on BN254 Fr.
//   2. LinearChip     — Q16.16 linear layer y = (W·x) >> 16 + b.
//   3. (Optional)     — TensorCommitChip (just a wrapper over hash_n).
//
// **Statement proven by InferenceCircuit::v1 (CIRCUIT_VERSION_LINEAR_Q16):**
//
//   Public inputs:
//     [0] input_commitment   = Poseidon(x[0], x[1], ..., x[in_dim-1])
//     [1] model_commitment   = Poseidon(W flat ++ b)
//     [2] output_commitment  = Poseidon(y[0], ..., y[out_dim-1])
//
//   Private witness:
//     W: out_dim × in_dim Q16 weights
//     x: in_dim Q16 inputs
//     b: out_dim Q16 biases
//
//   Constraint:
//     y = LinearChip(W, x, b)            (gate-enforced)
//     Poseidon(x cells)         = PI[0]  (cell-bound via copy constraints)
//     Poseidon(W cells ++ b cells) = PI[1]
//     Poseidon(y cells)         = PI[2]
//
// The cell-bindings (via PoseidonChip::hash_n_from_cells +
// LinearChip::linear_from_cells) prevent a malicious prover from
// feeding different values to the hash than to the linear layer.
//
// **v1 dimensions:** the circuit is parameterised at `Circuit::configure`
// time (compile-time const generics would be cleaner, but Halo2's
// `Circuit` trait doesn't compose with that API in 0.4 cleanly).
// For RM-M1b's first deployment we ship `out_dim=1, in_dim=2` —
// the smallest non-trivial linear layer. Larger sizes only require
// updating the witness vectors and (potentially) the `k` parameter
// for keygen.
//
// **Saturation status:** the LinearChip does NOT enforce Q16
// saturation in-circuit. The off-chain witness contract is that
// inputs stay in safe range (no saturation triggered). This is the
// RM-M1b v1 limitation; RM-M2 follow-up adds the lookup-table
// range checks for full saturation soundness.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, ErrorFront, Instance},
};
use halo2curves::bn256::Fr as Halo2Fr;

use super::chips::{LinearChip, LinearChipConfig, PoseidonChip, PoseidonChipConfig};

/// Configuration for the v1 InferenceCircuit. Exposes the three
/// public-input slots on a single `Instance` column:
///   slot 0 = input_commitment
///   slot 1 = model_commitment
///   slot 2 = output_commitment
#[derive(Clone, Debug)]
pub struct InferenceCircuitConfig {
    pub poseidon: PoseidonChipConfig,
    pub linear: LinearChipConfig,
    /// Witness columns for the canonical W, x, b cells. These live in
    /// a dedicated witness region so the chips can copy_advice them
    /// in. Allocating fresh columns is the simplest route — sharing
    /// LinearChip's columns is possible but conflates witness rows
    /// with gate rows.
    pub w_witness: Column<halo2_proofs::plonk::Advice>,
    pub x_witness: Column<halo2_proofs::plonk::Advice>,
    pub b_witness: Column<halo2_proofs::plonk::Advice>,
    pub instance: Column<Instance>,
}

/// v1 InferenceCircuit. `out_dim` and `in_dim` are configured per
/// instance; the witness vectors must have the matching shape.
#[derive(Default, Clone)]
pub struct InferenceCircuit {
    pub weights: Vec<Value<Halo2Fr>>, // length = out_dim * in_dim, row-major
    pub inputs: Vec<Value<Halo2Fr>>,  // length = in_dim
    pub biases: Vec<Value<Halo2Fr>>,  // length = out_dim
    pub out_dim: usize,
    pub in_dim: usize,
}

impl Circuit<Halo2Fr> for InferenceCircuit {
    type Config = InferenceCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            weights: vec![Value::unknown(); self.weights.len()],
            inputs: vec![Value::unknown(); self.inputs.len()],
            biases: vec![Value::unknown(); self.biases.len()],
            out_dim: self.out_dim,
            in_dim: self.in_dim,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Halo2Fr>) -> Self::Config {
        let poseidon = PoseidonChip::configure(meta);
        let linear = LinearChip::configure(meta);

        let w_witness = meta.advice_column();
        let x_witness = meta.advice_column();
        let b_witness = meta.advice_column();
        meta.enable_equality(w_witness);
        meta.enable_equality(x_witness);
        meta.enable_equality(b_witness);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        InferenceCircuitConfig {
            poseidon,
            linear,
            w_witness,
            x_witness,
            b_witness,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Halo2Fr>,
    ) -> Result<(), ErrorFront> {
        // Step 1: witness W, x, b in a dedicated region as canonical cells.
        let (w_cells, x_cells, b_cells) = layouter.assign_region(
            || "witness_W_x_b",
            |mut region| {
                let mut w_cells = Vec::with_capacity(self.weights.len());
                let mut x_cells = Vec::with_capacity(self.inputs.len());
                let mut b_cells = Vec::with_capacity(self.biases.len());
                for (idx, v) in self.weights.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("W[{}]", idx),
                        config.w_witness,
                        idx,
                        || *v,
                    )?;
                    w_cells.push(cell);
                }
                for (idx, v) in self.inputs.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("x[{}]", idx),
                        config.x_witness,
                        idx,
                        || *v,
                    )?;
                    x_cells.push(cell);
                }
                for (idx, v) in self.biases.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("b[{}]", idx),
                        config.b_witness,
                        idx,
                        || *v,
                    )?;
                    b_cells.push(cell);
                }
                Ok((w_cells, x_cells, b_cells))
            },
        )?;

        // Step 2: input_commitment = Poseidon(x_cells).
        let input_commit_cell =
            PoseidonChip::hash_n_from_cells(&config.poseidon, &mut layouter, &x_cells)?;
        layouter.constrain_instance(input_commit_cell.cell(), config.instance, 0)?;

        // Step 3: model_commitment = Poseidon(W_cells ++ b_cells).
        let mut model_cells: Vec<_> = w_cells.iter().cloned().collect();
        model_cells.extend(b_cells.iter().cloned());
        let model_commit_cell =
            PoseidonChip::hash_n_from_cells(&config.poseidon, &mut layouter, &model_cells)?;
        layouter.constrain_instance(model_commit_cell.cell(), config.instance, 1)?;

        // Step 4: y_cells = LinearChip(W, x, b).
        let y_cells = LinearChip::linear_from_cells(
            &config.linear,
            &mut layouter,
            &w_cells,
            &x_cells,
            &b_cells,
            self.out_dim,
            self.in_dim,
        )?;

        // Step 5: output_commitment = Poseidon(y_cells).
        let output_commit_cell =
            PoseidonChip::hash_n_from_cells(&config.poseidon, &mut layouter, &y_cells)?;
        layouter.constrain_instance(output_commit_cell.cell(), config.instance, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::q16::{ops as q16_ops, Q16};
    use crate::zkp::halo2::chips::q16_to_halo2_fr;
    use crate::zkp::poseidon_bn254::poseidon_hash;
    use ark_bn254::Fr as ArkFr;
    use halo2_proofs::dev::MockProver;

    /// Convert a Q16 value to ark_bn254 Fr (for off-chain Poseidon).
    fn q16_to_ark_fr(q: Q16) -> ArkFr {
        if q.0 >= 0 {
            ArkFr::from(q.0 as u64)
        } else {
            -ArkFr::from((q.0 as i64).unsigned_abs())
        }
    }

    /// Convert ark Fr → halo2 Fr via canonical bytes (mirror of
    /// chips::ark_to_halo2_fr but exposed locally for tests).
    fn ark_fr_to_halo2_fr(x: &ArkFr) -> Halo2Fr {
        use ark_ff::{BigInteger, PrimeField as _};
        use halo2curves::ff::PrimeField as _;
        let bigint = x.into_bigint();
        let mut bytes_le = bigint.to_bytes_le();
        bytes_le.resize(32, 0);
        let bytes_arr: [u8; 32] = bytes_le.try_into().expect("32 bytes");
        let opt: Option<Halo2Fr> = Halo2Fr::from_repr(bytes_arr.into()).into();
        opt.expect("Fr from_repr should succeed")
    }

    /// Run the full inference round-trip: compute commitments off-chain,
    /// build the InferenceCircuit, and verify with MockProver.
    fn assert_inference_circuit_verifies(
        weights: &[Q16],
        inputs: &[Q16],
        biases: &[Q16],
        out_dim: usize,
        in_dim: usize,
    ) {
        // 1. Off-chain: compute y via Q16 linear ops.
        let y_q16 = q16_ops::linear(weights, inputs, biases, out_dim, in_dim);

        // 2. Off-chain: compute the three commitments via off-chain Poseidon.
        let x_ark: Vec<ArkFr> = inputs.iter().copied().map(q16_to_ark_fr).collect();
        let model_ark: Vec<ArkFr> = weights
            .iter()
            .copied()
            .chain(biases.iter().copied())
            .map(q16_to_ark_fr)
            .collect();
        let y_ark: Vec<ArkFr> = y_q16.iter().copied().map(q16_to_ark_fr).collect();

        let input_commit_ark = poseidon_hash(&x_ark);
        let model_commit_ark = poseidon_hash(&model_ark);
        let output_commit_ark = poseidon_hash(&y_ark);

        let input_commit = ark_fr_to_halo2_fr(&input_commit_ark);
        let model_commit = ark_fr_to_halo2_fr(&model_commit_ark);
        let output_commit = ark_fr_to_halo2_fr(&output_commit_ark);

        // 3. Build the circuit witness in halo2 Fr.
        let weights_fr: Vec<Halo2Fr> =
            weights.iter().copied().map(q16_to_halo2_fr).collect();
        let inputs_fr: Vec<Halo2Fr> =
            inputs.iter().copied().map(q16_to_halo2_fr).collect();
        let biases_fr: Vec<Halo2Fr> =
            biases.iter().copied().map(q16_to_halo2_fr).collect();

        let circuit = InferenceCircuit {
            weights: weights_fr.iter().map(|v| Value::known(*v)).collect(),
            inputs: inputs_fr.iter().map(|v| Value::known(*v)).collect(),
            biases: biases_fr.iter().map(|v| Value::known(*v)).collect(),
            out_dim,
            in_dim,
        };

        let public_inputs = vec![vec![input_commit, model_commit, output_commit]];

        // k=12: 4096 rows, comfortably fits the chip layouts (≤200 rows
        // for tiny inputs at out_dim=1, in_dim=2; up to ~400 for
        // 2x2 cases). Halo2 v0.4 needs k high enough for blinding +
        // permutation overhead too.
        let k = 12;
        let prover = MockProver::run(k, &circuit, public_inputs)
            .expect("MockProver setup");
        let r = prover.verify();
        assert_eq!(
            r,
            Ok(()),
            "InferenceCircuit MockProver verification failed for \
             out_dim={} in_dim={}",
            out_dim,
            in_dim
        );
    }

    #[test]
    fn inference_circuit_1x2_identity_like() {
        // y[0] = 1*3 + 0*4 + 5 = 8
        let w: Vec<Q16> = vec![Q16::from_int(1), Q16::from_int(0)];
        let x: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(4)];
        let b: Vec<Q16> = vec![Q16::from_int(5)];
        assert_inference_circuit_verifies(&w, &x, &b, 1, 2);
    }

    #[test]
    fn inference_circuit_1x2_negative_weights() {
        // y[0] = 2*3 + (-1)*5 + 0 = 1
        let w: Vec<Q16> = vec![Q16::from_int(2), Q16::from_int(-1)];
        let x: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(5)];
        let b: Vec<Q16> = vec![Q16::ZERO];
        assert_inference_circuit_verifies(&w, &x, &b, 1, 2);
    }

    #[test]
    fn inference_circuit_2x2() {
        // y[0] = 1*1 + 2*2 + 10 = 15
        // y[1] = 3*1 + 4*2 + 20 = 31
        let w: Vec<Q16> = [1, 2, 3, 4].iter().map(|&n| Q16::from_int(n)).collect();
        let x: Vec<Q16> = [1, 2].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = [10, 20].iter().map(|&n| Q16::from_int(n)).collect();
        assert_inference_circuit_verifies(&w, &x, &b, 2, 2);
    }

    #[test]
    fn inference_circuit_rejects_wrong_input_commit() {
        // Honest witness, but pass a wrong public input for input_commit.
        // MockProver should reject.
        let w: Vec<Q16> = vec![Q16::from_int(1), Q16::from_int(2)];
        let x: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(4)];
        let b: Vec<Q16> = vec![Q16::from_int(5)];

        let y_q16 = q16_ops::linear(&w, &x, &b, 1, 2);
        let x_ark: Vec<ArkFr> = x.iter().copied().map(q16_to_ark_fr).collect();
        let model_ark: Vec<ArkFr> = w
            .iter()
            .copied()
            .chain(b.iter().copied())
            .map(q16_to_ark_fr)
            .collect();
        let y_ark: Vec<ArkFr> = y_q16.iter().copied().map(q16_to_ark_fr).collect();
        let _correct_input_commit = ark_fr_to_halo2_fr(&poseidon_hash(&x_ark));
        let model_commit = ark_fr_to_halo2_fr(&poseidon_hash(&model_ark));
        let output_commit = ark_fr_to_halo2_fr(&poseidon_hash(&y_ark));

        // Lie: present a different input_commit value.
        let bogus_input_commit = Halo2Fr::from(0xDEADBEEFu64);

        let weights_fr: Vec<Halo2Fr> = w.iter().copied().map(q16_to_halo2_fr).collect();
        let inputs_fr: Vec<Halo2Fr> = x.iter().copied().map(q16_to_halo2_fr).collect();
        let biases_fr: Vec<Halo2Fr> = b.iter().copied().map(q16_to_halo2_fr).collect();
        let circuit = InferenceCircuit {
            weights: weights_fr.iter().map(|v| Value::known(*v)).collect(),
            inputs: inputs_fr.iter().map(|v| Value::known(*v)).collect(),
            biases: biases_fr.iter().map(|v| Value::known(*v)).collect(),
            out_dim: 1,
            in_dim: 2,
        };
        let public_inputs = vec![vec![bogus_input_commit, model_commit, output_commit]];
        let k = 12;
        let prover = MockProver::run(k, &circuit, public_inputs).expect("setup");
        let r = prover.verify();
        assert!(
            r.is_err(),
            "InferenceCircuit must reject mismatched input_commit"
        );
    }
}
