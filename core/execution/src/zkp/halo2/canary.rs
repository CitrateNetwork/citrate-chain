// citrate/core/execution/src/zkp/halo2/canary.rs
//
// **Build-chain canary circuit.** RM-M1b WP-M1b.1.
//
// The simplest non-trivial Halo2 circuit: prove that
// `out = 2 * a` where `a` is a public input and `out` is a
// computed private witness. Single row, single advice column,
// single selector, one custom gate.
//
// This circuit's only job is to **prove the dep chain works
// end-to-end**: halo2_proofs and halo2curves compile, the
// MockProver runs, the constraint system synthesizes, the proof
// verifies on the happy path and rejects on a tampered witness.
// Production circuits (the InferenceCircuit shipping in
// WP-M1b.3) follow the same trait surface but have many more
// columns, gates, and chips.
//
// Why use the bn256 field here, not Pasta: KZG over BN254 is the
// substrate per ADR-RM-M1b-1. Pinning the canary to bn256::Fr
// catches any "Cargo resolved a different curve" surprises.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, ErrorFront, Fixed,
        Instance, Selector,
    },
    poly::Rotation,
};
use halo2curves::bn256::Fr;

/// Configuration for the doubling circuit.
#[derive(Clone, Debug)]
pub struct DoublingConfig {
    /// Two advice columns. `advice[0]` carries the public input
    /// `a`; `advice[1]` carries the doubled output `out = 2a`.
    advice: [Column<Advice>; 2],
    /// Public-input column where we expose `a` and `out`.
    instance: Column<Instance>,
    /// Selector enabling the doubling gate on a row.
    s_double: Selector,
    /// Fixed column required by `enable_constant` for `Layouter`
    /// constant-region machinery; never written by this canary.
    _constant: Column<Fixed>,
}

/// The canary circuit. Witness is just `a`; the synthesizer
/// computes `out = 2a` and constrains it.
#[derive(Default, Clone, Copy)]
pub struct DoublingCircuit {
    pub a: Value<Fr>,
}

impl Circuit<Fr> for DoublingCircuit {
    type Config = DoublingConfig;
    type FloorPlanner = SimpleFloorPlanner;

    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        meta.enable_equality(instance);
        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);
        meta.enable_constant(constant);

        let s_double = meta.selector();

        meta.create_gate("double", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let out = meta.query_advice(advice[1], Rotation::cur());
            let s = meta.query_selector(s_double);
            // out - 2*a = 0  ⇔  out = 2a
            // Multiplication-by-constant is realized as a + a.
            vec![s * (out - (a.clone() + a))]
        });

        DoublingConfig {
            advice,
            instance,
            s_double,
            _constant: constant,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), ErrorFront> {
        // Single region: assign `a` and `out` on row 0, enable
        // the doubling selector. Then expose both as public
        // instances for the verifier to constrain.
        let (a_cell, out_cell): (
            AssignedCell<Fr, Fr>,
            AssignedCell<Fr, Fr>,
        ) = layouter.assign_region(
            || "double",
            |mut region| {
                config.s_double.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(
                    || "a",
                    config.advice[0],
                    0,
                    || self.a,
                )?;

                let two = Fr::from(2u64);
                let out_value = self.a.map(|v| v * two);
                let out_cell = region.assign_advice(
                    || "out = 2a",
                    config.advice[1],
                    0,
                    || out_value,
                )?;

                Ok((a_cell, out_cell))
            },
        )?;

        // Public-input slot 0 = `a`; slot 1 = `out`.
        layouter.constrain_instance(a_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(out_cell.cell(), config.instance, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    /// Smallest k such that the constraint system fits. The default
    /// blinding-factor floor for halo2 is 6 rows; we use 1 row so
    /// k=3 (8 rows) is the smallest power-of-two that accommodates
    /// the gate + blinding rows. We use k=4 for headroom.
    const K: u32 = 4;

    #[test]
    fn canary_valid_witness_verifies() {
        // a = 21, out should be 42.
        let a = Fr::from(21u64);
        let two_a = Fr::from(42u64);

        let circuit = DoublingCircuit { a: Value::known(a) };
        let public_inputs = vec![vec![a, two_a]];

        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert_eq!(
            prover.verify(),
            Ok(()),
            "valid witness must verify; canary build-chain check"
        );
    }

    #[test]
    fn canary_tampered_public_input_rejects() {
        // Same circuit, but the verifier is told `out = 43` (off
        // by one). Must reject.
        let a = Fr::from(21u64);
        let bad_out = Fr::from(43u64); // not 2 * 21

        let circuit = DoublingCircuit { a: Value::known(a) };
        let public_inputs = vec![vec![a, bad_out]];

        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        let r = prover.verify();
        assert!(
            r.is_err(),
            "tampered public input must reject; got {:?}",
            r
        );
    }

    #[test]
    fn canary_zero_input_verifies() {
        // Edge case: 2 * 0 = 0.
        let a = Fr::ZERO;

        let circuit = DoublingCircuit { a: Value::known(a) };
        let public_inputs = vec![vec![a, a]];

        let prover = MockProver::run(K, &circuit, public_inputs).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
