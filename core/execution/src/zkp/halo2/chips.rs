// citrate/core/execution/src/zkp/halo2/chips.rs
//
// RM-M1b WP-M1b.3 — Halo2 chip implementations (in-progress).
//
// This module is the home for in-circuit gadgets that the
// InferenceCircuit composes. The most important one — and the one
// gating WP-M1b.4's 0x0108 LIVE flip — is the **PoseidonChip**:
// it must produce the same byte-level hash output as the off-chain
// `zkp::poseidon::poseidon_hash`, otherwise commitments computed
// off-chain via 0x0107 TENSOR_COMMIT cannot be referenced inside
// proofs verified by 0x0108 INFERENCE_PROOF_VERIFY.
//
// **Status (2026-04-27):** the differential-test SCAFFOLD is
// shipped here; the actual `PoseidonChip` authoring is owed.
// Reasoning (see WP-M1b.3 partial closure block):
//
// - PSE's `halo2_poseidon` gadget pins to `halo2_proofs` v0.3.0,
//   which predates the v0.4.0 frontend/backend split. Our pin is
//   `198e9ae` (post-v0.4.0). The gadget would need a port to the
//   new API surface before we could consume it.
// - Authoring our own Poseidon-in-circuit is feasible (~64 rounds
//   × 3 state cells; transliteration of `ark-crypto-primitives`'
//   Poseidon parameters into halo2 constraint syntax) but is
//   exactly the kind of cryptographic work that benefits from
//   external review pairing.
// - The differential-test framework below is the critical
//   correctness gate: the moment a real chip lands, plugging it
//   into `assert_in_circuit_matches_off_chain` either passes
//   (chip is sound) or fails (chip is buggy). We are
//   building the test harness so the chip work cannot ship
//   without proving the soundness property.
//
// **Anti-rug carry-forward:** the differential-test function
// below is `#[cfg(test)]` and includes `unimplemented!()` calls
// that explicitly fail until the chip is wired. A future
// contributor who tries to "skip" the differential test will be
// caught by both the test failure and the
// `check_m1b_chip_diff_test_present.py` verifier (to author
// alongside the chip).

#![allow(dead_code, unused_imports)] // until the chip lands

use ark_bls12_381::Fr as ArkFr;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr as Halo2Fr;

use crate::zkp::poseidon::poseidon_hash;

// ---------------------------------------------------------------------------
// Differential-test scaffold.
// ---------------------------------------------------------------------------
//
// Every Halo2 chip that is supposed to be a faithful in-circuit
// reflection of an off-chain primitive ships with a
// "differential test" — running the same input through both the
// off-chain primitive and the in-circuit chip, asserting the
// outputs match byte-for-byte.
//
// For the PoseidonChip (WP-M1b.3 in progress), the asserted
// invariant is:
//
//   for any input vector V of Fr field elements:
//     in_circuit_poseidon(V).bytes() == off_chain_poseidon(V).bytes()
//
// This is the load-bearing soundness property tying 0x0107
// TENSOR_COMMIT (which uses off-chain `poseidon_hash`) to 0x0108
// INFERENCE_PROOF_VERIFY (which will use the in-circuit version
// to recompute the same commitment from witnesses).
//
// **Bridging BLS12-381 ↔ BN254 Fr:** off-chain `poseidon_hash`
// works on `ark_bls12_381::Fr`; the in-circuit version will use
// `halo2curves::bn256::Fr`. These are DIFFERENT fields with
// different moduli. The differential test uses a serialization
// boundary: convert the input vector to canonical bytes, hash
// off-chain (BLS12-381 Fr arithmetic), convert the hash output
// to bytes; convert input vector to BN254 Fr, hash in-circuit
// (BN254 arithmetic), convert in-circuit output to bytes;
// compare bytes.
//
// **NOTE on the curve mismatch:** RM-M1's Poseidon (via
// `zkp::poseidon`) lives on BLS12-381; RM-M1b's Halo2 verifier
// lives on BN254 (per ADR-RM-M1b-1). For 0x0107 commitments to be
// referenceable inside 0x0108 proofs, BOTH paths must agree on
// the same Fr family. Resolution per ADR-RM-M1b-1: 0x0107 will
// migrate to BN254 Fr in WP-M1b.3 (separate task). Until that
// migration lands, the differential test is documented but
// `#[ignore]`-d so it doesn't block CI; the migration WP unsets
// the ignore.
//
// This module documents the resolution path; the actual byte-
// level alignment work belongs to WP-M1b.3 chip authoring.

#[cfg(test)]
pub fn assert_in_circuit_matches_off_chain(_input: &[ArkFr]) {
    // Once the PoseidonChip is authored:
    //   1. compute off-chain hash via `poseidon_hash(input)`
    //   2. serialize input + expected output to bytes
    //   3. instantiate PoseidonCircuit with input
    //   4. MockProver::run + verify
    //   5. extract circuit's hash output cell
    //   6. compare circuit output bytes to off-chain output bytes
    //
    // Today the chip doesn't exist, so this scaffold panics with
    // a discoverable error rather than reporting fake success.
    unimplemented!(
        "PoseidonChip differential test is owed by WP-M1b.3. \
         See zkp/halo2/chips.rs header comment for the migration plan."
    )
}

// ---------------------------------------------------------------------------
// Chip skeletons — shape the InferenceCircuit will compose.
// ---------------------------------------------------------------------------
//
// These are NOT working chips. They define the trait surface and
// a column-allocation skeleton so chip authors have a stable
// starting point. Each `unimplemented!()` in the chip bodies is
// the discoverable "this needs cryptographic content" marker.

/// In-circuit Poseidon hash chip. WP-M1b.3 owns the implementation.
pub struct PoseidonChipConfig {
    /// State cells for the sponge (rate=2 + capacity=1 = 3 cells).
    pub state: [Column<Advice>; 3],
    /// Selector enabling the round constants on a row.
    pub s_round: Selector,
    /// Output column where the squeezed hash lands.
    pub output: Column<Advice>,
}

pub struct PoseidonChip {
    config: PoseidonChipConfig,
}

impl PoseidonChip {
    pub fn configure(_meta: &mut ConstraintSystem<Halo2Fr>) -> PoseidonChipConfig {
        // WP-M1b.3: implement the Poseidon round constants + MDS
        // matrix as halo2 selectors + fixed columns. Match the
        // ark-crypto-primitives parameters used by zkp::poseidon
        // (rate=2, capacity=1, full=8, partial=56, alpha=5,
        // Grain LFSR-derived constants).
        unimplemented!(
            "PoseidonChip::configure is owed by WP-M1b.3. The \
             differential test in this module is the gate."
        )
    }

    pub fn hash(
        &self,
        _layouter: impl Layouter<Halo2Fr>,
        _input: &[Value<Halo2Fr>],
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        unimplemented!(
            "PoseidonChip::hash is owed by WP-M1b.3. Must produce \
             output bytes equal to zkp::poseidon::poseidon_hash on \
             the same input under the BN254 ↔ BLS12-381 alignment \
             documented in ADR-RM-M1b-1."
        )
    }
}

/// In-circuit tensor commitment. Composes PoseidonChip after
/// chunking input bytes 31-at-a-time into Fr field elements. WP-M1b.3.
pub struct TensorCommitChip {
    _poseidon: PoseidonChip,
}

impl TensorCommitChip {
    pub fn commit(
        &self,
        _layouter: impl Layouter<Halo2Fr>,
        _tensor_bytes: &[Value<Halo2Fr>],
    ) -> Result<AssignedCell<Halo2Fr, Halo2Fr>, ErrorFront> {
        unimplemented!(
            "TensorCommitChip::commit is owed by WP-M1b.3. Must \
             produce output bytes equal to \
             precompiles::verify::tensor_commit on the same input."
        )
    }
}

/// In-circuit linear layer (Q16.16 matmul + bias). Lands AFTER
/// RM-M2 ships the off-chain Q16.16 ops (so we have a reference
/// to differential-test against). WP-M1b.3 + RM-M2 dependency.
pub struct LinearChip;

impl LinearChip {
    pub fn linear(
        &self,
        _layouter: impl Layouter<Halo2Fr>,
        _weights: &[Value<Halo2Fr>],
        _input: &[Value<Halo2Fr>],
        _bias: &[Value<Halo2Fr>],
    ) -> Result<Vec<AssignedCell<Halo2Fr, Halo2Fr>>, ErrorFront> {
        unimplemented!(
            "LinearChip::linear is owed by WP-M1b.3 + RM-M2. \
             Must produce output bytes equal to \
             precompiles::q16::ops::linear on the same input."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: the scaffold imports correctly and the
    /// unimplemented!() markers fire as expected.
    #[test]
    #[should_panic(expected = "owed by WP-M1b.3")]
    fn poseidon_chip_unimplemented_marker_fires() {
        let _ = PoseidonChip::configure(&mut ConstraintSystem::<Halo2Fr>::default());
    }

    /// The differential-test scaffold also fires its
    /// unimplemented!() until the chip ships. This catches a
    /// future contributor who tries to "fix" the test by
    /// silencing it instead of authoring the chip.
    #[test]
    #[should_panic(expected = "owed by WP-M1b.3")]
    fn differential_test_unimplemented_marker_fires() {
        assert_in_circuit_matches_off_chain(&[ArkFr::from(0u64)]);
    }
}
