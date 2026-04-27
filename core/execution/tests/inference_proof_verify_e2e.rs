// citrate_v0.01.1/core/execution/tests/inference_proof_verify_e2e.rs
//
// RM-M1b WP-M1b.4 — end-to-end integration test for 0x0108
// INFERENCE_PROOF_VERIFY.
//
// This is the gate that proves the precompile is LIVE: generate a
// real Halo2-KZG proof against the v1 InferenceCircuit, build the
// wire format the precompile expects, call the precompile via the
// `precompiles::verify::execute` dispatcher, and assert the
// returned bool == 1.
//
// **Why a separate test file:** the test needs the
// `halo2-substrate` feature, which the workspace default does not
// enable. By placing it here, `cargo test -p citrate-execution`
// (default features) skips it cleanly; opt in via
// `cargo test -p citrate-execution --features halo2-substrate
// --test inference_proof_verify_e2e`.
//
// **Anti-rug:** if this test fails or is removed before mainnet,
// 0x0108 is NOT actually live — only the call dispatcher is. The
// CI verifier `check_m1_verification_precompiles.py` requires this
// test to be present.

#![cfg(feature = "halo2-substrate")]

use citrate_execution::precompiles::verify::{addresses, execute, gas_costs};
use citrate_execution::precompiles::q16::{ops as q16_ops, Q16};
use citrate_execution::types::Address;
use citrate_execution::zkp::halo2::circuits::InferenceCircuit;
use citrate_execution::zkp::halo2::CIRCUIT_VERSION_LINEAR_Q16;
use citrate_execution::zkp::poseidon_bn254::poseidon_hash;

use ark_bn254::Fr as ArkFr;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, Circuit};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::ProverSHPLONK;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
use halo2curves::bn256::{Bn256, Fr as Halo2Fr, G1Affine};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn q16_to_ark_fr(q: Q16) -> ArkFr {
    if q.0 >= 0 {
        ArkFr::from(q.0 as u64)
    } else {
        -ArkFr::from((q.0 as i64).unsigned_abs())
    }
}

fn q16_to_halo2_fr(q: Q16) -> Halo2Fr {
    let v64 = q.0 as i64;
    if v64 >= 0 {
        Halo2Fr::from(v64 as u64)
    } else {
        -Halo2Fr::from((-v64) as u64)
    }
}

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

/// Halo2 Fr → 32-byte big-endian (matches the wire format expected by
/// 0x0108 and the output format of 0x0107).
fn fr_to_be32(x: &Halo2Fr) -> [u8; 32] {
    use halo2curves::ff::PrimeField as _;
    let le_bytes = x.to_repr();
    let le_slice: &[u8] = le_bytes.as_ref();
    let le: [u8; 32] = le_slice.try_into().expect("Fr repr is 32 bytes");
    let mut be = le;
    be.reverse();
    be
}

/// Build the on-wire input for 0x0108 from commitments + circuit_version
/// + chain_id + proof_bytes.
fn build_wire_input(
    input_commit: &Halo2Fr,
    model_commit: &Halo2Fr,
    output_commit: &Halo2Fr,
    circuit_version: u32,
    chain_id: u32,
    proof_bytes: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 * 3 + 4 + 4 + proof_bytes.len());
    buf.extend_from_slice(&fr_to_be32(input_commit));
    buf.extend_from_slice(&fr_to_be32(model_commit));
    buf.extend_from_slice(&fr_to_be32(output_commit));
    buf.extend_from_slice(&circuit_version.to_be_bytes());
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(proof_bytes);
    buf
}

/// Generate a real Halo2-KZG proof for the v1 InferenceCircuit using
/// THE SAME ParamsKZG seed that `halo2::inference_kzg_artifacts_v1`
/// uses on the verifier side. Returns (commitments, proof_bytes).
fn generate_inference_proof(
    weights: &[Q16],
    inputs: &[Q16],
    biases: &[Q16],
) -> (Halo2Fr, Halo2Fr, Halo2Fr, Vec<u8>) {
    // 1. Off-chain: compute y and the three commitments.
    let y_q16 = q16_ops::linear(weights, inputs, biases, 1, 2);
    let x_ark: Vec<ArkFr> = inputs.iter().copied().map(q16_to_ark_fr).collect();
    let model_ark: Vec<ArkFr> = weights
        .iter()
        .copied()
        .chain(biases.iter().copied())
        .map(q16_to_ark_fr)
        .collect();
    let y_ark: Vec<ArkFr> = y_q16.iter().copied().map(q16_to_ark_fr).collect();
    let input_commit = ark_fr_to_halo2_fr(&poseidon_hash(&x_ark));
    let model_commit = ark_fr_to_halo2_fr(&poseidon_hash(&model_ark));
    let output_commit = ark_fr_to_halo2_fr(&poseidon_hash(&y_ark));

    // 2. Build circuit witness.
    let weights_fr: Vec<Halo2Fr> = weights.iter().copied().map(q16_to_halo2_fr).collect();
    let inputs_fr: Vec<Halo2Fr> = inputs.iter().copied().map(q16_to_halo2_fr).collect();
    let biases_fr: Vec<Halo2Fr> = biases.iter().copied().map(q16_to_halo2_fr).collect();
    let circuit = InferenceCircuit {
        weights: weights_fr.iter().map(|v| Value::known(*v)).collect(),
        inputs: inputs_fr.iter().map(|v| Value::known(*v)).collect(),
        biases: biases_fr.iter().map(|v| Value::known(*v)).collect(),
        out_dim: 1,
        in_dim: 2,
    };

    // 3. Use the SAME deterministic ParamsKZG seed as the verifier.
    //    (See halo2/mod.rs::inference_kzg_artifacts_v1.)
    let mut params_rng = StdRng::from_seed([0x4D; 32]);
    let params = ParamsKZG::<Bn256>::setup(12, &mut params_rng);

    // 4. Keygen: VK and PK.
    let vk = keygen_vk(&params, &circuit.without_witnesses()).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &circuit.without_witnesses())
        .expect("keygen_pk");

    // 5. Prove.
    let public_inputs: Vec<Vec<Halo2Fr>> =
        vec![vec![input_commit, model_commit, output_commit]];
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    let prover_rng = StdRng::from_seed([0xAB; 32]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[public_inputs],
        prover_rng,
        &mut transcript,
    )
    .expect("create_proof");
    let proof_bytes = transcript.finalize();

    (input_commit, model_commit, output_commit, proof_bytes)
}

#[test]
fn precompile_0x0108_accepts_valid_proof() {
    // Witness: y[0] = 1*3 + 0*4 + 5 = 8.
    let weights: Vec<Q16> = vec![Q16::from_int(1), Q16::from_int(0)];
    let inputs: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(4)];
    let biases: Vec<Q16> = vec![Q16::from_int(5)];

    let (input_commit, model_commit, output_commit, proof_bytes) =
        generate_inference_proof(&weights, &inputs, &biases);

    let wire = build_wire_input(
        &input_commit,
        &model_commit,
        &output_commit,
        CIRCUIT_VERSION_LINEAR_Q16,
        40204, // chain_id (advisory in v1)
        &proof_bytes,
    );

    // Call 0x0108 via the verify::execute dispatcher.
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000)
        .expect("INFERENCE_PROOF_VERIFY must not error on a valid proof");

    assert!(result.success, "precompile reports success");
    assert_eq!(result.output.len(), 32, "32-byte big-endian output");
    assert_eq!(result.output[31], 1, "verifier returned 1 (proof valid)");
    assert!(
        result.output[..31].iter().all(|&b| b == 0),
        "high 31 bytes are zero (only LSB carries the bool)"
    );

    // Sanity: gas matches the formula.
    let expected_gas = gas_costs::INFERENCE_PROOF_VERIFY_BASE
        + gas_costs::INFERENCE_PROOF_VERIFY_PER_BYTE * wire.len() as u64;
    assert_eq!(result.gas_used, expected_gas);
}

#[test]
fn precompile_0x0108_rejects_tampered_proof() {
    let weights: Vec<Q16> = vec![Q16::from_int(2), Q16::from_int(-1)];
    let inputs: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(5)];
    let biases: Vec<Q16> = vec![Q16::ZERO];

    let (input_commit, model_commit, output_commit, mut proof_bytes) =
        generate_inference_proof(&weights, &inputs, &biases);

    // Flip a byte in the proof.
    proof_bytes[0] ^= 0xFF;

    let wire = build_wire_input(
        &input_commit,
        &model_commit,
        &output_commit,
        CIRCUIT_VERSION_LINEAR_Q16,
        40204,
        &proof_bytes,
    );

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000)
        .expect("precompile must run (return value carries verdict)");

    assert!(result.success, "precompile reports it ran");
    assert_eq!(result.output.len(), 32);
    assert_eq!(
        result.output[31], 0,
        "tampered proof must be rejected (verifier returned 0)"
    );
}

#[test]
fn precompile_0x0108_rejects_wrong_commitment() {
    let weights: Vec<Q16> = vec![Q16::from_int(1), Q16::from_int(0)];
    let inputs: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(4)];
    let biases: Vec<Q16> = vec![Q16::from_int(5)];

    let (_input_commit, model_commit, output_commit, proof_bytes) =
        generate_inference_proof(&weights, &inputs, &biases);

    // Lie about input_commit — present a bogus value.
    let bogus_input_commit = Halo2Fr::from(0xDEADBEEFu64);

    let wire = build_wire_input(
        &bogus_input_commit,
        &model_commit,
        &output_commit,
        CIRCUIT_VERSION_LINEAR_Q16,
        40204,
        &proof_bytes,
    );

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000)
        .expect("precompile must run");

    assert_eq!(
        result.output[31], 0,
        "wrong input_commit must be rejected"
    );
}

#[test]
fn precompile_0x0108_rejects_truncated_input() {
    // Wire format header is 104 bytes; anything shorter must error.
    let truncated = vec![0u8; 50];
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &truncated, 100_000_000);
    assert!(result.is_err(), "truncated wire format must error");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Truncated") || err.contains("INFERENCE_PROOF_VERIFY"),
        "error message must indicate the failure reason: {err}"
    );
}

#[test]
fn precompile_0x0108_rejects_unknown_circuit_version() {
    let weights: Vec<Q16> = vec![Q16::from_int(1), Q16::from_int(0)];
    let inputs: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(4)];
    let biases: Vec<Q16> = vec![Q16::from_int(5)];

    let (input_commit, model_commit, output_commit, proof_bytes) =
        generate_inference_proof(&weights, &inputs, &biases);

    // Wrong circuit_version (v999 — not registered).
    let wire = build_wire_input(
        &input_commit,
        &model_commit,
        &output_commit,
        999,
        40204,
        &proof_bytes,
    );

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000);
    assert!(result.is_err(), "unknown circuit_version must error");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("UnknownCircuitVersion") || err.contains("circuit_version"),
        "error message must mention the version mismatch: {err}"
    );
}

#[test]
fn precompile_0x0108_insufficient_gas() {
    let wire = vec![0u8; 200]; // header + 100 bytes "proof" placeholder
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    // Provide far less than INFERENCE_PROOF_VERIFY_BASE.
    let result = execute(&addr, &wire, 1_000);
    assert!(result.is_err(), "insufficient gas must error");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Insufficient gas"),
        "error message must indicate gas: {err}"
    );
}
