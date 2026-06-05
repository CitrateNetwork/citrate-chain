// citrate/core/execution/tests/porep_proof_verify_e2e.rs
//
// PIN-P1 step (a) — end-to-end integration test for 0x0108
// circuit_version=2 (reduced PoRep) AND the domain separation between
// the inference (v1) and PoRep (v2) verifier paths.
//
// This is the gate that proves:
//   1. A real reduced-PoRep Halo2-KZG proof verifies through 0x0108
//      with circuit_version=2.
//   2. The v1 inference path is UNCHANGED (regression copy of the e2e
//      acceptance test, dispatched through the new version router).
//   3. Domain separation: an inference proof submitted as v2 fails, a
//      PoRep proof submitted as v1 fails, a tampered PoRep public input
//      fails, and an unknown version fails.
//
// Like `inference_proof_verify_e2e.rs`, this file needs the
// `halo2-substrate` feature; the workspace default skips it cleanly.
// Opt in via:
//   cargo test -p citrate-execution --features halo2-substrate \
//     --test porep_proof_verify_e2e

#![cfg(feature = "halo2-substrate")]

use citrate_execution::precompiles::verify::{addresses, execute, gas_costs};
use citrate_execution::precompiles::q16::{ops as q16_ops, Q16};
use citrate_execution::types::Address;
use citrate_execution::zkp::halo2::circuits::InferenceCircuit;
use citrate_execution::zkp::halo2::porep::{self, seal_reduced, PoRepCircuit, SealedReplica};
use citrate_execution::zkp::halo2::{
    CIRCUIT_VERSION_LINEAR_Q16, CIRCUIT_VERSION_POREP_REDUCED, CIRCUIT_VERSION_POST_RESERVED,
};
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

// k for the reduced PoRep circuit — MUST match V2_K in
// `halo2::porep_kzg_artifacts_v2` (k=13) so the prover and the
// precompile-side verifier derive identical VKs.
const POREP_K: u32 = 13;

// ---------------------------------------------------------------------------
// Wire-format + Fr helpers (shared shape with the inference e2e test).
// ---------------------------------------------------------------------------

fn fr_to_be32(x: &Halo2Fr) -> [u8; 32] {
    use halo2curves::ff::PrimeField as _;
    let le_bytes = x.to_repr();
    let le_slice: &[u8] = le_bytes.as_ref();
    let le: [u8; 32] = le_slice.try_into().expect("Fr repr is 32 bytes");
    let mut be = le;
    be.reverse();
    be
}

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

// ---------------------------------------------------------------------------
// v2 PoRep wire builder — the documented ABI from
// `halo2::verify_porep_proof`:
//   | 32B replicaID | 32B cid | 32B sectorIndex
//   | 4B version | 4B chain_id
//   | 32B CommD | 32B CommR | 32B CommC | 32B challengeNonce | 32B epoch
//   | proof_bytes
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_porep_wire(
    sealed: &SealedReplica,
    challenge_index: usize,
    circuit_version: u32,
    chain_id: u32,
    proof_bytes: &[u8],
) -> Vec<u8> {
    let challenge_fr = Halo2Fr::from(challenge_index as u64);
    let mut buf = Vec::with_capacity(32 * 8 + 8 + proof_bytes.len());
    buf.extend_from_slice(&fr_to_be32(&sealed.replica_id));
    buf.extend_from_slice(&fr_to_be32(&sealed.cid));
    buf.extend_from_slice(&fr_to_be32(&sealed.sector_index));
    buf.extend_from_slice(&circuit_version.to_be_bytes());
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&fr_to_be32(&sealed.comm_d));
    buf.extend_from_slice(&fr_to_be32(&sealed.comm_r));
    buf.extend_from_slice(&fr_to_be32(&sealed.comm_c));
    buf.extend_from_slice(&fr_to_be32(&challenge_fr));
    buf.extend_from_slice(&fr_to_be32(&sealed.epoch));
    buf.extend_from_slice(proof_bytes);
    buf
}

/// Seal a reduced replica and produce a real KZG proof for the given
/// challenge index, using the SAME deterministic ParamsKZG seed
/// (`[0x4D; 32]`) and k as `halo2::porep_kzg_artifacts_v2`.
fn generate_porep_proof(challenge_index: usize) -> (SealedReplica, Vec<u8>) {
    let pinner = Halo2Fr::from(0xA11CEu64);
    let sealed = seal_reduced(
        pinner,
        Halo2Fr::from(0xC1Du64), // cid
        Halo2Fr::from(7u64),     // sectorIndex
        Halo2Fr::from(42u64),    // epoch
        [
            Halo2Fr::from(1001u64),
            Halo2Fr::from(2002u64),
            Halo2Fr::from(3003u64),
            Halo2Fr::from(4004u64),
        ],
    );
    let circuit = PoRepCircuit::from_sealed(&sealed, pinner, challenge_index);
    let pis = PoRepCircuit::public_inputs(&sealed, challenge_index);

    // SAME seed + k as the verifier side.
    let mut params_rng = StdRng::from_seed([0x4D; 32]);
    let params = ParamsKZG::<Bn256>::setup(POREP_K, &mut params_rng);
    let vk = keygen_vk(&params, &circuit.without_witnesses()).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &circuit.without_witnesses()).expect("keygen_pk");

    let public_inputs: Vec<Vec<Halo2Fr>> = vec![pis];
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
    (sealed, proof_bytes)
}

// ---------------------------------------------------------------------------
// Inference (v1) proof generator — copied from inference_proof_verify_e2e
// so the regression assertion below is self-contained.
// ---------------------------------------------------------------------------

fn build_inference_wire(
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

fn generate_inference_proof(
    weights: &[Q16],
    inputs: &[Q16],
    biases: &[Q16],
) -> (Halo2Fr, Halo2Fr, Halo2Fr, Vec<u8>) {
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

    let mut params_rng = StdRng::from_seed([0x4D; 32]);
    let params = ParamsKZG::<Bn256>::setup(12, &mut params_rng);
    let vk = keygen_vk(&params, &circuit.without_witnesses()).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &circuit.without_witnesses()).expect("keygen_pk");

    let public_inputs: Vec<Vec<Halo2Fr>> = vec![vec![input_commit, model_commit, output_commit]];
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

// ===========================================================================
// PoRep happy path (v2).
// ===========================================================================

#[test]
fn precompile_0x0108_accepts_valid_porep_proof() {
    for v in 0..porep::N {
        let (sealed, proof_bytes) = generate_porep_proof(v);
        let wire = build_porep_wire(&sealed, v, CIRCUIT_VERSION_POREP_REDUCED, 40204, &proof_bytes);

        let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
        let result = execute(&addr, &wire, 100_000_000)
            .unwrap_or_else(|e| panic!("v2 PoRep verify must not error for challenge {v}: {e}"));

        assert!(result.success, "precompile ran (challenge {v})");
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 1, "PoRep proof must verify (challenge {v})");
        assert!(result.output[..31].iter().all(|&b| b == 0));

        // Gas uses the v2 schedule.
        let expected_gas = gas_costs::POREP_PROOF_VERIFY_BASE
            + gas_costs::POREP_PROOF_VERIFY_PER_BYTE * wire.len() as u64;
        assert_eq!(result.gas_used, expected_gas, "v2 gas schedule (challenge {v})");
    }
}

#[test]
fn precompile_0x0108_rejects_tampered_porep_proof() {
    let v = 2usize;
    let (sealed, mut proof_bytes) = generate_porep_proof(v);
    proof_bytes[0] ^= 0xFF; // flip a proof byte

    let wire = build_porep_wire(&sealed, v, CIRCUIT_VERSION_POREP_REDUCED, 40204, &proof_bytes);
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000).expect("precompile runs");
    assert_eq!(result.output[31], 0, "tampered PoRep proof must be rejected");
}

// ===========================================================================
// REGRESSION — v1 inference path unchanged through the version router.
// ===========================================================================

#[test]
fn precompile_0x0108_v1_inference_unchanged_regression() {
    // Identical witness to inference_proof_verify_e2e::accepts_valid_proof.
    let weights: Vec<Q16> = vec![Q16::from_int(1), Q16::from_int(0)];
    let inputs: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(4)];
    let biases: Vec<Q16> = vec![Q16::from_int(5)];

    let (input_commit, model_commit, output_commit, proof_bytes) =
        generate_inference_proof(&weights, &inputs, &biases);

    let wire = build_inference_wire(
        &input_commit,
        &model_commit,
        &output_commit,
        CIRCUIT_VERSION_LINEAR_Q16,
        40204,
        &proof_bytes,
    );

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000)
        .expect("v1 inference proof must still verify through the dispatcher");

    assert!(result.success);
    assert_eq!(result.output[31], 1, "v1 inference proof verifies (unchanged)");
    assert!(result.output[..31].iter().all(|&b| b == 0));

    // v1 gas formula is byte-for-byte the original inference schedule.
    let expected_gas = gas_costs::INFERENCE_PROOF_VERIFY_BASE
        + gas_costs::INFERENCE_PROOF_VERIFY_PER_BYTE * wire.len() as u64;
    assert_eq!(result.gas_used, expected_gas, "v1 gas schedule unchanged");
}

// ===========================================================================
// DOMAIN SEPARATION — must REJECT cross-circuit submissions.
// ===========================================================================

/// (a) An inference proof submitted as circuit_version=2 must fail.
/// The inference wire has only 3 public commitments + proof; reframed
/// as v2 it either fails the PoRep length gate or, if padded, fails the
/// PoRep VK (8 public inputs, different key).
#[test]
fn domain_sep_inference_proof_as_v2_rejected() {
    let weights: Vec<Q16> = vec![Q16::from_int(1), Q16::from_int(0)];
    let inputs: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(4)];
    let biases: Vec<Q16> = vec![Q16::from_int(5)];
    let (input_commit, model_commit, output_commit, proof_bytes) =
        generate_inference_proof(&weights, &inputs, &biases);

    // Take the inference proof + commitments but stamp circuit_version=2
    // and pad the body to the PoRep header length so the version router
    // sends it down the PoRep path (rather than failing on length alone).
    // The PoRep VK then rejects: an inference proof transcript cannot
    // satisfy the 8-public-input PoRep circuit.
    let mut wire = Vec::new();
    wire.extend_from_slice(&fr_to_be32(&input_commit)); // replicaID slot
    wire.extend_from_slice(&fr_to_be32(&model_commit)); // cid slot
    wire.extend_from_slice(&fr_to_be32(&output_commit)); // sectorIndex slot
    wire.extend_from_slice(&CIRCUIT_VERSION_POREP_REDUCED.to_be_bytes());
    wire.extend_from_slice(&40204u32.to_be_bytes());
    // Five more 32B field elements (CommD..epoch) — use the inference
    // commitments as filler; challengeNonce kept in 0..N so the router
    // does not reject it on range.
    wire.extend_from_slice(&fr_to_be32(&input_commit)); // CommD
    wire.extend_from_slice(&fr_to_be32(&model_commit)); // CommR
    wire.extend_from_slice(&fr_to_be32(&output_commit)); // CommC
    wire.extend_from_slice(&fr_to_be32(&Halo2Fr::from(0u64))); // challengeNonce=0
    wire.extend_from_slice(&fr_to_be32(&Halo2Fr::from(42u64))); // epoch
    wire.extend_from_slice(&proof_bytes);

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000);
    // Either a cryptographic 0 (proof ran, rejected) or a structured Err
    // (malformed transcript) — both are correct rejections; what must
    // NOT happen is a verifying `1`.
    match result {
        Ok(r) => assert_eq!(
            r.output[31], 0,
            "inference proof framed as v2 must NOT verify against the PoRep VK"
        ),
        Err(_) => { /* structured rejection is also acceptable */ }
    }
}

/// (b) A PoRep proof submitted as circuit_version=1 must fail. The
/// PoRep wire reframed as v1 is parsed against the 3-commitment
/// inference layout and verified with the inference VK — it cannot
/// satisfy it.
#[test]
fn domain_sep_porep_proof_as_v1_rejected() {
    let v = 1usize;
    let (sealed, proof_bytes) = generate_porep_proof(v);

    // Build a v1-shaped wire: 3 commitments (reuse PoRep public fields in
    // the first 3 slots), circuit_version=1, then the PoRep proof bytes.
    let wire = build_inference_wire(
        &sealed.replica_id,
        &sealed.cid,
        &sealed.sector_index,
        CIRCUIT_VERSION_LINEAR_Q16,
        40204,
        &proof_bytes,
    );

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000);
    match result {
        Ok(r) => assert_eq!(
            r.output[31], 0,
            "PoRep proof framed as v1 must NOT verify against the inference VK"
        ),
        Err(_) => { /* structured rejection is also acceptable */ }
    }
}

/// (c) A valid PoRep proof with a TAMPERED public input must fail.
/// Flip the CommR public input on the wire; the proof was bound to the
/// honest CommR, so the verifier rejects.
#[test]
fn domain_sep_porep_tampered_public_input_rejected() {
    let v = 0usize;
    let (mut sealed, proof_bytes) = generate_porep_proof(v);
    // Tamper CommR (one of the 8 public inputs).
    sealed.comm_r += Halo2Fr::from(1u64);

    let wire = build_porep_wire(&sealed, v, CIRCUIT_VERSION_POREP_REDUCED, 40204, &proof_bytes);
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000).expect("precompile runs");
    assert_eq!(
        result.output[31], 0,
        "PoRep proof with a tampered public input (CommR) must be rejected"
    );
}

/// (d) Unknown circuit_version (including the reserved-but-unimplemented
/// PoSt v3) must error — unchanged behavior.
#[test]
fn domain_sep_unknown_and_reserved_versions_rejected() {
    let v = 0usize;
    let (sealed, proof_bytes) = generate_porep_proof(v);
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);

    for bad_version in [CIRCUIT_VERSION_POST_RESERVED, 4u32, 999u32, u32::MAX] {
        let wire = build_porep_wire(&sealed, v, bad_version, 40204, &proof_bytes);
        let result = execute(&addr, &wire, 100_000_000);
        assert!(
            result.is_err(),
            "circuit_version {bad_version} must be rejected (no VK registered)"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("UnknownCircuitVersion") || err.contains("circuit_version"),
            "error must name the version problem for v{bad_version}: {err}"
        );
    }
}

/// Out-of-range challengeNonce (≥ N) must be rejected even with v2 —
/// there is no honest circuit/VK for it.
#[test]
fn precompile_0x0108_rejects_out_of_range_challenge_nonce() {
    let v = 0usize;
    let (sealed, proof_bytes) = generate_porep_proof(v);
    // Claim challenge index N (out of range) on the wire.
    let wire = build_porep_wire(&sealed, porep::N, CIRCUIT_VERSION_POREP_REDUCED, 40204, &proof_bytes);
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000);
    assert!(
        result.is_err(),
        "challengeNonce ≥ N must be rejected before VK lookup"
    );
}
