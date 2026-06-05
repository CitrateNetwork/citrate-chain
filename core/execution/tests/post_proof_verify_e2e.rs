// citrate/core/execution/tests/post_proof_verify_e2e.rs
//
// PIN-P1 step (b) — end-to-end integration test for 0x0108
// circuit_version=3 (reduced PoSt) AND the domain separation between the
// inference (v1), PoRep (v2), and PoSt (v3) verifier paths.
//
// This is the gate that proves:
//   1. A real reduced-PoSt Halo2-KZG proof verifies through 0x0108 with
//      circuit_version=3, for every challenge index (0..N).
//   2. The v3 gas schedule (POST_PROOF_VERIFY_*) is applied.
//   3. Domain separation: a PoSt proof submitted as v1 or v2 fails, a
//      PoRep proof submitted as v3 fails, an inference proof submitted as
//      v3 fails, and a tampered PoSt public input fails.
//   4. A tampered PoSt proof and an out-of-range challengeNonce fail.
//
// The v1 inference and v2 PoRep regression coverage lives in
// `inference_proof_verify_e2e.rs` and `porep_proof_verify_e2e.rs`; this
// file is purely the additive v3 surface + the v3↔v1/v2 separation. It
// needs the `halo2-substrate` feature; the workspace default skips it.
//   cargo test -p citrate-execution --features halo2-substrate \
//     --test post_proof_verify_e2e

#![cfg(feature = "halo2-substrate")]

use citrate_execution::precompiles::verify::{addresses, execute, gas_costs};
use citrate_execution::types::Address;
use citrate_execution::zkp::halo2::porep::{self, seal_reduced, PoRepCircuit, SealedReplica};
use citrate_execution::zkp::halo2::post::PoStCircuit;
use citrate_execution::zkp::halo2::{
    CIRCUIT_VERSION_LINEAR_Q16, CIRCUIT_VERSION_POREP_REDUCED, CIRCUIT_VERSION_POST,
};

use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, Circuit};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::ProverSHPLONK;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
use halo2curves::bn256::{Bn256, Fr as Halo2Fr, G1Affine};
use rand::rngs::StdRng;
use rand::SeedableRng;

// k for the reduced PoSt circuit — MUST match V3_K in
// `halo2::post_kzg_artifacts_v3` (k=13) so the prover and the
// precompile-side verifier derive identical VKs.
const POST_K: u32 = 13;

// ---------------------------------------------------------------------------
// Fr / wire-format helpers.
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

// v3 PoSt wire builder — the documented ABI from `halo2::verify_post_proof`:
//   | 32B replicaID | 32B cid | 32B sectorIndex
//   | 4B version | 4B chain_id
//   | 32B CommR | 32B CommC | 32B challengeNonce | 32B epoch
//   | proof_bytes
// NOTE: NO CommD — that is the v2/v3 structural difference.
fn build_post_wire(
    sealed: &SealedReplica,
    challenge_index: usize,
    circuit_version: u32,
    chain_id: u32,
    proof_bytes: &[u8],
) -> Vec<u8> {
    let challenge_fr = Halo2Fr::from(challenge_index as u64);
    let mut buf = Vec::with_capacity(32 * 7 + 8 + proof_bytes.len());
    buf.extend_from_slice(&fr_to_be32(&sealed.replica_id));
    buf.extend_from_slice(&fr_to_be32(&sealed.cid));
    buf.extend_from_slice(&fr_to_be32(&sealed.sector_index));
    buf.extend_from_slice(&circuit_version.to_be_bytes());
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&fr_to_be32(&sealed.comm_r));
    buf.extend_from_slice(&fr_to_be32(&sealed.comm_c));
    buf.extend_from_slice(&fr_to_be32(&challenge_fr));
    buf.extend_from_slice(&fr_to_be32(&sealed.epoch));
    buf.extend_from_slice(proof_bytes);
    buf
}

/// Seal a reduced replica and produce a real KZG PoSt proof for the given
/// challenge index, using the SAME deterministic ParamsKZG seed
/// (`[0x4D; 32]`) and k as `halo2::post_kzg_artifacts_v3`.
fn generate_post_proof(challenge_index: usize) -> (SealedReplica, Vec<u8>) {
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
    let circuit = PoStCircuit::from_sealed(&sealed, pinner, challenge_index);
    let pis = PoStCircuit::public_inputs(&sealed, challenge_index);

    // SAME seed + k as the verifier side.
    let mut params_rng = StdRng::from_seed([0x4D; 32]);
    let params = ParamsKZG::<Bn256>::setup(POST_K, &mut params_rng);
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

/// Produce a real v2 PoRep proof + its sealed replica (for the
/// PoRep-as-v3 domain-separation test). Mirrors the v2 e2e generator.
fn generate_porep_proof(challenge_index: usize) -> (SealedReplica, Vec<u8>) {
    let pinner = Halo2Fr::from(0xA11CEu64);
    let sealed = seal_reduced(
        pinner,
        Halo2Fr::from(0xC1Du64),
        Halo2Fr::from(7u64),
        Halo2Fr::from(42u64),
        [
            Halo2Fr::from(1001u64),
            Halo2Fr::from(2002u64),
            Halo2Fr::from(3003u64),
            Halo2Fr::from(4004u64),
        ],
    );
    let circuit = PoRepCircuit::from_sealed(&sealed, pinner, challenge_index);
    let pis = PoRepCircuit::public_inputs(&sealed, challenge_index);

    let mut params_rng = StdRng::from_seed([0x4D; 32]);
    let params = ParamsKZG::<Bn256>::setup(13, &mut params_rng);
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
    (sealed, transcript.finalize())
}

// ===========================================================================
// PoSt happy path (v3) — all challenge indices.
// ===========================================================================

#[test]
fn precompile_0x0108_accepts_valid_post_proof() {
    for v in 0..porep::N {
        let (sealed, proof_bytes) = generate_post_proof(v);
        let wire = build_post_wire(&sealed, v, CIRCUIT_VERSION_POST, 40204, &proof_bytes);

        let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
        let result = execute(&addr, &wire, 100_000_000)
            .unwrap_or_else(|e| panic!("v3 PoSt verify must not error for challenge {v}: {e}"));

        assert!(result.success, "precompile ran (challenge {v})");
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 1, "PoSt proof must verify (challenge {v})");
        assert!(result.output[..31].iter().all(|&b| b == 0));

        // Gas uses the v3 schedule.
        let expected_gas = gas_costs::POST_PROOF_VERIFY_BASE
            + gas_costs::POST_PROOF_VERIFY_PER_BYTE * wire.len() as u64;
        assert_eq!(result.gas_used, expected_gas, "v3 gas schedule (challenge {v})");
    }
}

#[test]
fn precompile_0x0108_rejects_tampered_post_proof() {
    let v = 2usize;
    let (sealed, mut proof_bytes) = generate_post_proof(v);
    proof_bytes[0] ^= 0xFF; // flip a proof byte

    let wire = build_post_wire(&sealed, v, CIRCUIT_VERSION_POST, 40204, &proof_bytes);
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000).expect("precompile runs");
    assert_eq!(result.output[31], 0, "tampered PoSt proof must be rejected");
}

#[test]
fn precompile_0x0108_rejects_tampered_post_public_input() {
    let v = 0usize;
    let (mut sealed, proof_bytes) = generate_post_proof(v);
    // Tamper CommR (one of the 7 public inputs).
    sealed.comm_r += Halo2Fr::from(1u64);

    let wire = build_post_wire(&sealed, v, CIRCUIT_VERSION_POST, 40204, &proof_bytes);
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000).expect("precompile runs");
    assert_eq!(
        result.output[31], 0,
        "PoSt proof with a tampered public input (CommR) must be rejected"
    );
}

#[test]
fn precompile_0x0108_rejects_out_of_range_post_challenge_nonce() {
    let v = 0usize;
    let (sealed, proof_bytes) = generate_post_proof(v);
    // Claim challenge index N (out of range) on the wire.
    let wire = build_post_wire(&sealed, porep::N, CIRCUIT_VERSION_POST, 40204, &proof_bytes);
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000);
    assert!(
        result.is_err(),
        "PoSt challengeNonce ≥ N must be rejected before VK lookup"
    );
}

// ===========================================================================
// DOMAIN SEPARATION — must REJECT cross-circuit submissions.
// ===========================================================================

/// A PoSt proof submitted as circuit_version=1 (inference) must fail: the
/// PoSt wire reframed as v1 is parsed against the 3-commitment inference
/// layout and verified with the inference VK — it cannot satisfy it.
#[test]
fn domain_sep_post_proof_as_v1_rejected() {
    let v = 1usize;
    let (sealed, proof_bytes) = generate_post_proof(v);

    // v1-shaped wire: 3 commitments + version=1 + chain_id + proof.
    let mut wire = Vec::new();
    wire.extend_from_slice(&fr_to_be32(&sealed.replica_id));
    wire.extend_from_slice(&fr_to_be32(&sealed.cid));
    wire.extend_from_slice(&fr_to_be32(&sealed.sector_index));
    wire.extend_from_slice(&CIRCUIT_VERSION_LINEAR_Q16.to_be_bytes());
    wire.extend_from_slice(&40204u32.to_be_bytes());
    wire.extend_from_slice(&proof_bytes);

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000);
    match result {
        Ok(r) => assert_eq!(
            r.output[31], 0,
            "PoSt proof framed as v1 must NOT verify against the inference VK"
        ),
        Err(_) => { /* structured rejection is also acceptable */ }
    }
}

/// A PoSt proof submitted as circuit_version=2 (PoRep) must fail: the
/// PoRep verifier expects 8 public inputs (with CommD) and a different VK;
/// a 7-input PoSt proof cannot satisfy it. We frame the PoSt fields into a
/// v2 wire (CommD filled with CommR as filler, challengeNonce kept in
/// range) so the router sends it down the PoRep path, where the PoRep VK
/// rejects it.
#[test]
fn domain_sep_post_proof_as_v2_rejected() {
    let v = 1usize;
    let (sealed, proof_bytes) = generate_post_proof(v);

    let mut wire = Vec::new();
    wire.extend_from_slice(&fr_to_be32(&sealed.replica_id));
    wire.extend_from_slice(&fr_to_be32(&sealed.cid));
    wire.extend_from_slice(&fr_to_be32(&sealed.sector_index));
    wire.extend_from_slice(&CIRCUIT_VERSION_POREP_REDUCED.to_be_bytes());
    wire.extend_from_slice(&40204u32.to_be_bytes());
    wire.extend_from_slice(&fr_to_be32(&sealed.comm_r)); // CommD slot (filler)
    wire.extend_from_slice(&fr_to_be32(&sealed.comm_r)); // CommR
    wire.extend_from_slice(&fr_to_be32(&sealed.comm_c)); // CommC
    wire.extend_from_slice(&fr_to_be32(&Halo2Fr::from(v as u64))); // challengeNonce
    wire.extend_from_slice(&fr_to_be32(&sealed.epoch)); // epoch
    wire.extend_from_slice(&proof_bytes);

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000);
    match result {
        Ok(r) => assert_eq!(
            r.output[31], 0,
            "PoSt proof framed as v2 must NOT verify against the PoRep VK"
        ),
        Err(_) => { /* structured rejection (e.g. transcript) is acceptable */ }
    }
}

/// A PoRep proof submitted as circuit_version=3 (PoSt) must fail: routed
/// to the PoSt verifier (7-input ABI, different VK), a PoRep proof cannot
/// satisfy it. We frame the PoRep fields into a v3 wire (drop CommD).
#[test]
fn domain_sep_porep_proof_as_v3_rejected() {
    let v = 1usize;
    let (sealed, proof_bytes) = generate_porep_proof(v);

    // v3-shaped wire from the PoRep sealed replica (CommR/CommC carried,
    // CommD dropped per the PoSt ABI).
    let wire = build_post_wire(&sealed, v, CIRCUIT_VERSION_POST, 40204, &proof_bytes);

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000);
    match result {
        Ok(r) => assert_eq!(
            r.output[31], 0,
            "PoRep proof framed as v3 must NOT verify against the PoSt VK"
        ),
        Err(_) => { /* structured rejection is also acceptable */ }
    }
}

/// An inference proof submitted as circuit_version=3 (PoSt) must fail:
/// the inference transcript cannot satisfy the 7-input PoSt circuit. The
/// inference wire is shorter than the PoSt header, so this typically fails
/// on the PoSt length gate — also a correct rejection.
#[test]
fn domain_sep_inference_proof_as_v3_rejected() {
    // A minimal inference-shaped body: 3 commitments + version=3 + chain.
    // We don't need a *valid* inference proof — any bytes stamped v3 that
    // reach the PoSt path must not verify. Pad to the PoSt header length so
    // the router commits to the PoSt layout rather than only rejecting on
    // a too-short input (we want to exercise the PoSt VK rejection too).
    let filler = Halo2Fr::from(123u64);
    let mut wire = Vec::new();
    wire.extend_from_slice(&fr_to_be32(&filler)); // replicaID
    wire.extend_from_slice(&fr_to_be32(&filler)); // cid
    wire.extend_from_slice(&fr_to_be32(&filler)); // sectorIndex
    wire.extend_from_slice(&CIRCUIT_VERSION_POST.to_be_bytes());
    wire.extend_from_slice(&40204u32.to_be_bytes());
    wire.extend_from_slice(&fr_to_be32(&filler)); // CommR
    wire.extend_from_slice(&fr_to_be32(&filler)); // CommC
    wire.extend_from_slice(&fr_to_be32(&Halo2Fr::from(0u64))); // challengeNonce=0
    wire.extend_from_slice(&fr_to_be32(&filler)); // epoch
    // A short, bogus "proof" body — not a real inference transcript.
    wire.extend_from_slice(&[0u8; 192]);

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000);
    match result {
        Ok(r) => assert_eq!(
            r.output[31], 0,
            "an inference-shaped proof framed as v3 must NOT verify against the PoSt VK"
        ),
        Err(_) => { /* malformed-transcript rejection is also acceptable */ }
    }
}
