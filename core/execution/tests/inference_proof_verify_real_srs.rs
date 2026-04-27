// citrate_v0.01.1/core/execution/tests/inference_proof_verify_real_srs.rs
//
// RM-M1b WP-M1b.7 — end-to-end integration test for 0x0108 using the
// REAL PPoT k=18 .ptau-derived ParamsKZG.
//
// **Distinction from `inference_proof_verify_e2e.rs`:** that file
// uses the deterministic-seed-based fallback ParamsKZG (dev/test
// path). This file sets `CITRATE_PTAU_PATH` and goes through the
// production code path: hash-verify the .ptau, parse it, construct
// ParamsKZG via `from_parts`, keygen VK against InferenceCircuit,
// generate proof, verify proof.
//
// **Why a separate test binary:** the OnceLock-cached
// `inference_kzg_artifacts_v1()` initializes once per process. The
// other e2e file initializes from the seed; this file initializes
// from the .ptau. Sharing a binary would let one test poison the
// other depending on execution order. Cargo runs each `tests/*.rs`
// in its own binary, so this is the cleanest isolation.
//
// **Why ignored by default:** the .ptau is 289 MB and not in the
// repo. Run via:
//   `CITRATE_PTAU_PATH=/path/to/ppot_0080_18.ptau cargo test \
//      -p citrate-execution --features halo2-substrate \
//      --test inference_proof_verify_real_srs -- --ignored`

#![cfg(feature = "halo2-substrate")]

use citrate_execution::precompiles::verify::{addresses, execute};
use citrate_execution::precompiles::q16::{ops as q16_ops, Q16};
use citrate_execution::types::Address;
use citrate_execution::zkp::halo2::circuits::InferenceCircuit;
use citrate_execution::zkp::halo2::CIRCUIT_VERSION_LINEAR_Q16;
use citrate_execution::zkp::halo2::ptau::load_ptau_into_params_kzg;
use citrate_execution::zkp::poseidon_bn254::poseidon_hash;

use ark_bn254::Fr as ArkFr;
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, Circuit};
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::multiopen::ProverSHPLONK;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
use halo2curves::bn256::{Bn256, Fr as Halo2Fr, G1Affine};
use rand::rngs::StdRng;
use rand::SeedableRng;

const V1_K: u32 = 12;

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

fn fr_to_be32(x: &Halo2Fr) -> [u8; 32] {
    use halo2curves::ff::PrimeField as _;
    let le_bytes = x.to_repr();
    let le_slice: &[u8] = le_bytes.as_ref();
    let le: [u8; 32] = le_slice.try_into().expect("Fr repr is 32 bytes");
    let mut be = le;
    be.reverse();
    be
}

#[test]
#[ignore = "needs CITRATE_PTAU_PATH to a 289MB PPoT k=18 .ptau"]
fn precompile_0x0108_with_real_ptau_srs() {
    // 1. Resolve the .ptau path. If unset OR the file isn't there,
    //    skip — this test is intended to be opt-in.
    let path = match std::env::var("CITRATE_PTAU_PATH") {
        Ok(p) if !p.is_empty() && std::path::Path::new(&p).is_file() => p,
        _ => {
            eprintln!(
                "skipping: CITRATE_PTAU_PATH not set or file missing — \
                 set it to a verified PPoT k=18 .ptau and re-run with \
                 `--ignored` to exercise this path"
            );
            return;
        }
    };

    // 2. Witness: y[0] = 1*3 + 0*4 + 5 = 8 (matches the seed-path test).
    let weights: Vec<Q16> = vec![Q16::from_int(1), Q16::from_int(0)];
    let inputs: Vec<Q16> = vec![Q16::from_int(3), Q16::from_int(4)];
    let biases: Vec<Q16> = vec![Q16::from_int(5)];

    // 3. Off-chain commitments via the production Poseidon (BN254).
    let y_q16 = q16_ops::linear(&weights, &inputs, &biases, 1, 2);
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

    // 4. Set CITRATE_PTAU_PATH so the precompile (verifier side)
    //    loads from the SAME .ptau the prover is about to use.
    //    SAFETY: this is the only OnceLock initialization in this
    //    test binary; tests in this file run sequentially via cargo's
    //    default test-threads=1 for #[ignore]'d.
    // (Ignored test runs with --test-threads=1 by convention; even
    // in parallel mode this is the only test in the file so no race.)
    unsafe {
        std::env::set_var("CITRATE_PTAU_PATH", &path);
    }

    // 5. Prover side: load the same .ptau and generate the proof.
    eprintln!("Loading .ptau from {} (k={})", path, V1_K);
    let params = load_ptau_into_params_kzg(&path, V1_K)
        .expect("load real .ptau");
    eprintln!("ParamsKZG ready. Running keygen + proof generation...");

    // Build the circuit witness in halo2 Fr.
    let weights_fr: Vec<Halo2Fr> =
        weights.iter().copied().map(q16_to_halo2_fr).collect();
    let inputs_fr: Vec<Halo2Fr> = inputs.iter().copied().map(q16_to_halo2_fr).collect();
    let biases_fr: Vec<Halo2Fr> = biases.iter().copied().map(q16_to_halo2_fr).collect();
    let circuit = InferenceCircuit {
        weights: weights_fr.iter().map(|v| Value::known(*v)).collect(),
        inputs: inputs_fr.iter().map(|v| Value::known(*v)).collect(),
        biases: biases_fr.iter().map(|v| Value::known(*v)).collect(),
        out_dim: 1,
        in_dim: 2,
    };

    let vk = keygen_vk(&params, &circuit.without_witnesses()).expect("vk");
    let pk = keygen_pk(&params, vk.clone(), &circuit.without_witnesses()).expect("pk");

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
    eprintln!("Proof generated: {} bytes", proof_bytes.len());

    // 6. Build the wire format and call 0x0108. The verifier side
    //    will see CITRATE_PTAU_PATH set, load the same .ptau, run
    //    keygen_vk on the same circuit topology, and verify.
    let mut wire = Vec::with_capacity(32 * 3 + 4 + 4 + proof_bytes.len());
    wire.extend_from_slice(&fr_to_be32(&input_commit));
    wire.extend_from_slice(&fr_to_be32(&model_commit));
    wire.extend_from_slice(&fr_to_be32(&output_commit));
    wire.extend_from_slice(&CIRCUIT_VERSION_LINEAR_Q16.to_be_bytes());
    wire.extend_from_slice(&40_204u32.to_be_bytes()); // chain_id
    wire.extend_from_slice(&proof_bytes);

    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    let result = execute(&addr, &wire, 100_000_000)
        .expect("INFERENCE_PROOF_VERIFY must succeed with valid proof");

    assert!(result.success, "precompile reports success");
    assert_eq!(result.output.len(), 32);
    assert_eq!(
        result.output[31], 1,
        "proof MUST verify under the real PPoT-derived SRS"
    );
    eprintln!("✓ 0x0108 verified a real-SRS proof end-to-end");
}
