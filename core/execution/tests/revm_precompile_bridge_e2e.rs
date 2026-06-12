// citrate/core/execution/tests/revm_precompile_bridge_e2e.rs
//
// WP-B0 (TD-28) — contract → REVM → custom-precompile bridge.
//
// Until this WP, `Evm::builder()` in `revm_adapter.rs` registered NO custom
// precompiles: a deployed contract's STATICCALL to the Citrate verify
// family (0x0107–0x0109) hit an EMPTY ACCOUNT, returned `success=1` with
// empty returndata, and `IPFSIncentivesV2._verify()` read that as "invalid
// proof" forever. None of the existing test layers crossed the seam this
// file covers:
//   - the Foundry suites `vm.etch` a MockVerifier at 0x0108;
//   - the Rust e2e suites call `precompiles::verify::execute` directly.
//
// This file is the missing test class: it deploys REAL runtime bytecode
// into REVM and exercises the precompile THROUGH contract execution.
//
// It also pins the canonical address scheme: the Solidity contracts
// (`IPFSIncentivesV2.sol`, `ComputeVerifier.sol`), the canonical address
// table (`contracts/addresses/40204.json` → `precompiles.InferenceVerify`)
// and every design doc say `0x…0108`, while the pre-WP-B0 Rust constants
// encoded `0x…010008` ([..,1,0,8]). The Solidity/table form wins — these
// tests fail if the Rust constants ever drift from it again.
//
// Layout:
//   - ungated tests: 0x0107 TENSOR_COMMIT (pure Poseidon, no halo2 feature)
//     + the canonical-address tripwires. These run in default CI.
//   - `#[cfg(feature = "halo2-substrate")]` module: a REAL reduced-PoRep
//     KZG proof verifies through a contract STATICCALL to 0x0108
//     (mirrors `IPFSIncentivesV2.sealCommit`'s verification step), and a
//     tampered proof makes the STATICCALL fail.

use std::collections::HashMap;
use std::sync::Arc;

use citrate_execution::precompiles::tensor_format::{encode, Dtype};
use citrate_execution::precompiles::verify::{addresses, execute as verify_execute};
use citrate_execution::revm_adapter::{execute_contract_call_with_context, BlockContext};
use citrate_execution::state::StateDB;
use citrate_execution::types::Address;
use primitive_types::U256;

// ---------------------------------------------------------------------------
// Forwarder contract: STATICCALLs a fixed target with its own calldata and
// returns 64 bytes: [0..32] = first 32 returndata bytes, [32..64] = the
// STATICCALL success flag. Mirrors the exact call shape of
// `IPFSIncentivesV2._verify()` (STATICCALL, 32-byte return expected).
//
// Assembly:
//   CALLDATASIZE PUSH0 PUSH0 CALLDATACOPY   ; mem[0..cds] = calldata
//   PUSH1 0x20                              ; retSize = 32
//   PUSH0                                   ; retOffset = 0
//   CALLDATASIZE                            ; argsSize
//   PUSH0                                   ; argsOffset
//   PUSH20 <target>                         ; address
//   GAS                                     ; gas
//   STATICCALL                              ; -> success
//   PUSH1 0x20 MSTORE                       ; mem[32..64] = success
//   PUSH1 0x40 PUSH0 RETURN                 ; return mem[0..64]
// ---------------------------------------------------------------------------
fn staticcall_forwarder_runtime(target: [u8; 20]) -> Vec<u8> {
    let mut code = vec![
        0x36, 0x5f, 0x5f, 0x37, // CALLDATASIZE PUSH0 PUSH0 CALLDATACOPY
        0x60, 0x20, // PUSH1 0x20 (retSize)
        0x5f, // PUSH0 (retOffset)
        0x36, // CALLDATASIZE (argsSize)
        0x5f, // PUSH0 (argsOffset)
        0x73, // PUSH20
    ];
    code.extend_from_slice(&target);
    code.extend_from_slice(&[
        0x5a, // GAS
        0xfa, // STATICCALL
        0x60, 0x20, 0x52, // PUSH1 0x20 MSTORE
        0x60, 0x40, 0x5f, 0xf3, // PUSH1 0x40 PUSH0 RETURN
    ]);
    code
}

/// Deploy the forwarder targeting `target`, call it with `calldata` through
/// the production REVM path, and split the 64-byte return into
/// (first-returndata-word, success-flag-word).
fn call_via_forwarder(target: [u8; 20], calldata: Vec<u8>) -> ([u8; 32], [u8; 32]) {
    let state_db = Arc::new(StateDB::new());
    let caller = Address([0x11u8; 20]);
    let forwarder = Address([0x22u8; 20]);
    state_db
        .accounts
        .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));
    state_db.set_code(forwarder, staticcall_forwarder_runtime(target));

    let ctx = BlockContext {
        coinbase: [0x42; 20],
        prevrandao: [0u8; 32],
        block_hashes: HashMap::new(),
    };

    let (output, _gas, _logs) = execute_contract_call_with_context(
        state_db,
        caller,
        forwarder,
        calldata,
        U256::zero(),
        20_000_000, // verify gas: 500k base + 50/byte; generous headroom
        U256::from(1_000_000_000u64),
        40204,
        100,
        1_000_000,
        ctx,
        None,
        None,
        None,
    )
    .expect("the forwarder contract itself must execute successfully");

    assert_eq!(
        output.len(),
        64,
        "forwarder returns 64 bytes (returndata word + success word)"
    );
    let mut ret = [0u8; 32];
    let mut ok = [0u8; 32];
    ret.copy_from_slice(&output[..32]);
    ok.copy_from_slice(&output[32..]);
    (ret, ok)
}

fn word_is_one(w: &[u8; 32]) -> bool {
    w[..31].iter().all(|&b| b == 0) && w[31] == 1
}

fn word_is_zero(w: &[u8; 32]) -> bool {
    w.iter().all(|&b| b == 0)
}

/// Valid Q16 tensor in the canonical `tensor_format::encode` wire format —
/// the documented input of the 0x0107 TENSOR_COMMIT precompile.
fn valid_q16_tensor() -> Vec<u8> {
    let values: [i32; 3] = [1, 2, 3];
    let mut data = Vec::with_capacity(values.len() * 4);
    for v in values {
        data.extend_from_slice(&v.to_le_bytes());
    }
    encode(&[3], Dtype::Q16_16, &data).expect("canonical tensor encodes")
}

// ===========================================================================
// Canonical-address tripwires (TD-28's second finding). The byte patterns
// here are transcribed from `contracts/addresses/40204.json` →
// `precompiles.InferenceVerify` = 0x…0108 and the Solidity constants
// (`IPFSIncentivesV2.INFERENCE_PROOF_VERIFY = address(0x0108)`).
// ===========================================================================

fn canonical(short: u16) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[18] = (short >> 8) as u8;
    a[19] = (short & 0xff) as u8;
    a
}

#[test]
fn verify_family_addresses_match_canonical_40204_table() {
    assert_eq!(
        addresses::TENSOR_COMMIT,
        canonical(0x0107),
        "TENSOR_COMMIT must be the canonical 0x…0107 the contracts/table use"
    );
    assert_eq!(
        addresses::INFERENCE_PROOF_VERIFY,
        canonical(0x0108),
        "INFERENCE_PROOF_VERIFY must be the canonical 0x…0108 that \
         IPFSIncentivesV2.sol STATICCALLs and 40204.json publishes"
    );
    assert_eq!(
        addresses::MERKLE_VERIFY_TENSOR,
        canonical(0x0109),
        "MERKLE_VERIFY_TENSOR must be the canonical 0x…0109"
    );
}

// ===========================================================================
// Ungated bridge tests — 0x0107 TENSOR_COMMIT is pure Poseidon and needs no
// feature flag, so default CI exercises the REVM bridge end-to-end.
// ===========================================================================

#[test]
fn tensor_commit_0x0107_reachable_from_contract_staticcall() {
    let input = valid_q16_tensor();

    // Ground truth: the precompile called directly (the only path the
    // pre-WP-B0 tests ever exercised).
    let direct = verify_execute(&Address(addresses::TENSOR_COMMIT), &input, 20_000_000)
        .expect("direct tensor_commit succeeds on canonical input");
    assert_eq!(direct.output.len(), 32);

    // Through a real contract STATICCALL inside REVM.
    let (ret, ok) = call_via_forwarder(addresses::TENSOR_COMMIT, input);

    assert!(
        word_is_one(&ok),
        "STATICCALL to 0x0107 must succeed from contract code (got success={})",
        ok[31]
    );
    assert_eq!(
        ret,
        direct.output.as_slice(),
        "the commitment seen by contract code must equal the precompile's \
         direct output — empty/zero means the bridge is missing (TD-28)"
    );
}

#[test]
fn malformed_input_fails_the_staticcall_to_0x0107() {
    // 4 junk bytes are not a canonical tensor: the precompile rejects them.
    // Pre-WP-B0 the STATICCALL SUCCEEDED (empty account!) — the dangerous
    // silent-acceptance this test pins against.
    let (_ret, ok) = call_via_forwarder(addresses::TENSOR_COMMIT, vec![0xde, 0xad, 0xbe, 0xef]);
    assert!(
        word_is_zero(&ok),
        "a malformed tensor must FAIL the staticcall (precompile error), \
         not silently succeed as an empty-account call"
    );
}

// ===========================================================================
// 0x0108 through contract code with a REAL reduced-PoRep proof — the exact
// verification step `IPFSIncentivesV2.sealCommit` performs on-chain.
// Feature-gated like the other proof e2e suites.
// ===========================================================================
#[cfg(feature = "halo2-substrate")]
mod porep_v2_through_revm {
    use super::*;

    use citrate_execution::zkp::halo2::porep::{seal_reduced, PoRepCircuit, SealedReplica};
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, Circuit};
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
    use halo2_proofs::poly::kzg::multiopen::ProverSHPLONK;
    use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
    use halo2curves::bn256::{Bn256, Fr as Halo2Fr, G1Affine};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // MUST match V2_K in `halo2::porep_kzg_artifacts_v2` (k=14 since PIN-P1
    // (c1)) so prover and verifier derive identical artifacts.
    const POREP_K: u32 = 14;

    fn fr_to_be32(x: &Halo2Fr) -> [u8; 32] {
        use halo2curves::ff::PrimeField as _;
        let le_bytes = x.to_repr();
        let le_slice: &[u8] = le_bytes.as_ref();
        let le: [u8; 32] = le_slice.try_into().expect("Fr repr is 32 bytes");
        let mut be = le;
        be.reverse();
        be
    }

    /// v2 PoRep wire per `halo2::verify_porep_proof`:
    ///   replicaID(32) ‖ cid(32) ‖ sectorIndex(32) ‖ version=2(4) ‖
    ///   chainId(4) ‖ CommD(32) ‖ CommR(32) ‖ CommC(32) ‖
    ///   challengeNonce(32) ‖ epoch(32) ‖ proof
    fn build_porep_wire(sealed: &SealedReplica, challenge_index: usize, proof: &[u8]) -> Vec<u8> {
        let challenge_fr = Halo2Fr::from(challenge_index as u64);
        let mut buf = Vec::with_capacity(32 * 8 + 8 + proof.len());
        buf.extend_from_slice(&fr_to_be32(&sealed.replica_id));
        buf.extend_from_slice(&fr_to_be32(&sealed.cid));
        buf.extend_from_slice(&fr_to_be32(&sealed.sector_index));
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&40204u32.to_be_bytes());
        buf.extend_from_slice(&fr_to_be32(&sealed.comm_d));
        buf.extend_from_slice(&fr_to_be32(&sealed.comm_r));
        buf.extend_from_slice(&fr_to_be32(&sealed.comm_c));
        buf.extend_from_slice(&fr_to_be32(&challenge_fr));
        buf.extend_from_slice(&fr_to_be32(&sealed.epoch));
        buf.extend_from_slice(proof);
        buf
    }

    /// Seal + prove with the SAME deterministic ParamsKZG seed ([0x4D; 32])
    /// and k as the verifier side (`porep_kzg_artifacts_v2`). Mirrors
    /// `porep_proof_verify_e2e::generate_porep_proof`.
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
        let params = ParamsKZG::<Bn256>::setup(POREP_K, &mut params_rng);
        let vk = keygen_vk(&params, &circuit.without_witnesses()).expect("keygen_vk");
        let pk = keygen_pk(&params, vk, &circuit.without_witnesses()).expect("keygen_pk");

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

    #[test]
    fn valid_porep_proof_verifies_through_contract_staticcall_0x0108() {
        let (sealed, proof) = generate_porep_proof(1);
        let wire = build_porep_wire(&sealed, 1, &proof);

        let (ret, ok) = call_via_forwarder(addresses::INFERENCE_PROOF_VERIFY, wire);

        assert!(
            word_is_one(&ok),
            "the STATICCALL IPFSIncentivesV2._verify performs must succeed"
        );
        assert!(
            word_is_one(&ret),
            "contract code must see the 32-byte BE verdict word 1 — \
             zero/empty means the bridge is missing (TD-28) and every \
             sealCommit/submitPoSt would revert on the live chain"
        );
    }

    #[test]
    fn tampered_porep_proof_fails_the_staticcall_0x0108() {
        let (sealed, mut proof) = generate_porep_proof(1);
        let mid = proof.len() / 2;
        proof[mid] ^= 0x01;
        let wire = build_porep_wire(&sealed, 1, &proof);

        let (ret, ok) = call_via_forwarder(addresses::INFERENCE_PROOF_VERIFY, wire);

        // The verifier's documented reject semantics (IPFSIncentivesV2._verify):
        // EITHER the staticcall fails (parse/dispatch error → precompile
        // error) OR it succeeds with a verdict word ≠ 1 (well-formed proof
        // that fails verification → 32-byte zero word). Both are rejects;
        // the only forbidden outcome is the verdict word 1.
        assert!(
            !word_is_one(&ret),
            "a tampered proof must never produce the verdict word 1"
        );
        if word_is_one(&ok) {
            assert!(
                word_is_zero(&ret),
                "a successful staticcall on a tampered proof must return \
                 the zero verdict word, got 0x{}",
                hex::encode(ret)
            );
        }
    }

    /// Top-level (eth_call-shaped) transaction straight to 0x0108 — the
    /// probe shape used to diagnose TD-28 live on chain 40204.
    #[test]
    fn direct_top_level_call_to_0x0108_verifies_a_valid_proof() {
        let (sealed, proof) = generate_porep_proof(2);
        let wire = build_porep_wire(&sealed, 2, &proof);

        let state_db = Arc::new(StateDB::new());
        let caller = Address([0x11u8; 20]);
        state_db
            .accounts
            .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));

        let ctx = BlockContext {
            coinbase: [0x42; 20],
            prevrandao: [0u8; 32],
            block_hashes: HashMap::new(),
        };

        let (output, _gas, _logs) = execute_contract_call_with_context(
            state_db,
            caller,
            Address(addresses::INFERENCE_PROOF_VERIFY),
            wire,
            U256::zero(),
            20_000_000,
            U256::from(1_000_000_000u64),
            40204,
            100,
            1_000_000,
            ctx,
            None,
            None,
            None,
        )
        .expect("direct call to the verifier precompile must execute");

        assert_eq!(
            output.len(),
            32,
            "the precompile returns one 32-byte word — empty output means \
             REVM treated 0x0108 as an empty account (TD-28)"
        );
        assert!(
            word_is_one(&output[..32].try_into().expect("32 bytes")),
            "verdict word must be 1 for a valid proof"
        );
    }
}
