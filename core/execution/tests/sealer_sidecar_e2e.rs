// core/execution/tests/sealer_sidecar_e2e.rs
//
// PIN-S6 — the sealing/proving sidecar produces proofs the live 0x0108 verifier
// accepts. Two layers:
//   1. the prover helpers (`prove_porep_reduced` / `prove_post_reduced`) emit a
//      proof that `verify_porep_proof` / `verify_post_proof` (the exact
//      precompile path) accepts, and a tampered proof rejects;
//   2. the `citrate-sealer` BINARY, driven over its stdin/stdout JSON protocol
//      (exactly how the pinning daemon's SidecarSealer drives it), returns a
//      seal proof + comm roots that verify through the precompile.
//
// Feature-gated like the other proof e2e suites.
#![cfg(feature = "halo2-substrate")]

use citrate_execution::precompiles::verify::{addresses, execute};
use citrate_execution::types::Address;
use citrate_execution::zkp::halo2::porep::seal_reduced;
use citrate_execution::zkp::halo2::{prove_porep_reduced, prove_post_reduced};
use halo2curves::bn256::Fr as Halo2Fr;
use halo2curves::ff::PrimeField as _;

fn fr_to_be32(x: &Halo2Fr) -> [u8; 32] {
    let le = x.to_repr();
    let le_slice: &[u8] = le.as_ref();
    let le_arr: [u8; 32] = le_slice.try_into().expect("32 bytes");
    let mut be = le_arr;
    be.reverse();
    be
}

const CHAIN_ID: u32 = 40204;

/// v2 PoRep wire: replicaID ‖ cid ‖ sectorIndex ‖ version=2 ‖ chainId ‖
/// CommD ‖ CommR ‖ CommC ‖ challengeNonce ‖ epoch ‖ proof.
#[allow(clippy::too_many_arguments)]
fn porep_wire(
    replica_id: &Halo2Fr,
    cid: &Halo2Fr,
    sector: &Halo2Fr,
    comm_d: &Halo2Fr,
    comm_r: &Halo2Fr,
    comm_c: &Halo2Fr,
    epoch: &Halo2Fr,
    challenge_index: usize,
    proof: &[u8],
) -> Vec<u8> {
    let challenge_fr = Halo2Fr::from(challenge_index as u64);
    let mut buf = Vec::new();
    buf.extend_from_slice(&fr_to_be32(replica_id));
    buf.extend_from_slice(&fr_to_be32(cid));
    buf.extend_from_slice(&fr_to_be32(sector));
    buf.extend_from_slice(&2u32.to_be_bytes());
    buf.extend_from_slice(&CHAIN_ID.to_be_bytes());
    buf.extend_from_slice(&fr_to_be32(comm_d));
    buf.extend_from_slice(&fr_to_be32(comm_r));
    buf.extend_from_slice(&fr_to_be32(comm_c));
    buf.extend_from_slice(&fr_to_be32(&challenge_fr));
    buf.extend_from_slice(&fr_to_be32(epoch));
    buf.extend_from_slice(proof);
    buf
}

/// v3 PoSt wire: same minus CommD, version=3.
#[allow(clippy::too_many_arguments)]
fn post_wire(
    replica_id: &Halo2Fr,
    cid: &Halo2Fr,
    sector: &Halo2Fr,
    comm_r: &Halo2Fr,
    comm_c: &Halo2Fr,
    epoch: &Halo2Fr,
    challenge_index: usize,
    proof: &[u8],
) -> Vec<u8> {
    let challenge_fr = Halo2Fr::from(challenge_index as u64);
    let mut buf = Vec::new();
    buf.extend_from_slice(&fr_to_be32(replica_id));
    buf.extend_from_slice(&fr_to_be32(cid));
    buf.extend_from_slice(&fr_to_be32(sector));
    buf.extend_from_slice(&3u32.to_be_bytes());
    buf.extend_from_slice(&CHAIN_ID.to_be_bytes());
    buf.extend_from_slice(&fr_to_be32(comm_r));
    buf.extend_from_slice(&fr_to_be32(comm_c));
    buf.extend_from_slice(&fr_to_be32(&challenge_fr));
    buf.extend_from_slice(&fr_to_be32(epoch));
    buf.extend_from_slice(proof);
    buf
}

fn verify_via_precompile(wire: &[u8]) -> bool {
    let addr = Address(addresses::INFERENCE_PROOF_VERIFY);
    match execute(&addr, wire, 50_000_000) {
        Ok(res) => res.output.len() == 32 && res.output[31] == 1,
        Err(_) => false,
    }
}

fn sample_seal() -> (Halo2Fr, Halo2Fr, Halo2Fr, Halo2Fr, [Halo2Fr; 4]) {
    let pinner = Halo2Fr::from(0xA11CEu64);
    let cid = Halo2Fr::from(0xC1Du64);
    let sector = Halo2Fr::from(7u64);
    let epoch = Halo2Fr::from(42u64);
    let data = [
        Halo2Fr::from(1001u64),
        Halo2Fr::from(2002u64),
        Halo2Fr::from(3003u64),
        Halo2Fr::from(4004u64),
    ];
    (pinner, cid, sector, epoch, data)
}

#[test]
fn prover_porep_proof_verifies_through_0x0108() {
    let (pinner, cid, sector, epoch, data) = sample_seal();
    let sealed = seal_reduced(pinner, cid, sector, epoch, data);
    let proof = prove_porep_reduced(&sealed, pinner, 1).expect("prove porep");
    let wire = porep_wire(
        &sealed.replica_id, &sealed.cid, &sealed.sector_index,
        &sealed.comm_d, &sealed.comm_r, &sealed.comm_c, &sealed.epoch, 1, &proof,
    );
    assert!(verify_via_precompile(&wire), "sidecar PoRep proof must verify via 0x0108");
}

#[test]
fn seal_proof_at_index0_verifies_matching_contract_seal_wire() {
    // IPFSIncentivesV3.sealCommit builds its 0x0108 wire with challengeNonce=0,
    // so the seal-time proof MUST be valid at challenge_index 0 (the reduced
    // circuit's v=0 seed slot). This guards the actual on-chain seal path.
    let (pinner, cid, sector, epoch, data) = sample_seal();
    let sealed = seal_reduced(pinner, cid, sector, epoch, data);
    let proof = prove_porep_reduced(&sealed, pinner, 0).expect("prove porep @0");
    let wire = porep_wire(
        &sealed.replica_id, &sealed.cid, &sealed.sector_index,
        &sealed.comm_d, &sealed.comm_r, &sealed.comm_c, &sealed.epoch, 0, &proof,
    );
    assert!(
        verify_via_precompile(&wire),
        "index-0 seal proof (challengeNonce=0) must verify — the contract's seal wire"
    );
}

#[test]
fn prover_post_proof_verifies_through_0x0108() {
    let (pinner, cid, sector, epoch, data) = sample_seal();
    let sealed = seal_reduced(pinner, cid, sector, epoch, data);
    let proof = prove_post_reduced(&sealed, pinner, 1).expect("prove post");
    let wire = post_wire(
        &sealed.replica_id, &sealed.cid, &sealed.sector_index,
        &sealed.comm_r, &sealed.comm_c, &sealed.epoch, 1, &proof,
    );
    assert!(verify_via_precompile(&wire), "sidecar PoSt proof must verify via 0x0108");
}

#[test]
fn tampered_sidecar_proof_rejected() {
    let (pinner, cid, sector, epoch, data) = sample_seal();
    let sealed = seal_reduced(pinner, cid, sector, epoch, data);
    let mut proof = prove_porep_reduced(&sealed, pinner, 1).expect("prove porep");
    let mid = proof.len() / 2;
    proof[mid] ^= 0x01;
    let wire = porep_wire(
        &sealed.replica_id, &sealed.cid, &sealed.sector_index,
        &sealed.comm_d, &sealed.comm_r, &sealed.comm_c, &sealed.epoch, 1, &proof,
    );
    assert!(!verify_via_precompile(&wire), "a tampered proof must not verify");
}

// ── Full sidecar BINARY e2e: drive the citrate-sealer process over its JSON
//    protocol (exactly as the daemon's SidecarSealer does) and verify the
//    returned seal proof through the precompile. ──
#[test]
fn sealer_binary_roundtrip_verifies_through_0x0108() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Cargo sets CARGO_BIN_EXE_<name> for integration tests when the bin builds.
    let exe = match option_env!("CARGO_BIN_EXE_citrate-sealer") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("citrate-sealer bin path not provided by cargo; skipping process e2e");
            return;
        }
    };

    fn be_hex(x: &Halo2Fr) -> String {
        format!("0x{}", hex::encode(fr_to_be32(x)))
    }

    let (pinner, cid, sector, epoch, data) = sample_seal();
    let req = serde_json::json!({
        "op": "seal",
        "pinner": be_hex(&pinner),
        "cid": be_hex(&cid),
        "sector": be_hex(&sector),
        "epoch": be_hex(&epoch),
        "data": data.iter().map(be_hex).collect::<Vec<_>>(),
        "challenge_index": 1,
    })
    .to_string();

    let mut child = Command::new(&exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn citrate-sealer");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(format!("{req}\n").as_bytes())
        .expect("write request");
    let output = child.wait_with_output().expect("sealer output");
    assert!(output.status.success(), "sealer exited non-zero");
    let line = String::from_utf8(output.stdout).expect("utf8");
    let resp: serde_json::Value =
        serde_json::from_str(line.lines().next().expect("a response line")).expect("json");
    assert_eq!(resp["ok"], serde_json::Value::Bool(true), "sealer returned error: {resp}");

    let parse = |k: &str| -> Halo2Fr {
        let s = resp[k].as_str().expect("hex field").trim_start_matches("0x");
        let bytes = hex::decode(s).expect("hex");
        let mut le = [0u8; 32];
        for (i, b) in bytes.iter().enumerate() {
            le[31 - i] = *b;
        }
        Option::<Halo2Fr>::from(Halo2Fr::from_repr(le.into())).expect("fr")
    };
    let replica_id = parse("replica_id");
    let comm_d = parse("comm_d");
    let comm_r = parse("comm_r");
    let comm_c = parse("comm_c");
    let proof_hex = resp["proof"].as_str().expect("proof").trim_start_matches("0x");
    let proof = hex::decode(proof_hex).expect("proof hex");

    let wire = porep_wire(
        &replica_id, &cid, &sector, &comm_d, &comm_r, &comm_c, &epoch, 1, &proof,
    );
    assert!(
        verify_via_precompile(&wire),
        "the citrate-sealer binary's seal proof must verify through 0x0108"
    );
}
