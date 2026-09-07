use citrate_execution::precompiles::inference::{addresses, InferencePrecompile};
use citrate_execution::types::Address;
use sha3::Digest;
use std::sync::Arc;

fn legacy_commitment_proof(statement: &[u8], response: &[u8; 32]) -> Vec<u8> {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(statement);
    hasher.update(response);
    let commitment = hasher.finalize();
    [commitment.as_slice(), response, statement].concat()
}

#[test]
fn cry_h2_legacy_0104_proof_route_is_disabled() {
    let runtime = Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().expect("runtime"),
    );
    let mut precompile = InferencePrecompile::new(runtime);
    let proof = legacy_commitment_proof(b"attacker-controlled statement", &[0xA5; 32]);
    let mut input = vec![0u8; 32];
    input.extend_from_slice(&proof);

    match precompile.execute(&Address(addresses::PROOF_VERIFY), &input, 1_000_000) {
        Ok(_) => panic!("retired 0x0104 must reject caller-forgeable commitments"),
        Err(err) => assert!(err.to_string().contains("retired")),
    }
}
