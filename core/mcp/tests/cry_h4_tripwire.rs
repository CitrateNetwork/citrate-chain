use citrate_execution::Hash;
use citrate_mcp::execution::Model;
use citrate_mcp::types::{ExecutionProof, ModelId};
use citrate_mcp::verification::ExecutionVerifier;
use sha3::{Digest, Sha3_256};

fn hash(data: &[u8]) -> Hash {
    Hash::new(Sha3_256::digest(data).into())
}

fn model_hash(model: &Model) -> Hash {
    let mut h = Sha3_256::new();
    h.update(&model.architecture);
    h.update(&model.weights);
    h.update(&model.metadata);
    Hash::new(h.finalize().into())
}

#[test]
fn cry_h4_forgeable_commitment_is_not_an_execution_proof() {
    let verifier = ExecutionVerifier::new();
    let model = Model {
        id: ModelId([7u8; 32]),
        architecture: b"arch".to_vec(),
        weights: b"weights".to_vec(),
        metadata: b"metadata".to_vec(),
    };
    let input = b"input";
    let output = b"output";
    let model_hash = model_hash(&model);
    let input_hash = hash(input);
    let output_hash = hash(output);
    let mut io = Sha3_256::new();
    io.update(input_hash.as_bytes());
    io.update(output_hash.as_bytes());
    let io_commitment = Hash::new(io.finalize().into());

    let statement = b"attacker-controlled execution statement".to_vec();
    let response = [0xA5u8; 32];
    let mut commitment = Sha3_256::new();
    commitment.update(&statement);
    commitment.update(response);
    let proof_data = [commitment.finalize().as_slice(), &response].concat();
    let proof = ExecutionProof {
        model_hash,
        input_hash,
        output_hash,
        io_commitment,
        statement,
        proof_data,
        timestamp: 1,
        provider: citrate_execution::Address([9u8; 20]),
    };

    assert!(
        !verifier.verify_execution(&model, input, output, &proof).unwrap(),
        "a caller-computed SHA3 commitment must not satisfy execution-proof verification"
    );
}
