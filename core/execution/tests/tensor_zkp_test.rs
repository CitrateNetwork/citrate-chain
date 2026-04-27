#[cfg(feature = "ai_zkp")]
mod ai_zkp_tests {
    use citrate_execution::tensor::{Tensor, TensorEngine, TensorOps};
    use citrate_execution::zkp::{ProofType, ZKPBackend};

    #[test]
    fn test_tensor_operations() {
        let mut engine = TensorEngine::new(100); // 100MB max memory
        let shape = vec![2, 3];
        let data_a = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let data_b = vec![2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
        let tensor_a_id = engine.create_tensor(data_a, shape.clone()).unwrap();
        let tensor_b_id = engine.create_tensor(data_b, shape.clone()).unwrap();
        let result_id = engine.add(&tensor_a_id, &tensor_b_id).unwrap();
        assert!(engine.get_tensor(&result_id).is_some());
        let mul_result_id = engine.mul(&tensor_a_id, &tensor_b_id).unwrap();
        assert!(engine.get_tensor(&mul_result_id).is_some());
        engine.delete_tensor(&tensor_a_id).unwrap();
        engine.delete_tensor(&tensor_b_id).unwrap();
    }

    #[test]
    fn test_tensor_activations() {
        let tensor = Tensor::new(vec![-1.0, 0.0, 1.0, 2.0], vec![2, 2]).unwrap();
        let relu_result = TensorOps::relu(&tensor);
        assert_eq!(relu_result.shape.0, vec![2, 2]);
        let sigmoid_result = TensorOps::sigmoid(&tensor);
        assert_eq!(sigmoid_result.shape.0, vec![2, 2]);
        let tanh_result = TensorOps::tanh(&tensor);
        assert_eq!(tanh_result.shape.0, vec![2, 2]);
    }

    #[test]
    fn test_zkp_backend() {
        let backend = ZKPBackend::new();
        backend.initialize().unwrap();
        let estimate = backend.estimate_proving_time(ProofType::ModelExecution);
        assert!(estimate > 0);
        let proof = backend
            .prove_tensor_computation("add", vec![vec![1, 2, 3], vec![4, 5, 6]], vec![5, 7, 9])
            .unwrap();
        assert!(!proof.proof_bytes.is_empty());
        assert!(!proof.public_inputs.is_empty());
    }

    // RM-M2 WP-M2.11 (2026-04-27): the test_vm_integration test was
    // removed alongside core/execution/src/vm/. AI operations are no
    // longer exposed as opcodes (0xA0–0xDF); they're precompiles
    // 0x010A–0x010F. See `core/execution/src/precompiles/compute.rs`
    // for the LIVE replacement and `tests/inference_proof_verify_e2e.rs`
    // for proof verification (0x0108).
}
