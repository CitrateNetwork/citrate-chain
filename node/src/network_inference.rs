use async_trait::async_trait;
use citrate_execution::Address;
use citrate_mcp::MCPService;
use citrate_network::ai_handler::{NetworkInferenceExecutor, NetworkInferenceResult};
use std::sync::Arc;

/// Bridge between the network layer's inference requests and the MCP execution engine.
///
/// Implements `NetworkInferenceExecutor` so that `AINetworkHandler` can run
/// inference without depending on the `citrate-mcp` crate directly.
pub struct NodeNetworkInferenceExecutor {
    mcp: Arc<MCPService>,
    default_provider: Address,
}

impl NodeNetworkInferenceExecutor {
    pub fn new(mcp: Arc<MCPService>, default_provider: Address) -> Self {
        Self {
            mcp,
            default_provider,
        }
    }
}

#[async_trait]
impl NetworkInferenceExecutor for NodeNetworkInferenceExecutor {
    async fn execute_inference(
        &self,
        model_id: [u8; 32],
        input: Vec<u8>,
        _provider: [u8; 32],
    ) -> Result<NetworkInferenceResult, anyhow::Error> {
        let mcp_model_id =
            citrate_mcp::types::ModelId::from_hash(&citrate_consensus::types::Hash::new(model_id));

        let result = self
            .mcp
            .execute_inference(mcp_model_id, input, self.default_provider)
            .await?;

        // Serialize proof to JSON bytes (mirrors node/src/inference.rs pattern)
        let proof_bytes = serde_json::to_vec(&serde_json::json!({
            "model_hash": hex::encode(result.proof.model_hash.as_bytes()),
            "input_hash": hex::encode(result.proof.input_hash.as_bytes()),
            "output_hash": hex::encode(result.proof.output_hash.as_bytes()),
            "io_commitment": hex::encode(result.proof.io_commitment.as_bytes()),
            "provider": hex::encode(self.default_provider.0),
            "timestamp": result.proof.timestamp,
        }))
        .ok();

        Ok(NetworkInferenceResult {
            output: result.output,
            proof: proof_bytes,
            execution_time_ms: result.latency_ms,
        })
    }
}
