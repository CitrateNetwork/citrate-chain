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

/// PBA-L1b-005: runs peer `InferenceRequest`s OFF the node's single inbound
/// P2P message loop, with bounded concurrency.
///
/// Before this the loop awaited `AINetworkHandler::handle_message` inline for
/// an inference request, so one unpaid peer request stalled every other
/// message (blocks, sync, gossip) for the duration of a model run; the stall
/// detector then exits the process after ~60 s. Now a request either takes one
/// of a few worker permits and runs in its own task, or — when all are busy —
/// is dropped immediately (the requester may retry; nothing queues).
pub struct InferenceDispatcher {
    ai: Arc<citrate_network::ai_handler::AINetworkHandler>,
    peers: Arc<citrate_network::PeerManager>,
    permits: Arc<tokio::sync::Semaphore>,
}

/// Concurrent peer inferences a node will run at once.
pub const MAX_CONCURRENT_PEER_INFERENCES: usize = 2;

impl InferenceDispatcher {
    pub fn new(
        ai: Arc<citrate_network::ai_handler::AINetworkHandler>,
        peers: Arc<citrate_network::PeerManager>,
        max_concurrent: usize,
    ) -> Self {
        Self {
            ai,
            peers,
            permits: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
        }
    }

    /// Hand an `InferenceRequest` to a worker. Returns immediately: `true` if
    /// a worker took it, `false` if all workers were busy and it was dropped.
    pub fn dispatch(
        &self,
        pid: citrate_network::PeerId,
        msg: citrate_network::NetworkMessage,
    ) -> bool {
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            tracing::debug!(
                "PBA-L1b-005: all {} peer-inference workers busy; dropping request from {}",
                MAX_CONCURRENT_PEER_INFERENCES,
                pid
            );
            return false;
        };
        let ai = self.ai.clone();
        let peers = self.peers.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match ai.handle_message(&pid, &msg).await {
                Ok(Some(response)) => {
                    let _ = peers
                        .send_to_peers(std::slice::from_ref(&pid), &response)
                        .await;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("peer inference from {} failed: {}", pid, e),
            }
        });
        true
    }
}

#[cfg(test)]
mod pba_l1b_005_dispatcher {
    use super::*;
    use citrate_consensus::types::Hash;
    use citrate_network::ai_handler::AINetworkHandler;
    use citrate_network::{NetworkMessage, PeerId, PeerManager, PeerManagerConfig};

    /// An executor that takes a long time, like a real model run.
    struct Slow;
    #[async_trait]
    impl NetworkInferenceExecutor for Slow {
        async fn execute_inference(
            &self,
            _m: [u8; 32],
            _i: Vec<u8>,
            _p: [u8; 32],
        ) -> Result<NetworkInferenceResult, anyhow::Error> {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Ok(NetworkInferenceResult {
                output: vec![],
                proof: None,
                execution_time_ms: 30_000,
            })
        }
    }

    fn request(i: u8, model: Hash) -> NetworkMessage {
        NetworkMessage::InferenceRequest {
            request_id: Hash::new([i; 32]),
            model_id: model,
            input_hash: Hash::new([1; 32]),
            requester: vec![0xAB; 20],
            max_fee: 0,
        }
    }

    #[tokio::test]
    async fn dispatch_returns_immediately_and_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            citrate_storage::StorageManager::new(
                dir.path(),
                citrate_storage::pruning::PruningConfig::default(),
            )
            .unwrap(),
        );
        let sm = Arc::new(citrate_storage::state_manager::StateManager::new(storage.db.clone()));
        let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let model = Hash::new([7; 32]);
        let ai = Arc::new(AINetworkHandler::new(sm, pm.clone()).with_inference_executor(Arc::new(Slow)));
        // Make the model servable (a peer announcement, as in discovery).
        ai.handle_message(
            &PeerId("provider".into()),
            &NetworkMessage::ModelAnnounce {
                model_id: model,
                model_hash: Hash::new([1; 32]),
                owner: vec![0xAA; 20],
                metadata: citrate_network::protocol::ModelMetadata {
                    name: "m".into(),
                    version: "1".into(),
                    description: String::new(),
                    framework: "gguf".into(),
                    input_shape: vec![],
                    output_shape: vec![],
                    size_bytes: 0,
                    created_at: 0,
                },
                weight_cid: "bafy".into(),
            },
        )
        .await
        .unwrap();

        let d = InferenceDispatcher::new(ai, pm, MAX_CONCURRENT_PEER_INFERENCES);
        let t0 = std::time::Instant::now();
        let mut accepted = 0;
        for i in 0..10u8 {
            if d.dispatch(PeerId("attacker".into()), request(i, model)) {
                accepted += 1;
            }
        }
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(500),
            "PBA-L1b-005: dispatch must not wait for the inference to run"
        );
        assert_eq!(accepted, MAX_CONCURRENT_PEER_INFERENCES, "concurrency is bounded");
    }

    /// Tripwire: the inbound loop routes InferenceRequest through the
    /// dispatcher, never an inline `handle_message(..).await`.
    #[test]
    fn main_loop_dispatches_inference_off_loop() {
        let src = include_str!("main.rs");
        let arm = src
            .find("NetworkMessage::InferenceRequest { .. } =>")
            .expect("PBA-L1b-005: main loop needs a dedicated InferenceRequest arm");
        assert!(src[arm..arm + 600].contains("inference_dispatcher.dispatch("));
        let ai_arm = src.find("NetworkMessage::ModelAnnounce { .. }").expect("AI arm");
        let ai_arm_head = &src[ai_arm..ai_arm + 400];
        assert!(
            !ai_arm_head.contains("NetworkMessage::InferenceRequest"),
            "InferenceRequest must not fall into the inline AI arm"
        );
    }
}
