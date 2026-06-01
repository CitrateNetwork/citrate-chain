// citrate/core/network/src/protocol.rs

// Network protocol definitions
use crate::learning_messages::LearningMessage;
use citrate_consensus::types::{Block, BlockHeader, Hash, Transaction};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Model metadata for AI network messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub framework: String,
    pub input_shape: Vec<usize>,
    pub output_shape: Vec<usize>,
    pub size_bytes: u64,
    pub created_at: u64,
}

/// Protocol version for compatibility checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ProtocolVersion {
    pub const CURRENT: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    pub fn is_compatible(&self, other: &Self) -> bool {
        // Major version must match, minor/patch can differ
        self.major == other.major
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Network message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum NetworkMessage {
    // Handshake messages
    Hello {
        version: ProtocolVersion,
        network_id: u32,
        genesis_hash: Hash,
        head_height: u64,
        head_hash: Hash,
        peer_id: String,
    },

    HelloAck {
        version: ProtocolVersion,
        head_height: u64,
        head_hash: Hash,
        peer_id: String,
    },

    Disconnect {
        reason: String,
    },

    // Ping/Pong for keepalive
    Ping {
        nonce: u64,
    },

    Pong {
        nonce: u64,
    },

    // Block messages
    NewBlock {
        block: Block,
    },

    GetBlocks {
        from: Hash,
        count: u32,
        step: u32, // For sparse download
    },

    Blocks {
        blocks: Vec<Block>,
    },

    GetHeaders {
        from: Hash,
        count: u32,
    },

    Headers {
        headers: Vec<BlockHeader>,
    },

    // Transaction messages
    NewTransaction {
        transaction: Transaction,
    },

    GetTransactions {
        hashes: Vec<Hash>,
    },

    Transactions {
        transactions: Vec<Transaction>,
    },

    // AI-specific messages for model and inference data

    // Model registration and updates
    ModelAnnounce {
        model_id: Hash,
        model_hash: Hash,
        owner: Vec<u8>, // Address bytes
        metadata: ModelMetadata,
        weight_cid: String, // IPFS CID for weights
    },

    GetModel {
        model_id: Hash,
    },

    ModelData {
        model_id: Hash,
        weight_cid: String,
        metadata: ModelMetadata,
    },

    // Inference requests and results
    InferenceRequest {
        request_id: Hash,
        model_id: Hash,
        input_hash: Hash,
        requester: Vec<u8>,
        max_fee: u128,
    },

    InferenceResponse {
        request_id: Hash,
        output_hash: Hash,
        proof: Vec<u8>, // ZK proof of computation
        provider: Vec<u8>,
    },

    // Training coordination
    TrainingJobAnnounce {
        job_id: Hash,
        model_id: Hash,
        dataset_hash: Hash,
        participants_needed: u32,
        reward_per_gradient: u128,
        /// Owner address (20 bytes) - the entity that created and funds this training job
        owner: [u8; 20],
    },

    GradientSubmission {
        job_id: Hash,
        gradient_hash: Hash,
        epoch: u32,
        participant: Vec<u8>,
    },

    // LoRA adapter sharing
    LoraAdapterAnnounce {
        adapter_id: Hash,
        base_model: Hash,
        weight_cid: String,
        rank: u32,
        alpha: f32,
    },

    GetLoraAdapter {
        adapter_id: Hash,
    },

    // Model weight synchronization
    WeightSync {
        model_id: Hash,
        version: u32,
        weight_delta: Vec<u8>, // Compressed weight update
    },

    // AI state synchronization
    GetAIState {
        from_height: u64,
    },

    AIStateUpdate {
        height: u64,
        models_root: Hash,
        training_root: Hash,
        inference_root: Hash,
        lora_root: Hash,
    },

    GetMempool,

    Mempool {
        tx_hashes: Vec<Hash>,
    },

    // Sync messages
    GetBlocksByHeight {
        from_height: u64,
        count: u32,
    },

    GetState {
        root: Hash,
        keys: Vec<Vec<u8>>,
    },

    StateData {
        root: Hash,
        data: Vec<(Vec<u8>, Vec<u8>)>,
    },

    // Discovery messages
    GetPeers,

    Peers {
        peers: Vec<PeerAddress>,
    },

    // Consensus messages (GhostDAG specific)
    GetBlueSet {
        block: Hash,
    },

    BlueSet {
        block: Hash,
        blue_blocks: Vec<Hash>,
        blue_score: u64,
    },

    GetDagInfo {
        blocks: Vec<Hash>,
    },

    DagInfo {
        info: Vec<DagBlockInfo>,
    },

    // WP-S.3: BFT checkpoint vote
    CheckpointVote {
        height: u64,
        block_hash: Hash,
        voter_pubkey: Vec<u8>,
        signature: Vec<u8>,
    },

    // WP-S.4: NAT traversal relay messages
    /// Request a relay node to forward data to another peer.
    RelayRequest {
        target_peer_id: String,
        payload: Vec<u8>,
    },

    /// Data forwarded through a relay node from another peer.
    RelayData {
        source_peer_id: String,
        payload: Vec<u8>,
    },

    /// Request a relay node to facilitate a hole punch.
    HolePunchRequest {
        target_peer_id: String,
        /// The requester's external address as seen by the relay.
        external_addr: String,
    },

    /// Notification to a peer that another peer wants to hole punch.
    HolePunchNotify {
        peer_id: String,
        external_addr: String,
    },

    // WP-F.2: Learning gossip messages (paraconsensus layer)

    /// Learning-layer message (embedding broadcast or LoRA adapter offer).
    /// Gossiped at BFT checkpoint boundaries.
    LearningGossip {
        message: LearningMessage,
    },
}

/// Peer address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAddress {
    pub id: String,
    pub addr: String,
    pub last_seen: u64,
    pub score: i32,
}

/// DAG block information for GhostDAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagBlockInfo {
    pub hash: Hash,
    pub selected_parent: Hash,
    pub merge_parents: Vec<Hash>,
    pub blue_score: u64,
    pub is_blue: bool,
}

/// Protocol handler trait
#[async_trait::async_trait]
pub trait Protocol: Send + Sync {
    /// Handle incoming message
    async fn handle_message(
        &self,
        peer_id: &str,
        message: NetworkMessage,
    ) -> Result<Option<NetworkMessage>, crate::NetworkError>;

    /// Called when a new peer connects
    async fn on_peer_connected(&self, peer_id: &str);

    /// Called when a peer disconnects
    async fn on_peer_disconnected(&self, peer_id: &str);
}

/// Message priority for queue management
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl NetworkMessage {
    /// Get the priority of this message
    pub fn priority(&self) -> MessagePriority {
        match self {
            // Critical priority for handshake and sync
            Self::Hello { .. } | Self::HelloAck { .. } => MessagePriority::Critical,
            Self::GetBlocks { .. } | Self::GetHeaders { .. } => MessagePriority::Critical,

            // High priority for new blocks
            Self::NewBlock { .. } => MessagePriority::High,

            // Normal priority for transactions and general messages
            Self::NewTransaction { .. } => MessagePriority::Normal,
            Self::GetTransactions { .. } | Self::Transactions { .. } => MessagePriority::Normal,

            // Low priority for discovery and stats
            Self::GetPeers | Self::Peers { .. } => MessagePriority::Low,
            Self::Ping { .. } | Self::Pong { .. } => MessagePriority::Low,

            _ => MessagePriority::Normal,
        }
    }

    /// Check if this message requires a response
    pub fn requires_response(&self) -> bool {
        matches!(
            self,
            Self::Ping { .. }
                | Self::GetBlocks { .. }
                | Self::GetHeaders { .. }
                | Self::GetTransactions { .. }
                | Self::GetMempool
                | Self::GetPeers
                | Self::GetBlueSet { .. }
                | Self::GetDagInfo { .. }
                | Self::GetState { .. }
                | Self::GetBlocksByHeight { .. }
        )
    }

    /// Strip peer-asserted trust from a message deserialized off the wire.
    ///
    /// SECURITY (C-01 network variant): `Transaction::ecdsa_verified` is a
    /// LOCAL trust flag — it means "this node's decoder cryptographically
    /// recovered the ECDSA signer." It is also a serialized struct field, so
    /// a peer can set it to `true` on a gossiped transaction with a forged
    /// signature and a victim `from` address. The mempool gate
    /// (`mempool.rs`) and `crypto::verify_transaction` accept an EVM-shaped
    /// transaction purely on this flag, so a trusted-but-unverified gossip
    /// tx would be accepted into the mempool/validation path with a forged
    /// sender. The `eth_sendRawTransaction` RPC ingress was hardened (C-01)
    /// but the P2P transaction ingress was not.
    ///
    /// This resets `ecdsa_verified = false` on every transaction carried by
    /// an inbound message, at the deserialization boundary, so a peer can
    /// never assert verification this node did not perform. An EVM-shaped
    /// gossip tx must then be re-verified locally (follow-up: re-recover the
    /// signer at ingress) before it can enter the mempool — fail closed.
    /// Native (ed25519) transactions are unaffected: their signature is
    /// verified independently by `verify_ed25519_transaction`.
    pub fn sanitize_inbound(&mut self) {
        match self {
            Self::NewTransaction { transaction } => {
                transaction.ecdsa_verified = false;
            }
            Self::Transactions { transactions } => {
                for tx in transactions.iter_mut() {
                    tx.ecdsa_verified = false;
                }
            }
            _ => {}
        }
    }

    /// Deserialize a `NetworkMessage` from the wire and immediately strip
    /// peer-asserted trust (`sanitize_inbound`). EVERY inbound decode path
    /// MUST use this rather than `bincode::deserialize` directly, so a new
    /// ingress can never reintroduce the C-01 network-variant bypass.
    pub fn decode_inbound(bytes: &[u8]) -> Result<Self, bincode::Error> {
        let mut msg: Self = bincode::deserialize(bytes)?;
        msg.sanitize_inbound();
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CIT-NET-C01b tripwire (blind-pass NEW-FROM-B2): a transaction
    /// gossiped with a peer-asserted `ecdsa_verified = true` MUST have that
    /// flag stripped when decoded off the wire, so a forged-sender EVM tx
    /// can never reach the mempool's flag-gated acceptance path. Pre-fix the
    /// P2P ingress trusted the wire flag (the C-01 RPC fix did not cover it).
    #[test]
    fn decode_inbound_strips_peer_asserted_ecdsa_verified() {
        use citrate_consensus::types::{PublicKey, Transaction};

        let mut from = [0u8; 32];
        from[..20].copy_from_slice(&[0xAA; 20]); // EVM-shaped (20B + 12 zero)
        let forged = Transaction {
            from: PublicKey::new(from),
            ecdsa_verified: true, // attacker-asserted over the wire
            chain_id: Some(40204),
            ..Default::default()
        };

        // Single-tx gossip (NewTransaction).
        let wire = bincode::serialize(&NetworkMessage::NewTransaction {
            transaction: forged.clone(),
        })
        .expect("serialize");
        match NetworkMessage::decode_inbound(&wire).expect("decode_inbound") {
            NetworkMessage::NewTransaction { transaction } => assert!(
                !transaction.ecdsa_verified,
                "peer-asserted ecdsa_verified must be stripped at decode"
            ),
            other => panic!("unexpected variant: {other:?}"),
        }

        // Batch gossip (Transactions).
        let wire = bincode::serialize(&NetworkMessage::Transactions {
            transactions: vec![forged.clone(), forged],
        })
        .expect("serialize");
        match NetworkMessage::decode_inbound(&wire).expect("decode_inbound") {
            NetworkMessage::Transactions { transactions } => assert!(
                transactions.iter().all(|t| !t.ecdsa_verified),
                "every tx in a gossiped batch must be stripped"
            ),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn test_protocol_version_compatibility() {
        let v1 = ProtocolVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };
        let v2 = ProtocolVersion {
            major: 1,
            minor: 1,
            patch: 0,
        };
        let v3 = ProtocolVersion {
            major: 2,
            minor: 0,
            patch: 0,
        };

        assert!(v1.is_compatible(&v2));
        assert!(!v1.is_compatible(&v3));
    }

    #[test]
    fn test_message_priority() {
        let hello = NetworkMessage::Hello {
            version: ProtocolVersion::CURRENT,
            network_id: 1,
            genesis_hash: Hash::default(),
            head_height: 0,
            head_hash: Hash::default(),
            peer_id: "test".to_string(),
        };

        assert_eq!(hello.priority(), MessagePriority::Critical);

        // Create a test transaction
        let new_tx = NetworkMessage::NewTransaction {
            transaction: Transaction {
                hash: Hash::default(),
                nonce: 0,
                from: citrate_consensus::types::PublicKey::new([0; 32]),
                to: None,
                value: 0,
                gas_limit: 21000,
                gas_price: 1000000000,
                data: vec![],
                signature: citrate_consensus::types::Signature::new([0; 64]),
                tx_type: None,
                ..Default::default()
            },
        };

        assert_eq!(new_tx.priority(), MessagePriority::Normal);

        // GetBlocks should be critical
        let get_blocks = NetworkMessage::GetBlocks {
            from: Hash::default(),
            count: 10,
            step: 1,
        };
        assert_eq!(get_blocks.priority(), MessagePriority::Critical);

        // NewBlock should be high
        let nb = NetworkMessage::NewBlock {
            block: citrate_consensus::types::BlockBuilder::new().build_unhashed(),
        };
        assert_eq!(nb.priority(), MessagePriority::High);

        // GetPeers is low
        assert_eq!(NetworkMessage::GetPeers.priority(), MessagePriority::Low);
    }

    // -----------------------------------------------------------------------
    // Property-based tests (proptest)
    // -----------------------------------------------------------------------
    use proptest::prelude::*;

    proptest! {
        /// Property: NetworkMessage Ping serialization round-trip via bincode.
        #[test]
        fn prop_ping_pong_serialization_roundtrip(nonce in any::<u64>()) {
            let ping = NetworkMessage::Ping { nonce };
            let bytes = bincode::serialize(&ping).expect("serialize Ping");
            let recovered: NetworkMessage = bincode::deserialize(&bytes).expect("deserialize Ping");
            match recovered {
                NetworkMessage::Ping { nonce: n } => prop_assert_eq!(n, nonce),
                other => prop_assert!(false, "Expected Ping, got {:?}", other),
            }

            let pong = NetworkMessage::Pong { nonce };
            let bytes = bincode::serialize(&pong).expect("serialize Pong");
            let recovered: NetworkMessage = bincode::deserialize(&bytes).expect("deserialize Pong");
            match recovered {
                NetworkMessage::Pong { nonce: n } => prop_assert_eq!(n, nonce),
                other => prop_assert!(false, "Expected Pong, got {:?}", other),
            }
        }

        /// Property: ProtocolVersion compatibility is reflexive — a version is always compatible with itself.
        #[test]
        fn prop_protocol_version_self_compatible(major in any::<u16>(), minor in any::<u16>(), patch in any::<u16>()) {
            let v = ProtocolVersion { major, minor, patch };
            prop_assert!(v.is_compatible(&v), "Version must be compatible with itself");
        }
    }

    #[test]
    fn test_message_requires_response() {
        let ping = NetworkMessage::Ping { nonce: 42 };
        assert!(ping.requires_response());

        // Test a message that doesn't require response
        let pong = NetworkMessage::Pong { nonce: 42 };
        assert!(!pong.requires_response());
    }
}
