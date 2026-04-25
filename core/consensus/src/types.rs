// citrate/core/consensus/src/types.rs

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// Hash type for block and transaction identifiers
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, PartialOrd, Ord,
)]
pub struct Hash([u8; 32]);

impl Hash {
    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[..32]);
        Self(hash)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..8])
    }
}

/// Public key type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Signature type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn new(data: [u8; 64]) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid signature length"));
        }
        let mut data = [0u8; 64];
        data.copy_from_slice(&bytes);
        Ok(Signature(data))
    }
}

/// VRF proof for proposer selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfProof {
    pub proof: Vec<u8>,
    pub output: Hash,
}

/// GhostDAG consensus parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostDagParams {
    /// K-cluster parameter for blue set calculation
    pub k: u32,

    /// Maximum number of parents a block can have
    pub max_parents: usize,

    /// Maximum allowed blue score difference for reorg
    pub max_blue_score_diff: u64,

    /// Pruning window size
    pub pruning_window: u64,

    /// Finality depth
    pub finality_depth: u64,
}

impl Default for GhostDagParams {
    fn default() -> Self {
        Self {
            k: 18,           // Standard k-cluster parameter
            max_parents: 10, // Maximum 10 parents per block
            max_blue_score_diff: 1000,
            pruning_window: 100000,
            finality_depth: 100,
        }
    }
}

/// Block header containing consensus-critical fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub block_hash: Hash,
    pub selected_parent_hash: Hash,
    pub merge_parent_hashes: Vec<Hash>,
    pub timestamp: u64,
    pub height: u64,
    pub blue_score: u64,
    pub blue_work: u128,
    pub pruning_point: Hash,
    pub proposer_pubkey: PublicKey,
    pub vrf_reveal: VrfProof,

    /// EIP-1559 base fee per gas (in wei). Used for accurate fee history.
    /// Default 0 for backwards compatibility with older blocks.
    #[serde(default)]
    pub base_fee_per_gas: u64,

    /// Total gas used by all transactions in this block.
    /// Required for EIP-1559 base fee calculation.
    #[serde(default)]
    pub gas_used: u64,

    /// Block gas limit. Default is 30M gas.
    #[serde(default = "default_gas_limit")]
    pub gas_limit: u64,
}

fn default_gas_limit() -> u64 {
    30_000_000 // 30M gas default
}

/// Full block structure as specified in CLAUDE.md
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub state_root: Hash,
    pub tx_root: Hash,
    pub receipt_root: Hash,
    pub artifact_root: Hash,
    pub ghostdag_params: GhostDagParams,
    pub transactions: Vec<Transaction>,
    pub signature: Signature,

    /// AI models embedded in genesis block only (empty for all other blocks)
    #[serde(default)]
    pub embedded_models: Vec<EmbeddedModel>,

    /// Required model pins (genesis block only, empty for all other blocks)
    #[serde(default)]
    pub required_pins: Vec<RequiredModel>,

    // --- Learning extension fields (Paper II §6.1, Sprint M WP-M.2b) ---
    // These are optional sidecars. Non-learning nodes set them to None.
    // They are NOT included in compute_hash() — consensus is unaffected.

    /// Per-dimension embedding vector from this node's local model (~3 KB at d=768).
    #[serde(default)]
    pub learning_embedding: Option<Vec<f32>>,

    /// Per-dimension softmax-entropy confidence matching learning_embedding (~3 KB at d=768).
    #[serde(default)]
    pub learning_confidence: Option<Vec<f32>>,

    /// SHA3-256 commitment to gradient update, revealed in next block (32 bytes).
    #[serde(default)]
    pub gradient_commitment: Option<[u8; 32]>,

    /// MiMC hash of aggregated learning state at this block's checkpoint height.
    /// Only set for blocks at checkpoint boundaries (height % checkpoint_interval == 0).
    /// Zero hash for non-checkpoint blocks or below-quorum checkpoints.
    ///
    /// Theorem 3 guarantee: this field NEVER affects state_root computation.
    /// It is NOT included in compute_hash() — consensus ordering is unaffected.
    ///
    /// Verified by TLA+ spec StrobilationCheckpoint.tla (INV-4: StateRootIndependent).
    #[serde(default)]
    pub learning_root: Hash,
}

impl Block {
    /// Get the block hash
    pub fn hash(&self) -> Hash {
        self.header.block_hash
    }

    /// Compute the canonical block hash from all consensus-critical fields (C-05).
    ///
    /// This is the single authoritative hash function for blocks. It covers:
    /// - All header fields (parent, height, timestamp, blue score, proposer, VRF)
    /// - All commitment roots (state, tx, receipt, artifact)
    /// - Gas parameters
    ///
    /// Both the producer and the validator MUST use this function.
    pub fn compute_hash(&self) -> Hash {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();

        // Header fields
        hasher.update(self.header.version.to_le_bytes());
        hasher.update(self.header.selected_parent_hash.as_bytes());
        for parent in &self.header.merge_parent_hashes {
            hasher.update(parent.as_bytes());
        }
        hasher.update(self.header.timestamp.to_le_bytes());
        hasher.update(self.header.height.to_le_bytes());
        hasher.update(self.header.blue_score.to_le_bytes());
        hasher.update(self.header.blue_work.to_le_bytes());
        hasher.update(self.header.pruning_point.as_bytes());
        hasher.update(self.header.proposer_pubkey.as_bytes());
        hasher.update(&self.header.vrf_reveal.proof);
        hasher.update(self.header.vrf_reveal.output.as_bytes());
        hasher.update(self.header.base_fee_per_gas.to_le_bytes());
        hasher.update(self.header.gas_used.to_le_bytes());
        hasher.update(self.header.gas_limit.to_le_bytes());

        // Commitment roots (these bind the block body to the hash)
        hasher.update(self.state_root.as_bytes());
        hasher.update(self.tx_root.as_bytes());
        hasher.update(self.receipt_root.as_bytes());
        hasher.update(self.artifact_root.as_bytes());

        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes[..32]);
        Hash::new(hash_array)
    }

    /// Verify that the block's advertised hash matches the canonical computation.
    /// Returns false if the hash has been tampered with.
    pub fn verify_hash(&self) -> bool {
        self.header.block_hash == self.compute_hash()
    }

    /// Get selected parent
    pub fn selected_parent(&self) -> Hash {
        self.header.selected_parent_hash
    }

    /// Get all parent hashes (selected + merge)
    pub fn parents(&self) -> Vec<Hash> {
        let mut parents = vec![self.header.selected_parent_hash];
        parents.extend(self.header.merge_parent_hashes.clone());
        parents
    }

    /// Get blue score
    pub fn blue_score(&self) -> u64 {
        self.header.blue_score
    }

    /// Check if this is a genesis block
    pub fn is_genesis(&self) -> bool {
        self.header.selected_parent_hash == Hash::default()
            && self.header.merge_parent_hashes.is_empty()
    }
}

/// AI Transaction Types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    Standard = 0,
    ModelDeploy = 1,
    ModelUpdate = 2,
    InferenceRequest = 3,
    TrainingJob = 4,
    LoraAdapter = 5,
}

impl TransactionType {
    pub fn from_data(data: &[u8]) -> Self {
        if data.len() >= 4 {
            match &data[0..4] {
                [0x01, 0x00, 0x00, 0x00] => TransactionType::ModelDeploy,
                [0x02, 0x00, 0x00, 0x00] => TransactionType::ModelUpdate,
                [0x03, 0x00, 0x00, 0x00] => TransactionType::InferenceRequest,
                [0x04, 0x00, 0x00, 0x00] => TransactionType::TrainingJob,
                [0x05, 0x00, 0x00, 0x00] => TransactionType::LoraAdapter,
                _ => TransactionType::Standard,
            }
        } else {
            TransactionType::Standard
        }
    }

    /// Get priority weight for mempool ordering
    pub fn priority_weight(&self) -> u32 {
        match self {
            TransactionType::ModelDeploy => 100, // Highest priority
            TransactionType::TrainingJob => 90,
            TransactionType::ModelUpdate => 80,
            TransactionType::LoraAdapter => 70,
            TransactionType::InferenceRequest => 60,
            TransactionType::Standard => 10, // Lowest priority
        }
    }
}

/// Transaction structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Transaction {
    pub hash: Hash,
    pub nonce: u64,
    pub from: PublicKey,
    pub to: Option<PublicKey>,
    pub value: u128,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub data: Vec<u8>,
    pub signature: Signature,
    #[serde(default)]
    pub tx_type: Option<TransactionType>,

    /// EIP-2718 transaction type: 0=legacy, 1=EIP-2930, 2=EIP-1559
    #[serde(default)]
    pub eth_tx_type: u8,

    /// EIP-1559 max fee per gas (in wei)
    #[serde(default)]
    pub max_fee_per_gas: Option<u64>,

    /// EIP-1559 max priority fee per gas (in wei)
    #[serde(default)]
    pub max_priority_fee_per_gas: Option<u64>,

    /// EIP-2930/1559 access list: Vec of (address_bytes, Vec<storage_key_bytes>)
    #[serde(default)]
    #[allow(clippy::type_complexity)]
    pub access_list: Option<Vec<(Vec<u8>, Vec<Vec<u8>>)>>,

    /// Chain ID decoded from the transaction signature
    #[serde(default)]
    pub chain_id: Option<u64>,

    /// Set to true only when ECDSA signature was cryptographically verified
    /// during decode (eth_tx_decoder). Never trust address shape alone.
    #[serde(default)]
    pub ecdsa_verified: bool,
}

impl Transaction {
    /// Determine transaction type from data
    pub fn determine_type(&mut self) {
        self.tx_type = Some(TransactionType::from_data(&self.data));
    }

    /// Get transaction priority for mempool
    pub fn priority(&self) -> u64 {
        let type_weight = self
            .tx_type
            .unwrap_or(TransactionType::Standard)
            .priority_weight() as u64;

        // Combine type weight with gas price for final priority
        (type_weight * 1_000_000) + self.gas_price
    }
}

// ============================================================================
// AI Model Types for Genesis Block (Hybrid Architecture)
// ============================================================================

/// Unique identifier for AI models
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelId(pub String);

impl ModelId {
    pub fn from_name(name: &str) -> Self {
        Self(name.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ModelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type of AI model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelType {
    /// Embedding model for semantic search
    Embeddings,
    /// Small language model (< 1B params)
    TinyLLM,
    /// General purpose LLM
    GeneralLLM,
    /// Code-specialized model
    CodeLLM,
    /// Vision-language model
    VisionLLM,
    /// Diffusion model for image generation
    Diffusion,
}

/// Metadata about an AI model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    /// Human-readable name
    pub name: String,
    /// Version string (e.g., "1.0.0")
    pub version: String,
    /// Context length in tokens
    pub context_length: u32,
    /// Embedding dimension (for embedding models)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding_dim: Option<u32>,
    /// License (MIT, Apache 2.0, Llama 3.1, etc.)
    pub license: String,
    /// Model framework (GGUF, SafeTensors, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Model commitment carried in the genesis block.
///
/// **Post-WP-B change (2026-04-21):** the previous design carried raw GGUF
/// bytes in a `weights: Vec<u8>` field, which was an unbounded on-chain
/// data vector committed to `artifact_root`. That design was a latent
/// genesis-bloat footgun — see
/// [`.audit/2026-04-21-repo-walkthrough/02_GENESIS_AND_EMBEDDED_MODELS.md`].
///
/// The new shape carries only a 32-byte `weights_sha256` commitment;
/// the actual bytes live off-chain (IPFS, trusted mirror, or bundled
/// asset). Any node verifying the genesis block can fetch the bytes and
/// check `sha256(bytes) == weights_sha256` to detect tampering. Under
/// SHA-256 collision-resistance, tampering is infeasible.
///
/// Integrity properties are proven in
/// [`specs/tla/consensus/EmbeddedModelCommitment.tla`] — 7 invariants:
/// `TypeInv`, `CommitmentSound`, `ValidStatusImpliesMatch`,
/// `CommittedBlockFullyVerified`, `TamperDetection`,
/// `CommitmentStability`, `PerModelOnChainSizeBounded`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedModel {
    /// Unique model identifier
    pub model_id: ModelId,
    /// Type of model
    pub model_type: ModelType,
    /// SHA-256 commitment over the off-chain weight bytes (32 bytes,
    /// fixed-size). Replaces the pre-WP-B `weights: Vec<u8>` field.
    pub weights_sha256: Hash,
    /// Model metadata
    pub metadata: ModelMetadata,
}

impl EmbeddedModel {
    /// On-chain serialized size contribution of this model, in bytes.
    ///
    /// Post-WP-B this is a fixed upper bound driven by the commitment hash
    /// (32 bytes) plus small fixed-size metadata fields. The pre-WP-B
    /// equivalent returned `self.weights.len()`, which could be unbounded.
    ///
    /// Used by `estimate_block_size` in the sync layer to bound per-peer
    /// memory consumption during block propagation.
    pub fn size_bytes(&self) -> usize {
        // 32 bytes for the SHA-256 commitment + roughly bounded metadata.
        // Metadata strings (name, version, license, framework) are small;
        // enforce the bound at block-validation if tightening is needed.
        32 + Self::EMBEDDED_MODEL_METADATA_SIZE_UPPER_BOUND
    }

    /// Conservative upper bound on serialized metadata size per model.
    /// 512 bytes covers name/version/license/framework strings +
    /// fixed-size numeric fields with comfortable margin.
    pub const EMBEDDED_MODEL_METADATA_SIZE_UPPER_BOUND: usize = 512;

    /// The commitment to the off-chain weight bytes.
    ///
    /// Pre-WP-B this computed SHA-256 over `self.weights` each call.
    /// Post-WP-B it simply returns the stored commitment — callers that
    /// need to verify against actual bytes must fetch them off-chain and
    /// compare `sha256(fetched_bytes) == model.weights_hash()`.
    pub fn weights_hash(&self) -> Hash {
        self.weights_sha256
    }
}

/// Model required to be pinned on IPFS by validators
/// These models are verified via consensus but stored off-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredModel {
    /// Unique model identifier
    pub model_id: ModelId,
    /// IPFS content identifier
    pub ipfs_cid: String,
    /// SHA256 hash for verification
    pub sha256_hash: Hash,
    /// Size in bytes
    pub size_bytes: u64,
    /// Whether validators MUST pin this model
    pub must_pin: bool,
    /// Penalty in SALT tokens for not pinning
    pub slash_penalty: u128,
    /// Grace period in hours for new validators
    #[serde(default = "default_grace_period")]
    pub grace_period_hours: u64,
}

fn default_grace_period() -> u64 {
    24 // 24 hours default
}

impl RequiredModel {
    /// Create a new required model entry
    pub fn new(
        model_id: ModelId,
        ipfs_cid: String,
        sha256_hash: Hash,
        size_bytes: u64,
        slash_penalty: u128,
    ) -> Self {
        Self {
            model_id,
            ipfs_cid,
            sha256_hash,
            size_bytes,
            must_pin: true,
            slash_penalty,
            grace_period_hours: default_grace_period(),
        }
    }
}

/// Status of a validator's model pin
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinStatus {
    /// Model is pinned and verified
    Pinned,
    /// Model is not pinned
    Unpinned,
    /// Pin status not yet verified
    Unverified,
}

/// Record of a validator's pin check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorPinCheck {
    /// Validator's public key
    pub validator: PublicKey,
    /// Model CID being checked
    pub model_cid: String,
    /// Last check timestamp
    pub last_check: u64,
    /// Current status
    pub status: PinStatus,
    /// Last challenge-response proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_proof: Option<Vec<u8>>,
}

/// Builder for Block with sensible defaults.
/// All optional fields default to zero/empty/default values.
/// Required: at minimum, `height` should be set for non-default blocks.
///
/// # Examples
///
/// ```
/// use citrate_consensus::types::{BlockBuilder, Hash};
///
/// // Simple test block
/// let block = BlockBuilder::new().height(1).build();
///
/// // Production block with specific fields
/// let block = BlockBuilder::new()
///     .parent(Hash::new([1; 32]))
///     .height(5)
///     .timestamp(1234567890)
///     .build();
///
/// // Test block without hash computation
/// let block = BlockBuilder::new().height(1).build_unhashed();
/// ```
pub struct BlockBuilder {
    block: Block,
}

impl BlockBuilder {
    /// Create a new builder with all defaults (zero hashes, empty vecs, etc.)
    pub fn new() -> Self {
        Self {
            block: Block {
                header: BlockHeader {
                    version: 1,
                    block_hash: Hash::default(),
                    selected_parent_hash: Hash::default(),
                    merge_parent_hashes: vec![],
                    timestamp: 0,
                    height: 0,
                    blue_score: 0,
                    blue_work: 0,
                    pruning_point: Hash::default(),
                    proposer_pubkey: PublicKey::default(),
                    vrf_reveal: VrfProof {
                        proof: vec![],
                        output: Hash::default(),
                    },
                    base_fee_per_gas: 0,
                    gas_used: 0,
                    gas_limit: 30_000_000,
                },
                state_root: Hash::default(),
                tx_root: Hash::default(),
                receipt_root: Hash::default(),
                artifact_root: Hash::default(),
                ghostdag_params: GhostDagParams::default(),
                transactions: vec![],
                signature: Signature::default(),
                embedded_models: vec![],
                required_pins: vec![],
                learning_embedding: None,
                learning_confidence: None,
                gradient_commitment: None,
                learning_root: Hash::default(),
            },
        }
    }

    // --- Header field setters ---

    pub fn hash(mut self, hash: Hash) -> Self {
        self.block.header.block_hash = hash;
        self
    }
    pub fn parent(mut self, hash: Hash) -> Self {
        self.block.header.selected_parent_hash = hash;
        self
    }
    pub fn merge_parents(mut self, hashes: Vec<Hash>) -> Self {
        self.block.header.merge_parent_hashes = hashes;
        self
    }
    pub fn height(mut self, h: u64) -> Self {
        self.block.header.height = h;
        self
    }
    pub fn timestamp(mut self, ts: u64) -> Self {
        self.block.header.timestamp = ts;
        self
    }
    pub fn blue_score(mut self, score: u64) -> Self {
        self.block.header.blue_score = score;
        self
    }
    pub fn blue_work(mut self, work: u128) -> Self {
        self.block.header.blue_work = work;
        self
    }
    pub fn pruning_point(mut self, hash: Hash) -> Self {
        self.block.header.pruning_point = hash;
        self
    }
    pub fn proposer(mut self, pubkey: PublicKey) -> Self {
        self.block.header.proposer_pubkey = pubkey;
        self
    }
    pub fn vrf_reveal(mut self, proof: VrfProof) -> Self {
        self.block.header.vrf_reveal = proof;
        self
    }
    pub fn base_fee_per_gas(mut self, fee: u64) -> Self {
        self.block.header.base_fee_per_gas = fee;
        self
    }
    pub fn gas_used(mut self, gas: u64) -> Self {
        self.block.header.gas_used = gas;
        self
    }
    pub fn gas_limit(mut self, limit: u64) -> Self {
        self.block.header.gas_limit = limit;
        self
    }
    pub fn version(mut self, v: u32) -> Self {
        self.block.header.version = v;
        self
    }

    /// Set the full header at once (useful when header is pre-built)
    pub fn header(mut self, header: BlockHeader) -> Self {
        self.block.header = header;
        self
    }

    // --- Body field setters ---

    pub fn state_root(mut self, root: Hash) -> Self {
        self.block.state_root = root;
        self
    }
    pub fn tx_root(mut self, root: Hash) -> Self {
        self.block.tx_root = root;
        self
    }
    pub fn receipt_root(mut self, root: Hash) -> Self {
        self.block.receipt_root = root;
        self
    }
    pub fn artifact_root(mut self, root: Hash) -> Self {
        self.block.artifact_root = root;
        self
    }
    pub fn ghostdag_params(mut self, params: GhostDagParams) -> Self {
        self.block.ghostdag_params = params;
        self
    }
    pub fn transactions(mut self, txs: Vec<Transaction>) -> Self {
        self.block.transactions = txs;
        self
    }
    pub fn signature(mut self, sig: Signature) -> Self {
        self.block.signature = sig;
        self
    }
    pub fn embedded_models(mut self, models: Vec<EmbeddedModel>) -> Self {
        self.block.embedded_models = models;
        self
    }
    pub fn required_pins(mut self, pins: Vec<RequiredModel>) -> Self {
        self.block.required_pins = pins;
        self
    }
    pub fn learning_embedding(mut self, emb: Option<Vec<f32>>) -> Self {
        self.block.learning_embedding = emb;
        self
    }
    pub fn learning_confidence(mut self, conf: Option<Vec<f32>>) -> Self {
        self.block.learning_confidence = conf;
        self
    }
    pub fn gradient_commitment(mut self, commitment: Option<[u8; 32]>) -> Self {
        self.block.gradient_commitment = commitment;
        self
    }
    pub fn learning_root(mut self, root: Hash) -> Self {
        self.block.learning_root = root;
        self
    }

    /// Build the block. Computes block_hash from contents.
    pub fn build(mut self) -> Block {
        self.block.header.block_hash = self.block.compute_hash();
        self.block
    }

    /// Build without computing hash (for tests that set hash manually or
    /// for intermediate blocks where hash will be set later).
    pub fn build_unhashed(self) -> Block {
        self.block
    }
}

impl Default for BlockBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Blue set information for a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueSet {
    /// Set of blue block hashes
    pub blocks: HashSet<Hash>,

    /// Blue score (cumulative blue blocks in ancestry)
    pub score: u64,

    /// Blue work (cumulative difficulty)
    pub work: u128,
}

impl BlueSet {
    pub fn new() -> Self {
        Self {
            blocks: HashSet::new(),
            score: 0,
            work: 0,
        }
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.blocks.contains(hash)
    }

    pub fn insert(&mut self, hash: Hash) {
        self.blocks.insert(hash);
        self.score += 1;
    }

    pub fn size(&self) -> usize {
        self.blocks.len()
    }
}

impl Default for BlueSet {
    fn default() -> Self {
        Self::new()
    }
}

/// DAG relationship between blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagRelation {
    pub block: Hash,
    pub selected_parent: Hash,
    pub merge_parents: Vec<Hash>,
    pub children: Vec<Hash>,
    pub blue_set: BlueSet,
    pub is_chain_block: bool,
    /// Height of this block in the DAG. Used by `is_ancestor_of` to
    /// short-circuit structurally impossible ancestry queries
    /// (audit finding H-07): if `ancestor.height >= descendant.height`
    /// and the hashes differ, ancestry is impossible regardless of
    /// BFS budget. `#[serde(default)]` keeps in-memory cache loaded
    /// from older test fixtures backward-compatible (height 0 falls
    /// back to the legacy BFS-only path).
    #[serde(default)]
    pub height: u64,
}

/// Represents a tip in the DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tip {
    pub hash: Hash,
    pub blue_score: u64,
    pub height: u64,
    pub timestamp: u64,
}

impl Tip {
    pub fn new(block: &Block) -> Self {
        Self {
            hash: block.hash(),
            blue_score: block.header.blue_score,
            height: block.header.height,
            timestamp: block.header.timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_display() {
        let hash = Hash::new([0x12; 32]);
        assert_eq!(hash.to_hex().len(), 64);
        assert_eq!(format!("{}", hash), "12121212");
    }

    #[test]
    fn test_block_parents() {
        let mut block = create_test_block();
        block.header.selected_parent_hash = Hash::new([1; 32]);
        block.header.merge_parent_hashes = vec![Hash::new([2; 32]), Hash::new([3; 32])];

        let parents = block.parents();
        assert_eq!(parents.len(), 3);
        assert_eq!(parents[0], Hash::new([1; 32]));
        assert_eq!(parents[1], Hash::new([2; 32]));
        assert_eq!(parents[2], Hash::new([3; 32]));
    }

    #[test]
    fn test_blue_set() {
        let mut blue_set = BlueSet::new();
        assert_eq!(blue_set.score, 0);

        blue_set.insert(Hash::new([1; 32]));
        blue_set.insert(Hash::new([2; 32]));

        assert_eq!(blue_set.score, 2);
        assert_eq!(blue_set.size(), 2);
        assert!(blue_set.contains(&Hash::new([1; 32])));
        assert!(!blue_set.contains(&Hash::new([3; 32])));
    }

    fn create_test_block() -> Block {
        BlockBuilder::new().build_unhashed()
    }

    // PC-T16a: Block without learning fields round-trips via JSON
    #[test]
    fn test_block_no_learning_fields_roundtrip() {
        let block = create_test_block();
        assert!(block.learning_embedding.is_none());
        assert!(block.learning_confidence.is_none());
        assert!(block.gradient_commitment.is_none());

        let json = serde_json::to_string(&block).unwrap();
        let deserialized: Block = serde_json::from_str(&json).unwrap();
        assert!(deserialized.learning_embedding.is_none());
        assert!(deserialized.learning_confidence.is_none());
        assert!(deserialized.gradient_commitment.is_none());
    }

    // PC-T16b: Block with all 3 learning fields round-trips
    #[test]
    fn test_block_with_learning_fields_roundtrip() {
        let mut block = create_test_block();
        block.learning_embedding = Some(vec![0.1, 0.2, 0.3]);
        block.learning_confidence = Some(vec![0.9, 0.8, 0.7]);
        block.gradient_commitment = Some([0xAA; 32]);

        let json = serde_json::to_string(&block).unwrap();
        let deserialized: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.learning_embedding, Some(vec![0.1, 0.2, 0.3]));
        assert_eq!(deserialized.learning_confidence, Some(vec![0.9, 0.8, 0.7]));
        assert_eq!(deserialized.gradient_commitment, Some([0xAA; 32]));
    }

    // PC-T16c: Learning fields do NOT affect compute_hash
    #[test]
    fn test_learning_fields_excluded_from_hash() {
        let block_a = create_test_block();
        let mut block_b = create_test_block();
        block_b.learning_embedding = Some(vec![1.0, 2.0, 3.0]);
        block_b.learning_confidence = Some(vec![0.5, 0.5, 0.5]);
        block_b.gradient_commitment = Some([0xFF; 32]);

        // Hash must be identical — learning fields are NOT consensus-critical
        assert_eq!(block_a.compute_hash(), block_b.compute_hash());
    }

    // WP-F.3: learning_root does NOT affect compute_hash (Theorem 3).
    // Per StrobilationCheckpoint.tla INV-4: StateRootIndependent.
    #[test]
    fn test_learning_root_excluded_from_hash() {
        let block_a = create_test_block();
        let mut block_b = create_test_block();
        block_b.learning_root = Hash::new([0xFF; 32]);

        // Different learning_root must NOT change the block hash
        assert_eq!(block_a.compute_hash(), block_b.compute_hash());
    }

    // WP-F.3: learning_root defaults to zero for backward compatibility.
    #[test]
    fn test_learning_root_default_zero() {
        let block = create_test_block();
        assert_eq!(block.learning_root, Hash::default());
    }

    // WP-F.3: learning_root serialization roundtrip via JSON.
    #[test]
    fn test_learning_root_serialization_roundtrip() {
        let mut block = create_test_block();
        block.learning_root = Hash::new([0xAB; 32]);

        let json = serde_json::to_string(&block).unwrap();
        let deserialized: Block = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.learning_root, Hash::new([0xAB; 32]));
    }

    // WP-F.3: Backward compatibility — old JSON without learning_root deserializes.
    #[test]
    fn test_learning_root_backward_compat() {
        // Simulate old block JSON without the learning_root field
        let block = create_test_block();
        let mut json: serde_json::Value = serde_json::to_value(&block).unwrap();
        // Remove learning_root to simulate an old format
        json.as_object_mut().unwrap().remove("learning_root");
        let json_str = serde_json::to_string(&json).unwrap();
        let deserialized: Block = serde_json::from_str(&json_str).unwrap();
        // Should default to zero hash
        assert_eq!(deserialized.learning_root, Hash::default());
    }

    // LC.2.0: BlockBuilder tests

    #[test]
    fn test_block_builder_defaults() {
        let block = BlockBuilder::new().build_unhashed();
        assert_eq!(block.header.version, 1);
        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.timestamp, 0);
        assert_eq!(block.header.blue_score, 0);
        assert_eq!(block.header.blue_work, 0);
        assert_eq!(block.header.block_hash, Hash::default());
        assert_eq!(block.header.selected_parent_hash, Hash::default());
        assert!(block.header.merge_parent_hashes.is_empty());
        assert_eq!(block.header.gas_limit, 30_000_000);
        assert_eq!(block.state_root, Hash::default());
        assert_eq!(block.tx_root, Hash::default());
        assert_eq!(block.receipt_root, Hash::default());
        assert_eq!(block.artifact_root, Hash::default());
        assert!(block.transactions.is_empty());
        assert!(block.embedded_models.is_empty());
        assert!(block.required_pins.is_empty());
        assert!(block.learning_embedding.is_none());
        assert!(block.learning_confidence.is_none());
        assert!(block.gradient_commitment.is_none());
        assert_eq!(block.learning_root, Hash::default());
    }

    #[test]
    fn test_block_builder_sets_fields() {
        let parent = Hash::new([1; 32]);
        let merge = vec![Hash::new([2; 32]), Hash::new([3; 32])];
        let state = Hash::new([4; 32]);
        let proposer = PublicKey::new([5; 32]);

        let block = BlockBuilder::new()
            .parent(parent)
            .merge_parents(merge.clone())
            .height(42)
            .timestamp(99999)
            .blue_score(10)
            .blue_work(500)
            .state_root(state)
            .proposer(proposer)
            .base_fee_per_gas(1_000_000_000)
            .gas_limit(15_000_000)
            .version(2)
            .build_unhashed();

        assert_eq!(block.header.selected_parent_hash, parent);
        assert_eq!(block.header.merge_parent_hashes, merge);
        assert_eq!(block.header.height, 42);
        assert_eq!(block.header.timestamp, 99999);
        assert_eq!(block.header.blue_score, 10);
        assert_eq!(block.header.blue_work, 500);
        assert_eq!(block.state_root, state);
        assert_eq!(block.header.proposer_pubkey, proposer);
        assert_eq!(block.header.base_fee_per_gas, 1_000_000_000);
        assert_eq!(block.header.gas_limit, 15_000_000);
        assert_eq!(block.header.version, 2);
    }

    #[test]
    fn test_block_builder_computes_hash() {
        let block = BlockBuilder::new()
            .height(5)
            .timestamp(12345)
            .build();

        // build() should compute the hash
        assert_ne!(block.header.block_hash, Hash::default());
        // The hash should match compute_hash()
        assert_eq!(block.header.block_hash, block.compute_hash());
    }

    #[test]
    fn test_block_builder_build_unhashed() {
        let block = BlockBuilder::new()
            .height(5)
            .timestamp(12345)
            .build_unhashed();

        // build_unhashed() should leave block_hash as default
        assert_eq!(block.header.block_hash, Hash::default());
    }

    #[test]
    fn test_block_builder_header_setter() {
        let header = BlockHeader {
            version: 3,
            block_hash: Hash::new([0xAA; 32]),
            selected_parent_hash: Hash::new([0xBB; 32]),
            merge_parent_hashes: vec![],
            timestamp: 55555,
            height: 100,
            blue_score: 50,
            blue_work: 9999,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([7; 32]),
            vrf_reveal: VrfProof {
                proof: vec![1, 2, 3],
                output: Hash::new([0xCC; 32]),
            },
            base_fee_per_gas: 2_000_000_000,
            gas_used: 21000,
            gas_limit: 15_000_000,
        };

        let block = BlockBuilder::new()
            .header(header.clone())
            .state_root(Hash::new([0xDD; 32]))
            .build_unhashed();

        assert_eq!(block.header.version, 3);
        assert_eq!(block.header.height, 100);
        assert_eq!(block.header.timestamp, 55555);
        assert_eq!(block.state_root, Hash::new([0xDD; 32]));
    }

    #[test]
    fn test_block_builder_default_trait() {
        let builder = BlockBuilder::default();
        let block = builder.build_unhashed();
        assert_eq!(block.header.version, 1);
        assert_eq!(block.header.height, 0);
    }
}
