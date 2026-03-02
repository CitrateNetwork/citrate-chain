// citrate/core/consensus/src/checkpoint.rs
//
// WP-S.3: Committee BFT Checkpoints for deterministic finality.
// Complements depth-based finality with committee signature aggregation.

use crate::dag_store::{cf, DagStore, KvStore};
use crate::types::{Hash, PublicKey, Signature};
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Error, Debug, Clone)]
pub enum CheckpointError {
    #[error("Checkpoint block not found: {0}")]
    BlockNotFound(Hash),

    #[error("Not at checkpoint boundary (height must be multiple of interval)")]
    NotCheckpointBoundary,

    #[error("Checkpoint already exists for height {0}")]
    AlreadyExists(u64),

    #[error("Validator not in committee: {0:?}")]
    NotInCommittee(PublicKey),

    #[error("Duplicate vote from {0:?}")]
    DuplicateVote(PublicKey),

    #[error("Invalid signature from {0:?}")]
    InvalidSignature(PublicKey),

    #[error("Quorum not reached: {0}/{1} votes")]
    QuorumNotReached(usize, usize),

    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Checkpoint configuration.
#[derive(Debug, Clone)]
pub struct CheckpointConfig {
    /// Interval in blocks between checkpoints.
    pub interval: u64,

    /// Committee size (number of validators selected for each checkpoint).
    pub committee_size: usize,

    /// Quorum threshold (minimum votes for finalization).
    /// Default: 67/100 (2/3 + 1).
    pub quorum_threshold: usize,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            interval: 50,
            committee_size: 100,
            quorum_threshold: 67,
        }
    }
}

impl CheckpointConfig {
    /// Testing config with smaller parameters.
    pub fn for_testing() -> Self {
        Self {
            interval: 5,
            committee_size: 5,
            quorum_threshold: 4,
        }
    }

    /// Check if a height is a checkpoint boundary.
    pub fn is_checkpoint_height(&self, height: u64) -> bool {
        height > 0 && height % self.interval == 0
    }
}

/// A checkpoint vote from a committee member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointVote {
    /// The checkpoint height being voted on.
    pub height: u64,

    /// The block hash at the checkpoint height.
    pub block_hash: Hash,

    /// The voter's public key.
    pub voter: PublicKey,

    /// Signature over (height || block_hash) by the voter.
    pub signature: Signature,
}

/// Status of a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointStatus {
    /// Checkpoint proposed, collecting votes.
    Pending,

    /// Quorum reached, checkpoint finalized.
    Finalized,
}

/// A finalized checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The checkpoint height.
    pub height: u64,

    /// The block hash at the checkpoint height.
    pub block_hash: Hash,

    /// The committee that voted on this checkpoint.
    pub committee: Vec<PublicKey>,

    /// Collected votes (voter pubkey → signature).
    pub votes: HashMap<PublicKey, Signature>,

    /// Checkpoint status.
    pub status: CheckpointStatus,
}

impl Checkpoint {
    /// Check if quorum has been reached.
    pub fn has_quorum(&self, threshold: usize) -> bool {
        self.votes.len() >= threshold
    }

    /// Get the number of votes collected.
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }
}

/// Deterministic committee selection for checkpoint voting.
pub struct CommitteeSelector;

impl CommitteeSelector {
    /// Select a committee deterministically from the validator set.
    /// Uses the VRF output at the checkpoint boundary block for randomness.
    ///
    /// Selection is weighted by stake: higher-stake validators are more likely to be selected.
    /// The algorithm is deterministic — all honest nodes will compute the same committee.
    pub fn select(
        validators: &[(PublicKey, u128)], // (pubkey, stake)
        checkpoint_height: u64,
        vrf_seed: &Hash,
        committee_size: usize,
    ) -> Vec<PublicKey> {
        if validators.is_empty() {
            return vec![];
        }

        let actual_size = committee_size.min(validators.len());

        // Score each validator deterministically using VRF seed + their pubkey
        let mut scored: Vec<(PublicKey, u64)> = validators
            .iter()
            .map(|(pk, stake)| {
                let mut hasher = sha2::Sha256::new();
                use sha2::Digest;
                hasher.update(vrf_seed.as_bytes());
                hasher.update(pk.as_bytes());
                hasher.update(checkpoint_height.to_le_bytes());
                let hash = hasher.finalize();

                // Score = hash_value weighted by stake
                let hash_val = u64::from_be_bytes(hash[0..8].try_into().unwrap());
                // Weight by sqrt(stake) to balance fairness with stake
                let weight = (*stake as f64).sqrt() as u64;
                let score = hash_val.wrapping_mul(weight.max(1));
                (*pk, score)
            })
            .collect();

        // Sort by score (deterministic tie-breaking via pubkey bytes)
        scored.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });

        // Take the top committee_size validators
        scored.into_iter().take(actual_size).map(|(pk, _)| pk).collect()
    }
}

/// Verify a checkpoint vote signature cryptographically (ed25519).
///
/// The canonical vote message is: `height(8 LE bytes) || block_hash(32 bytes)` = 40 bytes.
/// The voter must sign this message with their ed25519 private key.
fn verify_vote_signature(vote: &CheckpointVote) -> Result<(), CheckpointError> {
    // Build canonical message: height(8 LE) || block_hash(32) = 40 bytes
    let mut message = Vec::with_capacity(40);
    message.extend_from_slice(&vote.height.to_le_bytes());
    message.extend_from_slice(vote.block_hash.as_bytes());

    let pubkey = VerifyingKey::from_bytes(vote.voter.as_bytes())
        .map_err(|_| CheckpointError::InvalidSignature(vote.voter))?;
    let sig = DalekSignature::from_bytes(vote.signature.as_bytes());

    pubkey
        .verify(&message, &sig)
        .map_err(|_| CheckpointError::InvalidSignature(vote.voter))
}

/// Checkpoint manager — proposes, collects votes, and finalizes checkpoints.
pub struct CheckpointManager {
    config: CheckpointConfig,
    dag_store: Arc<DagStore>,

    /// Active checkpoints being collected.
    pending: RwLock<HashMap<u64, Checkpoint>>,

    /// Finalized checkpoints (height → checkpoint).
    finalized: RwLock<HashMap<u64, Checkpoint>>,

    /// Latest finalized checkpoint height.
    latest_finalized_height: RwLock<u64>,

    /// Optional persistent backend for checkpoint storage.
    persistent: Option<Arc<dyn KvStore>>,

    /// Replay protection: tracks (height, voter) pairs already seen.
    voted: RwLock<HashSet<(u64, PublicKey)>>,
}

impl CheckpointManager {
    pub fn new(config: CheckpointConfig, dag_store: Arc<DagStore>) -> Self {
        Self {
            config,
            dag_store,
            pending: RwLock::new(HashMap::new()),
            finalized: RwLock::new(HashMap::new()),
            latest_finalized_height: RwLock::new(0),
            persistent: None,
            voted: RwLock::new(HashSet::new()),
        }
    }

    /// Create with persistent storage for checkpoint durability.
    pub fn with_persistence(
        config: CheckpointConfig,
        dag_store: Arc<DagStore>,
        kv: Arc<dyn KvStore>,
    ) -> Self {
        let mut mgr = Self::new(config, dag_store);
        // Load finalized checkpoints from storage
        if let Ok(entries) = kv.kv_iter_cf(cf::DAG_METADATA) {
            for (key, value) in entries {
                if key.starts_with(b"checkpoint:") {
                    if let Ok(cp) = bincode::deserialize::<Checkpoint>(&value) {
                        if cp.status == CheckpointStatus::Finalized {
                            let mut latest = mgr.latest_finalized_height.try_write().unwrap();
                            if cp.height > *latest {
                                *latest = cp.height;
                            }
                            mgr.finalized.try_write().unwrap().insert(cp.height, cp);
                        }
                    }
                }
            }
        }
        mgr.persistent = Some(kv);
        // voted is already initialized via new()
        mgr
    }

    /// Get the checkpoint config.
    pub fn config(&self) -> &CheckpointConfig {
        &self.config
    }

    /// Get the latest finalized checkpoint height.
    pub async fn latest_finalized_height(&self) -> u64 {
        *self.latest_finalized_height.read().await
    }

    /// Get a finalized checkpoint by height.
    pub async fn get_checkpoint(&self, height: u64) -> Option<Checkpoint> {
        self.finalized.read().await.get(&height).cloned()
    }

    /// Propose a new checkpoint at the given height.
    ///
    /// The block at `height` must exist in the DAG, and `height` must be
    /// a valid checkpoint boundary.
    pub async fn propose(
        &self,
        height: u64,
        block_hash: Hash,
        committee: Vec<PublicKey>,
    ) -> Result<(), CheckpointError> {
        if !self.config.is_checkpoint_height(height) {
            return Err(CheckpointError::NotCheckpointBoundary);
        }

        // Check block exists
        if !self.dag_store.has_block(&block_hash).await {
            return Err(CheckpointError::BlockNotFound(block_hash));
        }

        let mut pending = self.pending.write().await;
        if pending.contains_key(&height) {
            return Err(CheckpointError::AlreadyExists(height));
        }

        // Also check if already finalized
        if self.finalized.read().await.contains_key(&height) {
            return Err(CheckpointError::AlreadyExists(height));
        }

        let checkpoint = Checkpoint {
            height,
            block_hash,
            committee,
            votes: HashMap::new(),
            status: CheckpointStatus::Pending,
        };

        info!("Proposed checkpoint at height {} for block {}", height, block_hash);
        pending.insert(height, checkpoint);
        Ok(())
    }

    /// Submit a vote for a pending checkpoint.
    ///
    /// Returns `true` if quorum was reached by this vote.
    pub async fn submit_vote(&self, vote: CheckpointVote) -> Result<bool, CheckpointError> {
        // Replay protection: reject if (height, voter) already seen
        {
            let mut voted = self.voted.write().await;
            if !voted.insert((vote.height, vote.voter)) {
                return Err(CheckpointError::DuplicateVote(vote.voter));
            }
        }

        let mut pending = self.pending.write().await;

        let checkpoint = pending
            .get_mut(&vote.height)
            .ok_or(CheckpointError::BlockNotFound(Hash::default()))?;

        // Verify voter is in committee
        let committee_set: HashSet<&PublicKey> = checkpoint.committee.iter().collect();
        if !committee_set.contains(&vote.voter) {
            return Err(CheckpointError::NotInCommittee(vote.voter));
        }

        // Check for duplicate vote (also checked by voted set above)
        if checkpoint.votes.contains_key(&vote.voter) {
            return Err(CheckpointError::DuplicateVote(vote.voter));
        }

        // Verify vote is for the correct block
        if vote.block_hash != checkpoint.block_hash {
            return Err(CheckpointError::InvalidSignature(vote.voter));
        }

        // Cryptographic ed25519 signature verification
        verify_vote_signature(&vote)?;

        debug!(
            "Vote from {:?} for checkpoint at height {} ({}/{})",
            &vote.voter.as_bytes()[..4],
            vote.height,
            checkpoint.votes.len() + 1,
            self.config.quorum_threshold
        );

        checkpoint.votes.insert(vote.voter, vote.signature);

        // Check quorum
        if checkpoint.has_quorum(self.config.quorum_threshold) {
            return Ok(true);
        }

        Ok(false)
    }

    /// Finalize a checkpoint that has reached quorum.
    ///
    /// Moves the checkpoint from pending to finalized, marks the block as finalized
    /// in the DAG store, and persists to storage if available.
    pub async fn finalize_checkpoint(&self, height: u64) -> Result<Checkpoint, CheckpointError> {
        let mut pending = self.pending.write().await;
        let mut checkpoint = pending
            .remove(&height)
            .ok_or(CheckpointError::BlockNotFound(Hash::default()))?;

        if !checkpoint.has_quorum(self.config.quorum_threshold) {
            // Put it back
            pending.insert(height, checkpoint);
            return Err(CheckpointError::QuorumNotReached(
                pending[&height].votes.len(),
                self.config.quorum_threshold,
            ));
        }

        checkpoint.status = CheckpointStatus::Finalized;

        // Mark the block as finalized in the DAG store
        if let Err(e) = self.dag_store.finalize_block(&checkpoint.block_hash).await {
            warn!("Failed to finalize checkpoint block in DAG: {}", e);
        }

        // Persist to storage
        if let Some(ref kv) = self.persistent {
            let key = format!("checkpoint:{}", height);
            let bytes = bincode::serialize(&checkpoint).unwrap_or_default();
            if let Err(e) = kv.kv_put(cf::DAG_METADATA, key.as_bytes(), &bytes) {
                warn!("Failed to persist checkpoint at height {}: {}", height, e);
            }
        }

        // Update latest finalized height
        let mut latest = self.latest_finalized_height.write().await;
        if height > *latest {
            *latest = height;
        }

        info!(
            "Finalized checkpoint at height {} with {}/{} votes",
            height,
            checkpoint.votes.len(),
            self.config.quorum_threshold
        );

        let cp = checkpoint.clone();
        self.finalized.write().await.insert(height, checkpoint);

        Ok(cp)
    }

    /// Get the status of a checkpoint at a given height.
    pub async fn checkpoint_status(&self, height: u64) -> Option<CheckpointStatus> {
        if let Some(cp) = self.finalized.read().await.get(&height) {
            return Some(cp.status.clone());
        }
        if let Some(cp) = self.pending.read().await.get(&height) {
            return Some(cp.status.clone());
        }
        None
    }

    /// Get pending vote count for a checkpoint.
    pub async fn pending_vote_count(&self, height: u64) -> Option<usize> {
        self.pending.read().await.get(&height).map(|cp| cp.vote_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Generate a deterministic ed25519 signing key from a seed byte.
    fn make_signing_key(id: u8) -> SigningKey {
        let mut seed = [0u8; 32];
        seed[0] = id;
        SigningKey::from_bytes(&seed)
    }

    /// Get the PublicKey for a given seed byte.
    fn make_pubkey(id: u8) -> PublicKey {
        let sk = make_signing_key(id);
        let vk = sk.verifying_key();
        PublicKey::new(vk.to_bytes())
    }

    /// Sign a checkpoint vote's canonical message with the given signing key.
    fn sign_vote(height: u64, block_hash: &Hash, signing_key: &SigningKey) -> Signature {
        let mut message = Vec::with_capacity(40);
        message.extend_from_slice(&height.to_le_bytes());
        message.extend_from_slice(block_hash.as_bytes());
        let sig = signing_key.sign(&message);
        Signature::new(sig.to_bytes())
    }

    /// Create a properly signed CheckpointVote for testing.
    fn make_signed_vote(id: u8, height: u64, block_hash: &Hash) -> CheckpointVote {
        let sk = make_signing_key(id);
        CheckpointVote {
            height,
            block_hash: *block_hash,
            voter: make_pubkey(id),
            signature: sign_vote(height, block_hash, &sk),
        }
    }

    fn create_test_block(hash: [u8; 32], height: u64, parent: Hash) -> crate::types::Block {
        use crate::types::*;
        Block {
            header: BlockHeader {
                version: 1,
                block_hash: Hash::new(hash),
                selected_parent_hash: parent,
                merge_parent_hashes: vec![],
                timestamp: 0,
                height,
                blue_score: 0,
                blue_work: 0,
                pruning_point: Hash::default(),
                proposer_pubkey: PublicKey::new([0; 32]),
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
            signature: Signature::new([0; 64]),
            embedded_models: vec![],
            required_pins: vec![],
            learning_embedding: None,
            learning_confidence: None,
            gradient_commitment: None,
        }
    }

    async fn build_chain(dag: &DagStore, length: usize) -> Vec<crate::types::Block> {
        let mut blocks = vec![];
        let mut parent = Hash::default();
        for i in 0..length {
            let block = create_test_block([(i + 1) as u8; 32], i as u64, parent);
            dag.store_block(block.clone()).await.unwrap();
            parent = block.hash();
            blocks.push(block);
        }
        blocks
    }

    /// Committee selection is deterministic.
    #[test]
    fn test_committee_selection_determinism() {
        let validators: Vec<(PublicKey, u128)> = (0..10)
            .map(|i| (make_pubkey(i), 1000 * (i as u128 + 1)))
            .collect();
        let seed = Hash::new([42; 32]);

        let committee1 = CommitteeSelector::select(&validators, 50, &seed, 5);
        let committee2 = CommitteeSelector::select(&validators, 50, &seed, 5);

        assert_eq!(committee1, committee2);
        assert_eq!(committee1.len(), 5);
    }

    /// Different seeds produce different committees.
    #[test]
    fn test_committee_different_seeds() {
        let validators: Vec<(PublicKey, u128)> = (0..20)
            .map(|i| (make_pubkey(i), 1000))
            .collect();

        let c1 = CommitteeSelector::select(&validators, 50, &Hash::new([1; 32]), 5);
        let c2 = CommitteeSelector::select(&validators, 50, &Hash::new([2; 32]), 5);

        // Very unlikely to be the same with different seeds
        assert_ne!(c1, c2);
    }

    /// Quorum threshold: 3 rejected, 4 accepted (for test config with quorum=4).
    #[tokio::test]
    async fn test_quorum_threshold() {
        let dag = Arc::new(DagStore::new());
        let config = CheckpointConfig::for_testing(); // interval=5, committee=5, quorum=4
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag);

        let committee: Vec<PublicKey> = (0..5).map(make_pubkey).collect();
        let checkpoint_block = &blocks[5]; // height 5

        mgr.propose(5, checkpoint_block.hash(), committee.clone())
            .await
            .unwrap();

        // Submit 3 votes (below quorum of 4)
        for i in 0..3u8 {
            let vote = make_signed_vote(i, 5, &checkpoint_block.hash());
            let quorum_reached = mgr.submit_vote(vote).await.unwrap();
            assert!(!quorum_reached, "Quorum should not be reached with {} votes", i + 1);
        }

        // 4th vote reaches quorum
        let vote = make_signed_vote(3, 5, &checkpoint_block.hash());
        let quorum_reached = mgr.submit_vote(vote).await.unwrap();
        assert!(quorum_reached, "Quorum should be reached with 4 votes");
    }

    /// Zero signature is rejected.
    #[tokio::test]
    async fn test_zero_signature_rejected() {
        let dag = Arc::new(DagStore::new());
        let config = CheckpointConfig::for_testing();
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag);

        let committee: Vec<PublicKey> = (0..5).map(make_pubkey).collect();
        mgr.propose(5, blocks[5].hash(), committee).await.unwrap();

        let vote = CheckpointVote {
            height: 5,
            block_hash: blocks[5].hash(),
            voter: make_pubkey(0),
            signature: Signature::new([0; 64]), // Zero signature
        };
        let result = mgr.submit_vote(vote).await;
        assert!(matches!(result, Err(CheckpointError::InvalidSignature(_))));
    }

    /// Invalid (tampered) signature is rejected by crypto verification.
    #[tokio::test]
    async fn test_invalid_signature_rejected() {
        let dag = Arc::new(DagStore::new());
        let config = CheckpointConfig::for_testing();
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag);

        let committee: Vec<PublicKey> = (0..5).map(make_pubkey).collect();
        mgr.propose(5, blocks[5].hash(), committee).await.unwrap();

        // Create a vote with non-zero but cryptographically invalid signature
        let vote = CheckpointVote {
            height: 5,
            block_hash: blocks[5].hash(),
            voter: make_pubkey(0),
            signature: Signature::new([0xAB; 64]), // Non-zero but invalid
        };
        let result = mgr.submit_vote(vote).await;
        assert!(matches!(result, Err(CheckpointError::InvalidSignature(_))));
    }

    /// Valid cryptographic signature is accepted.
    #[tokio::test]
    async fn test_valid_signature_accepted() {
        let dag = Arc::new(DagStore::new());
        let config = CheckpointConfig::for_testing();
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag);

        let committee: Vec<PublicKey> = (0..5).map(make_pubkey).collect();
        mgr.propose(5, blocks[5].hash(), committee).await.unwrap();

        let vote = make_signed_vote(0, 5, &blocks[5].hash());
        let result = mgr.submit_vote(vote).await;
        assert!(result.is_ok());
    }

    /// Checkpoint finalization propagates to DagStore.
    #[tokio::test]
    async fn test_checkpoint_finalization_propagates() {
        let dag = Arc::new(DagStore::new());
        let config = CheckpointConfig::for_testing(); // quorum=4
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag.clone());

        let committee: Vec<PublicKey> = (0..5).map(make_pubkey).collect();
        mgr.propose(5, blocks[5].hash(), committee).await.unwrap();

        // Submit 4 signed votes to reach quorum
        for i in 0..4u8 {
            let vote = make_signed_vote(i, 5, &blocks[5].hash());
            mgr.submit_vote(vote).await.unwrap();
        }

        // Finalize
        let cp = mgr.finalize_checkpoint(5).await.unwrap();
        assert_eq!(cp.status, CheckpointStatus::Finalized);
        assert_eq!(cp.votes.len(), 4);

        // Block should be marked finalized in DAG store
        assert!(dag.is_finalized(&blocks[5].hash()).await);

        // Latest finalized height updated
        assert_eq!(mgr.latest_finalized_height().await, 5);
    }

    /// Duplicate vote from same validator is rejected (replay protection).
    #[tokio::test]
    async fn test_duplicate_vote_rejected() {
        let dag = Arc::new(DagStore::new());
        let config = CheckpointConfig::for_testing();
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag);

        let committee: Vec<PublicKey> = (0..5).map(make_pubkey).collect();
        mgr.propose(5, blocks[5].hash(), committee).await.unwrap();

        let vote = make_signed_vote(0, 5, &blocks[5].hash());
        mgr.submit_vote(vote.clone()).await.unwrap();

        // Duplicate — rejected by replay protection
        let result = mgr.submit_vote(vote).await;
        assert!(matches!(result, Err(CheckpointError::DuplicateVote(_))));
    }

    /// Non-committee member vote is rejected.
    #[tokio::test]
    async fn test_non_committee_vote_rejected() {
        let dag = Arc::new(DagStore::new());
        let config = CheckpointConfig::for_testing();
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag);

        let committee: Vec<PublicKey> = (0..5).map(make_pubkey).collect();
        mgr.propose(5, blocks[5].hash(), committee).await.unwrap();

        // Voter 99 has a valid signature but is NOT in the committee
        let vote = make_signed_vote(99, 5, &blocks[5].hash());
        let result = mgr.submit_vote(vote).await;
        assert!(matches!(result, Err(CheckpointError::NotInCommittee(_))));
    }

    /// Signature for wrong height is rejected.
    #[tokio::test]
    async fn test_wrong_height_signature_rejected() {
        let dag = Arc::new(DagStore::new());
        let config = CheckpointConfig::for_testing();
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag);

        let committee: Vec<PublicKey> = (0..5).map(make_pubkey).collect();
        mgr.propose(5, blocks[5].hash(), committee).await.unwrap();

        // Sign for height 10 but submit for height 5 — crypto check fails
        let sk = make_signing_key(0);
        let wrong_sig = sign_vote(10, &blocks[5].hash(), &sk);
        let vote = CheckpointVote {
            height: 5,
            block_hash: blocks[5].hash(),
            voter: make_pubkey(0),
            signature: wrong_sig,
        };
        let result = mgr.submit_vote(vote).await;
        assert!(matches!(result, Err(CheckpointError::InvalidSignature(_))));
    }
}
