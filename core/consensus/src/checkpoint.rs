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

/// Domain separator prefix for checkpoint vote canonical messages.
///
/// RM-B1 / WP-B2.2 (audit H-02): the canonical signing message MUST be
/// prefixed with this byte string so a vote signed for one chain
/// cannot be replayed onto a fork or alternate chain. The trailing
/// version `-V1` lets future protocol changes rotate the separator
/// without ambiguity. The full canonical layout is:
///
/// ```text
/// CITRATE_VOTE_DOMAIN_SEPARATOR (21 bytes)
///   || chain_id (8 bytes, little-endian)
///   || height   (8 bytes, little-endian)
///   || block_hash (32 bytes)
/// ```
///
/// = 69 bytes total.
pub const CITRATE_VOTE_DOMAIN_SEPARATOR: &[u8] = b"CITRATE-CHECKPOINT-V1";

/// Build the canonical signing message for a checkpoint vote.
///
/// RM-B1 / WP-B2.2 (audit H-02). Used by both the producer (when
/// signing a vote) and the verifier (when checking a vote signature)
/// — these MUST agree byte-for-byte.
pub fn canonical_vote_message(chain_id: u64, height: u64, block_hash: &Hash) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        CITRATE_VOTE_DOMAIN_SEPARATOR.len() + 8 + 8 + 32,
    );
    msg.extend_from_slice(CITRATE_VOTE_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&chain_id.to_le_bytes());
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(block_hash.as_bytes());
    msg
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

    /// Chain ID. RM-B1 / WP-B2.2 (audit H-02): bound into the
    /// canonical vote message via [`canonical_vote_message`] so a
    /// vote on one chain cannot replay onto another. Defaults to
    /// the testnet-beta chain id (40204) — production configs MUST
    /// set this explicitly.
    pub chain_id: u64,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            interval: 50,
            committee_size: 100,
            quorum_threshold: 67,
            chain_id: 40204,
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
            chain_id: 40204,
        }
    }

    /// Check if a height is a checkpoint boundary.
    pub fn is_checkpoint_height(&self, height: u64) -> bool {
        height > 0 && height.is_multiple_of(self.interval)
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

/// Integer square root of a u128 via Newton's method.
/// RM-B1 / WP-B4.2 (audit M-04): replaces the pre-fix
/// `(stake as f64).sqrt() as u64` which lossily quantized for
/// stake > 2^53 and saturated non-portably across LLVM versions.
/// Exact on every platform; deterministic.
pub fn integer_sqrt_u128(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    // Initial estimate: 2^(bits/2) where `bits` is ceil(log2(n)).
    let mut x = 1u128 << ((128 - n.leading_zeros()).div_ceil(2));
    // Newton iteration: x_{k+1} = (x_k + n / x_k) / 2.
    // Converges in O(log log n) iterations on this initial value.
    loop {
        let next = (x + n / x) / 2;
        if next >= x {
            // Converged (or oscillating between adjacent values).
            return x;
        }
        x = next;
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

                // Score = hash_value weighted by stake.
                let mut hash_prefix = [0u8; 8];
                hash_prefix.copy_from_slice(&hash[0..8]);
                let hash_val = u64::from_be_bytes(hash_prefix);
                // Weight by sqrt(stake). RM-B1 / WP-B4.2 (audit M-04):
                // pre-fix used `(*stake as f64).sqrt() as u64` which
                // lossily quantizes for stake > 2^53 (with 18 decimals,
                // 0.009 SALT base units already exceeds 2^53), and the
                // f64→u64 cast saturates differently across rustc/LLVM
                // versions for special values. Both make committee
                // membership non-portable. Integer sqrt on u128 is
                // exact and deterministic on every platform.
                let weight = integer_sqrt_u128(*stake);
                // Cap weight at u64::MAX since `wrapping_mul` is u64.
                let weight_u64 = weight.min(u64::MAX as u128) as u64;
                let score = hash_val.wrapping_mul(weight_u64.max(1));
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
/// RM-B1 / WP-B2.2 (audit H-02): canonical message is
/// `CITRATE-CHECKPOINT-V1 || chain_id(8 LE) || height(8 LE) || block_hash(32)`
/// = 69 bytes — see [`canonical_vote_message`]. Cross-chain replay
/// is structurally impossible because chain_id is bound into the
/// signed bytes.
fn verify_vote_signature(
    vote: &CheckpointVote,
    chain_id: u64,
) -> Result<(), CheckpointError> {
    let message = canonical_vote_message(chain_id, vote.height, &vote.block_hash);

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
        // Load finalized checkpoints from storage.
        // These try_write() calls are made during construction before the CheckpointManager
        // is shared, so the locks should never be contended. We log and skip on failure
        // rather than panicking.
        if let Ok(entries) = kv.kv_iter_cf(cf::DAG_METADATA) {
            for (key, value) in entries {
                if key.starts_with(b"checkpoint:") {
                    if let Ok(cp) = bincode::deserialize::<Checkpoint>(&value) {
                        if cp.status == CheckpointStatus::Finalized {
                            if let Ok(mut latest) = mgr.latest_finalized_height.try_write() {
                                if cp.height > *latest {
                                    *latest = cp.height;
                                }
                            } else {
                                warn!("Failed to acquire write lock on latest_finalized_height during checkpoint load");
                            }
                            if let Ok(mut finalized) = mgr.finalized.try_write() {
                                finalized.insert(cp.height, cp);
                            } else {
                                warn!("Failed to acquire write lock on finalized during checkpoint load");
                            }
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
    ///
    /// RM-B1 / WP-B2.1 (audit H-01): the `voted` replay-protection
    /// set is updated **only after every validation step succeeds**:
    ///
    ///   1. Pending checkpoint exists at `vote.height`.
    ///   2. Voter is in the committee for that checkpoint.
    ///   3. Voter has not already cast an ACCEPTED vote (checkpoint.votes).
    ///   4. `vote.block_hash` matches the checkpoint's block hash.
    ///   5. ed25519 signature over the canonical message verifies.
    ///
    /// Only after step 5 do we mark `(height, voter)` as voted.
    /// Pre-fix, the marker was set at step 1 — a flood of invalid
    /// votes for victim pubkeys could lock honest voters out and
    /// permanently break liveness at every checkpoint height.
    pub async fn submit_vote(&self, vote: CheckpointVote) -> Result<bool, CheckpointError> {
        let mut pending = self.pending.write().await;

        let checkpoint = pending
            .get_mut(&vote.height)
            .ok_or(CheckpointError::BlockNotFound(Hash::default()))?;

        // 1. Verify voter is in committee.
        let committee_set: HashSet<&PublicKey> = checkpoint.committee.iter().collect();
        if !committee_set.contains(&vote.voter) {
            return Err(CheckpointError::NotInCommittee(vote.voter));
        }

        // 2. Check for an already-accepted vote from this voter.
        if checkpoint.votes.contains_key(&vote.voter) {
            return Err(CheckpointError::DuplicateVote(vote.voter));
        }

        // 3. Verify vote is for the correct block.
        if vote.block_hash != checkpoint.block_hash {
            return Err(CheckpointError::InvalidSignature(vote.voter));
        }

        // 4. Cryptographic ed25519 signature verification (binds
        //    chain_id + height + block_hash into the signed bytes).
        verify_vote_signature(&vote, self.config.chain_id)?;

        // 5. Replay protection — ONLY mark voted after all validation
        //    succeeds. Pre-fix this happened at step 0; the H-01
        //    flood-DoS exploited that ordering.
        {
            let mut voted = self.voted.write().await;
            if !voted.insert((vote.height, vote.voter)) {
                // Race: another concurrent submit_vote already
                // accepted this voter. Treat as duplicate.
                return Err(CheckpointError::DuplicateVote(vote.voter));
            }
        }

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

        // Persist to storage.
        // RM-B1 / WP-B1.5 (audit M-06): on serialization failure log
        // `error!` and skip the kv_put rather than writing empty bytes
        // (which would silently deserialize-fail on next restart).
        if let Some(ref kv) = self.persistent {
            let key = format!("checkpoint:{}", height);
            match bincode::serialize(&checkpoint) {
                Ok(bytes) => {
                    if let Err(e) = kv.kv_put(cf::DAG_METADATA, key.as_bytes(), &bytes) {
                        warn!("Failed to persist checkpoint at height {}: {}", height, e);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "M-06: serialize checkpoint at height {} failed: {} — skipping persistence",
                        height, e
                    );
                }
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
    /// RM-B1 / WP-B2.2 (H-02): uses canonical_vote_message helper.
    fn sign_vote(height: u64, block_hash: &Hash, signing_key: &SigningKey) -> Signature {
        let message = canonical_vote_message(40204, height, block_hash);
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
        BlockBuilder::new()
            .hash(Hash::new(hash))
            .height(height)
            .parent(parent)
            .build_unhashed()
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
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
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
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
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
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
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
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
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
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
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
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
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
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
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
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
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
