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

    #[error("Committee too small to finalize: {0} < {1} (minimum)")]
    CommitteeTooSmall(usize, usize),

    #[error("Storage error: {0}")]
    StorageError(String),

    /// A stored (finalized) checkpoint certificate does not verify: wrong status,
    /// committee below the finality minimum, too few votes for its derived quorum,
    /// a voter outside its committee, or a signature that does not verify over
    /// the canonical message for `(chain_id, height, block_hash)`.
    #[error("Invalid checkpoint certificate at height {height}: {reason}")]
    InvalidCertificate { height: u64, reason: String },
}

/// Minimum committee size that may finalize a checkpoint.
///
/// docs/consensus/CHECKPOINT_FINALITY_WIRING.md §3 (D-2a): a 1- or 2-member
/// committee must never self-finalize — that is centralized rubber-stamping,
/// not BFT. Below this size the manager still proposes and collects votes but
/// never finalizes. A committee of 4 tolerates 1 Byzantine member at quorum 3.
pub const MIN_FINALITY_COMMITTEE: usize = 4;

/// Derived BFT quorum for an effective committee of size `n`: `floor(2n/3) + 1`.
///
/// docs/consensus/CHECKPOINT_FINALITY_WIRING.md §3 (D-2). This is the standard
/// BFT threshold (e.g. 67 for n=100, 3 for n=4) and replaces the fixed 67, which
/// could never be met below 100 validators. Callers gate on
/// [`MIN_FINALITY_COMMITTEE`] before using this value.
pub fn derived_quorum(n: usize) -> usize {
    (n.saturating_mul(2) / 3).saturating_add(1)
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
        CITRATE_VOTE_DOMAIN_SEPARATOR
            .len()
            .saturating_add(8 + 8 + 32),
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

    /// Confirmation depth `D` (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §3):
    /// a node votes for the canonical block at boundary height `H` only once its
    /// applied tip is at least `H + vote_depth` — never at the tip, where a
    /// heavier GhostDAG sibling can still win. Values below 1 are treated as 1.
    pub vote_depth: u64,
}

/// Default confirmation depth `D` (spec §3 chosen parameters: interval 2, D 3).
pub const DEFAULT_VOTE_DEPTH: u64 = 3;

/// §11.9 memory bound: at most this many checkpoints are pending at once. During
/// a quorum stall the OLDEST pending checkpoint (and its voted markers) is
/// evicted to admit a new one, so memory stays bounded however long the stall.
pub const MAX_PENDING_CHECKPOINTS: usize = 64;

/// §11.9 memory bound: finalized checkpoints kept in memory. Older ones are
/// dropped from the in-memory map only; they remain in the persistent store and
/// [`CheckpointManager::get_checkpoint`] reads them back from there.
pub const MAX_FINALIZED_IN_MEMORY: usize = 256;

/// Outcome of [`CheckpointManager::ensure_proposed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposeOutcome {
    /// A new pending checkpoint was created for `(height, block_hash)`.
    Proposed,
    /// `(height, block_hash)` was already pending — nothing changed.
    AlreadyPending,
    /// `height` is finalized, or at/below the latest finalized height.
    AlreadyFinalized,
    /// A DIFFERENT hash is pending at `height`; nothing changed.
    ConflictingPending { pending: Hash },
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            interval: 50,
            committee_size: 100,
            quorum_threshold: 67,
            chain_id: 40204,
            vote_depth: DEFAULT_VOTE_DEPTH,
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
            vote_depth: 2,
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
    /// Check if quorum has been reached against an explicit threshold.
    pub fn has_quorum(&self, threshold: usize) -> bool {
        self.votes.len() >= threshold
    }

    /// The effective quorum for THIS checkpoint, derived from its own committee
    /// size: `floor(2n/3)+1`. Returns `None` when the committee is smaller than
    /// [`MIN_FINALITY_COMMITTEE`], i.e. too small to finalize at all.
    pub fn effective_quorum(&self) -> Option<usize> {
        let n = self.committee.len();
        if n < MIN_FINALITY_COMMITTEE {
            None
        } else {
            Some(derived_quorum(n))
        }
    }

    /// Whether this checkpoint has reached its DERIVED quorum. `false` when the
    /// committee is below [`MIN_FINALITY_COMMITTEE`] (never self-finalize a tiny
    /// committee) or when it simply has too few votes.
    pub fn has_derived_quorum(&self) -> bool {
        match self.effective_quorum() {
            Some(q) => self.votes.len() >= q,
            None => false,
        }
    }

    /// Get the number of votes collected.
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Re-check this checkpoint as a finality CERTIFICATE for `chain_id`
    /// (spec §4.5, Stage 1c). Accepts exactly what an honest
    /// [`CheckpointManager::finalize_checkpoint`] produces and nothing weaker:
    ///
    /// 1. status is [`CheckpointStatus::Finalized`];
    /// 2. the committee has at least [`MIN_FINALITY_COMMITTEE`] members;
    /// 3. the votes reach the derived quorum `floor(2n/3)+1` over that committee;
    /// 4. every voter is a committee member;
    /// 5. every signature verifies (ed25519) over
    ///    [`canonical_vote_message`]`(chain_id, height, block_hash)`.
    ///
    /// What this does NOT establish: that the committee itself is the one the
    /// validator registry yields for this height. A stored certificate is either
    /// produced by this node's own manager, whose committee came from its own
    /// epoch snapshot, or installed by Stage 1b certificate sync
    /// ([`CheckpointManager::install_synced_certificate`]), which only accepts a
    /// [`VerifiedCertificate`] whose committee this node derived itself — the
    /// committee a peer sends is never used.
    pub fn verify_certificate(&self, chain_id: u64) -> Result<(), CheckpointError> {
        let height = self.height;
        let invalid = |reason: String| CheckpointError::InvalidCertificate { height, reason };
        if self.status != CheckpointStatus::Finalized {
            return Err(invalid(format!(
                "status is {:?}, not Finalized",
                self.status
            )));
        }
        let n = self.committee.len();
        let quorum = self.effective_quorum().ok_or_else(|| {
            invalid(format!(
                "committee of {n} is below the finality minimum {MIN_FINALITY_COMMITTEE}"
            ))
        })?;
        if self.votes.len() < quorum {
            return Err(invalid(format!(
                "{} votes; the quorum for a committee of {n} is {quorum}",
                self.votes.len()
            )));
        }
        let committee: HashSet<&PublicKey> = self.committee.iter().collect();
        for (voter, signature) in &self.votes {
            if !committee.contains(voter) {
                return Err(invalid(format!("voter {voter:?} is not in the committee")));
            }
            let vote = CheckpointVote {
                height,
                block_hash: self.block_hash,
                voter: *voter,
                signature: *signature,
            };
            if verify_vote_signature(&vote, chain_id).is_err() {
                return Err(invalid(format!(
                    "signature of {voter:?} does not verify for chain {chain_id}"
                )));
            }
        }
        Ok(())
    }
}

/// A finalized checkpoint certificate received from a peer (Stage 1b, spec
/// §11.10) that has passed [`CheckpointManager::verify_synced_certificate`]
/// against a committee THIS node derived. Only that function constructs one,
/// so [`CheckpointManager::install_synced_certificate`] cannot be handed a
/// certificate that skipped verification.
#[derive(Debug, Clone)]
pub struct VerifiedCertificate {
    checkpoint: Checkpoint,
}

impl VerifiedCertificate {
    /// The verified certificate (its `committee` is the locally derived one).
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
}

/// Outcome of [`CheckpointManager::install_synced_certificate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncedInstall {
    /// Stored as the latest finalized checkpoint (memory + persistent store).
    Installed { height: u64 },
    /// At or below the latest finalized height this node already holds; nothing
    /// was changed.
    Stale { height: u64, latest: u64 },
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
    // n != 0, so `bits` is in 1..=128 and the exponent in 1..=64: never overflows.
    let bits = 128u32.saturating_sub(n.leading_zeros());
    let mut x = 2u128.checked_pow(bits.div_ceil(2)).unwrap_or(u128::MAX);
    // Newton iteration: x_{k+1} = (x_k + n / x_k) / 2.
    // Converges in O(log log n) iterations on this initial value.
    loop {
        // x >= 1 throughout (starts >= 2, and Newton never undershoots isqrt(n) >= 1).
        let next = x.saturating_add(n.checked_div(x).unwrap_or(0)) / 2;
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
                let hash_prefix: [u8; 8] = hash.first_chunk::<8>().copied().unwrap_or_default();
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
        scored
            .into_iter()
            .take(actual_size)
            .map(|(pk, _)| pk)
            .collect()
    }
}

/// Construct this node's signed vote for the checkpoint `(height, block_hash)`
/// on `chain_id` (spec §4.3): an ed25519 signature by `signing_key` over
/// [`canonical_vote_message`], so the vote binds chain id, height and hash.
/// `signing_key` is the node's consensus key — the `proposer.key` identity
/// registered in `ValidatorRegistry` (spec D-4).
pub fn sign_checkpoint_vote(
    chain_id: u64,
    height: u64,
    block_hash: Hash,
    signing_key: &crate::crypto::Ed25519SigningKey,
) -> CheckpointVote {
    use ed25519_dalek::Signer;
    let message = canonical_vote_message(chain_id, height, &block_hash);
    let sig = signing_key.sign(&message);
    CheckpointVote {
        height,
        block_hash,
        voter: PublicKey::new(signing_key.verifying_key().to_bytes()),
        signature: Signature::new(sig.to_bytes()),
    }
}

/// Verify a checkpoint vote signature cryptographically (ed25519).
///
/// RM-B1 / WP-B2.2 (audit H-02): canonical message is
/// `CITRATE-CHECKPOINT-V1 || chain_id(8 LE) || height(8 LE) || block_hash(32)`
/// = 69 bytes — see [`canonical_vote_message`]. Cross-chain replay
/// is structurally impossible because chain_id is bound into the
/// signed bytes.
pub(crate) fn verify_vote_signature(
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

/// Hook run by [`CheckpointManager::finalize_checkpoint`] once a checkpoint has
/// reached quorum and its certificate has been written DURABLY (synced, see
/// [`KvStore::kv_put_durable`]), and BEFORE the finalization becomes visible:
/// before the block is marked finalized in the DAG store and before
/// [`CheckpointManager::latest_finalized_height`] moves. If the certificate
/// cannot be written, the hook does not run and nothing is finalized
/// (`finalize_checkpoint` returns [`CheckpointError::StorageError`]), so the
/// floor the node raises here always has a certificate that survives a crash
/// or power loss.
///
/// The node installs its finality floor verifier here (Enforced mode only,
/// `node/src/finality_floor.rs`): it checks the certified `(height, hash)`
/// against the node's applied chain and raises the reorg floor in the same
/// critical section as that check, or engages the finality safety stop when the
/// block is not confirmed on this node's chain. That closes the window in which
/// a just-finalized block could be reorged out before the floor followed it
/// (spec §5 S2). The hook cannot veto: a certificate with quorum is a fact about
/// the network, and it is recorded either way.
///
/// Called with no manager lock held (only the manager's finalization mutex, which
/// serializes finalizations), so the hook may read the manager.
///
/// PUBLICATION. `before_finalize` must not PUBLISH the finalization (e.g. the
/// finalized/safe RPC tags): the finalization is not visible yet (latest
/// finalized height, DAG mark). Publication belongs in [`Self::after_finalize`];
/// it should still check [`CheckpointManager::is_certificate_persisted`] for the
/// exact pair it publishes.
#[async_trait::async_trait]
pub trait FinalizationGuard: Send + Sync {
    /// `certificate` has `status == Finalized`, a committee of at least
    /// [`MIN_FINALITY_COMMITTEE`] and its derived quorum of votes.
    async fn before_finalize(&self, certificate: &Checkpoint);

    /// Runs after the finalization is visible: the certificate durably
    /// written, the block marked in the DAG store, the latest finalized
    /// height and the in-memory record updated. No manager lock is held (only
    /// the finalization mutex). Default: nothing.
    async fn after_finalize(&self, _certificate: &Checkpoint) {}
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

    /// Runs before a finalization becomes visible ([`FinalizationGuard`]).
    /// Installed at most once; `None` = finalize exactly as before.
    finalization_guard: std::sync::OnceLock<Arc<dyn FinalizationGuard>>,

    /// Serializes [`Self::finalize_checkpoint`] so the guard's verdict and the
    /// finalization it precedes are one step for every other finalization.
    /// Outermost manager lock: never awaited while holding any other manager
    /// lock.
    finalize_serial: tokio::sync::Mutex<()>,
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
            finalization_guard: std::sync::OnceLock::new(),
            finalize_serial: tokio::sync::Mutex::new(()),
        }
    }

    /// Install the hook run before every finalization becomes visible
    /// ([`FinalizationGuard`]). The first install wins; returns `false` (and
    /// changes nothing) if a guard is already installed.
    pub fn install_finalization_guard(&self, guard: Arc<dyn FinalizationGuard>) -> bool {
        self.finalization_guard.set(guard).is_ok()
    }

    /// Whether a [`FinalizationGuard`] is installed.
    pub fn has_finalization_guard(&self) -> bool {
        self.finalization_guard.get().is_some()
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
        // §11.9: keep only the most recent MAX_FINALIZED_IN_MEMORY in memory
        // (the rest stay readable from `kv` via get_checkpoint).
        if let Ok(mut finalized) = mgr.finalized.try_write() {
            trim_finalized(&mut finalized);
        }
        // voted is already initialized via new()
        mgr
    }

    /// Get the checkpoint config.
    pub fn config(&self) -> &CheckpointConfig {
        &self.config
    }

    /// The persistent backend this manager was built with
    /// ([`Self::with_persistence`]), if any. The finality gadget keeps its
    /// durable signed-vote record (equivocation protection across restarts) in
    /// the same store; a manager built with [`Self::new`] has none, and a
    /// gadget over it refuses to sign.
    pub fn persistent_store(&self) -> Option<&Arc<dyn KvStore>> {
        self.persistent.as_ref()
    }

    /// Get the latest finalized checkpoint height.
    pub async fn latest_finalized_height(&self) -> u64 {
        *self.latest_finalized_height.read().await
    }

    /// Get a finalized checkpoint by height: from memory, else (for one trimmed
    /// out of the in-memory window) from the persistent `checkpoint:{height}`
    /// record in `DAG_METADATA`.
    pub async fn get_checkpoint(&self, height: u64) -> Option<Checkpoint> {
        if let Some(cp) = self.finalized.read().await.get(&height).cloned() {
            return Some(cp);
        }
        let kv = self.persistent.as_ref()?;
        let key = format!("checkpoint:{}", height);
        let bytes = kv.kv_get(cf::DAG_METADATA, key.as_bytes()).ok()??;
        bincode::deserialize::<Checkpoint>(&bytes)
            .ok()
            .filter(|cp| cp.status == CheckpointStatus::Finalized && cp.height == height)
    }

    /// The finalized checkpoint at [`Self::latest_finalized_height`] — the
    /// certificate a finality floor would be raised from — from memory, else
    /// from the persisted `DAG_METADATA` record `checkpoint:{height}`. `None`
    /// when nothing has finalized (height 0) or the record cannot be read.
    /// Returned AS STORED: callers must [`Checkpoint::verify_certificate`] it
    /// before trusting it.
    pub async fn latest_finalized_certificate(&self) -> Option<Checkpoint> {
        let height = self.latest_finalized_height().await;
        if height == 0 {
            return None;
        }
        self.get_checkpoint(height).await
    }

    /// Whether the finalized certificate for `(height, block_hash)` is in the
    /// persistent store (`DAG_METADATA` `checkpoint:{height}`), i.e. a restart
    /// would load it. `false` without a persistent backend, when the record is
    /// absent or unreadable, or when it names another block. The finality floor
    /// verifier publishes a finalized pair (RPC `finalized`/`safe`) only once
    /// this holds.
    pub fn is_certificate_persisted(&self, height: u64, block_hash: &Hash) -> bool {
        let Some(kv) = self.persistent.as_ref() else {
            return false;
        };
        let key = format!("checkpoint:{}", height);
        match kv.kv_get(cf::DAG_METADATA, key.as_bytes()) {
            Ok(Some(bytes)) => bincode::deserialize::<Checkpoint>(&bytes).is_ok_and(|cp| {
                cp.status == CheckpointStatus::Finalized
                    && cp.height == height
                    && cp.block_hash == *block_hash
            }),
            _ => false,
        }
    }

    /// Every height holding a finalized certificate — the in-memory window AND
    /// the persistent `DAG_METADATA` `checkpoint:{height}` records (the memory
    /// window keeps only the latest [`MAX_FINALIZED_IN_MEMORY`]) — highest
    /// first. Read each with [`Self::get_checkpoint`] and
    /// [`Checkpoint::verify_certificate`] before trusting it. Scans the
    /// metadata column family (as [`Self::with_persistence`] does at load):
    /// meant for boot, not for a hot path. If the scan fails, only the
    /// in-memory heights are returned and a warning is logged.
    pub async fn finalized_certificate_heights(&self) -> Vec<u64> {
        let mut heights: std::collections::BTreeSet<u64> =
            self.finalized.read().await.keys().copied().collect();
        if let Some(kv) = &self.persistent {
            match kv.kv_iter_cf(cf::DAG_METADATA) {
                Ok(entries) => {
                    for (key, _) in entries {
                        let height = key
                            .strip_prefix(b"checkpoint:".as_slice())
                            .and_then(|rest| std::str::from_utf8(rest).ok())
                            .and_then(|rest| rest.parse::<u64>().ok());
                        if let Some(h) = height {
                            heights.insert(h);
                        }
                    }
                }
                Err(e) => warn!(
                    "checkpoint: could not list persisted finalized certificates ({}); \
                     using the {} held in memory",
                    e,
                    heights.len()
                ),
            }
        }
        heights.into_iter().rev().collect()
    }

    /// Stage 1b serving (spec §11.10): the highest finalized checkpoint with
    /// `above < height <= at_or_below`, from the in-memory window (the most
    /// recent [`MAX_FINALIZED_IN_MEMORY`]) or, for the latest, the persistent
    /// record. Returned AS STORED; the requester verifies it independently.
    pub async fn latest_finalized_in_range(
        &self,
        above: u64,
        at_or_below: u64,
    ) -> Option<Checkpoint> {
        if at_or_below <= above {
            return None;
        }
        let latest = self.latest_finalized_height().await;
        if latest > above && latest <= at_or_below {
            if let Some(cp) = self.get_checkpoint(latest).await {
                return Some(cp);
            }
        }
        let finalized = self.finalized.read().await;
        finalized
            .iter()
            .filter(|(h, cp)| {
                **h > above && **h <= at_or_below && cp.status == CheckpointStatus::Finalized
            })
            .max_by_key(|(h, _)| **h)
            .map(|(_, cp)| cp.clone())
    }

    /// Stage 1b (spec §11.10): verify a finalized checkpoint certificate
    /// received from a peer against `committee` — the committee THIS node
    /// derived for `height` from the epoch validator snapshot governing it and
    /// the checkpoint block's own VRF beacon (`FinalityGadget::committee_for`).
    /// No committee is ever taken from the peer.
    ///
    /// Accepts exactly what [`Checkpoint::verify_certificate`] accepts for a
    /// certificate over that committee: a boundary height, a committee of at
    /// least [`MIN_FINALITY_COMMITTEE`], at least `floor(2n/3)+1` distinct
    /// voters, every voter a member, every signature valid over
    /// [`canonical_vote_message`]`(chain_id, height, block_hash)`. More
    /// signatures than committee members, or a voter listed twice, is refused
    /// before any signature is checked (bounds the work a peer can cause).
    ///
    /// The `(height, block_hash)` binding to this node's own chain is the
    /// caller's job (the node checks the block is canonical here before calling
    /// this, and the floor verifier re-checks it under the advance lock).
    pub fn verify_synced_certificate(
        &self,
        height: u64,
        block_hash: Hash,
        signatures: &[(PublicKey, Signature)],
        committee: Vec<PublicKey>,
    ) -> Result<VerifiedCertificate, CheckpointError> {
        let invalid = |reason: String| CheckpointError::InvalidCertificate { height, reason };
        if !self.config.is_checkpoint_height(height) {
            return Err(invalid(format!(
                "height is not a checkpoint boundary (interval {})",
                self.config.interval
            )));
        }
        if signatures.len() > committee.len() {
            return Err(invalid(format!(
                "{} signatures for a committee of {}",
                signatures.len(),
                committee.len()
            )));
        }
        let mut votes = HashMap::with_capacity(signatures.len());
        for (voter, signature) in signatures {
            if votes.insert(*voter, *signature).is_some() {
                return Err(invalid(format!("voter {voter:?} is listed twice")));
            }
        }
        let checkpoint = Checkpoint {
            height,
            block_hash,
            committee,
            votes,
            status: CheckpointStatus::Finalized,
        };
        checkpoint.verify_certificate(self.config.chain_id)?;
        Ok(VerifiedCertificate { checkpoint })
    }

    /// Stage 1b (spec §11.10): store a verified synced certificate exactly as
    /// [`Self::finalize_checkpoint`] stores a locally finalized one (DAG
    /// finalized mark, `DAG_METADATA` `checkpoint:{height}`, in-memory window,
    /// latest finalized height) and drop pending / replay state at or below it.
    /// A certificate at or below the latest finalized height changes nothing.
    /// The certificate record is written with the synced write
    /// ([`KvStore::kv_put_durable`]) before anything else changes; if that
    /// write fails nothing is installed and `StorageError` is returned.
    pub async fn install_synced_certificate(
        &self,
        cert: VerifiedCertificate,
    ) -> Result<SyncedInstall, CheckpointError> {
        let checkpoint = cert.checkpoint;
        let height = checkpoint.height;
        // Held across the whole install so two installs cannot interleave.
        let mut latest = self.latest_finalized_height.write().await;
        if height <= *latest {
            return Ok(SyncedInstall::Stale {
                height,
                latest: *latest,
            });
        }
        // Durable BEFORE anything is visible, exactly as a local finalization
        // (#362): a failed write installs nothing and surfaces as
        // `StorageError` (the sync poll asks again later).
        self.persist_certificate(&checkpoint)?;
        if let Err(e) = self.dag_store.finalize_block(&checkpoint.block_hash).await {
            debug!(
                "synced checkpoint {}: block {} not marked finalized in the DAG store: {}",
                height, checkpoint.block_hash, e
            );
        }
        {
            let mut finalized = self.finalized.write().await;
            finalized.insert(height, checkpoint);
            trim_finalized(&mut finalized);
        }
        *latest = height;
        drop(latest);
        self.prune_at_or_below(height).await;
        info!(
            "Installed synced checkpoint certificate at height {}",
            height
        );
        Ok(SyncedInstall::Installed { height })
    }

    /// Whether `height` holds a finalized checkpoint (memory or persistent store).
    pub async fn is_finalized(&self, height: u64) -> bool {
        self.get_checkpoint(height).await.is_some()
    }

    /// The block hash pending at `height`, if a checkpoint is being collected there.
    pub async fn pending_hash(&self, height: u64) -> Option<Hash> {
        self.pending
            .read()
            .await
            .get(&height)
            .map(|cp| cp.block_hash)
    }

    /// Idempotent propose (spec §4.2): create the pending checkpoint for
    /// `(height, block_hash)` unless it already exists. Unlike [`Self::propose`]
    /// a repeat for the SAME hash is not an error, a different pending hash is
    /// reported (never replaced), and a height at/below the latest finalized
    /// height is never re-opened. Admitting a new checkpoint while
    /// [`MAX_PENDING_CHECKPOINTS`] are pending evicts the lowest pending height
    /// (§11.9 stall bound).
    pub async fn ensure_proposed(
        &self,
        height: u64,
        block_hash: Hash,
        committee: Vec<PublicKey>,
    ) -> Result<ProposeOutcome, CheckpointError> {
        if !self.config.is_checkpoint_height(height) {
            return Err(CheckpointError::NotCheckpointBoundary);
        }
        let latest = *self.latest_finalized_height.read().await;
        if height <= latest || self.is_finalized(height).await {
            return Ok(ProposeOutcome::AlreadyFinalized);
        }
        if !self.dag_store.has_block(&block_hash).await {
            return Err(CheckpointError::BlockNotFound(block_hash));
        }
        let mut pending = self.pending.write().await;
        if let Some(existing) = pending.get(&height) {
            return Ok(if existing.block_hash == block_hash {
                ProposeOutcome::AlreadyPending
            } else {
                ProposeOutcome::ConflictingPending {
                    pending: existing.block_hash,
                }
            });
        }
        while pending.len() >= MAX_PENDING_CHECKPOINTS {
            let Some(&lowest) = pending.keys().min() else {
                break;
            };
            pending.remove(&lowest);
            let mut voted = self.voted.write().await;
            voted.retain(|(h, _)| *h != lowest);
            drop(voted);
            warn!(
                "checkpoint {}: evicted unfinalized pending checkpoint (pending cap {})",
                lowest, MAX_PENDING_CHECKPOINTS
            );
        }
        info!(
            "Proposed checkpoint at height {} for block {} (committee {})",
            height,
            block_hash,
            committee.len()
        );
        pending.insert(
            height,
            Checkpoint {
                height,
                block_hash,
                committee,
                votes: HashMap::new(),
                status: CheckpointStatus::Pending,
            },
        );
        Ok(ProposeOutcome::Proposed)
    }

    /// §11.9: drop pending checkpoints and per-height voted markers at or below
    /// `floor` (the latest finalized height): nothing there can matter any more.
    pub async fn prune_at_or_below(&self, floor: u64) {
        let mut pending = self.pending.write().await;
        pending.retain(|h, _| *h > floor);
        drop(pending);
        let mut voted = self.voted.write().await;
        voted.retain(|(h, _)| *h > floor);
    }

    /// Number of pending checkpoints (memory-bound assertions).
    pub async fn pending_len(&self) -> usize {
        self.pending.read().await.len()
    }

    /// Number of `(height, voter)` replay markers held (memory-bound assertions).
    pub async fn voted_len(&self) -> usize {
        self.voted.read().await.len()
    }

    /// Number of finalized checkpoints held in memory (memory-bound assertions).
    pub async fn finalized_in_memory_len(&self) -> usize {
        self.finalized.read().await.len()
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

        info!(
            "Proposed checkpoint at height {} for block {}",
            height, block_hash
        );
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
            checkpoint.votes.len().saturating_add(1),
            checkpoint
                .effective_quorum()
                .map(|q| q.to_string())
                .unwrap_or_else(|| "n/a (committee < min)".to_string())
        );

        checkpoint.votes.insert(vote.voter, vote.signature);

        // Check quorum. Uses the derived `floor(2n/3)+1` over this checkpoint's
        // effective committee; a committee below MIN_FINALITY_COMMITTEE never
        // reaches quorum (has_derived_quorum returns false).
        if checkpoint.has_derived_quorum() {
            return Ok(true);
        }

        Ok(false)
    }

    /// Write `certificate` (status `Finalized`) to `DAG_METADATA`
    /// `checkpoint:{height}` DURABLY ([`KvStore::kv_put_durable`]: synced, so it
    /// survives a power loss, not only a process crash). `Ok` without a
    /// persistent backend. On `Err` the record must be treated as not written.
    /// RM-B1 / WP-B1.5 (audit M-06): a serialization failure is an error, never
    /// an empty record.
    fn persist_certificate(&self, certificate: &Checkpoint) -> Result<(), CheckpointError> {
        let Some(kv) = self.persistent.as_ref() else {
            return Ok(());
        };
        let height = certificate.height;
        let bytes = bincode::serialize(certificate).map_err(|e| {
            tracing::error!("checkpoint {height}: certificate serialization failed: {e}");
            CheckpointError::StorageError(format!("serialize certificate at height {height}: {e}"))
        })?;
        let key = format!("checkpoint:{}", height);
        kv.kv_put_durable(cf::DAG_METADATA, key.as_bytes(), &bytes)
            .map_err(|e| {
                tracing::error!(
                    "checkpoint {height}: certificate not persisted ({e}); \
                     the finalization is not applied"
                );
                CheckpointError::StorageError(format!(
                    "persist certificate at height {height}: {e}"
                ))
            })
    }

    /// Finalize a checkpoint that has reached quorum.
    ///
    /// Writes the certificate durably (synced) when a persistent store is
    /// configured, then moves the checkpoint from pending to finalized and marks
    /// the block as finalized in the DAG store. Nothing becomes visible before
    /// the certificate is durable: if the write fails the call returns
    /// [`CheckpointError::StorageError`], the checkpoint stays pending with its
    /// votes, and no guard / post-finalization hook runs.
    ///
    /// With a [`FinalizationGuard`] installed, the guard runs on the certificate
    /// after quorum is confirmed and the certificate is durable, and before the
    /// DAG mark, the in-memory record or the latest finalized height changes.
    /// If the pending entry that finalizes extends the guarded certificate
    /// (more votes) it replaces it on disk only if that write succeeds;
    /// otherwise the durable guarded certificate is finalized. Once the guard has run, the certificate it saw
    /// (which has quorum) is what finalizes: if the pending checkpoint is
    /// evicted, pruned, replaced, or pruned and RE-PROPOSED for the same hash
    /// while the guard runs, the pending entry is used only when it extends that
    /// certificate ([`extends_certificate`]); otherwise the guarded certificate
    /// is finalized. So the guard's state change (floor raised / safety stop) is
    /// never left without its certificate, and every finalization after a guard
    /// returns `Ok`.
    pub async fn finalize_checkpoint(&self, height: u64) -> Result<Checkpoint, CheckpointError> {
        let _serial = self.finalize_serial.lock().await;
        let guarded = match self.finalization_guard.get() {
            Some(guard) => {
                let candidate = {
                    let pending = self.pending.read().await;
                    let cp = pending
                        .get(&height)
                        .ok_or(CheckpointError::BlockNotFound(Hash::default()))?;
                    let quorum =
                        cp.effective_quorum()
                            .ok_or(CheckpointError::CommitteeTooSmall(
                                cp.committee.len(),
                                MIN_FINALITY_COMMITTEE,
                            ))?;
                    if !cp.has_derived_quorum() {
                        return Err(CheckpointError::QuorumNotReached(cp.votes.len(), quorum));
                    }
                    let mut candidate = cp.clone();
                    candidate.status = CheckpointStatus::Finalized;
                    candidate
                };
                // Durable BEFORE the guard: the guard raises the floor, so the
                // certificate it acts on must already survive a crash or power
                // loss. A failed write finalizes nothing: the guard does not run,
                // the pending entry is untouched (a later vote or the gadget's
                // retry tick retries), and the error surfaces.
                self.persist_certificate(&candidate)?;
                // No manager lock is held here (only `finalize_serial`).
                guard.before_finalize(&candidate).await;
                Some(candidate)
            }
            None => None,
        };

        let was_guarded = guarded.is_some();
        // The guarded certificate, already durable (written above).
        let durable = guarded.clone();
        let mut pending = self.pending.write().await;
        let mut checkpoint = match (pending.remove(&height), guarded) {
            // The entry still pending extends the guarded certificate (same
            // block and committee, every guarded vote): it has at least that
            // quorum and carries everything the guard verified.
            (Some(cp), Some(seen)) if extends_certificate(&cp, &seen) => cp,
            // Anything else after a guard ran — evicted or pruned, replaced by a
            // proposal for another hash (which can never finalize now that this
            // height has a quorum certificate), or pruned and re-proposed for the
            // SAME hash with fewer votes or another committee: matching hashes
            // alone do not show the entry survived the guard. Finalize what the
            // guard saw; the replacement (and its replay markers, below) is
            // settled with the height.
            (_, Some(mut seen)) => {
                seen.status = CheckpointStatus::Pending;
                seen
            }
            (Some(cp), None) => cp,
            (None, None) => return Err(CheckpointError::BlockNotFound(Hash::default())),
        };

        // Minimum-committee guard (§3, D-2a): a committee below
        // MIN_FINALITY_COMMITTEE must never finalize. Put the checkpoint back and
        // refuse — no self-finalization by a 1- or 2-member committee.
        let effective_quorum = match checkpoint.effective_quorum() {
            Some(q) => q,
            None => {
                // Unreachable after a guard ran: the guarded certificate (or its
                // extension, same committee) passed this check before the guard.
                debug_assert!(!was_guarded, "guarded certificate lost its committee");
                let n = checkpoint.committee.len();
                pending.insert(height, checkpoint);
                return Err(CheckpointError::CommitteeTooSmall(
                    n,
                    MIN_FINALITY_COMMITTEE,
                ));
            }
        };

        if !checkpoint.has_derived_quorum() {
            // Unreachable after a guard ran (see above): the guard's state
            // change is never left without its certificate.
            debug_assert!(!was_guarded, "guarded certificate lost its quorum");
            // Put it back
            let votes = checkpoint.votes.len();
            pending.insert(height, checkpoint);
            return Err(CheckpointError::QuorumNotReached(votes, effective_quorum));
        }

        checkpoint.status = CheckpointStatus::Finalized;

        // The certificate is durable before the finalization is visible (DAG
        // mark, latest finalized height, in-memory record, post-finalization
        // hook / RPC publication).
        match durable {
            // No guard ran: write it now. On failure nothing is visible; the
            // checkpoint goes back to pending with its votes and the error
            // surfaces (a later vote or the gadget's retry tick retries).
            None => {
                if let Err(e) = self.persist_certificate(&checkpoint) {
                    checkpoint.status = CheckpointStatus::Pending;
                    pending.insert(height, checkpoint);
                    return Err(e);
                }
            }
            // The guarded certificate is already durable. An extension (more
            // votes for the same block and committee) replaces it on disk only
            // if that write succeeds; otherwise the durable guarded certificate
            // is the one finalized, so memory and disk agree and the floor the
            // guard raised keeps its persisted certificate.
            Some(seen) => {
                if checkpoint.votes.len() != seen.votes.len() {
                    if let Err(e) = self.persist_certificate(&checkpoint) {
                        warn!(
                            "checkpoint {}: extended certificate not persisted ({}); \
                             finalizing the persisted guarded certificate",
                            height, e
                        );
                        checkpoint = seen;
                    }
                }
            }
        }

        // Mark the block as finalized in the DAG store
        if let Err(e) = self.dag_store.finalize_block(&checkpoint.block_hash).await {
            warn!("Failed to finalize checkpoint block in DAG: {}", e);
        }

        // Update latest finalized height
        let mut latest = self.latest_finalized_height.write().await;
        if height > *latest {
            *latest = height;
        }
        drop(latest);

        info!(
            "Finalized checkpoint at height {} with {}/{} votes",
            height,
            checkpoint.votes.len(),
            effective_quorum
        );

        let cp = checkpoint.clone();
        {
            let mut finalized = self.finalized.write().await;
            finalized.insert(height, checkpoint);
            trim_finalized(&mut finalized);
        }
        // §11.9: the height is settled; its replay markers are dead weight.
        let mut voted = self.voted.write().await;
        voted.retain(|(h, _)| *h != height);
        drop(voted);
        drop(pending);

        // Still under `finalize_serial`, with no other manager lock held.
        if let Some(guard) = self.finalization_guard.get() {
            guard.after_finalize(&cp).await;
        }

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

    /// Heights pending WITH derived quorum, ascending: checkpoints that can
    /// finalize but have not (their finalization failed, or is in flight).
    pub async fn quorum_pending_heights(&self) -> Vec<u64> {
        let mut heights: Vec<u64> = self
            .pending
            .read()
            .await
            .iter()
            .filter(|(_, cp)| cp.has_derived_quorum())
            .map(|(h, _)| *h)
            .collect();
        heights.sort_unstable();
        heights
    }

    /// Whether the pending checkpoint at `height` already holds an accepted vote
    /// from `voter` (`false` when nothing is pending there).
    pub async fn has_pending_vote(&self, height: u64, voter: &PublicKey) -> bool {
        self.pending
            .read()
            .await
            .get(&height)
            .is_some_and(|cp| cp.votes.contains_key(voter))
    }

    /// Get pending vote count for a checkpoint.
    pub async fn pending_vote_count(&self, height: u64) -> Option<usize> {
        self.pending
            .read()
            .await
            .get(&height)
            .map(|cp| cp.vote_count())
    }
}

/// Whether `current` (the entry pending at finalization) extends `guarded` (the
/// certificate a [`FinalizationGuard`] ran on): same height, block and
/// committee, and every guarded vote present with the same signature. Then
/// `current` has at least `guarded`'s quorum and may be finalized in its place.
/// A matching block hash alone is NOT enough: the pending entry may have been
/// pruned and re-proposed for the same hash (with no votes, or another
/// committee) while the guard ran.
fn extends_certificate(current: &Checkpoint, guarded: &Checkpoint) -> bool {
    current.height == guarded.height
        && current.block_hash == guarded.block_hash
        && current.committee == guarded.committee
        && guarded
            .votes
            .iter()
            .all(|(voter, sig)| current.votes.get(voter) == Some(sig))
}

/// Drop the lowest finalized heights until at most [`MAX_FINALIZED_IN_MEMORY`] remain.
fn trim_finalized(finalized: &mut HashMap<u64, Checkpoint>) {
    if finalized.len() <= MAX_FINALIZED_IN_MEMORY {
        return;
    }
    let mut heights: Vec<u64> = finalized.keys().copied().collect();
    heights.sort_unstable();
    let excess = heights.len().saturating_sub(MAX_FINALIZED_IN_MEMORY);
    for h in heights.into_iter().take(excess) {
        finalized.remove(&h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_s1_quorum_and_isqrt_are_total() {
        assert_eq!(derived_quorum(0), 1);
        assert_eq!(derived_quorum(4), 3);
        assert_eq!(derived_quorum(100), 67);
        let _ = derived_quorum(usize::MAX); // must not panic
        for (n, r) in [
            (0u128, 0u128),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 2),
            (15, 3),
            (16, 4),
            (1 << 64, 1 << 32),
        ] {
            assert_eq!(integer_sqrt_u128(n), r, "isqrt({n})");
        }
        assert_eq!(integer_sqrt_u128(u128::MAX), u128::from(u64::MAX));
    }
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
        let validators: Vec<(PublicKey, u128)> = (0..20).map(|i| (make_pubkey(i), 1000)).collect();

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
            assert!(
                !quorum_reached,
                "Quorum should not be reached with {} votes",
                i + 1
            );
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

    /// Derived quorum `floor(2n/3)+1` matches the spec's reference values.
    #[test]
    fn test_derived_quorum_values() {
        assert_eq!(derived_quorum(4), 3, "n=4 => floor(8/3)+1 = 3");
        assert_eq!(derived_quorum(100), 67, "n=100 => floor(200/3)+1 = 67");
        // A few more boundary points for confidence.
        assert_eq!(derived_quorum(5), 4);
        assert_eq!(derived_quorum(7), 5);
        assert_eq!(derived_quorum(10), 7);
    }

    /// `effective_quorum` is `None` (never finalizable) below the minimum
    /// committee, and the derived quorum at/above it.
    #[test]
    fn test_effective_quorum_min_committee() {
        let mk = |n: usize| Checkpoint {
            height: 5,
            block_hash: Hash::new([1; 32]),
            committee: (0..n as u8).map(make_pubkey).collect(),
            votes: HashMap::new(),
            status: CheckpointStatus::Pending,
        };
        assert_eq!(mk(1).effective_quorum(), None);
        assert_eq!(mk(3).effective_quorum(), None, "3 < MIN_FINALITY_COMMITTEE");
        assert_eq!(mk(4).effective_quorum(), Some(3));
        assert_eq!(mk(100).effective_quorum(), Some(67));
    }

    /// A committee below MIN_FINALITY_COMMITTEE (here 3) never reaches quorum and
    /// never finalizes, even with a valid vote from every member.
    #[tokio::test]
    async fn test_below_min_committee_does_not_finalize() {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let config = CheckpointConfig::for_testing();
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag);

        // Committee of 3 (< MIN_FINALITY_COMMITTEE = 4).
        let committee: Vec<PublicKey> = (0..3).map(make_pubkey).collect();
        mgr.propose(5, blocks[5].hash(), committee).await.unwrap();

        // Every one of the 3 members casts a valid vote — none reaches quorum.
        for i in 0..3u8 {
            let vote = make_signed_vote(i, 5, &blocks[5].hash());
            let quorum_reached = mgr.submit_vote(vote).await.unwrap();
            assert!(
                !quorum_reached,
                "committee < 4 must never reach quorum (vote {})",
                i + 1
            );
        }

        // Explicit finalize is refused with CommitteeTooSmall.
        let result = mgr.finalize_checkpoint(5).await;
        assert!(
            matches!(result, Err(CheckpointError::CommitteeTooSmall(3, 4))),
            "expected CommitteeTooSmall(3, 4), got {:?}",
            result
        );
    }

    /// A committee of exactly MIN_FINALITY_COMMITTEE (4) finalizes at the derived
    /// quorum of 3.
    #[tokio::test]
    async fn test_min_committee_finalizes_at_derived_quorum() {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let config = CheckpointConfig::for_testing();
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(config, dag);

        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        mgr.propose(5, blocks[5].hash(), committee).await.unwrap();

        // 2 votes: below derived quorum (3).
        for i in 0..2u8 {
            let vote = make_signed_vote(i, 5, &blocks[5].hash());
            assert!(!mgr.submit_vote(vote).await.unwrap());
        }
        // 3rd vote reaches the derived quorum of 3.
        let vote = make_signed_vote(2, 5, &blocks[5].hash());
        assert!(mgr.submit_vote(vote).await.unwrap(), "3 of 4 => quorum");

        let cp = mgr.finalize_checkpoint(5).await.unwrap();
        assert_eq!(cp.status, CheckpointStatus::Finalized);
        assert_eq!(cp.votes.len(), 3);
    }

    /// Stage 1a §4.2: `ensure_proposed` is idempotent per (H, hash), reports a
    /// conflicting hash without replacing it, and never re-opens a finalized height.
    #[tokio::test]
    async fn ensure_proposed_outcomes() {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 12).await;
        let mgr = CheckpointManager::new(CheckpointConfig::for_testing(), dag);
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let b5 = blocks.get(5).expect("block 5").hash();
        let b6 = blocks.get(6).expect("block 6").hash();

        let first = mgr.ensure_proposed(5, b5, committee.clone()).await;
        assert_eq!(first.expect("propose"), ProposeOutcome::Proposed);
        let again = mgr.ensure_proposed(5, b5, committee.clone()).await;
        assert_eq!(again.expect("repeat"), ProposeOutcome::AlreadyPending);
        let other = mgr.ensure_proposed(5, b6, committee.clone()).await;
        assert_eq!(
            other.expect("conflict"),
            ProposeOutcome::ConflictingPending { pending: b5 }
        );
        assert_eq!(mgr.pending_hash(5).await, Some(b5), "never replaced");
        assert!(matches!(
            mgr.ensure_proposed(6, b6, committee.clone()).await,
            Err(CheckpointError::NotCheckpointBoundary)
        ));
        assert!(matches!(
            mgr.ensure_proposed(10, Hash::new([0xEE; 32]), committee.clone())
                .await,
            Err(CheckpointError::BlockNotFound(_))
        ));

        for i in 0..3u8 {
            mgr.submit_vote(make_signed_vote(i, 5, &b5))
                .await
                .expect("vote");
        }
        mgr.finalize_checkpoint(5).await.expect("finalize");
        assert_eq!(
            mgr.voted_len().await,
            0,
            "voted markers dropped on finalize"
        );
        let reopened = mgr.ensure_proposed(5, b5, committee).await;
        assert_eq!(
            reopened.expect("finalized"),
            ProposeOutcome::AlreadyFinalized
        );
    }

    /// (height, hash, latest finalized height, readable, persisted).
    type AfterSeen = (u64, Hash, u64, bool, bool);

    /// Records what was visible on the manager when the guard ran.
    #[derive(Default)]
    struct ProbeGuard {
        mgr: std::sync::Mutex<Option<std::sync::Weak<CheckpointManager>>>,
        seen: std::sync::Mutex<Vec<(u64, Hash, u64, bool)>>,
        /// What `after_finalize` saw: (height, hash, latest finalized height,
        /// certificate readable, certificate persisted).
        after: std::sync::Mutex<Vec<AfterSeen>>,
        /// Prune pending checkpoints at or below this height from inside the
        /// guard (simulates an eviction racing the finalization).
        prune_during: Option<u64>,
    }

    #[async_trait::async_trait]
    impl FinalizationGuard for ProbeGuard {
        async fn before_finalize(&self, certificate: &Checkpoint) {
            let mgr = self
                .mgr
                .lock()
                .expect("probe lock")
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .expect("manager alive");
            assert_eq!(certificate.status, CheckpointStatus::Finalized);
            assert!(certificate.has_derived_quorum());
            let latest = mgr.latest_finalized_height().await;
            let stored = mgr.get_checkpoint(certificate.height).await.is_some();
            self.seen.lock().expect("probe lock").push((
                certificate.height,
                certificate.block_hash,
                latest,
                stored,
            ));
            if let Some(floor) = self.prune_during {
                mgr.prune_at_or_below(floor).await;
            }
        }

        async fn after_finalize(&self, certificate: &Checkpoint) {
            let mgr = self
                .mgr
                .lock()
                .expect("probe lock")
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .expect("manager alive");
            // Reads every manager lock: proves none is held here.
            let latest = mgr.latest_finalized_height().await;
            let stored = mgr.get_checkpoint(certificate.height).await.is_some();
            let _ = mgr.pending_len().await;
            let persisted =
                mgr.is_certificate_persisted(certificate.height, &certificate.block_hash);
            self.after.lock().expect("probe lock").push((
                certificate.height,
                certificate.block_hash,
                latest,
                stored,
                persisted,
            ));
        }
    }

    async fn guarded(prune_during: Option<u64>) -> (Arc<CheckpointManager>, Arc<ProbeGuard>, Hash) {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 6).await;
        let mgr = Arc::new(CheckpointManager::new(CheckpointConfig::for_testing(), dag));
        let probe = Arc::new(ProbeGuard {
            prune_during,
            ..ProbeGuard::default()
        });
        *probe.mgr.lock().expect("probe lock") = Some(Arc::downgrade(&mgr));
        assert!(mgr.install_finalization_guard(probe.clone()));
        assert!(
            !mgr.install_finalization_guard(probe.clone()),
            "first install wins"
        );
        assert!(mgr.has_finalization_guard());
        let b5 = blocks.get(5).expect("block 5").hash();
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        mgr.ensure_proposed(5, b5, committee)
            .await
            .expect("propose");
        (mgr, probe, b5)
    }

    /// S2 (finality floor at finalization): the guard runs once quorum is
    /// confirmed and BEFORE the finalization is visible — latest finalized
    /// height unchanged, no stored certificate — and is not called below quorum.
    #[tokio::test]
    async fn finalization_guard_runs_before_finalization_is_visible() {
        let (mgr, probe, b5) = guarded(None).await;
        for i in 0..2u8 {
            assert!(!mgr
                .submit_vote(make_signed_vote(i, 5, &b5))
                .await
                .expect("vote"));
        }
        assert!(matches!(
            mgr.finalize_checkpoint(5).await,
            Err(CheckpointError::QuorumNotReached(2, 3))
        ));
        assert!(
            probe.seen.lock().expect("probe lock").is_empty(),
            "no quorum: guard not run"
        );
        assert!(mgr
            .submit_vote(make_signed_vote(2, 5, &b5))
            .await
            .expect("vote"));
        let cp = mgr.finalize_checkpoint(5).await.expect("finalize");
        assert_eq!(cp.block_hash, b5);
        assert_eq!(
            probe.seen.lock().expect("probe lock").as_slice(),
            &[(5, b5, 0, false)],
            "guard saw the certificate while nothing was finalized yet"
        );
        assert_eq!(
            probe.after.lock().expect("probe lock").as_slice(),
            &[(5, b5, 5, true, false)],
            "after_finalize runs once the finalization is visible; no persistent \
             backend here, so the certificate is never reported persisted"
        );
        assert_eq!(mgr.latest_finalized_height().await, 5);
        assert!(matches!(
            mgr.finalize_checkpoint(5).await,
            Err(CheckpointError::BlockNotFound(_))
        ));
        assert_eq!(
            probe.seen.lock().expect("probe lock").len(),
            1,
            "guard once per finalization"
        );
        assert_eq!(probe.after.lock().expect("probe lock").len(), 1);
    }

    /// A pending checkpoint pruned while the guard runs still finalizes as the
    /// certificate the guard saw (the guard's verdict always describes what
    /// finalizes).
    #[tokio::test]
    async fn finalization_guard_verdict_survives_a_concurrent_prune() {
        let (mgr, probe, b5) = guarded(Some(5)).await;
        for i in 0..3u8 {
            mgr.submit_vote(make_signed_vote(i, 5, &b5))
                .await
                .expect("vote");
        }
        let cp = mgr.finalize_checkpoint(5).await.expect("finalize");
        assert_eq!((cp.height, cp.block_hash, cp.votes.len()), (5, b5, 3));
        assert_eq!(cp.status, CheckpointStatus::Finalized);
        assert_eq!(probe.seen.lock().expect("probe lock").len(), 1);
        assert_eq!(mgr.latest_finalized_height().await, 5);
        assert_eq!(mgr.pending_len().await, 0);
    }

    /// Parks `before_finalize` on a barrier so a test can interleave other
    /// manager calls deterministically between the guard's state change and the
    /// finalization it precedes.
    #[derive(Default)]
    struct GateGuard {
        /// Signalled once the guard has run (its state change is done).
        entered: tokio::sync::Notify,
        /// Awaited before the guard returns to `finalize_checkpoint`.
        release: tokio::sync::Notify,
        /// Certificates the guard ran on: (height, hash, vote count).
        before: std::sync::Mutex<Vec<(u64, Hash, usize)>>,
        /// Certificates `after_finalize` saw: (height, hash, vote count).
        after: std::sync::Mutex<Vec<(u64, Hash, usize)>>,
    }

    #[async_trait::async_trait]
    impl FinalizationGuard for GateGuard {
        async fn before_finalize(&self, certificate: &Checkpoint) {
            self.before.lock().expect("gate lock").push((
                certificate.height,
                certificate.block_hash,
                certificate.votes.len(),
            ));
            self.entered.notify_one();
            self.release.notified().await;
        }

        async fn after_finalize(&self, certificate: &Checkpoint) {
            self.after.lock().expect("gate lock").push((
                certificate.height,
                certificate.block_hash,
                certificate.votes.len(),
            ));
        }
    }

    async fn gated() -> (Arc<CheckpointManager>, Arc<GateGuard>, Hash, Vec<PublicKey>) {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 6).await;
        let mgr = Arc::new(CheckpointManager::new(CheckpointConfig::for_testing(), dag));
        let gate = Arc::new(GateGuard::default());
        assert!(mgr.install_finalization_guard(gate.clone()));
        let b5 = blocks.get(5).expect("block 5").hash();
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        mgr.ensure_proposed(5, b5, committee.clone())
            .await
            .expect("propose");
        for i in 0..3u8 {
            mgr.submit_vote(make_signed_vote(i, 5, &b5))
                .await
                .expect("vote");
        }
        (mgr, gate, b5, committee)
    }

    /// S2 atomicity (guard state change <-> certificate): while the guard runs,
    /// the pending checkpoint is pruned and RE-PROPOSED for the SAME block hash
    /// with no votes, and a second finalization of the same height is started.
    /// The certificate the guard ran on (with its quorum) must still be the one
    /// finalized: the guard's state change is never left without its
    /// certificate, and the votes are never dropped. The concurrent finalization
    /// waits for the first and finds nothing left to finalize.
    #[tokio::test]
    async fn finalization_guard_certificate_survives_a_same_hash_re_proposal() {
        let (mgr, gate, b5, committee) = gated().await;

        let first = tokio::spawn({
            let mgr = mgr.clone();
            async move { mgr.finalize_checkpoint(5).await }
        });
        gate.entered.notified().await;
        // The guard has run on the 3-vote certificate; finalization is parked.
        assert_eq!(
            gate.before.lock().expect("gate lock").as_slice(),
            &[(5, b5, 3)]
        );
        let second = tokio::spawn({
            let mgr = mgr.clone();
            async move { mgr.finalize_checkpoint(5).await }
        });
        mgr.prune_at_or_below(5).await;
        assert_eq!(mgr.pending_len().await, 0, "pruned during the guard");
        assert_eq!(
            mgr.ensure_proposed(5, b5, committee.clone())
                .await
                .expect("re-propose"),
            ProposeOutcome::Proposed,
            "the same hash is re-proposed with no votes"
        );
        assert_eq!(mgr.pending_vote_count(5).await, Some(0));
        gate.release.notify_one();

        let first = first.await.expect("first finalization task");
        assert!(
            first.is_ok(),
            "the guarded certificate must finalize, got {first:?}"
        );
        let cp = first.expect("checked above");
        assert_eq!((cp.height, cp.block_hash, cp.votes.len()), (5, b5, 3));
        assert_eq!(cp.status, CheckpointStatus::Finalized);
        assert!(cp.has_derived_quorum());
        assert_eq!(mgr.latest_finalized_height().await, 5);
        let stored = mgr.get_checkpoint(5).await.expect("certificate recorded");
        assert_eq!(stored.votes.len(), 3, "the votes are kept");
        assert_eq!(mgr.pending_len().await, 0, "the replacement is settled");
        assert_eq!(
            gate.after.lock().expect("gate lock").as_slice(),
            &[(5, b5, 3)],
            "after_finalize ran on the guarded certificate"
        );

        // The concurrent finalization ran after the first (serialized): nothing
        // left to finalize, and the guard never ran a second time.
        let second = second.await.expect("second finalization task");
        assert!(
            matches!(second, Err(CheckpointError::BlockNotFound(_))),
            "{second:?}"
        );
        assert_eq!(gate.before.lock().expect("gate lock").len(), 1);
        assert_eq!(gate.after.lock().expect("gate lock").len(), 1);
        assert_eq!(
            mgr.ensure_proposed(5, b5, committee)
                .await
                .expect("re-open attempt"),
            ProposeOutcome::AlreadyFinalized
        );
    }

    /// A same-hash replacement that EXTENDS the guarded certificate (same
    /// committee, every guarded vote, plus more) may be finalized in its place:
    /// it carries everything the guard verified. A replacement with another
    /// committee is not an extension, so the guarded certificate is kept.
    #[tokio::test]
    async fn finalization_guard_keeps_the_certificate_unless_the_replacement_extends_it() {
        // Extension: the re-proposed checkpoint re-collects the same 3 votes
        // (the replay markers were pruned with it) and a 4th.
        let (mgr, gate, b5, committee) = gated().await;
        let task = tokio::spawn({
            let mgr = mgr.clone();
            async move { mgr.finalize_checkpoint(5).await }
        });
        gate.entered.notified().await;
        mgr.prune_at_or_below(5).await;
        mgr.ensure_proposed(5, b5, committee.clone())
            .await
            .expect("re-propose");
        for i in 0..4u8 {
            mgr.submit_vote(make_signed_vote(i, 5, &b5))
                .await
                .expect("vote");
        }
        gate.release.notify_one();
        let cp = task.await.expect("task");
        assert!(cp.is_ok(), "{cp:?}");
        let cp = cp.expect("checked above");
        assert_eq!((cp.block_hash, cp.votes.len()), (b5, 4), "extension kept");

        // Not an extension: same hash, a different committee, no votes.
        let (mgr, gate, b5, _) = gated().await;
        let task = tokio::spawn({
            let mgr = mgr.clone();
            async move { mgr.finalize_checkpoint(5).await }
        });
        gate.entered.notified().await;
        mgr.prune_at_or_below(5).await;
        let other: Vec<PublicKey> = (10..14).map(make_pubkey).collect();
        mgr.ensure_proposed(5, b5, other).await.expect("re-propose");
        gate.release.notify_one();
        let cp = task.await.expect("task");
        assert!(cp.is_ok(), "{cp:?}");
        let cp = cp.expect("checked above");
        assert_eq!((cp.block_hash, cp.votes.len()), (b5, 3));
        assert_eq!(
            cp.committee,
            (0..4).map(make_pubkey).collect::<Vec<_>>(),
            "the guarded certificate's committee is the one recorded"
        );
    }

    // -----------------------------------------------------------------------
    // Certificate durability (follow-up to #335): the certificate is written
    // with a synced write BEFORE the guard raises the floor and before the
    // finalization is visible; a failed write finalizes nothing.
    // -----------------------------------------------------------------------

    /// In-memory store with a fault seam on the certificate records
    /// (`DAG_METADATA` `checkpoint:{height}`): the first `allow_cert_writes`
    /// certificate writes succeed, every later one fails, as a failed write or a
    /// failed fsync would. Counts which path each certificate write took.
    /// `(column family, key) -> value`.
    type FaultMap = HashMap<(String, Vec<u8>), Vec<u8>>;

    struct FaultKv {
        map: std::sync::Mutex<FaultMap>,
        allow_cert_writes: std::sync::atomic::AtomicUsize,
        durable_cert_writes: std::sync::atomic::AtomicUsize,
        plain_cert_writes: std::sync::atomic::AtomicUsize,
        failed_cert_writes: std::sync::atomic::AtomicUsize,
    }

    impl FaultKv {
        fn new(allow_cert_writes: usize) -> Arc<Self> {
            Arc::new(Self {
                map: std::sync::Mutex::new(HashMap::new()),
                allow_cert_writes: std::sync::atomic::AtomicUsize::new(allow_cert_writes),
                durable_cert_writes: std::sync::atomic::AtomicUsize::new(0),
                plain_cert_writes: std::sync::atomic::AtomicUsize::new(0),
                failed_cert_writes: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn heal(&self) {
            self.allow_cert_writes
                .store(usize::MAX, std::sync::atomic::Ordering::SeqCst);
        }

        fn load(c: &std::sync::atomic::AtomicUsize) -> usize {
            c.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn is_cert(cf_name: &str, key: &[u8]) -> bool {
            cf_name == cf::DAG_METADATA && key.starts_with(b"checkpoint:")
        }

        /// The fault seam: `Err` once the allowance is spent.
        fn admit_cert_write(&self) -> Result<(), String> {
            use std::sync::atomic::Ordering::SeqCst;
            let ok = self
                .allow_cert_writes
                .fetch_update(SeqCst, SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if ok {
                Ok(())
            } else {
                self.failed_cert_writes.fetch_add(1, SeqCst);
                Err("injected: fsync failed (EIO)".to_string())
            }
        }

        fn insert(&self, cf_name: &str, key: &[u8], value: &[u8]) {
            self.map
                .lock()
                .expect("fault kv lock")
                .insert((cf_name.to_string(), key.to_vec()), value.to_vec());
        }
    }

    impl KvStore for FaultKv {
        fn kv_get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
            Ok(self
                .map
                .lock()
                .expect("fault kv lock")
                .get(&(cf_name.to_string(), key.to_vec()))
                .cloned())
        }

        fn kv_put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
            if Self::is_cert(cf_name, key) {
                self.plain_cert_writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.admit_cert_write()?;
            }
            self.insert(cf_name, key, value);
            Ok(())
        }

        fn kv_put_durable(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
            if Self::is_cert(cf_name, key) {
                self.durable_cert_writes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.admit_cert_write()?;
            }
            self.insert(cf_name, key, value);
            Ok(())
        }

        fn kv_delete(&self, cf_name: &str, key: &[u8]) -> Result<(), String> {
            self.map
                .lock()
                .expect("fault kv lock")
                .remove(&(cf_name.to_string(), key.to_vec()));
            Ok(())
        }

        fn kv_exists(&self, cf_name: &str, key: &[u8]) -> Result<bool, String> {
            Ok(self.kv_get(cf_name, key)?.is_some())
        }

        fn kv_iter_cf(&self, cf_name: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
            Ok(self
                .map
                .lock()
                .expect("fault kv lock")
                .iter()
                .filter(|((c, _), _)| c == cf_name)
                .map(|((_, k), v)| (k.clone(), v.clone()))
                .collect())
        }
    }

    /// The stored certificate record at `height`, as a restart would load it.
    fn stored_certificate(kv: &FaultKv, height: u64) -> Option<Checkpoint> {
        kv.kv_get(cf::DAG_METADATA, format!("checkpoint:{height}").as_bytes())
            .expect("read")
            .map(|b| bincode::deserialize::<Checkpoint>(&b).expect("decode"))
    }

    /// A persistent manager over `kv` with a probe guard and a 4-member
    /// committee proposed at height 5 holding 3 votes (quorum).
    async fn durable_guarded(
        kv: Arc<FaultKv>,
    ) -> (Arc<CheckpointManager>, Arc<ProbeGuard>, Arc<DagStore>, Hash) {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 6).await;
        let mgr = Arc::new(CheckpointManager::with_persistence(
            CheckpointConfig::for_testing(),
            dag.clone(),
            kv,
        ));
        let probe = Arc::new(ProbeGuard::default());
        *probe.mgr.lock().expect("probe lock") = Some(Arc::downgrade(&mgr));
        assert!(mgr.install_finalization_guard(probe.clone()));
        let b5 = blocks.get(5).expect("block 5").hash();
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        mgr.ensure_proposed(5, b5, committee)
            .await
            .expect("propose");
        for i in 0..3u8 {
            mgr.submit_vote(make_signed_vote(i, 5, &b5))
                .await
                .expect("vote");
        }
        (mgr, probe, dag, b5)
    }

    /// Fault injection, guarded (Enforced) path: the certificate write fails.
    /// Nothing advances — the guard (which raises the floor) never runs, the
    /// post-finalization hook (which publishes) never runs, the latest finalized
    /// height, the in-memory record and the DAG mark are unchanged — and the
    /// error surfaces. The votes stay pending; once the store recovers the same
    /// certificate finalizes and is on disk before the guard sees it.
    #[tokio::test]
    async fn certificate_write_failure_finalizes_nothing_and_never_runs_the_guard() {
        let kv = FaultKv::new(0);
        let (mgr, probe, dag, b5) = durable_guarded(kv.clone()).await;

        let r = mgr.finalize_checkpoint(5).await;
        assert!(
            matches!(&r, Err(CheckpointError::StorageError(_))),
            "a failed certificate write must surface, got {r:?}"
        );
        assert_eq!(FaultKv::load(&kv.failed_cert_writes), 1);
        assert!(
            probe.seen.lock().expect("probe lock").is_empty(),
            "the guard (floor raise) must not run on an unpersisted certificate"
        );
        assert!(
            probe.after.lock().expect("probe lock").is_empty(),
            "nothing may be published"
        );
        assert_eq!(mgr.latest_finalized_height().await, 0);
        assert!(mgr.get_checkpoint(5).await.is_none());
        assert!(!mgr.is_certificate_persisted(5, &b5));
        assert!(!dag.is_finalized(&b5).await, "block not marked finalized");
        assert_eq!(mgr.pending_vote_count(5).await, Some(3), "votes kept");

        // The store recovers: the retry finalizes the same certificate, written
        // before the guard ran.
        kv.heal();
        let cp = mgr
            .finalize_checkpoint(5)
            .await
            .expect("finalize after heal");
        assert_eq!((cp.height, cp.block_hash, cp.votes.len()), (5, b5, 3));
        assert_eq!(
            probe.seen.lock().expect("probe lock").as_slice(),
            &[(5, b5, 0, true)],
            "the guard sees the certificate already on disk, nothing visible yet"
        );
        assert_eq!(
            probe.after.lock().expect("probe lock").as_slice(),
            &[(5, b5, 5, true, true)]
        );
        assert_eq!(mgr.latest_finalized_height().await, 5);
        assert!(dag.is_finalized(&b5).await);
        let stored = stored_certificate(&kv, 5).expect("on disk");
        assert_eq!(stored.status, CheckpointStatus::Finalized);
        assert_eq!(stored.votes.len(), 3);
    }

    /// Fault injection, unguarded (Legacy / Observed) path: same fail-closed
    /// contract — no visible finalization, the checkpoint stays pending with its
    /// votes, and a retry after recovery finalizes it.
    #[tokio::test]
    async fn certificate_write_failure_without_a_guard_finalizes_nothing() {
        let kv = FaultKv::new(0);
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::with_persistence(
            CheckpointConfig::for_testing(),
            dag.clone(),
            kv.clone(),
        );
        let b5 = blocks.get(5).expect("block 5").hash();
        mgr.ensure_proposed(5, b5, (0..4).map(make_pubkey).collect())
            .await
            .expect("propose");
        for i in 0..3u8 {
            mgr.submit_vote(make_signed_vote(i, 5, &b5))
                .await
                .expect("vote");
        }
        let r = mgr.finalize_checkpoint(5).await;
        assert!(
            matches!(&r, Err(CheckpointError::StorageError(_))),
            "a failed certificate write must surface, got {r:?}"
        );
        assert_eq!(mgr.latest_finalized_height().await, 0);
        assert!(mgr.get_checkpoint(5).await.is_none());
        assert!(!dag.is_finalized(&b5).await);
        assert_eq!(mgr.pending_vote_count(5).await, Some(3), "votes kept");
        assert_eq!(
            mgr.checkpoint_status(5).await,
            Some(CheckpointStatus::Pending)
        );
        kv.heal();
        let cp = mgr
            .finalize_checkpoint(5)
            .await
            .expect("finalize after heal");
        assert_eq!(cp.votes.len(), 3);
        assert_eq!(mgr.latest_finalized_height().await, 5);
        assert!(mgr.is_certificate_persisted(5, &b5));
    }

    /// Every certificate write goes through the durable (synced) path; the
    /// plain, unsynced `kv_put` is never used for a certificate.
    #[tokio::test]
    async fn certificate_is_written_only_through_the_durable_path() {
        let kv = FaultKv::new(usize::MAX);
        let (mgr, _probe, _dag, b5) = durable_guarded(kv.clone()).await;
        mgr.finalize_checkpoint(5).await.expect("finalize");
        assert!(mgr.is_certificate_persisted(5, &b5));
        assert_eq!(
            FaultKv::load(&kv.plain_cert_writes),
            0,
            "a certificate must never be written with the unsynced kv_put"
        );
        assert_eq!(FaultKv::load(&kv.durable_cert_writes), 1);
    }

    /// The guard ran on a durable 3-vote certificate; the pending entry that
    /// replaced it extends it with a 4th vote, but writing that extension fails.
    /// The finalization must fall back to the guarded certificate already on
    /// disk: memory and disk agree, and the call still succeeds (the floor the
    /// guard raised has its persisted certificate).
    #[tokio::test]
    async fn extension_write_failure_keeps_the_durable_guarded_certificate() {
        let kv = FaultKv::new(1);
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 6).await;
        let mgr = Arc::new(CheckpointManager::with_persistence(
            CheckpointConfig::for_testing(),
            dag,
            kv.clone(),
        ));
        let gate = Arc::new(GateGuard::default());
        assert!(mgr.install_finalization_guard(gate.clone()));
        let b5 = blocks.get(5).expect("block 5").hash();
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        mgr.ensure_proposed(5, b5, committee.clone())
            .await
            .expect("propose");
        for i in 0..3u8 {
            mgr.submit_vote(make_signed_vote(i, 5, &b5))
                .await
                .expect("vote");
        }
        let task = tokio::spawn({
            let mgr = mgr.clone();
            async move { mgr.finalize_checkpoint(5).await }
        });
        gate.entered.notified().await;
        // The 4th vote lands on the pending entry while the guard runs.
        mgr.submit_vote(make_signed_vote(3, 5, &b5))
            .await
            .expect("4th vote");
        gate.release.notify_one();
        let cp = task.await.expect("task");
        assert!(cp.is_ok(), "{cp:?}");
        let cp = cp.expect("checked above");
        assert_eq!(
            FaultKv::load(&kv.failed_cert_writes),
            1,
            "extension write failed"
        );
        assert_eq!(
            cp.votes.len(),
            3,
            "the durable guarded certificate is finalized, not the unpersisted extension"
        );
        let stored = stored_certificate(&kv, 5).expect("guarded certificate on disk");
        assert_eq!(stored.votes.len(), 3);
        assert_eq!(
            mgr.get_checkpoint(5).await.expect("recorded").votes.len(),
            3,
            "memory and disk agree"
        );
        assert_eq!(mgr.latest_finalized_height().await, 5);
    }

    /// Stage 1a §11.9: the pending map is capped; the lowest height is evicted.
    #[tokio::test]
    async fn ensure_proposed_evicts_oldest_beyond_cap() {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let mut cfg = CheckpointConfig::for_testing();
        cfg.interval = 1;
        let count = MAX_PENDING_CHECKPOINTS.saturating_add(10);
        let blocks = build_chain(&dag, count.saturating_add(1)).await;
        let mgr = CheckpointManager::new(cfg, dag);
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        for (h, b) in blocks.iter().enumerate().skip(1) {
            let h = u64::try_from(h).expect("height fits");
            mgr.ensure_proposed(h, b.hash(), committee.clone())
                .await
                .expect("propose");
            mgr.submit_vote(make_signed_vote(0, h, &b.hash()))
                .await
                .expect("vote");
        }
        assert_eq!(mgr.pending_len().await, MAX_PENDING_CHECKPOINTS);
        assert_eq!(mgr.voted_len().await, MAX_PENDING_CHECKPOINTS);
        assert_eq!(mgr.pending_hash(1).await, None, "oldest evicted");
        mgr.prune_at_or_below(u64::MAX).await;
        assert_eq!(mgr.pending_len().await, 0);
        assert_eq!(mgr.voted_len().await, 0);
    }

    /// Stage 1a §4.3: a vote built by `sign_checkpoint_vote` under the manager's
    /// chain id is accepted; the same key signing for another chain is not.
    #[tokio::test]
    async fn sign_checkpoint_vote_is_accepted_only_on_its_chain() {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 6).await;
        let mut cfg = CheckpointConfig::for_testing();
        cfg.chain_id = 1337;
        let mgr = CheckpointManager::new(cfg, dag);
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let b5 = blocks.get(5).expect("block 5").hash();
        mgr.ensure_proposed(5, b5, committee)
            .await
            .expect("propose");
        let k0 = make_signing_key(0);
        let wrong_chain = sign_checkpoint_vote(40204, 5, b5, &k0);
        assert!(matches!(
            mgr.submit_vote(wrong_chain).await,
            Err(CheckpointError::InvalidSignature(_))
        ));
        let right = sign_checkpoint_vote(1337, 5, b5, &k0);
        assert!(mgr.submit_vote(right).await.is_ok());
    }

    /// Stage 1c §4.5: a certificate produced by an honest finalize verifies; every
    /// weakening of it (status, committee size, vote count, non-member voter, bad
    /// signature, other chain, other hash) is `InvalidCertificate`.
    #[tokio::test]
    async fn verify_certificate_accepts_honest_and_rejects_every_weakening() {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 6).await;
        let mgr = CheckpointManager::new(CheckpointConfig::for_testing(), dag);
        assert!(
            mgr.latest_finalized_certificate().await.is_none(),
            "nothing finalized yet"
        );
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let b5 = blocks.get(5).expect("block 5").hash();
        mgr.ensure_proposed(5, b5, committee)
            .await
            .expect("propose");
        for i in 0..3u8 {
            mgr.submit_vote(make_signed_vote(i, 5, &b5))
                .await
                .expect("vote");
        }
        mgr.finalize_checkpoint(5).await.expect("finalize");
        let cert = mgr
            .latest_finalized_certificate()
            .await
            .expect("latest certificate");
        assert_eq!((cert.height, cert.block_hash), (5, b5));
        cert.verify_certificate(40204).expect("honest certificate");

        let invalid = |c: &Checkpoint, chain: u64| {
            matches!(
                c.verify_certificate(chain),
                Err(CheckpointError::InvalidCertificate { height: 5, .. })
            )
        };
        assert!(invalid(&cert, 1337), "other chain id");

        let mut pending = cert.clone();
        pending.status = CheckpointStatus::Pending;
        assert!(invalid(&pending, 40204), "not finalized");

        let mut small = cert.clone();
        small.committee.truncate(3);
        assert!(invalid(&small, 40204), "committee below minimum");

        let mut thin = cert.clone();
        thin.votes.remove(&make_pubkey(0));
        assert!(invalid(&thin, 40204), "below quorum");

        let mut outsider = cert.clone();
        let sig = outsider
            .votes
            .remove(&make_pubkey(0))
            .expect("vote of member 0");
        outsider.votes.insert(make_pubkey(9), sig);
        assert!(invalid(&outsider, 40204), "voter outside the committee");

        let mut forged = cert.clone();
        let sig1 = *forged.votes.get(&make_pubkey(1)).expect("vote of member 1");
        forged.votes.insert(make_pubkey(0), sig1);
        assert!(invalid(&forged, 40204), "signature of another voter");

        let mut moved = cert.clone();
        moved.block_hash = blocks.get(4).expect("block 4").hash();
        assert!(invalid(&moved, 40204), "votes do not cover another hash");

        // An extra valid committee vote beyond quorum is still a valid certificate.
        let mut extra = cert.clone();
        let v3 = make_signed_vote(3, 5, &b5);
        extra.votes.insert(v3.voter, v3.signature);
        extra.verify_certificate(40204).expect("4 of 4 votes");
    }

    // ── Stage 1b: synced certificate verification / install (spec §11.10) ──

    /// `n` signatures over `(height, hash)` on 40204 from key ids `ids`.
    fn sigs(ids: &[u8], height: u64, hash: &Hash) -> Vec<(PublicKey, Signature)> {
        ids.iter()
            .map(|&i| {
                (
                    make_pubkey(i),
                    sign_vote(height, hash, &make_signing_key(i)),
                )
            })
            .collect()
    }

    async fn sync_mgr() -> (CheckpointManager, Vec<crate::types::Block>) {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 11).await;
        // interval 5, chain 40204.
        (
            CheckpointManager::new(CheckpointConfig::for_testing(), dag),
            blocks,
        )
    }

    #[tokio::test]
    async fn synced_certificate_verifies_against_the_local_committee_and_installs() {
        let (mgr, blocks) = sync_mgr().await;
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let h5 = blocks[5].hash();
        let cert = mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1, 2], 5, &h5), committee.clone())
            .expect("quorum 3 of 4 verifies");
        assert_eq!(
            cert.checkpoint().committee,
            committee,
            "local committee kept"
        );
        assert_eq!(
            mgr.install_synced_certificate(cert).await.expect("install"),
            SyncedInstall::Installed { height: 5 }
        );
        assert_eq!(mgr.latest_finalized_height().await, 5);
        let stored = mgr.latest_finalized_certificate().await.expect("stored");
        assert_eq!(stored.block_hash, h5);
        stored
            .verify_certificate(40204)
            .expect("stored certificate re-verifies");
        assert!(mgr.dag_store.is_finalized(&h5).await);
    }

    #[tokio::test]
    async fn synced_certificate_with_a_forged_signature_is_rejected() {
        let (mgr, blocks) = sync_mgr().await;
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let h5 = blocks[5].hash();
        let mut s = sigs(&[0, 1, 2], 5, &h5);
        // Member 2's slot carries member 3's signature: valid bytes, wrong signer.
        if let Some(slot) = s.get_mut(2) {
            slot.1 = sign_vote(5, &h5, &make_signing_key(3));
        }
        let err = mgr
            .verify_synced_certificate(5, h5, &s, committee)
            .expect_err("forged signature");
        assert!(matches!(
            err,
            CheckpointError::InvalidCertificate { height: 5, .. }
        ));
        assert_eq!(mgr.latest_finalized_height().await, 0);
    }

    /// Signatures valid for (5, h5) but by a DIFFERENT epoch's validators than
    /// the committee this node derived: rejected (voter not in committee),
    /// whatever committee the sender believed in.
    #[tokio::test]
    async fn synced_certificate_from_another_epoch_committee_is_rejected() {
        let (mgr, blocks) = sync_mgr().await;
        let local_committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let h5 = blocks[5].hash();
        let other_epoch = sigs(&[10, 11, 12, 13], 5, &h5);
        let err = mgr
            .verify_synced_certificate(5, h5, &other_epoch, local_committee)
            .expect_err("other epoch committee");
        assert!(
            err.to_string().contains("not in the committee"),
            "got {err}"
        );
    }

    /// Signatures for a sibling hash do not verify for the canonical hash.
    #[tokio::test]
    async fn synced_certificate_signed_for_a_sibling_hash_is_rejected() {
        let (mgr, blocks) = sync_mgr().await;
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let h5 = blocks[5].hash();
        let sibling = Hash::new([0xAB; 32]);
        let err = mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1, 2], 5, &sibling), committee)
            .expect_err("signed for the sibling");
        assert!(err.to_string().contains("does not verify"), "got {err}");
    }

    #[tokio::test]
    async fn synced_certificate_shape_checks_run_before_signatures() {
        let (mgr, blocks) = sync_mgr().await;
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let h5 = blocks[5].hash();
        // Below quorum.
        assert!(mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1], 5, &h5), committee.clone())
            .is_err());
        // More signatures than committee members.
        assert!(mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1, 2, 3, 4], 5, &h5), committee.clone())
            .is_err());
        // A voter listed twice.
        assert!(mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1, 1], 5, &h5), committee.clone())
            .is_err());
        // Not a checkpoint boundary.
        let h4 = blocks[4].hash();
        assert!(mgr
            .verify_synced_certificate(4, h4, &sigs(&[0, 1, 2], 4, &h4), committee.clone())
            .is_err());
        // Committee below the finality minimum.
        let tiny: Vec<PublicKey> = (0..3).map(make_pubkey).collect();
        assert!(mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1, 2], 5, &h5), tiny)
            .is_err());
    }

    #[tokio::test]
    async fn stale_synced_certificate_changes_nothing() {
        let (mgr, blocks) = sync_mgr().await;
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let (h5, h10) = (blocks[5].hash(), blocks[10].hash());
        let c10 = mgr
            .verify_synced_certificate(10, h10, &sigs(&[0, 1, 2], 10, &h10), committee.clone())
            .expect("verifies");
        mgr.install_synced_certificate(c10).await.expect("install");
        let c5 = mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1, 2], 5, &h5), committee)
            .expect("verifies");
        assert_eq!(
            mgr.install_synced_certificate(c5).await.expect("stale"),
            SyncedInstall::Stale {
                height: 5,
                latest: 10
            }
        );
        assert_eq!(mgr.latest_finalized_height().await, 10);
        assert!(
            mgr.get_checkpoint(5).await.is_none(),
            "stale one not stored"
        );
    }

    #[tokio::test]
    async fn latest_finalized_in_range_picks_the_highest_within_bounds() {
        let (mgr, blocks) = sync_mgr().await;
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        for h in [5u64, 10] {
            let hash = blocks[h as usize].hash();
            let c = mgr
                .verify_synced_certificate(h, hash, &sigs(&[0, 1, 2], h, &hash), committee.clone())
                .expect("verifies");
            mgr.install_synced_certificate(c).await.expect("install");
        }
        let pick = |a, b| {
            let mgr = &mgr;
            async move { mgr.latest_finalized_in_range(a, b).await.map(|c| c.height) }
        };
        assert_eq!(pick(0, 100).await, Some(10));
        assert_eq!(pick(0, 9).await, Some(5));
        assert_eq!(pick(5, 9).await, None);
        assert_eq!(pick(10, 100).await, None);
        assert_eq!(pick(7, 7).await, None);
    }

    // Synced certificates are written like locally finalized ones (#362):
    // through the synced write, before anything is visible; a failed write
    // installs nothing.

    async fn sync_mgr_over(kv: Arc<FaultKv>) -> (CheckpointManager, Vec<crate::types::Block>) {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let blocks = build_chain(&dag, 11).await;
        let kv: Arc<dyn KvStore> = kv;
        (
            CheckpointManager::with_persistence(CheckpointConfig::for_testing(), dag, kv),
            blocks,
        )
    }

    #[tokio::test]
    async fn synced_certificate_is_written_only_through_the_durable_path() {
        let kv = FaultKv::new(usize::MAX);
        let (mgr, blocks) = sync_mgr_over(kv.clone()).await;
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let h5 = blocks[5].hash();
        let cert = mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1, 2], 5, &h5), committee)
            .expect("verifies");
        assert!(matches!(
            mgr.install_synced_certificate(cert).await.expect("install"),
            SyncedInstall::Installed { height: 5, .. }
        ));
        assert_eq!(FaultKv::load(&kv.durable_cert_writes), 1);
        assert_eq!(
            FaultKv::load(&kv.plain_cert_writes),
            0,
            "a synced certificate must not be written with the buffered kv_put"
        );
        let stored = stored_certificate(&kv, 5).expect("on disk");
        assert_eq!(stored.block_hash, h5);
        assert!(mgr.is_certificate_persisted(5, &h5));
    }

    #[tokio::test]
    async fn synced_certificate_write_failure_installs_nothing() {
        let kv = FaultKv::new(0);
        let (mgr, blocks) = sync_mgr_over(kv.clone()).await;
        let committee: Vec<PublicKey> = (0..4).map(make_pubkey).collect();
        let h5 = blocks[5].hash();
        let cert = mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1, 2], 5, &h5), committee.clone())
            .expect("verifies");
        let err = mgr
            .install_synced_certificate(cert)
            .await
            .expect_err("a failed certificate write must surface");
        assert!(matches!(err, CheckpointError::StorageError(_)), "{err:?}");
        assert_eq!(FaultKv::load(&kv.failed_cert_writes), 1);
        assert_eq!(mgr.latest_finalized_height().await, 0, "nothing advanced");
        assert!(mgr.get_checkpoint(5).await.is_none(), "not recorded");
        assert!(stored_certificate(&kv, 5).is_none());
        assert!(
            !mgr.dag_store.is_finalized(&h5).await,
            "no DAG finalized mark without a durable certificate"
        );

        // The store recovers: the same certificate (fetched again) installs.
        kv.heal();
        let again = mgr
            .verify_synced_certificate(5, h5, &sigs(&[0, 1, 2], 5, &h5), committee)
            .expect("verifies");
        assert!(matches!(
            mgr.install_synced_certificate(again)
                .await
                .expect("install"),
            SyncedInstall::Installed { height: 5, .. }
        ));
        assert_eq!(mgr.latest_finalized_height().await, 5);
        assert!(stored_certificate(&kv, 5).is_some());
        assert!(mgr.dag_store.is_finalized(&h5).await);
    }
}
