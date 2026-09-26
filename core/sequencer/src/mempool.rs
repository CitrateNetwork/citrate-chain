// citrate/core/sequencer/src/mempool.rs

use citrate_consensus::{Hash, PublicKey, Transaction};
use priority_queue::PriorityQueue;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Error, Debug)]
pub enum MempoolError {
    #[error("Mempool is full")]
    Full,

    #[error("Transaction already exists: {0}")]
    DuplicateTransaction(Hash),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Nonce too low: expected {expected}, got {got}")]
    NonceTooLow { expected: u64, got: u64 },

    /// A transaction with this exact nonce is already buffered in the
    /// mempool for this sender. Replacement with a higher gas price
    /// is not yet supported; senders must wait for the prior tx to
    /// either be included in a block or be evicted before re-using
    /// the nonce.
    #[error("Duplicate nonce for sender: nonce {nonce}")]
    DuplicateNonce { nonce: u64 },

    #[error("Gas price too low: minimum {min}, got {got}")]
    GasPriceTooLow { min: u64, got: u64 },

    #[error("Sender limit exceeded")]
    SenderLimitExceeded,

    #[error("Invalid signature")]
    InvalidSignature,
}

/// Transaction class for categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TxClass {
    /// Standard transfer or contract call
    Standard,
    /// Model weight update
    ModelUpdate,
    /// Inference request
    Inference,
    /// Training job
    Training,
    /// Storage operation
    Storage,
    /// High-priority system transaction
    System,
    /// AI compute operations (models, inference, training)
    Compute,
}

impl TxClass {
    /// Get priority multiplier for this class
    pub fn priority_multiplier(&self) -> u64 {
        match self {
            TxClass::System => 1000,
            TxClass::ModelUpdate => 100,
            TxClass::Compute => 80,
            TxClass::Training => 50,
            TxClass::Inference => 20,
            TxClass::Storage => 10,
            TxClass::Standard => 1,
        }
    }
}

/// Transaction priority for ordering
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxPriority {
    pub gas_price: u64,
    pub class: TxClass,
    pub timestamp: u64,
    pub ai_priority: u64,
}

impl TxPriority {
    pub fn new(gas_price: u64, class: TxClass, timestamp: u64) -> Self {
        Self {
            gas_price,
            class,
            timestamp,
            ai_priority: 0,
        }
    }

    pub fn new_with_ai(gas_price: u64, class: TxClass, timestamp: u64, ai_priority: u64) -> Self {
        Self {
            gas_price,
            class,
            timestamp,
            ai_priority,
        }
    }

    /// Calculate effective priority score
    pub fn score(&self) -> u64 {
        // Use AI priority if set, otherwise fall back to class-based priority
        if self.ai_priority > 0 {
            self.ai_priority
        } else {
            // SEQ-H2: saturating ordering math. A u64 `gas_price * multiplier`
            // overflows and, with release `overflow-checks = true`, panics the
            // producer thread while scoring a single crafted tx.
            self.gas_price
                .saturating_mul(self.class.priority_multiplier())
        }
    }
}

impl Ord for TxPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher score = higher priority
        self.score()
            .cmp(&other.score())
            .then_with(|| other.timestamp.cmp(&self.timestamp)) // Older = higher priority for same score
    }
}

impl PartialOrd for TxPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Mempool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    /// Maximum number of transactions in mempool
    pub max_size: usize,

    /// Maximum transactions per sender
    pub max_per_sender: usize,

    /// Minimum gas price
    pub min_gas_price: u64,

    /// Transaction expiry time in seconds
    pub tx_expiry_secs: u64,

    /// Enable transaction replacement
    pub allow_replacement: bool,

    /// Replacement gas price increase percentage
    pub replacement_factor: u64, // e.g., 110 = 10% increase required

    /// Require valid cryptographic signature on incoming transactions
    pub require_valid_signature: bool,

    /// Chain ID for Ethereum-style transaction verification (EIP-155)
    pub chain_id: u64,

    /// RM-B1 / WP-C4.1 (audit M-SEQ-01): maximum allowed gap between
    /// the sender's lowest mempool nonce and the new tx's nonce.
    /// The 16-slot window matches Geth's default `txpool.accountqueue`.
    pub max_nonce_gap: u64,
}

/// SEQ-H2: per-block gas ceiling enforced at mempool admission: a transaction
/// whose `gas_limit` exceeds it can never fit in a block. Matches
/// `BlockBuilderConfig::max_gas_per_block` (30M), the chain's block gas limit.
pub const MAX_GAS_PER_BLOCK: u64 = 30_000_000;

/// PBA-L1a-017: largest transaction payload (`data`) the mempool admits —
/// geth's `txMaxSize` (4 x 32 KiB) and the same bound as the sequencer
/// `TxValidator::max_data_size`.
pub const MAX_TX_DATA_BYTES: usize = 128 * 1024;

/// PBA-L1a-017: ceiling on the summed size of all pooled transactions. The
/// `total_size` counter was tracked but never enforced.
pub const MAX_POOL_BYTES: usize = 64 * 1024 * 1024;

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10000,
            max_per_sender: 100,
            min_gas_price: 1_000_000_000, // 1 gwei
            tx_expiry_secs: 3600,         // 1 hour
            allow_replacement: true,
            replacement_factor: 110,
            // Tighten by default; tests or devnet can disable explicitly
            require_valid_signature: true,
            chain_id: 40204, // Testnet beta
            max_nonce_gap: 16,
        }
    }
}

/// Transaction with metadata
#[derive(Debug, Clone)]
pub struct MempoolTx {
    pub tx: Transaction,
    pub class: TxClass,
    pub priority: TxPriority,
    pub added_at: u64,
    pub size: usize,
}

/// SECREM-01 CONS-4: hard cap on the `evicted` dedup set.
///
/// Why the set exists: `remove_transaction` records every hash that
/// leaves the mempool (block inclusion, eviction, expiry) so that
/// `add_transaction` can cheaply reject a re-submission of the same
/// tx (gossip echo, RPC retry) as `DuplicateTransaction`. Unbounded,
/// it grew by one 32-byte hash per removed tx forever — a slow OOM
/// on every steady-state validator (pre-audit finding CONS-4).
///
/// Why bounding is safe: the set is a fast-path dedup, not a
/// consensus-level replay guard. Once a hash ages out (after
/// `EVICTED_CAP` newer removals), a re-submitted copy still goes
/// through full validation, the per-sender nonce-set checks here,
/// and account-nonce checks at execution time, so it cannot
/// double-spend; the only cost is transient mempool space. 100k
/// entries is ~3.2 MB of hashes and, at a sustained 1k tx/s, gives
/// ~100 s of dedup memory — far longer than gossip-echo or RPC
/// retry windows.
const EVICTED_CAP: usize = 100_000;

/// SECREM-01 CONS-4: bounded insertion-ordered hash set.
///
/// O(1) insert/contains; once `cap` is exceeded the oldest inserted
/// entry is evicted (FIFO). `order` and `set` always track the same
/// membership 1:1.
#[derive(Debug)]
struct BoundedHashSet {
    set: HashSet<Hash>,
    order: VecDeque<Hash>,
    cap: usize,
}

impl BoundedHashSet {
    fn new(cap: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    fn insert(&mut self, hash: Hash) {
        if self.set.insert(hash) {
            self.order.push_back(hash);
            while self.set.len() > self.cap {
                match self.order.pop_front() {
                    Some(oldest) => {
                        self.set.remove(&oldest);
                    }
                    // Unreachable: order mirrors set membership.
                    None => break,
                }
            }
        }
    }

    fn contains(&self, hash: &Hash) -> bool {
        self.set.contains(hash)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.set.len()
    }

    fn clear(&mut self) {
        self.set.clear();
        self.order.clear();
    }
}

/// PBA-L1a-001: reads a sender's COMMITTED (on-chain) nonce. The node wires
/// this to the executor so admission can bound a new sender's nonce against
/// state instead of accepting any value (the per-sender gap check only sees
/// txs already buffered here).
pub type StateNonceReader = Arc<dyn Fn(&PublicKey) -> u64 + Send + Sync>;

/// Transaction mempool
pub struct Mempool {
    /// Configuration
    config: MempoolConfig,

    /// All pending transactions by hash
    transactions: Arc<RwLock<HashMap<Hash, MempoolTx>>>,

    /// Priority queue of transaction hashes
    priority_queue: Arc<RwLock<PriorityQueue<Hash, TxPriority>>>,

    /// Transactions grouped by sender
    by_sender: Arc<RwLock<HashMap<PublicKey, VecDeque<Hash>>>>,

    /// Per-sender set of nonces currently buffered in the mempool.
    ///
    /// Previously this was a `HashMap<PublicKey, u64>` tracking a
    /// single "next expected nonce" per sender, written through
    /// `tx.nonce + 1` on every accepted tx. That design had two
    /// catastrophic faults (backlog #123, L-002):
    ///
    /// 1. **Forward-jump accept**: any accepted future-nonce tx
    ///    leapfrogged the counter, causing every later lower-nonce
    ///    tx to be rejected as `NonceTooLow` under any concurrent
    ///    submission pattern.
    /// 2. **Stale counter**: the counter was never decremented when
    ///    txs left the mempool (eviction, expiration), leaving a
    ///    phantom high watermark that permanently poisoned the
    ///    sender until node restart.
    ///
    /// The set-of-nonces model fixes both: the set IS the source
    /// of truth for "what nonces does this sender have pending?",
    /// it's pruned on every removal, and `pending_nonce` is
    /// derived from it on read. No counter to leapfrog, no phantom
    /// to persist.
    ///
    /// Empty sets are pruned from the map eagerly.
    sender_nonces: Arc<RwLock<HashMap<PublicKey, BTreeSet<u64>>>>,

    /// Recently evicted transaction hashes (for duplicate detection).
    /// SECREM-01 CONS-4: bounded to `EVICTED_CAP` entries (FIFO
    /// aging) so steady-state operation no longer leaks memory.
    evicted: Arc<RwLock<BoundedHashSet>>,

    /// Total size of transactions in bytes
    total_size: Arc<RwLock<usize>>,

    /// PBA-L1a-001: optional committed-nonce reader (see [`StateNonceReader`]).
    state_nonce: Option<StateNonceReader>,

    /// PBA-L1a-004: senders temporarily refused admission (until the instant),
    /// set by the producer when a sender's transaction fails before a receipt
    /// exists (such a failure costs the sender nothing on chain).
    banned: Arc<RwLock<HashMap<PublicKey, std::time::Instant>>>,
}

/// PBA-L1a-004: most senders held in the temporary ban list.
pub const MAX_BANNED_SENDERS: usize = 10_000;

impl Mempool {
    /// Return configured chain id
    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            transactions: Arc::new(RwLock::new(HashMap::new())),
            priority_queue: Arc::new(RwLock::new(PriorityQueue::new())),
            by_sender: Arc::new(RwLock::new(HashMap::new())),
            sender_nonces: Arc::new(RwLock::new(HashMap::new())),
            // SECREM-01 CONS-4: bounded dedup set (was an unbounded HashSet)
            evicted: Arc::new(RwLock::new(BoundedHashSet::new(EVICTED_CAP))),
            total_size: Arc::new(RwLock::new(0)),
            state_nonce: None,
            banned: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// PBA-L1a-004: refuse `sender` for `duration` and drop its pooled
    /// transactions. Producer-side policy; no effect on block validity.
    pub async fn ban_sender(&self, sender: &PublicKey, duration: std::time::Duration) {
        let now = std::time::Instant::now();
        {
            let mut b = self.banned.write().await;
            b.retain(|_, until| *until > now);
            if b.len() >= MAX_BANNED_SENDERS && !b.contains_key(sender) {
                // Full: evict the entry that expires soonest.
                if let Some(oldest) = b.iter().min_by_key(|(_, until)| **until).map(|(k, _)| *k) {
                    b.remove(&oldest);
                }
            }
            b.insert(*sender, now + duration);
        }
        let hashes: Vec<Hash> = self
            .by_sender
            .read()
            .await
            .get(sender)
            .map(|q| q.iter().copied().collect())
            .unwrap_or_default();
        for h in hashes {
            self.remove_transaction(&h).await;
        }
    }

    /// Whether `sender` is currently refused admission.
    pub async fn is_banned(&self, sender: &PublicKey) -> bool {
        self.banned
            .read()
            .await
            .get(sender)
            .is_some_and(|until| *until > std::time::Instant::now())
    }

    /// PBA-L1a-001: bound admitted nonces against the sender's committed
    /// nonce: reject `nonce < state` (stale) and `nonce > state +
    /// max_nonce_gap` (unselectable gap-junk), for new senders too.
    pub fn with_state_nonce_reader(mut self, reader: StateNonceReader) -> Self {
        self.state_nonce = Some(reader);
        self
    }

    /// Add a transaction to the mempool
    pub async fn add_transaction(
        &self,
        mut tx: Transaction,
        mut class: TxClass,
    ) -> Result<(), MempoolError> {
        // Determine transaction type from data
        tx.determine_type();

        // Override class from the executor-aligned AI classifier (the same one
        // the executor dispatches on), not the wire `tx_type` label.
        if citrate_consensus::types::AiOpKind::of(&tx).is_some() {
            class = TxClass::Compute;
        }

        tracing::info!(
            "Adding transaction to mempool: hash={:?}, from={:?}, nonce={}, type={:?}",
            tx.hash,
            tx.from,
            tx.nonce,
            tx.tx_type
        );

        // Basic validation
        self.validate_transaction(&tx).await?;

        // PBA-L1a-006: the dedup / storage key is the canonical id derived
        // from the signed contents, never the claimed `tx.hash`. Before this an
        // attacker's own signed tx carrying a victim's hash took the victim's
        // dedup slot (targeted censorship) and, if mined, overwrote the
        // victim's stored tx/receipt. Only a tx that did not authenticate here
        // (the trusted-decoder `ecdsa_verified` path, or signature checking
        // disabled by config) keeps its claimed hash; block import rejects a
        // non-canonical hash after the PBA-R2 activation height.
        if let Ok(canonical) = citrate_consensus::tx_auth::authenticate(&tx) {
            tx.hash = canonical;
        }

        let tx_hash = tx.hash;
        let sender = tx.from;

        // Check for duplicates
        if self.transactions.read().await.contains_key(&tx_hash) {
            tracing::warn!("Duplicate transaction: {:?}", tx_hash);
            return Err(MempoolError::DuplicateTransaction(tx_hash));
        }

        // Check if previously evicted
        if self.evicted.read().await.contains(&tx_hash) {
            return Err(MempoolError::DuplicateTransaction(tx_hash));
        }

        // Check sender limit
        let sender_txs = self.by_sender.read().await;
        if let Some(txs) = sender_txs.get(&sender) {
            if txs.len() >= self.config.max_per_sender {
                return Err(MempoolError::SenderLimitExceeded);
            }
        }
        drop(sender_txs);

        // Per-sender nonce uniqueness check: the mempool buffers a
        // set of nonces per sender, not a next-expected counter.
        // Reject an attempt to add two txs with the same nonce from
        // the same sender (nonce-replacement is not yet supported).
        // This path must come AFTER the hash-level duplicate check so
        // that exact-tx re-adds are caught as DuplicateTransaction,
        // and we only surface DuplicateNonce when the nonce collides
        // with a different tx hash.
        //
        // RM-B1 / WP-C4.1 (audit M-SEQ-01): also enforce
        // `tx.nonce <= min_existing_nonce + max_nonce_gap`. Pre-fix
        // a funded attacker could post 100 nonces per address with
        // arbitrary spacing (1, 1_000_000, u64::MAX, …) — 99 of
        // those rotted as gap-junk while consuming slots. The
        // 16-slot window matches Geth's `txpool.accountqueue`.
        if let Some(set) = self.sender_nonces.read().await.get(&sender) {
            if set.contains(&tx.nonce) {
                tracing::warn!(
                    "Duplicate nonce for sender {:?}: nonce={}",
                    sender,
                    tx.nonce
                );
                return Err(MempoolError::DuplicateNonce { nonce: tx.nonce });
            }
            if let Some(&min_nonce) = set.iter().next() {
                let gap = tx.nonce.saturating_sub(min_nonce);
                if gap > self.config.max_nonce_gap {
                    tracing::warn!(
                        "M-SEQ-01: nonce gap from sender {:?}: tx.nonce={}, min_existing={}, gap={} > {}",
                        sender, tx.nonce, min_nonce, gap, self.config.max_nonce_gap
                    );
                    return Err(MempoolError::DuplicateNonce { nonce: tx.nonce });
                }
            }
        }

        // PBA-L1a-001: `u64::MAX` can never be followed (the sender's next
        // nonce would overflow), so it is never a valid nonce to admit. Before
        // this check a fresh key's validly signed `nonce = u64::MAX` tx was
        // admitted — the gap check above only runs for a sender that already
        // has pending txs — and `get_best_transactions` panicked on
        // `nonce + 1`, killing the producer task. Every ingress (RPC, P2P
        // `NewTransaction` and `Transactions`) goes through here.
        if tx.nonce == u64::MAX {
            return Err(MempoolError::InvalidTransaction(
                "nonce u64::MAX is not admissible (PBA-L1a-001)".into(),
            ));
        }

        // Check mempool size limit
        if self.transactions.read().await.len() >= self.config.max_size {
            // Try to evict lower priority transaction
            self.evict_lowest_priority().await?;
        }
        // PBA-L1a-017: enforce the byte budget too (evict lowest priority
        // until the new transaction fits; `Full` if nothing is left to evict).
        let incoming_size = self.calculate_tx_size(&tx);
        while *self.total_size.read().await + incoming_size > MAX_POOL_BYTES {
            self.evict_lowest_priority().await?;
        }

        // Create mempool transaction with AI-aware priority
        let timestamp = chrono::Utc::now().timestamp() as u64;

        // AI operations are ordered by fee like everything else (class
        // multiplier only); no fee-independent boost.
        let ai_priority = 0;
        let priority = TxPriority::new_with_ai(tx.gas_price, class, timestamp, ai_priority);
        let tx_size = self.calculate_tx_size(&tx);

        let mempool_tx = MempoolTx {
            tx: tx.clone(),
            class,
            priority,
            added_at: timestamp,
            size: tx_size,
        };

        // Add to collections
        self.transactions.write().await.insert(tx_hash, mempool_tx);
        self.priority_queue.write().await.push(tx_hash, priority);

        // Update sender tracking
        self.by_sender
            .write()
            .await
            .entry(sender)
            .or_insert_with(VecDeque::new)
            .push_back(tx_hash);

        // Update the per-sender nonce set. The old model had a buggy
        // write-through "next expected" counter here
        // (`self.nonces.insert(sender, tx.nonce + 1)`) — see the
        // sender_nonces doc comment on the struct for why that was
        // catastrophically wrong. The new model simply adds this
        // tx's nonce to the sender's set; pending_nonce is derived
        // from the max of the set on read.
        self.sender_nonces
            .write()
            .await
            .entry(sender)
            .or_default()
            .insert(tx.nonce);

        // Update total size
        *self.total_size.write().await += tx_size;

        info!(
            "Added transaction {} from {:?} with priority {} to mempool",
            tx_hash,
            sender,
            priority.score()
        );

        Ok(())
    }

    /// Validate a transaction
    async fn validate_transaction(&self, tx: &Transaction) -> Result<(), MempoolError> {
        tracing::debug!("Validating transaction with hash: {:?}", tx.hash);

        // PBA-L1a-017: bound the payload before anything else looks at it.
        if tx.data.len() > MAX_TX_DATA_BYTES {
            return Err(MempoolError::InvalidTransaction(format!(
                "transaction data is {} bytes; the maximum is {}",
                tx.data.len(),
                MAX_TX_DATA_BYTES
            )));
        }

        // PBA-L1a-004: admit only what the executor's own parser accepts. A
        // payload it rejects fails before a receipt exists (no fee is charged),
        // so it must never occupy block-selection space. Same function the
        // executor dispatches through, so the two cannot drift.
        if citrate_execution::executor::Executor::parse_transaction_type(tx).is_err() {
            return Err(MempoolError::InvalidTransaction(
                "transaction payload is not executable".to_string(),
            ));
        }

        if self.is_banned(&tx.from).await {
            return Err(MempoolError::InvalidTransaction(
                "sender temporarily refused".to_string(),
            ));
        }

        if let Some(read_state_nonce) = &self.state_nonce {
            let state_nonce = read_state_nonce(&tx.from);
            if tx.nonce < state_nonce {
                return Err(MempoolError::NonceTooLow {
                    expected: state_nonce,
                    got: tx.nonce,
                });
            }
            if tx.nonce - state_nonce > self.config.max_nonce_gap {
                return Err(MempoolError::InvalidTransaction(format!(
                    "nonce {} is more than {} ahead of the sender's committed nonce {} \
                     (PBA-L1a-001)",
                    tx.nonce, self.config.max_nonce_gap, state_nonce
                )));
            }
        }

        // Basic sanity checks

        // For devnet mode, accept test signatures and addresses
        #[cfg(feature = "devnet")]
        {
            // In devnet, we're more lenient with signatures for testing
            // Just check that from address is not all zeros
            if tx.from.as_bytes().iter().all(|&b| b == 0) {
                tracing::warn!("Transaction has empty sender public key");
                return Err(MempoolError::InvalidTransaction("Empty sender".into()));
            }
            // Accept any non-zero signature in devnet mode for testing
            tracing::debug!("Devnet mode: Accepting test transaction from {:?}", tx.from);
        }

        #[cfg(not(feature = "devnet"))]
        {
            // Production validation
            if tx.signature.as_bytes().iter().all(|&b| b == 0) {
                tracing::warn!("Transaction has empty signature");
                return Err(MempoolError::InvalidSignature);
            }
            if tx.from.as_bytes().iter().all(|&b| b == 0) {
                tracing::warn!("Transaction has empty sender public key");
                return Err(MempoolError::InvalidTransaction("Empty sender".into()));
            }
            // WP-K.1: For ECDSA-shaped transactions (20-byte embedded EVM address),
            // require ecdsa_verified=true. This flag is set ONLY by the tx decoder
            // after cryptographic ECDSA recovery. The bincode fallback path forces
            // ecdsa_verified=false, so forged payloads cannot bypass this gate.
            let from_bytes = tx.from.as_bytes();
            let is_evm_address = from_bytes[20..].iter().all(|&b| b == 0)
                && !from_bytes[..20].iter().all(|&b| b == 0);
            // PBA-L1b-007: a tx that arrived over P2P has the flag stripped;
            // accept it when the signer is recovered from its contents (all
            // EIP-2718 types), never on address shape or the flag alone.
            if is_evm_address && !tx.ecdsa_verified && !self.verify_eth_ecdsa(tx).unwrap_or(false) {
                tracing::warn!(
                    "ECDSA-shaped transaction from {:?} rejected: not decoder-verified and \
                     the signer does not recover from its contents",
                    tx.from
                );
                return Err(MempoolError::InvalidSignature);
            }
        }

        // CHAIN-B-A015: sender authenticity for EVM-shaped (20-byte embedded) senders must
        // rest on a REAL secp256k1 recovery, never on a compile-time feature, the
        // `ecdsa_verified` flag alone, or the `require_valid_signature` switch. The WP-K.1
        // gate above lives under `#[cfg(not(feature = "devnet"))]`, and `citrate-sequencer`
        // ships `default = ["devnet"]`, so in a default build that gate is compiled OUT; and
        // the `require_valid_signature=false` early-return below skips all cryptography. Both
        // P2P ingress paths deliver transactions with `ecdsa_verified=false`, so without this
        // an unauthenticated peer can insert transactions from ANY address. Recover here,
        // unconditionally: if the sender is EVM-shaped and not already decoder-verified,
        // require `verify_eth_ecdsa` to recover exactly `from[0..20]`. This is INERT on honest
        // traffic (a validly-signed tx always recovers) and rejects only forgeries.
        {
            let from_bytes = tx.from.as_bytes();
            let is_evm_address = from_bytes[20..].iter().all(|&b| b == 0)
                && !from_bytes[..20].iter().all(|&b| b == 0);
            if is_evm_address && !tx.ecdsa_verified && !self.verify_eth_ecdsa(tx).unwrap_or(false) {
                tracing::warn!(
                    "CHAIN-B-A015: EVM-shaped tx from {:?} rejected — secp256k1 recovery did \
                     not match the claimed sender (feature/config-independent gate)",
                    tx.from
                );
                return Err(MempoolError::InvalidSignature);
            }
        }

        // Check gas price
        if tx.gas_price < self.config.min_gas_price {
            tracing::warn!(
                "Transaction gas price too low: {} < {}",
                tx.gas_price,
                self.config.min_gas_price
            );
            return Err(MempoolError::GasPriceTooLow {
                min: self.config.min_gas_price,
                got: tx.gas_price,
            });
        }

        // SEQ-H2: reject a transaction whose gas_limit exceeds the per-block
        // ceiling. Such a tx can never be selected into a block; admitting it
        // just parks it at the head of the fee-ordered queue where the block
        // builder repeatedly trips over it. Rejecting at admission (combined
        // with the builder's `continue`-not-`break` fix) closes the free
        // empty-block halt.
        if tx.gas_limit > MAX_GAS_PER_BLOCK {
            tracing::warn!(
                "Transaction gas_limit {} exceeds per-block ceiling {}",
                tx.gas_limit,
                MAX_GAS_PER_BLOCK
            );
            return Err(MempoolError::InvalidTransaction(format!(
                "gas_limit {} exceeds per-block ceiling {}",
                tx.gas_limit, MAX_GAS_PER_BLOCK
            )));
        }

        // Check chain ID (M-01: mandatory — reject transactions without chain domain binding)
        match tx.chain_id {
            Some(tx_chain_id) if tx_chain_id == self.config.chain_id => {
                // Chain ID matches — ok
            }
            Some(tx_chain_id) => {
                tracing::warn!(
                    "Transaction chain ID mismatch: expected {}, got {}",
                    self.config.chain_id,
                    tx_chain_id
                );
                return Err(MempoolError::InvalidTransaction(format!(
                    "Wrong chain ID: expected {}, got {}",
                    self.config.chain_id, tx_chain_id
                )));
            }
            None => {
                tracing::warn!("Transaction missing chain ID (pre-EIP-155 not accepted)");
                return Err(MempoolError::InvalidTransaction(format!(
                    "Missing chain ID: all transactions must specify chain_id={}",
                    self.config.chain_id
                )));
            }
        }

        // Note: nonce validation against a per-sender "expected"
        // counter was removed as part of backlog #123 (L-002) — that
        // counter was a single high-watermark value that couldn't
        // represent buffered future nonces and that got poisoned by
        // evicted forward-jump txs. The new model treats duplicate
        // nonces from the same sender as the only validation-time
        // rejection (`DuplicateNonce`, enforced in add_transaction
        // under the sender-limit check). Stale-vs-chain-state
        // rejection requires state access and is tracked as a
        // follow-up (see backlog #123 §"State-aware validation").
        // Until then, stale txs naturally get filtered out by
        // get_best_transactions (which picks consecutive nonces
        // from the mempool minimum) and by the executor rejecting
        // mismatched nonces on block application.

        // Verify signature using real cryptographic verification unless disabled by config
        if !self.config.require_valid_signature {
            tracing::debug!("Signature verification disabled via mempool config");
            return Ok(());
        }

        match citrate_consensus::crypto::verify_transaction(tx) {
            Ok(true) => {
                // Signature is valid
            }
            Ok(false) => {
                // Try Ethereum-style secp256k1 verification as a fallback
                if self.verify_eth_ecdsa(tx).unwrap_or(false) {
                    tracing::info!("Verified transaction via Ethereum-style ECDSA");
                } else {
                    return Err(MempoolError::InvalidTransaction(
                        "Invalid signature: verification failed".to_string(),
                    ));
                }
            }
            Err(e) => {
                return Err(MempoolError::InvalidTransaction(format!(
                    "Signature error: {}",
                    e
                )));
            }
        }

        Ok(())
    }

    /// Verify a transaction's signature from its contents alone.
    ///
    /// PBA-L1b-007: this used to rebuild ONLY the legacy EIP-155 payload (and
    /// encoded value 0 as `0x00` instead of `0x80`), so every EIP-2930/1559
    /// transaction and every zero-value legacy one arriving over P2P (where
    /// `ecdsa_verified` is stripped) failed and was dropped. It now delegates
    /// to the shared verifier block import also uses (`tx_auth::authenticate`:
    /// legacy/2930/1559 payloads, EIP-2 low-s, ed25519 for native keys).
    fn verify_eth_ecdsa(&self, tx: &Transaction) -> anyhow::Result<bool> {
        Ok(citrate_consensus::tx_auth::authenticate(tx).is_ok())
    }

    /// Remove a transaction from mempool
    pub async fn remove_transaction(&self, hash: &Hash) -> Option<Transaction> {
        // Remove from main storage
        let mempool_tx = self.transactions.write().await.remove(hash)?;

        // Remove from priority queue
        self.priority_queue.write().await.remove(hash);

        let sender = mempool_tx.tx.from;
        let removed_nonce = mempool_tx.tx.nonce;

        // Remove from sender list
        if let Some(sender_txs) = self.by_sender.write().await.get_mut(&sender) {
            sender_txs.retain(|&h| h != *hash);
        }

        // Update total size
        *self.total_size.write().await -= mempool_tx.size;

        // Remove this tx's nonce from the per-sender set and prune
        // the entry entirely if no nonces remain. This replaces the
        // old `rollback_nonce_for_sender` path, which could only
        // handle tip-removal and left phantom high watermarks when
        // a non-tip nonce was removed (backlog #123 fault 2).
        {
            let mut sender_nonces = self.sender_nonces.write().await;
            let prune = if let Some(set) = sender_nonces.get_mut(&sender) {
                set.remove(&removed_nonce);
                set.is_empty()
            } else {
                false
            };
            if prune {
                sender_nonces.remove(&sender);
            }
        }

        // Add to evicted set (to prevent re-addition)
        self.evicted.write().await.insert(*hash);

        debug!("Removed transaction {} from mempool", hash);

        Some(mempool_tx.tx)
    }

    /// Consistency check for the per-sender nonce sets.
    ///
    /// Historically (Sprint EL-1, Issue #20) this method rebuilt a
    /// single "expected next nonce" counter per sender from
    /// `by_sender` after the block producer finished a block, to
    /// work around the forward-jump bug (backlog #123 fault 1).
    /// The new set-based nonce model prunes on every
    /// `remove_transaction` so no post-block reconciliation should
    /// be needed under normal operation.
    ///
    /// This method is kept as a safety net and as a public API for
    /// tests + the producer. It rebuilds `sender_nonces` from
    /// `by_sender`/`transactions`, correcting any drift (which
    /// should only happen if someone bypassed `remove_transaction`).
    pub async fn reconcile_nonces(&self) {
        let by_sender = self.by_sender.read().await;
        let txs = self.transactions.read().await;
        let mut sender_nonces = self.sender_nonces.write().await;

        let mut rebuilt: HashMap<PublicKey, BTreeSet<u64>> = HashMap::new();
        for (sender, tx_hashes) in by_sender.iter() {
            let set: BTreeSet<u64> = tx_hashes
                .iter()
                .filter_map(|h| txs.get(h).map(|t| t.tx.nonce))
                .collect();
            if !set.is_empty() {
                rebuilt.insert(*sender, set);
            }
        }

        // Detect any divergence for the debug log, then swap in the
        // rebuilt view wholesale.
        for (sender, new_set) in rebuilt.iter() {
            match sender_nonces.get(sender) {
                Some(old) if old != new_set => {
                    debug!(
                        "Reconciled sender_nonces for {:?}: {:?} -> {:?}",
                        sender, old, new_set
                    );
                }
                _ => {}
            }
        }
        for sender in sender_nonces.keys().cloned().collect::<Vec<_>>() {
            if !rebuilt.contains_key(&sender) {
                debug!("Removed stale sender_nonces entry for {:?}", sender);
            }
        }

        *sender_nonces = rebuilt;
    }

    /// Return the highest-plus-one nonce currently buffered in the
    /// mempool for this sender, or `None` if no txs from this sender
    /// are pending. This is the "pending nonce" value surfaced to
    /// `eth_getTransactionCount(address, "pending")` via the
    /// `MempoolAccess::get_pending_nonce` trait method.
    ///
    /// Note this is derived on read from the authoritative
    /// `sender_nonces` set — it cannot drift from the actual tx
    /// storage the way the old `self.nonces` counter could.
    pub async fn pending_nonce_for(&self, sender: &PublicKey) -> Option<u64> {
        let set = self.sender_nonces.read().await;
        set.get(sender)
            .and_then(|s| s.iter().next_back().copied())
            .and_then(|n| n.checked_add(1))
    }

    /// PBA-L1a-021: the pending nonce (`max pending nonce + 1`) over every
    /// sender whose key satisfies `matches`, WITHOUT cloning transactions.
    ///
    /// `eth_getTransactionCount(addr, "pending")` used to clone the entire
    /// mempool (every payload) per call to find one sender's nonces, and then
    /// computed `m + 1` unchecked (panics on a pending `u64::MAX`). This walks
    /// only the per-sender nonce index. Returns `None` when no matching sender
    /// has pending transactions, or when the successor of the highest pending
    /// nonce would overflow (a `u64::MAX` nonce has no next nonce).
    pub async fn pending_nonce_matching<F>(&self, matches: F) -> Option<u64>
    where
        F: Fn(&PublicKey) -> bool,
    {
        let set = self.sender_nonces.read().await;
        set.iter()
            .filter(|(sender, _)| matches(sender))
            .filter_map(|(_, nonces)| nonces.iter().next_back().copied())
            .max()
            .and_then(|m| m.checked_add(1))
    }

    /// Get AI transactions (model operations, inference requests)
    pub async fn get_ai_transactions(&self, max_count: usize) -> Vec<Transaction> {
        let transactions = self.transactions.read().await;
        // Executor-aligned classification, highest fee first (ties: oldest).
        let mut ai: Vec<&MempoolTx> = transactions
            .values()
            .filter(|m| citrate_consensus::types::AiOpKind::of(&m.tx).is_some())
            .collect();
        ai.sort_by(|a, b| {
            b.tx.gas_price
                .cmp(&a.tx.gas_price)
                .then(a.added_at.cmp(&b.added_at))
                .then(a.tx.hash.as_bytes().cmp(b.tx.hash.as_bytes()))
        });
        ai.into_iter()
            .take(max_count)
            .map(|m| m.tx.clone())
            .collect()
    }

    /// Get the best transactions for block inclusion
    pub async fn get_best_transactions(
        &self,
        max_count: usize,
        max_size: usize,
    ) -> Vec<Transaction> {
        let mut selected: Vec<Transaction> = Vec::new();
        let mut total_size = 0;
        let mut next_nonce: HashMap<PublicKey, u64> = HashMap::new();
        let mut picked: HashSet<Hash> = HashSet::new();

        // Snapshot state to avoid nested awaits in loops
        let txs = self.transactions.read().await;
        let by_sender = self.by_sender.read().await;
        let priority_queue = self.priority_queue.read().await;
        let mut sorted: Vec<(Hash, TxPriority)> =
            priority_queue.iter().map(|(h, p)| (*h, *p)).collect();
        drop(priority_queue);
        sorted.sort_by_key(|x| std::cmp::Reverse(x.1));

        loop {
            let mut progressed = false;
            for (hash, _prio) in &sorted {
                if selected.len() >= max_count {
                    break;
                }
                if let Some(mtx) = txs.get(hash) {
                    if picked.contains(hash) {
                        continue;
                    }
                    if total_size + mtx.size > max_size {
                        continue;
                    }

                    let sender = mtx.tx.from;
                    let expected = next_nonce.get(&sender).copied().or_else(|| {
                        by_sender.get(&sender).and_then(|list| {
                            list.iter()
                                .filter_map(|h| txs.get(h).map(|t| t.tx.nonce))
                                .min()
                        })
                    });

                    let ok = match expected {
                        Some(n) => mtx.tx.nonce == n,
                        None => true,
                    };
                    if ok {
                        // PBA-L1a-001: `nonce + 1` panicked (overflow-checks) on
                        // a u64::MAX nonce and killed the producer task. A tx
                        // whose successor nonce does not exist is skipped.
                        let Some(successor) = mtx.tx.nonce.checked_add(1) else {
                            continue;
                        };
                        total_size += mtx.size;
                        next_nonce.insert(sender, successor);
                        picked.insert(*hash);
                        selected.push(mtx.tx.clone());
                        progressed = true;
                        if selected.len() >= max_count {
                            break;
                        }
                    }
                }
            }
            if !progressed {
                break;
            }
        }

        info!(
            "Selected {} transactions for block inclusion",
            selected.len()
        );
        selected
    }

    /// Check if transaction has the next expected nonce for sender
    #[allow(dead_code)]
    async fn is_next_nonce(&self, tx: &Transaction, included: &HashSet<Hash>) -> bool {
        let by_sender = self.by_sender.read().await;

        if let Some(sender_txs) = by_sender.get(&tx.from) {
            // Find the highest nonce already included
            let mut highest_included_nonce = None;

            for tx_hash in sender_txs {
                if included.contains(tx_hash) {
                    if let Some(mempool_tx) = self.transactions.read().await.get(tx_hash) {
                        highest_included_nonce = Some(
                            highest_included_nonce
                                .map_or(mempool_tx.tx.nonce, |n: u64| n.max(mempool_tx.tx.nonce)),
                        );
                    }
                }
            }

            // Check if this tx has the next nonce
            match highest_included_nonce {
                Some(nonce) => nonce.checked_add(1) == Some(tx.nonce),
                None => {
                    // No txs from this sender included yet, allow contiguous sequence starting at the minimal nonce
                    let txs_guard = self.transactions.read().await;
                    let mut nonces: Vec<u64> = sender_txs
                        .iter()
                        .filter_map(|h| txs_guard.get(h).map(|t| t.tx.nonce))
                        .collect();
                    if nonces.is_empty() {
                        return true;
                    }
                    nonces.sort_unstable();
                    // If the minimal nonce is n0, allow n0, n0+1, n0+2,... as we include them in one selection pass
                    let min = nonces[0];
                    tx.nonce >= min
                }
            }
        } else {
            true // First tx from this sender
        }
    }

    /// Evict the lowest priority transaction
    async fn evict_lowest_priority(&self) -> Result<(), MempoolError> {
        let priority_queue = self.priority_queue.read().await;

        // Find the transaction with the lowest priority
        let lowest = priority_queue
            .iter()
            .min_by_key(|(_, priority)| priority.score())
            .map(|(hash, _)| *hash);

        drop(priority_queue);

        if let Some(hash) = lowest {
            self.remove_transaction(&hash).await;
            Ok(())
        } else {
            Err(MempoolError::Full)
        }
    }

    /// Calculate transaction size
    fn calculate_tx_size(&self, tx: &Transaction) -> usize {
        Self::tx_size(tx)
    }

    /// The size the pool (and the producer's block-size cap) charges a
    /// transaction.
    pub fn tx_size(tx: &Transaction) -> usize {
        // Approximate size calculation
        32 + // hash
        8 + // nonce  
        32 + // from
        32 + // to (optional)
        16 + // value
        8 + // gas_limit
        8 + // gas_price
        tx.data.len() + // data
        64 // signature
    }

    /// Clear expired transactions
    pub async fn clear_expired(&self) {
        let current_time = chrono::Utc::now().timestamp() as u64;
        let expiry_time = current_time.saturating_sub(self.config.tx_expiry_secs);

        let txs = self.transactions.read().await;
        let expired: Vec<Hash> = txs
            .iter()
            .filter(|(_, tx)| tx.added_at < expiry_time)
            .map(|(hash, _)| *hash)
            .collect();
        drop(txs);

        let count = expired.len();
        for hash in expired {
            self.remove_transaction(&hash).await;
        }

        debug!("Cleared {} expired transactions", count);
    }

    /// Get mempool statistics
    pub async fn stats(&self) -> MempoolStats {
        let txs = self.transactions.read().await;
        let mut by_class = HashMap::new();

        for mempool_tx in txs.values() {
            *by_class.entry(mempool_tx.class).or_insert(0) += 1;
        }

        MempoolStats {
            total_transactions: txs.len(),
            total_size: *self.total_size.read().await,
            by_class,
            unique_senders: self.by_sender.read().await.len(),
        }
    }

    /// Get transaction by hash
    pub async fn get_transaction(&self, hash: &Hash) -> Option<Transaction> {
        self.transactions
            .read()
            .await
            .get(hash)
            .map(|tx| tx.tx.clone())
    }

    /// Check if transaction exists
    pub async fn contains(&self, hash: &Hash) -> bool {
        self.transactions.read().await.contains_key(hash)
    }

    /// Get multiple transactions from mempool
    pub async fn get_transactions(&self, limit: usize) -> Vec<Transaction> {
        let txs = self.transactions.read().await;
        let mut result = Vec::new();

        for (_, mempool_tx) in txs.iter().take(limit) {
            result.push(mempool_tx.tx.clone());
        }

        result
    }

    /// Clear the mempool
    pub async fn clear(&self) {
        self.transactions.write().await.clear();
        self.priority_queue.write().await.clear();
        self.by_sender.write().await.clear();
        self.evicted.write().await.clear();
        self.sender_nonces.write().await.clear();
        *self.total_size.write().await = 0;
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    pub total_transactions: usize,
    pub total_size: usize,
    pub by_class: HashMap<TxClass, usize>,
    pub unique_senders: usize,
}

/// Trait for abstracting mempool access patterns.
///
/// This trait allows the RPC server to work with both:
/// - `Arc<Mempool>` (used by the core node)
/// - `Arc<RwLock<Mempool>>` (used by the GUI embedded node)
///
/// All methods are async to support both direct and locked access.
#[async_trait::async_trait]
pub trait MempoolAccess: Send + Sync {
    /// Get the chain ID configured for this mempool
    fn chain_id(&self) -> u64;

    /// Add a transaction to the mempool
    async fn add_transaction(&self, tx: Transaction, class: TxClass) -> Result<(), MempoolError>;

    /// Remove a transaction from the mempool
    async fn remove_transaction(&self, hash: &Hash) -> Option<Transaction>;

    /// Get a transaction by hash
    async fn get_transaction(&self, hash: &Hash) -> Option<Transaction>;

    /// Check if a transaction exists in the mempool
    async fn contains(&self, hash: &Hash) -> bool;

    /// Get transactions up to a limit, ordered by priority
    async fn get_transactions(&self, limit: usize) -> Vec<Transaction>;

    /// Get AI-specific transactions
    async fn get_ai_transactions(&self, max_count: usize) -> Vec<Transaction>;

    /// Get mempool statistics
    async fn stats(&self) -> MempoolStats;

    /// Clear all transactions from the mempool
    async fn clear(&self);

    /// Clear expired transactions
    async fn clear_expired(&self);

    /// Get the pending nonce for a sender (next expected nonce)
    async fn get_pending_nonce(&self, sender: &PublicKey) -> Option<u64>;

    /// Sprint EL-1 (Issue #20): Reconcile nonce map with actual remaining transactions.
    /// Called by the producer after block execution.
    async fn reconcile_nonces(&self);
}

/// Implementation of MempoolAccess for Arc<Mempool> (direct access)
#[async_trait::async_trait]
impl MempoolAccess for Arc<Mempool> {
    fn chain_id(&self) -> u64 {
        Mempool::chain_id(self)
    }

    async fn add_transaction(&self, tx: Transaction, class: TxClass) -> Result<(), MempoolError> {
        Mempool::add_transaction(self, tx, class).await
    }

    async fn remove_transaction(&self, hash: &Hash) -> Option<Transaction> {
        Mempool::remove_transaction(self, hash).await
    }

    async fn get_transaction(&self, hash: &Hash) -> Option<Transaction> {
        Mempool::get_transaction(self, hash).await
    }

    async fn contains(&self, hash: &Hash) -> bool {
        Mempool::contains(self, hash).await
    }

    async fn get_transactions(&self, limit: usize) -> Vec<Transaction> {
        Mempool::get_transactions(self, limit).await
    }

    async fn get_ai_transactions(&self, max_count: usize) -> Vec<Transaction> {
        Mempool::get_ai_transactions(self, max_count).await
    }

    async fn stats(&self) -> MempoolStats {
        Mempool::stats(self).await
    }

    async fn clear(&self) {
        Mempool::clear(self).await
    }

    async fn clear_expired(&self) {
        Mempool::clear_expired(self).await
    }

    async fn get_pending_nonce(&self, sender: &PublicKey) -> Option<u64> {
        Mempool::pending_nonce_for(self, sender).await
    }

    async fn reconcile_nonces(&self) {
        Mempool::reconcile_nonces(self).await
    }
}

/// Implementation of MempoolAccess for Arc<RwLock<Mempool>> (locked access)
/// This is used by the GUI's embedded node which requires mutable access coordination
#[async_trait::async_trait]
impl MempoolAccess for Arc<RwLock<Mempool>> {
    fn chain_id(&self) -> u64 {
        // We need to block briefly to get the chain_id
        // This is a sync method so we use try_read or block_in_place
        futures::executor::block_on(async { self.read().await.chain_id() })
    }

    async fn add_transaction(&self, tx: Transaction, class: TxClass) -> Result<(), MempoolError> {
        self.read().await.add_transaction(tx, class).await
    }

    async fn remove_transaction(&self, hash: &Hash) -> Option<Transaction> {
        self.read().await.remove_transaction(hash).await
    }

    async fn get_transaction(&self, hash: &Hash) -> Option<Transaction> {
        self.read().await.get_transaction(hash).await
    }

    async fn contains(&self, hash: &Hash) -> bool {
        self.read().await.contains(hash).await
    }

    async fn get_transactions(&self, limit: usize) -> Vec<Transaction> {
        self.read().await.get_transactions(limit).await
    }

    async fn get_ai_transactions(&self, max_count: usize) -> Vec<Transaction> {
        self.read().await.get_ai_transactions(max_count).await
    }

    async fn stats(&self) -> MempoolStats {
        self.read().await.stats().await
    }

    async fn clear(&self) {
        self.read().await.clear().await
    }

    async fn clear_expired(&self) {
        self.read().await.clear_expired().await
    }

    async fn get_pending_nonce(&self, sender: &PublicKey) -> Option<u64> {
        self.read().await.pending_nonce_for(sender).await
    }

    async fn reconcile_nonces(&self) {
        self.read().await.reconcile_nonces().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pba_native_tx(seed: u8, nonce: u64, data_len: usize) -> Transaction {
        let mut h = [seed; 32];
        h[..8].copy_from_slice(&nonce.to_be_bytes());
        Transaction {
            hash: Hash::new(h),
            nonce,
            from: PublicKey::new([seed; 32]),
            to: Some(PublicKey::new([0xEE; 32])),
            value: 0,
            gas_limit: 21_000,
            gas_price: 2_000_000_000,
            data: vec![0xAB; data_len],
            signature: citrate_consensus::types::Signature::new([1; 64]),
            chain_id: Some(40204),
            ..Default::default()
        }
    }

    fn pba_pool() -> Mempool {
        Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        })
    }

    /// PBA-L1a-017: a payload larger than any block could carry must not be
    /// admitted.
    #[tokio::test]
    async fn pba_l1a_017_oversized_payload_is_rejected() {
        let pool = pba_pool();
        let err = pool
            .add_transaction(
                pba_native_tx(0x31, 0, MAX_TX_DATA_BYTES + 1),
                TxClass::Standard,
            )
            .await
            .expect_err("payload over the cap must be rejected");
        assert!(
            matches!(err, MempoolError::InvalidTransaction(_)),
            "{err:?}"
        );
        // The audit's >1 MB case.
        assert!(pool
            .add_transaction(pba_native_tx(0x32, 0, 1_100_000), TxClass::Standard)
            .await
            .is_err());
        // At the cap is fine.
        pool.add_transaction(pba_native_tx(0x33, 0, MAX_TX_DATA_BYTES), TxClass::Standard)
            .await
            .expect("payload at the cap is admitted");
    }

    /// PBA-L1a-017: the byte budget is enforced (total_size was tracked, never
    /// checked). Fill past MAX_POOL_BYTES with max-size payloads.
    #[tokio::test]
    async fn pba_l1a_017_pool_byte_budget_is_enforced() {
        let pool = pba_pool();
        let per_tx = MAX_TX_DATA_BYTES;
        let needed = MAX_POOL_BYTES / per_tx + 8;
        let mut admitted = 0usize;
        // max_nonce_gap (16) bounds each sender to 17 buffered nonces.
        'outer: for sender in 0..((needed / 16) + 2) {
            for nonce in 0..16u64 {
                if admitted >= needed {
                    break 'outer;
                }
                let mut t = pba_native_tx(0x40u8.wrapping_add(sender as u8), nonce, per_tx);
                t.hash = Hash::new({
                    let mut h = [0u8; 32];
                    h[..8].copy_from_slice(&(admitted as u64).to_be_bytes());
                    h[31] = 0x17;
                    h
                });
                if pool.add_transaction(t, TxClass::Standard).await.is_ok() {
                    admitted += 1;
                }
            }
        }
        assert!(
            admitted >= needed,
            "the test must push past the budget ({admitted} < {needed})"
        );
        let stats = pool.stats().await;
        assert!(
            stats.total_size <= MAX_POOL_BYTES,
            "pool holds {} bytes, over the {} budget",
            stats.total_size,
            MAX_POOL_BYTES
        );
    }

    /// A payload each executor parser accepts (selector 0x04/0x05 and others
    /// are plain calls and accept anything).
    fn pba_valid_payload(sel: u8) -> Vec<u8> {
        let mut d = vec![sel, 0, 0, 0];
        d.extend_from_slice(&[0x4D; 32]);
        if sel == 0x01 || sel == 0x03 {
            let meta = b"{}";
            d.extend_from_slice(&(meta.len() as u32).to_be_bytes());
            d.extend_from_slice(meta);
            d.push(0); // access policy (register) / ignored (update)
        }
        d
    }

    /// Admission uses the executor's own parser: a payload it rejects never
    /// enters the pool.
    #[tokio::test]
    async fn ai_payload_admission_matches_executor_parser() {
        let pool = pba_pool();
        let mut n = 0u8;
        let mut try_add = |data: Vec<u8>| {
            n += 1;
            let mut t = pba_native_tx(0x90u8.wrapping_add(n), 0, 0);
            t.data = data;
            t
        };
        let bad: Vec<Vec<u8>> = vec![
            vec![0x02, 0, 0, 0],          // inference: no model id
            vec![0x02, 0, 0, 0, 1, 2, 3], // inference: short model id
            {
                let mut d = vec![0x01, 0, 0, 0];
                d.extend_from_slice(&[0xAB; 32]);
                d.extend_from_slice(&u32::MAX.to_be_bytes()); // metadata past end
                d.resize(64, 0x5A);
                d
            },
            vec![0x03, 0, 0, 0, 9], // update: truncated
        ];
        for data in bad {
            let t = try_add(data.clone());
            assert!(
                citrate_execution::executor::Executor::parse_transaction_type(&t).is_err(),
                "precondition: executor rejects {data:?}"
            );
            let err = pool
                .add_transaction(t, TxClass::Standard)
                .await
                .expect_err("rejected at admission");
            assert!(
                matches!(err, MempoolError::InvalidTransaction(_)),
                "{err:?}"
            );
        }
        for sel in [0x01u8, 0x02, 0x03, 0x04, 0x05] {
            let t = try_add(pba_valid_payload(sel));
            pool.add_transaction(t, TxClass::Standard)
                .await
                .expect("parseable payload admitted");
        }
    }

    /// A banned sender is refused and its pooled transactions are dropped;
    /// the ban expires.
    #[tokio::test]
    async fn sender_ban_refuses_and_expires() {
        let pool = pba_pool();
        let t0 = pba_native_tx(0xA0, 0, 0);
        let sender = t0.from;
        pool.add_transaction(t0.clone(), TxClass::Standard)
            .await
            .expect("admit");
        pool.ban_sender(&sender, std::time::Duration::from_secs(60))
            .await;
        assert!(pool.is_banned(&sender).await);
        assert!(!pool.contains(&t0.hash).await, "pooled txs dropped");
        let t1 = pba_native_tx(0xA0, 1, 0);
        assert!(pool.add_transaction(t1, TxClass::Standard).await.is_err());
        let other = pba_native_tx(0xA1, 0, 0);
        assert!(!pool.is_banned(&other.from).await);
        pool.add_transaction(other, TxClass::Standard)
            .await
            .expect("other senders unaffected");
        pool.ban_sender(&sender, std::time::Duration::from_millis(0))
            .await;
        assert!(!pool.is_banned(&sender).await, "ban expired");
        pool.add_transaction(pba_native_tx(0xA0, 2, 0), TxClass::Standard)
            .await
            .expect("admitted after expiry");
    }

    /// Bans are per sender, persist across later bans, and the ban list is
    /// bounded.
    #[tokio::test]
    async fn sender_ban_list_is_bounded_and_independent() {
        let pool = pba_pool();
        let a = PublicKey::new([0xB1; 32]);
        let b = PublicKey::new([0xB2; 32]);
        let long = std::time::Duration::from_secs(600);
        pool.ban_sender(&a, long).await;
        pool.ban_sender(&b, long).await;
        assert!(
            pool.is_banned(&a).await,
            "an earlier ban survives a later one"
        );
        assert!(pool.is_banned(&b).await);
        // Fill to the cap; the next distinct sender is not recorded.
        for i in 2..MAX_BANNED_SENDERS {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_be_bytes());
            k[31] = 0xC0;
            pool.banned
                .write()
                .await
                .insert(PublicKey::new(k), std::time::Instant::now() + long);
        }
        assert_eq!(pool.banned.read().await.len(), MAX_BANNED_SENDERS);
        let over = PublicKey::new([0xB3; 32]);
        pool.ban_sender(&over, long).await;
        assert!(
            pool.is_banned(&over).await,
            "list full: new sender recorded"
        );
        assert_eq!(pool.banned.read().await.len(), MAX_BANNED_SENDERS);
        assert!(!pool.is_banned(&a).await, "soonest-expiring entry evicted");
        pool.ban_sender(&b, long).await;
        assert!(
            pool.is_banned(&b).await,
            "already-listed sender is refreshed"
        );
        assert_eq!(pool.banned.read().await.len(), MAX_BANNED_SENDERS);
    }

    #[test]
    fn tx_size_accounting() {
        let t = pba_native_tx(0x10, 0, 123);
        assert_eq!(Mempool::tx_size(&t), 200 + 123);
        assert_eq!(Mempool::tx_size(&pba_native_tx(0x10, 0, 0)), 200);
    }

    #[tokio::test]
    async fn best_transactions_respects_count() {
        let pool = pba_pool();
        for seed in [0x21u8, 0x22, 0x23] {
            pool.add_transaction(pba_native_tx(seed, 0, 0), TxClass::Standard)
                .await
                .expect("admit");
        }
        assert_eq!(pool.get_best_transactions(2, usize::MAX).await.len(), 2);
        assert_eq!(pool.get_best_transactions(1, usize::MAX).await.len(), 1);
        assert_eq!(pool.get_best_transactions(10, usize::MAX).await.len(), 3);
    }

    /// The AI slice uses the executor's classifier (selectors 0x01..0x03 on a
    /// call) and is ordered by fee.
    #[tokio::test]
    async fn ai_classifier_parity_in_mempool() {
        let pool = pba_pool();
        let mk = |seed: u8, sel: u8, price: u64| {
            let mut t = pba_native_tx(seed, 0, 0);
            t.data = pba_valid_payload(sel);
            t.gas_price = price;
            t
        };
        for (seed, sel, price) in [
            (0x71u8, 0x02u8, 2_000_000_000u64),
            (0x72, 0x04, 9_000_000_000),
            (0x73, 0x05, 9_000_000_000),
            (0x74, 0x01, 5_000_000_000),
            (0x75, 0x03, 3_000_000_000),
        ] {
            pool.add_transaction(mk(seed, sel, price), TxClass::Standard)
                .await
                .expect("admit");
        }
        let ai = pool.get_ai_transactions(10).await;
        let sels: Vec<u8> = ai.iter().map(|t| t.data[0]).collect();
        assert_eq!(
            sels,
            vec![0x01, 0x03, 0x02],
            "executor AI ops only, highest fee first"
        );
        assert_eq!(pool.get_ai_transactions(2).await.len(), 2);
        // The trait views used by the node forward to the same selection.
        let shared = Arc::new(pool);
        let via_arc = MempoolAccess::get_ai_transactions(&shared, 10).await;
        assert_eq!(via_arc.iter().map(|t| t.data[0]).collect::<Vec<_>>(), sels);
        let pool2 = Arc::try_unwrap(shared).map_err(|_| ()).expect("sole owner");
        let locked = Arc::new(RwLock::new(pool2));
        let via_lock = MempoolAccess::get_ai_transactions(&locked, 10).await;
        assert_eq!(via_lock.iter().map(|t| t.data[0]).collect::<Vec<_>>(), sels);
    }

    /// PBA-L1a-021: the pending-nonce lookup has no successor for u64::MAX
    /// (was `m + 1`, a panic under overflow-checks) — injected directly so the
    /// check holds even once admission rejects u64::MAX nonces.
    #[tokio::test]
    async fn pba_l1a_021_pending_nonce_matching_is_overflow_safe() {
        let pool = pba_pool();
        let k = PublicKey::new([0x5A; 32]);
        pool.sender_nonces
            .write()
            .await
            .insert(k, [3u64, u64::MAX].into_iter().collect());
        assert_eq!(pool.pending_nonce_matching(|pk| *pk == k).await, None);
        pool.sender_nonces
            .write()
            .await
            .insert(k, [3u64, 7].into_iter().collect());
        assert_eq!(pool.pending_nonce_matching(|pk| *pk == k).await, Some(8));
        assert_eq!(pool.pending_nonce_matching(|_| false).await, None);
    }

    /// PBA-L1a-017: clear_expired must not underflow and must drop stale txs.
    #[tokio::test]
    async fn pba_l1a_017_clear_expired_drops_stale_entries() {
        let pool = Mempool::new(MempoolConfig {
            require_valid_signature: false,
            tx_expiry_secs: u64::MAX, // would underflow `now - expiry`
            ..Default::default()
        });
        pool.add_transaction(pba_native_tx(0x61, 0, 0), TxClass::Standard)
            .await
            .expect("admit");
        pool.clear_expired().await; // must not panic
        assert_eq!(pool.stats().await.total_transactions, 1);

        let pool = Mempool::new(MempoolConfig {
            require_valid_signature: false,
            tx_expiry_secs: 0,
            ..Default::default()
        });
        let t = pba_native_tx(0x62, 0, 0);
        let h = t.hash;
        pool.add_transaction(t, TxClass::Standard)
            .await
            .expect("admit");
        if let Some(m) = pool.transactions.write().await.get_mut(&h) {
            m.added_at = m.added_at.saturating_sub(10);
        }
        pool.clear_expired().await;
        assert_eq!(pool.stats().await.total_transactions, 0, "stale tx swept");
    }
    use citrate_consensus::Signature;

    fn create_test_tx(nonce: u64, gas_price: u64, from: [u8; 32]) -> Transaction {
        // Create unique hash based on all tx parameters
        let mut hash_data = [0u8; 32];
        hash_data[0..8].copy_from_slice(&nonce.to_le_bytes());
        hash_data[8..16].copy_from_slice(&gas_price.to_le_bytes());
        hash_data[16..32].copy_from_slice(&from[0..16]);

        Transaction {
            hash: Hash::new(hash_data),
            nonce,
            from: PublicKey::new(from),
            to: Some(PublicKey::new([2; 32])),
            value: 1000,
            gas_limit: 21000,
            gas_price,
            data: vec![],
            signature: Signature::new([1; 64]), // Non-zero signature for tests
            tx_type: None,
            chain_id: Some(40204), // M-01: chain domain binding — matches canonical default
            ..Default::default()
        }
    }

    // ── PBA-R2 mutation-survivor kills (validate_transaction /
    // get_best_transactions / is_next_nonce / MempoolAccess). ──

    fn signed_native(seed: u8, nonce: u64, chain_id: Option<u64>, gas_limit: u64) -> Transaction {
        let sk = citrate_consensus::crypto::Ed25519SigningKey::from_bytes(&[seed; 32]);
        let mut tx = Transaction {
            nonce,
            to: Some(PublicKey::new([9; 32])),
            value: 1,
            gas_limit,
            gas_price: 1_000_000_000,
            chain_id,
            ..Default::default()
        };
        citrate_consensus::crypto::sign_transaction(&mut tx, &sk).unwrap();
        tx
    }

    #[tokio::test]
    async fn pba_r2_chain_id_must_match() {
        let mp = Mempool::new(MempoolConfig::default());
        assert!(mp
            .add_transaction(signed_native(1, 0, Some(1), 21_000), TxClass::Standard)
            .await
            .is_err());
        assert!(mp
            .add_transaction(signed_native(1, 0, None, 21_000), TxClass::Standard)
            .await
            .is_err());
        mp.add_transaction(signed_native(1, 0, Some(40204), 21_000), TxClass::Standard)
            .await
            .expect("matching chain id admitted");
    }

    #[tokio::test]
    async fn pba_r2_gas_limit_ceiling_is_inclusive() {
        let mp = Mempool::new(MempoolConfig::default());
        mp.add_transaction(
            signed_native(2, 0, Some(40204), MAX_GAS_PER_BLOCK),
            TxClass::Standard,
        )
        .await
        .expect("exactly the per-block ceiling is admissible");
        assert!(mp
            .add_transaction(
                signed_native(3, 0, Some(40204), MAX_GAS_PER_BLOCK + 1),
                TxClass::Standard
            )
            .await
            .is_err());
    }

    /// With signature checking disabled by config, the empty-sender gate is
    /// the only thing standing between an all-zero `from` and admission.
    #[tokio::test]
    async fn pba_r2_empty_sender_rejected_even_without_signature_checks() {
        let mp = Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        });
        let mut tx = create_test_tx(0, 1_000_000_000, [0; 32]);
        tx.from = PublicKey::new([0; 32]);
        assert!(mp.add_transaction(tx, TxClass::Standard).await.is_err());
    }

    #[tokio::test]
    async fn pba_r2_selection_respects_count_and_size_limits() {
        let mp = Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        });
        let txs: Vec<Transaction> = (0..3u8)
            .map(|i| create_test_tx(0, 1_000_000_000 + i as u64, [i + 1; 32]))
            .collect();
        for t in &txs {
            mp.add_transaction(t.clone(), TxClass::Standard)
                .await
                .unwrap();
        }
        assert_eq!(
            mp.get_best_transactions(1, usize::MAX).await.len(),
            1,
            "count cap"
        );
        assert_eq!(
            mp.get_best_transactions(2, usize::MAX).await.len(),
            2,
            "count cap"
        );
        let one = mp.calculate_tx_size(&txs[0]);
        assert_eq!(
            mp.get_best_transactions(10, 2 * one).await.len(),
            2,
            "size cap: exactly two fit"
        );
        assert_eq!(mp.get_best_transactions(10, 2 * one - 1).await.len(), 1);
    }

    #[tokio::test]
    async fn pba_r2_is_next_nonce_semantics() {
        let mp = Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        });
        let a = create_test_tx(5, 1_000_000_000, [7; 32]);
        let b = create_test_tx(6, 1_000_000_000, [7; 32]);
        mp.add_transaction(a.clone(), TxClass::Standard)
            .await
            .unwrap();
        mp.add_transaction(b.clone(), TxClass::Standard)
            .await
            .unwrap();
        let none: HashSet<Hash> = HashSet::new();
        assert!(
            mp.is_next_nonce(&a, &none).await,
            "the minimum pending nonce is next"
        );
        assert!(
            mp.is_next_nonce(&b, &none).await,
            "contiguous run from the minimum"
        );
        let below = create_test_tx(4, 1_000_000_000, [7; 32]);
        assert!(
            !mp.is_next_nonce(&below, &none).await,
            "below the minimum is not next"
        );
        let included: HashSet<Hash> = [a.hash].into_iter().collect();
        assert!(mp.is_next_nonce(&b, &included).await);
        assert!(!mp.is_next_nonce(&a, &included).await);
        let fresh = create_test_tx(0, 1_000_000_000, [8; 32]);
        assert!(
            mp.is_next_nonce(&fresh, &none).await,
            "first tx of an unknown sender"
        );
    }

    /// The trait impls the node uses must propagate admission errors.
    #[tokio::test]
    async fn pba_r2_mempool_access_impls_propagate_rejections() {
        let bad = signed_native(4, u64::MAX, Some(40204), 21_000);
        let arc = Arc::new(Mempool::new(MempoolConfig::default()));
        assert!(
            MempoolAccess::add_transaction(&arc, bad.clone(), TxClass::Standard)
                .await
                .is_err()
        );
        let locked = Arc::new(RwLock::new(Mempool::new(MempoolConfig::default())));
        assert!(
            MempoolAccess::add_transaction(&locked, bad, TxClass::Standard)
                .await
                .is_err()
        );
    }

    /// The A015 gate alone (signature checks disabled by config) must reject
    /// an EVM-shaped sender that does not recover from the tx contents.
    #[tokio::test]
    async fn pba_r2_a015_gate_holds_without_signature_checks() {
        let mp = Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        });
        let mut from = [0u8; 32];
        from[..20].copy_from_slice(&[0xAA; 20]);
        let mut tx = create_test_tx(0, 1_000_000_000, from);
        tx.ecdsa_verified = false;
        assert!(mp.add_transaction(tx, TxClass::Standard).await.is_err());
        // A mixed-byte address (some zero bytes) is still EVM-shaped.
        let mut from2 = [0u8; 32];
        from2[..20].copy_from_slice(&[
            0xAA, 0, 0xBB, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ]);
        let mut tx2 = create_test_tx(0, 1_000_000_000, from2);
        tx2.ecdsa_verified = false;
        assert!(mp.add_transaction(tx2, TxClass::Standard).await.is_err());
    }

    /// PBA-L1a-001 defence in depth: even if a `nonce = u64::MAX` tx reached
    /// the pool by some path that skipped admission (an older binary's state,
    /// a future ingress), selection must skip it, not panic. Inserted directly
    /// into the internal maps to bypass the admission check.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pba_l1a_001_selection_skips_unfollowable_nonce_without_panicking() {
        let mp = std::sync::Arc::new(Mempool::new(MempoolConfig::default()));
        let poison = create_test_tx(u64::MAX, 5_000_000_000, [7; 32]);
        let honest = create_test_tx(0, 1_000_000_000, [8; 32]);
        for tx in [poison.clone(), honest.clone()] {
            let prio = TxPriority::new_with_ai(tx.gas_price, TxClass::Standard, 0, 0);
            mp.transactions.write().await.insert(
                tx.hash,
                MempoolTx {
                    tx: tx.clone(),
                    class: TxClass::Standard,
                    priority: prio,
                    added_at: 0,
                    size: 100,
                },
            );
            mp.priority_queue.write().await.push(tx.hash, prio);
            mp.by_sender
                .write()
                .await
                .entry(tx.from)
                .or_default()
                .push_back(tx.hash);
            mp.sender_nonces
                .write()
                .await
                .entry(tx.from)
                .or_default()
                .insert(tx.nonce);
        }
        let mp2 = mp.clone();
        let sel = tokio::spawn(async move { mp2.get_best_transactions(100, 1 << 20).await })
            .await
            .expect("PBA-L1a-001: selection panicked on a u64::MAX nonce");
        assert_eq!(
            sel.len(),
            1,
            "the unfollowable tx is skipped, the honest one selected"
        );
        assert_eq!(sel[0].hash, honest.hash);
        assert_eq!(mp.pending_nonce_for(&poison.from).await, None);
        // The successor of an included u64::MAX nonce does not exist.
        let included: HashSet<Hash> = [poison.hash].into_iter().collect();
        assert!(!mp.is_next_nonce(&poison, &included).await);
    }

    /// SEQ-H2: scoring a tx with `gas_price = u64::MAX` must not panic. Pre-fix
    /// `gas_price * priority_multiplier()` overflowed and, with release
    /// `overflow-checks = true`, panicked the producer while ordering the
    /// mempool. GREEN: saturates to `u64::MAX`.
    #[test]
    fn seq_h2_tx_priority_score_saturates_on_max_gas_price() {
        let p = TxPriority {
            gas_price: u64::MAX,
            class: TxClass::Standard,
            timestamp: 0,
            ai_priority: 0,
        };
        assert_eq!(p.score(), u64::MAX);
    }

    /// SEQ-H2: a transaction whose `gas_limit` exceeds the per-block ceiling can
    /// never fit in a block, so it must be rejected at mempool admission rather
    /// than parked at the head of the fee-ordered queue where it starves block
    /// production. RED before the admission check (the tx was accepted); GREEN
    /// after (rejected).
    #[tokio::test]
    async fn seq_h2_mempool_rejects_over_block_gas_limit() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let mut tx = create_test_tx(0, 2_000_000_000, [9u8; 32]);
        tx.gas_limit = 30_000_001; // > MAX_GAS_PER_BLOCK (30M)

        let res = mempool.add_transaction(tx, TxClass::Standard).await;
        assert!(
            res.is_err(),
            "a tx with gas_limit over the per-block ceiling must be rejected at admission"
        );
    }

    /// SECREM-01 CONS-4: the bounded evicted-set structure must cap
    /// its size and age out the OLDEST entries first (FIFO), while
    /// still answering `contains` correctly for retained entries.
    #[test]
    fn test_bounded_hashset_caps_size_and_ages_out_oldest() {
        const CAP: usize = 64;
        const EXTRA: usize = 16;
        let mut set = BoundedHashSet::new(CAP);

        let hash_for = |i: usize| {
            let mut data = [0u8; 32];
            data[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            Hash::new(data)
        };

        // Insert CAP + EXTRA distinct entries.
        for i in 0..(CAP + EXTRA) {
            set.insert(hash_for(i));
            assert!(
                set.len() <= CAP,
                "bounded set exceeded cap after insert {}: len={}",
                i,
                set.len()
            );
        }

        assert_eq!(set.len(), CAP, "set must sit exactly at cap");

        // The EXTRA oldest entries must have aged out...
        for i in 0..EXTRA {
            assert!(
                !set.contains(&hash_for(i)),
                "oldest entry {} should have aged out",
                i
            );
        }
        // ...and the CAP newest entries must all be retained.
        for i in EXTRA..(CAP + EXTRA) {
            assert!(
                set.contains(&hash_for(i)),
                "newest entry {} must be retained",
                i
            );
        }

        // Duplicate insert must not grow the set or perturb ordering.
        set.insert(hash_for(CAP + EXTRA - 1));
        assert_eq!(set.len(), CAP);
        assert!(
            set.contains(&hash_for(EXTRA)),
            "duplicate insert must not evict"
        );

        // clear() empties both the set and the order queue.
        set.clear();
        assert_eq!(set.len(), 0);
        set.insert(hash_for(0));
        assert!(set.contains(&hash_for(0)));
    }

    /// SECREM-01 CONS-4: semantic contract preserved — a tx removed
    /// from the mempool is still rejected as a duplicate when
    /// re-submitted (the whole point of the evicted set).
    #[tokio::test]
    async fn test_evicted_tx_still_rejected_after_bounding() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let tx = create_test_tx(0, 2_000_000_000, [7; 32]);
        mempool
            .add_transaction(tx.clone(), TxClass::Standard)
            .await
            .expect("first add should succeed");

        mempool.remove_transaction(&tx.hash).await;
        assert!(!mempool.contains(&tx.hash).await);

        let err = mempool
            .add_transaction(tx.clone(), TxClass::Standard)
            .await
            .expect_err("re-adding a removed tx must be rejected");
        assert!(matches!(err, MempoolError::DuplicateTransaction(h) if h == tx.hash));
    }

    #[tokio::test]
    async fn test_add_transaction() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let tx = create_test_tx(0, 2_000_000_000, [1; 32]);
        mempool
            .add_transaction(tx.clone(), TxClass::Standard)
            .await
            .unwrap();

        assert!(mempool.contains(&tx.hash).await);
        assert_eq!(mempool.stats().await.total_transactions, 1);
    }

    #[tokio::test]
    async fn test_duplicate_transaction() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let tx = create_test_tx(0, 2_000_000_000, [1; 32]);
        mempool
            .add_transaction(tx.clone(), TxClass::Standard)
            .await
            .unwrap();

        // Re-adding the exact same tx (same hash) is rejected as
        // DuplicateTransaction. Pre-backlog-#123 this case was
        // masked by a spurious NonceTooLow rejection (the buggy
        // expected-nonce counter had advanced past 0), so the test
        // asserted the wrong variant; the set-based nonce model
        // surfaces the real reason.
        let result = mempool.add_transaction(tx.clone(), TxClass::Standard).await;
        assert!(
            matches!(result, Err(MempoolError::DuplicateTransaction(_))),
            "exact hash re-add should be DuplicateTransaction, got {result:?}"
        );
    }

    /// Backlog #123: A second tx with the **same nonce but a different
    /// hash** from the same sender must be rejected as
    /// `DuplicateNonce`, not `DuplicateTransaction`. This is the
    /// nonce-replacement-not-supported case.
    #[tokio::test]
    async fn test_duplicate_nonce_different_hash() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);
        let sender = [0xab; 32];

        let first = create_test_tx(7, 2_000_000_000, sender);
        mempool
            .add_transaction(first, TxClass::Standard)
            .await
            .unwrap();

        // Second tx: same sender, same nonce, different gas price
        // (therefore different hash).
        let second = create_test_tx(7, 3_000_000_000, sender);
        let result = mempool.add_transaction(second, TxClass::Standard).await;
        assert!(
            matches!(result, Err(MempoolError::DuplicateNonce { nonce: 7 })),
            "same-nonce different-hash must be DuplicateNonce, got {result:?}"
        );
    }

    /// Backlog #123 primary regression: concurrent out-of-order
    /// submissions from the same sender must all be accepted, and the
    /// block-builder must serialize them into consecutive nonce order.
    ///
    /// Pre-fix, this test would fail because the mempool's forward-
    /// jump-accept at line 313 would promote the highest-arrived nonce
    /// as the expected counter, rejecting every lower-nonce tx that
    /// followed as `NonceTooLow`.
    #[tokio::test]
    async fn test_concurrent_out_of_order_nonces_all_accepted() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);
        let sender = [0xcc; 32];
        let sender_pk = PublicKey::new(sender);

        // Submit nonces in the pathological order 5, 3, 7, 0, 4, 2, 6, 1.
        // Pre-fix: 5 is accepted, expected becomes 6, then 3 is
        // NonceTooLow and everything after is rejected.
        // Post-fix: all eight land in the mempool.
        let nonces = [5u64, 3, 7, 0, 4, 2, 6, 1];
        for n in nonces {
            let tx = create_test_tx(n, 2_000_000_000, sender);
            mempool
                .add_transaction(tx, TxClass::Standard)
                .await
                .unwrap_or_else(|e| panic!("nonce {n} rejected: {e}"));
        }

        // The sender set should contain all eight nonces.
        assert_eq!(mempool.stats().await.total_transactions, 8);
        assert_eq!(mempool.pending_nonce_for(&sender_pk).await, Some(8));

        // Block-builder should serialize them into 0..=7 order.
        let best = mempool.get_best_transactions(16, 1_000_000).await;
        assert_eq!(best.len(), 8);
        for (i, tx) in best.iter().enumerate() {
            assert_eq!(
                tx.nonce, i as u64,
                "block position {i} has nonce {}",
                tx.nonce
            );
        }
    }

    /// Backlog #123 phantom-eviction regression: after a tx is added
    /// and then evicted (the case that catastrophically poisoned the
    /// mempool during the 2026-04-08 live-chain bench attempt), the
    /// sender's pending nonce should reflect ONLY currently-buffered
    /// txs — there must be no phantom high-water-mark left behind.
    ///
    /// Pre-fix: the `self.nonces` counter was written with
    /// `tx.nonce + 1` on add and not decremented when the tx was
    /// evicted, so a ghost value from the evicted high-nonce tx
    /// locked out every legitimate later submission.
    #[tokio::test]
    async fn test_phantom_eviction_does_not_poison_sender() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);
        let sender = [0xdd; 32];
        let sender_pk = PublicKey::new(sender);

        // Submit a wildly forward-jumped tx at nonce 99_000 and
        // verify it lands.
        let future_tx = create_test_tx(99_000, 2_000_000_000, sender);
        let future_hash = future_tx.hash;
        mempool
            .add_transaction(future_tx, TxClass::Standard)
            .await
            .unwrap();
        assert_eq!(mempool.pending_nonce_for(&sender_pk).await, Some(99_001));

        // Evict the forward-jumped tx — simulate capacity pressure,
        // expiration, or any other non-inclusion drop.
        mempool.remove_transaction(&future_hash).await;
        assert_eq!(
            mempool.pending_nonce_for(&sender_pk).await,
            None,
            "phantom nonce must not persist after eviction"
        );

        // The same sender must now be able to submit nonces 0..=5
        // freely (the real use case that was broken on the live
        // chain: the bench burners were poisoned to reject every
        // submission after a set of high-nonce forward-jumps were
        // evicted).
        for n in 0u64..=5 {
            let tx = create_test_tx(n, 3_000_000_000, sender);
            mempool
                .add_transaction(tx, TxClass::Standard)
                .await
                .unwrap_or_else(|e| panic!("nonce {n} rejected after phantom eviction: {e}"));
        }
        assert_eq!(mempool.stats().await.total_transactions, 6);
        assert_eq!(mempool.pending_nonce_for(&sender_pk).await, Some(6));
    }

    #[tokio::test]
    async fn test_gas_price_validation() {
        let config = MempoolConfig {
            min_gas_price: 1_000_000_000,
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let tx = create_test_tx(0, 500_000_000, [1; 32]); // Too low gas price
        let result = mempool.add_transaction(tx, TxClass::Standard).await;

        assert!(matches!(result, Err(MempoolError::GasPriceTooLow { .. })));
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        // Add transactions with different priorities
        let tx1 = create_test_tx(0, 1_000_000_000, [1; 32]);
        let tx2 = create_test_tx(0, 3_000_000_000, [2; 32]);
        let tx3 = create_test_tx(0, 2_000_000_000, [3; 32]);

        mempool
            .add_transaction(tx1.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx2.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx3.clone(), TxClass::Standard)
            .await
            .unwrap();

        let best_txs = mempool.get_best_transactions(10, 1_000_000).await;

        // Should be ordered by gas price (highest first)
        assert_eq!(best_txs[0].hash, tx2.hash);
        assert_eq!(best_txs[1].hash, tx3.hash);
        assert_eq!(best_txs[2].hash, tx1.hash);
    }

    #[tokio::test]
    async fn test_tx_class_priority() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        // Same gas price but different classes
        let tx1 = create_test_tx(0, 1_000_000_000, [1; 32]);
        let tx2 = create_test_tx(0, 1_000_000_000, [2; 32]);

        mempool
            .add_transaction(tx1.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx2.clone(), TxClass::ModelUpdate)
            .await
            .unwrap();

        let best_txs = mempool.get_best_transactions(10, 1_000_000).await;

        // ModelUpdate should have higher priority
        assert_eq!(best_txs[0].hash, tx2.hash);
        assert_eq!(best_txs[1].hash, tx1.hash);
    }

    #[tokio::test]
    async fn test_nonce_ordering() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let sender = [1; 32];
        let tx1 = create_test_tx(0, 2_000_000_000, sender);
        let tx2 = create_test_tx(1, 2_000_000_000, sender);
        let tx3 = create_test_tx(2, 2_000_000_000, sender);

        // Add in correct nonce order (mempool enforces sequential nonces)
        mempool
            .add_transaction(tx1.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx2.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx3.clone(), TxClass::Standard)
            .await
            .unwrap();

        let best_txs = mempool.get_best_transactions(10, 1_000_000).await;

        // Should respect nonce ordering
        assert_eq!(best_txs.len(), 3);
        assert_eq!(best_txs[0].nonce, 0);
        assert_eq!(best_txs[1].nonce, 1);
        assert_eq!(best_txs[2].nonce, 2);
    }

    #[tokio::test]
    async fn test_sender_limit_exceeded() {
        let config = MempoolConfig {
            max_per_sender: 2,
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let sender = [9; 32];
        let tx0 = create_test_tx(0, 2_000_000_000, sender);
        let tx1 = create_test_tx(1, 2_000_000_000, sender);
        let tx2 = create_test_tx(2, 2_000_000_000, sender);

        mempool
            .add_transaction(tx0, TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx1, TxClass::Standard)
            .await
            .unwrap();
        let res = mempool.add_transaction(tx2, TxClass::Standard).await;
        assert!(matches!(res, Err(MempoolError::SenderLimitExceeded)));
    }

    /// WP-K.1 regression: A forged bincode payload with ecdsa_verified=true and
    /// an EVM-shaped address (20-byte embedded) must be rejected by the mempool.
    /// The tx decoder now forces ecdsa_verified=false on bincode fallback, and
    /// the mempool checks the flag for EVM-shaped senders.
    ///
    /// CHAIN-B-A015: no longer `#[cfg(not(feature = "devnet"))]`. The
    /// feature/config-independent recovery gate rejects this forgery in a DEFAULT
    /// (devnet) build too — the whole point of the finding is that the gate must not
    /// be compiled out. `require_valid_signature=false` is set here precisely to prove
    /// the gate does not depend on that switch.
    #[tokio::test]
    async fn test_k1_forged_ecdsa_verified_rejected() {
        let config = MempoolConfig {
            require_valid_signature: false, // Disable crypto verification for this test
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        // Create an EVM-shaped address: first 20 bytes non-zero, last 12 bytes zero
        let mut evm_sender = [0u8; 32];
        evm_sender[..20].copy_from_slice(&[0xAA; 20]);
        // evm_sender[20..32] are already zero — this is the EVM pattern

        // Forged transaction: attacker sets ecdsa_verified=true in bincode payload
        let mut forged_tx = Transaction {
            hash: Hash::new([0x42; 32]),
            nonce: 0,
            from: PublicKey::new(evm_sender),
            to: Some(PublicKey::new([2; 32])),
            value: 1000,
            gas_limit: 21000,
            gas_price: 2_000_000_000,
            data: vec![],
            signature: Signature::new([1; 64]),
            chain_id: Some(40204), // Matches canonical MempoolConfig::default()
            ecdsa_verified: true,  // Attacker-forged value
            ..Default::default()
        };

        // Simulate what the tx decoder now does: force ecdsa_verified=false
        forged_tx.ecdsa_verified = false;

        let result = mempool.add_transaction(forged_tx, TxClass::Standard).await;
        assert!(
            matches!(result, Err(MempoolError::InvalidSignature)),
            "EVM-shaped tx with ecdsa_verified=false must be rejected, got: {:?}",
            result
        );
    }

    /// WP-K.1: Verify that native (non-EVM) senders are NOT affected by the ECDSA gate.
    /// Full 32-byte pubkeys don't trigger the EVM address check.
    ///
    /// CHAIN-B-A015: ungated so it runs in the default (devnet) build — proves the new
    /// feature-independent gate does not reject honest non-EVM traffic.
    #[tokio::test]
    async fn test_k1_native_sender_not_affected() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        // Native sender: all 32 bytes non-zero — not EVM-shaped
        let tx = create_test_tx(0, 2_000_000_000, [1; 32]);
        let result = mempool.add_transaction(tx, TxClass::Standard).await;
        assert!(result.is_ok(), "Native sender should pass ECDSA gate");
    }

    /// WP-E1 tripwire (UNCONDITIONAL — must hold on every build profile, including the
    /// shipped default). An EVM-shaped transaction whose `ecdsa_verified` flag is false
    /// must be rejected at mempool admission. This is RED whenever `devnet` is a default
    /// cargo feature (the production ECDSA gate at validate_transaction is compiled out and
    /// the forged tx is accepted); it is GREEN once `[features] default = []`. It also guards
    /// against `devnet` ever being restored to the default set. See audit D010 / RM-Q WP-E1.
    #[tokio::test]
    async fn test_wp_e1_evm_forged_sig_rejected_on_default_build() {
        let config = MempoolConfig {
            require_valid_signature: false, // isolate the ecdsa_verified gate, not crypto recovery
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let mut evm_sender = [0u8; 32];
        evm_sender[..20].copy_from_slice(&[0xAA; 20]); // 20-byte EVM shape, last 12 zero

        let forged = Transaction {
            hash: Hash::new([0x42; 32]),
            nonce: 0,
            from: PublicKey::new(evm_sender),
            to: Some(PublicKey::new([2; 32])),
            value: 1000,
            gas_limit: 21000,
            gas_price: 2_000_000_000,
            data: vec![],
            signature: Signature::new([1; 64]),
            chain_id: Some(40204),
            ecdsa_verified: false,
            ..Default::default()
        };

        let result = mempool.add_transaction(forged, TxClass::Standard).await;
        assert!(
            matches!(result, Err(MempoolError::InvalidSignature)),
            "WP-E1: an EVM-shaped tx with ecdsa_verified=false must be rejected on the DEFAULT              build; got {:?}. If it was accepted, `devnet` is compiled into the shipped binary              and the production signature gate is absent.",
            result
        );
    }

    #[tokio::test]
    async fn test_mixed_class_priority_with_gas_cap() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        // Create four txs from distinct senders, same gas price
        let tx_sys = {
            let mut t = create_test_tx(0, 1_000_000_000, [1; 32]);
            t.hash = Hash::new([0x10; 32]);
            t
        };
        let tx_mu = {
            let mut t = create_test_tx(0, 1_000_000_000, [2; 32]);
            t.hash = Hash::new([0x11; 32]);
            t
        };
        let tx_comp = {
            let mut t = create_test_tx(0, 1_000_000_000, [3; 32]);
            t.hash = Hash::new([0x12; 32]);
            t
        };
        let tx_std = {
            let mut t = create_test_tx(0, 1_000_000_000, [4; 32]);
            t.hash = Hash::new([0x13; 32]);
            t
        };

        mempool
            .add_transaction(tx_sys.clone(), TxClass::System)
            .await
            .unwrap();
        mempool
            .add_transaction(tx_mu.clone(), TxClass::ModelUpdate)
            .await
            .unwrap();
        mempool
            .add_transaction(tx_comp.clone(), TxClass::Compute)
            .await
            .unwrap();
        mempool
            .add_transaction(tx_std.clone(), TxClass::Standard)
            .await
            .unwrap();

        let best = mempool.get_best_transactions(10, 1_000_000).await;
        // Expect order: System > ModelUpdate > Compute > Standard
        assert_eq!(best[0].hash, tx_sys.hash);
        assert_eq!(best[1].hash, tx_mu.hash);
        assert_eq!(best[2].hash, tx_comp.hash);
        assert_eq!(best[3].hash, tx_std.hash);
    }

    /// Sprint EL-1 regression (Issue #20), refreshed for backlog #123:
    /// After removing a transaction, the sender's pending nonce should
    /// reflect the reduced set so the same nonce can be re-submitted.
    ///
    /// The original Sprint EL-1 version reached into `mempool.nonces`
    /// directly to assert values. With the set-based nonce model that
    /// field no longer exists; this test uses the public
    /// `pending_nonce_for` accessor instead.
    #[tokio::test]
    async fn test_el2_nonce_rollback_on_remove() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);
        let sender = [5u8; 32];
        let sender_pk = PublicKey::new(sender);

        // Add tx with nonce 0
        let tx0 = create_test_tx(0, 2_000_000_000, sender);
        let tx0_hash = tx0.hash;
        mempool
            .add_transaction(tx0, TxClass::Standard)
            .await
            .unwrap();

        // Pending nonce should now be 1 (max of {0} plus 1)
        assert_eq!(
            mempool.pending_nonce_for(&sender_pk).await,
            Some(1),
            "pending_nonce should be 1 after adding nonce-0 tx"
        );

        // Remove the transaction — the sender's set should now be empty
        // and the sender entry should be pruned.
        mempool.remove_transaction(&tx0_hash).await;
        assert_eq!(
            mempool.pending_nonce_for(&sender_pk).await,
            None,
            "pending_nonce should be None after removing the only tx"
        );

        // Re-submit with nonce 0 should succeed (use different gas price for unique hash)
        let tx0_retry = create_test_tx(0, 3_000_000_000, sender);
        let result = mempool.add_transaction(tx0_retry, TxClass::Standard).await;
        assert!(
            result.is_ok(),
            "Re-submitting nonce 0 after removal should succeed: {:?}",
            result.err()
        );
    }

    /// Sprint EL-1 regression (Issue #20), refreshed for backlog #123:
    /// reconcile_nonces() should leave a correct view of the per-sender
    /// nonce sets when called after mutation. With the set-based model
    /// this is primarily a safety net — remove_transaction keeps the
    /// sets in sync directly.
    #[tokio::test]
    async fn test_el2_reconcile_nonces() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);
        let sender = [6u8; 32];
        let sender_pk = PublicKey::new(sender);

        // Add txs with nonces 0, 1, 2
        let tx0 = create_test_tx(0, 2_000_000_000, sender);
        let tx1 = create_test_tx(1, 2_000_000_000, sender);
        let tx2 = create_test_tx(2, 2_000_000_000, sender);
        let tx1_hash = tx1.hash;

        mempool
            .add_transaction(tx0, TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx1, TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx2, TxClass::Standard)
            .await
            .unwrap();

        // Pending nonce should be 3 (max of {0,1,2} + 1).
        assert_eq!(mempool.pending_nonce_for(&sender_pk).await, Some(3));

        // Remove tx with nonce 1 (middle tx). The set is now {0, 2}.
        // pending_nonce should still be 3 (max + 1), NOT 1 — the gap
        // at nonce 1 is representable and doesn't rewind the pending
        // view. The sender can legitimately re-submit nonce 1 to fill
        // the gap.
        mempool.remove_transaction(&tx1_hash).await;
        assert_eq!(mempool.pending_nonce_for(&sender_pk).await, Some(3));

        // reconcile is a no-op in steady state — running it should
        // not change the observable view.
        mempool.reconcile_nonces().await;
        assert_eq!(mempool.pending_nonce_for(&sender_pk).await, Some(3));

        // Re-submit the gap: nonce 1 at a different gas price (fresh hash).
        // This must succeed — the old model rejected it as NonceTooLow
        // because expected was cached at 3; the new model sees a free
        // slot in the set and accepts.
        let tx1_retry = create_test_tx(1, 3_000_000_000, sender);
        let result = mempool.add_transaction(tx1_retry, TxClass::Standard).await;
        assert!(
            result.is_ok(),
            "Refilling a nonce gap must succeed under the set-based model: {:?}",
            result.err()
        );
    }

    /// Sprint EL-1 regression (Issue #20), refreshed for backlog #123:
    /// When all transactions for a sender are removed, the sender
    /// entry should be pruned from the nonce map. This used to
    /// require a separate reconcile call; now it happens eagerly in
    /// remove_transaction.
    #[tokio::test]
    async fn test_el2_reconcile_removes_stale_sender() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);
        let sender = [7u8; 32];
        let sender_pk = PublicKey::new(sender);

        // Add and remove a transaction
        let tx0 = create_test_tx(0, 2_000_000_000, sender);
        let tx0_hash = tx0.hash;
        mempool
            .add_transaction(tx0, TxClass::Standard)
            .await
            .unwrap();
        mempool.remove_transaction(&tx0_hash).await;

        // The sender entry should be pruned eagerly by remove_transaction.
        assert_eq!(
            mempool.pending_nonce_for(&sender_pk).await,
            None,
            "sender entry should be pruned after last tx removed"
        );

        // reconcile should remain a no-op.
        mempool.reconcile_nonces().await;
        assert_eq!(mempool.pending_nonce_for(&sender_pk).await, None);

        // Re-submit with nonce 0 should succeed.
        let tx0_new = create_test_tx(0, 3_000_000_000, sender);
        let result = mempool.add_transaction(tx0_new, TxClass::Standard).await;
        assert!(
            result.is_ok(),
            "Fresh submit after sender cleanup should succeed: {:?}",
            result.err()
        );
    }

    /// Fill mempool to max_size, then add one more tx with higher gas price.
    /// The lowest-priority tx should be evicted to make room.
    #[tokio::test]
    async fn test_mempool_capacity_eviction() {
        let config = MempoolConfig {
            max_size: 3,
            max_per_sender: 100,
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        // Fill mempool with 3 txs from distinct senders at varying gas prices
        let tx_low = create_test_tx(0, 1_000_000_000, [10; 32]);
        let tx_mid = create_test_tx(0, 2_000_000_000, [11; 32]);
        let tx_high = create_test_tx(0, 3_000_000_000, [12; 32]);

        mempool
            .add_transaction(tx_low.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx_mid.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx_high.clone(), TxClass::Standard)
            .await
            .unwrap();
        assert_eq!(mempool.stats().await.total_transactions, 3);

        // Add a 4th tx with higher gas price than the lowest — should evict tx_low
        let tx_new = create_test_tx(0, 5_000_000_000, [13; 32]);
        mempool
            .add_transaction(tx_new.clone(), TxClass::Standard)
            .await
            .unwrap();

        // Still 3 txs (one evicted)
        assert_eq!(mempool.stats().await.total_transactions, 3);
        // The lowest-priority tx should have been evicted
        assert!(
            !mempool.contains(&tx_low.hash).await,
            "Lowest priority tx should be evicted"
        );
        // The new tx should be present
        assert!(
            mempool.contains(&tx_new.hash).await,
            "New higher-priority tx should be present"
        );
    }

    /// Add transactions, call clear(), verify the mempool is empty.
    #[tokio::test]
    async fn test_mempool_clear() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let tx1 = create_test_tx(0, 2_000_000_000, [20; 32]);
        let tx2 = create_test_tx(0, 2_000_000_000, [21; 32]);
        mempool
            .add_transaction(tx1, TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx2, TxClass::Inference)
            .await
            .unwrap();
        assert_eq!(mempool.stats().await.total_transactions, 2);

        mempool.clear().await;

        let stats = mempool.stats().await;
        assert_eq!(
            stats.total_transactions, 0,
            "Mempool should be empty after clear"
        );
        assert_eq!(stats.total_size, 0, "Total size should be 0 after clear");
        assert_eq!(
            stats.unique_senders, 0,
            "No senders should remain after clear"
        );
    }

    /// Add a tx with very short expiry, then call clear_expired() and verify removal.
    /// Note: clear_expired uses wall-clock time, so we set tx_expiry_secs=0 to make
    /// all existing txs "expired" immediately on the next call.
    #[tokio::test]
    async fn test_mempool_expired_tx_cleanup() {
        let config = MempoolConfig {
            tx_expiry_secs: 0, // Expire immediately
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        let tx = create_test_tx(0, 2_000_000_000, [30; 32]);
        let tx_hash = tx.hash;
        mempool
            .add_transaction(tx, TxClass::Standard)
            .await
            .unwrap();
        assert_eq!(mempool.stats().await.total_transactions, 1);

        // Wait >1s so the tx timestamp (second-precision) is strictly in the past
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        mempool.clear_expired().await;

        assert!(
            !mempool.contains(&tx_hash).await,
            "Expired tx should be removed"
        );
        assert_eq!(mempool.stats().await.total_transactions, 0);
    }

    /// Add transactions of various classes and verify stats().by_class counts.
    #[tokio::test]
    async fn test_mempool_stats() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        // Add 2 Standard, 1 System, 1 Inference from different senders
        mempool
            .add_transaction(
                create_test_tx(0, 2_000_000_000, [40; 32]),
                TxClass::Standard,
            )
            .await
            .unwrap();
        mempool
            .add_transaction(
                create_test_tx(0, 2_000_000_000, [41; 32]),
                TxClass::Standard,
            )
            .await
            .unwrap();
        mempool
            .add_transaction(create_test_tx(0, 2_000_000_000, [42; 32]), TxClass::System)
            .await
            .unwrap();
        mempool
            .add_transaction(
                create_test_tx(0, 2_000_000_000, [43; 32]),
                TxClass::Inference,
            )
            .await
            .unwrap();

        let stats = mempool.stats().await;
        assert_eq!(stats.total_transactions, 4);
        assert_eq!(stats.unique_senders, 4);
        assert_eq!(*stats.by_class.get(&TxClass::Standard).unwrap_or(&0), 2);
        assert_eq!(*stats.by_class.get(&TxClass::System).unwrap_or(&0), 1);
        assert_eq!(*stats.by_class.get(&TxClass::Inference).unwrap_or(&0), 1);
        assert_eq!(*stats.by_class.get(&TxClass::ModelUpdate).unwrap_or(&0), 0);
    }

    /// Add txs of known sizes, call get_best_transactions with a tight max_size
    /// limit, and verify the size limit is respected.
    #[tokio::test]
    async fn test_mempool_get_best_transactions_respects_size_limit() {
        let config = MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        };
        let mempool = Mempool::new(config);

        // Create txs with different data sizes. Base tx size is ~200 bytes (hash+nonce+from+to+value+gas+sig).
        // Adding data increases the size.
        let mut tx_small = create_test_tx(0, 3_000_000_000, [50; 32]);
        tx_small.data = vec![0u8; 10]; // ~210 bytes total
        let mut tx_medium = create_test_tx(0, 2_000_000_000, [51; 32]);
        tx_medium.data = vec![0u8; 100]; // ~300 bytes total
        let mut tx_large = create_test_tx(0, 1_000_000_000, [52; 32]);
        tx_large.data = vec![0u8; 500]; // ~700 bytes total

        mempool
            .add_transaction(tx_small.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx_medium.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(tx_large.clone(), TxClass::Standard)
            .await
            .unwrap();

        // Set max_size that fits only the small and medium txs (~510 bytes)
        // but not the large one too
        let best = mempool.get_best_transactions(10, 510).await;

        // The small tx has highest gas price so it's selected first (~210 bytes),
        // then medium (~300 bytes, total ~510), then large won't fit.
        assert!(
            best.len() <= 2,
            "Should not include all 3 txs under the size limit"
        );
        // Verify no tx was included that would push total over the limit
        let total: usize = best
            .iter()
            .map(|t| {
                // Replicate the size calculation: 32+8+32+32+16+8+8+data.len()+64
                32 + 8 + 32 + 32 + 16 + 8 + 8 + t.data.len() + 64
            })
            .sum();
        assert!(
            total <= 510,
            "Total selected tx size {} should not exceed max_size 510",
            total
        );
    }
}
