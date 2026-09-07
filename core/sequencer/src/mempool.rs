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
    /// Pre-fix the mempool accepted any nonce, so a funded attacker
    /// could post 100 nonces (1, 1_000_000, u64::MAX, …) per address;
    /// 99 of those rotted as gap-junk while filling the global cap.
    /// The 16-slot window matches Geth's default `txpool.accountqueue`.
    pub max_nonce_gap: u64,
}

/// SEQ-H2: per-block gas ceiling enforced at mempool admission. A transaction
/// whose `gas_limit` exceeds this can never fit in a block, so admitting it only
/// lets it sit at the front of the fee-ordered queue and starve block
/// production (the break-not-continue selection bug turned that into a
/// network-wide, zero-cost empty-block halt). Reject it up front. Matches
/// `BlockBuilderConfig::max_gas_per_block` (30M), the chain's block gas limit.
pub const MAX_GAS_PER_BLOCK: u64 = 30_000_000;

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
}

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
        }
    }

    /// Add a transaction to the mempool
    pub async fn add_transaction(
        &self,
        mut tx: Transaction,
        mut class: TxClass,
    ) -> Result<(), MempoolError> {
        // Determine transaction type from data
        tx.determine_type();

        // Override class based on AI transaction type
        if let Some(tx_type) = tx.tx_type {
            class = match tx_type {
                citrate_consensus::types::TransactionType::ModelDeploy
                | citrate_consensus::types::TransactionType::ModelUpdate
                | citrate_consensus::types::TransactionType::TrainingJob
                | citrate_consensus::types::TransactionType::LoraAdapter => TxClass::Compute,
                citrate_consensus::types::TransactionType::InferenceRequest => TxClass::Compute,
                citrate_consensus::types::TransactionType::Standard => class,
            };
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

        // Check mempool size limit
        if self.transactions.read().await.len() >= self.config.max_size {
            // Try to evict lower priority transaction
            self.evict_lowest_priority().await?;
        }

        // Create mempool transaction with AI-aware priority
        let timestamp = chrono::Utc::now().timestamp() as u64;

        // Use transaction's built-in priority calculation only for non-standard AI txs
        let ai_priority = match tx.tx_type {
            Some(citrate_consensus::types::TransactionType::Standard) | None => 0,
            _ => tx.priority(),
        };
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
            if is_evm_address && !tx.ecdsa_verified {
                tracing::warn!(
                    "ECDSA-shaped transaction from {:?} rejected: ecdsa_verified=false",
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

    /// Attempt Ethereum legacy/EIP-155 ECDSA verification using secp256k1
    fn verify_eth_ecdsa(&self, tx: &Transaction) -> anyhow::Result<bool> {
        use rlp::RlpStream;
        use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, Secp256k1};
        use sha3::{Digest, Keccak256};

        // Extract 20-byte address from `from` (we expect decoder to set this)
        let from_addr20 = {
            let bytes = tx.from.as_bytes();
            let mut a = [0u8; 20];
            a.copy_from_slice(&bytes[0..20]);
            a
        };

        // Build signable RLP (EIP-155 with configured chain_id)
        let mut s = RlpStream::new_list(9);
        s.append(&tx.nonce);
        s.append(&tx.gas_price);
        s.append(&tx.gas_limit);
        // to: empty for contract creation
        if let Some(to_pk) = &tx.to {
            // take first 20 bytes
            let mut to20 = [0u8; 20];
            to20.copy_from_slice(&to_pk.as_bytes()[0..20]);
            s.append(&to20.as_slice());
        } else {
            s.append_empty_data();
        }
        // value as minimal big-endian bytes
        let mut value_be = tx.value.to_be_bytes().to_vec();
        while value_be.first() == Some(&0u8) && value_be.len() > 1 {
            value_be.remove(0);
        }
        s.append(&value_be.as_slice());
        s.append(&tx.data.as_slice());
        s.append(&self.config.chain_id);
        s.append(&0u8);
        s.append(&0u8);

        let rlp_bytes = s.out().freeze();
        let mut hasher = Keccak256::new();
        hasher.update(&rlp_bytes);
        let sighash = hasher.finalize();

        // Build recoverable signature from r||s (no v available; try both recovery ids)
        let secp = Secp256k1::new();
        let msg = Message::from_slice(&sighash)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(tx.signature.as_bytes());

        for rec_id in 0..=1 {
            if let Ok(recid) = RecoveryId::from_i32(rec_id) {
                if let Ok(recsig) = RecoverableSignature::from_compact(&sig_bytes, recid) {
                    if let Ok(pubkey) = secp.recover_ecdsa(&msg, &recsig) {
                        let uncompressed = pubkey.serialize_uncompressed();
                        // Compute Ethereum address
                        let mut hasher = Keccak256::new();
                        hasher.update(&uncompressed[1..]);
                        let hash = hasher.finalize();
                        let mut addr = [0u8; 20];
                        addr.copy_from_slice(&hash[12..]);
                        if addr == from_addr20 {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
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
            .map(|n| n + 1)
    }

    /// Get AI transactions (model operations, inference requests)
    pub async fn get_ai_transactions(&self, max_count: usize) -> Vec<Transaction> {
        let transactions = self.transactions.read().await;
        let mut ai_txs = Vec::new();

        for (_, mempool_tx) in transactions.iter() {
            if let Some(
                citrate_consensus::types::TransactionType::ModelDeploy
                | citrate_consensus::types::TransactionType::ModelUpdate
                | citrate_consensus::types::TransactionType::TrainingJob
                | citrate_consensus::types::TransactionType::InferenceRequest
                | citrate_consensus::types::TransactionType::LoraAdapter,
            ) = mempool_tx.tx.tx_type
            {
                ai_txs.push(mempool_tx.tx.clone());
                if ai_txs.len() >= max_count {
                    break;
                }
            }
        }

        ai_txs
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
                    if selected.iter().any(|t| t.hash == *hash) {
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
                        total_size += mtx.size;
                        next_nonce.insert(sender, mtx.tx.nonce + 1);
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
                Some(nonce) => tx.nonce == nonce + 1,
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
        let expiry_time = current_time - self.config.tx_expiry_secs;

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
