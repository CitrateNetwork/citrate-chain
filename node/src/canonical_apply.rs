// citrate/node/src/canonical_apply.rs
//
// EXECUTE-ON-RECEIVE — step 2: the applied-tip pointer + fast-path driver.
//
// The node has historically had NO execute-on-receive: received blocks were
// DAG-admitted and their bytes persisted, but their transactions were never
// executed, so world state advanced ONLY via local production. This module
// closes that gap for the common case — linear canonical growth — by wiring
// `Executor::apply_block` into the receive path behind a persisted "applied
// tip" pointer.
//
// Design & invariants: docs/consensus/EXECUTE_ON_RECEIVE_state_application.md.
// Reroll activation (v2 headers): docs/consensus/REROLL_ADDENDUM_*.md.
//
// Concurrency: `apply_block` takes an executor snapshot, executes, verifies the
// state root, then persists-or-restores. It is therefore NOT safe to run
// concurrently with the producer's own execute→persist (a snapshot could
// capture, and a restore roll back, the producer's in-flight state). A single
// `Arc<Mutex<AppliedTip>>` serializes ALL state-advancing operations: the
// receive path goes through `apply_received` (which locks internally) and the
// producer holds the SAME lock (via `advance_lock()`) across its build critical
// section, updating the tip inline before releasing it.
//
// Reward reproducibility: a receiver can only reproduce a block's `state_root`
// if it credits the exact same block rewards the producer did. The enhanced
// economics reward path reads node-local, non-consensus state (staking manager,
// f64 reputation, dynamic pricing) and is NOT reproducible — so under
// execute-on-receive (v2 headers) the producer MUST use the deterministic basic
// reward path, which is a pure function of `header.height` + `transactions`.
// This module recomputes that same basic reward to build the credit list.

use std::sync::Arc;

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};

use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::{Block, Hash};
use citrate_economics::{RewardCalculator, RewardConfig};
use citrate_execution::state::StateSnapshot;
use citrate_execution::types::ExecutionError;
use citrate_execution::Executor;
use citrate_storage::StorageManager;
use primitive_types::U256;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Reorg window: the number of most-recent applied blocks whose full state
/// snapshots the ring retains. Bounds both memory (≤ this many full-state
/// snapshots) and the deepest revertible reorg — a fork older than this is
/// refused (treated like a finality violation). Matches `ChainSelector`'s
/// default `max_reorg_depth`. See docs/consensus/EXECUTE_ON_RECEIVE §4 step 4.
const MAX_REORG_DEPTH: u64 = 100;

/// Treasury address that receives the treasury slice of each block reward.
/// Mirrors the producer's `settle_block_rewards` basic-credit list and
/// `RewardConfig.treasury_address`.
const TREASURY_ADDR: [u8; 20] = [0x11; 20];

/// Canonical block-reward parameters. **Single source of truth** shared by the
/// producer (basic reward path) and the receive-side driver, so both credit
/// byte-identical rewards and the receiver reproduces the producer's
/// `state_root`. If these ever diverge, execute-on-receive rejects every block.
pub fn canonical_reward_config() -> RewardConfig {
    RewardConfig {
        block_reward: 10, // 10 SALT per block
        halving_interval: 2_100_000,
        inference_bonus: 1,        // 0.01 SALT per inference
        model_deployment_bonus: 1, // 1 SALT per model deployment
        treasury_percentage: 10,
        treasury_address: citrate_execution::types::Address(TREASURY_ADDR),
    }
}

/// The block whose post-execution world state the executor currently reflects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedTip {
    pub hash: Hash,
    pub height: u64,
}

/// The applied tip plus a bounded ring of state snapshots — one per applied
/// block within the reorg window, keyed by height — so a reorg can revert world
/// state to the fork point. Guarded by the shared state-advance lock, so the
/// producer and the receive path mutate it atomically.
pub struct AppliedState {
    tip: AppliedTip,
    /// height → (that block's hash, executor state AS-OF that block). Pruned to
    /// the most recent `MAX_REORG_DEPTH` heights (below the reorg window is
    /// unrevertible). One entry per applied height on the current applied chain.
    snapshots: BTreeMap<u64, (Hash, StateSnapshot)>,
}

impl AppliedState {
    /// Record the state snapshot for a freshly-applied block and advance the tip,
    /// pruning snapshots that fall out of the reorg window.
    fn record(&mut self, hash: Hash, height: u64, snapshot: StateSnapshot) {
        self.tip = AppliedTip { hash, height };
        self.snapshots.insert(height, (hash, snapshot));
        let floor = height.saturating_sub(MAX_REORG_DEPTH);
        self.snapshots.retain(|h, _| *h >= floor);
    }
}

/// Fork-choice hook: yields the DAG's currently selected (best) tip, or `None`.
/// A boxed async closure so production wires `GhostDag::select_tip` while tests
/// inject a fixed tip — avoiding an async-trait dependency.
type ForkChoice = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Option<Hash>> + Send>> + Send + Sync>;

/// Registry snapshot-sync hook: given a snapshot-boundary height, rebuild the
/// proposer selector and return the validator count (or an error string). A boxed
/// async closure so production wires `RegistrySync::sync_for_snapshot` while tests
/// inject a counter.
type RegistrySyncHook =
    Arc<dyn Fn(u64) -> Pin<Box<dyn Future<Output = Result<usize, String>> + Send>> + Send + Sync>;

/// Outcome of a reorg attempt.
#[derive(Debug)]
pub enum ReorgOutcome {
    /// Reverted to the fork point and re-applied the winning branch to `new_tip`.
    Reorged {
        new_tip: Hash,
        height: u64,
        /// Blocks rolled off the abandoned branch (fork_point..old_tip).
        reverted: u64,
        /// Blocks applied on the winning branch (fork_point..new_tip).
        applied: u64,
    },
    /// `new_tip` is already the applied tip — nothing to do.
    NoChange,
    /// Refused or failed: fork point below the retained window / finalized floor,
    /// a missing block, or a bad block on the winning branch. World state is left
    /// byte-identical to before the attempt (invariant I3).
    Rejected(String),
}

/// Result of attempting to apply a received block on the fast path.
#[derive(Debug)]
pub enum ApplyOutcome {
    /// Executed, `state_root` verified, applied tip advanced + persisted.
    Applied { root: Hash, height: u64 },
    /// Does not linearly extend the applied tip (a gap ahead, or a sibling /
    /// fork). State untouched — deferred to a later driver step (gap-extend /
    /// reorg, design doc §4). Not an error.
    Deferred,
    /// `state_root` mismatch or a transaction hard-errored: the block is
    /// invalid. State untouched (reverted). The peer should be scored down.
    Rejected(String),
    /// Already applied (block == current tip, or below it). No-op.
    AlreadyApplied,
}

/// Execute-on-receive driver. Owns the shared applied-state lock (tip + reorg
/// snapshot ring), the deterministic reward calculator, and an optional
/// fork-choice source; drives `Executor::apply_block`.
pub struct CanonicalApplicator {
    executor: Arc<Executor>,
    storage: Arc<StorageManager>,
    reward_calculator: RewardCalculator,
    /// Serializes state advancement (see module docs). Holds the applied tip +
    /// the reorg snapshot ring.
    lock: Arc<Mutex<AppliedState>>,
    /// Fork-choice hook (GhostDAG in production). When set, after the forward
    /// drain the driver reorgs the applied tip toward the selected tip. `None`
    /// disables reorg (steps 2–3 behavior only). Wired under `CITRATE_BLOCK_V2`.
    fork_choice: Option<ForkChoice>,
    /// Last finalized height — the reorg floor (I4: never revert below finality).
    /// Defaults to 0 (genesis); tightened when wired to the checkpoint manager.
    finalized_height: Arc<AtomicU64>,
    /// VALIDATOR-S1 registry snapshot-sync. When set, after applying a RECEIVED
    /// or REORGED block at a snapshot boundary S(E) the driver rebuilds the shared
    /// proposer selector from `ValidatorRegistry.activeSet()` as-of that state —
    /// so a non-producing node (or any node that receives / reorgs to S(E) from a
    /// peer) loads epoch-E membership, not just the producer. Complements the
    /// producer's own hook, which covers locally-produced S(E) blocks; the two
    /// cover disjoint block sources (produced blocks are recorded, never drained),
    /// so there is no double-sync. `None` disables it.
    registry_sync: Option<RegistrySyncHook>,
}

impl CanonicalApplicator {
    /// Construct the driver, seeding the applied tip from the persisted pointer.
    ///
    /// If no pointer exists (fresh genesis, or a store written before this
    /// feature), seed from the latest persisted block: a producer has already
    /// executed+persisted state through its latest height, so "state is applied
    /// through `latest_height`" is the correct default. A pure receiver that has
    /// only genesis seeds to (genesis_hash, 0).
    pub fn new(executor: Arc<Executor>, storage: Arc<StorageManager>) -> Self {
        let tip = storage
            .blocks
            .get_applied_tip()
            .ok()
            .flatten()
            .map(|(hash, height)| AppliedTip { hash, height })
            .unwrap_or_else(|| {
                let height = storage.blocks.get_latest_height().unwrap_or(0);
                let hash = storage
                    .blocks
                    .get_block_by_height(height)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                AppliedTip { hash, height }
            });
        info!(
            "execute-on-receive: applied tip seeded at {} @ height {}",
            tip.hash, tip.height
        );
        // Seed the reorg ring with the current state as-of the seeded tip: the
        // executor reflects this tip's state at construction, so it is the base a
        // reorg can revert to before any new block is applied.
        let mut snapshots = BTreeMap::new();
        snapshots.insert(tip.height, (tip.hash, executor.state_snapshot()));
        Self {
            executor,
            storage,
            reward_calculator: RewardCalculator::new(canonical_reward_config()),
            lock: Arc::new(Mutex::new(AppliedState { tip, snapshots })),
            fork_choice: None,
            finalized_height: Arc::new(AtomicU64::new(0)),
            registry_sync: None,
        }
    }

    /// Attach the fork-choice authority (GhostDAG). Enables reorg: after the
    /// forward drain, the driver reorgs the applied tip toward `select_tip()`.
    pub fn with_fork_choice(mut self, ghostdag: Arc<GhostDag>) -> Self {
        self.fork_choice = Some(Arc::new(move || {
            let g = ghostdag.clone();
            Box::pin(async move { g.select_tip().await.ok() })
        }));
        self
    }

    /// Shared handle to the finalized-height floor, for the caller to update as
    /// BFT checkpoints finalize. Reorgs never revert below this height (I4).
    pub fn finalized_height_handle(&self) -> Arc<AtomicU64> {
        self.finalized_height.clone()
    }

    /// Attach the VALIDATOR-S1 registry snapshot-sync (see the field docs). The
    /// driver then re-syncs the proposer selector at each applied/reorged S(E).
    pub fn with_registry_sync(
        mut self,
        registry_sync: Arc<crate::registry_sync::RegistrySync>,
    ) -> Self {
        self.registry_sync = Some(Arc::new(move |height| {
            let rs = registry_sync.clone();
            Box::pin(async move { rs.sync_for_snapshot(height).await })
        }));
        self
    }

    /// VALIDATOR-S1: if `height` is a snapshot boundary S(E), rebuild the shared
    /// proposer selector from the registry against the just-applied state (so
    /// epoch-E membership is loaded before epoch-E blocks are admitted). Called
    /// after applying a received or reorged block. No-op unless a registry sync is
    /// attached and `height` is a boundary. Runs under the applied-state lock, so
    /// the selector update is atomic with advancing past S(E).
    async fn maybe_sync_registry(&self, height: u64) {
        if let Some(hook) = &self.registry_sync {
            if let Some(epoch) = crate::registry_sync::snapshot_epoch_at(height) {
                match hook(height).await {
                    Ok(n) => info!(
                        "VALIDATOR-S1: synced validator set for epoch {} at snapshot height {} ({} validators) [receive/reorg path]",
                        epoch, height, n
                    ),
                    Err(e) => warn!(
                        "VALIDATOR-S1: registry snapshot sync failed at height {} (epoch {}): {}",
                        height, epoch, e
                    ),
                }
            }
        }
    }

    fn finalized_height(&self) -> u64 {
        self.finalized_height.load(Ordering::SeqCst)
    }

    /// The shared state-advance lock (applied tip + reorg snapshot ring). The
    /// producer acquires this across its execute→persist critical section so
    /// production never races the receive path, and records the sealed block via
    /// [`record_produced`] before release.
    pub fn advance_lock(&self) -> Arc<Mutex<AppliedState>> {
        self.lock.clone()
    }

    /// Current applied tip (locks briefly).
    pub async fn applied_tip(&self) -> AppliedTip {
        self.lock.lock().await.tip
    }

    /// Deterministic reward credits for `block` — the SAME mints the producer
    /// applied on the basic reward path: `[(coinbase, validator_reward),
    /// (treasury, treasury_reward)]`. `coinbase` comes from the committed v2
    /// header field (`block.header.coinbase`).
    fn reward_credits(
        &self,
        block: &Block,
    ) -> Vec<(citrate_execution::types::Address, U256)> {
        let reward = self.reward_calculator.calculate_reward(block);
        vec![
            (
                citrate_execution::types::Address(block.header.coinbase),
                reward.validator_reward,
            ),
            (
                citrate_execution::types::Address(TREASURY_ADDR),
                reward.treasury_reward,
            ),
        ]
    }

    /// Persist the applied-tip pointer + this block's verified state root (crash
    /// recovery / fast startup). Non-fatal on failure — logged, not returned.
    fn persist_applied(&self, block_hash: &Hash, height: u64, state_root: &Hash) {
        if let Err(e) = self.storage.blocks.put_applied_tip(block_hash, height) {
            warn!(
                "execute-on-receive: applied block {} @ {} but failed to persist tip: {}",
                block_hash, height, e
            );
        }
        if let Err(e) = self.storage.state.put_state_root(block_hash, state_root) {
            warn!(
                "execute-on-receive: failed to persist state root for {}: {}",
                block_hash, e
            );
        }
    }

    /// The single persisted block that directly extends the applied `tip` on the
    /// selected chain: a child of `tip.hash` whose `selected_parent` is `tip.hash`
    /// and which sits exactly one height above it.
    /// - `Ok(Some(block))` — a unique linear extension is persisted.
    /// - `Ok(None)` — none persisted (chain tip, or an out-of-order gap not yet filled).
    /// - `Err(())` — MULTIPLE selected-parent children at that height (a fork /
    ///   equivocation): linear extension is ambiguous, defer to fork-choice (step 4).
    ///
    /// `get_children` returns blocks listing `tip` as ANY parent (selected or
    /// merge); the `selected_parent` filter keeps only the linear canonical chain.
    fn next_persisted_extension(&self, tip: &AppliedTip) -> Result<Option<Block>, ()> {
        let children = match self.storage.blocks.get_children(&tip.hash) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "execute-on-receive: get_children({}) failed: {}",
                    tip.hash, e
                );
                return Ok(None);
            }
        };
        let mut extensions: Vec<Block> = children
            .into_iter()
            .filter_map(|h| self.storage.blocks.get_block(&h).ok().flatten())
            .filter(|b| b.selected_parent() == tip.hash && b.header.height == tip.height + 1)
            .collect();
        match extensions.len() {
            0 => Ok(None),
            1 => Ok(Some(extensions.pop().expect("len == 1"))),
            _ => Err(()),
        }
    }

    /// Walk the applied tip FORWARD through already-persisted descendants on the
    /// selected chain, executing + state-root-verifying each, until no persisted
    /// block extends it (chain tip), a fork is hit, or a block is rejected.
    ///
    /// Subsumes the step-2 direct extension (one iteration) AND step-3 gap-extend:
    /// because every received block is persisted (`put_block`) before the driver
    /// runs, the instant an out-of-order gap is filled the whole contiguous suffix
    /// drains in a single call. Must be called with the lock held (mutates the live
    /// `tip`). Blocks applied before a rejection are valid + committed; the chain
    /// simply cannot advance past the offending block until fork-choice (step 4)
    /// routes around it.
    async fn drain_forward(&self, state: &mut AppliedState) -> DrainOutcome {
        let mut applied: Vec<Hash> = Vec::new();
        loop {
            let block = match self.next_persisted_extension(&state.tip) {
                Ok(Some(b)) => b,
                Ok(None) => break,
                Err(()) => {
                    debug!(
                        "execute-on-receive: fork above applied tip {} @ {} — deferring to reorg (step 4)",
                        state.tip.hash, state.tip.height
                    );
                    break;
                }
            };
            let block_hash = block.header.block_hash;
            let height = block.header.height;
            let credits = self.reward_credits(&block);
            match self
                .executor
                .apply_block(&block, block.header.coinbase, &credits)
                .await
            {
                Ok(_root) => {
                    state.record(block_hash, height, self.executor.state_snapshot());
                    self.persist_applied(&block_hash, height, &block.state_root);
                    applied.push(block_hash);
                    info!(
                        "execute-on-receive: applied block {} @ height {} (root verified)",
                        block_hash, height
                    );
                    // VALIDATOR-S1: re-sync the selector if this crossed a snapshot boundary.
                    self.maybe_sync_registry(height).await;
                }
                Err(ExecutionError::StateRootMismatch { expected, got }) => {
                    warn!(
                        "execute-on-receive: REJECT block {} @ {} — state root mismatch (claimed {}, computed {})",
                        block_hash, height, expected, got
                    );
                    return DrainOutcome {
                        applied,
                        rejected: Some((
                            block_hash,
                            format!("state root mismatch: claimed {expected}, computed {got}"),
                        )),
                    };
                }
                Err(e) => {
                    warn!(
                        "execute-on-receive: REJECT block {} @ {} — execution error: {}",
                        block_hash, height, e
                    );
                    return DrainOutcome {
                        applied,
                        rejected: Some((block_hash, format!("execution error: {e}"))),
                    };
                }
            }
        }
        DrainOutcome { applied, rejected: None }
    }

    /// Reorg the applied chain to `new_tip`: revert world state to the fork point
    /// (the deepest applied block on both the current and the target chain), then
    /// re-apply + state-root-verify the winning branch forward to `new_tip`.
    ///
    /// The fork point is found by walking `new_tip`'s selected-parent ancestry
    /// until it meets a retained applied block `(height, hash)` in the snapshot
    /// ring — which both locates the divergence and guarantees a snapshot to
    /// revert to. Guards (each leaves world state byte-identical — invariant I3):
    /// - fork point older than the retained window (`MAX_REORG_DEPTH`) → `Rejected`
    ///   (too deep to revert; treated like a finality violation);
    /// - fork point below the finalized floor → `Rejected` (I4: never revert past
    ///   finality);
    /// - a missing or bad block on the winning branch → `Rejected`, and the ENTIRE
    ///   attempt is rolled back to the pre-reorg state (an outer full snapshot).
    ///
    /// Must be called with the lock held (mutates the live `AppliedState`).
    pub async fn reorg_to(&self, state: &mut AppliedState, new_tip: Hash) -> ReorgOutcome {
        if new_tip == state.tip.hash {
            return ReorgOutcome::NoChange;
        }
        // Outer safety net: a byte-exact snapshot of the current state + tip so a
        // failed reapply is fully undone (I3). This is the pre-reorg applied tip.
        let pre_state = self.executor.state_snapshot();
        let pre_tip = state.tip;

        // Walk new_tip's selected-parent ancestry down to the fork point (the
        // first ancestor that is a retained applied block), collecting the branch.
        let mut branch: Vec<Block> = Vec::new(); // new_tip .. fork_point+1
        let mut cursor = new_tip;
        let fork = loop {
            let block = match self.storage.blocks.get_block(&cursor).ok().flatten() {
                Some(b) => b,
                None => {
                    // The genesis base is a sentinel (`Hash::default` @ height 0)
                    // seeded into the ring at construction with no stored block. A
                    // branch that forks at genesis walks down to it — that is the
                    // fork point, and its snapshot is the base to revert to.
                    if let Some((h0, _)) = state.snapshots.get(&0) {
                        if *h0 == cursor {
                            break AppliedTip { hash: cursor, height: 0 };
                        }
                    }
                    return ReorgOutcome::Rejected(format!(
                        "reorg to {new_tip}: missing block {cursor} on branch"
                    ));
                }
            };
            let h = block.header.height;
            if let Some((hash, _)) = state.snapshots.get(&h) {
                if *hash == cursor {
                    break AppliedTip { hash: cursor, height: h }; // fork point (the base)
                }
            }
            // NB: do NOT bail on `block.is_genesis()` — that is true for any
            // first block (its selected_parent is the genesis sentinel), and we
            // must still step to that sentinel, which the `None` arm above turns
            // into the genesis fork point. Only the depth cap bounds the walk.
            if branch.len() as u64 >= MAX_REORG_DEPTH {
                return ReorgOutcome::Rejected(format!(
                    "reorg to {new_tip}: no common applied ancestor within {MAX_REORG_DEPTH} blocks"
                ));
            }
            cursor = block.selected_parent();
            branch.push(block);
        };

        // I4: never revert below the finalized floor.
        let floor = self.finalized_height();
        if fork.height < floor {
            return ReorgOutcome::Rejected(format!(
                "reorg fork point height {} below finalized height {}",
                fork.height, floor
            ));
        }

        // Revert to the fork point.
        let base_snapshot = match state.snapshots.get(&fork.height) {
            Some((_, snap)) => snap.clone(),
            None => {
                return ReorgOutcome::Rejected(format!(
                    "reorg fork point snapshot missing at height {}",
                    fork.height
                ));
            }
        };
        self.executor.state_restore(base_snapshot);

        // Re-apply the winning branch forward IN-MEMORY ONLY (`apply_block_no_persist`).
        // HIGH-2: the durable store has no rollback, so we must NOT write the candidate
        // branch to it per block — otherwise an abort would leave abandoned writes on
        // disk. Nothing is persisted here; `reconcile_store_from` writes the store once,
        // after the whole reorg succeeds. Snapshots commit to the ring on success only.
        branch.reverse(); // fork_point+1 .. new_tip
        let mut new_snaps: Vec<(u64, Hash, StateSnapshot)> = Vec::new();
        let mut tip = fork;
        for block in &branch {
            let credits = self.reward_credits(block);
            match self
                .executor
                .apply_block_no_persist(block, block.header.coinbase, &credits)
                .await
            {
                Ok(_) => {
                    let h = block.header.height;
                    let hh = block.header.block_hash;
                    tip = AppliedTip { hash: hh, height: h };
                    new_snaps.push((h, hh, self.executor.state_snapshot()));
                }
                Err(e) => {
                    // Abort: byte-exact in-memory restore (incl. dirty-code, captured
                    // in the snapshot) — the re-apply did NOT persist, so the durable
                    // store is untouched (still the old branch, == pre_state) and the
                    // ring/tip/pointer never moved (review finding E).
                    self.executor.state_restore(pre_state);
                    warn!(
                        "execute-on-receive: reorg to {} aborted at {} — {} (reverted to {})",
                        new_tip, block.header.block_hash, e, pre_tip.hash
                    );
                    return ReorgOutcome::Rejected(format!(
                        "reorg reapply failed at {}: {e}",
                        block.header.block_hash
                    ));
                }
            }
        }

        // Success. Reconcile the durable store from the pre-reorg baseline (which
        // the store still reflects) to the now-current new-branch state — writing
        // the account+storage diff and deleting abandoned-created accounts — so
        // RocksDB matches memory and a restart-after-reorg hydrates correctly.
        if let Err(e) = self.executor.reconcile_store_from(&pre_state) {
            warn!(
                "execute-on-receive: reorg to {} applied in-memory but store reconcile failed: {}",
                new_tip, e
            );
        }
        // Persist the new branch's state roots + re-sync the selector at any S(E)
        // the reorg crossed (deferred to here so an abort writes nothing durable).
        for block in &branch {
            let _ = self
                .storage
                .state
                .put_state_root(&block.header.block_hash, &block.state_root);
            self.maybe_sync_registry(block.header.height).await;
        }

        // Commit: adopt the new tip, merge new-branch snapshots, drop the stale
        // abandoned-branch snapshots (heights above the new tip) and prune the
        // window, then persist the pointer once.
        state.tip = tip;
        for (h, hh, snap) in new_snaps {
            state.snapshots.insert(h, (hh, snap));
        }
        let floor = tip.height.saturating_sub(MAX_REORG_DEPTH);
        state.snapshots.retain(|h, _| *h <= tip.height && *h >= floor);
        if let Err(e) = self.storage.blocks.put_applied_tip(&tip.hash, tip.height) {
            warn!(
                "execute-on-receive: reorged to {} @ {} but failed to persist tip: {}",
                tip.hash, tip.height, e
            );
        }
        info!(
            "execute-on-receive: REORG {} @ {} → {} @ {} (reverted {}, applied {})",
            pre_tip.hash,
            pre_tip.height,
            tip.hash,
            tip.height,
            pre_tip.height.saturating_sub(fork.height),
            branch.len()
        );
        ReorgOutcome::Reorged {
            new_tip: tip.hash,
            height: tip.height,
            reverted: pre_tip.height.saturating_sub(fork.height),
            applied: branch.len() as u64,
        }
    }

    /// Apply a received, DAG-admitted block, extending the applied tip as far as
    /// the persisted selected chain allows, then (if a fork-choice source is
    /// attached) reorging toward the DAG's selected tip.
    ///
    /// Common case (step 2): the block directly extends the tip → applied +
    /// state-root-verified. Out-of-order (step 3, gap-extend): the block arrived
    /// ahead of its intermediates and was deferred; a later arrival fills the gap
    /// and the drain cascades the whole suffix. Fork (step 4): when the drain
    /// stalls at a fork and the DAG selects a heavier branch, `reorg_to` reverts
    /// to the fork point and re-applies the winner. A bad `state_root` anywhere is
    /// rejected with world state left byte-identical.
    ///
    /// The outcome is classified for the RECEIVED block: `Applied` iff it ended up
    /// on the applied chain (via drain or reorg); `Rejected` iff it was reached and
    /// rejected; otherwise `Deferred`.
    pub async fn apply_received(&self, block: &Block) -> ApplyOutcome {
        let mut state = self.lock.lock().await;

        let block_hash = block.header.block_hash;
        let height = block.header.height;

        // Echo of the exact applied tip, or a block already on the applied chain.
        // NB (F3): we do NOT short-circuit on `height <= tip.height` alone — an
        // equal-or-lower-height block that is NOT on our applied chain is a
        // competing fork sibling, and fork choice below may select it (a heavier
        // equal-height branch). Only a block that is genuinely already applied is
        // a no-op here.
        if block_hash == state.tip.hash || self.on_applied_chain(&state, block_hash, height) {
            return ApplyOutcome::AlreadyApplied;
        }

        let out = self.drain_forward(&mut state).await;

        // Step 4: after the linear drain, follow fork choice. If the DAG selects a
        // tip that isn't ours, reorg toward it (a no-op extension when our tip is
        // an ancestor of it; a revert+reapply when it's on a heavier branch).
        if let Some(fc) = &self.fork_choice {
            if let Some(best) = fc().await {
                if best != state.tip.hash {
                    match self.reorg_to(&mut state, best).await {
                        ReorgOutcome::Reorged { new_tip, height, reverted, applied } => {
                            info!(
                                "execute-on-receive: fork-choice reorged to {new_tip} @ {height} (reverted {reverted}, applied {applied})"
                            );
                        }
                        ReorgOutcome::NoChange => {}
                        ReorgOutcome::Rejected(why) => {
                            debug!("execute-on-receive: fork-choice reorg to {best} declined: {why}");
                        }
                    }
                }
            }
        }

        // Classify for the received block against the FINAL (post-reorg) applied
        // chain — NOT the pre-reorg `out.applied` (F1): a block the drain applied
        // could have been reverted by the subsequent fork-choice reorg, so only
        // the ring reflects whether it actually ended up on the applied chain.
        if self.on_applied_chain(&state, block_hash, height) {
            ApplyOutcome::Applied {
                root: block.state_root,
                height,
            }
        } else if let Some((bad, why)) = &out.rejected {
            if *bad == block_hash {
                ApplyOutcome::Rejected(format!("{bad}: {why}"))
            } else {
                ApplyOutcome::Deferred
            }
        } else {
            if !out.applied.is_empty() {
                debug!(
                    "execute-on-receive: extended tip to {} @ {} ({} block(s)); {} still deferred",
                    state.tip.hash,
                    state.tip.height,
                    out.applied.len(),
                    block_hash
                );
            }
            ApplyOutcome::Deferred
        }
    }

    /// Whether `(hash, height)` is the applied block at that height on the current
    /// applied chain (i.e., it was applied — possibly via reorg — and retained).
    fn on_applied_chain(&self, state: &AppliedState, hash: Hash, height: u64) -> bool {
        height <= state.tip.height
            && state
                .snapshots
                .get(&height)
                .map(|(h, _)| *h == hash)
                .unwrap_or(false)
    }
}

/// Result of draining the applied tip forward (private to the driver). Always
/// reports the blocks applied (in order); `rejected` names the first block that
/// failed verification, if any (blocks in `applied` are valid + committed).
struct DrainOutcome {
    applied: Vec<Hash>,
    rejected: Option<(Hash, String)>,
}

/// Update the applied state to a block the producer just authored (executed +
/// persisted itself). Called by the producer WHILE it holds `advance_lock()`, so
/// it takes the already-held guard rather than re-locking (the tokio Mutex is not
/// reentrant). Captures the executor's post-block state into the reorg ring (so a
/// later reorg can revert to a locally-produced block) and persists the pointer.
pub fn record_produced(
    state: &mut AppliedState,
    storage: &StorageManager,
    executor: &Executor,
    block: &Block,
) {
    let hash = block.header.block_hash;
    let height = block.header.height;
    state.record(hash, height, executor.state_snapshot());
    if let Err(e) = storage.blocks.put_applied_tip(&hash, height) {
        warn!(
            "execute-on-receive: produced block {} @ {} but failed to persist applied tip: {}",
            hash, height, e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{BlockBuilder, PublicKey, Signature, Transaction, VrfProof};
    use citrate_execution::revm_adapter::BlockContext;
    use citrate_execution::types::Address;
    use citrate_execution::StateDB;
    use citrate_storage::pruning::PruningConfig;

    const CB: [u8; 20] = [0x33; 20];
    const VRF_OUT: [u8; 32] = [0x5A; 32];

    /// Build an empty (reward-only) v2 block with an explicit VRF output.
    /// `vrf` only distinguishes block HASHES (it feeds prevrandao, which
    /// reward-only blocks never read) — so two branches can share a state root
    /// while forking, exactly as sibling blocks from different producers do.
    fn mk_block_vrf(height: u64, parent: Hash, state_root: Hash, vrf: [u8; 32]) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(CB)
            .timestamp(1000)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new(vrf),
            })
            .transactions(vec![])
            .state_root(state_root)
            .build_unhashed();
        b.header.block_hash = b.compute_hash();
        b
    }

    /// A-branch block (canonical VRF). Transactions are exercised by the
    /// executor's own `apply_block` tests; here we isolate the DRIVER.
    fn mk_block(height: u64, parent: Hash, state_root: Hash) -> Block {
        mk_block_vrf(height, parent, state_root, VRF_OUT)
    }

    /// B-branch block — distinct VRF so it forks from the A-branch at the same
    /// height with an identical (reward-only) state root but a different hash.
    fn mk_block_b(height: u64, parent: Hash, state_root: Hash) -> Block {
        mk_block_vrf(height, parent, state_root, [0x5B; 32])
    }

    /// Reward credits the driver applies, computed the same way it does internally.
    fn reward_for(block: &Block) -> (U256, U256) {
        let r = RewardCalculator::new(canonical_reward_config()).calculate_reward(block);
        (r.validator_reward, r.treasury_reward)
    }

    /// Post-execution state root a reward-only block must produce, computed on a
    /// throwaway executor (mirrors `apply_block`: set context → credit rewards →
    /// root). Isolated so the test asserts the driver reproduces the producer.
    fn expected_root(block: &Block) -> Hash {
        let exec = Executor::new(Arc::new(StateDB::new()));
        exec.set_block_context(BlockContext {
            coinbase: CB,
            prevrandao: VRF_OUT,
            block_hashes: std::collections::HashMap::new(),
        });
        let (validator, treasury) = reward_for(block);
        for (addr, amt) in [
            (Address(CB), validator),
            (Address(TREASURY_ADDR), treasury),
        ] {
            if amt > U256::zero() {
                let bal = exec.get_balance(&addr);
                exec.set_balance(&addr, bal + amt);
            }
        }
        exec.calculate_state_root()
    }

    fn fresh() -> (Arc<Executor>, Arc<StorageManager>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let exec = Arc::new(Executor::new(Arc::new(StateDB::new())));
        (exec, storage, dir)
    }

    /// Persist a block exactly as the receive path does (`put_block` precedes the
    /// driver), so the drain can find it via the DAG parent→children index.
    fn persist(storage: &StorageManager, block: &Block) {
        storage.blocks.put_block(block).expect("put_block");
    }

    /// Build a linked chain of `n` reward-only blocks from genesis, each carrying
    /// the correct CUMULATIVE post-execution state root (computed on a mirror
    /// executor). `blocks[i].parent == blocks[i-1].hash`.
    fn chain(n: u64) -> Vec<Block> {
        let exec = Executor::new(Arc::new(StateDB::new()));
        let mut blocks = Vec::new();
        let mut parent = Hash::default();
        for h in 1..=n {
            exec.set_block_context(BlockContext {
                coinbase: CB,
                prevrandao: VRF_OUT,
                block_hashes: std::collections::HashMap::new(),
            });
            let tmpl = mk_block(h, parent, Hash::default());
            let (v, t) = reward_for(&tmpl);
            for (addr, amt) in [(Address(CB), v), (Address(TREASURY_ADDR), t)] {
                if amt > U256::zero() {
                    let bal = exec.get_balance(&addr);
                    exec.set_balance(&addr, bal + amt);
                }
            }
            let root = exec.calculate_state_root();
            let blk = mk_block(h, parent, root);
            parent = blk.header.block_hash;
            blocks.push(blk);
        }
        blocks
    }

    #[tokio::test]
    async fn applies_linear_extension_and_advances_tip() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec.clone(), storage.clone());

        // Fresh store: applied tip seeds at (default, 0).
        assert_eq!(
            app.applied_tip().await,
            AppliedTip { hash: Hash::default(), height: 0 }
        );

        // A block at height 1 extending the genesis tip, claiming the correct root.
        let template = mk_block(1, Hash::default(), Hash::default());
        let root = expected_root(&template);
        let block = mk_block(1, Hash::default(), root);
        let (validator, treasury) = reward_for(&block);
        persist(&storage, &block);

        match app.apply_received(&block).await {
            ApplyOutcome::Applied { height, root: got } => {
                assert_eq!(height, 1);
                assert_eq!(got, root, "driver must reproduce the claimed state root");
            }
            other => panic!("expected Applied, got {other:?}"),
        }

        // Tip advanced (in-memory + persisted) and rewards credited to real executor.
        let tip = app.applied_tip().await;
        assert_eq!(tip.hash, block.header.block_hash);
        assert_eq!(tip.height, 1);
        assert_eq!(
            storage.blocks.get_applied_tip().expect("read tip"),
            Some((block.header.block_hash, 1))
        );
        assert_eq!(exec.get_balance(&Address(CB)), validator, "validator reward");
        assert_eq!(
            exec.get_balance(&Address(TREASURY_ADDR)),
            treasury,
            "treasury reward"
        );

        // Re-delivering the same block is a no-op (already applied).
        assert!(matches!(
            app.apply_received(&block).await,
            ApplyOutcome::AlreadyApplied
        ));
    }

    #[tokio::test]
    async fn rejects_bad_state_root_and_leaves_state_and_tip_untouched() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let root_before = exec.calculate_state_root();

        // Height 1 extends the tip, but claims a bogus root.
        let block = mk_block(1, Hash::default(), Hash::new([0xFF; 32]));
        persist(&storage, &block);
        match app.apply_received(&block).await {
            ApplyOutcome::Rejected(_) => {}
            other => panic!("expected Rejected, got {other:?}"),
        }

        // Invariant: tip unchanged, world state byte-identical, nothing persisted.
        assert_eq!(
            app.applied_tip().await,
            AppliedTip { hash: Hash::default(), height: 0 }
        );
        assert_eq!(exec.calculate_state_root(), root_before, "state reverted");
        assert_eq!(exec.get_balance(&Address(CB)), U256::zero(), "reward reverted");
        assert_eq!(storage.blocks.get_applied_tip().expect("read tip"), None);
    }

    #[tokio::test]
    async fn defers_non_linear_blocks() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec, storage.clone());

        // Gap ahead: height 3 while the tip is height 0 (intermediates missing).
        let gap = mk_block(3, Hash::default(), Hash::default());
        persist(&storage, &gap);
        assert!(matches!(
            app.apply_received(&gap).await,
            ApplyOutcome::Deferred
        ));

        // Right height, wrong parent (a fork/sibling off the applied chain).
        let fork = mk_block(1, Hash::new([0xAB; 32]), Hash::default());
        persist(&storage, &fork);
        assert!(matches!(
            app.apply_received(&fork).await,
            ApplyOutcome::Deferred
        ));

        // Tip never moved.
        assert_eq!(app.applied_tip().await.height, 0);
    }

    /// Step 3: a block that arrives ahead of its intermediates is deferred, and
    /// the drain cascades the whole contiguous suffix once the gap is filled.
    #[tokio::test]
    async fn gap_extend_cascades_when_missing_intermediate_arrives() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let c = chain(3);
        let (v, t) = reward_for(&c[0]); // identical per-block reward at these heights

        // b3 arrives first — ahead of b1/b2 → deferred, tip stays at genesis.
        persist(&storage, &c[2]);
        assert!(matches!(
            app.apply_received(&c[2]).await,
            ApplyOutcome::Deferred
        ));
        assert_eq!(app.applied_tip().await.height, 0);

        // b1 arrives — extends genesis; b2 still missing so it stops at height 1.
        persist(&storage, &c[0]);
        assert!(matches!(
            app.apply_received(&c[0]).await,
            ApplyOutcome::Applied { .. }
        ));
        assert_eq!(app.applied_tip().await.height, 1);

        // b2 arrives — fills the gap; the drain cascades b2 AND the already-persisted b3.
        persist(&storage, &c[1]);
        assert!(matches!(
            app.apply_received(&c[1]).await,
            ApplyOutcome::Applied { .. }
        ));
        let tip = app.applied_tip().await;
        assert_eq!(tip.height, 3, "gap-extend must cascade to the chain tip");
        assert_eq!(tip.hash, c[2].header.block_hash);

        // Three blocks' rewards accumulated; pointer persisted at the chain tip.
        assert_eq!(exec.get_balance(&Address(CB)), v * U256::from(3u64));
        assert_eq!(exec.get_balance(&Address(TREASURY_ADDR)), t * U256::from(3u64));
        assert_eq!(
            storage.blocks.get_applied_tip().expect("read tip"),
            Some((c[2].header.block_hash, 3))
        );
    }

    /// Re-delivering a block whose whole chain is already persisted drains it in a
    /// single call (all intermediates present) — the "top arrives last" case.
    #[tokio::test]
    async fn drains_full_chain_when_top_arrives_with_all_intermediates_present() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let c = chain(3);
        for b in &c {
            persist(&storage, b);
        }
        // Deliver only the tip; the drain walks genesis→b1→b2→b3 in one shot.
        assert!(matches!(
            app.apply_received(&c[2]).await,
            ApplyOutcome::Applied { .. }
        ));
        assert_eq!(app.applied_tip().await.height, 3);
    }

    /// Cumulative reward-only state roots for heights 1..=n (mirrors `chain`).
    fn roots(n: u64) -> Vec<Hash> {
        chain(n).iter().map(|b| b.state_root).collect()
    }

    /// Apply the A-branch [a1, a2] so the applied tip is a2 @ height 2, then
    /// persist a competing B-branch [b2, b3] that forks at a1. Returns everything
    /// the reorg tests need. b2/b3 are persisted but NOT applied (a fork above a1).
    async fn setup_fork(
        app: &CanonicalApplicator,
        storage: &StorageManager,
    ) -> (Block, Block, Block, Block) {
        let r = roots(3);
        let a1 = mk_block(1, Hash::default(), r[0]);
        let a2 = mk_block(2, a1.header.block_hash, r[1]);
        let b2 = mk_block_b(2, a1.header.block_hash, r[1]); // same state as a2, different hash
        let b3 = mk_block_b(3, b2.header.block_hash, r[2]);

        // Apply the A branch in order (b2 not yet persisted, so no fork blocks it).
        persist(storage, &a1);
        assert!(matches!(app.apply_received(&a1).await, ApplyOutcome::Applied { .. }));
        persist(storage, &a2);
        assert!(matches!(app.apply_received(&a2).await, ApplyOutcome::Applied { .. }));
        assert_eq!(app.applied_tip().await, AppliedTip { hash: a2.header.block_hash, height: 2 });

        // Now the heavier B branch arrives (persisted, but forks above the tip).
        persist(storage, &b2);
        persist(storage, &b3);
        (a1, a2, b2, b3)
    }

    #[tokio::test]
    async fn reorg_reverts_to_fork_point_and_reapplies_winning_branch() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let (a1, _a2, b2, b3) = setup_fork(&app, &storage).await;
        let (v, t) = reward_for(&b3);

        let lock = app.advance_lock();
        let mut state = lock.lock().await;
        match app.reorg_to(&mut state, b3.header.block_hash).await {
            ReorgOutcome::Reorged { new_tip, height, reverted, applied } => {
                assert_eq!(new_tip, b3.header.block_hash);
                assert_eq!(height, 3);
                assert_eq!(reverted, 1, "a2 rolled off");
                assert_eq!(applied, 2, "b2 + b3 applied");
            }
            other => panic!("expected Reorged, got {other:?}"),
        }

        // Tip is on the B branch; state = 3 blocks of reward; fork point retained.
        assert_eq!(state.tip, AppliedTip { hash: b3.header.block_hash, height: 3 });
        assert_eq!(state.snapshots.get(&2).map(|(h, _)| *h), Some(b2.header.block_hash),
            "height-2 snapshot now belongs to the B branch");
        assert_eq!(state.snapshots.get(&1).map(|(h, _)| *h), Some(a1.header.block_hash),
            "fork point retained");
        drop(state);
        assert_eq!(exec.get_balance(&Address(CB)), v * U256::from(3u64));
        assert_eq!(exec.get_balance(&Address(TREASURY_ADDR)), t * U256::from(3u64));
        assert_eq!(
            storage.blocks.get_applied_tip().expect("tip"),
            Some((b3.header.block_hash, 3))
        );
    }

    #[tokio::test]
    async fn reorg_aborts_on_bad_block_and_restores_pre_reorg_state() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let (_a1, a2, b2, _b3) = setup_fork(&app, &storage).await;
        let (v, t) = reward_for(&a2);

        // A B-branch tip claiming a bogus state root (b2 is valid; b3_bad is not).
        let b3_bad = mk_block_b(3, b2.header.block_hash, Hash::new([0xFF; 32]));
        persist(&storage, &b3_bad);

        let lock = app.advance_lock();
        let mut state = lock.lock().await;
        match app.reorg_to(&mut state, b3_bad.header.block_hash).await {
            ReorgOutcome::Rejected(_) => {}
            other => panic!("expected Rejected, got {other:?}"),
        }

        // I3: pre-reorg state + tip fully restored (still a2 @ 2, 2 blocks reward).
        assert_eq!(state.tip, AppliedTip { hash: a2.header.block_hash, height: 2 });
        assert_eq!(state.snapshots.get(&2).map(|(h, _)| *h), Some(a2.header.block_hash),
            "height-2 snapshot still the A branch");
        drop(state);
        assert_eq!(exec.get_balance(&Address(CB)), v * U256::from(2u64));
        assert_eq!(exec.get_balance(&Address(TREASURY_ADDR)), t * U256::from(2u64));
        assert_eq!(
            storage.blocks.get_applied_tip().expect("tip"),
            Some((a2.header.block_hash, 2)),
            "persisted pointer never moved"
        );
    }

    #[tokio::test]
    async fn reorg_refused_below_finalized_floor() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let (_a1, a2, _b2, b3) = setup_fork(&app, &storage).await;

        // Finalize height 2: the fork point (a1 @ 1) is now below finality.
        app.finalized_height_handle().store(2, Ordering::SeqCst);

        let lock = app.advance_lock();
        let mut state = lock.lock().await;
        match app.reorg_to(&mut state, b3.header.block_hash).await {
            ReorgOutcome::Rejected(why) => assert!(why.contains("finalized"), "got: {why}"),
            other => panic!("expected Rejected (finality), got {other:?}"),
        }
        // I4: applied tip unchanged (never reverted past finality).
        assert_eq!(state.tip, AppliedTip { hash: a2.header.block_hash, height: 2 });
    }

    #[tokio::test]
    async fn reorg_to_current_tip_is_noop() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let (_a1, a2, _b2, _b3) = setup_fork(&app, &storage).await;
        let lock = app.advance_lock();
        let mut state = lock.lock().await;
        assert!(matches!(
            app.reorg_to(&mut state, a2.header.block_hash).await,
            ReorgOutcome::NoChange
        ));
    }

    /// A fork-choice hook that always returns a fixed tip (a stand-in for
    /// GhostDAG's `select_tip` so the trigger path is testable in isolation).
    fn fork_choice_returning(hash: Hash) -> ForkChoice {
        Arc::new(move || Box::pin(async move { Some(hash) }))
    }

    /// STEP 3 UNBLOCK: prove the fork-above-tip wedge (a drain stalled at a fork
    /// with ≥2 selected-parent children) is drained by the step-4 fork-choice
    /// trigger inside `apply_received` — the resolution step 3 deferred.
    #[tokio::test]
    async fn fork_choice_reorg_drains_fork_above_tip_wedge() {
        let (exec, storage, _dir) = fresh();
        let mut app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let r = roots(3);
        let a1 = mk_block(1, Hash::default(), r[0]);
        let a2 = mk_block(2, a1.header.block_hash, r[1]);
        let b2 = mk_block_b(2, a1.header.block_hash, r[1]);
        let b3 = mk_block_b(3, b2.header.block_hash, r[2]);

        // Apply only a1; the tip is a1 @ 1.
        persist(&storage, &a1);
        assert!(matches!(app.apply_received(&a1).await, ApplyOutcome::Applied { .. }));

        // Both branches now present → the drain stalls at a1's fork (2 children).
        persist(&storage, &a2);
        persist(&storage, &b2);
        persist(&storage, &b3);

        // Without fork choice, the wedge is real: a2 can't be drained, tip stuck.
        assert!(matches!(app.apply_received(&a2).await, ApplyOutcome::Deferred));
        assert_eq!(app.applied_tip().await.height, 1, "wedged at the fork");

        // Attach fork choice selecting the heavier B tip; the trigger now reverts
        // the (no-op) fork point and re-applies the winning branch to b3.
        app.fork_choice = Some(fork_choice_returning(b3.header.block_hash));
        assert!(matches!(app.apply_received(&b3).await, ApplyOutcome::Applied { .. }));
        assert_eq!(
            app.applied_tip().await,
            AppliedTip { hash: b3.header.block_hash, height: 3 },
            "fork choice drained the wedge onto the winning branch"
        );
    }

    /// The fork-choice trigger also performs a true branch switch: applied tip on
    /// the A branch, fork choice selects the heavier B branch → reorg.
    #[tokio::test]
    async fn fork_choice_trigger_switches_to_heavier_branch() {
        let (exec, storage, _dir) = fresh();
        let mut app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let (_a1, _a2, _b2, b3) = setup_fork(&app, &storage).await; // tip = a2 @ 2
        app.fork_choice = Some(fork_choice_returning(b3.header.block_hash));

        // Any received block re-drives fork choice; deliver b3.
        app.apply_received(&b3).await;
        assert_eq!(
            app.applied_tip().await,
            AppliedTip { hash: b3.header.block_hash, height: 3 }
        );
    }

    /// F3: an equal-height competing sibling must still consult fork choice
    /// (pre-fix `height <= tip.height` short-circuited to AlreadyApplied and
    /// never reorged to a heavier equal-height branch).
    #[tokio::test]
    async fn equal_height_sibling_triggers_fork_choice_reorg() {
        let (exec, storage, _dir) = fresh();
        let mut app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let (_a1, _a2, b2, b3) = setup_fork(&app, &storage).await; // tip = a2 @ 2
        // b2 is an equal-height (2) sibling of the applied tip a2.
        app.fork_choice = Some(fork_choice_returning(b3.header.block_hash));
        // Delivering the equal-height sibling must NOT be dismissed as
        // AlreadyApplied — it drives fork choice, which reorgs to the heavier B.
        assert!(!matches!(
            app.apply_received(&b2).await,
            ApplyOutcome::AlreadyApplied
        ));
        assert_eq!(
            app.applied_tip().await,
            AppliedTip { hash: b3.header.block_hash, height: 3 },
            "equal-height sibling drove the reorg to the heavier branch"
        );
    }

    /// F1: a block the drain applied but the same call's fork-choice reorg then
    /// reverted must NOT be reported Applied (pre-fix used the stale pre-reorg
    /// `out.applied`).
    #[tokio::test]
    async fn drain_applied_then_reorged_away_is_not_reported_applied() {
        let (exec, storage, _dir) = fresh();
        let mut app = CanonicalApplicator::new(exec.clone(), storage.clone());
        let r = roots(3);
        let a1 = mk_block(1, Hash::default(), r[0]);
        let a2 = mk_block(2, a1.header.block_hash, r[1]);
        let b2 = mk_block_b(2, a1.header.block_hash, r[1]);
        let b3 = mk_block_b(3, b2.header.block_hash, r[2]);

        persist(&storage, &a1);
        app.apply_received(&a1).await; // tip = a1
        for b in [&a2, &b2, &b3] {
            persist(&storage, b);
        }
        // Fork choice prefers the heavier B branch.
        app.fork_choice = Some(fork_choice_returning(b3.header.block_hash));

        // Receiving a2 drains a1→a2, then fork choice reorgs it away to b3.
        // a2 is therefore NOT on the final applied chain → not Applied.
        let outcome = app.apply_received(&a2).await;
        assert!(
            !matches!(outcome, ApplyOutcome::Applied { .. }),
            "a2 was reverted by the reorg; must not report Applied (got {outcome:?})"
        );
        assert_eq!(
            app.applied_tip().await,
            AppliedTip { hash: b3.header.block_hash, height: 3 }
        );
    }

    /// STEP 5: the driver re-syncs the validator registry ONLY at snapshot
    /// boundaries S(E) = E·1000 − 200 (800, 1800, …) — the generalization that
    /// makes a receiving/reorging node load epoch membership, not just producers.
    #[tokio::test]
    async fn registry_sync_fires_only_at_snapshot_boundaries() {
        use std::sync::atomic::AtomicUsize;
        let (exec, storage, _dir) = fresh();
        let hits: Arc<std::sync::Mutex<Vec<u64>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let hits2 = hits.clone();
        let calls2 = calls.clone();
        let mut app = CanonicalApplicator::new(exec, storage);
        app.registry_sync = Some(Arc::new(move |h| {
            hits2.lock().expect("lock").push(h);
            calls2.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(3usize) })
        }));

        // Non-boundary heights: no sync.
        for h in [1u64, 500, 799, 801, 1000] {
            app.maybe_sync_registry(h).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0, "no sync off a boundary");

        // Boundaries S(1)=800, S(2)=1800: sync fires.
        app.maybe_sync_registry(800).await;
        app.maybe_sync_registry(1800).await;
        assert_eq!(*hits.lock().expect("lock"), vec![800, 1800]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    const CAROL: [u8; 20] = [0xCC; 20];
    const DAVE: [u8; 20] = [0xDD; 20];

    /// A store-backed executor sharing `storage`'s durable state store, so
    /// `apply_block` actually persists and a "restart" (a fresh executor over the
    /// same store, cold cache) reads the durable truth.
    fn store_backed(storage: &Arc<StorageManager>) -> Arc<Executor> {
        Arc::new(Executor::with_storage(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
        ))
    }

    /// HIGH-2: after a reorg, the DURABLE store must match the new branch — proven
    /// by reading a fresh (cold-cache) executor over the same store. Includes an
    /// account CREATED on the abandoned branch, which must be deleted from the store.
    #[tokio::test]
    async fn reorg_reconciles_durable_store_and_survives_restart() {
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let follower = store_backed(&storage);
        follower.set_balance(&Address(ALICE), U256::from(FUND));
        follower.persist_state_changes().await.expect("persist genesis");
        let mut app = CanonicalApplicator::new(follower.clone(), storage.clone());

        // Shared block a1 (ALICE→DAVE), then A branch a2 (ALICE→BOB).
        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pa.set_balance(&Address(ALICE), U256::from(FUND));
        let a1 = produce(&pa, Hash::default(), 1, VRF_OUT, vec![transfer(ALICE, DAVE, 1_000, 0)]).await;
        let a2 = produce(&pa, a1.header.block_hash, 2, VRF_OUT, vec![transfer(ALICE, BOB, 1_000, 1)]).await;
        persist(&storage, &a1);
        app.apply_received(&a1).await;
        persist(&storage, &a2);
        app.apply_received(&a2).await;
        assert_eq!(follower.get_balance(&Address(BOB)), U256::from(1_000u64), "A branch funded BOB");

        // Heavier B branch off a1: b2, b3 (ALICE→CAROL). BOB is never touched on B.
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pb.set_balance(&Address(ALICE), U256::from(FUND));
        let _b1 = produce(&pb, Hash::default(), 1, VRF_OUT, vec![transfer(ALICE, DAVE, 1_000, 0)]).await;
        let vrf_b = [0x5B; 32];
        let b2 = produce(&pb, a1.header.block_hash, 2, vrf_b, vec![transfer(ALICE, CAROL, 1_000, 1)]).await;
        let b3 = produce(&pb, b2.header.block_hash, 3, vrf_b, vec![transfer(ALICE, CAROL, 1_000, 2)]).await;
        persist(&storage, &b2);
        persist(&storage, &b3);

        app.fork_choice = Some(fork_choice_returning(b3.header.block_hash));
        app.apply_received(&b3).await;
        assert_eq!(app.applied_tip().await.height, 3, "reorged to B");

        // Simulated restart: a brand-new executor over the SAME store, cold cache.
        let restarted = store_backed(&storage);
        assert_eq!(restarted.get_balance(&Address(CAROL)), U256::from(2_000u64), "B branch CAROL persisted");
        assert_eq!(restarted.get_balance(&Address(DAVE)), U256::from(1_000u64), "shared DAVE persisted");
        assert_eq!(
            restarted.get_balance(&Address(BOB)),
            U256::zero(),
            "BOB (created on the abandoned A branch) must be deleted from the store"
        );
        assert_eq!(
            restarted.get_balance(&Address(ALICE)),
            follower.get_balance(&Address(ALICE)),
            "ALICE durable balance matches in-memory after reorg"
        );
        // Reward accounts (credited via set_balance, which defers under apply):
        // the store must reflect the B branch's rewards, not A's.
        assert_eq!(
            restarted.get_balance(&Address(CB)),
            follower.get_balance(&Address(CB)),
            "coinbase reward durable balance matches in-memory after reorg"
        );
        assert_eq!(
            restarted.get_balance(&Address(TREASURY_ADDR)),
            follower.get_balance(&Address(TREASURY_ADDR)),
            "treasury reward durable balance matches after reorg"
        );
    }

    /// HIGH-2 (abort path): a reorg that aborts on a bad block must leave the
    /// durable store on the OLD branch — proven across a restart.
    #[tokio::test]
    async fn aborted_reorg_leaves_durable_store_on_old_branch() {
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let follower = store_backed(&storage);
        follower.set_balance(&Address(ALICE), U256::from(FUND));
        follower.persist_state_changes().await.expect("persist genesis");
        let mut app = CanonicalApplicator::new(follower.clone(), storage.clone());

        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pa.set_balance(&Address(ALICE), U256::from(FUND));
        let a1 = produce(&pa, Hash::default(), 1, VRF_OUT, vec![transfer(ALICE, BOB, 1_000, 0)]).await;
        let a2 = produce(&pa, a1.header.block_hash, 2, VRF_OUT, vec![transfer(ALICE, BOB, 1_000, 1)]).await;
        persist(&storage, &a1);
        app.apply_received(&a1).await;
        persist(&storage, &a2);
        app.apply_received(&a2).await; // store has A: BOB = 2000

        // A B branch whose valid b2 is followed by a bad-root b3.
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pb.set_balance(&Address(ALICE), U256::from(FUND));
        let _b1 = produce(&pb, Hash::default(), 1, VRF_OUT, vec![transfer(ALICE, BOB, 1_000, 0)]).await;
        let vrf_b = [0x5B; 32];
        let b2 = produce(&pb, a1.header.block_hash, 2, vrf_b, vec![transfer(ALICE, CAROL, 1_000, 1)]).await;
        let b3_bad = mk_block_txs(3, b2.header.block_hash, Hash::new([0xFF; 32]), vrf_b, vec![transfer(ALICE, CAROL, 1_000, 2)]);
        persist(&storage, &b2);
        persist(&storage, &b3_bad);

        app.fork_choice = Some(fork_choice_returning(b3_bad.header.block_hash));
        app.apply_received(&b3_bad).await; // reorg reapplies b2 in-memory, b3_bad fails → abort

        // Applied tip stayed on A; the durable store was never written during reapply.
        assert_eq!(app.applied_tip().await, AppliedTip { hash: a2.header.block_hash, height: 2 });
        let restarted = store_backed(&storage);
        assert_eq!(restarted.get_balance(&Address(BOB)), U256::from(2_000u64), "store still on A branch");
        assert_eq!(restarted.get_balance(&Address(CAROL)), U256::zero(), "aborted B branch never persisted");
        // Reward accounts must not carry the aborted B reapply's credits (set_balance
        // deferred under apply → nothing persisted during the aborted reapply).
        assert_eq!(
            restarted.get_balance(&Address(CB)),
            follower.get_balance(&Address(CB)),
            "coinbase reward store matches A branch after abort"
        );
    }

    /// Review finding E (backward-compat side): a DIRECT `set_code` (genesis
    /// init, RPC — no apply in progress, so `defer_persist` is off) still
    /// persists account + code eagerly, exactly as before. The deferral only
    /// engages inside `apply_block`.
    #[tokio::test]
    async fn direct_set_code_persists_eagerly() {
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let exec = store_backed(&storage);
        let addr = Address([0xCD; 20]);
        let code = vec![0x60u8, 0x2a, 0x60, 0x00, 0x52];

        exec.set_code(&addr, code.clone());
        let code_hash = exec.get_code_hash(&addr);
        // Eagerly durable (no persist_state_changes call needed).
        assert!(storage.state.get_account(&addr).expect("get").is_some(), "account persisted eagerly");
        assert_eq!(storage.state.get_code(&code_hash).expect("get"), Some(code), "code persisted eagerly");
    }

    /// With no registry-sync attached the hook is inert (steps 2–4 unaffected).
    #[tokio::test]
    async fn registry_sync_absent_is_noop() {
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec, storage);
        app.maybe_sync_registry(800).await; // must not panic / do anything
    }

    // ========================================================================
    // STEP 6 — two-node divergence harness.
    //
    // A "producer" executor builds a chain exactly as node/src/producer.rs does
    // (set block context → execute txs → credit the deterministic basic reward →
    // state_root → seal a v2 header). A "follower" — a CanonicalApplicator over an
    // INDEPENDENT executor + store — applies each block via apply_received. The
    // harness asserts the follower reproduces the producer's state_root at EVERY
    // height (invariant I2), rejects a corrupted block (I3), and CONVERGES to the
    // producer after a reorg. Uses real value-transfer transactions (not just
    // rewards) so the full execute→verify pipeline is exercised across nodes.
    // ========================================================================

    const ALICE: [u8; 20] = [0xAA; 20];
    const BOB: [u8; 20] = [0xBB; 20];
    const FUND: u128 = 1_000_000_000_000_000_000; // 1e18 wei

    /// Address → PublicKey embedding that `Address::from_public_key` round-trips
    /// back to the same address (the EVM-address shape the node uses for tx.from).
    fn embedded(addr: [u8; 20]) -> PublicKey {
        let mut b = [0u8; 32];
        b[..20].copy_from_slice(&addr);
        PublicKey::new(b)
    }

    /// A value-transfer transaction from `from` to `to` (executor trusts tx.from).
    fn transfer(from: [u8; 20], to: [u8; 20], value: u128, nonce: u64) -> Transaction {
        Transaction {
            nonce,
            from: embedded(from),
            to: Some(embedded(to)),
            value,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            signature: Signature::new([1; 64]),
            chain_id: Some(40204),
            ..Default::default()
        }
    }

    /// Build a v2 block carrying `txs` (state_root supplied by the producer).
    fn mk_block_txs(
        height: u64,
        parent: Hash,
        state_root: Hash,
        vrf: [u8; 32],
        txs: Vec<Transaction>,
    ) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(CB)
            .timestamp(1000)
            .vrf_reveal(VrfProof { proof: vec![], output: Hash::new(vrf) })
            .transactions(txs)
            .state_root(state_root)
            .build_unhashed();
        b.header.block_hash = b.compute_hash();
        b
    }

    /// Produce a block on `exec` the way node/src/producer.rs does under v2:
    /// set block context → execute txs → credit the basic reward → compute the
    /// final state_root → seal. Advances `exec` to the post-block state.
    async fn produce(
        exec: &Executor,
        parent: Hash,
        height: u64,
        vrf: [u8; 32],
        txs: Vec<Transaction>,
    ) -> Block {
        exec.set_block_context(BlockContext {
            coinbase: CB,
            prevrandao: vrf,
            block_hashes: std::collections::HashMap::new(),
        });
        // Reward calc reads only header.height + txs — a provisional block suffices.
        let provisional = mk_block_txs(height, parent, Hash::default(), vrf, txs.clone());
        for tx in &txs {
            exec.execute_transaction(&provisional, tx)
                .await
                .expect("producer tx must execute");
        }
        let reward = RewardCalculator::new(canonical_reward_config()).calculate_reward(&provisional);
        for (addr, amt) in [
            (Address(CB), reward.validator_reward),
            (Address(TREASURY_ADDR), reward.treasury_reward),
        ] {
            if amt > U256::zero() {
                let bal = exec.get_balance(&addr);
                exec.set_balance(&addr, bal + amt);
            }
        }
        let root = exec.calculate_state_root();
        mk_block_txs(height, parent, root, vrf, txs)
    }

    /// A funded producer executor + a funded follower (applicator over an
    /// independent exec/store). Both start from the identical genesis state.
    fn two_nodes() -> (Arc<Executor>, CanonicalApplicator, Arc<Executor>, Arc<StorageManager>, tempfile::TempDir)
    {
        let producer = Arc::new(Executor::new(Arc::new(StateDB::new())));
        producer.set_balance(&Address(ALICE), U256::from(FUND));

        let (follower, storage, dir) = fresh();
        follower.set_balance(&Address(ALICE), U256::from(FUND));
        // Construct the applicator AFTER funding so its genesis base snapshot
        // reflects the shared funded state.
        let app = CanonicalApplicator::new(follower.clone(), storage.clone());
        (producer, app, follower, storage, dir)
    }

    #[tokio::test]
    async fn two_node_state_root_parity_with_transactions() {
        let (producer, app, follower, storage, _dir) = two_nodes();

        let mut parent = Hash::default();
        for h in 1..=3u64 {
            // Producer builds block h with a transfer alice → bob.
            let tx = transfer(ALICE, BOB, 1_000, h - 1);
            let block = produce(&producer, parent, h, VRF_OUT, vec![tx]).await;
            let producer_root = block.state_root;

            // Follower ingests it exactly as the receive path does.
            persist(&storage, &block);
            assert!(
                matches!(app.apply_received(&block).await, ApplyOutcome::Applied { .. }),
                "follower must apply block {h}"
            );

            // I2: the follower reproduced the producer's state root at this height.
            assert_eq!(
                follower.calculate_state_root(),
                producer_root,
                "state root parity at height {h}"
            );
            parent = block.header.block_hash;
        }

        // Balances agree across the two independent executors.
        assert_eq!(
            producer.get_balance(&Address(BOB)),
            follower.get_balance(&Address(BOB))
        );
        assert_eq!(follower.get_balance(&Address(BOB)), U256::from(3_000u64));
        assert_eq!(app.applied_tip().await.height, 3);
    }

    #[tokio::test]
    async fn follower_rejects_corrupted_state_root() {
        let (producer, mut app, follower, storage, _dir) = two_nodes();

        // The genuine block, and a malicious variant flipping the committed root.
        // (Distinct VRF so it is a genuine sibling, not the same block hash.)
        let good = produce(&producer, Hash::default(), 1, VRF_OUT, vec![transfer(ALICE, BOB, 1_000, 0)]).await;
        let corrupt = mk_block_txs(
            1,
            Hash::default(),
            Hash::new([0xFF; 32]),
            [0x5B; 32],
            vec![transfer(ALICE, BOB, 1_000, 0)],
        );
        let root_before = follower.calculate_state_root();

        // The corrupt block is admitted + persisted (structure/sig pass), then
        // execute-on-receive verifies its state root and REJECTS it.
        persist(&storage, &corrupt);
        assert!(matches!(
            app.apply_received(&corrupt).await,
            ApplyOutcome::Rejected(_)
        ));

        // I3: rejected block leaves the follower byte-identical + tip unmoved.
        assert_eq!(follower.calculate_state_root(), root_before);
        assert_eq!(app.applied_tip().await.height, 0);
        assert_eq!(follower.get_balance(&Address(BOB)), U256::zero());

        // Fork choice routes around the rejected block to the valid sibling
        // (which forks at genesis): the follower reorgs onto it and converges.
        persist(&storage, &good);
        app.fork_choice = Some(fork_choice_returning(good.header.block_hash));
        assert!(matches!(app.apply_received(&good).await, ApplyOutcome::Applied { .. }));
        assert_eq!(follower.calculate_state_root(), good.state_root);
        assert_eq!(follower.get_balance(&Address(BOB)), U256::from(1_000u64));
    }

    #[tokio::test]
    async fn two_nodes_converge_after_reorg() {
        let (producer, mut app, follower, storage, _dir) = two_nodes();

        // Shared block a1 (both nodes apply it).
        let a1 = produce(&producer, Hash::default(), 1, VRF_OUT, vec![transfer(ALICE, BOB, 1_000, 0)]).await;
        persist(&storage, &a1);
        app.apply_received(&a1).await;

        // A branch continues on the producer's a1 state: a2.
        let a2 = produce(&producer, a1.header.block_hash, 2, VRF_OUT, vec![transfer(ALICE, BOB, 1_000, 1)]).await;
        persist(&storage, &a2);
        app.apply_received(&a2).await;
        assert_eq!(follower.calculate_state_root(), a2.state_root, "follower on the A branch");

        // Now a heavier B branch appears, forking at a1. Rebuild the producer's
        // state to a1 (fresh exec) and produce b2, b3 with a DISTINCT vrf.
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pb.set_balance(&Address(ALICE), U256::from(FUND));
        let b1 = produce(&pb, Hash::default(), 1, VRF_OUT, vec![transfer(ALICE, BOB, 1_000, 0)]).await;
        assert_eq!(b1.header.block_hash, a1.header.block_hash, "b1 == a1 (shared)");
        let vrf_b = [0x5B; 32];
        let b2 = produce(&pb, a1.header.block_hash, 2, vrf_b, vec![transfer(ALICE, BOB, 2_000, 1)]).await;
        let b3 = produce(&pb, b2.header.block_hash, 3, vrf_b, vec![transfer(ALICE, BOB, 2_000, 2)]).await;
        persist(&storage, &b2);
        persist(&storage, &b3);

        // Follower's fork choice now selects the B tip → it reorgs and converges.
        app.fork_choice = Some(fork_choice_returning(b3.header.block_hash));
        app.apply_received(&b3).await;

        assert_eq!(
            app.applied_tip().await,
            AppliedTip { hash: b3.header.block_hash, height: 3 }
        );
        // I2 after reorg: follower state == producer's B-branch state at the tip.
        assert_eq!(follower.calculate_state_root(), b3.state_root, "converged to B branch");
        assert_eq!(follower.get_balance(&Address(BOB)), pb.get_balance(&Address(BOB)));
    }
}
