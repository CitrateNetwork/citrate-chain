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

/// VALIDATOR-S1 §R' policy-only resync hook: given a snapshot-boundary height,
/// re-materialize ONLY the reward-policy half of the epoch snapshot against the
/// executor's current state (no selector mutation, no durable persist), returning
/// `Err` on a materialization failure. Used by `reorg_to` to keep the reward policy
/// current DURING the in-memory branch reapply (the reapplied blocks' state roots
/// are settled against it) while the selector stays deferred + abort-safe. Wired
/// from the SAME `RegistrySync` as `RegistrySyncHook`.
type RegistryPolicyResyncHook =
    Arc<dyn Fn(u64) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync>;

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
    /// VALIDATOR-S1 §R' (reorg): the policy-only resync used INSIDE the reorg
    /// reapply loop at each crossed S(E), so the reapplied blocks' state roots are
    /// settled against the epoch-correct reward policy. Wired together with
    /// `registry_sync`; `None` disables it. See [`RegistryPolicyResyncHook`].
    registry_policy_resync: Option<RegistryPolicyResyncHook>,
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
            registry_policy_resync: None,
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
        let rs_full = registry_sync.clone();
        self.registry_sync = Some(Arc::new(move |height| {
            let rs = rs_full.clone();
            Box::pin(async move { rs.sync_for_snapshot(height).await })
        }));
        // The policy-only resync used inside `reorg_to`'s reapply loop, from the
        // SAME RegistrySync so it reads byte-identical policy inputs.
        self.registry_policy_resync = Some(Arc::new(move |height| {
            let rs = registry_sync.clone();
            Box::pin(async move { rs.resync_policy_only(height).await })
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
        // VALIDATOR-S1 §R': the reward-policy cell is NOT part of `state_snapshot`,
        // yet the in-loop reapply below re-materializes it at each crossed S(E). Capture
        // it here so EVERY abort arm can restore it — a failed reorg must never leave the
        // shared policy mutated (it would fork the next block the producer/receiver settles).
        let pre_policy = self.executor.capture_reward_policy();

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

        // Revert IN-MEMORY state to the fork point. `base_snapshot` is RETAINED
        // (cloned into `state_restore`) because it is also the reconcile baseline for
        // both the success (forward) and abort (restore) store writes below.
        let base_snapshot = match state.snapshots.get(&fork.height) {
            Some((_, snap)) => snap.clone(),
            None => {
                return ReorgOutcome::Rejected(format!(
                    "reorg fork point snapshot missing at height {}",
                    fork.height
                ));
            }
        };
        self.executor.state_restore(base_snapshot.clone());

        // REORG-STORE-FIX (consensus fork remediation). The durable store is a FLAT
        // latest-state KV: an account/slot ABSENT from the in-memory fork-point working
        // set falls THROUGH to the store on read (`Executor::get_balance`/`get_nonce`/
        // `get_code_hash` and the REVM adapter `basic`/`storage`). Immediately after the
        // in-memory revert above, the store STILL holds the LOSING branch (`pre_state`),
        // so a reapply read of any account the fork point never resident-cached but the
        // losing branch persisted would return the losing value — settling the winning
        // block against stale state → state-root mismatch → the reorg ABORTS and the
        // node REJECTS a valid heavier branch its peers accepted (a partition/fork). This
        // is generic (it also bites NORMAL-TX reorgs), and §R' registry credits trigger
        // it reliably (the registry is credited on both branches but untouched at the
        // fork point).
        //
        // Fix: revert the durable store to the FORK POINT *before* reapply, so every
        // read-through resolves against fork-point state — uniformly for balance / nonce
        // / code / storage. `reconcile_store_from(baseline)` writes the diff from
        // `baseline` to CURRENT in-memory state; with memory just restored to the fork
        // point and the store == `pre_state`, `reconcile_store_from(&pre_state)` rewrites
        // the store from the losing branch back to the fork point (put changed accounts
        // /slots at their fork-point value, delete losing-branch-created ones). On
        // SUCCESS the store is reconciled forward to the winning branch (baseline = the
        // fork point); on EVERY abort it is reconciled back to `pre_state` — so an
        // aborted reorg still leaves the store byte-identical to before the attempt
        // (HIGH-2 / invariant I2). Only committed branch states (fork point / pre_state /
        // winning) are ever written — never an un-rollback-able candidate.
        if let Err(e) = self.executor.reconcile_store_from(&pre_state) {
            // The account+storage write is a single atomic batch (unchanged on failure).
            // Restore in-memory state + the §R' policy cell and best-effort re-reconcile
            // the store back to pre_state, then decline the reorg — world state is left
            // as before the attempt (invariant I3).
            self.executor.state_restore(pre_state.clone());
            self.executor.restore_reward_policy(pre_policy.clone());
            let _ = self.executor.reconcile_store_from(&base_snapshot);
            warn!(
                "execute-on-receive: reorg to {} aborted — could not revert store to fork point {} @ {}: {} (reverted to {})",
                new_tip, fork.hash, fork.height, e, pre_tip.hash
            );
            return ReorgOutcome::Rejected(format!(
                "reorg store-revert to fork point failed at height {}: {e}",
                fork.height
            ));
        }

        // Re-apply the winning branch forward IN-MEMORY ONLY (`apply_block_no_persist`).
        // Per-block writes are still NOT persisted (an abort must leave nothing of the
        // candidate branch on disk); the store — currently AT THE FORK POINT — is
        // reconciled ONCE, to the winning branch, only after the whole reorg succeeds.
        // Snapshots commit to the ring on success only.
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
                    // VALIDATOR-S1 §R': if this reapplied block is a snapshot boundary
                    // S(E), re-materialize the REWARD-POLICY half NOW (against the just-
                    // reapplied new-branch state), so every subsequent reapplied block's
                    // state root is settled against the epoch-E policy — mirroring the
                    // forward path. The selector stays deferred (post-commit) to remain
                    // abort-safe. A materialization failure is treated as a bad reapply.
                    if crate::registry_sync::snapshot_epoch_at(h).is_some() {
                        if let Some(hook) = &self.registry_policy_resync {
                            if let Err(e) = hook(h).await {
                                self.executor.state_restore(pre_state.clone());
                                self.executor.restore_reward_policy(pre_policy.clone());
                                // The store was reverted to the fork point before reapply;
                                // reconcile it back to pre_state so the abort leaves the
                                // durable store byte-identical to before the reorg (I2).
                                // memory == pre_state, store == fork point (== base_snapshot).
                                if let Err(re) = self.executor.reconcile_store_from(&base_snapshot) {
                                    warn!(
                                        "execute-on-receive: reorg to {} abort — store restore to pre_state failed: {re}",
                                        new_tip
                                    );
                                }
                                warn!(
                                    "execute-on-receive: reorg to {} aborted — reward-policy resync at S({}) failed: {} (reverted to {})",
                                    new_tip, h, e, pre_tip.hash
                                );
                                return ReorgOutcome::Rejected(format!(
                                    "reorg reward-policy resync failed at height {h}: {e}"
                                ));
                            }
                        }
                    }
                }
                Err(e) => {
                    // Abort: byte-exact in-memory restore (incl. dirty-code, captured
                    // in the snapshot); the re-apply did NOT persist per-block, so the
                    // ring/tip/pointer never moved (review finding E). Restore the §R'
                    // policy cell (mutated in-loop above), then reconcile the durable
                    // store — reverted to the fork point before reapply — back to
                    // pre_state, so a failed reorg leaves BOTH in-memory state AND the
                    // store byte-identical to before the attempt (invariants I2/I3).
                    self.executor.state_restore(pre_state);
                    self.executor.restore_reward_policy(pre_policy.clone());
                    // memory == pre_state, store == fork point (== base_snapshot).
                    if let Err(re) = self.executor.reconcile_store_from(&base_snapshot) {
                        warn!(
                            "execute-on-receive: reorg to {} abort — store restore to pre_state failed: {re}",
                            new_tip
                        );
                    }
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

        // Success. The store currently reflects the FORK POINT (reverted before
        // reapply); reconcile it FORWARD to the now-current winning-branch state —
        // writing the account+storage diff and deleting abandoned-created accounts — so
        // RocksDB matches memory and a restart-after-reorg hydrates correctly. Baseline
        // is `base_snapshot` (the fork point == what the store now holds), NOT pre_state.
        if let Err(e) = self.executor.reconcile_store_from(&base_snapshot) {
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

    // ========================================================================
    // VALIDATOR-S1 §R' — CROSS-BOUNDARY CROSS-POLICY REORG (test (b)).
    //
    // Store-backed. The follower applies branch A across the snapshot boundary
    // S(1)=800 under reward policy_A (share 2500 bps), then reorgs to a heavier
    // branch B whose post-boundary blocks were produced under policy_B (5000 bps).
    // The in-loop policy re-sync (fix #2) must re-materialize the reward policy at
    // S(1) DURING the reorg reapply so branches 801'/802' settle with policy_B and
    // reproduce B's roots; without it the stale policy_A would mis-settle and the
    // reorg would be REJECTED (root mismatch) — so this test fails if fix #2 regresses.
    // Cross-policy is scripted by a state-marker hook (CAROL is a B-only recipient).
    // ========================================================================
    const PROPOSER: [u8; 32] = [0x5A; 32];
    const REG: [u8; 20] = [0x99; 20];

    fn rprime_policy(bps: u64) -> citrate_execution::block_rewards::EpochRewardPolicy {
        let mut staker_of = std::collections::HashMap::new();
        staker_of.insert(PROPOSER, CB); // coinbase == registered staker (§R' 3c)
        citrate_execution::block_rewards::EpochRewardPolicy {
            epoch: 1,
            snapshot_height: 800,
            activation_height: 800,
            registry: REG,
            reward_minter: citrate_execution::block_rewards::REWARD_MINTER_ADDRESS,
            priority_fee_share_bps: bps,
            staker_of,
        }
    }

    /// A type-2 (EIP-1559) priority transfer: over_base=900, tip cap=250 → tip 250.
    fn prio_tx(from: [u8; 20], to: [u8; 20], nonce: u64, seed: u8) -> Transaction {
        let base = citrate_execution::block_rewards::CANONICAL_BASE_FEE_PER_GAS;
        let mut hb = [0u8; 32];
        hb[0] = seed;
        let mut tx = Transaction {
            hash: Hash::new(hb),
            nonce,
            from: embedded(from),
            to: Some(embedded(to)),
            value: 500,
            gas_limit: 100_000,
            gas_price: base + 900,
            signature: Signature::new([1; 64]),
            chain_id: Some(40204),
            eth_tx_type: 2,
            max_fee_per_gas: Some(base + 900),
            max_priority_fee_per_gas: Some(250),
            ..Default::default()
        };
        tx.determine_type();
        tx
    }

    /// Seal a v2 §R' block committing proposer + coinbase + canonical base fee.
    fn seal_rprime(height: u64, parent: Hash, root: Hash, vrf: [u8; 32], txs: Vec<Transaction>) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(CB)
            .proposer(PublicKey::new(PROPOSER))
            .timestamp(1000)
            .base_fee_per_gas(citrate_execution::block_rewards::CANONICAL_BASE_FEE_PER_GAS)
            .vrf_reveal(VrfProof { proof: vec![], output: Hash::new(vrf) })
            .transactions(txs)
            .state_root(root)
            .build_unhashed();
        b.header.block_hash = b.compute_hash();
        b
    }

    /// Produce a §R' block exactly as `apply_block_inner` settles it (set ctx →
    /// execute txs → settle basic+§R' rewards → root), on `exec`'s current policy.
    async fn produce_rprime(exec: &Executor, parent: Hash, height: u64, vrf: [u8; 32], txs: Vec<Transaction>) -> Block {
        exec.set_block_context(BlockContext {
            coinbase: CB,
            prevrandao: vrf,
            block_hashes: std::collections::HashMap::new(),
        });
        let provisional = seal_rprime(height, parent, Hash::default(), vrf, txs.clone());
        let mut receipts = Vec::new();
        for tx in &txs {
            receipts.push(exec.execute_transaction(&provisional, tx).await.expect("producer tx executes"));
        }
        let reward = RewardCalculator::new(canonical_reward_config()).calculate_reward(&provisional);
        let basic = [
            (Address(CB), reward.validator_reward),
            (Address(TREASURY_ADDR), reward.treasury_reward),
        ];
        exec.settle_block_rewards(
            height,
            CB,
            PROPOSER,
            citrate_execution::block_rewards::CANONICAL_BASE_FEE_PER_GAS,
            &txs,
            &receipts,
            &basic,
        )
        .await
        .expect("producer §R' settle");
        let root = exec.calculate_state_root();
        seal_rprime(height, parent, root, vrf, txs)
    }

    /// A cross-policy hook: reads a state MARKER (CAROL, a B-only recipient) to
    /// decide the epoch — 5000 bps once branch B's boundary block has credited
    /// CAROL, else 2500. Simulates the registry-contract state differing per branch.
    fn cross_policy_hook(exec: Arc<Executor>) -> impl Fn() {
        move || {
            let bps = if exec.get_balance(&Address(CAROL)) > U256::zero() { 5000 } else { 2500 };
            *exec.reward_policy_handle().write() = Some(rprime_policy(bps));
        }
    }

    /// Store-backed follower seeded at height 798, then advanced through a SHARED
    /// applied block s799 (height 799) + a losing branch A (empty blocks 800, 801).
    /// The fork point is s799 — an APPLIED block whose ring snapshot captures the
    /// basic-reward accounts (coinbase, treasury) — so the reorg reapply reads their
    /// correct fork values from memory (no stale store read-through). Branch A carries
    /// NO priority fees, so the durable store holds NO §R' (registry) state before the
    /// winning branch B vests — B reapply reads registry = 0 cleanly. Returns the wired
    /// applicator, follower, storage, and the s799 fork hash.
    async fn setup_cross_policy() -> (
        CanonicalApplicator,
        Arc<Executor>,
        Arc<StorageManager>,
        Hash,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let follower = store_backed(&storage);
        follower.set_balance(&Address(ALICE), U256::from(FUND));
        follower.persist_state_changes().await.expect("persist genesis");
        let a798 = seal_rprime(798, Hash::default(), Hash::default(), VRF_OUT, vec![]);
        persist(&storage, &a798);
        storage.blocks.put_applied_tip(&a798.header.block_hash, 798).expect("seed tip");
        follower.set_validator_activation_height(800);
        *follower.reward_policy_handle().write() = Some(rprime_policy(2500)); // epoch E-1

        let mut app = CanonicalApplicator::new(follower.clone(), storage.clone());
        let h_full = cross_policy_hook(follower.clone());
        app.registry_sync = Some(Arc::new(move |_h| {
            h_full();
            Box::pin(async { Ok(1usize) })
        }));
        let h_pol = cross_policy_hook(follower.clone());
        app.registry_policy_resync = Some(Arc::new(move |_h| {
            h_pol();
            Box::pin(async { Ok(()) })
        }));

        // Shared block s799 + losing branch A (empty → basic rewards only, no §R' vest).
        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pa.set_balance(&Address(ALICE), U256::from(FUND));
        pa.set_validator_activation_height(800);
        *pa.reward_policy_handle().write() = Some(rprime_policy(2500));
        let s799 = produce_rprime(&pa, a798.header.block_hash, 799, VRF_OUT, vec![]).await;
        let a800 = produce_rprime(&pa, s799.header.block_hash, 800, VRF_OUT, vec![]).await;
        let a801 = produce_rprime(&pa, a800.header.block_hash, 801, VRF_OUT, vec![]).await;

        persist(&storage, &s799);
        assert!(matches!(app.apply_received(&s799).await, ApplyOutcome::Applied { .. }), "s799");
        persist(&storage, &a800);
        assert!(matches!(app.apply_received(&a800).await, ApplyOutcome::Applied { .. }), "a800");
        persist(&storage, &a801);
        assert!(matches!(app.apply_received(&a801).await, ApplyOutcome::Applied { .. }), "a801");
        assert_eq!(follower.calculate_state_root(), a801.state_root, "follower on branch A");
        assert_eq!(follower.get_balance(&Address(REG)), U256::zero(), "branch A vested no §R' share");
        (app, follower, storage, s799.header.block_hash, dir)
    }

    /// Produce branch B off `s799`: b800 (policy 2500, crosses S(1)), then b801/b802
    /// under policy 5000 — each a priority-fee transfer ALICE → CAROL (the B marker).
    async fn produce_branch_b(s799: Hash) -> (Block, Block, Block) {
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pb.set_balance(&Address(ALICE), U256::from(FUND));
        pb.set_validator_activation_height(800);
        *pb.reward_policy_handle().write() = Some(rprime_policy(2500));
        // Replay the shared s799 so pb's state matches the fork point.
        let _s = produce_rprime(&pb, Hash::default(), 799, VRF_OUT, vec![]).await;
        let vrf_b = [0x5B; 32];
        let b800 = produce_rprime(&pb, s799, 800, vrf_b, vec![prio_tx(ALICE, CAROL, 0, 0xB0)]).await;
        *pb.reward_policy_handle().write() = Some(rprime_policy(5000)); // epoch-E governs post-boundary
        let b801 = produce_rprime(&pb, b800.header.block_hash, 801, vrf_b, vec![prio_tx(ALICE, CAROL, 1, 0xB1)]).await;
        let b802 = produce_rprime(&pb, b801.header.block_hash, 802, vrf_b, vec![prio_tx(ALICE, CAROL, 2, 0xB2)]).await;
        (b800, b801, b802)
    }

    #[tokio::test]
    async fn reorg_across_snapshot_reproduces_cross_policy_branch() {
        let (mut app, follower, storage, s799, _dir) = setup_cross_policy().await;
        let (b800, b801, b802) = produce_branch_b(s799).await;

        persist(&storage, &b800);
        persist(&storage, &b801);
        persist(&storage, &b802);
        app.fork_choice = Some(fork_choice_returning(b802.header.block_hash));
        let outcome = app.apply_received(&b802).await;
        assert!(matches!(outcome, ApplyOutcome::Applied { .. }), "b802 outcome: {outcome:?}");

        // Converged to B: only possible if the in-loop policy re-sync flipped 2500→5000
        // at S(1) so 801'/802' settled with policy_B and reproduced B's roots.
        assert_eq!(
            app.applied_tip().await,
            AppliedTip { hash: b802.header.block_hash, height: 802 }
        );
        assert_eq!(follower.calculate_state_root(), b802.state_root, "converged to cross-policy branch B");
        // The final policy cell is epoch-E (5000) — the post-reorg deferred full sync.
        assert_eq!(
            follower.reward_policy_handle().read().as_ref().map(|p| p.priority_fee_share_bps),
            Some(5000)
        );

        // Cold-cache (restart) read: the durable store reflects the B branch's §R'
        // vesting — the registry balance (and the B-only CAROL recipient) match the
        // in-memory follower. (vestedRewards/emittedInEpoch is the ValidatorRegistry
        // contract's own storage, forge-tested; the registry here is codeless so its
        // BALANCE is the on-chain vesting proxy at this layer.)
        let restarted = store_backed(&storage);
        assert!(follower.get_balance(&Address(REG)) > U256::zero(), "branch B vested a positive §R' share");
        assert_eq!(
            restarted.get_balance(&Address(REG)),
            follower.get_balance(&Address(REG)),
            "durable registry (vested-share) balance matches after cross-policy reorg"
        );
        assert_eq!(
            restarted.get_balance(&Address(CAROL)),
            follower.get_balance(&Address(CAROL)),
            "durable B-branch recipient balance matches"
        );
    }

    #[tokio::test]
    async fn aborted_cross_policy_reorg_restores_reward_policy() {
        let (mut app, follower, storage, s799, _dir) = setup_cross_policy().await;
        let policy_before = follower.reward_policy_handle().read().as_ref().map(|p| p.priority_fee_share_bps);
        assert_eq!(policy_before, Some(2500));

        // Branch B: valid b800 (crosses S(1) → in-loop resync flips to 5000), then a
        // BAD b801 (bogus root) that aborts the reorg AFTER the policy was mutated.
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pb.set_balance(&Address(ALICE), U256::from(FUND));
        pb.set_validator_activation_height(800);
        *pb.reward_policy_handle().write() = Some(rprime_policy(2500));
        let _s = produce_rprime(&pb, Hash::default(), 799, VRF_OUT, vec![]).await;
        let vrf_b = [0x5B; 32];
        let b800 = produce_rprime(&pb, s799, 800, vrf_b, vec![prio_tx(ALICE, CAROL, 0, 0xB0)]).await;
        let b801_bad = seal_rprime(801, b800.header.block_hash, Hash::new([0xFF; 32]), vrf_b, vec![prio_tx(ALICE, CAROL, 1, 0xB1)]);
        persist(&storage, &b800);
        persist(&storage, &b801_bad);

        let a_tip = app.applied_tip().await;
        app.fork_choice = Some(fork_choice_returning(b801_bad.header.block_hash));
        app.apply_received(&b801_bad).await; // reorg reapplies b800 (→5000), b801_bad fails → abort

        // Applied tip stayed on A, AND the §R' policy cell was RESTORED to 2500 — the
        // aborted reorg left the shared policy byte-identical (fix #2 capture/restore).
        assert_eq!(app.applied_tip().await, a_tip, "aborted reorg left the applied tip on branch A");
        assert_eq!(
            follower.reward_policy_handle().read().as_ref().map(|p| p.priority_fee_share_bps),
            Some(2500),
            "aborted reorg must restore the pre-reorg reward policy (not leave it at 5000)"
        );
    }

    // ========================================================================
    // REORG-STORE-FIX acceptance — the reorg durable-store read-through fork.
    //
    // These are the residual repro tests from `build/campaign-lifecycle-fuzz`,
    // brought in and FLIPPED from their CONFIRMED-BUG assertions to the correct,
    // peer-consistent expectation: the heavier winning branch is now ACCEPTED and
    // the victim CONVERGES (identical tip + root + registry balance) with the golden
    // node. Root cause + fix: see `reorg_to` REORG-STORE-FIX comment (revert the
    // durable store to the fork point before reapply, so read-throughs during reapply
    // resolve against fork-point state, not the losing branch the store still held).
    // ========================================================================

    /// Fork point s799 on a store-backed follower (registry untouched at 0). Returns
    /// (app, follower, storage, s799_hash, dir). Constant-2500 §R' policy hooks.
    async fn seed_s799(
    ) -> (CanonicalApplicator, Arc<Executor>, Arc<StorageManager>, Hash, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let follower = store_backed(&storage);
        follower.set_balance(&Address(ALICE), U256::from(FUND));
        follower.persist_state_changes().await.expect("persist genesis");
        let a798 = seal_rprime(798, Hash::default(), Hash::default(), VRF_OUT, vec![]);
        persist(&storage, &a798);
        storage.blocks.put_applied_tip(&a798.header.block_hash, 798).expect("seed tip");
        follower.set_validator_activation_height(800);
        *follower.reward_policy_handle().write() = Some(rprime_policy(2500));

        let mut app = CanonicalApplicator::new(follower.clone(), storage.clone());
        // Constant-2500 hooks (isolate the registry read-through from any policy flip).
        let f1 = follower.clone();
        app.registry_sync = Some(Arc::new(move |_h| {
            *f1.reward_policy_handle().write() = Some(rprime_policy(2500));
            Box::pin(async { Ok(1usize) })
        }));
        let f2 = follower.clone();
        app.registry_policy_resync = Some(Arc::new(move |_h| {
            *f2.reward_policy_handle().write() = Some(rprime_policy(2500));
            Box::pin(async { Ok(()) })
        }));

        // Produce + apply the shared s799 (empty).
        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pa.set_balance(&Address(ALICE), U256::from(FUND));
        pa.set_validator_activation_height(800);
        *pa.reward_policy_handle().write() = Some(rprime_policy(2500));
        let s799 = produce_rprime(&pa, a798.header.block_hash, 799, VRF_OUT, vec![]).await;
        persist(&storage, &s799);
        assert!(matches!(app.apply_received(&s799).await, ApplyOutcome::Applied { .. }), "s799");
        assert_eq!(follower.get_balance(&Address(REG)), U256::zero(), "registry untouched at fork point");
        (app, follower, storage, s799.header.block_hash, dir)
    }

    /// Branch A off s799: two VESTING blocks (prio ALICE→BOB) at 800, 801. Fresh
    /// memory-only producer → honest fork-point-relative roots. Returns (a800, a801).
    async fn produce_branch_a(s799: Hash) -> (Block, Block) {
        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pa.set_balance(&Address(ALICE), U256::from(FUND));
        pa.set_validator_activation_height(800);
        *pa.reward_policy_handle().write() = Some(rprime_policy(2500));
        let _s = produce_rprime(&pa, Hash::default(), 799, VRF_OUT, vec![]).await;
        let a800 = produce_rprime(&pa, s799, 800, VRF_OUT, vec![prio_tx(ALICE, BOB, 0, 0xA0)]).await;
        let a801 = produce_rprime(&pa, a800.header.block_hash, 801, VRF_OUT, vec![prio_tx(ALICE, BOB, 1, 0xA1)]).await;
        (a800, a801)
    }

    /// Branch B off s799: three VESTING blocks (prio ALICE→CAROL) at 800/801/802,
    /// distinct VRF so they fork from branch A. Fresh memory-only producer → honest
    /// fork-point-relative roots (registry starts at 0 for B).
    async fn produce_branch_b_vesting(s799: Hash) -> (Block, Block, Block) {
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pb.set_balance(&Address(ALICE), U256::from(FUND));
        pb.set_validator_activation_height(800);
        *pb.reward_policy_handle().write() = Some(rprime_policy(2500));
        let _s = produce_rprime(&pb, Hash::default(), 799, VRF_OUT, vec![]).await;
        let vrf_b = [0x5B; 32];
        let b800 = produce_rprime(&pb, s799, 800, vrf_b, vec![prio_tx(ALICE, CAROL, 0, 0xB0)]).await;
        let b801 = produce_rprime(&pb, b800.header.block_hash, 801, vrf_b, vec![prio_tx(ALICE, CAROL, 1, 0xB1)]).await;
        let b802 = produce_rprime(&pb, b801.header.block_hash, 802, vrf_b, vec![prio_tx(ALICE, CAROL, 2, 0xB2)]).await;
        (b800, b801, b802)
    }

    /// ⭐ THE FLAGGED RESIDUAL — now REMEDIATED. A store-backed victim that briefly
    /// followed + PERSISTED a losing §R'-vesting branch A must, on reorg, CONVERGE to
    /// the heavier winning branch B (identical tip + root + registry balance) with a
    /// golden node that only ever followed B. Pre-fix, the reorg reapply read the
    /// registry THROUGH to the durable store (still holding branch A's vest) and
    /// settled the winning block against stale state → root mismatch → abort → fork.
    #[tokio::test]
    async fn residual3_stale_registry_read_through_forks_reorg_now_converges() {
        // --- GOLDEN: only ever follows branch B. ---
        let (golden_app, golden, gstore, s799_g, _gdir) = seed_s799().await;
        let s799_ref = s799_g;
        let (b800, b801, b802) = produce_branch_b_vesting(s799_ref).await;
        persist(&gstore, &b800);
        assert!(matches!(golden_app.apply_received(&b800).await, ApplyOutcome::Applied { .. }), "golden b800");
        persist(&gstore, &b801);
        assert!(matches!(golden_app.apply_received(&b801).await, ApplyOutcome::Applied { .. }), "golden b801");
        persist(&gstore, &b802);
        assert!(matches!(golden_app.apply_received(&b802).await, ApplyOutcome::Applied { .. }), "golden b802");
        let golden_tip = golden_app.applied_tip().await;
        let golden_root = golden.calculate_state_root();
        let golden_reg = golden.get_balance(&Address(REG));
        assert_eq!(golden_tip.height, 802, "golden converged to branch B tip");
        assert!(golden_reg > U256::zero(), "golden vested a positive §R' share on branch B");

        // --- VICTIM: follows+persists branch A (which VESTS), then reorgs to B. ---
        let (mut victim_app, victim, vstore, s799_v, _vdir) = seed_s799().await;
        assert_eq!(s799_v, s799_ref, "both nodes share the deterministic fork point");
        let (a800, a801) = produce_branch_a(s799_ref).await;
        persist(&vstore, &a800);
        assert!(matches!(victim_app.apply_received(&a800).await, ApplyOutcome::Applied { .. }), "victim a800");
        persist(&vstore, &a801);
        assert!(matches!(victim_app.apply_received(&a801).await, ApplyOutcome::Applied { .. }), "victim a801");
        let stale_reg = victim.get_balance(&Address(REG));
        assert!(stale_reg > U256::zero(), "branch A vested a NONZERO registry balance (now persisted)");

        // Deliver the heavier branch B; fork choice selects b802.
        for b in [&b800, &b801, &b802] {
            persist(&vstore, b);
        }
        victim_app.fork_choice = Some(fork_choice_returning(b802.header.block_hash));
        let outcome = victim_app.apply_received(&b802).await;

        // ---- PEER-CONSISTENT assertions (the winning branch is ACCEPTED) ----
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "victim ACCEPTS the valid winning branch (reorg no longer aborts on a stale-registry read); got {outcome:?}"
        );
        assert_eq!(victim_app.applied_tip().await, golden_tip, "victim tip converges to the golden winning-branch tip");
        assert_eq!(victim.calculate_state_root(), golden_root, "victim state root converges to the golden node's");
        assert_eq!(
            victim.get_balance(&Address(REG)),
            golden_reg,
            "victim registry reflects branch B's vest (fork-point 0 + B share), NOT branch A's stale persisted vest"
        );
        assert_ne!(victim.get_balance(&Address(REG)), stale_reg, "registry is no longer frozen at branch-A's stale value");

        // Cold restart reads the winning branch from the durable store (invariant I3).
        let restarted = store_backed(&vstore);
        assert_eq!(restarted.get_balance(&Address(REG)), golden_reg, "durable store holds branch B's registry vest after reorg");
    }

    /// ROOT-CAUSE ISOLATION control (unchanged expectation): a MEMORY-ONLY victim has
    /// no durable store to read through, so it ALWAYS converged — and still must. This
    /// pins that the fix did not regress the memory-only path.
    #[tokio::test]
    async fn residual3_memory_only_node_converges_no_store_read_through() {
        let follower = Arc::new(Executor::new(Arc::new(StateDB::new())));
        follower.set_balance(&Address(ALICE), U256::from(FUND));
        follower.set_validator_activation_height(800);
        *follower.reward_policy_handle().write() = Some(rprime_policy(2500));
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let a798 = seal_rprime(798, Hash::default(), Hash::default(), VRF_OUT, vec![]);
        persist(&storage, &a798);
        storage.blocks.put_applied_tip(&a798.header.block_hash, 798).expect("seed tip");
        let mut app = CanonicalApplicator::new(follower.clone(), storage.clone());
        let f1 = follower.clone();
        app.registry_sync = Some(Arc::new(move |_h| {
            *f1.reward_policy_handle().write() = Some(rprime_policy(2500));
            Box::pin(async { Ok(1usize) })
        }));
        let f2 = follower.clone();
        app.registry_policy_resync = Some(Arc::new(move |_h| {
            *f2.reward_policy_handle().write() = Some(rprime_policy(2500));
            Box::pin(async { Ok(()) })
        }));

        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pa.set_balance(&Address(ALICE), U256::from(FUND));
        pa.set_validator_activation_height(800);
        *pa.reward_policy_handle().write() = Some(rprime_policy(2500));
        let s799 = produce_rprime(&pa, a798.header.block_hash, 799, VRF_OUT, vec![]).await;
        persist(&storage, &s799);
        assert!(matches!(app.apply_received(&s799).await, ApplyOutcome::Applied { .. }));
        let s799 = s799.header.block_hash;

        let (a800, a801) = produce_branch_a(s799).await;
        persist(&storage, &a800);
        assert!(matches!(app.apply_received(&a800).await, ApplyOutcome::Applied { .. }));
        persist(&storage, &a801);
        assert!(matches!(app.apply_received(&a801).await, ApplyOutcome::Applied { .. }));

        let (b800, b801, b802) = produce_branch_b_vesting(s799).await;
        for b in [&b800, &b801, &b802] {
            persist(&storage, b);
        }
        app.fork_choice = Some(fork_choice_returning(b802.header.block_hash));
        let outcome = app.apply_received(&b802).await;
        assert_eq!(
            app.applied_tip().await,
            AppliedTip { hash: b802.header.block_hash, height: 802 },
            "memory-only victim CONVERGES to branch B — outcome {outcome:?}"
        );
        assert_eq!(
            follower.calculate_state_root(),
            b802.state_root,
            "memory-only victim reproduces branch B's winning root"
        );
    }

    /// RESIDUAL breadth — now REMEDIATED: the SAME stale-registry fork occurred on a
    /// reorg crossing NO S(E) boundary (constant policy, one epoch window), proving the
    /// divergence was the generic durable-store read-through, not a §R' boundary
    /// artifact. Post-fix the victim CONVERGES to the winning branch across no boundary.
    #[tokio::test]
    async fn residual3_same_epoch_no_boundary_reorg_now_converges() {
        async fn seed_809(
        ) -> (CanonicalApplicator, Arc<Executor>, Arc<StorageManager>, Hash, tempfile::TempDir) {
            let dir = tempfile::tempdir().expect("dir");
            let storage =
                Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
            let follower = store_backed(&storage);
            follower.set_balance(&Address(ALICE), U256::from(FUND));
            follower.persist_state_changes().await.expect("persist genesis");
            let a808 = seal_rprime(808, Hash::default(), Hash::default(), VRF_OUT, vec![]);
            persist(&storage, &a808);
            storage.blocks.put_applied_tip(&a808.header.block_hash, 808).expect("seed tip");
            follower.set_validator_activation_height(800);
            *follower.reward_policy_handle().write() = Some(rprime_policy(2500));
            let mut app = CanonicalApplicator::new(follower.clone(), storage.clone());
            let f1 = follower.clone();
            app.registry_sync = Some(Arc::new(move |_h| {
                *f1.reward_policy_handle().write() = Some(rprime_policy(2500));
                Box::pin(async { Ok(1usize) })
            }));
            let f2 = follower.clone();
            app.registry_policy_resync = Some(Arc::new(move |_h| {
                *f2.reward_policy_handle().write() = Some(rprime_policy(2500));
                Box::pin(async { Ok(()) })
            }));
            let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
            pa.set_balance(&Address(ALICE), U256::from(FUND));
            pa.set_validator_activation_height(800);
            *pa.reward_policy_handle().write() = Some(rprime_policy(2500));
            let s809 = produce_rprime(&pa, a808.header.block_hash, 809, VRF_OUT, vec![]).await;
            persist(&storage, &s809);
            assert!(matches!(app.apply_received(&s809).await, ApplyOutcome::Applied { .. }));
            assert!(crate::registry_sync::snapshot_epoch_at(810).is_none(), "810 is NOT a boundary");
            (app, follower, storage, s809.header.block_hash, dir)
        }

        // GOLDEN: only follows branch B (four vesting blocks 810..813).
        let (golden_app, golden, gstore, s809, _gd) = seed_809().await;
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pb.set_balance(&Address(ALICE), U256::from(FUND));
        pb.set_validator_activation_height(800);
        *pb.reward_policy_handle().write() = Some(rprime_policy(2500));
        let _s = produce_rprime(&pb, Hash::default(), 809, VRF_OUT, vec![]).await;
        let vrf_b = [0x5B; 32];
        let mut parent = s809;
        let mut b_blocks = Vec::new();
        for i in 0..4u64 {
            let blk = produce_rprime(&pb, parent, 810 + i, vrf_b, vec![prio_tx(ALICE, CAROL, i, 0xB0 + i as u8)]).await;
            parent = blk.header.block_hash;
            b_blocks.push(blk);
        }
        for b in &b_blocks {
            persist(&gstore, b);
            assert!(matches!(golden_app.apply_received(b).await, ApplyOutcome::Applied { .. }));
        }
        let golden_tip = golden_app.applied_tip().await;
        let golden_root = golden.calculate_state_root();
        let golden_reg = golden.get_balance(&Address(REG));
        assert_eq!(golden_tip.height, 813, "golden converged to branch B");

        // VICTIM: follows+persists losing branch A (vests at 810/811), then reorg to B.
        let (mut victim_app, victim, vstore, s809v, _vd) = seed_809().await;
        assert_eq!(s809v, s809);
        let pa2 = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pa2.set_balance(&Address(ALICE), U256::from(FUND));
        pa2.set_validator_activation_height(800);
        *pa2.reward_policy_handle().write() = Some(rprime_policy(2500));
        let _s2 = produce_rprime(&pa2, Hash::default(), 809, VRF_OUT, vec![]).await;
        let a810 = produce_rprime(&pa2, s809, 810, VRF_OUT, vec![prio_tx(ALICE, BOB, 0, 0xA0)]).await;
        let a811 = produce_rprime(&pa2, a810.header.block_hash, 811, VRF_OUT, vec![prio_tx(ALICE, BOB, 1, 0xA1)]).await;
        persist(&vstore, &a810);
        assert!(matches!(victim_app.apply_received(&a810).await, ApplyOutcome::Applied { .. }));
        persist(&vstore, &a811);
        assert!(matches!(victim_app.apply_received(&a811).await, ApplyOutcome::Applied { .. }));
        assert!(victim.get_balance(&Address(REG)) > U256::zero(), "losing branch persisted a §R' vest");
        for b in &b_blocks {
            persist(&vstore, b);
        }
        let tip_b = b_blocks.last().expect("nonempty");
        victim_app.fork_choice = Some(fork_choice_returning(tip_b.header.block_hash));
        let outcome = victim_app.apply_received(tip_b).await;

        // PEER-CONSISTENT: the victim converges even with NO boundary crossed.
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "no-boundary victim ACCEPTS the valid winning branch: {outcome:?}"
        );
        assert_eq!(victim_app.applied_tip().await, golden_tip, "no-boundary victim tip converges to golden");
        assert_eq!(victim.calculate_state_root(), golden_root, "no-boundary victim root converges to golden");
        assert_eq!(victim.get_balance(&Address(REG)), golden_reg, "no-boundary victim registry converges to golden");
    }

    /// A reward-only v2 block with an explicit coinbase (the account the basic
    /// block reward credits). Reward-only, so `vrf` only distinguishes hashes.
    fn mk_block_cb(height: u64, parent: Hash, state_root: Hash, vrf: [u8; 32], coinbase: [u8; 20]) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(coinbase)
            .timestamp(1000)
            .vrf_reveal(VrfProof { proof: vec![], output: Hash::new(vrf) })
            .transactions(vec![])
            .state_root(state_root)
            .build_unhashed();
        b.header.block_hash = b.compute_hash();
        b
    }

    /// Produce a reward-only block crediting `coinbase` (+ treasury), advancing
    /// `exec` to the post-block state and sealing the honest root. Mirrors the
    /// producer's basic-reward path (node/src/producer.rs) for a custom coinbase.
    async fn produce_cb(exec: &Executor, parent: Hash, height: u64, vrf: [u8; 32], coinbase: [u8; 20]) -> Block {
        exec.set_block_context(BlockContext {
            coinbase,
            prevrandao: vrf,
            block_hashes: std::collections::HashMap::new(),
        });
        let provisional = mk_block_cb(height, parent, Hash::default(), vrf, coinbase);
        let reward = RewardCalculator::new(canonical_reward_config()).calculate_reward(&provisional);
        for (addr, amt) in [
            (Address(coinbase), reward.validator_reward),
            (Address(TREASURY_ADDR), reward.treasury_reward),
        ] {
            if amt > U256::zero() {
                let bal = exec.get_balance(&addr);
                exec.set_balance(&addr, bal + amt);
            }
        }
        let root = exec.calculate_state_root();
        mk_block_cb(height, parent, root, vrf, coinbase)
    }

    /// GENERIC (NON-§R') variant — proves the fix is NOT registry-specific. A plain
    /// reward-settlement reorg with NO §R', NO epoch boundary, NO reward policy: both
    /// branches are produced by a NEW validator whose coinbase `CBN` the fork point
    /// never credited. The basic block reward credits `CBN` via `Executor::get_balance`
    /// — the SAME durable-store read-through primitive. The LOSING branch persists a
    /// `CBN` balance the WINNING branch also credits; the fork point never touched
    /// `CBN`. Pre-fix, reapplying the winning branch read `CBN` THROUGH to the store
    /// (still the losing branch's vest) and settled `stale + reward` instead of
    /// `0 + reward` → root mismatch → abort → the victim rejected a valid heavier
    /// branch (a fork). Post-fix the victim CONVERGES.
    ///
    /// (Native EOA value transfers read the recipient via `state_db.accounts` — memory
    /// only, no store read-through — so they do NOT trip this bug; the read-through
    /// vectors are `Executor::get_balance/get_nonce/get_code_hash` and the REVM adapter,
    /// exercised here by the reward-credit path.)
    #[tokio::test]
    async fn normal_reward_reorg_new_validator_coinbase_no_longer_forks() {
        const CBN: [u8; 20] = [0x44; 20]; // a new validator's coinbase, unseen at the fork point
        let vrf_b = [0x5B; 32];

        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let follower = store_backed(&storage);
        let mut app = CanonicalApplicator::new(follower.clone(), storage.clone());

        // Shared a1 (coinbase CB): the fork point at height 1 — credits CB + TREASURY,
        // NEVER CBN. Losing branch A off a1 is a2 (coinbase CBN) → persists a CBN vest.
        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        let a1 = produce_cb(&pa, Hash::default(), 1, VRF_OUT, CB).await;
        let a2 = produce_cb(&pa, a1.header.block_hash, 2, VRF_OUT, CBN).await;
        persist(&storage, &a1);
        assert!(matches!(app.apply_received(&a1).await, ApplyOutcome::Applied { .. }), "a1");
        persist(&storage, &a2);
        assert!(matches!(app.apply_received(&a2).await, ApplyOutcome::Applied { .. }), "a2");
        let stale_cbn = follower.get_balance(&Address(CBN));
        assert!(stale_cbn > U256::zero(), "branch A persisted a NONZERO CBN reward");

        // GOLDEN (only branch B): b2, b3 (coinbase CBN) fork at a1. CBN starts at the
        // fork-point value 0 → golden CBN = reward(h2) + reward(h3).
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        let _b1 = produce_cb(&pb, Hash::default(), 1, VRF_OUT, CB).await; // identical to a1
        let b2 = produce_cb(&pb, a1.header.block_hash, 2, vrf_b, CBN).await;
        let b3 = produce_cb(&pb, b2.header.block_hash, 3, vrf_b, CBN).await;
        // Independent golden node to pin the honest convergence target.
        let gdir = tempfile::tempdir().expect("gdir");
        let gstorage =
            Arc::new(StorageManager::new(gdir.path(), PruningConfig::default()).expect("gstorage"));
        let golden = store_backed(&gstorage);
        let gapp = CanonicalApplicator::new(golden.clone(), gstorage.clone());
        // Persist-just-before-deliver so the golden node applies a1→b2→b3 as a clean
        // linear extension (no premature cascade from pre-persisted descendants).
        persist(&gstorage, &a1);
        assert!(matches!(gapp.apply_received(&a1).await, ApplyOutcome::Applied { .. }), "golden a1");
        persist(&gstorage, &b2);
        assert!(matches!(gapp.apply_received(&b2).await, ApplyOutcome::Applied { .. }), "golden b2");
        persist(&gstorage, &b3);
        assert!(matches!(gapp.apply_received(&b3).await, ApplyOutcome::Applied { .. }), "golden b3");
        let golden_cbn = golden.get_balance(&Address(CBN));
        let golden_root = golden.calculate_state_root();
        assert!(golden_cbn > U256::zero() && golden_cbn != stale_cbn, "golden CBN differs from branch A's stale vest");

        // Victim reorgs A → B.
        persist(&storage, &b2);
        persist(&storage, &b3);
        app.fork_choice = Some(fork_choice_returning(b3.header.block_hash));
        let outcome = app.apply_received(&b3).await;

        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "victim ACCEPTS the valid heavier winning branch (no stale-coinbase read-through abort); got {outcome:?}"
        );
        assert_eq!(app.applied_tip().await, AppliedTip { hash: b3.header.block_hash, height: 3 }, "reorged to B tip");
        assert_eq!(follower.calculate_state_root(), golden_root, "victim root converges to golden");
        assert_eq!(
            follower.get_balance(&Address(CBN)),
            golden_cbn,
            "CBN = 0 (fork point) + reward(h2) + reward(h3) on branch B, NOT the stale A vest + rewards"
        );
        assert_ne!(follower.get_balance(&Address(CBN)), stale_cbn, "CBN is no longer frozen at branch-A's stale value");

        // Cold restart proves the durable store holds branch B (I3).
        let restarted = store_backed(&storage);
        assert_eq!(restarted.get_balance(&Address(CBN)), golden_cbn, "durable store CBN == branch B after reorg");
    }

    // ========================================================================
    // INDEPENDENT ADVERSARIAL RE-FUZZ of the REORG-STORE-FIX (build/campaign-
    // lifecycle-refuzz). This harness is written to BREAK the fix, not to trust
    // its own tests: it randomizes fork depth / vest amounts / branch shapes over
    // many seeds and asserts the store-backed victim CONVERGES with an independent
    // golden node (byte-identical root + balances), that aborts leave the durable
    // store byte-identical (read COLD), and it CONSTRUCTS + CHARACTERIZES the
    // author-flagged residual (cold pre-existing account in the reorg base).
    //
    // Deterministic PRNG (splitmix64) so any failure repro is a fixed seed.
    // ========================================================================

    fn splitmix64_rf(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The FULL durable account set, sorted — a true byte-identity fingerprint of
    /// the persisted store (independent of any in-memory executor cache).
    fn dump_store(storage: &StorageManager) -> Vec<(Address, citrate_execution::types::AccountState)> {
        let mut v = storage.state.get_all_accounts().expect("get_all_accounts");
        v.sort_by_key(|a| a.0 .0);
        v
    }

    /// A linear §R'-vesting branch of `n` blocks off `fork` (heights 800..800+n-1),
    /// `per_block` priority transfers ALICE→`to` each. Fresh memory-only producer
    /// advanced through the empty fork point (799) → honest fork-point-relative
    /// roots. Constant 2500 bps (0-boundary). `seed_base` disambiguates tx hashes.
    async fn produce_vesting_branch(
        fork: Hash,
        n: u64,
        per_block: u64,
        to: [u8; 20],
        vrf: [u8; 32],
        seed_base: u8,
    ) -> Vec<Block> {
        let p = Arc::new(Executor::new(Arc::new(StateDB::new())));
        p.set_balance(&Address(ALICE), U256::from(FUND));
        p.set_validator_activation_height(800);
        *p.reward_policy_handle().write() = Some(rprime_policy(2500));
        let _s = produce_rprime(&p, Hash::default(), 799, VRF_OUT, vec![]).await;
        let mut parent = fork;
        let mut nonce = 0u64;
        let mut sctr = seed_base;
        let mut out = Vec::new();
        for i in 0..n {
            let h = 800 + i;
            let mut txs = Vec::new();
            for _ in 0..per_block {
                txs.push(prio_tx(ALICE, to, nonce, sctr));
                nonce += 1;
                sctr = sctr.wrapping_add(1);
            }
            let blk = produce_rprime(&p, parent, h, vrf, txs).await;
            parent = blk.header.block_hash;
            out.push(blk);
        }
        out
    }

    /// One randomized §R'-vesting reorg: a store-backed VICTIM follows + persists a
    /// losing branch A (`da` vesting blocks, `pa` vests each), then reorgs to a
    /// winning branch B (`db` vesting blocks, `pb` vests each). It must converge —
    /// identical tip + root + registry balance, in memory AND durably — with a
    /// GOLDEN node that only ever followed B. This is the fix's core claim under
    /// randomized fork depth and vest amounts (RESIDUAL CLOSED AT SCALE).
    async fn run_vesting_convergence(da: u64, db: u64, pa: u64, pb: u64) {
        // GOLDEN: only ever follows branch B.
        let (golden_app, golden, gstore, s799_g, _gd) = seed_s799().await;
        let branch_b = produce_vesting_branch(s799_g, db, pb, CAROL, [0x5B; 32], 0xB0).await;
        for b in &branch_b {
            persist(&gstore, b);
        }
        let tip_b = branch_b.last().expect("branch B nonempty");
        assert!(
            matches!(golden_app.apply_received(tip_b).await, ApplyOutcome::Applied { .. }),
            "da={da} db={db} pa={pa} pb={pb}: golden failed to drain branch B"
        );
        let golden_tip = golden_app.applied_tip().await;
        let golden_root = golden.calculate_state_root();
        let golden_reg = golden.get_balance(&Address(REG));

        // VICTIM: follow + persist losing branch A, then reorg to B.
        let (mut victim_app, victim, vstore, s799_v, _vd) = seed_s799().await;
        assert_eq!(s799_v, s799_g, "deterministic fork point across nodes");
        let branch_a = produce_vesting_branch(s799_v, da, pa, BOB, VRF_OUT, 0xA0).await;
        for a in &branch_a {
            persist(&vstore, a);
            assert!(
                matches!(victim_app.apply_received(a).await, ApplyOutcome::Applied { .. }),
                "da={da} db={db}: victim failed to follow losing branch A"
            );
        }
        for b in &branch_b {
            persist(&vstore, b);
        }
        victim_app.fork_choice = Some(fork_choice_returning(tip_b.header.block_hash));
        let outcome = victim_app.apply_received(tip_b).await;

        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "da={da} db={db} pa={pa} pb={pb}: winning branch not accepted: {outcome:?}"
        );
        assert_eq!(
            victim_app.applied_tip().await,
            golden_tip,
            "da={da} db={db} pa={pa} pb={pb}: victim tip diverged from golden"
        );
        assert_eq!(
            victim.calculate_state_root(),
            golden_root,
            "da={da} db={db} pa={pa} pb={pb}: victim root diverged from golden"
        );
        assert_eq!(
            victim.get_balance(&Address(REG)),
            golden_reg,
            "da={da} db={db} pa={pa} pb={pb}: victim registry diverged from golden"
        );
        // Durable parity across a cold restart (I3).
        let restarted = store_backed(&vstore);
        assert_eq!(
            restarted.get_balance(&Address(REG)),
            golden_reg,
            "da={da} db={db} pa={pa} pb={pb}: durable registry != golden after reorg"
        );
    }

    /// TRACK 1 — RESIDUAL CLOSED AT SCALE (§R' vesting). Randomize fork depth and
    /// vest amounts over many seeds; the victim must converge with the golden node
    /// every time. Includes explicit near-`MAX_REORG_DEPTH` fork depths.
    #[tokio::test]
    async fn refuzz_vesting_reorg_converges_at_scale() {
        let mut seed = 0xCAFE_F00D_1234_5678u64;
        let mut cases = 0u32;
        for _ in 0..40 {
            let da = 1 + splitmix64_rf(&mut seed) % 5; // losing depth 1..=5
            let db = 1 + splitmix64_rf(&mut seed) % 5; // winning depth 1..=5 (indep.)
            let pa = 1 + splitmix64_rf(&mut seed) % 3; // vests/block losing 1..=3
            let pb = 1 + splitmix64_rf(&mut seed) % 3; // vests/block winning 1..=3
            run_vesting_convergence(da, db, pa, pb).await;
            cases += 1;
        }
        assert_eq!(cases, 40);
        // Explicit deep fork depths near MAX_REORG_DEPTH=100 (must still converge).
        for &(da, db) in &[(1u64, 20u64), (3, 50), (2, 90), (1, 99)] {
            run_vesting_convergence(da, db, 1, 1).await;
        }
    }

    /// One randomized NORMAL-TX (non-§R') reorg: both branches are produced by a
    /// NEW validator whose coinbase `CBN` the fork point never credited, exercising
    /// the SAME `Executor::get_balance` durable read-through via the basic reward
    /// path — no registry, no policy. Losing `da` blocks, winning `db` blocks; the
    /// victim must converge with a golden node that only followed B.
    async fn run_normal_convergence(da: u64, db: u64) {
        const CBN: [u8; 20] = [0x44; 20];
        let vrf_b = [0x5B; 32];

        // Producers. a1 (coinbase CB) is the shared fork point; branches credit CBN.
        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        let a1 = produce_cb(&pa, Hash::default(), 1, VRF_OUT, CB).await;
        let mut branch_a = Vec::new();
        let mut parent = a1.header.block_hash;
        for i in 0..da {
            let blk = produce_cb(&pa, parent, 2 + i, VRF_OUT, CBN).await;
            parent = blk.header.block_hash;
            branch_a.push(blk);
        }
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        let _b1 = produce_cb(&pb, Hash::default(), 1, VRF_OUT, CB).await; // identical to a1
        let mut branch_b = Vec::new();
        let mut parent = a1.header.block_hash;
        for i in 0..db {
            let blk = produce_cb(&pb, parent, 2 + i, vrf_b, CBN).await;
            parent = blk.header.block_hash;
            branch_b.push(blk);
        }
        let tip_b = branch_b.last().expect("branch B nonempty");

        // GOLDEN: only ever follows branch B.
        let gdir = tempfile::tempdir().expect("gdir");
        let gstorage =
            Arc::new(StorageManager::new(gdir.path(), PruningConfig::default()).expect("gstorage"));
        let golden = store_backed(&gstorage);
        let gapp = CanonicalApplicator::new(golden.clone(), gstorage.clone());
        persist(&gstorage, &a1);
        assert!(matches!(gapp.apply_received(&a1).await, ApplyOutcome::Applied { .. }), "golden a1");
        for b in &branch_b {
            persist(&gstorage, b);
        }
        assert!(
            matches!(gapp.apply_received(tip_b).await, ApplyOutcome::Applied { .. }),
            "da={da} db={db}: golden failed to drain branch B"
        );
        let golden_tip = gapp.applied_tip().await;
        let golden_root = golden.calculate_state_root();
        let golden_cbn = golden.get_balance(&Address(CBN));

        // VICTIM: follow + persist losing branch A, then reorg to B.
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let victim = store_backed(&storage);
        let mut app = CanonicalApplicator::new(victim.clone(), storage.clone());
        persist(&storage, &a1);
        assert!(matches!(app.apply_received(&a1).await, ApplyOutcome::Applied { .. }), "victim a1");
        for a in &branch_a {
            persist(&storage, a);
            assert!(
                matches!(app.apply_received(a).await, ApplyOutcome::Applied { .. }),
                "da={da} db={db}: victim failed to follow losing branch A"
            );
        }
        for b in &branch_b {
            persist(&storage, b);
        }
        app.fork_choice = Some(fork_choice_returning(tip_b.header.block_hash));
        let outcome = app.apply_received(tip_b).await;

        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "da={da} db={db}: winning branch not accepted: {outcome:?}"
        );
        assert_eq!(app.applied_tip().await, golden_tip, "da={da} db={db}: victim tip != golden");
        assert_eq!(victim.calculate_state_root(), golden_root, "da={da} db={db}: victim root != golden");
        assert_eq!(victim.get_balance(&Address(CBN)), golden_cbn, "da={da} db={db}: victim CBN != golden");
        let restarted = store_backed(&storage);
        assert_eq!(restarted.get_balance(&Address(CBN)), golden_cbn, "da={da} db={db}: durable CBN != golden");
    }

    /// TRACK 1 — RESIDUAL CLOSED AT SCALE (NORMAL-TX variant). The losing branch
    /// mutates a plain coinbase account the fork point never touched; the winning
    /// branch reads it. Randomized depths over many seeds → converge.
    #[tokio::test]
    async fn refuzz_normal_coinbase_reorg_converges_at_scale() {
        let mut seed = 0x0BAD_C0DE_D00D_FEEDu64;
        let mut cases = 0u32;
        for _ in 0..30 {
            let da = 1 + splitmix64_rf(&mut seed) % 4; // 1..=4
            let db = 1 + splitmix64_rf(&mut seed) % 4; // 1..=4
            run_normal_convergence(da, db).await;
            cases += 1;
        }
        assert_eq!(cases, 30);
        for &(da, db) in &[(1u64, 30u64), (4, 60), (2, 95)] {
            run_normal_convergence(da, db).await;
        }
    }

    // ------------------------------------------------------------------------
    // TRACK 2 — NO NEW REGRESSION. The original cross-boundary cross-policy
    // convergence + abort-restore matrix (perturbation #2/#4), ported verbatim
    // from build/campaign-lifecycle-fuzz. The store-revert must not have broken
    // the previously-passing (empty-losing-branch) cases.
    // ------------------------------------------------------------------------

    fn cross_policy_hook_p(exec: Arc<Executor>, pre: u64, post: u64) -> impl Fn() {
        move || {
            let bps = if exec.get_balance(&Address(CAROL)) > U256::zero() { post } else { pre };
            *exec.reward_policy_handle().write() = Some(rprime_policy(bps));
        }
    }

    async fn setup_cross_policy_p(
        pre: u64,
        post: u64,
    ) -> (CanonicalApplicator, Arc<Executor>, Arc<StorageManager>, Hash, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let follower = store_backed(&storage);
        follower.set_balance(&Address(ALICE), U256::from(FUND));
        follower.persist_state_changes().await.expect("persist genesis");
        let a798 = seal_rprime(798, Hash::default(), Hash::default(), VRF_OUT, vec![]);
        persist(&storage, &a798);
        storage.blocks.put_applied_tip(&a798.header.block_hash, 798).expect("seed tip");
        follower.set_validator_activation_height(800);
        *follower.reward_policy_handle().write() = Some(rprime_policy(pre));

        let mut app = CanonicalApplicator::new(follower.clone(), storage.clone());
        let h_full = cross_policy_hook_p(follower.clone(), pre, post);
        app.registry_sync = Some(Arc::new(move |_h| {
            h_full();
            Box::pin(async { Ok(1usize) })
        }));
        let h_pol = cross_policy_hook_p(follower.clone(), pre, post);
        app.registry_policy_resync = Some(Arc::new(move |_h| {
            h_pol();
            Box::pin(async { Ok(()) })
        }));

        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pa.set_balance(&Address(ALICE), U256::from(FUND));
        pa.set_validator_activation_height(800);
        *pa.reward_policy_handle().write() = Some(rprime_policy(pre));
        let s799 = produce_rprime(&pa, a798.header.block_hash, 799, VRF_OUT, vec![]).await;
        let a800 = produce_rprime(&pa, s799.header.block_hash, 800, VRF_OUT, vec![]).await;
        let a801 = produce_rprime(&pa, a800.header.block_hash, 801, VRF_OUT, vec![]).await;
        persist(&storage, &s799);
        assert!(matches!(app.apply_received(&s799).await, ApplyOutcome::Applied { .. }), "s799");
        persist(&storage, &a800);
        assert!(matches!(app.apply_received(&a800).await, ApplyOutcome::Applied { .. }), "a800");
        persist(&storage, &a801);
        assert!(matches!(app.apply_received(&a801).await, ApplyOutcome::Applied { .. }), "a801");
        assert_eq!(follower.get_balance(&Address(REG)), U256::zero(), "branch A vested nothing");
        (app, follower, storage, s799.header.block_hash, dir)
    }

    async fn produce_branch_b_p(s799: Hash, pre: u64, post: u64, depth: u64) -> Vec<Block> {
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        pb.set_balance(&Address(ALICE), U256::from(FUND));
        pb.set_validator_activation_height(800);
        *pb.reward_policy_handle().write() = Some(rprime_policy(pre));
        let _s = produce_rprime(&pb, Hash::default(), 799, VRF_OUT, vec![]).await;
        let vrf_b = [0x5B; 32];
        let mut out = Vec::new();
        let b800 = produce_rprime(&pb, s799, 800, vrf_b, vec![prio_tx(ALICE, CAROL, 0, 0xB0)]).await;
        let mut parent = b800.header.block_hash;
        out.push(b800);
        *pb.reward_policy_handle().write() = Some(rprime_policy(post));
        for i in 0..depth {
            let h = 801 + i;
            let nonce = 1 + i;
            let blk = produce_rprime(&pb, parent, h, vrf_b, vec![prio_tx(ALICE, CAROL, nonce, 0xB1 + i as u8)]).await;
            parent = blk.header.block_hash;
            out.push(blk);
        }
        out
    }

    #[tokio::test]
    async fn refuzz_cross_policy_reorg_converges_over_boundary() {
        let bps_choices = [0u64, 2500, 5000, 10000];
        let mut seed = 0xABCD_1234u64;
        let mut cases = 0u32;
        for _ in 0..24 {
            let pre = bps_choices[(splitmix64_rf(&mut seed) % 4) as usize];
            let post = bps_choices[(splitmix64_rf(&mut seed) % 4) as usize];
            let depth = 1 + splitmix64_rf(&mut seed) % 3;

            let (mut app, follower, storage, s799, _dir) = setup_cross_policy_p(pre, post).await;
            let branch_b = produce_branch_b_p(s799, pre, post, depth).await;
            for b in &branch_b {
                persist(&storage, b);
            }
            let tip_b = branch_b.last().expect("branch B nonempty");
            app.fork_choice = Some(fork_choice_returning(tip_b.header.block_hash));
            let outcome = app.apply_received(tip_b).await;
            assert!(
                matches!(outcome, ApplyOutcome::Applied { .. }),
                "pre={pre} post={post} depth={depth}: winning branch not accepted: {outcome:?}"
            );
            assert_eq!(
                app.applied_tip().await.hash,
                tip_b.header.block_hash,
                "pre={pre} post={post} depth={depth}: did not converge to branch B tip"
            );
            assert_eq!(
                follower.calculate_state_root(),
                tip_b.state_root,
                "pre={pre} post={post} depth={depth}: state root != winning branch"
            );
            assert_eq!(
                follower.reward_policy_handle().read().as_ref().map(|p| p.priority_fee_share_bps),
                Some(post),
                "pre={pre} post={post} depth={depth}: final policy != post-boundary bps"
            );
            let restarted = store_backed(&storage);
            assert_eq!(
                restarted.get_balance(&Address(REG)),
                follower.get_balance(&Address(REG)),
                "pre={pre} post={post} depth={depth}: durable registry vest != in-memory"
            );
            cases += 1;
        }
        assert_eq!(cases, 24);
    }

    #[tokio::test]
    async fn refuzz_cross_policy_reorg_abort_restores_policy_and_tip() {
        let bps_choices = [0u64, 2500, 5000, 10000];
        let mut seed = 0x5150_9977u64;
        for _ in 0..18 {
            let pre = bps_choices[(splitmix64_rf(&mut seed) % 4) as usize];
            let post = bps_choices[(splitmix64_rf(&mut seed) % 4) as usize];
            let depth = 1 + splitmix64_rf(&mut seed) % 3;

            let (mut app, follower, storage, s799, _dir) = setup_cross_policy_p(pre, post).await;
            let a_tip = app.applied_tip().await;
            let pre_root = follower.calculate_state_root();
            let pre_dump = dump_store(&storage);
            let pre_policy = follower
                .reward_policy_handle()
                .read()
                .as_ref()
                .map(|p| p.priority_fee_share_bps);
            assert_eq!(pre_policy, Some(pre), "sanity: pre-reorg policy is the pre bps");

            let mut branch_b = produce_branch_b_p(s799, pre, post, depth).await;
            let last = branch_b.last().expect("nonempty");
            let bad_height = last.header.height + 1;
            let bad = seal_rprime(
                bad_height,
                last.header.block_hash,
                Hash::new([0xFF; 32]),
                [0x5B; 32],
                vec![prio_tx(ALICE, CAROL, 1 + depth, 0xEE)],
            );
            for b in &branch_b {
                persist(&storage, b);
            }
            persist(&storage, &bad);
            branch_b.push(bad.clone());

            app.fork_choice = Some(fork_choice_returning(bad.header.block_hash));
            app.apply_received(&bad).await;

            assert_eq!(
                app.applied_tip().await, a_tip,
                "pre={pre} post={post} depth={depth}: aborted reorg moved the applied tip"
            );
            assert_eq!(
                follower.calculate_state_root(), pre_root,
                "pre={pre} post={post} depth={depth}: aborted reorg left world state mutated"
            );
            assert_eq!(
                follower.reward_policy_handle().read().as_ref().map(|p| p.priority_fee_share_bps),
                Some(pre),
                "pre={pre} post={post} depth={depth}: aborted reorg did not restore reward policy"
            );
            // I2: the durable store, read COLD, is byte-identical to before the attempt.
            assert_eq!(
                dump_store(&storage), pre_dump,
                "pre={pre} post={post} depth={depth}: aborted reorg left the durable store mutated"
            );
        }
    }

    // ------------------------------------------------------------------------
    // TRACK 3 — ABORT BYTE-IDENTITY (I2), FUZZED, on a NON-EMPTY (vesting) losing
    // branch so the store actually holds §R' registry state to (mis)restore. Every
    // aborted reorg must leave the durable store — read COLD via get_all_accounts —
    // byte-identical to `pre_state`, and the applied tip + ring unmoved.
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn refuzz_abort_byte_identity_cold_store_vesting() {
        let mut seed = 0x7777_1111_2222_3333u64;
        for _ in 0..20 {
            let da = 1 + splitmix64_rf(&mut seed) % 3; // losing vesting depth
            let pre_depth = 1 + splitmix64_rf(&mut seed) % 3; // valid B prefix before the bad block

            // Victim follows + persists a VESTING losing branch A (nonzero REG in store).
            let (mut app, follower, storage, s799, _dir) = seed_s799().await;
            let branch_a = produce_vesting_branch(s799, da, 2, BOB, VRF_OUT, 0xA0).await;
            for a in &branch_a {
                persist(&storage, a);
                assert!(matches!(app.apply_received(a).await, ApplyOutcome::Applied { .. }), "victim A");
            }
            assert!(follower.get_balance(&Address(REG)) > U256::zero(), "losing branch vested REG");

            let a_tip = app.applied_tip().await;
            let ring_len_before = app.advance_lock().lock().await.snapshots.len();
            let pre_dump = dump_store(&storage);

            // Valid B prefix that vests, then a BAD-root block → the reorg reapplies
            // the prefix in-memory, then ABORTS on the bad block.
            let mut branch_b = produce_vesting_branch(s799, pre_depth, 2, CAROL, [0x5B; 32], 0xB0).await;
            let last = branch_b.last().expect("nonempty");
            let bad = seal_rprime(
                last.header.height + 1,
                last.header.block_hash,
                Hash::new([0xFF; 32]),
                [0x5B; 32],
                vec![prio_tx(ALICE, CAROL, 100, 0xEE)],
            );
            for b in &branch_b {
                persist(&storage, b);
            }
            persist(&storage, &bad);
            branch_b.push(bad.clone());

            app.fork_choice = Some(fork_choice_returning(bad.header.block_hash));
            let outcome = app.apply_received(&bad).await;

            assert!(
                matches!(outcome, ApplyOutcome::Deferred | ApplyOutcome::Rejected(_)),
                "da={da} pre_depth={pre_depth}: aborted reorg unexpectedly {outcome:?}"
            );
            assert_eq!(app.applied_tip().await, a_tip, "da={da} pre_depth={pre_depth}: tip moved on abort");
            assert_eq!(
                app.advance_lock().lock().await.snapshots.len(),
                ring_len_before,
                "da={da} pre_depth={pre_depth}: ring size changed on abort"
            );
            // I2: COLD durable store byte-identical to before the attempt.
            assert_eq!(
                dump_store(&storage), pre_dump,
                "da={da} pre_depth={pre_depth}: aborted reorg left the durable store mutated"
            );
        }
    }

    // ------------------------------------------------------------------------
    // TRACK 4 — ⭐ THE FLAGGED RESIDUAL: post-restart COLD-mutated pre-existing
    // account (the reorg base snapshot lacks a pre-existing account the losing
    // branch mutated). Two proofs: (4a) the store-revert MECHANIC in isolation
    // (delete→0 then byte-restore), and (4b) the FULL reorg with a deliberately
    // cold/incomplete base snapshot injected into the ring — asserting the reorg
    // is FAIL-SAFE (aborts, store byte-restored, wrong state never adopted).
    // ------------------------------------------------------------------------

    /// 4a — MECHANIC PROOF. `reconcile_store_from(pre_state)` after a revert to a
    /// base that LACKS a pre-existing nonzero account DELETES that account from the
    /// store (→0) — so a reapply read-through returns 0, not its fork-point value.
    /// On abort, `reconcile_store_from(base)` PUTS it back → the store is restored
    /// byte-identically. Fund/state never corrupts; the account merely can't be
    /// read correctly until warmed. Driven at the executor level, no applicator.
    #[tokio::test]
    async fn flagged_residual_store_revert_deletes_then_restores_preexisting_account() {
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let exec = store_backed(&storage);

        // Pre-existing nonzero account DAVE=V, fully persisted (the fork-point truth).
        let v = U256::from(7_000_000u64);
        exec.set_balance(&Address(DAVE), v);
        exec.persist_state_changes().await.expect("persist DAVE");
        // `pre_state` = the losing branch's persisted world (here just DAVE=V).
        let pre_snapshot = exec.state_snapshot();
        let pre_dump = dump_store(&storage);
        assert_eq!(pre_dump.len(), 1, "only DAVE persisted");

        // BASE (the reorg fork point) captured while DAVE is NON-resident: a cold
        // executor over the same store that never loaded DAVE. This is the exact
        // author-flagged condition — a base snapshot missing a pre-existing account.
        let cold = store_backed(&storage);
        let base_snapshot = cold.state_snapshot();
        assert!(base_snapshot.account_entries().is_empty(), "base snapshot is cold (no DAVE)");

        // Reorg step 1: revert in-memory to the cold base, then reconcile the store
        // to the fork point relative to `pre_state`. DAVE is in `pre_state` but not
        // in current (cold) memory → the store-revert DELETES it.
        exec.state_restore(base_snapshot.clone());
        exec.reconcile_store_from(&pre_snapshot).expect("store-revert to fork point");
        let cold_read = store_backed(&storage);
        assert_eq!(
            cold_read.get_balance(&Address(DAVE)),
            U256::zero(),
            "store-revert DELETED the cold pre-existing account (a reapply now reads 0)"
        );

        // Reorg step 2 (abort arm): reconcile the store back to `pre_state` from the
        // cold base. Memory is restored to pre_state; DAVE is put back.
        exec.state_restore(pre_snapshot.clone());
        exec.reconcile_store_from(&base_snapshot).expect("store restore to pre_state");
        assert_eq!(
            dump_store(&storage), pre_dump,
            "abort restored the durable store byte-identically to pre_state (no fund loss)"
        );
    }

    /// 4b — FAIL-SAFE PROOF via the full applicator. A store-backed victim applies
    /// a1 (fork) + a losing branch (coinbase CBN), then the reorg base snapshot at
    /// the fork height is REPLACED with a cold/incomplete one (modelling the flagged
    /// residual: base missing accounts the winning branch reads). Delivering the
    /// heavier winning branch must ABORT: the winning blocks settle against the
    /// (deleted → 0) read-through, mismatch the honest roots, and the reorg declines
    /// — leaving the applied tip on the losing branch and the durable store
    /// byte-identical. The wrong state is NEVER adopted (abort-only, fail-safe).
    #[tokio::test]
    async fn flagged_residual_cold_base_snapshot_reorg_is_fail_safe() {
        const CBN: [u8; 20] = [0x44; 20];
        let vrf_b = [0x5B; 32];

        // Producers: a1 (coinbase CB) is the fork point; branches credit CBN.
        let pa = Arc::new(Executor::new(Arc::new(StateDB::new())));
        let a1 = produce_cb(&pa, Hash::default(), 1, VRF_OUT, CB).await;
        let a2 = produce_cb(&pa, a1.header.block_hash, 2, VRF_OUT, CBN).await;
        let pb = Arc::new(Executor::new(Arc::new(StateDB::new())));
        let _b1 = produce_cb(&pb, Hash::default(), 1, VRF_OUT, CB).await;
        let b2 = produce_cb(&pb, a1.header.block_hash, 2, vrf_b, CBN).await;
        let b3 = produce_cb(&pb, b2.header.block_hash, 3, vrf_b, CBN).await;

        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let victim = store_backed(&storage);
        let mut app = CanonicalApplicator::new(victim.clone(), storage.clone());
        persist(&storage, &a1);
        assert!(matches!(app.apply_received(&a1).await, ApplyOutcome::Applied { .. }), "a1");
        persist(&storage, &a2);
        assert!(matches!(app.apply_received(&a2).await, ApplyOutcome::Applied { .. }), "a2");

        let a_tip = app.applied_tip().await;
        assert_eq!(a_tip.height, 2, "victim on losing branch A");
        let pre_dump = dump_store(&storage);

        // Inject the flagged condition: replace the fork-point (a1, height 1) ring
        // snapshot with a COLD/incomplete one that lacks the accounts the winning
        // branch will read. A production node CANNOT reach this state (boot eagerly
        // loads every persisted account via get_all_accounts, so every ring snapshot
        // is complete) — we force it to exercise the fail-safe path directly.
        let cold = Executor::new(Arc::new(StateDB::new()));
        {
            let lock = app.advance_lock();
            let mut st = lock.lock().await;
            st.snapshots.insert(1, (a1.header.block_hash, cold.state_snapshot()));
        }

        // Deliver the heavier winning branch B.
        persist(&storage, &b2);
        persist(&storage, &b3);
        app.fork_choice = Some(fork_choice_returning(b3.header.block_hash));
        let outcome = app.apply_received(&b3).await;

        // FAIL-SAFE: the reorg ABORTS (never adopts the wrong state).
        assert!(
            matches!(outcome, ApplyOutcome::Deferred | ApplyOutcome::Rejected(_)),
            "cold-base reorg must NOT be accepted; got {outcome:?}"
        );
        assert_eq!(app.applied_tip().await, a_tip, "wrong state NOT adopted — tip stays on branch A");
        assert_ne!(app.applied_tip().await.hash, b3.header.block_hash, "winning tip was NOT adopted");
        // The durable store, read COLD, is byte-identical to before the attempt.
        assert_eq!(dump_store(&storage), pre_dump, "aborted cold-base reorg left the durable store byte-identical");
    }
}
