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

use citrate_consensus::types::{Block, Hash};
use citrate_economics::{RewardCalculator, RewardConfig};
use citrate_execution::types::ExecutionError;
use citrate_execution::Executor;
use citrate_storage::StorageManager;
use primitive_types::U256;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Treasury address that receives the treasury slice of each block reward.
/// Mirrors `producer.rs::apply_basic_rewards` and `RewardConfig.treasury_address`.
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

/// Execute-on-receive driver. Owns the shared applied-tip lock and the
/// deterministic reward calculator; drives `Executor::apply_block`.
pub struct CanonicalApplicator {
    executor: Arc<Executor>,
    storage: Arc<StorageManager>,
    reward_calculator: RewardCalculator,
    /// Serializes state advancement (see module docs). The value under the lock
    /// is the current applied tip.
    lock: Arc<Mutex<AppliedTip>>,
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
        Self {
            executor,
            storage,
            reward_calculator: RewardCalculator::new(canonical_reward_config()),
            lock: Arc::new(Mutex::new(tip)),
        }
    }

    /// The shared state-advance lock. The producer acquires this across its own
    /// execute→persist critical section so production never races the receive
    /// path, and updates the tip inline via [`record_produced`] before release.
    pub fn advance_lock(&self) -> Arc<Mutex<AppliedTip>> {
        self.lock.clone()
    }

    /// Current applied tip (locks briefly).
    pub async fn applied_tip(&self) -> AppliedTip {
        *self.lock.lock().await
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
    async fn drain_forward(&self, tip: &mut AppliedTip) -> DrainOutcome {
        let mut applied: Vec<Hash> = Vec::new();
        loop {
            let block = match self.next_persisted_extension(tip) {
                Ok(Some(b)) => b,
                Ok(None) => break,
                Err(()) => {
                    debug!(
                        "execute-on-receive: fork above applied tip {} @ {} — deferring to reorg (step 4)",
                        tip.hash, tip.height
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
                    *tip = AppliedTip { hash: block_hash, height };
                    self.persist_applied(&block_hash, height, &block.state_root);
                    applied.push(block_hash);
                    info!(
                        "execute-on-receive: applied block {} @ height {} (root verified)",
                        block_hash, height
                    );
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

    /// Apply a received, DAG-admitted block, extending the applied tip as far as
    /// the persisted selected chain allows.
    ///
    /// Common case (step 2): the block directly extends the tip → applied +
    /// state-root-verified. Out-of-order case (step 3, gap-extend): the block
    /// arrived ahead of its intermediates and was deferred; a later arrival fills
    /// the gap and this drain cascades the whole suffix (including this block). A
    /// bad `state_root` anywhere on the drained chain is rejected with world state
    /// left byte-identical (revert inside `apply_block`).
    ///
    /// The outcome is classified for the RECEIVED block: `Applied` iff the drain
    /// executed it; `Rejected` iff the drain reached and rejected exactly it;
    /// otherwise `Deferred` (still ahead of the applied chain, or stuck behind a
    /// rejected ancestor).
    pub async fn apply_received(&self, block: &Block) -> ApplyOutcome {
        let mut tip = self.lock.lock().await;

        let block_hash = block.header.block_hash;
        let height = block.header.height;

        // Echo of our own tip, or an already-applied / stale block.
        if block_hash == tip.hash || height <= tip.height {
            return ApplyOutcome::AlreadyApplied;
        }

        let out = self.drain_forward(&mut tip).await;

        if out.applied.contains(&block_hash) {
            ApplyOutcome::Applied {
                root: block.state_root,
                height,
            }
        } else if let Some((bad, why)) = &out.rejected {
            if *bad == block_hash {
                ApplyOutcome::Rejected(format!("{bad}: {why}"))
            } else {
                // This block sits beyond a rejected ancestor — cannot apply until
                // fork-choice routes around the bad block (step 4).
                ApplyOutcome::Deferred
            }
        } else {
            if !out.applied.is_empty() {
                debug!(
                    "execute-on-receive: extended tip to {} @ {} ({} block(s)); {} still deferred",
                    tip.hash,
                    tip.height,
                    out.applied.len(),
                    block_hash
                );
            }
            ApplyOutcome::Deferred
        }
    }
}

/// Result of draining the applied tip forward (private to the driver). Always
/// reports the blocks applied (in order); `rejected` names the first block that
/// failed verification, if any (blocks in `applied` are valid + committed).
struct DrainOutcome {
    applied: Vec<Hash>,
    rejected: Option<(Hash, String)>,
}

/// Update the applied tip to a block the producer just authored (executed +
/// persisted itself). Called by the producer WHILE it holds `advance_lock()`,
/// so it takes the already-held guard rather than re-locking (the tokio Mutex
/// is not reentrant). Persists the pointer for crash recovery.
pub fn record_produced(
    guard: &mut AppliedTip,
    storage: &StorageManager,
    block: &Block,
) {
    let hash = block.header.block_hash;
    let height = block.header.height;
    *guard = AppliedTip { hash, height };
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
    use citrate_consensus::types::{BlockBuilder, VrfProof};
    use citrate_execution::revm_adapter::BlockContext;
    use citrate_execution::types::Address;
    use citrate_execution::StateDB;
    use citrate_storage::pruning::PruningConfig;

    const CB: [u8; 20] = [0x33; 20];
    const VRF_OUT: [u8; 32] = [0x5A; 32];

    /// Build an empty (reward-only) v2 block. Transactions are exercised by the
    /// executor's own `apply_block` tests; here we isolate the DRIVER: fast-path
    /// decision, deterministic reward reproduction, pointer advance, and revert.
    fn mk_block(height: u64, parent: Hash, state_root: Hash) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(CB)
            .timestamp(1000)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new(VRF_OUT),
            })
            .transactions(vec![])
            .state_root(state_root)
            .build_unhashed();
        b.header.block_hash = b.compute_hash();
        b
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
}
