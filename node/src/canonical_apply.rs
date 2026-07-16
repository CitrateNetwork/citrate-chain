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
use tracing::{info, warn};

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

    /// Fast-path apply of a received, DAG-admitted block.
    ///
    /// If the block linearly extends the applied tip (`selected_parent ==
    /// applied_tip.hash` and `height == applied_tip.height + 1`), execute it,
    /// verify its `state_root`, and advance the persisted pointer on success.
    /// Otherwise defer (gap/fork) or reject (bad root). Never advances state on
    /// a non-extending or invalid block.
    pub async fn apply_received(&self, block: &Block) -> ApplyOutcome {
        let mut tip = self.lock.lock().await;

        let block_hash = block.header.block_hash;
        let height = block.header.height;

        // Already applied (echo of our own tip, or an old block).
        if block_hash == tip.hash || height <= tip.height {
            return ApplyOutcome::AlreadyApplied;
        }

        // Fast path only: a direct linear extension of the applied tip.
        if block.selected_parent() != tip.hash || height != tip.height + 1 {
            return ApplyOutcome::Deferred;
        }

        let credits = self.reward_credits(block);
        match self
            .executor
            .apply_block(block, block.header.coinbase, &credits)
            .await
        {
            Ok(root) => {
                // Advance the pointer atomically with the successful apply
                // (still under the lock). Persist for crash recovery.
                *tip = AppliedTip {
                    hash: block_hash,
                    height,
                };
                if let Err(e) = self.storage.blocks.put_applied_tip(&block_hash, height) {
                    warn!(
                        "execute-on-receive: applied block {} @ {} but failed to persist tip: {}",
                        block_hash, height, e
                    );
                }
                if let Err(e) = self
                    .storage
                    .state
                    .put_state_root(&block_hash, &block.state_root)
                {
                    warn!(
                        "execute-on-receive: failed to persist state root for {}: {}",
                        block_hash, e
                    );
                }
                info!(
                    "execute-on-receive: applied received block {} @ height {} (root verified)",
                    block_hash, height
                );
                ApplyOutcome::Applied { root, height }
            }
            Err(ExecutionError::StateRootMismatch { expected, got }) => {
                warn!(
                    "execute-on-receive: REJECT block {} @ {} — state root mismatch (claimed {}, computed {})",
                    block_hash, height, expected, got
                );
                ApplyOutcome::Rejected(format!(
                    "state root mismatch: claimed {expected}, computed {got}"
                ))
            }
            Err(e) => {
                warn!(
                    "execute-on-receive: REJECT block {} @ {} — execution error: {}",
                    block_hash, height, e
                );
                ApplyOutcome::Rejected(format!("execution error: {e}"))
            }
        }
    }
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
        let app = CanonicalApplicator::new(exec, storage);

        // Gap ahead: height 3 while the tip is height 0.
        let gap = mk_block(3, Hash::default(), Hash::default());
        assert!(matches!(
            app.apply_received(&gap).await,
            ApplyOutcome::Deferred
        ));

        // Right height, wrong parent (a fork/sibling): height 1, non-genesis parent.
        let fork = mk_block(1, Hash::new([0xAB; 32]), Hash::default());
        assert!(matches!(
            app.apply_received(&fork).await,
            ApplyOutcome::Deferred
        ));

        // Tip never moved.
        assert_eq!(app.applied_tip().await.height, 0);
    }
}
