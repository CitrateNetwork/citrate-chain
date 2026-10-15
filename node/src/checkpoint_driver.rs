// citrate/node/src/checkpoint_driver.rs
//
// Checkpoint finality, Stage 1, first slice: PRODUCTION PROPOSE.
//
// Design: docs/consensus/CHECKPOINT_FINALITY_WIRING.md (§4.1 committee, §4.2
// propose, §11.6 epoch-pinned committee, §11.9 pruning). Slice plan:
// docs/consensus/CHECKPOINT_FINALITY_STAGE1_SLICES.md.
//
// What this does: once the applied tip is CHECKPOINT_CONFIRMATION_DEPTH blocks
// past a checkpoint boundary H, every node proposes the checkpoint for the
// canonical block at H, with the committee derived from the validator set of
// the snapshot that governs H. That creates the pending checkpoint the inbound
// vote handler (main.rs, NetworkMessage::CheckpointVote) attaches votes to.
//
// What this does NOT do (later slices): sign or broadcast a local vote, buffer
// early votes, relay votes, fetch certificates while syncing, or enforce the
// finalized floor. Nothing in production signs a vote yet, so no checkpoint can
// finalize and `latest_finalized_height()` stays 0. Off unless
// CITRATE_CHECKPOINT_FINALITY=1.

// PANIC-S1 G2: consensus-adjacent node path (T1); panic-free outside tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use citrate_consensus::checkpoint::{
    checkpoint_to_propose, CheckpointError, CheckpointManager, CommitteeSelector,
    CHECKPOINT_CONFIRMATION_DEPTH,
};
use citrate_consensus::types::PublicKey;
use citrate_storage::StorageManager;
use tracing::{debug, info, warn};

/// Opt-in switch for Stage 1 (WIRING §9). Off by default.
pub const ENABLE_ENV: &str = "CITRATE_CHECKPOINT_FINALITY";

/// How many checkpoint intervals of pending proposals to keep below the newest.
/// Older ones can no longer gather a useful quorum and are dropped (§11.9).
pub const PENDING_KEEP_INTERVALS: u64 = 16;

/// Whether Stage 1 proposing is switched on for this process.
pub fn enabled() -> bool {
    std::env::var(ENABLE_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// What one pass did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No boundary is buried deep enough yet.
    NothingDue,
    /// The due checkpoint was already proposed.
    AlreadyProposed(u64),
    /// Proposed the checkpoint at `height` with this committee.
    Proposed {
        height: u64,
        committee: Vec<PublicKey>,
    },
    /// No durable validator-set snapshot governs `height` on this node
    /// (below the first snapshot, or not materialised); nothing to propose.
    NoCommittee { height: u64 },
    /// The canonical block at `height` is not readable here yet.
    NoBlock { height: u64 },
}

/// Proposes checkpoints from the applied canonical chain.
pub struct CheckpointDriver {
    storage: Arc<StorageManager>,
    manager: Arc<CheckpointManager>,
    last_proposed: AtomicU64,
}

impl CheckpointDriver {
    pub fn new(storage: Arc<StorageManager>, manager: Arc<CheckpointManager>) -> Self {
        Self {
            storage,
            manager,
            last_proposed: AtomicU64::new(0),
        }
    }

    /// The committee for the checkpoint at `height`: `CommitteeSelector::select`
    /// over the validator set of the snapshot S(E) that governs `height` (the
    /// greatest S(E) < height, the same snapshot the executor settles that block
    /// against), seeded by the VRF output of the block at `height`. Every input
    /// is fixed by `height` and the canonical chain, so every node that applied
    /// that chain derives the same committee (§4.1, §11.6). Data source: the
    /// durable per-epoch snapshot (`block_store.get_reward_snapshot_at`) and the
    /// chain store.
    fn committee_for(
        &self,
        height: u64,
        seed: &citrate_consensus::types::Hash,
    ) -> Option<Vec<PublicKey>> {
        let snapshot = crate::registry_sync::greatest_snapshot_at(height.checked_sub(1)?)?;
        let blob = match self.storage.blocks.get_reward_snapshot_at(snapshot) {
            Ok(Some(blob)) => blob,
            Ok(None) => return None,
            Err(e) => {
                warn!("checkpoint: reading snapshot S({snapshot}) failed: {e}");
                return None;
            }
        };
        let (policy, entries, _min_stake) =
            match crate::registry_sync::decode_reward_snapshot(&blob) {
                Ok(decoded) => decoded,
                Err(e) => {
                    warn!("checkpoint: snapshot S({snapshot}) failed to decode: {e}");
                    return None;
                }
            };
        if policy.snapshot_height != snapshot {
            return None;
        }
        let set: Vec<(PublicKey, u128)> = entries
            .into_iter()
            .map(|(pk, stake)| (PublicKey::new(pk), stake))
            .collect();
        Some(CommitteeSelector::select(
            &set,
            height,
            seed,
            self.manager.config().committee_size,
        ))
    }

    /// One pass at applied height `applied_height`.
    pub async fn drive_once(&self, applied_height: u64) -> Outcome {
        let interval = self.manager.config().interval;
        let Some(height) =
            checkpoint_to_propose(applied_height, interval, CHECKPOINT_CONFIRMATION_DEPTH)
        else {
            return Outcome::NothingDue;
        };
        if height <= self.last_proposed.load(Ordering::SeqCst) {
            return Outcome::AlreadyProposed(height);
        }

        let block = match self.storage.blocks.get_block_by_height(height) {
            Ok(Some(hash)) => match self.storage.blocks.get_block(&hash) {
                Ok(Some(block)) => block,
                _ => return Outcome::NoBlock { height },
            },
            _ => return Outcome::NoBlock { height },
        };
        let block_hash = block.hash();
        let Some(committee) = self.committee_for(height, &block.header.vrf_reveal.output) else {
            debug!("checkpoint: no validator-set snapshot governs {height}; not proposing");
            return Outcome::NoCommittee { height };
        };

        match self
            .manager
            .propose(height, block_hash, committee.clone())
            .await
        {
            Ok(()) => {
                info!(
                    "checkpoint: proposed {height} ({block_hash}), committee of {}",
                    committee.len()
                );
            }
            Err(CheckpointError::AlreadyExists(_)) => {
                self.last_proposed.store(height, Ordering::SeqCst);
                return Outcome::AlreadyProposed(height);
            }
            Err(e) => {
                warn!("checkpoint: propose {height} failed: {e}");
                return Outcome::NoBlock { height };
            }
        }
        self.last_proposed.store(height, Ordering::SeqCst);
        let keep_from = height.saturating_sub(interval.saturating_mul(PENDING_KEEP_INTERVALS));
        self.manager.prune_below(keep_from).await;
        Outcome::Proposed { height, committee }
    }
}

/// Spawn the Stage 1 propose loop. No-op (no task) unless [`ENABLE_ENV`] is set.
pub fn spawn(storage: Arc<StorageManager>, manager: Arc<CheckpointManager>) {
    if !enabled() {
        debug!("checkpoint: Stage 1 propose loop off (set {ENABLE_ENV}=1)");
        return;
    }
    info!(
        "checkpoint: Stage 1 propose loop ON (interval {}, depth {}). No local vote is \
         signed yet, so nothing finalizes.",
        manager.config().interval,
        CHECKPOINT_CONFIRMATION_DEPTH
    );
    let driver = CheckpointDriver::new(storage.clone(), manager);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tick.tick().await;
            let applied = storage
                .blocks
                .get_applied_tip()
                .ok()
                .flatten()
                .map(|(_, h)| h)
                .unwrap_or(0);
            driver.drive_once(applied).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::checkpoint::{CheckpointConfig, CheckpointStatus};
    use citrate_consensus::dag_store::DagStore;
    use citrate_consensus::types::{BlockBuilder, Hash, VrfProof};
    use citrate_execution::block_rewards::EpochRewardPolicy;
    use citrate_storage::pruning::PruningConfig;
    use primitive_types::U256;

    fn mk(height: u64, parent: Hash) -> citrate_consensus::types::Block {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&height.to_be_bytes());
        out[31] = 0x5A;
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase([0x33; 20])
            .timestamp(1000)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new(out),
            })
            .transactions(vec![])
            .state_root(Hash::default())
            .blue_score(height)
            .blue_work(citrate_consensus::types::blue_work_for_score(height))
            .build_unhashed();
        b.header.block_hash = b.compute_hash();
        b
    }

    async fn setup(
        tip: u64,
        snapshot: Option<Vec<([u8; 32], u128)>>,
    ) -> (
        CheckpointDriver,
        Arc<CheckpointManager>,
        Arc<StorageManager>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let mut parent = Hash::default();
        for h in 0..=tip {
            let b = mk(h, parent);
            parent = b.header.block_hash;
            dag.store_block(b.clone()).await.expect("dag");
            storage.blocks.put_block(&b).expect("chain");
        }
        if let Some(entries) = snapshot {
            let policy = EpochRewardPolicy {
                epoch: 1,
                snapshot_height: 800,
                activation_height: 0,
                registry: [0x99; 20],
                reward_minter: [0x50; 20],
                priority_fee_share_bps: 0,
                block_subsidy: U256::zero(),
                staker_of: std::collections::HashMap::new(),
            };
            let blob = crate::registry_sync::encode_reward_snapshot(&policy, &entries, 32);
            storage
                .blocks
                .put_reward_snapshot_at(800, &blob)
                .expect("snapshot");
        }
        let manager = Arc::new(CheckpointManager::new(
            CheckpointConfig {
                interval: 50,
                committee_size: 100,
                quorum_threshold: 67,
                chain_id: 40204,
            },
            dag,
        ));
        (
            CheckpointDriver::new(storage.clone(), manager.clone()),
            manager,
            storage,
            dir,
        )
    }

    fn validators() -> Vec<([u8; 32], u128)> {
        (1u8..=5).map(|i| ([i; 32], 32 * u128::from(i))).collect()
    }

    /// The first wired slice: at a buried boundary the node proposes the
    /// checkpoint for the canonical block, with the committee derived from the
    /// governing snapshot's set and the block's own VRF output.
    #[tokio::test]
    async fn stage1_proposes_the_buried_boundary_with_the_epoch_committee() {
        let (driver, manager, storage, _dir) = setup(903, Some(validators())).await;
        let outcome = driver.drive_once(903).await;

        let hash = storage
            .blocks
            .get_block_by_height(900)
            .expect("read")
            .expect("canonical block at 900");
        let block = storage
            .blocks
            .get_block(&hash)
            .expect("read")
            .expect("block");
        let set: Vec<(PublicKey, u128)> = validators()
            .into_iter()
            .map(|(pk, s)| (PublicKey::new(pk), s))
            .collect();
        let expected = CommitteeSelector::select(&set, 900, &block.header.vrf_reveal.output, 100);
        assert_eq!(
            outcome,
            Outcome::Proposed {
                height: 900,
                committee: expected
            }
        );
        assert_eq!(
            manager.checkpoint_status(900).await,
            Some(CheckpointStatus::Pending)
        );
        // Idempotent, and inert: no local vote is signed, so nothing finalizes.
        assert_eq!(driver.drive_once(904).await, Outcome::AlreadyProposed(900));
        assert_eq!(manager.latest_finalized_height().await, 0);
    }

    /// Not deep enough yet: the tip block (or one within depth D) is never proposed.
    #[tokio::test]
    async fn stage1_never_proposes_within_the_confirmation_depth() {
        let (driver, manager, _storage, _dir) = setup(902, Some(validators())).await;
        // 900 is only 2 deep at 902, so the newest buried boundary is 850.
        assert!(matches!(
            driver.drive_once(902).await,
            Outcome::Proposed { height: 850, .. }
        ));
        assert!(
            manager.checkpoint_status(900).await.is_none(),
            "900 is only 2 deep"
        );
    }

    /// No governing snapshot on this node: no committee, no proposal.
    #[tokio::test]
    async fn stage1_without_a_governing_snapshot_does_not_propose() {
        let (driver, manager, _storage, _dir) = setup(903, None).await;
        assert_eq!(
            driver.drive_once(903).await,
            Outcome::NoCommittee { height: 900 }
        );
        assert!(manager.checkpoint_status(900).await.is_none());
    }
}
