//! Operator rollback: cut a stopped node's stored chain back to a height.
//!
//! `citrate rollback --to-height H --keep <hash>` removes every stored block
//! above `H`, and every other block at `H`, from the chain store, the
//! persistent DAG store and the transaction index (the same removal the
//! start-up rejoin check uses, see `hardening_rejoin`). The block kept at `H`
//! is named by hash, so the command cannot cut to the wrong branch.
//!
//! The removed branch still exists on other machines, which could offer it
//! again. So the blocks that were stored directly above the cut (and any
//! sibling of the kept block) are recorded as withdrawn in the database, and
//! [`crate::admission::BlockAdmission`] refuses them, and every block built on
//! them, from then on. Nothing above the cut can be re-admitted: every block
//! above `H` descends from a block at `H + 1`.
//!
//! State: the durable world state is a flat latest-state store and cannot be
//! rewound. When the applied tip is at or below `H` and on the kept block's
//! chain (a node that was replaying from genesis when it was stopped), the
//! state is untouched and the node's drain applies the remaining blocks up to
//! `H` after the restart. When the applied tip is above `H` the command
//! refuses unless `--rebuild-state` is given; the applied-tip pointer is then
//! left on the removed block, and the start-up recovery rebuilds state from
//! genesis along the kept chain (the `hardening_rejoin` semantics).
//!
//! The node must be stopped: this opens the data directory directly.

use std::collections::HashSet;

use anyhow::{anyhow, bail, Context};
use citrate_consensus::types::{Hash, Transaction};
use citrate_storage::db::column_families::{CF_DAG_FINALIZED, CF_METADATA};
use citrate_storage::StorageManager;

/// Withdrawn block hashes, concatenated 32-byte values, in `CF_METADATA`.
const WITHDRAWN_KEY: &[u8] = b"operator_withdrawn_blocks";

/// Parse a 32-byte block hash written as hex, with or without `0x`.
pub fn parse_hash(s: &str) -> anyhow::Result<Hash> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).with_context(|| format!("not a hex block hash: {s}"))?;
    if bytes.len() != 32 {
        bail!("a block hash is 32 bytes, got {} ({s})", bytes.len());
    }
    Hash::try_from_bytes(&bytes).ok_or_else(|| anyhow!("not a block hash: {s}"))
}

/// The withdrawn block hashes recorded in this database (empty when none).
pub fn load_withdrawn(storage: &StorageManager) -> HashSet<Hash> {
    let Ok(Some(v)) = storage.db.get_cf(CF_METADATA, WITHDRAWN_KEY) else {
        return HashSet::new();
    };
    v.chunks_exact(32)
        .filter_map(Hash::try_from_bytes)
        .collect()
}

fn store_withdrawn(storage: &StorageManager, set: &HashSet<Hash>) -> anyhow::Result<()> {
    let mut sorted: Vec<&Hash> = set.iter().collect();
    sorted.sort();
    let mut v = Vec::with_capacity(sorted.len().saturating_mul(32));
    for h in sorted {
        v.extend_from_slice(h.as_bytes());
    }
    storage.db.put_cf(CF_METADATA, WITHDRAWN_KEY, &v)
}

/// What a rollback would do; computed without changing anything.
#[derive(Debug)]
pub struct RollbackPlan {
    pub height: u64,
    pub keep: Hash,
    /// Highest stored height before the rollback.
    pub latest: u64,
    /// Every block removed: all above `height`, and the other blocks at it.
    pub remove: HashSet<Hash>,
    /// Blocks recorded as withdrawn: the removed blocks at `height + 1` and at
    /// `height`, plus any given with `--deny`.
    pub withdraw: HashSet<Hash>,
    /// The applied tip before the rollback.
    pub applied: Option<(Hash, u64)>,
    /// The applied state survives: the applied tip is at or below `height` on
    /// the kept block's chain.
    pub state_kept: bool,
}

/// Work out the rollback to `height`, keeping `keep` there.
pub fn plan(
    storage: &StorageManager,
    height: u64,
    keep: Hash,
    extra_withdraw: &[Hash],
) -> anyhow::Result<RollbackPlan> {
    let latest = storage.blocks.get_latest_height()?;
    let stored = storage.blocks.hashes_in_height_range(height, u64::MAX)?;
    if !stored.iter().any(|(h, hash)| *h == height && *hash == keep) {
        bail!("block {} is not stored at height {height}", keep.to_hex());
    }
    let mut remove = HashSet::new();
    let mut withdraw: HashSet<Hash> = extra_withdraw.iter().copied().collect();
    for (h, hash) in stored {
        if hash == keep {
            continue;
        }
        remove.insert(hash);
        if h <= height.saturating_add(1) {
            withdraw.insert(hash);
        }
    }
    withdraw.remove(&keep);

    let applied = storage.blocks.get_applied_tip()?;
    let state_kept = match applied {
        None => true,
        Some((hash, h)) => {
            h <= height && !remove.contains(&hash) && on_chain_of(storage, keep, hash, h)?
        }
    };
    Ok(RollbackPlan {
        height,
        keep,
        latest,
        remove,
        withdraw,
        applied,
        state_kept,
    })
}

/// Whether `ancestor` (at `ancestor_height`) is on `head`'s selected-parent chain.
fn on_chain_of(
    storage: &StorageManager,
    head: Hash,
    ancestor: Hash,
    ancestor_height: u64,
) -> anyhow::Result<bool> {
    let mut cursor = head;
    loop {
        if cursor == ancestor {
            return Ok(true);
        }
        let header = storage
            .blocks
            .get_header(&cursor)?
            .ok_or_else(|| anyhow!("block {} on the kept chain is not stored", cursor.to_hex()))?;
        if header.height <= ancestor_height || header.height == 0 {
            return Ok(false);
        }
        cursor = header.selected_parent_hash;
    }
}

/// What a rollback did.
#[derive(Debug)]
pub struct RollbackReport {
    pub removed: usize,
    pub latest: u64,
    pub withdrawn: usize,
    /// Transactions only the removed blocks carried (their records are gone).
    pub dropped_txs: Vec<Transaction>,
    pub state_kept: bool,
}

/// Carry out `plan`. Refuses when the applied state is built on a removed
/// block, unless `rebuild_state` is set (see the module docs).
pub fn apply(
    storage: &StorageManager,
    plan: &RollbackPlan,
    rebuild_state: bool,
) -> anyhow::Result<RollbackReport> {
    if !plan.state_kept && !rebuild_state {
        let (hash, h) = plan.applied.unwrap_or_default();
        bail!(
            "the applied state is at block {} @ {h}, which is above height {} or not on the kept \
             chain; it cannot be rewound in place. Re-run with --rebuild-state to have the node \
             rebuild its state from genesis at the next start",
            hash.to_hex(),
            plan.height
        );
    }

    // Records of transactions included only by removed blocks.
    let mut dropped_txs = Vec::new();
    let mut seen: HashSet<Hash> = HashSet::new();
    for hash in &plan.remove {
        if let Some(block) = storage.blocks.get_block(hash)? {
            for tx in block.transactions {
                let included_here = storage
                    .transactions
                    .get_receipt(&tx.hash)?
                    .is_some_and(|r| plan.remove.contains(&r.block_hash));
                if included_here {
                    storage.transactions.delete_transaction(&tx.hash)?;
                }
                if seen.insert(tx.hash) {
                    dropped_txs.push(tx);
                }
            }
        }
    }

    // Withdraw first: if anything below fails, the node still refuses the branch.
    let mut withdrawn = load_withdrawn(storage);
    withdrawn.extend(plan.withdraw.iter().copied());
    store_withdrawn(storage, &withdrawn)?;

    let kv = crate::persistent_dag::RocksDbKvStore::new(storage.db.clone());
    citrate_consensus::dag_store::DagStore::purge_persisted_blocks(&kv, &plan.remove)
        .map_err(|e| anyhow!("DAG store purge: {e}"))?;
    for hash in &plan.remove {
        storage.db.delete_cf(CF_DAG_FINALIZED, hash.as_bytes())?;
    }
    let latest = storage.blocks.purge_blocks(&plan.remove)?;
    if latest != plan.height {
        bail!(
            "after the rollback the highest stored block is at {latest}, expected {}",
            plan.height
        );
    }
    Ok(RollbackReport {
        removed: plan.remove.len(),
        latest,
        withdrawn: withdrawn.len(),
        dropped_txs,
        state_kept: plan.state_kept,
    })
}

/// `citrate rollback`: print the plan, then carry it out unless `dry_run`.
pub fn run(
    storage: &StorageManager,
    data_dir: &std::path::Path,
    height: u64,
    keep: &str,
    withdraw: &[String],
    dry_run: bool,
    rebuild_state: bool,
) -> anyhow::Result<()> {
    let keep = parse_hash(keep)?;
    let extra = withdraw
        .iter()
        .map(|s| parse_hash(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let p = plan(storage, height, keep, &extra)?;
    println!("data directory: {}", data_dir.display());
    println!("highest stored height: {}", p.latest);
    println!("keep: {} @ {}", p.keep.to_hex(), p.height);
    println!("remove: {} block(s) above it or beside it", p.remove.len());
    let mut withdraw: Vec<&Hash> = p.withdraw.iter().collect();
    withdraw.sort();
    println!("refuse from peers from now on ({}):", withdraw.len());
    for h in withdraw {
        println!("  0x{}", h.to_hex());
    }
    match p.applied {
        Some((hash, h)) => println!(
            "applied state: 0x{} @ {h} — {}",
            hash.to_hex(),
            if p.state_kept {
                "kept; the node applies the remaining blocks up to the cut after it starts"
            } else {
                "built on a removed block; rebuilt from genesis at the next start"
            }
        ),
        None => println!("applied state: none recorded"),
    }
    if dry_run {
        println!("dry run: nothing changed");
        return Ok(());
    }
    let r = apply(storage, &p, rebuild_state)?;
    println!(
        "done: removed {} block(s); highest stored height is now {}; {} block(s) refused from peers",
        r.removed, r.latest, r.withdrawn
    );
    if !r.state_kept {
        println!("the applied state was built on a removed block: the node rebuilds it from genesis when it starts");
    }
    if !r.dropped_txs.is_empty() {
        println!(
            "{} transaction(s) were only in removed blocks and are no longer recorded:",
            r.dropped_txs.len()
        );
        for tx in &r.dropped_txs {
            println!("  0x{}", tx.hash.to_hex());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::AdmitOutcome;
    use crate::canonical_apply::AppliedTip;
    use crate::hardening_rejoin::tests::{genesis, open, produce};
    use citrate_consensus::hardening::PbaHardening;
    use citrate_consensus::types::Block;
    use citrate_execution::{Executor, StateDB};
    use std::sync::Arc;

    const CB_FLEET: [u8; 20] = [0xF1; 20];
    const CB_OTHER: [u8; 20] = [0x0C; 20];

    /// A chain of `n` blocks on genesis from one producer.
    fn chain(n: u64, coinbase: [u8; 20], vrf: u8) -> (Vec<Block>, Executor) {
        let exec = Executor::new(Arc::new(StateDB::new()));
        let mut out = Vec::new();
        let mut parent = genesis().header.block_hash;
        for h in 1..=n {
            let b = produce(
                &exec,
                PbaHardening::off(),
                h,
                parent,
                coinbase,
                vrf.wrapping_add(h as u8),
            );
            parent = b.header.block_hash;
            out.push(b);
        }
        (out, exec)
    }

    /// Extend `base[..=fork]` with `n` blocks from another producer.
    fn branch(base: &[Block], fork: usize, n: u64, coinbase: [u8; 20], vrf: u8) -> Vec<Block> {
        let exec = Executor::new(Arc::new(StateDB::new()));
        let mut parent = genesis().header.block_hash;
        for b in &base[..=fork] {
            let r = produce(
                &exec,
                PbaHardening::off(),
                b.header.height,
                parent,
                CB_FLEET,
                0x40 + b.header.height as u8,
            );
            assert_eq!(
                r.header.block_hash, b.header.block_hash,
                "replays the shared prefix"
            );
            parent = r.header.block_hash;
        }
        let mut out = Vec::new();
        let start = base[fork].header.height;
        for h in start + 1..=start + n {
            let b = produce(
                &exec,
                PbaHardening::off(),
                h,
                parent,
                coinbase,
                vrf.wrapping_add(h as u8),
            );
            parent = b.header.block_hash;
            out.push(b);
        }
        out
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rollback_removes_the_branch_keeps_state_and_refuses_it_afterwards() {
        // Fleet chain 1..=8, and another producer's branch 6..=10 forking off block 5.
        let (fleet, _) = chain(8, CB_FLEET, 0x40);
        let other = branch(&fleet, 4, 5, CB_OTHER, 0x70);
        let dir = tempfile::tempdir().expect("dir");
        {
            let (n, _) = open(dir.path(), PbaHardening::off(), false).await;
            // A node that has applied up to 3 and stored everything else.
            for b in &fleet[..3] {
                assert!(matches!(n.receive(b).await, AdmitOutcome::Admitted { .. }));
            }
            assert_eq!(n.tip().await.height, 3);
        }
        {
            // Stored in both stores but not applied: a node replaying when it was stopped.
            let storage = StorageManager::new(
                dir.path(),
                citrate_storage::pruning::PruningConfig::default(),
            )
            .expect("storage");
            let kv = Arc::new(crate::persistent_dag::RocksDbKvStore::new(
                storage.db.clone(),
            ));
            let dag = citrate_consensus::dag_store::DagStore::persistent_with_strict_vrf(kv, false)
                .expect("dag");
            dag.set_configured_genesis(genesis().header.block_hash);
            for b in fleet[3..].iter().chain(other.iter()) {
                dag.store_block(b.clone()).await.expect("dag store");
                storage.blocks.put_block(b).expect("chain store");
            }
            assert_eq!(storage.blocks.get_latest_height().expect("latest"), 10);
            assert_eq!(
                storage.blocks.get_applied_tip().expect("tip"),
                Some((fleet[2].header.block_hash, 3))
            );
        }

        // Roll back to 5, keeping the fleet's block 5.
        let keep = fleet[4].header.block_hash;
        {
            let storage = StorageManager::new(
                dir.path(),
                citrate_storage::pruning::PruningConfig::default(),
            )
            .expect("storage");
            let p = plan(&storage, 5, keep, &[]).expect("plan");
            assert!(
                p.state_kept,
                "applied tip 3 is below the cut, on the kept chain"
            );
            assert_eq!(
                p.remove.len(),
                3 + 5,
                "fleet 6..=8 and the other branch 6..=10"
            );
            let withdrawn: HashSet<Hash> =
                [fleet[5].header.block_hash, other[0].header.block_hash].into();
            assert_eq!(p.withdraw, withdrawn, "the blocks directly above the cut");
            let r = apply(&storage, &p, false).expect("apply");
            assert_eq!(r.latest, 5);
            for b in fleet[5..].iter().chain(other.iter()) {
                assert!(!storage
                    .blocks
                    .has_block(&b.header.block_hash)
                    .expect("read"));
            }
            assert_eq!(
                storage.blocks.get_applied_tip().expect("tip"),
                Some((fleet[2].header.block_hash, 3)),
                "the applied tip is untouched"
            );
        }

        // Restart: the drain applies 4..=5, and the removed branch stays out.
        let (n, _) = open(dir.path(), PbaHardening::off(), false).await;
        assert_eq!(n.ghostdag.select_tip().await.expect("head"), keep);
        assert!(
            n.app.applied_tip_is_ancestor_of(keep).await,
            "behind the head on its chain: start-up leaves it to the drain, no rebuild"
        );
        assert!(
            !n.app
                .applied_tip_is_ancestor_of(other[4].header.block_hash)
                .await
        );
        n.app.drive_drain().await;
        assert_eq!(
            n.tip().await,
            AppliedTip {
                hash: keep,
                height: 5
            }
        );
        assert_eq!(n.exec.calculate_state_root(), fleet[4].state_root);
        for b in &other {
            assert!(
                matches!(n.receive(b).await, AdmitOutcome::Rejected(_)),
                "withdrawn branch block {} refused",
                b.header.height
            );
        }
        assert!(matches!(
            n.receive(&fleet[5]).await,
            AdmitOutcome::Rejected(_)
        ));
        assert!(!n
            .storage
            .blocks
            .has_block(&other[4].header.block_hash)
            .expect("read"));

        // The fleet producer seals a new block 6 on the kept block 5.
        let exec = Executor::new(Arc::new(StateDB::new()));
        let mut parent = genesis().header.block_hash;
        for b in &fleet[..5] {
            let r = produce(
                &exec,
                PbaHardening::off(),
                b.header.height,
                parent,
                CB_FLEET,
                0x40 + b.header.height as u8,
            );
            parent = r.header.block_hash;
        }
        let new6 = produce(&exec, PbaHardening::off(), 6, parent, CB_FLEET, 0x99);
        assert_ne!(new6.header.block_hash, fleet[5].header.block_hash);
        assert!(matches!(
            n.receive(&new6).await,
            AdmitOutcome::Admitted { .. }
        ));
        n.app.drive_drain().await;
        assert_eq!(n.tip().await.height, 6);
        assert_eq!(n.exec.calculate_state_root(), new6.state_root);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rollback_refuses_a_wrong_keep_block_and_state_above_the_cut() {
        let (fleet, _) = chain(6, CB_FLEET, 0x40);
        let dir = tempfile::tempdir().expect("dir");
        {
            let (n, _) = open(dir.path(), PbaHardening::off(), false).await;
            for b in &fleet {
                assert!(matches!(n.receive(b).await, AdmitOutcome::Admitted { .. }));
            }
            assert_eq!(n.tip().await.height, 6);
        }
        let storage = StorageManager::new(
            dir.path(),
            citrate_storage::pruning::PruningConfig::default(),
        )
        .expect("storage");
        assert!(plan(&storage, 4, fleet[3].header.block_hash, &[]).is_ok());
        assert!(
            plan(&storage, 4, fleet[2].header.block_hash, &[]).is_err(),
            "the kept block must be at the given height"
        );
        let p = plan(&storage, 4, fleet[3].header.block_hash, &[]).expect("plan");
        assert!(!p.state_kept, "applied tip 6 is above the cut");
        assert!(apply(&storage, &p, false).is_err());
        assert!(
            storage
                .blocks
                .has_block(&fleet[5].header.block_hash)
                .expect("read"),
            "a refused rollback changes nothing"
        );
        assert!(load_withdrawn(&storage).is_empty());
        let r = apply(&storage, &p, true).expect("apply with --rebuild-state");
        assert!(!r.state_kept);
        assert_eq!(r.latest, 4);
    }

    #[test]
    fn parses_block_hashes() {
        let h = Hash::new([0xAB; 32]);
        assert_eq!(parse_hash(&format!("0x{}", h.to_hex())).expect("0x"), h);
        assert_eq!(parse_hash(&h.to_hex()).expect("bare"), h);
        assert!(parse_hash("0x1234").is_err());
        assert!(parse_hash("zz").is_err());
    }
}
