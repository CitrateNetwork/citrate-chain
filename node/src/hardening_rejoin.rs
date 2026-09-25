//! Rejoining the network after the block-validity hardening activates.
//!
//! A node that kept running an older release past the activation height H
//! stores blocks in the pre-activation format at heights >= H: its own, and
//! any it accepted from peers on the same release. Once it restarts on a
//! release that enforces the rules at H, those blocks are invalid. Left in
//! the store they still feed fork choice (a longer legacy branch outweighs the
//! canonical one) and the node wedges on a head it can never apply.
//!
//! [`purge_invalid_post_activation`] runs at start-up, before the DAG store,
//! GhostDAG and the applier load anything. It checks every stored block at or
//! above H against the rules, and removes each invalid block and all of its
//! descendants from the chain store, the persistent DAG store and the
//! transaction index. The transactions they carried are handed back so the
//! node can offer them to its mempool again.
//!
//! State: the durable world state still reflects the applied tip. If that tip
//! was purged, the applied-tip pointer is left on it on purpose, because the
//! applier's invariant is "the pointer names the block whose state the store
//! holds". The start-up recovery then sees an applied tip that is not the
//! fork-choice head and rebuilds state from genesis along the surviving
//! canonical chain (`CanonicalApplicator::recover_to_head`); sync then fetches
//! the canonical blocks above it from upgraded peers. No manual wipe.
//!
//! [`LegacyFormatPeers`] is the other half: an upgraded node counts the peers
//! that still send pre-activation-format blocks at or after H, so operators
//! can see which nodes have not upgraded.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use citrate_consensus::hardening::{PbaHardening, MAX_BLOCK_TIMESTAMP_ADVANCE_SECS};
use citrate_consensus::tx_auth;
use citrate_consensus::types::{Block, Hash, Transaction};
use citrate_storage::db::column_families::CF_METADATA;
use citrate_storage::StorageManager;
use tracing::{info, warn};

/// Records the activation height and the highest height already checked, so a
/// restart only checks blocks stored since.
const CHECKED_KEY: &[u8] = b"pba_rejoin_checked";

/// What the start-up check found and removed.
#[derive(Debug, Default)]
pub struct RejoinReport {
    /// Blocks at or above the activation height that were checked.
    pub checked: usize,
    /// Blocks removed: invalid under the rules, or descended from one.
    pub purged: HashSet<Hash>,
    /// How many of the invalid blocks were in the pre-activation format.
    pub legacy_format: usize,
    /// The applied tip was purged; state is rebuilt by the start-up recovery.
    pub applied_tip_purged: bool,
    /// Transactions carried by purged blocks, to offer to the mempool again.
    pub returned_txs: Vec<Transaction>,
}

/// A block at or above the activation height whose `tx_root` is the
/// pre-activation root of its transactions. This is how a block from a node
/// on an older release looks (even an empty block's roots differ).
pub fn is_legacy_format(hardening: PbaHardening, block: &Block) -> bool {
    hardening.active_at(block.header.height)
        && block.tx_root != tx_auth::tx_root_v2(&block.transactions)
        && block.tx_root == tx_auth::tx_root_legacy(&block.transactions)
}

/// The activation rules a stored block must satisfy: the admission body gate
/// (hash, content-bound `tx_root`, every transaction authenticated), the
/// execution-side chain binding, and the parent-relative timestamp bound.
fn check_block(
    hardening: PbaHardening,
    chain_id: u64,
    block: &Block,
    parent_ts: Option<u64>,
) -> Result<(), String> {
    if !hardening.active_at(block.header.height) {
        return Ok(());
    }
    crate::admission::verify_block_body(hardening, block)?;
    for (i, tx) in block.transactions.iter().enumerate() {
        tx_auth::verify_for_block(tx, chain_id).map_err(|e| format!("tx #{i}: {e}"))?;
    }
    if let Some(pts) = parent_ts {
        if block.header.timestamp > pts.saturating_add(MAX_BLOCK_TIMESTAMP_ADVANCE_SECS) {
            return Err(format!(
                "timestamp {} more than {}s past its parent's {}",
                block.header.timestamp, MAX_BLOCK_TIMESTAMP_ADVANCE_SECS, pts
            ));
        }
    }
    Ok(())
}

fn read_checked(storage: &StorageManager) -> Option<(u64, u64)> {
    let v = storage.db.get_cf(CF_METADATA, CHECKED_KEY).ok().flatten()?;
    if v.len() != 16 {
        return None;
    }
    let h = u64::from_be_bytes(v[..8].try_into().ok()?);
    let through = u64::from_be_bytes(v[8..].try_into().ok()?);
    Some((h, through))
}

fn write_checked(storage: &StorageManager, activation: u64, through: u64) -> anyhow::Result<()> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&activation.to_be_bytes());
    v.extend_from_slice(&through.to_be_bytes());
    storage.db.put_cf(CF_METADATA, CHECKED_KEY, &v)
}

/// Remove every stored block at or above the activation height that is
/// invalid under the rules, and everything built on it. See the module docs.
/// A no-op when no activation height is set or nothing is stored above it.
pub fn purge_invalid_post_activation(
    storage: &StorageManager,
    hardening: PbaHardening,
    chain_id: u64,
) -> anyhow::Result<RejoinReport> {
    let mut report = RejoinReport::default();
    let Some(activation) = hardening.activation_height() else {
        return Ok(report);
    };
    let latest = storage.blocks.get_latest_height()?;
    // Genesis is never re-judged.
    let mut from = activation.max(1);
    if let Some((h, through)) = read_checked(storage) {
        if h == activation {
            from = from.max(through.saturating_add(1));
        }
    }
    if latest < from {
        return Ok(report);
    }

    let mut candidates = storage.blocks.hashes_in_height_range(from, u64::MAX)?;
    candidates.sort();
    let mut reasons: HashMap<Hash, String> = HashMap::new();
    for (_, hash) in &candidates {
        let Some(block) = storage.blocks.get_block(hash)? else {
            continue;
        };
        report.checked += 1;
        let sp = block.selected_parent();
        let doomed_parent = block
            .parents()
            .into_iter()
            .find(|p| report.purged.contains(p));
        let verdict = match doomed_parent {
            Some(p) => Err(format!("descends from removed block {p}")),
            None => {
                let parent_ts = storage.blocks.get_header(&sp)?.map(|h| h.timestamp);
                check_block(hardening, chain_id, &block, parent_ts)
            }
        };
        if let Err(why) = verdict {
            if is_legacy_format(hardening, &block) {
                report.legacy_format += 1;
            }
            report.purged.insert(*hash);
            reasons.insert(*hash, why);
        }
    }

    if report.purged.is_empty() {
        write_checked(storage, activation, latest)?;
        return Ok(report);
    }

    let applied = storage.blocks.get_applied_tip()?;
    report.applied_tip_purged = applied.is_some_and(|(h, _)| report.purged.contains(&h));

    // Transactions the purged blocks carried: drop their inclusion records
    // (receipts, block index) and return them for the mempool.
    let mut seen: HashSet<Hash> = HashSet::new();
    for hash in &report.purged {
        if let Some(block) = storage.blocks.get_block(hash)? {
            for tx in block.transactions {
                let included_here = storage
                    .transactions
                    .get_receipt(&tx.hash)?
                    .is_some_and(|r| report.purged.contains(&r.block_hash));
                if included_here {
                    storage.transactions.delete_transaction(&tx.hash)?;
                }
                if seen.insert(tx.hash) {
                    report.returned_txs.push(tx);
                }
            }
        }
    }

    let kv = crate::persistent_dag::RocksDbKvStore::new(storage.db.clone());
    citrate_consensus::dag_store::DagStore::purge_persisted_blocks(&kv, &report.purged)
        .map_err(|e| anyhow::anyhow!("DAG store purge: {e}"))?;
    let new_latest = storage.blocks.purge_blocks(&report.purged)?;
    write_checked(storage, activation, new_latest)?;

    for (hash, why) in &reasons {
        info!("removed stored block {hash}: invalid from the activation height ({why})");
    }
    warn!(
        "Removed {} stored block(s) at or above the activation height {} that are invalid under \
         the current rules ({} in the pre-activation format); the latest stored height is now {}. \
         {}",
        report.purged.len(),
        activation,
        report.legacy_format,
        new_latest,
        if report.applied_tip_purged {
            "The applied state was built on them and is rebuilt from genesis along the \
             remaining chain before syncing from peers."
        } else {
            "The applied state was not affected."
        }
    );
    Ok(report)
}

/// The message a node prints when it cannot rewind by itself.
pub fn manual_resync_instructions(data_dir: &std::path::Path, activation: u64) -> String {
    format!(
        "This node's database holds blocks at or above the activation height {activation} that \
         are invalid under this release, and the node cannot rebuild its state automatically in \
         this mode. To rejoin: stop the node, move the data directory {} aside (keep it until \
         the node has resynced), and start the node again; it will sync the chain from peers.",
        data_dir.display()
    )
}

// ---------------------------------------------------------------------------
// Peers still sending pre-activation-format blocks.
// ---------------------------------------------------------------------------

/// Prometheus counter: pre-activation-format blocks received at or after the
/// activation height, labelled by peer.
pub const METRIC_LEGACY_FORMAT_BLOCKS: &str = "citrate_legacy_format_blocks_total";
/// Prometheus gauge: distinct peers seen sending them.
pub const METRIC_LEGACY_FORMAT_PEERS: &str = "citrate_legacy_format_peers";

/// Upper bound on peers tracked individually.
const MAX_TRACKED_PEERS: usize = 4096;

/// Counts, per peer, the blocks received in the pre-activation format at or
/// after the activation height.
#[derive(Default)]
pub struct LegacyFormatPeers {
    counts: Mutex<HashMap<String, u64>>,
}

impl LegacyFormatPeers {
    /// Check one received block. Returns true (and logs and counts it) when
    /// it is a pre-activation-format block at or after the activation height.
    pub fn observe(&self, hardening: PbaHardening, peer: &str, block: &Block) -> bool {
        if !is_legacy_format(hardening, block) {
            return false;
        }
        let (count, peers) = {
            let mut m = self.counts.lock().unwrap_or_else(|e| e.into_inner());
            let tracked = m.contains_key(peer) || m.len() < MAX_TRACKED_PEERS;
            let key = if tracked { peer } else { "other" };
            let c = m.entry(key.to_string()).or_insert(0);
            *c += 1;
            (*c, m.len())
        };
        metrics::counter!(METRIC_LEGACY_FORMAT_BLOCKS, 1, "peer" => peer.to_string());
        metrics::gauge!(METRIC_LEGACY_FORMAT_PEERS, peers as f64);
        if count == 1 || count.is_power_of_two() {
            info!(
                "peer {} sent block {} at height {} in the pre-activation format \
                 ({} such block(s) from this peer so far); the peer may be running an \
                 earlier release",
                peer, block.header.block_hash, block.header.height, count
            );
        }
        true
    }

    /// Blocks counted for `peer`.
    #[cfg(test)]
    pub fn count(&self, peer: &str) -> u64 {
        self.counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer)
            .copied()
            .unwrap_or(0)
    }

    /// Distinct peers counted.
    #[cfg(test)]
    pub fn peers(&self) -> usize {
        self.counts.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{AdmitOutcome, BlockAdmission};
    use crate::canonical_apply::{canonical_reward_config, AppliedTip, CanonicalApplicator};
    use crate::persistent_dag::RocksDbKvStore;
    use citrate_consensus::crypto;
    use citrate_consensus::dag_store::DagStore;
    use citrate_consensus::ghostdag::GhostDag;
    use citrate_consensus::tx_auth::{native_tx_id, tx_root_for_height};
    use citrate_consensus::types::{
        blue_work_for_score, BlockBuilder, GhostDagParams, PublicKey, VrfProof,
    };
    use citrate_economics::RewardCalculator;
    use citrate_execution::revm_adapter::BlockContext;
    use citrate_execution::types::Address;
    use citrate_execution::{Executor, StateDB};
    use citrate_storage::pruning::PruningConfig;
    use primitive_types::U256;
    use std::path::Path;
    use std::sync::Arc;

    const H: u64 = 3;
    const CHAIN: u64 = 40204;
    const CB_UPGRADED: [u8; 20] = [0xA0; 20];
    const CB_STALE: [u8; 20] = [0xC0; 20];

    fn template(
        pba: PbaHardening,
        height: u64,
        parent: Hash,
        coinbase: [u8; 20],
        vrf: u8,
        txs: Vec<Transaction>,
        state_root: Hash,
    ) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(coinbase)
            .timestamp(1_000 + height)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([vrf; 32]),
            })
            .transactions(txs)
            .state_root(state_root)
            .blue_score(height)
            .blue_work(blue_work_for_score(height))
            .build_unhashed();
        b.tx_root = tx_root_for_height(pba, height, &b.transactions);
        b.header.block_hash = b.compute_hash();
        b
    }

    /// Seal an empty block on `exec` the way the producer does: block
    /// context, basic reward credits, then the state root.
    fn produce(
        exec: &Executor,
        pba: PbaHardening,
        height: u64,
        parent: Hash,
        coinbase: [u8; 20],
        vrf: u8,
    ) -> Block {
        exec.set_block_context(BlockContext {
            coinbase,
            prevrandao: [vrf; 32],
            block_hashes: HashMap::new(),
        });
        let tmpl = template(pba, height, parent, coinbase, vrf, vec![], Hash::default());
        let r = RewardCalculator::new(canonical_reward_config()).calculate_reward(&tmpl);
        for (addr, amt) in [
            (Address(coinbase), r.validator_reward),
            (Address([0x11; 20]), r.treasury_reward),
        ] {
            if amt > U256::zero() {
                let bal = exec.get_balance(&addr);
                exec.set_balance(&addr, bal + amt);
            }
        }
        let root = exec.calculate_state_root();
        template(pba, height, parent, coinbase, vrf, vec![], root)
    }

    fn genesis() -> Block {
        let root = Executor::new(Arc::new(StateDB::new())).calculate_state_root();
        template(
            PbaHardening::off(),
            0,
            Hash::default(),
            [0x33; 20],
            0x5A,
            vec![],
            root,
        )
    }

    /// One node over a data directory, wired as `start_node` wires it:
    /// state loaded from the store, persistent DAG store, GhostDAG as fork
    /// choice, the applier, and the single admission path.
    struct Node {
        storage: Arc<StorageManager>,
        exec: Arc<Executor>,
        ghostdag: Arc<GhostDag>,
        app: Arc<CanonicalApplicator>,
        adm: BlockAdmission,
    }

    async fn open(path: &Path, pba: PbaHardening, purge: bool) -> (Node, RejoinReport) {
        let storage =
            Arc::new(StorageManager::new(path, PruningConfig::default()).expect("storage"));
        let report = if purge {
            purge_invalid_post_activation(&storage, pba, CHAIN).expect("purge")
        } else {
            RejoinReport::default()
        };
        let state_db = Arc::new(StateDB::new());
        for (address, account) in storage.state.get_all_accounts().expect("accounts") {
            state_db.accounts.load_account(address, account);
        }
        state_db.accounts.clear_dirty();
        let exec = Arc::new(Executor::with_storage_and_chain_id(
            state_db,
            Some(storage.state.clone()),
            CHAIN,
        ));
        exec.set_pba_hardening(pba);
        let kv = Arc::new(RocksDbKvStore::new(storage.db.clone()));
        let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv, false).expect("dag"));
        let ghostdag =
            Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()).with_pba_hardening(pba));
        let g = genesis();
        dag.set_configured_genesis(g.header.block_hash);
        let fresh = storage
            .blocks
            .get_block_by_height(0)
            .expect("read")
            .is_none();
        if fresh {
            storage
                .blocks
                .put_applied_tip(&g.header.block_hash, 0)
                .expect("tip");
        }
        let app = Arc::new(
            CanonicalApplicator::new(exec.clone(), storage.clone())
                .with_fork_choice(ghostdag.clone()),
        );
        app.set_genesis(
            Executor::new(Arc::new(StateDB::new())).state_snapshot(),
            g.header.block_hash,
        );
        let adm = BlockAdmission::new(storage.clone(), dag, ghostdag.clone(), Some(app.clone()));
        if fresh {
            assert!(matches!(adm.admit(&g).await, AdmitOutcome::Admitted { .. }));
        }
        ghostdag.reconcile_tips_from_dag_store().await;
        (
            Node {
                storage,
                exec,
                ghostdag,
                app,
                adm,
            },
            report,
        )
    }

    impl Node {
        async fn receive(&self, b: &Block) -> AdmitOutcome {
            self.adm.admit(b).await
        }

        /// The start-up recovery in `start_node`: converge an applied tip
        /// that is not the fork-choice head.
        async fn startup_recovery(&self) {
            let head = self.ghostdag.select_tip().await.expect("head");
            if head != self.app.applied_tip().await.hash {
                let _ = self
                    .app
                    .recover_to_head(
                        Executor::new(Arc::new(StateDB::new())).state_snapshot(),
                        genesis().header.block_hash,
                    )
                    .await;
            }
        }

        async fn tip(&self) -> AppliedTip {
            self.app.applied_tip().await
        }
    }

    /// Builds one block of the stale node's own branch at `height` on
    /// `parent`, advancing `exec` (the stale producer's state). Each block
    /// must be accepted by a node on the old rules and be invalid from the
    /// activation height `H` under the current rules. New validity rules
    /// that switch on at `H` add a fixture here, and the rejoin test covers
    /// them with no other change.
    type StaleBlock = fn(&Executor, u64, Hash) -> Block;

    /// The branch a node on an older release produces: pre-activation format.
    fn stale_legacy_format(exec: &Executor, height: u64, parent: Hash) -> Block {
        produce(
            exec,
            PbaHardening::off(),
            height,
            parent,
            CB_STALE,
            0x90 + height as u8,
        )
    }

    /// Current format, but every block runs more than the timestamp bound
    /// past its parent (accepted by the old rules, invalid from `H`).
    fn stale_timestamp_jump(exec: &Executor, height: u64, parent: Hash) -> Block {
        let mut b = produce(
            exec,
            PbaHardening::at(H),
            height,
            parent,
            CB_STALE,
            0xA0 + height as u8,
        );
        b.header.timestamp = 1_000 + height * (MAX_BLOCK_TIMESTAMP_ADVANCE_SECS + 400);
        b.header.block_hash = b.compute_hash();
        b
    }

    /// Two upgraded nodes build the canonical chain across the activation
    /// height. A third, still on the old rules, builds its own longer
    /// branch past it with `stale` (a block that is invalid from `H`).
    /// Restarted with the activation height set, the third drops that
    /// branch, rebuilds its state, takes the canonical blocks from its peers
    /// and converges on the canonical tip and state root, with no manual
    /// wipe. Returns the stale node's tip and root, the canonical head, and
    /// the start-up report.
    async fn stale_producer_rejoins(
        purge: bool,
        stale: StaleBlock,
    ) -> (AppliedTip, Hash, Block, RejoinReport) {
        let on = PbaHardening::at(H);
        let old = PbaHardening::off();

        // Canonical chain 1..=6 from the upgraded producer.
        let mirror_a = Executor::new(Arc::new(StateDB::new()));
        let mut canonical = Vec::new();
        let mut parent = genesis().header.block_hash;
        for h in 1..=6 {
            let b = produce(&mirror_a, on, h, parent, CB_UPGRADED, 0x50 + h as u8);
            parent = b.header.block_hash;
            canonical.push(b);
        }

        // Upgraded nodes A (producer) and B (follower) both hold it.
        let dir_a = tempfile::tempdir().expect("dir");
        let dir_b = tempfile::tempdir().expect("dir");
        for dir in [&dir_a, &dir_b] {
            let (n, _) = open(dir.path(), on, true).await;
            for b in &canonical {
                assert!(
                    matches!(n.receive(b).await, AdmitOutcome::Admitted { .. }),
                    "upgraded node admits canonical block {}",
                    b.header.height
                );
            }
            assert_eq!(n.tip().await.hash, parent);
            assert_eq!(n.exec.calculate_state_root(), canonical[5].state_root);
        }

        // Stale node C: shares 1..=2, then produces 3..=8 on the old rules.
        let dir_c = tempfile::tempdir().expect("dir");
        {
            let (c, _) = open(dir_c.path(), old, false).await;
            let mirror_c = Executor::new(Arc::new(StateDB::new()));
            let mut p = genesis().header.block_hash;
            for h in 1..=8u64 {
                let b = if h <= 2 {
                    let b = produce(&mirror_c, old, h, p, CB_UPGRADED, 0x50 + h as u8);
                    assert_eq!(
                        b.header.block_hash,
                        canonical[h as usize - 1].header.block_hash
                    );
                    b
                } else {
                    let b = stale(&mirror_c, h, p);
                    if h == H {
                        let parent_ts = c
                            .storage
                            .blocks
                            .get_header(&p)
                            .unwrap()
                            .map(|x| x.timestamp);
                        assert!(
                            check_block(on, CHAIN, &b, parent_ts).is_err(),
                            "the fixture's first block must be invalid from H"
                        );
                    }
                    b
                };
                assert!(
                    matches!(c.receive(&b).await, AdmitOutcome::Admitted { .. }),
                    "the old rules accept stale block {h}"
                );
                p = b.header.block_hash;
            }
            assert_eq!(c.tip().await.height, 8);
        }

        // Restart C on the new release (activation height set).
        let (c, report) = open(dir_c.path(), on, purge).await;
        if purge {
            assert_eq!(report.purged.len(), 6, "C3..C8 removed");
            assert!(report.applied_tip_purged);
            assert_eq!(c.storage.blocks.get_latest_height().unwrap(), 2);
        }
        c.startup_recovery().await;
        // Sync from upgraded peers.
        for b in &canonical[2..] {
            let _ = c.receive(b).await;
        }
        for _ in 0..3 {
            c.app.drive_drain().await;
        }
        (
            c.tip().await,
            c.exec.calculate_state_root(),
            canonical[5].clone(),
            report,
        )
    }

    async fn assert_rejoins(stale: StaleBlock) -> RejoinReport {
        let (tip, root, head, report) = stale_producer_rejoins(true, stale).await;
        assert_eq!(
            tip,
            AppliedTip {
                hash: head.header.block_hash,
                height: 6
            },
            "the restarted node converges on the canonical tip"
        );
        assert_eq!(root, head.state_root, "and on its state root");
        report
    }

    #[tokio::test]
    async fn stale_producer_rejoins_the_canonical_chain_after_restart() {
        let report = assert_rejoins(stale_legacy_format).await;
        assert_eq!(report.legacy_format, 6, "all six are in the old format");
    }

    /// The same rejoin for a stale branch that is in the current format but
    /// breaks another rule that switches on at `H`.
    #[tokio::test]
    async fn stale_branch_invalid_under_any_activation_rule_is_dropped() {
        let report = assert_rejoins(stale_timestamp_jump).await;
        assert_eq!(report.legacy_format, 0, "not the old format");
    }

    fn signed(seed: u8, nonce: u64) -> Transaction {
        let sk = crypto::Ed25519SigningKey::from_bytes(&[seed; 32]);
        let mut tx = Transaction {
            nonce,
            to: Some(PublicKey::new([0xB0; 32])),
            value: 1,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            chain_id: Some(CHAIN),
            ..Default::default()
        };
        crypto::sign_transaction(&mut tx, &sk).expect("sign");
        tx.hash = native_tx_id(&tx);
        tx
    }

    fn receipt(tx: &Transaction, block: &Block) -> citrate_execution::types::TransactionReceipt {
        citrate_execution::types::TransactionReceipt {
            tx_hash: tx.hash,
            block_hash: block.header.block_hash,
            block_number: block.header.height,
            from: Address([0; 20]),
            to: None,
            gas_used: 21_000,
            status: true,
            logs: vec![],
            output: vec![],
            eth_tx_type: 0,
            effective_gas_price: 0,
            revert_reason: None,
        }
    }

    /// The purge itself: only invalid blocks and their descendants go, a
    /// valid sibling keeps its height, every index is cleaned, the carried
    /// transactions come back, and a second start-up checks nothing again.
    #[tokio::test]
    async fn purge_removes_invalid_blocks_and_their_indexes_only() {
        let on = PbaHardening::at(2);
        let old = PbaHardening::off();
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let kv = Arc::new(RocksDbKvStore::new(storage.db.clone()));
        let g = genesis();
        let b1 = template(
            old,
            1,
            g.header.block_hash,
            CB_UPGRADED,
            1,
            vec![],
            Hash::default(),
        );
        let tx = signed(7, 0);
        let legacy2 = template(
            old,
            2,
            b1.header.block_hash,
            CB_STALE,
            2,
            vec![tx.clone()],
            Hash::default(),
        );
        let legacy3 = template(
            old,
            3,
            legacy2.header.block_hash,
            CB_STALE,
            3,
            vec![],
            Hash::default(),
        );
        let good2 = template(
            on,
            2,
            b1.header.block_hash,
            CB_UPGRADED,
            4,
            vec![],
            Hash::default(),
        );
        {
            let dag = DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("dag");
            dag.set_configured_genesis(g.header.block_hash);
            for b in [&g, &b1, &good2, &legacy2, &legacy3] {
                storage.blocks.put_block(b).expect("put");
                dag.store_block(b.clone()).await.expect("dag put");
            }
            storage
                .transactions
                .put_transactions(std::slice::from_ref(&tx))
                .expect("tx");
            storage
                .transactions
                .put_receipts(&[(tx.hash, receipt(&tx, &legacy2))])
                .expect("receipt");
            storage
                .blocks
                .put_applied_tip(&legacy3.header.block_hash, 3)
                .expect("tip");
        }

        let report = purge_invalid_post_activation(&storage, on, CHAIN).expect("purge");
        let want: HashSet<Hash> = [legacy2.header.block_hash, legacy3.header.block_hash].into();
        assert_eq!(report.purged, want);
        assert_eq!(report.checked, 3);
        assert_eq!(report.legacy_format, 2);
        assert!(report.applied_tip_purged);
        assert_eq!(report.returned_txs.len(), 1);
        assert_eq!(report.returned_txs[0].hash, tx.hash);

        // Chain store.
        for h in &want {
            assert!(!storage.blocks.has_block(h).unwrap());
        }
        assert!(storage.blocks.has_block(&good2.header.block_hash).unwrap());
        assert_eq!(
            storage.blocks.get_block_by_height(2).unwrap(),
            Some(good2.header.block_hash),
            "the surviving sibling holds the height"
        );
        assert_eq!(storage.blocks.get_block_by_height(3).unwrap(), None);
        assert!(storage
            .blocks
            .get_blocks_by_blue_score(2, 3)
            .unwrap()
            .is_empty());
        assert_eq!(storage.blocks.get_latest_height().unwrap(), 2);
        assert_eq!(
            storage.blocks.get_children(&b1.header.block_hash).unwrap(),
            vec![good2.header.block_hash]
        );
        assert!(!storage
            .blocks
            .get_tips()
            .unwrap()
            .contains(&legacy3.header.block_hash));
        // Transaction index.
        assert!(storage
            .transactions
            .get_transaction(&tx.hash)
            .unwrap()
            .is_none());
        assert!(storage
            .transactions
            .get_receipt(&tx.hash)
            .unwrap()
            .is_none());
        // DAG store, raw entries.
        use citrate_consensus::dag_store::{cf, KvStore};
        assert!(kv
            .kv_get(cf::DAG_CHILDREN, legacy2.header.block_hash.as_bytes())
            .unwrap()
            .is_none());
        let at2: Vec<Hash> = bincode::deserialize(
            &kv.kv_get(cf::DAG_HEIGHT_INDEX, &2u64.to_be_bytes())
                .unwrap()
                .expect("height 2 index kept"),
        )
        .unwrap();
        assert_eq!(at2, vec![good2.header.block_hash]);
        assert!(kv
            .kv_get(cf::DAG_HEIGHT_INDEX, &3u64.to_be_bytes())
            .unwrap()
            .is_none());
        // Idempotent, and it reports what it removed.
        assert_eq!(
            DagStore::purge_persisted_blocks(kv.as_ref(), &want).unwrap(),
            0
        );
        // DAG store, as it loads on the next start.
        let dag = DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("dag reload");
        for h in &want {
            assert!(!dag.has_block(h).await);
        }
        assert!(dag.has_block(&good2.header.block_hash).await);
        assert_eq!(
            dag.get_children(&b1.header.block_hash).await,
            vec![good2.header.block_hash]
        );
        assert_eq!(dag.get_blocks_at_height(3).await.len(), 0);
        let tips: Vec<Hash> = dag.get_tips().await.into_iter().map(|t| t.hash).collect();
        assert_eq!(tips, vec![good2.header.block_hash]);

        // Nothing new stored: the next start-up checks nothing.
        let again = purge_invalid_post_activation(&storage, on, CHAIN).expect("again");
        assert_eq!(again.checked, 0);
        assert!(again.purged.is_empty());
    }

    #[tokio::test]
    async fn dag_purge_reports_what_it_removed() {
        let dir = tempfile::tempdir().expect("dir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let kv = Arc::new(RocksDbKvStore::new(storage.db.clone()));
        let g = genesis();
        let old = PbaHardening::off();
        let b1 = template(
            old,
            1,
            g.header.block_hash,
            CB_STALE,
            1,
            vec![],
            Hash::default(),
        );
        let b2 = template(
            old,
            2,
            b1.header.block_hash,
            CB_STALE,
            2,
            vec![],
            Hash::default(),
        );
        {
            let dag = DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("dag");
            dag.set_configured_genesis(g.header.block_hash);
            for b in [&g, &b1, &b2] {
                dag.store_block(b.clone()).await.expect("dag put");
            }
        }
        let doomed: HashSet<Hash> = [b1.header.block_hash, b2.header.block_hash].into();
        assert_eq!(
            DagStore::purge_persisted_blocks(kv.as_ref(), &doomed).unwrap(),
            2
        );
        assert_eq!(
            DagStore::purge_persisted_blocks(kv.as_ref(), &doomed).unwrap(),
            0
        );
        assert_eq!(
            DagStore::purge_persisted_blocks(kv.as_ref(), &HashSet::new()).unwrap(),
            0
        );
    }

    #[test]
    fn nothing_to_do_without_an_activation_height() {
        let dir = tempfile::tempdir().expect("dir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let g = genesis();
        let b = template(
            PbaHardening::off(),
            1,
            g.header.block_hash,
            CB_STALE,
            1,
            vec![],
            Hash::default(),
        );
        storage.blocks.put_block(&g).unwrap();
        storage.blocks.put_block(&b).unwrap();
        let r = purge_invalid_post_activation(&storage, PbaHardening::off(), CHAIN).unwrap();
        assert!(r.purged.is_empty() && r.checked == 0);
        // Blocks below the activation height are never re-judged.
        let r = purge_invalid_post_activation(&storage, PbaHardening::at(2), CHAIN).unwrap();
        assert!(r.purged.is_empty() && r.checked == 0);
        assert!(storage.blocks.has_block(&b.header.block_hash).unwrap());
    }

    #[test]
    fn legacy_format_peers_are_counted_per_peer() {
        let on = PbaHardening::at(3);
        let g = genesis().header.block_hash;
        let legacy = template(
            PbaHardening::off(),
            3,
            g,
            CB_STALE,
            1,
            vec![],
            Hash::default(),
        );
        let current = template(on, 3, g, CB_UPGRADED, 1, vec![], Hash::default());
        let before = template(
            PbaHardening::off(),
            2,
            g,
            CB_STALE,
            1,
            vec![],
            Hash::default(),
        );
        let t = LegacyFormatPeers::default();
        assert!(t.observe(on, "peer-a", &legacy));
        assert!(t.observe(on, "peer-a", &legacy));
        assert!(t.observe(on, "peer-b", &legacy));
        assert!(
            !t.observe(on, "peer-c", &current),
            "current format is not counted"
        );
        assert!(
            !t.observe(on, "peer-c", &before),
            "below the activation height"
        );
        assert!(
            !t.observe(PbaHardening::off(), "peer-c", &legacy),
            "no activation set"
        );
        assert_eq!(t.count("peer-a"), 2);
        assert_eq!(t.count("peer-b"), 1);
        assert_eq!(t.count("peer-c"), 0);
        assert_eq!(t.peers(), 2);
        // A tampered root that is neither format is invalid, but not "legacy".
        let mut odd = current.clone();
        odd.tx_root = Hash::new([9; 32]);
        assert!(!is_legacy_format(on, &odd));
    }

    #[test]
    fn tracked_peers_are_bounded() {
        let on = PbaHardening::at(1);
        let legacy = template(
            PbaHardening::off(),
            1,
            Hash::new([1; 32]),
            CB_STALE,
            1,
            vec![],
            Hash::default(),
        );
        let t = LegacyFormatPeers::default();
        for i in 0..(MAX_TRACKED_PEERS + 10) {
            t.observe(on, &format!("p{i}"), &legacy);
        }
        assert_eq!(
            t.peers(),
            MAX_TRACKED_PEERS + 1,
            "overflow folds into one bucket"
        );
        assert_eq!(t.count("other"), 10);
    }

    /// Tripwire: start_node runs the check after the activation height is
    /// published and before anything loads the stored blocks, and every block
    /// ingress (gossip and sync) reports pre-activation-format senders.
    #[test]
    fn start_node_wiring() {
        let main = include_str!("main.rs");
        let body = &main[main.find("async fn start_node(").expect("start_node")..];
        let init = body.find("init_pba_hardening_for_chain(").expect("init");
        let purge = body
            .find("hardening_rejoin::purge_invalid_post_activation(")
            .expect("start-up check");
        assert!(init < purge);
        for later in [
            "storage.state.get_all_accounts()",
            "DagStore::persistent_with_strict_vrf(",
            "CanonicalApplicator::new(",
            "BlockAdmission::new(",
        ] {
            assert!(
                purge < body.find(later).expect(later),
                "check must precede {later}"
            );
        }
        let gossip = body
            .find("NetworkMessage::NewBlock { block } => {")
            .expect("gossip");
        let sync = body
            .find("NetworkMessage::Blocks { blocks } => {")
            .expect("sync");
        for arm in [gossip, sync] {
            let next = &body[arm..arm + 800];
            assert!(
                next.contains("legacy_peers_for_rx.observe("),
                "{}",
                &next[..60]
            );
        }
    }

    #[test]
    fn resync_message_is_actionable() {
        let m = manual_resync_instructions(Path::new("/data/citrate"), 42);
        assert!(m.contains("42") && m.contains("/data/citrate") && m.contains("move"));
    }
}
