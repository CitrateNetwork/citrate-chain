//! Follower catch-up group commit (`Executor::set_catchup_group_commit`,
//! `BlockStore::put_block_unsynced`).
//!
//! A follower far behind the network spends most of each applied block in two
//! fsyncs (the block write and the state + applied-tip batch). During catch-up
//! only every Nth received block's state batch is fsynced. These tests pin:
//!
//! - the count: N received blocks -> exactly one synced state batch;
//! - the default (no catch-up) still fsyncs every received block;
//! - the producer's commit always fsyncs, catch-up or not;
//! - `put_block_unsynced` skips the fsync, `put_block` does not;
//! - a process that dies without closing the database (abort: no destructors,
//!   no RocksDB shutdown) after unsynced commits reopens with state and
//!   applied tip on the same block, and the reloaded state root equals that
//!   block's committed root — never torn.

use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, VrfProof};
use citrate_execution::executor::Executor;
use citrate_execution::revm_adapter::BlockContext;
use citrate_execution::types::Address;
use citrate_execution::StateDB;
use citrate_storage::chain::BlockStore;
use citrate_storage::db::RocksDB;
use citrate_storage::state::StateStore;
use primitive_types::U256;
use std::sync::Arc;
use tempfile::TempDir;

const CB: [u8; 20] = [0x33; 20];
const REWARD: u64 = 10;

fn credits() -> Vec<(Address, U256)> {
    vec![(Address(CB), U256::from(REWARD))]
}

fn seal(height: u64, parent: Hash, root: Hash) -> Block {
    let mut b = BlockBuilder::new()
        .version(2)
        .height(height)
        .parent(parent)
        .coinbase(CB)
        .timestamp(1_000 + height)
        .vrf_reveal(VrfProof {
            proof: vec![],
            output: Hash::new([0x5A; 32]),
        })
        .transactions(vec![])
        .state_root(root)
        .proposer(PublicKey::new([1; 32]))
        .build_unhashed();
    b.header.block_hash = b.compute_hash();
    b
}

/// `n` reward-only blocks, each committing the cumulative state root.
fn chain(n: u64) -> Vec<Block> {
    let mirror = Executor::new(Arc::new(StateDB::new()));
    let mut parent = Hash::default();
    let mut out = Vec::new();
    for h in 1..=n {
        mirror.set_block_context(BlockContext {
            coinbase: CB,
            prevrandao: [0x5A; 32],
            block_hashes: std::collections::HashMap::new(),
        });
        let bal = mirror.get_balance(&Address(CB));
        mirror.set_balance(&Address(CB), bal + U256::from(REWARD));
        let b = seal(h, parent, mirror.calculate_state_root());
        parent = b.header.block_hash;
        out.push(b);
    }
    out
}

fn open(dir: &std::path::Path) -> (Arc<RocksDB>, Executor) {
    let db = Arc::new(RocksDB::open(dir).expect("open db"));
    let store = Arc::new(StateStore::new(db.clone()));
    let exec = Executor::with_storage(Arc::new(StateDB::new()), Some(store));
    (db, exec)
}

async fn apply_all(exec: &Executor, blocks: &[Block]) {
    for b in blocks {
        exec.apply_block(b, CB, &credits())
            .await
            .expect("valid block applies");
    }
}

#[tokio::test]
async fn catchup_fsyncs_one_received_block_in_n() {
    let temp = TempDir::new().expect("tempdir");
    let (db, exec) = open(temp.path());
    exec.set_catchup_group_commit(4);
    let sync0 = db.write_batch_sync_count();
    let nosync0 = db.write_batch_count();
    apply_all(&exec, &chain(8)).await;
    assert_eq!(
        db.write_batch_sync_count() - sync0,
        2,
        "8 received blocks at a group of 4 must fsync exactly twice"
    );
    assert_eq!(db.write_batch_count() - nosync0, 6);
}

#[tokio::test]
async fn outside_catchup_every_received_block_is_fsynced() {
    let temp = TempDir::new().expect("tempdir");
    let (db, exec) = open(temp.path());
    assert_eq!(
        exec.catchup_group_commit(),
        1,
        "default is an fsync per block"
    );
    let sync0 = db.write_batch_sync_count();
    let nosync0 = db.write_batch_count();
    apply_all(&exec, &chain(8)).await;
    assert_eq!(db.write_batch_sync_count() - sync0, 8);
    assert_eq!(db.write_batch_count() - nosync0, 0);

    // Leaving catch-up restores it immediately.
    let temp2 = TempDir::new().expect("tempdir");
    let (db2, exec2) = open(temp2.path());
    let blocks = chain(6);
    exec2.set_catchup_group_commit(64);
    apply_all(&exec2, &blocks[..3]).await;
    exec2.set_catchup_group_commit(1);
    let sync1 = db2.write_batch_sync_count();
    apply_all(&exec2, &blocks[3..]).await;
    assert_eq!(db2.write_batch_sync_count() - sync1, 3);
}

#[tokio::test]
async fn the_producer_commit_always_fsyncs() {
    let temp = TempDir::new().expect("tempdir");
    let (db, exec) = open(temp.path());
    exec.set_catchup_group_commit(64);
    exec.set_balance(&Address([0xAB; 20]), U256::from(5u64));
    let sync0 = db.write_batch_sync_count();
    let nosync0 = db.write_batch_count();
    exec.persist_state_changes_with_tip(Some((Hash::new([9; 32]), 1)))
        .await
        .expect("persist");
    assert_eq!(db.write_batch_sync_count() - sync0, 1);
    assert_eq!(db.write_batch_count() - nosync0, 0);
}

#[test]
fn put_block_unsynced_skips_the_fsync_and_put_block_keeps_it() {
    let temp = TempDir::new().expect("tempdir");
    let db = Arc::new(RocksDB::open(temp.path()).expect("open db"));
    let store = BlockStore::new(db.clone());
    let blocks = chain(2);
    let (s0, n0) = (db.write_batch_sync_count(), db.write_batch_count());
    store.put_block_unsynced(&blocks[0]).expect("put");
    assert_eq!(
        (
            db.write_batch_sync_count() - s0,
            db.write_batch_count() - n0
        ),
        (0, 1)
    );
    store.put_block(&blocks[1]).expect("put");
    assert_eq!(
        (
            db.write_batch_sync_count() - s0,
            db.write_batch_count() - n0
        ),
        (1, 1)
    );
    assert!(store.has_block(&blocks[0].header.block_hash).expect("has"));
}

const CHILD_ENV: &str = "CITRATE_CATCHUP_ABORT_CHILD_DIR";
const CRASH_BLOCKS: u64 = 10;

/// The child half of the crash test: apply every block with no fsync at all,
/// then die without running a single destructor.
#[tokio::test]
async fn catchup_abort_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return; // only meaningful when launched by the parent below
    };
    let (_db, exec) = open(std::path::Path::new(&dir));
    exec.set_catchup_group_commit(u64::MAX);
    apply_all(&exec, &chain(CRASH_BLOCKS)).await;
    std::process::abort();
}

#[test]
fn unsynced_catchup_commits_survive_a_process_crash_untorn() {
    let temp = TempDir::new().expect("tempdir");
    let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "catchup_abort_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, temp.path())
        .env("HOME", temp.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("spawn child");
    assert!(!status.success(), "the child must die by abort");

    let db = Arc::new(RocksDB::open(temp.path()).expect("reopen db"));
    let blocks = BlockStore::new(db.clone());
    let store = StateStore::new(db.clone());
    let tip = chain(CRASH_BLOCKS).pop().expect("tip");
    assert_eq!(
        blocks.get_applied_tip().expect("tip"),
        Some((tip.header.block_hash, CRASH_BLOCKS)),
        "every unsynced batch reached the write-ahead log before the crash"
    );
    // State reloaded from disk reproduces the tip's committed root: state and
    // tip were written together, so they cannot disagree.
    let sdb = StateDB::new();
    for (address, account) in store.get_all_accounts().expect("accounts") {
        sdb.accounts.load_account(address, account);
    }
    assert_eq!(sdb.calculate_state_root(), tip.state_root);
}
