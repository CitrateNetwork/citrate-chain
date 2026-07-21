// SRP-S3c — the producer's committed state root must keep reflecting reward credits AFTER a
// restart (CONSENSUS-CRITICAL). Live symptom: after a MINER restart, blocks N, N+1 sealed correct
// (changing) roots, but from N+2 on the sealed `calculate_state_root` FROZE at one value while the
// actual balances kept advancing — so followers computed the real (changed) root and rejected the
// producer's blocks → wedge. This test mimics the producer's per-block settle→root→persist loop at
// the executor level, with a "restart" (fresh StateDB bulk-loaded from the store) in the middle, and
// asserts every block's committed root is DISTINCT (each 9/1-SALT reward changes the root).

use citrate_execution::types::Address;
use citrate_execution::{Executor, StateDB};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use citrate_consensus::types::Hash;
use primitive_types::U256;
use std::collections::HashSet;
use std::sync::Arc;
use tempfile::TempDir;

const CB: [u8; 20] = [0x0e; 20];
const TREASURY: [u8; 20] = [0x11; 20];

/// Credit one block's basic reward (9 SALT validator + 1 SALT treasury), compute + return the
/// committed state root, and persist state + the applied tip atomically — exactly the executor
/// operations `produce_block` performs per block.
async fn credit_and_seal(exec: &Executor, sdb: &StateDB, height: u64) -> Hash {
    let cb = Address(CB);
    let tr = Address(TREASURY);
    sdb.accounts
        .set_balance(cb, sdb.accounts.get_balance(&cb) + U256::from(9u64));
    sdb.accounts
        .set_balance(tr, sdb.accounts.get_balance(&tr) + U256::from(1u64));
    let root = sdb.calculate_state_root();
    let tip_hash = {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&height.to_be_bytes());
        Hash::new(b)
    };
    exec.persist_state_changes_with_tip(Some((tip_hash, height)))
        .await
        .expect("persist");
    root
}

/// Bulk-reload a fresh StateDB from the store exactly as node boot does.
fn reload(storage: &StorageManager) -> Arc<StateDB> {
    let sdb = Arc::new(StateDB::new());
    for (address, account) in storage.state.get_all_accounts().expect("accts") {
        sdb.accounts.load_account(address, account);
    }
    for ((address, k), v) in storage.state.get_all_storage().expect("slots") {
        sdb.set_storage(address, k.as_bytes().to_vec(), v.as_bytes().to_vec());
    }
    let _ = sdb.take_dirty_storage();
    sdb
}

#[tokio::test]
async fn srp_s3c_producer_root_keeps_advancing_across_restart() {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));

    let mut roots: Vec<(u64, Hash)> = Vec::new();

    // Produce blocks 1..=5 on the first executor.
    let sdb1 = Arc::new(StateDB::new());
    let exec1 = Arc::new(Executor::with_storage_and_chain_id(
        sdb1.clone(),
        Some(storage.state.clone()),
        40204,
    ));
    for h in 1..=5u64 {
        roots.push((h, credit_and_seal(&exec1, &sdb1, h).await));
    }
    drop(exec1);
    drop(sdb1);

    // ── RESTART: fresh StateDB bulk-loaded from the store, fresh executor. ──
    let sdb2 = reload(&storage);
    let exec2 = Arc::new(Executor::with_storage_and_chain_id(
        sdb2.clone(),
        Some(storage.state.clone()),
        40204,
    ));
    // Produce blocks 6..=12 on the restarted executor — this is where the live chain FROZE.
    for h in 6..=12u64 {
        roots.push((h, credit_and_seal(&exec2, &sdb2, h).await));
    }

    // Every block credits a non-zero reward, so every committed root MUST be distinct. A frozen
    // (repeated) root after the restart is the block-174 bug.
    let mut seen: HashSet<Hash> = HashSet::new();
    for (h, r) in &roots {
        assert!(
            seen.insert(*r),
            "SRP-S3c: committed state root FROZE at block {h} ({:?}) — a reward was credited but the \
             root did not change (the post-restart producer-root-freeze that wedges followers)",
            r
        );
    }
}
