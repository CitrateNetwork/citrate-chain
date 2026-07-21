// SRP-S3b — bulk-reload hydration must reproduce the live committed state root (CONSENSUS-CRITICAL).
//
// The block-2345 boot-halt: a node that RESTARTS bulk-reloads its state from the durable store
// (`get_all_accounts` + `get_all_storage`, node/src/main.rs:1020/1035) and recomputes the root.
// A node that instead built the state by APPLYING BLOCKS FORWARD (the live fleet) holds the correct
// root. The two diverged for a state WITH CONTRACT STORAGE — so the persist→bulk-reload round-trip
// is not a faithful mirror of the live committed state, and a restarted miner/follower recomputes a
// different root (caught by the SRP-S3 boot hard-fail rather than forking).
//
// This test reproduces the round-trip in-process at the StateDB/StateStore layer, exactly as
// main.rs does, and asserts the reloaded root == the live root. It FAILS on the buggy round-trip
// and PINS the lossy field, then guards the fix.

use citrate_execution::types::Address;
use citrate_execution::{Executor, StateDB};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use primitive_types::U256;
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn srp_s3b_bulk_reload_reproduces_live_root() {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let state_db = Arc::new(StateDB::new());
    let executor = Arc::new(Executor::with_storage_and_chain_id(
        state_db.clone(),
        Some(storage.state.clone()),
        40204,
    ));

    // Build a state that mirrors a live chain at a storage-bearing height:
    //  - a plain funded EOA,
    //  - a contract with code AND a non-zero storage slot (like the ValidatorRegistry / SBT).
    let eoa = Address([0x11u8; 20]);
    let contract = Address([0xC0u8; 20]);
    state_db.accounts.set_balance(eoa, U256::from(1_000_000u64));
    state_db.set_code(contract, vec![0x60, 0x2a, 0x60, 0x00, 0x55]); // some bytecode
    let slot0 = vec![0u8; 32];
    let mut val = vec![0u8; 32];
    val[31] = 0x2a;
    state_db.set_storage(contract, slot0.clone(), val.clone());
    // A second slot with a larger value (exercises multi-slot trie).
    let mut slot1 = vec![0u8; 32];
    slot1[31] = 0x01;
    let mut val1 = vec![0u8; 32];
    val1[0] = 0xff;
    val1[31] = 0x99;
    state_db.set_storage(contract, slot1.clone(), val1.clone());
    // Give the contract account a nonce so it is non-empty independent of storage.
    state_db.accounts.set_nonce(contract, 1);

    // Persist exactly as the producer does, then read the LIVE committed root.
    executor
        .persist_state_changes()
        .await
        .expect("persist state changes");
    let root_live = state_db.calculate_state_root();

    // ── Bulk-reload into a FRESH StateDB, byte-for-byte as node/src/main.rs:1020-1046 does. ──
    let reloaded = StateDB::new();
    let accts = storage
        .state
        .get_all_accounts()
        .expect("get_all_accounts");
    for (address, account) in accts {
        reloaded.accounts.load_account(address, account);
    }
    let slots = storage.state.get_all_storage().expect("get_all_storage");
    for ((address, storage_key), storage_value) in slots {
        reloaded.set_storage(
            address,
            storage_key.as_bytes().to_vec(),
            storage_value.as_bytes().to_vec(),
        );
    }
    let _ = reloaded.take_dirty_storage(); // clear dirty, as main.rs does
    let root_reload = reloaded.calculate_state_root();

    assert_eq!(
        root_live, root_reload,
        "SRP-S3b: a node that bulk-reloads state from the store MUST reproduce the live committed \
         root — else a restarted node recomputes a different root and forks (block-2345 boot-halt). \
         live={:?} reload={:?}",
        root_live, root_reload
    );
}
