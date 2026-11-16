// citrate/node/src/boot_state.rs
//
// Start-up state hydration: the world state a restarted node executes on is
// read back from its RocksDB store (accounts and contract storage records),
// and the hydrated root must reproduce the committed root of the applied tip
// (SRP-S3b). `start_node` and the split-heal harness's disk-reload restart
// (`split_heal_tests.rs`, CV-9) run this same function, so a restart test
// reloads exactly what a node reloads.
//
// Data source: `StorageManager.state` (`StateStore::get_all_accounts`,
// `StateStore::get_all_storage`, `StateStore::get_state_root`, and under the
// MPT state root `StateStore::trie_root_at` / `get_trie_node`) and
// `StorageManager.blocks` (`BlockStore::get_applied_tip`).

use citrate_execution::StateDB;
use citrate_storage::StorageManager;
use tracing::{debug, error, info, warn};

/// Load the persisted world state of `storage` into `state_db` and verify it
/// against the applied tip's committed root. An error means the node must not
/// start (it would execute against a state it never committed).
pub(crate) fn hydrate_state_db(storage: &StorageManager, state_db: &StateDB) -> anyhow::Result<()> {
    info!("Loading state from storage...");
    match storage.state.get_all_accounts() {
        Ok(accounts) => {
            info!(
                "Found {} accounts in storage, loading into memory...",
                accounts.len()
            );
            for (address, account) in accounts {
                debug!(
                    "Loaded account: 0x{} with balance {}",
                    hex::encode(address.0),
                    account.balance
                );
                state_db.accounts.load_account(address, account);
            }
            info!("State loaded successfully");
        }
        Err(e) => {
            warn!("Failed to load accounts from storage: {}", e);
        }
    }

    // The applied tip = the block whose committed state the store holds. Fall back to
    // the latest block only when no applied-tip pointer exists (pre-S3b stores / fresh
    // genesis), preserving the prior behavior for those.
    let (boot_tip_hash, boot_tip_height) = storage
        .blocks
        .get_applied_tip()
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            let h = storage.blocks.get_latest_height().unwrap_or(0);
            let hash = storage
                .blocks
                .get_block_by_height(h)
                .ok()
                .flatten()
                .unwrap_or_default();
            (hash, h)
        });

    // C6 fix: Also load contract storage slots from persistent storage.
    // From the storage-root hardening height (the next block this node executes)
    // every persisted record is restored byte for byte; below it the legacy view
    // (32-byte keys, values cut or padded to 32 bytes) is kept, so a restarted
    // node rebuilds exactly the state it rebuilt before.
    let full_hydration = citrate_execution::storage_root_hardening::active_at(
        citrate_execution::storage_root_hardening::storage_root_hardening_height(),
        boot_tip_height.saturating_add(1),
    );
    match storage.state.get_all_storage() {
        Ok(records) => {
            let storage_slots = crate::boot_storage_view(
                records,
                citrate_execution::storage_root_hardening::storage_root_hardening_height(),
                boot_tip_height,
            );
            info!(
                "Found {} storage slots in storage, loading into memory ({} hydration)...",
                storage_slots.len(),
                if full_hydration { "full" } else { "legacy" }
            );
            for ((address, storage_key), storage_value) in storage_slots {
                state_db.set_storage(
                    address,
                    storage_key.as_bytes().to_vec(),
                    storage_value.as_bytes().to_vec(),
                );
            }
            // Clear dirty flags since these are loaded from storage, not new writes
            let _ = state_db.take_dirty_storage();
            info!("Storage slots loaded successfully");
        }
        Err(e) => {
            // Starting without contract storage would execute and root against
            // a state this node never committed. Refuse instead.
            error!("Failed to load storage slots from storage: {}", e);
            return Err(anyhow::anyhow!(
                "refusing to start: contract storage could not be hydrated: {e}"
            ));
        }
    }

    // SRP-S3b: verify the hydrated in-memory root reproduces the committed root of the
    // APPLIED TIP — the block whose post-execution state the durable store reflects — NOT
    // the latest stored block. A node legitimately stores blocks AHEAD of what it has
    // applied (execute-on-receive downloads then drains; the producer persists the block
    // before atomically advancing state+tip). Comparing against the latest BLOCK would
    // false-positive whenever blocks lead the applied tip; the applied-tip pointer and the
    // durable state are advanced ATOMICALLY (persist_state_changes_with_tip), so they must
    // always agree — a mismatch means a genuinely corrupt/divergent reconstruction.
    {
        let (tip_hash, tip_height) = (boot_tip_hash, boot_tip_height);
        // The hydrated state is the post-state of the applied tip: root it under
        // that height's storage-root rule.
        state_db.set_root_height(tip_height);
        reuse_persisted_trie(storage, state_db, tip_height);
        let memory_root = state_db.calculate_state_root();
        if tip_height > 0 && tip_hash != citrate_consensus::types::Hash::default() {
            let committed_root = storage
                .state
                .get_state_root(&tip_hash)
                .ok()
                .flatten()
                .or_else(|| {
                    storage
                        .blocks
                        .get_block(&tip_hash)
                        .ok()
                        .flatten()
                        .map(|b| b.state_root)
                });
            match committed_root {
                Some(root) if root != citrate_consensus::types::Hash::default() => {
                    if memory_root == root {
                        info!(
                            "State root verification PASSED (applied tip height {}, root={})",
                            tip_height,
                            hex::encode(&memory_root.as_bytes()[..8])
                        );
                    } else {
                        // SRP-S3: a node whose hydrated root does NOT reproduce the applied
                        // tip's committed root MUST NOT start — it would seal/verify against
                        // a divergent root and fork the fleet. HARD-FAIL (safe local stop),
                        // never warn-and-continue. See ADR-2026-07-21-restart-produce-purity.
                        error!("SRP-S3 BOOT HALT: state root MISMATCH at applied tip height {}: memory={} committed={} — refusing to start (a node that cannot reconstruct the committed root would fork the fleet)",
                            tip_height,
                            hex::encode(memory_root.as_bytes()),
                            hex::encode(root.as_bytes()));
                        return Err(anyhow::anyhow!(
                            "SRP-S3 boot halt: hydrated state root {} != committed root {} at applied tip height {}",
                            hex::encode(memory_root.as_bytes()),
                            hex::encode(root.as_bytes()),
                            tip_height
                        ));
                    }
                }
                _ => {
                    debug!(
                        "No committed state root for applied tip height {} — skipping verification",
                        tip_height
                    );
                }
            }
        }
        // Clear dirty flags from state root calculation
        state_db.accounts.clear_dirty();
    }
    Ok(())
}

/// CV-14: under the MPT state root, reuse the trie nodes persisted for the
/// applied tip instead of rebuilding the state trie from the hydrated state.
/// `StateDB::reuse_persisted_trie` checks every node and every leaf against
/// the hydrated state; on any difference nothing is installed and the root
/// below is built from state as on a cold start (the same root either way:
/// the node store is a cache). The committed-root check that follows is
/// unchanged.
fn reuse_persisted_trie(storage: &StorageManager, state_db: &StateDB, tip_height: u64) {
    use citrate_execution::executor::StateStoreTrait;
    if !citrate_execution::mpt_state_root::mpt_state_root_active(tip_height) {
        return;
    }
    match storage.state.trie_root_at(tip_height) {
        Ok(Some(root)) => {
            let source = |h: &[u8; 32]| storage.state.get_trie_node(h).ok().flatten();
            let started = std::time::Instant::now();
            match state_db.reuse_persisted_trie(&root, &source) {
                Ok(r) => info!(
                    "State trie reused from the node store at height {tip_height}: {} account(s), \
                     {} storage trie(s) checked in {:?} (no rebuild)",
                    r.accounts,
                    r.storage_tries,
                    started.elapsed()
                ),
                Err(e) => warn!(
                    "State trie at height {tip_height} not reused ({e}); rebuilding from state"
                ),
            }
        }
        Ok(None) => info!("No persisted state trie at height {tip_height}; rebuilding from state"),
        Err(e) => warn!("Trie root record at height {tip_height} unreadable ({e}); rebuilding"),
    }
}
