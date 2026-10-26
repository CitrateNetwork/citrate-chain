// SRP-S3b diagnostic: bulk-load a data dir's state exactly as node boot does, then print a
// deterministic per-account digest + the reloaded state root. Run against two nodes' data dirs and
// diff to name the account/slot whose persisted representation diverges. Read-only.
//
// Usage: state-digest /path/to/.citrate [chain-id]   (chain id defaults to 40204; the
// storage-root hardening height resolves as the node resolves it for that chain)

// PANIC-S1 G2: production code in this crate may not panic (tests excepted).
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

use citrate_execution::StateDB;
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::collections::BTreeMap;

fn main() -> anyhow::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: state-digest <data-dir>"))?;
    let chain_id: u64 = match std::env::args().nth(2) {
        Some(raw) => raw
            .parse()
            .map_err(|e| anyhow::anyhow!("chain id {raw}: {e}"))?,
        None => 40204,
    };
    citrate_execution::storage_root_hardening::init_for_chain(chain_id, None)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let storage = StorageManager::new(&dir, PruningConfig::default())?;
    let state_db = StateDB::new();
    let tip_height = match storage.blocks.get_applied_tip()? {
        Some((_, h)) => h,
        None => storage.blocks.get_latest_height().unwrap_or(0),
    };
    state_db.set_root_height(tip_height);
    let full_hydration = citrate_execution::storage_root_hardening::storage_root_hardening_active(
        tip_height.saturating_add(1),
    );

    // Mirror node/src/main.rs:1020-1046 exactly.
    let accts = storage.state.get_all_accounts()?;
    let n_accts = accts.len();
    for (address, account) in accts {
        state_db.accounts.load_account(address, account);
    }
    let records = storage.state.get_all_storage()?;
    let slots = if full_hydration {
        records
    } else {
        citrate_storage::state::legacy_hydration_view(records)
    };
    let n_slots = slots.len();
    // Count slots per address (incl. zero-valued rows) for the digest.
    let mut slot_count: BTreeMap<[u8; 20], usize> = BTreeMap::new();
    for ((address, storage_key), storage_value) in slots {
        {
            let c = slot_count.entry(address.0).or_default();
            *c = c.saturating_add(1);
        }
        state_db.set_storage(
            address,
            storage_key.as_bytes().to_vec(),
            storage_value.as_bytes().to_vec(),
        );
    }
    let _ = state_db.take_dirty_storage();

    // Per-account digest, sorted by address. storage_root is recomputed FRESH from the
    // reloaded trie (what calculate_state_root folds), so a divergence in slot contents shows up.
    let mut all = state_db.accounts.all_accounts();
    all.sort_by_key(|a| a.0 .0);
    println!("# accounts={n_accts} slots={n_slots}");
    for (address, mut account) in all {
        let sroot = state_db
            .get_storage_root_recomputed(&address)
            .unwrap_or(account.storage_root);
        account.storage_root = sroot;
        let empty = account.is_empty();
        println!(
            "{} bal={} nonce={} code={} sroot={} slots={} empty={}",
            hex::encode(address.0),
            account.balance,
            account.nonce,
            hex::encode(&account.code_hash.as_bytes()[..4]),
            hex::encode(&sroot.as_bytes()[..8]),
            slot_count.get(&address.0).copied().unwrap_or(0),
            empty,
        );
    }
    let root = state_db.calculate_state_root();
    println!("ROOT={}", hex::encode(root.as_bytes()));
    Ok(())
}
