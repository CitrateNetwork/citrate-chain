// SRP-S3b diagnostic: bulk-load a data dir's state exactly as node boot does, then print a
// deterministic per-account digest + the reloaded state root. Run against two nodes' data dirs and
// diff to name the account/slot whose persisted representation diverges. Read-only.
//
// Usage: state-digest /path/to/.citrate

use citrate_execution::StateDB;
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::collections::BTreeMap;

fn main() -> anyhow::Result<()> {
    let dir = std::env::args().nth(1).expect("usage: state-digest <data-dir>");
    let storage = StorageManager::new(&dir, PruningConfig::default())?;
    let state_db = StateDB::new();

    // Mirror node/src/main.rs:1020-1046 exactly.
    let accts = storage.state.get_all_accounts()?;
    let n_accts = accts.len();
    for (address, account) in accts {
        state_db.accounts.load_account(address, account);
    }
    let slots = storage.state.get_all_storage()?;
    let n_slots = slots.len();
    // Count slots per address (incl. zero-valued rows) for the digest.
    let mut slot_count: BTreeMap<[u8; 20], usize> = BTreeMap::new();
    for ((address, storage_key), storage_value) in slots {
        *slot_count.entry(address.0).or_default() += 1;
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
    all.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
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
