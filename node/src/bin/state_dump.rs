// state-dump: read a STOPPED node's data dir and print every account (balance, nonce,
// code, storage) as canonical JSON. Read-only. Used by the r1006 genesis builder
// (scripts/genesis/r1006/) to turn a ceremony devnet's post-ceremony state into a
// genesis allocation.
//
// Usage: state-dump <data-dir>
//
// Output (stdout), sorted by address, storage sorted by slot, every hex string
// lowercase and 0x-prefixed, zero-valued slots left out:
//   {"format":"citrate-state-dump-v1","stateRoot":"0x..","accounts":[
//     {"address":"0x..","balance":"0x..","nonce":N,"code":"0x..","storage":{"0x<slot>":"0x<value>"}}]}
// `code` is absent for an account without code. `stateRoot` is the root recomputed
// from the reloaded state, exactly as node boot reloads it (see state-digest).

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
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn main() -> anyhow::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: state-dump <data-dir>"))?;
    let storage = StorageManager::new(&dir, PruningConfig::default())?;
    let state_db = StateDB::new();

    let accts = storage.state.get_all_accounts()?;
    let mut by_addr: BTreeMap<[u8; 20], Map<String, Value>> = BTreeMap::new();
    for (address, account) in &accts {
        state_db.accounts.load_account(*address, account.clone());
        let mut o = Map::new();
        o.insert("address".into(), json!(hex0x(&address.0)));
        o.insert("balance".into(), json!(format!("0x{:x}", account.balance)));
        o.insert("nonce".into(), json!(account.nonce));
        if let Some(code) = storage.state.get_code(&account.code_hash)? {
            if !code.is_empty() {
                o.insert("code".into(), json!(hex0x(&code)));
            }
        }
        o.insert("storage".into(), Value::Object(Map::new()));
        by_addr.insert(address.0, o);
    }

    let mut slots: BTreeMap<[u8; 20], BTreeMap<[u8; 32], [u8; 32]>> = BTreeMap::new();
    for ((address, key), value) in storage.state.get_all_storage()? {
        state_db.set_storage(address, key.as_bytes().to_vec(), value.as_bytes().to_vec());
        if *value.as_bytes() == [0u8; 32] {
            continue;
        }
        slots
            .entry(address.0)
            .or_default()
            .insert(*key.as_bytes(), *value.as_bytes());
    }
    let _ = state_db.take_dirty_storage();
    for (addr, s) in slots {
        let o = by_addr.entry(addr).or_insert_with(|| {
            let mut o = Map::new();
            o.insert("address".into(), json!(hex0x(&addr)));
            o.insert("balance".into(), json!("0x0"));
            o.insert("nonce".into(), json!(0));
            o
        });
        let m: Map<String, Value> = s
            .iter()
            .map(|(k, v)| (hex0x(k), json!(hex0x(v))))
            .collect();
        o.insert("storage".into(), Value::Object(m));
    }

    let root = state_db.calculate_state_root();
    let out = json!({
        "format": "citrate-state-dump-v1",
        "stateRoot": hex0x(root.as_bytes()),
        "accounts": by_addr.into_values().map(Value::Object).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
