// citrate/core/api/tests/getlogs_latest_applied_tip.rs
//
// `latest` (and `pending`) in a log query resolves to the applied tip: the
// executed block `eth_getLogs` serves logs up to. Stored headers can be ahead
// of it (blocks admitted but not yet applied); `eth_blockNumber` reports those,
// and resolving `latest` to them put `latest..latest` above every executed
// block, so the answer was an empty list that read as "no logs at the head".
//
// Covered here: eth_getLogs and citrate_getLogs with `latest..latest` while
// admitted > applied, a sibling stored at the applied height, concurrent apply
// (including a rewind while a request runs), and log filters created with
// `fromBlock: "latest"` (eth_newFilter + eth_getFilterChanges/eth_getFilterLogs).
//
// Drives the real registered IoHandler over RocksDB. The applied tip is moved
// with `put_applied_tip`, the write the canonical applicator makes on every
// apply and reorg. Blocks above the applied tip carry no receipts, as on a
// node that has admitted them but not applied them.

use citrate_api::canonical_logs::GET_LOGS_METHOD;
use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_execution::types::{Address, Log, TransactionReceipt};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::{json, Value};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tempfile::TempDir;

fn hash_of(tag: u8, n: u64) -> Hash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = tag;
    Hash::new(h)
}

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

fn storage() -> (Arc<StorageManager>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let s = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    (s, tmp)
}

fn io(storage: Arc<StorageManager>) -> jsonrpc_core::IoHandler {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    register_eth_methods_with_finality(
        &mut io,
        storage,
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
        Arc::new(AtomicU64::new(0)),
    );
    io
}

fn call(io: &jsonrpc_core::IoHandler, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let resp = io.handle_request_sync(&req).expect("response");
    serde_json::from_str(&resp).expect("json")
}

fn hex_u64(v: &Value) -> u64 {
    let s = v.as_str().expect("hex string");
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex number")
}

/// A block at `height` on `parent` carrying one tx with one log. With
/// `receipt`, the receipt its execution writes is stored too (an applied
/// block); without, it is only admitted.
fn put(storage: &StorageManager, tag: u8, height: u64, parent: Hash, receipt: bool) -> Block {
    let t = Transaction {
        hash: hash_of(tag ^ 0x0F, height),
        nonce: height,
        from: PublicKey::new([1u8; 32]),
        to: Some(PublicKey::new([2u8; 32])),
        gas_limit: 50_000,
        gas_price: 2_000_000_000,
        signature: Signature::new([7u8; 64]),
        chain_id: Some(40204),
        ..Default::default()
    };
    let b = BlockBuilder::new()
        .hash(hash_of(tag, height))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .gas_limit(30_000_000)
        .transactions(vec![t.clone()])
        .build_unhashed();
    storage.blocks.put_block(&b).expect("block");
    if receipt {
        write_receipt(storage, &b);
    }
    b
}

fn write_receipt(storage: &StorageManager, b: &Block) {
    let t = &b.transactions[0];
    let r = TransactionReceipt {
        tx_hash: t.hash,
        block_hash: b.hash(),
        block_number: b.header.height,
        from: Address([1u8; 20]),
        to: Some(Address([2u8; 20])),
        gas_used: 30_000,
        status: true,
        logs: vec![Log {
            address: Address([0xC0; 20]),
            topics: vec![hash_of(0x55, b.header.height)],
            data: vec![b.hash().as_bytes()[31]],
        }],
        output: vec![],
        eth_tx_type: 0,
        effective_gas_price: 2_000_000_000,
        revert_reason: None,
    };
    storage
        .transactions
        .put_receipt(&t.hash, &r)
        .expect("receipt");
}

/// The A chain `a0..=a{n}`; blocks up to `applied` have receipts and the
/// applied tip is `a{applied}`. Blocks above it are admitted only.
fn chain(storage: &StorageManager, n: u64, applied: u64) -> Vec<Block> {
    let mut out = Vec::new();
    let mut parent = Hash::default();
    for h in 0..=n {
        let b = put(storage, 0xA0, h, parent, h <= applied);
        parent = b.hash();
        out.push(b);
    }
    tip(storage, &out[applied as usize]);
    out
}

fn tip(storage: &StorageManager, b: &Block) {
    storage
        .blocks
        .put_applied_tip(&b.hash(), b.header.height)
        .expect("applied tip");
}

/// `(blockNumber, blockHash)` of every log in an eth_getLogs-style array.
fn logs_of(v: &Value) -> Vec<(u64, String)> {
    v.as_array()
        .unwrap_or_else(|| panic!("expected a log array, got {v}"))
        .iter()
        .map(|l| {
            (
                hex_u64(&l["blockNumber"]),
                l["blockHash"].as_str().expect("blockHash").to_string(),
            )
        })
        .collect()
}

fn get_logs(io: &jsonrpc_core::IoHandler, filter: Value) -> Vec<(u64, String)> {
    let v = call(io, "eth_getLogs", json!([filter]));
    assert!(v.get("error").is_none(), "eth_getLogs {filter}: {v}");
    logs_of(&v["result"])
}

fn block_number(io: &jsonrpc_core::IoHandler) -> u64 {
    hex_u64(&call(io, "eth_blockNumber", json!([]))["result"])
}

/// Admitted height 8, applied tip 5: `latest..latest` is the applied tip's
/// block, not an empty list. The same for `pending`, for an omitted toBlock,
/// and for `fromBlock: latest` with a numeric toBlock above it.
#[test]
fn latest_to_latest_serves_the_applied_tip_when_admitted_is_ahead() {
    let (storage, _tmp) = storage();
    let a = chain(&storage, 8, 5);
    let io = io(storage.clone());
    assert_eq!(block_number(&io), 8, "stored headers are ahead of the tip");

    let at_tip = vec![(5, hx(&a[5].hash()))];
    assert_eq!(
        get_logs(&io, json!({"fromBlock": "latest", "toBlock": "latest"})),
        at_tip,
        "latest..latest is the applied tip"
    );
    assert_eq!(
        get_logs(&io, json!({"fromBlock": "pending", "toBlock": "pending"})),
        at_tip
    );
    assert_eq!(get_logs(&io, json!({"fromBlock": "latest"})), at_tip);
    assert_eq!(
        get_logs(&io, json!({"fromBlock": "latest", "toBlock": "0x8"})),
        at_tip
    );
    // A range below latest is unchanged: it ends at the applied tip.
    assert_eq!(
        get_logs(&io, json!({"fromBlock": "0x3", "toBlock": "latest"}))
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
    // An explicit range above the applied tip has nothing executed in it.
    assert_eq!(
        get_logs(&io, json!({"fromBlock": "0x6", "toBlock": "0x8"})),
        vec![]
    );

    // citrate_getLogs: the same block, and `through` names it.
    let v = call(
        &io,
        GET_LOGS_METHOD,
        json!([{"fromBlock": "latest", "toBlock": "latest"}]),
    );
    assert!(v.get("error").is_none(), "{v}");
    assert_eq!(logs_of(&v["result"]["logs"]), at_tip, "{v}");
    assert_eq!(
        v["result"]["through"],
        json!({"number": "0x5", "hash": hx(&a[5].hash())}),
        "{v}"
    );
}

/// A sibling stored after the executed block at the applied height takes the
/// height index; `latest..latest` still names the executed block.
#[test]
fn latest_names_the_executed_block_not_a_sibling_at_the_tip() {
    let (storage, _tmp) = storage();
    let a = chain(&storage, 7, 5);
    // b5: a sibling of a5 (same parent a4), stored after it, never executed.
    let b5 = put(&storage, 0xB0, 5, a[4].hash(), false);
    assert_eq!(
        storage.blocks.get_block_by_height(5).expect("index"),
        Some(b5.hash()),
        "the height index names the sibling"
    );
    let io = io(storage.clone());

    let want = vec![(5, hx(&a[5].hash()))];
    assert_eq!(
        get_logs(&io, json!({"fromBlock": "latest", "toBlock": "latest"})),
        want
    );
    let v = call(
        &io,
        GET_LOGS_METHOD,
        json!([{"fromBlock": "latest", "toBlock": "latest"}]),
    );
    assert_eq!(logs_of(&v["result"]["logs"]), want, "{v}");
    assert_eq!(v["result"]["through"]["hash"], hx(&a[5].hash()), "{v}");

    // The filter path names the executed block too.
    let id = call(&io, "eth_newFilter", json!([{"fromBlock": "latest"}]))["result"].clone();
    assert_eq!(
        logs_of(&call(&io, "eth_getFilterLogs", json!([id]))["result"]),
        want
    );
}

/// While the applied tip moves (forward, and back by one) under concurrent
/// requests, every `latest..latest` answer is exactly one log, the executed
/// block at the tip one read of it named: never empty, never a block of
/// another height or chain.
#[test]
fn latest_to_latest_under_concurrent_apply_is_never_empty() {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (storage, _tmp) = storage();
    // Admitted to 40, applied to 30; the writer moves the tip over 10..=30.
    let a = chain(&storage, 40, 30);
    let by_height: HashMap<u64, String> =
        a.iter().map(|b| (b.header.height, hx(&b.hash()))).collect();
    let io = io(storage.clone());

    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let storage = storage.clone();
        let stop = stop.clone();
        let tips: Vec<(Hash, u64)> = a[10..=30]
            .iter()
            .map(|b| (b.hash(), b.header.height))
            .collect();
        std::thread::spawn(move || {
            let mut writes = 0u64;
            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                // Forward one block, then (every other step) back one: an
                // apply followed by a one-block rewind.
                let (h, n) = tips[i % tips.len()];
                storage.blocks.put_applied_tip(&h, n).expect("applied tip");
                i = if writes % 2 == 0 {
                    i + 2
                } else {
                    i.saturating_sub(1)
                };
                writes += 1;
            }
            writes
        })
    };

    for i in 0..2_000u32 {
        let filter = if i % 2 == 0 {
            json!({"fromBlock": "latest", "toBlock": "latest"})
        } else {
            json!({"fromBlock": "latest"})
        };
        let logs = get_logs(&io, filter.clone());
        assert_eq!(logs.len(), 1, "read {i} {filter}: {logs:?}");
        let (n, h) = &logs[0];
        assert!(
            (10..=30).contains(n),
            "read {i}: height {n} was never applied"
        );
        assert_eq!(&by_height[n], h, "read {i}: not the executed block at {n}");

        let v = call(
            &io,
            GET_LOGS_METHOD,
            json!([{"fromBlock": "latest", "toBlock": "latest"}]),
        );
        assert!(v.get("error").is_none(), "read {i}: {v}");
        let logs = logs_of(&v["result"]["logs"]);
        assert_eq!(logs.len(), 1, "read {i}: {v}");
        assert_eq!(hex_u64(&v["result"]["through"]["number"]), logs[0].0, "{v}");
    }
    stop.store(true, Ordering::Relaxed);
    let writes = writer.join().expect("writer thread");
    assert!(writes > 0, "writer never ran");
}

/// A log filter created with `fromBlock: latest` while admitted > applied
/// starts at the applied tip: blocks applied afterwards are delivered by
/// eth_getFilterChanges, each exactly once, and eth_getFilterLogs serves the
/// applied tip.
#[test]
fn filter_from_latest_starts_at_the_applied_tip() {
    let (storage, _tmp) = storage();
    let a = chain(&storage, 8, 5);
    let io = io(storage.clone());

    let id = call(&io, "eth_newFilter", json!([{"fromBlock": "latest"}]))["result"].clone();
    assert!(id.is_string(), "{id}");
    assert_eq!(
        logs_of(&call(&io, "eth_getFilterLogs", json!([id]))["result"]),
        vec![(5, hx(&a[5].hash()))],
        "eth_getFilterLogs from latest is the applied tip"
    );
    assert_eq!(
        logs_of(&call(&io, "eth_getFilterChanges", json!([id]))["result"]),
        vec![],
        "nothing applied since creation"
    );

    // Apply 6 and 7.
    for b in &a[6..=7] {
        write_receipt(&storage, b);
        tip(&storage, b);
    }
    assert_eq!(
        logs_of(&call(&io, "eth_getFilterChanges", json!([id]))["result"]),
        vec![(6, hx(&a[6].hash())), (7, hx(&a[7].hash()))],
        "blocks applied after creation are delivered"
    );
    // Apply 8; only 8 is new.
    write_receipt(&storage, &a[8]);
    tip(&storage, &a[8]);
    assert_eq!(
        logs_of(&call(&io, "eth_getFilterChanges", json!([id]))["result"]),
        vec![(8, hx(&a[8].hash()))]
    );
    assert_eq!(
        logs_of(&call(&io, "eth_getFilterChanges", json!([id]))["result"]),
        vec![]
    );
}

/// A filter whose fromBlock is above the applied tip delivers every block from
/// fromBlock once the tip passes it, even when the tip jumps past it between
/// two polls.
#[test]
fn filter_from_a_future_block_is_not_skipped_by_a_tip_jump() {
    let (storage, _tmp) = storage();
    let a = chain(&storage, 9, 5);
    let io = io(storage.clone());

    let id = call(&io, "eth_newFilter", json!([{"fromBlock": "0x7"}]))["result"].clone();
    assert_eq!(
        logs_of(&call(&io, "eth_getFilterChanges", json!([id]))["result"]),
        vec![]
    );
    for b in &a[6..=9] {
        write_receipt(&storage, b);
    }
    tip(&storage, &a[9]);
    assert_eq!(
        logs_of(&call(&io, "eth_getFilterChanges", json!([id]))["result"])
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>(),
        vec![7, 8, 9]
    );
}
