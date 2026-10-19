// citrate_executedHead: the persisted applied tip `{number, hash}`, the same
// tip eth_getLogs serves up to. eth_blockNumber reports the stored-header
// height, which can be ahead of it; a log scanner bounds its progress by this
// method instead.
//
// Drives the real registered IoHandler over RocksDB. The applied tip is moved
// with `put_applied_tip`, the write the canonical applicator makes on every
// apply and reorg (the node crate's `canonical_apply` tests cover the
// applicator itself driving this method's data source).

use citrate_api::canonical_logs::{executed_head, ExecutedChainIndex, EXECUTED_HEAD_METHOD};
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

fn head(io: &jsonrpc_core::IoHandler) -> Value {
    let v = call(io, EXECUTED_HEAD_METHOD, json!([]));
    assert!(v.get("error").is_none(), "unexpected error: {v}");
    v["result"].clone()
}

fn block_number(io: &jsonrpc_core::IoHandler) -> u64 {
    let v = call(io, "eth_blockNumber", json!([]));
    let s = v["result"].as_str().expect("hex");
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("number")
}

/// `(blockNumber, blockHash)` of the highest log eth_getLogs serves over the
/// whole stored range.
fn top_log(io: &jsonrpc_core::IoHandler) -> (String, String) {
    let v = call(
        io,
        "eth_getLogs",
        json!([{"fromBlock": "0x0", "toBlock": "latest"}]),
    );
    assert!(v.get("error").is_none(), "unexpected error: {v}");
    let last = v["result"]
        .as_array()
        .and_then(|a| a.last().cloned())
        .expect("at least one log");
    (
        last["blockNumber"].as_str().expect("n").to_string(),
        last["blockHash"].as_str().expect("h").to_string(),
    )
}

/// Store a block at `height` on `parent` carrying one tx with one log, and the
/// receipt its producer writes.
fn put(storage: &StorageManager, tag: u8, height: u64, parent: Hash) -> Block {
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
    let r = TransactionReceipt {
        tx_hash: t.hash,
        block_hash: b.hash(),
        block_number: height,
        from: Address([1u8; 20]),
        to: Some(Address([2u8; 20])),
        gas_used: 30_000,
        status: true,
        logs: vec![Log {
            address: Address([0xC0; 20]),
            topics: vec![hash_of(tag ^ 0x55, height)],
            data: vec![tag],
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
    b
}

/// The A chain `a0..=a{n}` (a0 is genesis).
fn a_chain(storage: &StorageManager, n: u64) -> Vec<Block> {
    let mut out = Vec::new();
    let mut parent = Hash::default();
    for h in 0..=n {
        let b = put(storage, 0xA0, h, parent);
        parent = b.hash();
        out.push(b);
    }
    out
}

fn tip(storage: &StorageManager, b: &Block) {
    storage
        .blocks
        .put_applied_tip(&b.hash(), b.header.height)
        .expect("applied tip");
}

/// The method reports exactly the tip eth_getLogs walks from: the resolver's
/// highest executed block, and the block of the highest log served.
#[test]
fn executed_head_equals_the_tip_get_logs_serves() {
    let (storage, _tmp) = storage();
    let a = a_chain(&storage, 5);
    tip(&storage, &a[3]);
    let io = io(storage.clone());

    let h = head(&io);
    assert_eq!(h, json!({"number": "0x3", "hash": hx(&a[3].hash())}));

    let resolved = ExecutedChainIndex::new()
        .executed_hashes(&storage, 0, u64::MAX)
        .expect("executed chain");
    assert_eq!(resolved.last(), Some(&(3, a[3].hash())));
    assert_eq!(executed_head(&storage), Ok((a[3].hash(), 3)));

    assert_eq!(top_log(&io), ("0x3".to_string(), hx(&a[3].hash())));
}

/// Stored headers ahead of execution: eth_blockNumber reports them, the
/// executed head does not, and getLogs serves nothing above the executed head.
#[test]
fn executed_head_is_below_block_number_when_headers_are_ahead() {
    let (storage, _tmp) = storage();
    let a = a_chain(&storage, 7);
    tip(&storage, &a[4]);
    let io = io(storage.clone());

    assert_eq!(block_number(&io), 7, "stored-header height");
    assert_eq!(head(&io)["number"], "0x4");
    let above = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x5", "toBlock": "0x7"}]),
    );
    assert_eq!(above["result"], json!([]), "{above}");
}

/// Apply advances the head; a reorg replaces its hash (same height, higher, or
/// lower) and getLogs follows the same tip each time.
#[test]
fn executed_head_moves_with_apply_and_with_reorg() {
    let (storage, _tmp) = storage();
    let a = a_chain(&storage, 4);
    tip(&storage, &a[2]);
    let io = io(storage.clone());
    assert_eq!(
        head(&io),
        json!({"number": "0x2", "hash": hx(&a[2].hash())})
    );

    // Apply a3, a4.
    tip(&storage, &a[3]);
    assert_eq!(
        head(&io),
        json!({"number": "0x3", "hash": hx(&a[3].hash())})
    );
    tip(&storage, &a[4]);
    assert_eq!(
        head(&io),
        json!({"number": "0x4", "hash": hx(&a[4].hash())})
    );
    assert_eq!(top_log(&io), ("0x4".to_string(), hx(&a[4].hash())));

    // Reorg onto a B branch forking at a2: b3, b4, b5.
    let b3 = put(&storage, 0xB0, 3, a[2].hash());
    let b4 = put(&storage, 0xB0, 4, b3.hash());
    let b5 = put(&storage, 0xB0, 5, b4.hash());
    tip(&storage, &b5);
    assert_eq!(head(&io), json!({"number": "0x5", "hash": hx(&b5.hash())}));
    assert_eq!(top_log(&io), ("0x5".to_string(), hx(&b5.hash())));
    let at3 = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x3", "toBlock": "0x3"}]),
    );
    assert_eq!(at3["result"][0]["blockHash"], hx(&b3.hash()), "{at3}");

    // Reorg back to the shorter A branch: the head goes DOWN, and a client
    // that recorded 0x5 sees both the lower number and a different hash.
    tip(&storage, &a[4]);
    assert_eq!(
        head(&io),
        json!({"number": "0x4", "hash": hx(&a[4].hash())})
    );
    assert_eq!(top_log(&io), ("0x4".to_string(), hx(&a[4].hash())));
    assert_eq!(block_number(&io), 5, "stored headers stay at b5");
}

/// No persisted applied tip: -32603, never the height index's guess.
#[test]
fn executed_head_errors_without_a_persisted_tip() {
    let (storage, _tmp) = storage();
    let io = io(storage.clone());
    let empty = call(&io, EXECUTED_HEAD_METHOD, json!([]));
    assert_eq!(empty["error"]["code"], -32603, "{empty}");
    assert!(empty.get("result").is_none(), "{empty}");

    // Blocks stored (height index populated), but nothing executed.
    a_chain(&storage, 3);
    let stored = call(&io, EXECUTED_HEAD_METHOD, json!([]));
    assert_eq!(stored["error"]["code"], -32603, "{stored}");
    assert!(
        stored["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("no applied tip")),
        "{stored}"
    );
    assert!(stored.get("result").is_none(), "{stored}");
}

fn hex_u64(v: &Value) -> u64 {
    let s = v.as_str().expect("hex string");
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex number")
}

/// `(height, hash)` of the executed head.
fn head_pair(io: &jsonrpc_core::IoHandler) -> (u64, String) {
    let h = head(io);
    (
        hex_u64(&h["number"]),
        h["hash"].as_str().expect("hash").to_string(),
    )
}

/// `(blockNumber, blockHash)` of every log eth_getLogs serves over `from..=to`.
fn logs_between(io: &jsonrpc_core::IoHandler, from: u64, to: u64) -> Vec<(u64, String)> {
    let v = call(
        io,
        "eth_getLogs",
        json!([{"fromBlock": format!("0x{from:x}"), "toBlock": format!("0x{to:x}")}]),
    );
    assert!(v.get("error").is_none(), "unexpected error: {v}");
    v["result"]
        .as_array()
        .expect("log array")
        .iter()
        .map(|l| {
            (
                hex_u64(&l["blockNumber"]),
                l["blockHash"].as_str().expect("blockHash").to_string(),
            )
        })
        .collect()
}

/// Concurrent apply: a writer thread moves the applied tip (apply forward,
/// reorg sideways and down) the way the applicator does, while a reader
/// follows the scanner's read order: head, then eth_getLogs up to head.number.
/// The head is always an applied-tip pair the writer wrote (never the height
/// index's block at that height, which is a non-executed sibling here), and
/// getLogs never serves above it.
#[test]
fn executed_head_under_concurrent_apply_never_leads_get_logs() {
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, Ordering};

    let (storage, _tmp) = storage();
    // A chain a0..=a9; tips only reach a6, so a7..a9 are stored headers
    // ahead of execution (eth_blockNumber = 9).
    let a = a_chain(&storage, 9);
    // B branch forking at a2: the tip reorgs between A and B.
    let mut b = Vec::new();
    let mut parent = a[2].hash();
    for h in 3..=6 {
        let blk = put(&storage, 0xB0, h, parent);
        parent = blk.hash();
        b.push(blk);
    }
    // Non-executed siblings at 3..=6, written last: the height index names
    // these, and no applied tip ever does.
    for h in 3..=6 {
        put(&storage, 0xC0, h, a[h as usize - 1].hash());
    }
    let tips: Vec<(Hash, u64)> = a[3..=6]
        .iter()
        .chain(b.iter())
        .map(|blk| (blk.hash(), blk.header.height))
        .collect();
    let valid: HashSet<(u64, String)> = tips.iter().map(|(h, n)| (*n, hx(h))).collect();
    let parent_of: HashMap<String, String> = a
        .iter()
        .chain(b.iter())
        .map(|blk| (hx(&blk.hash()), hx(&blk.header.selected_parent_hash)))
        .collect();
    tip(&storage, &a[3]);
    let io = io(storage.clone());

    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let storage = storage.clone();
        let stop = stop.clone();
        let tips = tips.clone();
        std::thread::spawn(move || {
            let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
            let mut writes = 0u64;
            while !stop.load(Ordering::Relaxed) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let (h, n) = tips[(x % tips.len() as u64) as usize];
                storage.blocks.put_applied_tip(&h, n).expect("applied tip");
                writes += 1;
            }
            writes
        })
    };

    let mut below = 0u32;
    for _ in 0..2_000 {
        let (n, hash) = head_pair(&io);
        assert!(
            valid.contains(&(n, hash.clone())),
            "head ({n}, {hash}) is not an applied tip the writer wrote"
        );
        let by_hash = call(&io, "eth_getBlockByHash", json!([hash, false]));
        assert_eq!(hex_u64(&by_hash["result"]["number"]), n, "{by_hash}");

        let logs = logs_between(&io, 0, n);
        let top = logs.last().map(|(h, _)| *h).expect("genesis log at least");
        assert!(top <= n, "getLogs served height {top} above head {n}");
        if top < n {
            below += 1;
        }
        // Contiguous from genesis, one block per height, on one
        // selected-parent chain.
        for (i, (height, bh)) in logs.iter().enumerate() {
            assert_eq!(*height, i as u64, "gap or duplicate in {logs:?}");
            if i > 0 {
                assert_eq!(parent_of[bh], logs[i - 1].1, "not one chain: {logs:?}");
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    let writes = writer.join().expect("writer thread");
    assert!(writes > 0, "writer never ran");
    // `below` counts reads where the tip moved down between the two calls:
    // allowed (the scanner persists min(h1, h2)), never the reverse.
    eprintln!("tip writes: {writes}, reads served below head: {below}");
}

/// A sibling at the executed head's height, stored after the executed block:
/// the height index names the sibling, the executed head names the executed
/// block. eth_getBlockByNumber(head.number) returns the sibling, so a client
/// confirms the head with eth_getBlockByHash(head.hash), never by number.
#[test]
fn executed_head_names_the_executed_block_not_a_later_sibling() {
    let (storage, _tmp) = storage();
    let a = a_chain(&storage, 3);
    tip(&storage, &a[3]);
    // Sibling of a3 (same parent a2), written after the tip.
    let s3 = put(&storage, 0xC0, 3, a[2].hash());
    let io = io(storage.clone());

    assert_eq!(
        head(&io),
        json!({"number": "0x3", "hash": hx(&a[3].hash())})
    );

    let by_hash = call(&io, "eth_getBlockByHash", json!([hx(&a[3].hash()), false]));
    assert_eq!(by_hash["result"]["number"], "0x3", "{by_hash}");
    assert_eq!(by_hash["result"]["hash"], hx(&a[3].hash()), "{by_hash}");

    // The documented caveat: by number, the height index's last writer wins.
    let by_number = call(&io, "eth_getBlockByNumber", json!(["0x3", false]));
    assert_eq!(by_number["result"]["hash"], hx(&s3.hash()), "{by_number}");

    // getLogs at the head height serves the executed block's logs.
    assert_eq!(logs_between(&io, 3, 3), vec![(3, hx(&a[3].hash()))]);
}

/// One pass of the documented scanner protocol (core/api/README.md): read h1,
/// getLogs over `from..=min(target, h1)`, read h2, persist at most
/// `min(target, h1, h2) - margin`. Returns the logs served and that height
/// (`None`: don't advance).
fn scan_once(
    io: &jsonrpc_core::IoHandler,
    from: u64,
    target: u64,
    margin: u64,
    between: impl FnOnce(),
) -> (Vec<(u64, String)>, Option<u64>) {
    let (h1, _) = head_pair(io);
    between();
    let logs = logs_between(io, from, target.min(h1));
    let (h2, _) = head_pair(io);
    (logs, target.min(h1).min(h2).checked_sub(margin))
}

/// The head rewinds between the scanner's two reads (h2 < h1): getLogs served
/// only up to the rewound tip, so progress persisted at min(h1, h2) − margin
/// never passes a height whose logs were not served. Persisting h1 would skip
/// a height.
#[test]
fn scanner_protocol_survives_a_rewind_between_reads() {
    let (storage, _tmp) = storage();
    let a = a_chain(&storage, 4);
    let b3 = put(&storage, 0xB0, 3, a[2].hash());
    let b4 = put(&storage, 0xB0, 4, b3.hash());
    let b5 = put(&storage, 0xB0, 5, b4.hash());
    tip(&storage, &b5);
    let io = io(storage.clone());

    let (logs, persist) = scan_once(&io, 0, 100, 0, || tip(&storage, &a[4]));
    let served: Vec<u64> = logs.iter().map(|(h, _)| *h).collect();
    assert_eq!(served, vec![0, 1, 2, 3, 4], "served after rewind");
    assert_eq!(logs[4].1, hx(&a[4].hash()), "rewound branch served");
    assert_eq!(persist, Some(4), "min(h1 = 5, h2 = 4) - 0");
    assert!(
        persist.is_some_and(|p| p <= *served.last().expect("served")),
        "persisted above the highest height served"
    );

    // With a margin, progress stays that far below min(h1, h2).
    tip(&storage, &b5);
    let (_, persist) = scan_once(&io, 0, 100, 2, || tip(&storage, &a[4]));
    assert_eq!(persist, Some(2));

    // The target bounds the range; a margin above the head means no progress.
    tip(&storage, &a[4]);
    let (logs, persist) = scan_once(&io, 0, 2, 0, || {});
    assert_eq!(logs.last().map(|(h, _)| *h), Some(2));
    assert_eq!(persist, Some(2), "min(target = 2, h1, h2)");
    let (_, persist) = scan_once(&io, 0, 100, 9, || {});
    assert_eq!(persist, None);
}
