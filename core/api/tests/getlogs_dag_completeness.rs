// eth_getLogs over a GhostDAG store: logs come from the EXECUTED chain (the
// applied tip's selected-parent chain), not from the last-writer-wins height
// index, and an over-limit range is a -32005 error instead of a silent clamp.
//
// Drives the real registered IoHandler over RocksDB.

use citrate_api::canonical_logs::{
    bound_log_range, ExecutedChainIndex, LogIndexError, CHECKPOINT_STRIDE, LOG_INDEX_RETRY_CODE,
    SETTLED_DEPTH,
};
use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_execution::types::{Address, Log, TransactionReceipt};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::Value;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tempfile::TempDir;

const EMITTER: [u8; 20] = [0xC0; 20];

fn hash_of(tag: u8, n: u64) -> Hash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = tag;
    Hash::new(h)
}

fn tx(tag: u8, n: u64) -> Transaction {
    Transaction {
        hash: hash_of(tag, n),
        nonce: n,
        from: PublicKey::new([1u8; 32]),
        to: Some(PublicKey::new([2u8; 32])),
        gas_limit: 50_000,
        gas_price: 2_000_000_000,
        signature: Signature::new([7u8; 64]),
        chain_id: Some(40204),
        ..Default::default()
    }
}

fn topic(tag: u8, n: u64) -> Hash {
    hash_of(tag ^ 0x55, n)
}

fn block(hash: Hash, parent: Hash, merge: Vec<Hash>, height: u64, txs: Vec<Transaction>) -> Block {
    BlockBuilder::new()
        .hash(hash)
        .parent(parent)
        .merge_parents(merge)
        .height(height)
        .timestamp(1_000_000 + height)
        .gas_limit(30_000_000)
        .transactions(txs)
        .build_unhashed()
}

/// Store the receipt a producer would write after executing `t` in `b`, with
/// `logs` log entries whose topic0 identifies the tx.
fn put_receipt(storage: &StorageManager, b: &Block, t: &Transaction, tag: u8, logs: usize) {
    let logs = (0..logs)
        .map(|i| Log {
            address: Address(EMITTER),
            topics: vec![topic(tag, b.header.height), hash_of(0x77, i as u64)],
            data: vec![tag, i as u8],
        })
        .collect();
    let r = TransactionReceipt {
        tx_hash: t.hash,
        block_hash: b.hash(),
        block_number: b.header.height,
        from: Address([1u8; 20]),
        to: Some(Address([2u8; 20])),
        gas_used: 30_000,
        status: true,
        logs,
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
    let req =
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let resp = io.handle_request_sync(&req).expect("response");
    serde_json::from_str(&resp).expect("json")
}

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

/// The fork at height 2 the old reader got wrong:
///
/// ```text
///   g ── a1 ── a2 ── a3        (selected-parent chain; applied tip = a3)
///          \        /
///           b2 ────'           (sibling at height 2, merged by a3 as a merge parent)
/// ```
///
/// a2 and b2 share height 2 and each carries a log-emitting tx. Only a2's tx
/// executed (the applicator follows selected parents; merge parents are never
/// executed). b2 is written AFTER a2, so the height index names b2. The node
/// also holds a receipt for b2's tx, as the producer of a block that then lost
/// fork choice does.
struct Fork {
    storage: Arc<StorageManager>,
    _tmp: TempDir,
    a: Vec<Block>,
    b2: Block,
}

fn fork() -> Fork {
    let (storage, tmp) = storage();
    let g = block(hash_of(0xEE, 0), Hash::default(), vec![], 0, vec![]);
    storage.blocks.put_block(&g).expect("g");

    let a1_tx = tx(0xA1, 1);
    let a1 = block(hash_of(0xA0, 1), g.hash(), vec![], 1, vec![a1_tx.clone()]);
    storage.blocks.put_block(&a1).expect("a1");
    put_receipt(&storage, &a1, &a1_tx, 0xA1, 1);

    // Two txs in a2 so transactionIndex / per-block logIndex are exercised.
    let a2_tx0 = tx(0xA2, 2);
    let a2_tx1 = tx(0xA3, 2);
    let a2 = block(
        hash_of(0xA0, 2),
        a1.hash(),
        vec![],
        2,
        vec![a2_tx0.clone(), a2_tx1.clone()],
    );
    storage.blocks.put_block(&a2).expect("a2");
    put_receipt(&storage, &a2, &a2_tx0, 0xA2, 2);
    put_receipt(&storage, &a2, &a2_tx1, 0xA3, 1);

    let b2_tx = tx(0xB2, 2);
    let b2 = block(hash_of(0xB0, 2), a1.hash(), vec![], 2, vec![b2_tx.clone()]);
    storage
        .blocks
        .put_block(&b2)
        .expect("b2 (later: takes the height index)");
    put_receipt(&storage, &b2, &b2_tx, 0xB2, 1);

    let a3_tx = tx(0xA4, 3);
    let a3 = block(
        hash_of(0xA0, 3),
        a2.hash(),
        vec![b2.hash()],
        3,
        vec![a3_tx.clone()],
    );
    storage.blocks.put_block(&a3).expect("a3");
    put_receipt(&storage, &a3, &a3_tx, 0xA4, 1);

    storage
        .blocks
        .put_applied_tip(&a3.hash(), 3)
        .expect("applied tip");
    assert_eq!(
        storage.blocks.get_block_by_height(2).expect("index"),
        Some(b2.hash()),
        "precondition: the height index names the later sibling"
    );
    Fork {
        storage,
        _tmp: tmp,
        a: vec![g, a1, a2, a3],
        b2,
    }
}

fn logs(io: &jsonrpc_core::IoHandler, filter: Value) -> Vec<Value> {
    let v = call(io, "eth_getLogs", serde_json::json!([filter]));
    assert!(v.get("error").is_none(), "unexpected error: {v}");
    v["result"].as_array().expect("array").clone()
}

/// The executed block's logs at a height whose index entry was taken by a
/// sibling are returned, and the never-executed sibling's are not.
#[test]
fn getlogs_returns_the_executed_block_at_a_contested_height() {
    let f = fork();
    let io = io(f.storage.clone());
    let a2 = &f.a[2];
    let got = logs(
        &io,
        serde_json::json!({"fromBlock": "0x2", "toBlock": "0x2"}),
    );
    assert_eq!(got.len(), 3, "a2 carries 3 logs over 2 txs: {got:?}");
    for l in &got {
        assert_eq!(l["blockHash"], hx(&a2.hash()));
        assert_eq!(l["blockNumber"], "0x2");
    }
    assert!(
        got.iter().all(|l| l["blockHash"] != hx(&f.b2.hash())),
        "the merged sibling's tx never executed; its logs must not be served"
    );
    // Filtering for the sibling's topic finds nothing.
    let b2_topic = hx(&topic(0xB2, 2));
    let none = logs(
        &io,
        serde_json::json!({"fromBlock": "0x0", "toBlock": "latest", "topics": [b2_topic]}),
    );
    assert!(none.is_empty(), "{none:?}");
}

/// Canonical execution order across the range, transactionIndex = position in
/// the block, logIndex = position of the log in its block.
#[test]
fn getlogs_is_in_execution_order_with_per_block_indices() {
    let f = fork();
    let io = io(f.storage.clone());
    let got = logs(
        &io,
        serde_json::json!({"fromBlock": "0x0", "toBlock": "latest"}),
    );
    let shape: Vec<(String, String, String, String)> = got
        .iter()
        .map(|l| {
            (
                l["blockNumber"].as_str().unwrap().to_string(),
                l["transactionHash"].as_str().unwrap().to_string(),
                l["transactionIndex"].as_str().unwrap().to_string(),
                l["logIndex"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let s = |x: &str| x.to_string();
    assert_eq!(
        shape,
        vec![
            (s("0x1"), hx(&hash_of(0xA1, 1)), s("0x0"), s("0x0")),
            (s("0x2"), hx(&hash_of(0xA2, 2)), s("0x0"), s("0x0")),
            (s("0x2"), hx(&hash_of(0xA2, 2)), s("0x0"), s("0x1")),
            (s("0x2"), hx(&hash_of(0xA3, 2)), s("0x1"), s("0x2")),
            (s("0x3"), hx(&hash_of(0xA4, 3)), s("0x0"), s("0x0")),
        ]
    );
    // A filtered query keeps the block-relative logIndex (not a per-response
    // counter): a2's tx1 log is logIndex 2 even when it is the only match.
    let only = logs(
        &io,
        serde_json::json!({"fromBlock": "0x2", "toBlock": "0x2", "topics": [hx(&topic(0xA3, 2))]}),
    );
    assert_eq!(only.len(), 1);
    assert_eq!(only[0]["logIndex"], "0x2");
    assert_eq!(only[0]["transactionIndex"], "0x1");
}

/// blockHash / blockNumber / transactionIndex agree with eth_getTransactionReceipt
/// for every served log.
#[test]
fn getlogs_fields_match_the_receipt() {
    let f = fork();
    let io = io(f.storage.clone());
    let got = logs(
        &io,
        serde_json::json!({"fromBlock": "0x0", "toBlock": "latest"}),
    );
    assert!(!got.is_empty());
    for l in &got {
        let r = call(
            &io,
            "eth_getTransactionReceipt",
            serde_json::json!([l["transactionHash"]]),
        );
        let r = &r["result"];
        assert_eq!(l["blockHash"], r["blockHash"], "{l} vs {r}");
        assert_eq!(l["blockNumber"], r["blockNumber"], "{l} vs {r}");
        assert_eq!(l["transactionIndex"], r["transactionIndex"], "{l} vs {r}");
    }
}

/// Heights above the applied tip have not executed: a block stored there is
/// not served even though the height index names it.
#[test]
fn getlogs_stops_at_the_applied_tip() {
    let f = fork();
    let a3 = &f.a[3];
    let t = tx(0xA5, 4);
    let a4 = block(hash_of(0xA0, 4), a3.hash(), vec![], 4, vec![t.clone()]);
    f.storage.blocks.put_block(&a4).expect("a4");
    put_receipt(&f.storage, &a4, &t, 0xA5, 1);
    let io = io(f.storage.clone());
    let got = logs(
        &io,
        serde_json::json!({"fromBlock": "0x4", "toBlock": "0x4"}),
    );
    assert!(got.is_empty(), "a4 is admitted but not applied: {got:?}");
    f.storage
        .blocks
        .put_applied_tip(&a4.hash(), 4)
        .expect("tip");
    let got = logs(
        &io,
        serde_json::json!({"fromBlock": "0x4", "toBlock": "0x4"}),
    );
    assert_eq!(got.len(), 1);
}

/// An over-limit range is a -32005 error naming the limit; exactly the limit passes.
#[test]
fn getlogs_over_limit_range_errors() {
    let f = fork();
    let io = io(f.storage.clone());
    let v = call(
        &io,
        "eth_getLogs",
        serde_json::json!([{"fromBlock": "0x0", "toBlock": "0x3e9"}]),
    );
    assert_eq!(v["error"]["code"], -32005, "{v}");
    assert_eq!(v["error"]["data"]["maxBlockRange"], 1000, "{v}");
    let v = call(
        &io,
        "eth_getLogs",
        serde_json::json!([{"fromBlock": "0x0", "toBlock": "0x3e8"}]),
    );
    assert!(v.get("error").is_none(), "{v}");
    // The legacy clamp (operator opt-in) keeps the old window.
    assert_eq!(bound_log_range(0, 0x3e9, true).unwrap(), 1000);
}

/// Deep history: the walk caches settled checkpoints, a later page starts from
/// one, and a contested height deep in history still resolves to the executed
/// block.
#[test]
fn executed_chain_index_resolves_deep_history_through_checkpoints() {
    let (storage, _tmp) = storage();
    let top = SETTLED_DEPTH + CHECKPOINT_STRIDE + 10;
    let mut parent = Hash::default();
    let mut canon = Vec::new();
    for h in 0..=top {
        let b = block(hash_of(0xA0, h), parent, vec![], h, vec![]);
        storage.blocks.put_block(&b).expect("block");
        parent = b.hash();
        canon.push(b.hash());
        if h == 5 {
            // A late sibling at a deep height takes the index entry.
            let s = block(hash_of(0xB0, 5), canon[4], vec![], 5, vec![]);
            storage.blocks.put_block(&s).expect("sibling");
        }
    }
    storage.blocks.put_applied_tip(&parent, top).expect("tip");
    assert_eq!(
        storage.blocks.get_block_by_height(5).unwrap(),
        Some(hash_of(0xB0, 5))
    );

    let idx = ExecutedChainIndex::new();
    let first = idx.executed_hashes(&storage, 0, 10).expect("walk");
    let hashes: Vec<Hash> = first.iter().map(|(_, h)| *h).collect();
    assert_eq!(hashes, canon[0..=10].to_vec());
    assert_eq!(idx.checkpoint_count(), 2, "checkpoints at 0 and 1024");

    // A page just below the 1024 checkpoint resolves from it.
    let page = idx.executed_hashes(&storage, 1_000, 1_020).expect("page");
    let hashes: Vec<Hash> = page.iter().map(|(_, h)| *h).collect();
    assert_eq!(hashes, canon[1_000..=1_020].to_vec());

    // A tip regression to an ancestor is served from the same chain.
    storage
        .blocks
        .put_applied_tip(&canon[2_000], 2_000)
        .expect("tip");
    let again = idx
        .executed_hashes(&storage, 3, 6)
        .expect("after regression");
    assert_eq!(
        again.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        canon[3..=6].to_vec()
    );
}

/// A broken executed chain is an error, never a silently shortened answer.
#[test]
fn executed_chain_index_errors_on_a_missing_ancestor() {
    let (storage, _tmp) = storage();
    let g = block(hash_of(0xA0, 0), Hash::default(), vec![], 0, vec![]);
    storage.blocks.put_block(&g).expect("g");
    // Height 2 names a selected parent that is not stored.
    let b2 = block(hash_of(0xA0, 2), hash_of(0xA0, 1), vec![], 2, vec![]);
    storage.blocks.put_block(&b2).expect("b2");
    storage.blocks.put_applied_tip(&b2.hash(), 2).expect("tip");
    let idx = ExecutedChainIndex::new();
    assert!(idx.executed_hashes(&storage, 0, 2).is_err());
    // A range entirely above the gap is still served.
    assert_eq!(idx.executed_hashes(&storage, 2, 2).expect("top").len(), 1);
}

/// Builds a straight chain `tag` over heights `lo..=hi` on top of `parent`,
/// every block carrying one log-emitting tx with a receipt. Returns the hashes.
fn build_branch(
    storage: &StorageManager,
    tag: u8,
    mut parent: Hash,
    lo: u64,
    hi: u64,
) -> Vec<Hash> {
    let mut out = Vec::new();
    for h in lo..=hi {
        let t = tx(tag, h);
        let b = block(hash_of(tag, h), parent, vec![], h, vec![t.clone()]);
        storage.blocks.put_block(&b).expect("block");
        put_receipt(storage, &b, &t, tag, 1);
        parent = b.hash();
        out.push(parent);
    }
    out
}

/// A chain replacement deeper than any fixed depth (the spine-rebuild path is
/// bounded only by the finalized floor) that lands at `extra` blocks above the
/// old tip, with no query in between. Logs for a height under a warmed
/// checkpoint must come from the new chain, never the abandoned one.
fn deep_replacement_serves_the_new_chain(extra: u64) {
    const OLD: u8 = 0xA0;
    const NEW: u8 = 0xB0;
    let (storage, _tmp) = storage();
    let top = SETTLED_DEPTH + CHECKPOINT_STRIDE + 10;
    let g = block(hash_of(0xEE, 0), Hash::default(), vec![], 0, vec![]);
    storage.blocks.put_block(&g).expect("g");
    let old = build_branch(&storage, OLD, g.hash(), 1, top);
    storage
        .blocks
        .put_applied_tip(old.last().expect("tip"), top)
        .expect("tip");

    let io = io(storage.clone());
    // Warm the handler's cache: a deep page caches the checkpoint at 1024 (an
    // OLD block), and the page itself is served from the OLD chain.
    let warm = logs(
        &io,
        serde_json::json!({"fromBlock": "0x3e8", "toBlock": "0x3fc"}),
    );
    assert_eq!(warm.len(), 21);
    assert!(warm.iter().all(|l| l["topics"][0]
        .as_str()
        .expect("t0")
        .ends_with(&format!("{:02x}", OLD ^ 0x55))));

    // Fork at height 500 (below the cached 1024 checkpoint, > 1,000 below the
    // tip) and replace the applied chain.
    let fork_parent = old[499];
    let new = build_branch(&storage, NEW, fork_parent, 501, top + extra);
    storage
        .blocks
        .put_applied_tip(new.last().expect("tip"), top + extra)
        .expect("tip");

    let got = logs(
        &io,
        serde_json::json!({"fromBlock": "0x3e8", "toBlock": "0x3fc"}),
    );
    assert_eq!(got.len(), 21, "{got:?}");
    for (i, l) in got.iter().enumerate() {
        let h = 1_000 + i as u64;
        assert_eq!(l["blockHash"], hx(&hash_of(NEW, h)), "height {h}: {l}");
        assert_eq!(l["topics"][0], hx(&topic(NEW, h)), "height {h}: {l}");
    }
    // Below the fork point the shared history is unchanged.
    let shared = logs(
        &io,
        serde_json::json!({"fromBlock": "0x1f0", "toBlock": "0x1f4"}),
    );
    assert!(shared.iter().all(|l| l["topics"][0]
        .as_str()
        .expect("t0")
        .ends_with(&format!("{:02x}", OLD ^ 0x55))));
}

#[test]
fn getlogs_after_deep_replacement_at_the_same_tip_height() {
    deep_replacement_serves_the_new_chain(0);
}

#[test]
fn getlogs_after_deep_replacement_at_a_higher_tip() {
    deep_replacement_serves_the_new_chain(7);
}

/// The index level: checkpoints survive a tip that extends the anchor; a
/// replacement serves the new chain above its fork.
#[test]
fn executed_chain_index_keeps_checkpoints_only_on_extension() {
    let (storage, _tmp) = storage();
    let top = SETTLED_DEPTH + CHECKPOINT_STRIDE + 10;
    let g = block(hash_of(0xEE, 0), Hash::default(), vec![], 0, vec![]);
    storage.blocks.put_block(&g).expect("g");
    let old = build_branch(&storage, 0xA0, g.hash(), 1, top + 3);
    storage
        .blocks
        .put_applied_tip(&old[top as usize - 1], top)
        .expect("tip");
    let idx = ExecutedChainIndex::new();
    idx.executed_hashes(&storage, 0, 10).expect("warm");
    assert_eq!(idx.checkpoint_count(), 2);

    // Extension: kept.
    storage
        .blocks
        .put_applied_tip(&old[top as usize + 2], top + 3)
        .expect("tip");
    idx.executed_hashes(&storage, 1_000, 1_001).expect("page");
    assert_eq!(
        idx.checkpoint_count(),
        2,
        "an extending tip keeps the cache"
    );

    // Replacement at the same height: dropped, and the page follows the new chain.
    let new = build_branch(&storage, 0xB0, old[9], 11, top + 3);
    storage
        .blocks
        .put_applied_tip(new.last().expect("tip"), top + 3)
        .expect("tip");
    let page = idx.executed_hashes(&storage, 1_000, 1_001).expect("page");
    assert_eq!(
        page.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        vec![hash_of(0xB0, 1_000), hash_of(0xB0, 1_001)]
    );
}

/// A cold walk deeper than the per-request header budget is split across
/// retries: each call reads at most the budget, publishes the checkpoints it
/// reached, and returns a retryable error; the retry that fits the budget
/// answers in full.
#[test]
fn executed_chain_index_bounds_a_cold_walk_and_progresses_on_retry() {
    let (storage, _tmp) = storage();
    let top = 6_000u64;
    let mut parent = Hash::default();
    let mut canon = Vec::new();
    for h in 0..=top {
        let b = block(hash_of(0xA0, h), parent, vec![], h, vec![]);
        storage.blocks.put_block(&b).expect("block");
        parent = b.hash();
        canon.push(parent);
    }
    storage.blocks.put_applied_tip(&parent, top).expect("tip");

    let idx = ExecutedChainIndex::with_walk_budget(2_500);
    // 6000 -> 3501: reaches the 4096 checkpoint.
    match idx.executed_hashes(&storage, 0, 10) {
        Err(LogIndexError::Retry(_)) => {}
        other => panic!("first cold call must be a bounded retry, got {other:?}"),
    }
    assert_eq!(idx.checkpoint_count(), 1);
    // 4096 -> 1597: reaches 3072 and 2048.
    assert!(matches!(
        idx.executed_hashes(&storage, 0, 10),
        Err(LogIndexError::Retry(_))
    ));
    assert_eq!(idx.checkpoint_count(), 3);
    // 2048 -> 0 fits the budget.
    let got = idx
        .executed_hashes(&storage, 0, 10)
        .expect("third call answers");
    assert_eq!(
        got.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        canon[0..=10].to_vec()
    );
    // Warm: a query near the tip and one deep in history both fit.
    assert!(idx.executed_hashes(&storage, 5_990, 6_000).is_ok());
    assert!(idx.executed_hashes(&storage, 100, 200).is_ok());

    let rpc = LogIndexError::Retry("x".into()).to_rpc_error();
    assert_eq!(
        rpc.code,
        jsonrpc_core::ErrorCode::ServerError(LOG_INDEX_RETRY_CODE)
    );
    assert_eq!(rpc.data.expect("data")["retryable"], true);
}

/// A cold fill deep below the tip must make progress while the tip advances.
/// A second thread keeps appending blocks and serving near-tip queries (each
/// re-anchors the cache on a verified extension) while the deep request is
/// retried. Every retry has to keep the checkpoints it found, so the deep
/// request completes within the same number of tries as with no churn.
#[test]
fn executed_chain_index_cold_fill_survives_tip_churn() {
    cold_fill_under_churn(0);
}

/// The same with several concurrent near-tip readers. A reader can read the
/// applied tip, lose the cache lock to a reader that read the next commit, and
/// re-anchor on a tip one block BELOW the anchor. That tip is an ancestor of
/// the anchor, so neither the cache nor an in-flight fill may be dropped.
#[test]
fn executed_chain_index_cold_fill_survives_concurrent_readers() {
    cold_fill_under_churn(8);
}

fn cold_fill_under_churn(readers: usize) {
    use std::sync::atomic::{AtomicBool, Ordering};

    let (storage, _tmp) = storage();
    let top = 12_000u64;
    let budget = 2_000u64;
    let mut parent = Hash::default();
    let mut canon = Vec::new();
    for h in 0..=top {
        let b = block(hash_of(0xA0, h), parent, vec![], h, vec![]);
        storage.blocks.put_block(&b).expect("block");
        parent = b.hash();
        canon.push(parent);
    }
    storage.blocks.put_applied_tip(&parent, top).expect("tip");

    let idx = Arc::new(ExecutedChainIndex::with_walk_budget(budget));
    let stop = Arc::new(AtomicBool::new(false));
    let appended = Arc::new(AtomicU64::new(0));
    let churn = {
        let (storage, idx, stop, appended) =
            (storage.clone(), idx.clone(), stop.clone(), appended.clone());
        std::thread::spawn(move || {
            let mut parent = parent;
            let mut h = top;
            while !stop.load(Ordering::Acquire) {
                h += 1;
                let b = block(hash_of(0xA0, h), parent, vec![], h, vec![]);
                storage.blocks.put_block(&b).expect("block");
                parent = b.hash();
                storage.blocks.put_applied_tip(&parent, h).expect("tip");
                appended.fetch_add(1, Ordering::AcqRel);
                let near = idx
                    .executed_hashes(&storage, h.saturating_sub(5), h)
                    .expect("near-tip query fits the budget");
                assert_eq!(near.len(), 6);
            }
        })
    };

    let reader_threads: Vec<_> = (0..readers)
        .map(|_| {
            let (storage, idx, stop) = (storage.clone(), idx.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let (_, h) = storage
                        .blocks
                        .get_applied_tip()
                        .expect("tip read")
                        .expect("tip");
                    let near = idx
                        .executed_hashes(&storage, h.saturating_sub(5), h)
                        .expect("near-tip query fits the budget");
                    assert_eq!(near.len(), 6);
                }
            })
        })
        .collect();

    // Each retry restarts at the lowest checkpoint it reached, so a cold fill
    // advances at least one stride per try. Allow slack for the blocks the
    // churn thread adds above the start.
    let max_tries = top / CHECKPOINT_STRIDE + 4;
    let mut tries = 0u64;
    let mut overlapped = 0u64;
    let mut last_count = idx.checkpoint_count();
    let got = loop {
        tries += 1;
        assert!(
            tries <= max_tries,
            "deep query not complete after {max_tries} tries; {} checkpoints kept",
            idx.checkpoint_count()
        );
        let before = appended.load(Ordering::Acquire);
        let res = idx.executed_hashes(&storage, 0, 10);
        if appended.load(Ordering::Acquire) != before {
            overlapped += 1;
        }
        match res {
            Ok(v) => break v,
            Err(LogIndexError::Retry(m)) => {
                let count = idx.checkpoint_count();
                assert!(
                    count > last_count,
                    "retry {tries} kept no new checkpoints ({count} after {last_count}): {m}"
                );
                last_count = count;
            }
            Err(e) => panic!("deep query failed: {e:?}"),
        }
    };
    stop.store(true, Ordering::Release);
    churn.join().expect("churn thread");
    for r in reader_threads {
        r.join().expect("reader thread");
    }

    assert!(overlapped > 0, "the tip never advanced during a deep walk");
    assert_eq!(
        got.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        canon[0..=10].to_vec()
    );
    assert!(idx.checkpoint_count() as u64 >= top / CHECKPOINT_STRIDE - 1);
}

/// A chain of `top + 1` blocks (tag 0xA0) with the applied tip at `top`.
fn straight_chain(storage: &StorageManager, top: u64) -> Vec<Hash> {
    let mut parent = Hash::default();
    let mut canon = Vec::new();
    for h in 0..=top {
        let b = block(hash_of(0xA0, h), parent, vec![], h, vec![]);
        storage.blocks.put_block(&b).expect("block");
        parent = b.hash();
        canon.push(parent);
    }
    storage.blocks.put_applied_tip(&parent, top).expect("tip");
    canon
}

/// A request that read the applied tip before a concurrent commit re-anchors on
/// an ancestor of the anchor. Deterministically: warm the cache, set the applied
/// tip back to its parent, query. The tip only went back along the same chain,
/// so every checkpoint stays, and the next commit keeps them too.
#[test]
fn executed_chain_index_keeps_checkpoints_on_an_older_tip_of_the_same_chain() {
    let (storage, _tmp) = storage();
    let top = SETTLED_DEPTH + 4 * CHECKPOINT_STRIDE + 10;
    let canon = straight_chain(&storage, top);
    let idx = ExecutedChainIndex::new();
    idx.executed_hashes(&storage, 0, 10).expect("warm");
    let warm = idx.checkpoint_count();
    assert_eq!(warm, 5, "checkpoints at 0, 1024, 2048, 3072, 4096");

    // The stale reader: the tip it sees is the parent of the anchor.
    storage
        .blocks
        .put_applied_tip(&canon[top as usize - 1], top - 1)
        .expect("tip");
    let near = idx
        .executed_hashes(&storage, top - 6, top - 1)
        .expect("near tip");
    assert_eq!(near.len(), 6);
    assert_eq!(
        idx.checkpoint_count(),
        warm,
        "an older tip on the anchor's chain must keep every checkpoint"
    );

    // Back to the newer tip: still kept, and a deep page is served from them.
    storage
        .blocks
        .put_applied_tip(&canon[top as usize], top)
        .expect("tip");
    let page = idx.executed_hashes(&storage, 2_000, 2_010).expect("page");
    assert_eq!(
        page.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        canon[2_000..=2_010].to_vec()
    );
    assert_eq!(idx.checkpoint_count(), warm);
}

/// A reorg near the tip (the applicator's rollback window) replaces a few
/// blocks; every checkpoint lies far below the fork and stays valid. A fork
/// between two checkpoints keeps exactly the ones at or below it, and pages
/// follow the new chain above it.
#[test]
fn executed_chain_index_keeps_checkpoints_below_the_fork_point() {
    let (storage, _tmp) = storage();
    let top = SETTLED_DEPTH + 4 * CHECKPOINT_STRIDE + 10;
    let canon = straight_chain(&storage, top);
    let idx = ExecutedChainIndex::new();
    idx.executed_hashes(&storage, 0, 10).expect("warm");
    let warm = idx.checkpoint_count();
    assert_eq!(warm, 5);

    // Shallow reorg: fork 5 below the tip, the new branch ends one higher.
    let fork = top - 5;
    let side = build_branch(&storage, 0xB0, canon[fork as usize], fork + 1, top + 1);
    storage
        .blocks
        .put_applied_tip(side.last().expect("tip"), top + 1)
        .expect("tip");
    let near = idx
        .executed_hashes(&storage, fork, top + 1)
        .expect("near tip");
    let mut want = vec![canon[fork as usize]];
    want.extend(side.iter().copied());
    assert_eq!(near.iter().map(|(_, h)| *h).collect::<Vec<_>>(), want);
    assert_eq!(
        idx.checkpoint_count(),
        warm,
        "a reorg above every checkpoint must keep them all"
    );

    // Deep fork between the 2048 and 3072 checkpoints: 0, 1024, 2048 stay.
    let deep = 2_500u64;
    let other = build_branch(&storage, 0xC0, canon[deep as usize], deep + 1, top + 2);
    storage
        .blocks
        .put_applied_tip(other.last().expect("tip"), top + 2)
        .expect("tip");
    let page = idx
        .executed_hashes(&storage, 2_495, 2_505)
        .expect("page across the fork");
    let mut want = canon[2_495..=2_500].to_vec();
    want.extend(other[..5].iter().copied());
    assert_eq!(page.iter().map(|(_, h)| *h).collect::<Vec<_>>(), want);
    // 0, 1024, 2048 kept; the walk from the new tip re-collected 3072 and 4096
    // on the new chain.
    assert_eq!(
        idx.checkpoint_count(),
        5,
        "checkpoints at or below the fork must survive a deeper reorg"
    );
    let shared = idx.executed_hashes(&storage, 1_000, 1_010).expect("shared");
    assert_eq!(
        shared.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        canon[1_000..=1_010].to_vec()
    );
    let page = idx.executed_hashes(&storage, 3_000, 3_010).expect("page");
    assert_eq!(
        page.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        other[(3_000 - deep - 1) as usize..=(3_010 - deep - 1) as usize].to_vec()
    );
}

/// The same tx is in the executed block and in a sibling that lost fork
/// choice, and the stored receipt names the sibling (this node produced it).
/// That receipt does not describe the executed block's run of the tx, so its
/// logs are not served at that height; the other tx's logs are, with logIndex
/// counted over the served receipts only.
#[test]
fn getlogs_skips_a_receipt_that_names_a_lost_sibling_for_the_same_tx() {
    let (storage, _tmp) = storage();
    let g = block(hash_of(0xEE, 0), Hash::default(), vec![], 0, vec![]);
    storage.blocks.put_block(&g).expect("g");
    let shared = tx(0xD1, 1);
    let own = tx(0xD2, 1);
    // The lost sibling, produced here first: its receipt for `shared` is stored.
    let lost = block(hash_of(0xB0, 1), g.hash(), vec![], 1, vec![shared.clone()]);
    storage.blocks.put_block(&lost).expect("lost");
    put_receipt(&storage, &lost, &shared, 0xD1, 2);
    // The executed block carries the same tx, then one of its own.
    let exec = block(
        hash_of(0xA0, 1),
        g.hash(),
        vec![],
        1,
        vec![shared.clone(), own.clone()],
    );
    storage.blocks.put_block(&exec).expect("exec");
    put_receipt(&storage, &exec, &own, 0xD2, 1);
    let top = block(hash_of(0xA0, 2), exec.hash(), vec![lost.hash()], 2, vec![]);
    storage.blocks.put_block(&top).expect("top");
    storage.blocks.put_applied_tip(&top.hash(), 2).expect("tip");

    let io = io(storage.clone());
    let got = logs(
        &io,
        serde_json::json!({"fromBlock": "0x1", "toBlock": "0x1"}),
    );
    assert!(
        got.iter().all(|l| l["blockHash"] != hx(&lost.hash())),
        "a receipt naming the lost sibling was served at the executed height: {got:?}"
    );
    assert!(
        got.iter()
            .all(|l| l["transactionHash"] != hx(&shared.hash)),
        "{got:?}"
    );
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0]["blockHash"], hx(&exec.hash()));
    assert_eq!(got[0]["transactionHash"], hx(&own.hash));
    assert_eq!(got[0]["transactionIndex"], "0x1");
    assert_eq!(got[0]["logIndex"], "0x0");
}

/// A cached checkpoint whose block has been purged from the store is not
/// trusted: the request errors (-32603, never a shortened answer) and the cache
/// is dropped. Once the block is stored again, the range is served from the tip.
#[test]
fn executed_chain_index_drops_a_checkpoint_whose_block_was_purged() {
    let (storage, _tmp) = storage();
    let top = SETTLED_DEPTH + CHECKPOINT_STRIDE + 10;
    let canon = straight_chain(&storage, top);
    let idx = ExecutedChainIndex::new();
    idx.executed_hashes(&storage, 0, 10).expect("warm");
    assert_eq!(idx.checkpoint_count(), 2, "checkpoints at 0 and 1024");

    let purged = storage
        .blocks
        .get_block(&canon[1_024])
        .expect("read")
        .expect("block");
    storage.blocks.delete_block(&canon[1_024]).expect("purge");
    match idx.executed_hashes(&storage, 1_000, 1_000) {
        Err(LogIndexError::Unavailable(m)) => assert!(m.contains("not stored"), "{m}"),
        other => panic!("expected Unavailable over a purged block, got {other:?}"),
    }
    assert_eq!(
        idx.checkpoint_count(),
        0,
        "a checkpoint whose block is gone must be dropped, not kept"
    );

    storage.blocks.put_block(&purged).expect("re-store");
    let got = idx.executed_hashes(&storage, 1_000, 1_000).expect("page");
    assert_eq!(got, vec![(1_000, canon[1_000])]);
}

/// A selected parent that claims a height at or above its child is a malformed
/// executed chain: an error, not an answer that skips the bad block.
#[test]
fn executed_chain_index_errors_on_a_parent_above_its_child() {
    let (storage, _tmp) = storage();
    let g = block(hash_of(0xA0, 0), Hash::default(), vec![], 0, vec![]);
    storage.blocks.put_block(&g).expect("g");
    let a1 = block(hash_of(0xA0, 1), g.hash(), vec![], 1, vec![]);
    storage.blocks.put_block(&a1).expect("a1");
    // Height 3, but the selected parent of the height-2 tip.
    let bad = block(hash_of(0xBA, 3), a1.hash(), vec![], 3, vec![]);
    storage.blocks.put_block(&bad).expect("bad");
    let t2 = block(hash_of(0xA0, 2), bad.hash(), vec![], 2, vec![]);
    storage.blocks.put_block(&t2).expect("t2");
    storage.blocks.put_applied_tip(&t2.hash(), 2).expect("tip");

    let idx = ExecutedChainIndex::new();
    match idx.executed_hashes(&storage, 0, 2) {
        Err(LogIndexError::Unavailable(m)) => assert!(m.contains("malformed"), "{m}"),
        other => panic!("expected a malformed-chain error, got {other:?}"),
    }
    let io = io(storage.clone());
    let v = call(
        &io,
        "eth_getLogs",
        serde_json::json!([{"fromBlock": "0x0", "toBlock": "0x2"}]),
    );
    assert_eq!(v["error"]["code"], -32603, "{v}");
}
