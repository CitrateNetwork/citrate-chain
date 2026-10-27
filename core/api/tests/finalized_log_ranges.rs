// Checkpoint finality Stage 1c (follow-up to the by-hash tag resolution): a log
// range bounded by `finalized` / `safe` in Enforced mode reads the heights at or
// below the certified height from the CERTIFIED CHAIN (the selected-parent chain
// that ends at the certified block), never from the height index, whose entry at
// a height is the LAST block written there and can be an uncertified sibling.
// `latest` / numeric ranges and the height-only source (Legacy / Observed) keep
// reading the height index. Drives the real registered IoHandler over a real
// RocksDB-backed StorageManager.

use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::{FilterRegistry, FinalizedTagSource, VerifiedFinalized};
use citrate_consensus::types::{BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_execution::types::{Address, Log, TransactionReceipt};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::{json, Value};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tempfile::TempDir;

const EMITTER: Address = Address([0x42; 20]);

fn tx(n: u64) -> Transaction {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = 0x66;
    Transaction {
        hash: Hash::new(h),
        nonce: n,
        from: PublicKey::new([1u8; 32]),
        to: Some(PublicKey::new([2u8; 32])),
        gas_limit: 21_000,
        gas_price: 2_000_000_000,
        signature: Signature::new([7u8; 64]),
        chain_id: Some(40204),
        ..Default::default()
    }
}

/// The topic each block's single log carries (distinct per block tag).
fn topic(tag: u8) -> Hash {
    Hash::new([tag; 32])
}

/// Store a block at `height` under `parent` with one tx whose receipt carries
/// one log tagged `tag`.
fn put(storage: &StorageManager, tag: u8, height: u64, parent: Hash) -> Hash {
    let mut raw = [tag; 32];
    raw[..8].copy_from_slice(&height.to_be_bytes());
    let t = tx(u64::from(tag).saturating_mul(1000).saturating_add(height));
    let b = BlockBuilder::new()
        .hash(Hash::new(raw))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .gas_limit(30_000_000)
        .gas_used(21_000)
        .base_fee_per_gas(1_000_000_000)
        .transactions(vec![t.clone()])
        .build_unhashed();
    storage.blocks.put_block(&b).expect("put block");
    let block_hash = b.hash();
    storage.transactions.put_transaction(&t).expect("put tx");
    let receipt = TransactionReceipt {
        tx_hash: t.hash,
        block_hash,
        block_number: height,
        from: Address([1; 20]),
        to: Some(Address([2; 20])),
        gas_used: 21_000,
        status: true,
        logs: vec![Log {
            address: EMITTER,
            topics: vec![topic(tag)],
            data: vec![tag],
        }],
        output: vec![],
        eth_tx_type: 0,
        effective_gas_price: 0,
        revert_reason: None,
    };
    storage
        .transactions
        .put_receipt(&t.hash, &receipt)
        .expect("put receipt");
    block_hash
}

/// genesis <- a1 <- a2 (certified), plus b2: an uncertified sibling of a2 at
/// height 2 written AFTER it, so the height index names b2 at height 2.
struct Fork {
    storage: Arc<StorageManager>,
    _tmp: TempDir,
    a1: Hash,
    a2: Hash,
    b2: Hash,
}

fn fork() -> Fork {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let genesis = put(&storage, 0xEE, 0, Hash::default());
    let a1 = put(&storage, 0xA1, 1, genesis);
    let a2 = put(&storage, 0xA2, 2, a1);
    let b2 = put(&storage, 0xB2, 2, a1);
    assert_eq!(
        storage.blocks.get_block_by_height(2).expect("index"),
        Some(b2),
        "precondition: the height index names the later-written sibling"
    );
    Fork {
        storage,
        _tmp: tmp,
        a1,
        a2,
        b2,
    }
}

fn io(storage: Arc<StorageManager>, src: FinalizedTagSource) -> jsonrpc_core::IoHandler {
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
        src,
    );
    io
}

fn call(io: &jsonrpc_core::IoHandler, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let resp = io.handle_request_sync(&req).expect("response");
    serde_json::from_str(&resp).expect("json")
}

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

fn verified(pairs: &[(u64, Hash)]) -> FinalizedTagSource {
    let v = Arc::new(VerifiedFinalized::new());
    for (h, hash) in pairs {
        v.record(*h, *hash);
    }
    FinalizedTagSource::Verified(v)
}

/// `(blockHash, first topic)` of each log in a result, in order.
fn logs_of(resp: &Value) -> Vec<(String, String)> {
    let arr = resp["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected a log array: {resp}"));
    arr.iter()
        .map(|l| {
            (
                l["blockHash"].as_str().unwrap_or_default().to_string(),
                l["topics"][0].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn log_at(block: &Hash, tag: u8) -> (String, String) {
    (hx(block), hx(&topic(tag)))
}

fn new_filter(io: &jsonrpc_core::IoHandler, criteria: Value) -> String {
    let r = call(io, "eth_newFilter", json!([criteria]));
    r["result"]
        .as_str()
        .unwrap_or_else(|| panic!("eth_newFilter: {r}"))
        .to_string()
}

#[test]
fn get_logs_to_finalized_returns_only_the_certified_chain() {
    let f = fork();
    let io = io(f.storage.clone(), verified(&[(2, f.a2)]));
    for tag in ["finalized", "safe"] {
        let r = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": "0x1", "toBlock": tag}]),
        );
        assert_eq!(
            logs_of(&r),
            vec![log_at(&f.a1, 0xA1), log_at(&f.a2, 0xA2)],
            "{tag}: {r}"
        );
        // Topic filter for the sibling's log: nothing.
        let r = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": "0x0", "toBlock": tag, "topics": [hx(&topic(0xB2))]}]),
        );
        assert_eq!(logs_of(&r), vec![], "{tag}: {r}");
    }
}

#[test]
fn numeric_and_latest_ranges_still_read_the_height_index() {
    let f = fork();
    let io = io(f.storage.clone(), verified(&[(2, f.a2)]));
    for to in ["0x2", "latest"] {
        let r = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": "0x2", "toBlock": to}]),
        );
        assert_eq!(logs_of(&r), vec![log_at(&f.b2, 0xB2)], "{to}: {r}");
    }
}

#[test]
fn height_only_source_is_unchanged() {
    // Legacy / Observed carry a height-only source (in production it stays at
    // genesis); a range read under it keeps using the height index.
    let f = fork();
    let io = io(f.storage.clone(), Arc::new(AtomicU64::new(2)).into());
    let r = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x2", "toBlock": "finalized"}]),
    );
    assert_eq!(logs_of(&r), vec![log_at(&f.b2, 0xB2)], "{r}");
}

#[test]
fn from_finalized_to_latest_splits_at_the_certified_height() {
    let f = fork();
    // a3 extends the certified block; above the certified height the range
    // reads the height index exactly as `latest` does.
    let a3 = put(&f.storage, 0xA3, 3, f.a2);
    let io = io(f.storage.clone(), verified(&[(2, f.a2)]));
    let r = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "finalized", "toBlock": "latest"}]),
    );
    assert_eq!(
        logs_of(&r),
        vec![log_at(&f.a2, 0xA2), log_at(&a3, 0xA3)],
        "{r}"
    );
}

#[test]
fn a_height_the_certified_chain_steps_over_has_no_logs() {
    let f = fork();
    // c4 sits at height 4 with selected parent a2 (height 2): the certified
    // chain has no block at height 3, while the height index holds an
    // unrelated block there.
    let x3 = put(&f.storage, 0xC3, 3, f.b2);
    let c4 = put(&f.storage, 0xC4, 4, f.a2);
    let io = io(f.storage.clone(), verified(&[(4, c4)]));
    let r = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x2", "toBlock": "finalized"}]),
    );
    assert_eq!(
        logs_of(&r),
        vec![log_at(&f.a2, 0xA2), log_at(&c4, 0xC4)],
        "{r}"
    );
    assert!(!r.to_string().contains(&hx(&x3)), "{r}");
}

#[test]
fn a_range_too_deep_below_the_certified_block_is_refused() {
    let f = fork();
    // A verified height far above the start of the range: the walk would exceed
    // FINALIZED_RANGE_MAX_WALK, so the request is refused rather than walked.
    let depth = citrate_api::finalized_tag::FINALIZED_RANGE_MAX_WALK + 1;
    let io = io(f.storage.clone(), verified(&[(depth, f.a2)]));
    let r = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x0", "toBlock": "finalized"}]),
    );
    assert_eq!(r["error"]["code"], -32602, "{r}");
    let msg = r["error"]["message"].as_str().unwrap_or_default();
    assert!(msg.contains("below the finalized block"), "{r}");
}

#[test]
fn new_filter_to_finalized_follows_the_certified_chain() {
    let f = fork();
    let io = io(f.storage.clone(), verified(&[(2, f.a2)]));
    for tag in ["finalized", "safe"] {
        let id = new_filter(&io, json!({"fromBlock": "0x1", "toBlock": tag}));
        let r = call(&io, "eth_getFilterLogs", json!([id]));
        assert_eq!(
            logs_of(&r),
            vec![log_at(&f.a1, 0xA1), log_at(&f.a2, 0xA2)],
            "{tag} getFilterLogs: {r}"
        );
        // Changes start above the head at creation (>= the certified height):
        // nothing new, and never the sibling.
        let r = call(&io, "eth_getFilterChanges", json!([id]));
        assert_eq!(logs_of(&r), vec![], "{tag} getFilterChanges: {r}");
    }
}

#[test]
fn new_filter_from_finalized_reports_new_blocks_through_get_filter_changes() {
    let f = fork();
    let io = io(f.storage.clone(), verified(&[(2, f.a2)]));
    let id = new_filter(&io, json!({"fromBlock": "finalized"}));
    let a3 = put(&f.storage, 0xA3, 3, f.a2);
    let r = call(&io, "eth_getFilterChanges", json!([id]));
    assert_eq!(logs_of(&r), vec![log_at(&a3, 0xA3)], "{r}");
    // The whole filter range: certified chain at height 2, height index above.
    let r = call(&io, "eth_getFilterLogs", json!([id]));
    assert_eq!(
        logs_of(&r),
        vec![log_at(&f.a2, 0xA2), log_at(&a3, 0xA3)],
        "{r}"
    );
    let r = call(&io, "eth_getFilterChanges", json!([id]));
    assert_eq!(logs_of(&r), vec![], "{r}");
}
