// Checkpoint finality Stage 1c (R1): in Enforced mode a RANGE read anchored at
// `finalized` / `safe` (eth_getLogs bounds, the eth_feeHistory window) reads
// every height at or below the certified height from the CERTIFIED CHAIN: the
// selected-parent chain followed back from the certified block by hash. The
// block store's height index keeps the LAST block written at a height, which can
// be an uncertified sibling of a certified block or of one of its ancestors; it
// must never be what these ranges return. Drives the real registered IoHandler
// over a real RocksDB-backed StorageManager.

use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::{FilterRegistry, FinalizedTagSource, VerifiedFinalized};
use citrate_consensus::types::{BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_execution::types::{Address, Log, TransactionReceipt};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::TempDir;

const EMITTER: Address = Address([0x42; 20]);
const GWEI: u64 = 1_000_000_000;

fn tx(n: u64) -> Transaction {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = 0x55;
    Transaction {
        hash: Hash::new(h),
        nonce: n,
        from: PublicKey::new([1u8; 32]),
        to: Some(PublicKey::new([2u8; 32])),
        gas_limit: 21_000,
        gas_price: 20 * GWEI,
        signature: Signature::new([7u8; 64]),
        chain_id: Some(40204),
        ..Default::default()
    }
}

/// The topic each block's single log carries (distinct per block tag).
fn topic(tag: u8) -> Hash {
    Hash::new([tag; 32])
}

/// Store a block at `height` under `parent` with base fee `base_fee` and one tx
/// whose receipt carries one log tagged `tag`.
fn put(storage: &StorageManager, tag: u8, height: u64, parent: Hash, base_fee: u64) -> Hash {
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
        .base_fee_per_gas(base_fee)
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

fn new_storage() -> (Arc<StorageManager>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    (storage, tmp)
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

fn fee(v: u64) -> String {
    format!("0x{v:x}")
}

fn verified(pairs: &[(u64, Hash)]) -> FinalizedTagSource {
    verified_handle(pairs).1
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

/// Certified A2 and a LATER-WRITTEN sibling B2 at height 2 (distinct logs):
/// a log range bounded by finalized/safe returns A2's log and never B2's.
#[test]
fn get_logs_bounded_by_finalized_reads_the_certified_sibling() {
    let (storage, _tmp) = new_storage();
    let genesis = put(&storage, 0xEE, 0, Hash::default(), GWEI);
    let a1 = put(&storage, 0xA1, 1, genesis, GWEI);
    let a2 = put(&storage, 0xA2, 2, a1, GWEI);
    let b2 = put(&storage, 0xB2, 2, a1, GWEI);
    assert_eq!(
        storage.blocks.get_block_by_height(2).expect("index"),
        Some(b2),
        "precondition: the height index names the later-written sibling"
    );
    let io = io(storage.clone(), verified(&[(2, a2)]));
    for tag in ["finalized", "safe"] {
        let r = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": tag, "toBlock": tag}]),
        );
        assert_eq!(logs_of(&r), vec![log_at(&a2, 0xA2)], "{tag}..{tag}: {r}");
        let r = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": "0x1", "toBlock": tag}]),
        );
        assert_eq!(
            logs_of(&r),
            vec![log_at(&a1, 0xA1), log_at(&a2, 0xA2)],
            "0x1..{tag}: {r}"
        );
        let r = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": "0x0", "toBlock": tag, "topics": [hx(&topic(0xB2))]}]),
        );
        assert_eq!(logs_of(&r), vec![], "sibling topic, ..{tag}: {r}");
    }
    // Numeric / latest ranges keep reading the height index (unchanged).
    let r = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x2", "toBlock": "0x2"}]),
    );
    assert_eq!(logs_of(&r), vec![log_at(&b2, 0xB2)], "{r}");
}

/// A multi-block fee window ending at the certified A3 whose ANCESTOR height 2
/// holds a later-written noncanonical sibling B2: the window reports A2 (the
/// certified chain), not B2.
#[test]
fn fee_history_window_follows_the_certified_ancestry() {
    let (storage, _tmp) = new_storage();
    let genesis = put(&storage, 0xEE, 0, Hash::default(), GWEI);
    let a1 = put(&storage, 0xA1, 1, genesis, GWEI);
    let a2 = put(&storage, 0xA2, 2, a1, 2 * GWEI);
    let a3 = put(&storage, 0xA3, 3, a2, 3 * GWEI);
    let b2 = put(&storage, 0xB2, 2, a1, 9 * GWEI);
    assert_eq!(
        storage.blocks.get_block_by_height(2).expect("index"),
        Some(b2),
        "precondition: the height index names the later-written sibling"
    );
    let io = io(storage.clone(), verified(&[(3, a3)]));
    for tag in ["finalized", "safe"] {
        let fh = call(&io, "eth_feeHistory", json!(["0x3", tag, []]));
        assert_eq!(fh["result"]["oldestBlock"], "0x1", "{tag}: {fh}");
        assert_eq!(
            fh["result"]["baseFeePerGas"],
            json!([fee(GWEI), fee(2 * GWEI), fee(3 * GWEI), fee(3 * GWEI)]),
            "{tag}: {fh}"
        );
    }
    // `latest` keeps the height index (unchanged behaviour): B2 at height 2.
    let fh = call(&io, "eth_feeHistory", json!(["0x2", "latest", []]));
    assert_eq!(
        fh["result"]["baseFeePerGas"][0],
        fee(9 * GWEI),
        "latest: {fh}"
    );
}

/// A height the certified chain steps over (selected parent two heights down)
/// gets the empty-slot defaults in the fee window, never the height index's
/// unrelated block there.
#[test]
fn fee_history_height_stepped_over_by_the_certified_chain_is_empty() {
    let (storage, _tmp) = new_storage();
    let genesis = put(&storage, 0xEE, 0, Hash::default(), GWEI);
    let a1 = put(&storage, 0xA1, 1, genesis, GWEI);
    let a2 = put(&storage, 0xA2, 2, a1, 2 * GWEI);
    let b2 = put(&storage, 0xB2, 2, a1, 9 * GWEI);
    let _x3 = put(&storage, 0xC3, 3, b2, 8 * GWEI);
    let c4 = put(&storage, 0xC4, 4, a2, 4 * GWEI);
    let io = io(storage.clone(), verified(&[(4, c4)]));
    let fh = call(&io, "eth_feeHistory", json!(["0x3", "finalized", []]));
    assert_eq!(fh["result"]["oldestBlock"], "0x2", "{fh}");
    assert_eq!(
        fh["result"]["baseFeePerGas"],
        json!([fee(2 * GWEI), fee(GWEI), fee(4 * GWEI), fee(4 * GWEI)]),
        "{fh}"
    );
    assert_eq!(fh["result"]["gasUsedRatio"][1], json!(0.0), "{fh}");
}

fn verified_handle(pairs: &[(u64, Hash)]) -> (Arc<VerifiedFinalized>, FinalizedTagSource) {
    let v = Arc::new(VerifiedFinalized::new());
    for (h, hash) in pairs {
        v.record(*h, *hash);
    }
    (v.clone(), FinalizedTagSource::Verified(v))
}

fn error_code(resp: &Value) -> Option<i64> {
    resp.get("error").and_then(|e| e["code"].as_i64())
}

/// A range that straddles the certified floor: heights at or below it follow
/// the certified chain (a1, a2 — not the later-written sibling b2), heights
/// above it keep the height index (a3), for `fromBlock` numeric or a finality
/// tag and `toBlock` latest.
#[test]
fn get_logs_range_straddling_the_floor() {
    let (storage, _tmp) = new_storage();
    let genesis = put(&storage, 0xEE, 0, Hash::default(), GWEI);
    let a1 = put(&storage, 0xA1, 1, genesis, GWEI);
    let a2 = put(&storage, 0xA2, 2, a1, GWEI);
    let a3 = put(&storage, 0xA3, 3, a2, GWEI);
    let _b2 = put(&storage, 0xB2, 2, a1, GWEI);
    let io = io(storage.clone(), verified(&[(2, a2)]));
    for tag in ["finalized", "safe"] {
        let r = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": tag, "toBlock": "latest"}]),
        );
        assert_eq!(
            logs_of(&r),
            vec![log_at(&a2, 0xA2), log_at(&a3, 0xA3)],
            "{tag}..latest: {r}"
        );
        let r = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": "0x1", "toBlock": tag}]),
        );
        assert_eq!(
            logs_of(&r),
            vec![log_at(&a1, 0xA1), log_at(&a2, 0xA2)],
            "0x1..{tag}: {r}"
        );
    }
}

/// A competing branch that forks BELOW the certified floor (b1..b4, written
/// after the certified chain, so the height index names it at every height):
/// finalized/safe ranges and the fee window keep reading the certified chain.
#[test]
fn competing_branch_across_the_floor_is_never_read_as_finalized() {
    let (storage, _tmp) = new_storage();
    let genesis = put(&storage, 0xEE, 0, Hash::default(), GWEI);
    let a1 = put(&storage, 0xA1, 1, genesis, GWEI);
    let a2 = put(&storage, 0xA2, 2, a1, 2 * GWEI);
    let b1 = put(&storage, 0xB1, 1, genesis, 7 * GWEI);
    let b2 = put(&storage, 0xB2, 2, b1, 8 * GWEI);
    let b3 = put(&storage, 0xB3, 3, b2, 9 * GWEI);
    let _b4 = put(&storage, 0xB4, 4, b3, 9 * GWEI);
    for (h, b) in [(1, b1), (2, b2)] {
        assert_eq!(
            storage.blocks.get_block_by_height(h).expect("index"),
            Some(b),
            "precondition: the competing branch owns the height index at {h}"
        );
    }
    let io = io(storage.clone(), verified(&[(2, a2)]));
    for tag in ["finalized", "safe"] {
        let r = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": "0x0", "toBlock": tag}]),
        );
        assert_eq!(
            logs_of(&r),
            vec![log_at(&genesis, 0xEE), log_at(&a1, 0xA1), log_at(&a2, 0xA2)],
            "0x0..{tag}: {r}"
        );
        let fh = call(&io, "eth_feeHistory", json!(["0x2", tag, []]));
        assert_eq!(
            fh["result"]["baseFeePerGas"],
            json!([fee(GWEI), fee(2 * GWEI), fee(2 * GWEI)]),
            "{tag}: {fh}"
        );
    }
}

/// A certificate that arrives AFTER the sibling was written: before it, the
/// tags resolve to genesis; once the verified pair is recorded, the same
/// requests read the certified chain, never the sibling the index names.
#[test]
fn late_certificate_moves_ranges_onto_the_certified_chain() {
    let (storage, _tmp) = new_storage();
    let genesis = put(&storage, 0xEE, 0, Hash::default(), GWEI);
    let a1 = put(&storage, 0xA1, 1, genesis, GWEI);
    let a2 = put(&storage, 0xA2, 2, a1, 2 * GWEI);
    let (pairs, src) = verified_handle(&[]);
    let io = io(storage.clone(), src);
    let r = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x0", "toBlock": "finalized"}]),
    );
    assert_eq!(
        logs_of(&r),
        vec![log_at(&genesis, 0xEE)],
        "no certificate yet: {r}"
    );

    let _b2 = put(&storage, 0xB2, 2, a1, 9 * GWEI);
    assert!(pairs.record(2, a2), "late certificate recorded");
    let r = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x1", "toBlock": "finalized"}]),
    );
    assert_eq!(
        logs_of(&r),
        vec![log_at(&a1, 0xA1), log_at(&a2, 0xA2)],
        "after the certificate: {r}"
    );
    let fh = call(&io, "eth_feeHistory", json!(["0x2", "safe", []]));
    assert_eq!(
        fh["result"]["baseFeePerGas"],
        json!([fee(GWEI), fee(2 * GWEI), fee(2 * GWEI)]),
        "{fh}"
    );
}

/// Restart: the store is closed and reopened from disk and the verified pair is
/// published again (as the floor verifier does at boot from the persisted
/// certificate). The height index on disk still names the sibling; the ranges
/// still follow the certified chain.
#[test]
fn restart_reloads_and_ranges_still_follow_the_certified_chain() {
    let tmp = TempDir::new().expect("tempdir");
    let (a1, a2) = {
        let storage =
            Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
        let genesis = put(&storage, 0xEE, 0, Hash::default(), GWEI);
        let a1 = put(&storage, 0xA1, 1, genesis, GWEI);
        let a2 = put(&storage, 0xA2, 2, a1, GWEI);
        let _b2 = put(&storage, 0xB2, 2, a1, GWEI);
        (a1, a2)
    };
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("reopen"));
    let io = io(storage.clone(), verified(&[(2, a2)]));
    let r = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x1", "toBlock": "finalized"}]),
    );
    assert_eq!(
        logs_of(&r),
        vec![log_at(&a1, 0xA1), log_at(&a2, 0xA2)],
        "after reopen: {r}"
    );
}

/// `eth_newFilter` with a finality-tag bound, read back through
/// `eth_getFilterLogs`: the filter's range follows the certified chain.
#[test]
fn filter_logs_bounded_by_finalized_follow_the_certified_chain() {
    let (storage, _tmp) = new_storage();
    let genesis = put(&storage, 0xEE, 0, Hash::default(), GWEI);
    let a1 = put(&storage, 0xA1, 1, genesis, GWEI);
    let a2 = put(&storage, 0xA2, 2, a1, GWEI);
    let _b2 = put(&storage, 0xB2, 2, a1, GWEI);
    let io = io(storage.clone(), verified(&[(2, a2)]));
    for tag in ["finalized", "safe"] {
        let created = call(
            &io,
            "eth_newFilter",
            json!([{"fromBlock": "0x1", "toBlock": tag}]),
        );
        let id = created["result"]
            .as_str()
            .unwrap_or_else(|| panic!("filter id: {created}"))
            .to_string();
        let r = call(&io, "eth_getFilterLogs", json!([id]));
        assert_eq!(
            logs_of(&r),
            vec![log_at(&a1, 0xA1), log_at(&a2, 0xA2)],
            "filter 0x1..{tag}: {r}"
        );
    }
}

/// A finality-bounded range that starts too deep below the certified block is
/// refused as invalid params rather than walked or served from the index.
#[test]
fn finalized_range_starting_too_deep_is_refused() {
    let (storage, _tmp) = new_storage();
    let genesis = put(&storage, 0xEE, 0, Hash::default(), GWEI);
    let deep = put(&storage, 0xA9, 20_000, genesis, GWEI);
    let io = io(storage.clone(), verified(&[(20_000, deep)]));
    let r = call(
        &io,
        "eth_getLogs",
        json!([{"fromBlock": "0x0", "toBlock": "finalized"}]),
    );
    assert_eq!(error_code(&r), Some(-32602), "{r}");
}
