// Checkpoint finality Stage 1c (R1): in Enforced mode the `finalized` / `safe`
// RPC tags resolve to the CERTIFIED block by hash. The block store's height index
// keeps the LAST block written at a height, which can be an uncertified sibling
// of the certified block; it must never be what these tags return. Drives the
// real registered IoHandler over a real RocksDB-backed StorageManager.

use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::{FilterRegistry, FinalizedTagSource, VerifiedFinalized};
use citrate_consensus::types::{BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::{json, Value};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tempfile::TempDir;

fn tx(n: u64) -> Transaction {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = 0x77;
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

struct Fork {
    storage: Arc<StorageManager>,
    _tmp: TempDir,
    genesis: Hash,
    a1: Hash,
    /// Certified block at height 2 (1 tx, base fee 1 gwei).
    a2: Hash,
    /// Uncertified sibling at height 2, written AFTER a2 (3 txs, base fee 7 gwei).
    b2: Hash,
}

fn put(
    storage: &StorageManager,
    tag: u8,
    height: u64,
    parent: Hash,
    txs: Vec<Transaction>,
    base_fee: u64,
) -> Hash {
    let mut raw = [tag; 32];
    raw[..8].copy_from_slice(&height.to_be_bytes());
    let b = BlockBuilder::new()
        .hash(Hash::new(raw))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .gas_limit(30_000_000)
        .gas_used(21_000)
        .base_fee_per_gas(base_fee)
        .transactions(txs)
        .build_unhashed();
    storage.blocks.put_block(&b).expect("put block");
    b.hash()
}

fn fork() -> Fork {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let genesis = put(&storage, 0xEE, 0, Hash::default(), vec![], 1_000_000_000);
    let a1 = put(&storage, 0xA1, 1, genesis, vec![tx(1)], 1_000_000_000);
    let a2 = put(&storage, 0xA2, 2, a1, vec![tx(2)], 1_000_000_000);
    let b2 = put(
        &storage,
        0xB2,
        2,
        a1,
        vec![tx(20), tx(21), tx(22)],
        7_000_000_000,
    );
    Fork {
        storage,
        _tmp: tmp,
        genesis,
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

fn block_hash_of(io: &jsonrpc_core::IoHandler, tag: &str) -> Option<String> {
    let b = call(io, "eth_getBlockByNumber", json!([tag, false]));
    b.get("result")?.get("hash")?.as_str().map(str::to_string)
}

fn verified(pairs: &[(u64, Hash)]) -> FinalizedTagSource {
    let v = Arc::new(VerifiedFinalized::new());
    for (h, hash) in pairs {
        v.record(*h, *hash);
    }
    FinalizedTagSource::Verified(v)
}

/// Two sibling blocks at the certified height, the later-written one NOT
/// certified: every block-lookup endpoint returns the certified one.
#[test]
fn finalized_returns_the_certified_block_not_the_last_written_sibling() {
    let f = fork();
    assert_eq!(
        f.storage.blocks.get_block_by_height(2).expect("index"),
        Some(f.b2),
        "precondition: the height index names the later-written sibling"
    );
    let io = io(f.storage.clone(), verified(&[(2, f.a2)]));
    for tag in ["finalized", "safe"] {
        assert_eq!(block_hash_of(&io, tag), Some(hx(&f.a2)), "{tag}");
        let c = call(&io, "eth_getBlockTransactionCountByNumber", json!([tag]));
        assert_eq!(c["result"], "0x1", "{tag}: a2 has 1 tx, b2 has 3: {c}");
        let t = call(
            &io,
            "eth_getTransactionByBlockNumberAndIndex",
            json!([tag, "0x0"]),
        );
        assert_eq!(t["result"]["blockHash"], hx(&f.a2), "{tag}: {t}");
        assert_eq!(t["result"]["hash"], hx(&tx(2).hash), "{tag}: {t}");
        // Fee history anchored at finalized: the newest block is a2 (1 gwei),
        // not b2 (7 gwei).
        let fh = call(&io, "eth_feeHistory", json!(["0x1", tag, []]));
        assert_eq!(fh["result"]["oldestBlock"], "0x2", "{tag}: {fh}");
        assert_eq!(
            fh["result"]["baseFeePerGas"][0],
            format!("0x{:x}", 1_000_000_000u64),
            "{tag}: {fh}"
        );
        // Range reads use the verified height.
        let l = call(
            &io,
            "eth_getLogs",
            json!([{"fromBlock": tag, "toBlock": tag}]),
        );
        assert!(l.get("error").is_none(), "{tag}: {l}");
    }
    // `latest` and an explicit height still go through the height index
    // (unchanged behaviour).
    assert_eq!(block_hash_of(&io, "0x2"), Some(hx(&f.b2)));
}

/// The hazard this guards against: a height-only source at the same height
/// serves the sibling. (Legacy / Observed never raise the height above genesis,
/// so this source is only ever used at 0 in production.)
#[test]
fn a_height_only_source_would_serve_the_sibling() {
    let f = fork();
    let io = io(f.storage.clone(), Arc::new(AtomicU64::new(2)).into());
    assert_eq!(block_hash_of(&io, "finalized"), Some(hx(&f.b2)));
}

/// If the newest certified block is not stored here, the previous verified pair
/// is served; with none stored, genesis — never a block at the certified height
/// looked up by height.
#[test]
fn missing_certified_block_falls_back_to_previous_pair_then_genesis() {
    let f = fork();
    let absent = Hash::new([0xCD; 32]);
    let io1 = io(f.storage.clone(), verified(&[(1, f.a1), (2, absent)]));
    assert_eq!(block_hash_of(&io1, "finalized"), Some(hx(&f.a1)));
    let c = call(
        &io1,
        "eth_getBlockTransactionCountByNumber",
        json!(["safe"]),
    );
    assert_eq!(c["result"], "0x1");

    let io2 = io(f.storage.clone(), verified(&[(2, absent)]));
    assert_eq!(block_hash_of(&io2, "finalized"), Some(hx(&f.genesis)));

    let io3 = io(f.storage.clone(), verified(&[]));
    assert_eq!(block_hash_of(&io3, "safe"), Some(hx(&f.genesis)));
}

/// State reads under a finality tag stay consistent with the block the tag
/// names: with the finalized height equal to the latest height, latest state
/// is served only when it is the CERTIFIED block's state (applied tip == the
/// certified hash), never a sibling's.
#[test]
fn state_reads_require_the_applied_tip_to_be_the_certified_block() {
    let f = fork();
    let io = io(f.storage.clone(), verified(&[(2, f.a2)]));
    let addr = "0x0101010101010101010101010101010101010101";
    let balance = |tag: &str| call(&io, "eth_getBalance", json!([addr, tag]));

    // No applied tip recorded: refused.
    let r = balance("finalized");
    assert!(r.get("error").is_some(), "no applied tip: {r}");
    // Applied tip is the uncertified sibling: refused.
    f.storage
        .blocks
        .put_applied_tip(&f.b2, 2)
        .expect("applied tip");
    for (m, p) in [
        ("eth_getBalance", json!([addr, "finalized"])),
        ("eth_getTransactionCount", json!([addr, "safe"])),
        ("eth_getCode", json!([addr, "finalized"])),
        ("eth_getStorageAt", json!([addr, "0x0", "safe"])),
    ] {
        let r = call(&io, m, p);
        let msg = r["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            msg.contains("not the state of the finalized block"),
            "{m} on sibling state: {r}"
        );
    }
    // Applied tip is the certified block: served.
    f.storage
        .blocks
        .put_applied_tip(&f.a2, 2)
        .expect("applied tip");
    let r = balance("finalized");
    assert!(r.get("error").is_none(), "certified state: {r}");
    let r = balance("safe");
    assert!(r.get("error").is_none(), "certified state: {r}");
    // `latest` is unaffected either way.
    f.storage
        .blocks
        .put_applied_tip(&f.b2, 2)
        .expect("applied tip");
    let r = balance("latest");
    assert!(r.get("error").is_none(), "latest: {r}");
}

/// Finalized behind the tip: refused exactly as before (Stage 0 rule), for a
/// verified-pair source too.
#[test]
fn state_reads_behind_the_tip_are_refused_for_a_verified_pair() {
    let f = fork();
    let a3 = put(&f.storage, 0xA3, 3, f.a2, vec![], 1_000_000_000);
    f.storage
        .blocks
        .put_applied_tip(&a3, 3)
        .expect("applied tip");
    let io = io(f.storage.clone(), verified(&[(2, f.a2)]));
    let r = call(
        &io,
        "eth_getBalance",
        json!(["0x0101010101010101010101010101010101010101", "finalized"]),
    );
    let msg = r["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(msg.contains("is behind it"), "{r}");
    assert_eq!(block_hash_of(&io, "finalized"), Some(hx(&f.a2)));
}
