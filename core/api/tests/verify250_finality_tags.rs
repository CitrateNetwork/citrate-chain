// INDEPENDENT VERIFIER (2026-09-28, MAC Lane D): citrate-chain PR #250,
// finalized/safe block tags. Local-only integration test, drop into
// core/api/tests/. Drives the real registered IoHandler.

use citrate_api::eth_rpc::{register_eth_methods_with_finality, resolve_block_tag};
use citrate_api::FilterRegistry;
use citrate_consensus::types::{BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tempfile::TempDir;

fn tx(n: u64) -> Transaction {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
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

fn chain(n: u64) -> (Arc<StorageManager>, TempDir, Vec<Hash>) {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let genesis = BlockBuilder::new()
        .hash(Hash::new([0xEE; 32]))
        .parent(Hash::default())
        .height(0)
        .build_unhashed();
    storage.blocks.put_block(&genesis).expect("genesis");
    let mut hashes = vec![genesis.hash()];
    let mut parent = genesis.hash();
    for h in 1..=n {
        let mut hb = [0u8; 32];
        hb[..8].copy_from_slice(&h.to_be_bytes());
        hb[31] = 0xAA;
        let b = BlockBuilder::new()
            .hash(Hash::new(hb))
            .parent(parent)
            .height(h)
            .timestamp(1_000_000 + h)
            .gas_limit(30_000_000)
            .gas_used(21_000)
            .base_fee_per_gas(1_000_000_000)
            .transactions(vec![tx(h)])
            .build_unhashed();
        storage.blocks.put_block(&b).expect("block");
        parent = b.hash();
        hashes.push(b.hash());
    }
    (storage, tmp, hashes)
}

fn io(storage: Arc<StorageManager>, fin: Arc<AtomicU64>) -> jsonrpc_core::IoHandler {
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
        fin,
    );
    io
}

fn call(io: &jsonrpc_core::IoHandler, method: &str, params: Value) -> Value {
    let req =
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let resp = io.handle_request_sync(&req).expect("response");
    serde_json::from_str(&resp).expect("json")
}

fn block_number(v: &Value) -> Option<u64> {
    v.get("result")?
        .get("number")?
        .as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
}

#[test]
fn v250_resolver_truth_table() {
    for (cur, fin) in [(0u64, 0u64), (10, 0), (10, 7), (10, 10)] {
        assert_eq!(resolve_block_tag(Some("latest"), cur, fin), Some(cur));
        assert_eq!(resolve_block_tag(Some("pending"), cur, fin), Some(cur));
        assert_eq!(resolve_block_tag(Some("earliest"), cur, fin), Some(0));
        assert_eq!(resolve_block_tag(Some("finalized"), cur, fin), Some(fin));
        assert_eq!(resolve_block_tag(Some("safe"), cur, fin), Some(fin));
        assert_eq!(resolve_block_tag(Some("0x5"), cur, fin), Some(5));
        assert_eq!(resolve_block_tag(Some("0xzz"), cur, fin), None);
        assert_eq!(resolve_block_tag(Some("FINALIZED"), cur, fin), None);
        assert_eq!(resolve_block_tag(Some("final"), cur, fin), None);
        assert_eq!(resolve_block_tag(None, cur, fin), None);
        // un-prefixed decimal/hex must not be read as a height (kills the
        // `starts_with("0x") -> true` mutant, which would also slice short tags)
        assert_eq!(resolve_block_tag(Some("1234"), cur, fin), None);
        assert_eq!(resolve_block_tag(Some("xx5"), cur, fin), None);
    }
}

/// With nothing finalized (1-producer chain, no committee) finalized/safe
/// must name genesis at every tag-taking block endpoint, never the tip.
#[test]
fn v250_nothing_final_resolves_to_genesis_everywhere() {
    let (storage, _t, hashes) = chain(5);
    let io = io(storage, Arc::new(AtomicU64::new(0)));
    for tag in ["finalized", "safe"] {
        let b = call(&io, "eth_getBlockByNumber", serde_json::json!([tag, false]));
        assert_eq!(block_number(&b), Some(0), "{tag}: {b}");
        assert_eq!(
            b["result"]["hash"].as_str().unwrap(),
            format!("0x{}", hex::encode(hashes[0].as_bytes()))
        );
        let c = call(
            &io,
            "eth_getBlockTransactionCountByNumber",
            serde_json::json!([tag]),
        );
        assert_eq!(c["result"], "0x0", "{tag}: {c}");
        let t = call(
            &io,
            "eth_getTransactionByBlockNumberAndIndex",
            serde_json::json!([tag, "0x0"]),
        );
        assert!(
            t.get("error").is_none() && t["result"].is_null(),
            "{tag}: {t}"
        );
        let l = call(
            &io,
            "eth_getLogs",
            serde_json::json!([{"fromBlock": tag, "toBlock": tag}]),
        );
        assert!(l.get("error").is_none(), "{tag}: {l}");
        let f = call(
            &io,
            "eth_newFilter",
            serde_json::json!([{"fromBlock": tag, "toBlock": tag}]),
        );
        assert!(f.get("error").is_none(), "{tag}: {f}");
    }
}

/// finalized/safe follow the live handle (the applicator's finalized height)
/// and never exceed it.
#[test]
fn v250_tags_follow_the_finalized_handle() {
    let (storage, _t, hashes) = chain(5);
    let fin = Arc::new(AtomicU64::new(0));
    let io = io(storage, fin.clone());
    for h in [0u64, 1, 3, 5] {
        fin.store(h, Ordering::SeqCst);
        for tag in ["finalized", "safe"] {
            let b = call(&io, "eth_getBlockByNumber", serde_json::json!([tag, false]));
            assert_eq!(block_number(&b), Some(h), "{tag}@{h}: {b}");
            assert_eq!(
                b["result"]["hash"].as_str().unwrap(),
                format!("0x{}", hex::encode(hashes[h as usize].as_bytes()))
            );
            let c = call(
                &io,
                "eth_getBlockTransactionCountByNumber",
                serde_json::json!([tag]),
            );
            assert_eq!(c["result"], if h == 0 { "0x0" } else { "0x1" });
        }
        let latest = call(
            &io,
            "eth_getBlockByNumber",
            serde_json::json!(["latest", false]),
        );
        assert!(block_number(&latest).unwrap() >= h);
    }
}

/// Documents what state-reading methods do with a finalized/safe tag.
/// These methods have no state-at-height read, so they answer with the
/// LATEST state for any tag. Recorded as a gap, not asserted as a pass.
#[test]
fn v250_state_methods_with_finalized_tag_are_recorded() {
    let (storage, _t, _h) = chain(5);
    let io = io(storage, Arc::new(AtomicU64::new(0)));
    let addr = "0x0101010101010101010101010101010101010101";
    for (m, p) in [
        (
            "eth_getTransactionCount",
            serde_json::json!([addr, "finalized"]),
        ),
        ("eth_getBalance", serde_json::json!([addr, "finalized"])),
        ("eth_getCode", serde_json::json!([addr, "finalized"])),
        (
            "eth_getStorageAt",
            serde_json::json!([addr, "0x0", "finalized"]),
        ),
        ("eth_getBalance", serde_json::json!([addr, "0x0"])),
        ("eth_getBalance", serde_json::json!([addr, "bogus-tag"])),
    ] {
        let r = call(&io, m, p.clone());
        println!("V250 state-tag {m} {p} -> {r}");
    }
}

/// RED (gap): a state read at "finalized"/"safe" must not answer with
/// un-finalized (latest) state. Here nothing is final (finalized height 0,
/// the account does not exist at genesis) but the account holds 5 wei and
/// nonce 3 in LATEST state. A correct node either serves genesis-height
/// state (0 / 0x0) or refuses the tag; it must not return 5 / 3.
#[test]
fn v250_state_read_at_finalized_must_not_return_latest_state() {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let (storage, _t, _h) = chain(5);
    let sdb = Arc::new(citrate_execution::StateDB::new());
    let executor = Arc::new(Executor::new(sdb.clone()));
    let a = citrate_execution::types::Address([0x42; 20]);
    executor.set_balance(&a, primitive_types::U256::from(5u64));
    sdb.accounts.set_nonce(a, 3);
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
    let addr = "0x4242424242424242424242424242424242424242";
    let mut leaks = Vec::new();
    for tag in ["finalized", "safe"] {
        let b = call(&io, "eth_getBalance", serde_json::json!([addr, tag]));
        let n = call(
            &io,
            "eth_getTransactionCount",
            serde_json::json!([addr, tag]),
        );
        println!("V250 {tag}: balance={b} nonce={n}");
        if b.get("result") == Some(&Value::String("0x5".into())) {
            leaks.push(format!("eth_getBalance({tag}) = latest 0x5"));
        }
        if n.get("result") == Some(&Value::String("0x3".into())) {
            leaks.push(format!("eth_getTransactionCount({tag}) = latest 0x3"));
        }
    }
    assert!(
        leaks.is_empty(),
        "un-finalized state served under a finality tag: {leaks:?}"
    );
}
