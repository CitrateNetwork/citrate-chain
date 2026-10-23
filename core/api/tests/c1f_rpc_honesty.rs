// UI truth contract §9 (C1-F, "RPC honesty"): regression tests for the
// read-only RPC fields that used to be hard-coded, estimated or defaulted.
// Each test drives the registered IoHandler against a real on-disk
// StorageManager (tempdir) and a real Mempool.

use citrate_api::node_rpc::{self, NodeIdentity, API_CRATE_VERSION};
use citrate_api::FilterRegistry;
use citrate_consensus::types::{
    BlockBuilder, GhostDagParams, Hash, PublicKey, Signature, Transaction,
};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig, TxClass};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::sync::Arc;
use tempfile::TempDir;

fn allow_anon_budget() {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
}

fn call(io: &jsonrpc_core::IoHandler, method: &str, params: &str) -> serde_json::Value {
    let req = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let resp = io.handle_request_sync(&req).expect("response");
    serde_json::from_str(&resp).expect("json response")
}

fn empty_storage() -> (Arc<StorageManager>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    (storage, tmp)
}

const GENESIS: [u8; 32] = [0xEE; 32];

fn put(
    storage: &StorageManager,
    hash: [u8; 32],
    parent: Hash,
    height: u64,
    blue_score: u64,
) -> Hash {
    let b = BlockBuilder::new()
        .hash(Hash::new(hash))
        .parent(parent)
        .height(height)
        .blue_score(blue_score)
        .timestamp(1_000_000u64.saturating_add(height))
        .gas_limit(30_000_000)
        .base_fee_per_gas(1_000_000_000)
        .build_unhashed();
    storage.blocks.put_block(&b).expect("put block");
    b.hash()
}

fn storage_with_genesis() -> (Arc<StorageManager>, TempDir, Hash) {
    let (storage, tmp) = empty_storage();
    let g = put(&storage, GENESIS, Hash::default(), 0, 0);
    (storage, tmp, g)
}

fn identity() -> NodeIdentity {
    NodeIdentity {
        version: "0.4.0".to_string(),
        git_sha: "c384fc98abcd".to_string(),
        git_dirty: false,
        consensus_fingerprint: "0x46a0f181000000000000000000000000".to_string(),
        activation_fingerprint: "0x0123456789abcdef0123456789abcdef".to_string(),
        ghostdag_params: Some(GhostDagParams::default()),
    }
}

fn node_io(storage: Arc<StorageManager>, id: Option<NodeIdentity>) -> jsonrpc_core::IoHandler {
    let mut io = jsonrpc_core::IoHandler::new();
    node_rpc::register_node_methods(&mut io, storage, 40204, id.map(Arc::new));
    io
}

// ---------------------------------------------------------------------------
// web3_clientVersion
// ---------------------------------------------------------------------------

#[test]
fn client_version_reports_node_version_and_git_sha() {
    let (storage, _tmp, _) = storage_with_genesis();
    let io = node_io(storage, Some(identity()));
    let v = call(&io, "web3_clientVersion", "[]");
    assert_eq!(v["result"], "citrate/v0.4.0-c384fc98abcd", "{v}");
}

#[test]
fn client_version_marks_a_dirty_build() {
    let (storage, _tmp, _) = storage_with_genesis();
    let mut id = identity();
    id.git_dirty = true;
    let io = node_io(storage, Some(id));
    let v = call(&io, "web3_clientVersion", "[]");
    assert_eq!(v["result"], "citrate/v0.4.0-c384fc98abcd-dirty", "{v}");
}

#[test]
fn client_version_without_identity_is_the_crate_version_not_the_old_literal() {
    let (storage, _tmp, _) = storage_with_genesis();
    let io = node_io(storage, None);
    let v = call(&io, "web3_clientVersion", "[]");
    assert_eq!(
        v["result"],
        serde_json::Value::String(format!("citrate/v{API_CRATE_VERSION}")),
        "{v}"
    );
    assert_ne!(
        v["result"], "citrate/v0.1.0",
        "the hard-coded literal is gone"
    );
}

// ---------------------------------------------------------------------------
// citrate_nodeIdentity
// ---------------------------------------------------------------------------

#[test]
fn node_identity_reports_genesis_chain_and_fingerprints() {
    let (storage, _tmp, g) = storage_with_genesis();
    let io = node_io(storage, Some(identity()));
    let v = call(&io, "citrate_nodeIdentity", "[]");
    let r = &v["result"];
    assert_eq!(r["chainId"], "0x9d0c", "{v}");
    assert_eq!(
        r["genesisHash"],
        serde_json::Value::String(format!("0x{}", hex::encode(g.as_bytes()))),
        "genesisHash is the stored block-0 hash: {v}"
    );
    assert_eq!(
        r["consensusFingerprint"],
        "0x46a0f181000000000000000000000000"
    );
    assert_eq!(
        r["activationFingerprint"],
        "0x0123456789abcdef0123456789abcdef"
    );
    assert_eq!(r["version"], "0.4.0");
    assert_eq!(r["gitSha"], "c384fc98abcd");
    assert_eq!(r["gitDirty"], false);
}

#[test]
fn node_identity_is_null_where_unknown() {
    // No genesis stored and no identity supplied: nothing is invented.
    let (storage, _tmp) = empty_storage();
    let io = node_io(storage, None);
    let v = call(&io, "citrate_nodeIdentity", "[]");
    let r = &v["result"];
    assert!(r["genesisHash"].is_null(), "{v}");
    assert!(r["consensusFingerprint"].is_null(), "{v}");
    assert!(r["activationFingerprint"].is_null(), "{v}");
    assert!(r["gitSha"].is_null(), "{v}");
    assert!(r["gitDirty"].is_null(), "{v}");
    assert_eq!(r["version"], API_CRATE_VERSION, "{v}");
    assert_eq!(r["chainId"], "0x9d0c", "{v}");
}

// ---------------------------------------------------------------------------
// citrate_getDagStats
// ---------------------------------------------------------------------------

#[test]
fn dag_stats_does_not_estimate_blue_red_or_total_counts() {
    let (storage, _tmp, g) = storage_with_genesis();
    let mut parent = g;
    for h in 1..=20u64 {
        let mut hb = [0u8; 32];
        hb[..8].copy_from_slice(&h.to_be_bytes());
        parent = put(&storage, hb, parent, h, h);
    }
    let io = node_io(storage, None);
    let v = call(&io, "citrate_getDagStats", "[]");
    let r = &v["result"];
    assert!(r["totalBlocks"].is_null(), "no block counter is kept: {v}");
    assert!(r["blueBlocks"].is_null(), "no blue tally is kept: {v}");
    assert!(r["redBlocks"].is_null(), "no red tally is kept: {v}");
    assert_eq!(r["height"], 20, "{v}");
    assert!(
        r["ghostdagParams"].is_null(),
        "params are null unless the node supplies its running ones: {v}"
    );
}

#[test]
fn dag_stats_max_blue_score_is_the_max_over_all_tips() {
    // G -> A(h1, bs1) -> C(h2, bs2)   and   G -> B(h1, bs9).
    // Tips sort by height descending, so C comes first; the old code reported
    // C's score (2). The maximum over the tips is B's 9.
    let (storage, _tmp, g) = storage_with_genesis();
    let a = put(&storage, [0xA1; 32], g, 1, 1);
    let _c = put(&storage, [0xC3; 32], a, 2, 2);
    let _b = put(&storage, [0xB2; 32], g, 1, 9);
    let io = node_io(storage, None);
    let v = call(&io, "citrate_getDagStats", "[]");
    let r = &v["result"];
    assert_eq!(r["tipsCount"], 2, "{v}");
    assert_eq!(r["maxBlueScore"], 9, "{v}");
}

#[test]
fn dag_stats_reports_the_running_ghostdag_params() {
    let (storage, _tmp, _) = storage_with_genesis();
    let mut id = identity();
    id.ghostdag_params = Some(GhostDagParams {
        k: 7,
        max_parents: 3,
        max_blue_score_diff: 11,
        pruning_window: 13,
        finality_depth: 17,
    });
    let io = node_io(storage, Some(id));
    let v = call(&io, "citrate_getDagStats", "[]");
    assert_eq!(
        v["result"]["ghostdagParams"],
        serde_json::json!({
            "k": 7, "maxParents": 3, "maxBlueScoreDiff": 11,
            "pruningWindow": 13, "finalityDepth": 17
        }),
        "{v}"
    );
}

// ---------------------------------------------------------------------------
// eth_feeHistory reward shape
// ---------------------------------------------------------------------------

fn eth_io(storage: Arc<StorageManager>) -> jsonrpc_core::IoHandler {
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage,
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
    );
    io
}

#[test]
fn fee_history_has_one_reward_per_percentile_for_empty_blocks() {
    allow_anon_budget();
    let (storage, _tmp, g) = storage_with_genesis();
    let mut parent = g;
    for h in 1..=4u64 {
        let mut hb = [0u8; 32];
        hb[..8].copy_from_slice(&h.to_be_bytes());
        parent = put(&storage, hb, parent, h, h);
    }
    let io = eth_io(storage);
    let v = call(&io, "eth_feeHistory", r#"["0x3","latest",[10,50,90]]"#);
    let reward = v["result"]["reward"].as_array().expect("reward array");
    assert_eq!(reward.len(), 3, "one row per block: {v}");
    for row in reward {
        assert_eq!(
            row,
            &serde_json::json!(["0x0", "0x0", "0x0"]),
            "an empty block has a zero per requested percentile: {v}"
        );
    }
}

#[test]
fn fee_history_mixed_blocks_rows_all_match_the_percentile_count() {
    allow_anon_budget();
    let (storage, _tmp, g) = storage_with_genesis();
    // Height 1: one transaction. Height 2: empty.
    let t = Transaction {
        hash: Hash::new([0x42; 32]),
        nonce: 0,
        from: PublicKey::new([1u8; 32]),
        to: Some(PublicKey::new([2u8; 32])),
        value: 0,
        gas_limit: 21_000,
        gas_price: 3_000_000_000,
        data: vec![],
        signature: Signature::new([7u8; 64]),
        chain_id: Some(40204),
        ..Default::default()
    };
    let b1 = BlockBuilder::new()
        .hash(Hash::new([0x01; 32]))
        .parent(g)
        .height(1)
        .timestamp(1_000_001)
        .gas_limit(30_000_000)
        .gas_used(21_000)
        .base_fee_per_gas(1_000_000_000)
        .transactions(vec![t])
        .build_unhashed();
    storage.blocks.put_block(&b1).expect("b1");
    put(&storage, [0x02; 32], b1.hash(), 2, 2);
    let io = eth_io(storage);
    let v = call(&io, "eth_feeHistory", r#"["0x2","latest",[25,75]]"#);
    let reward = v["result"]["reward"].as_array().expect("reward array");
    assert_eq!(reward.len(), 2, "{v}");
    for row in reward {
        assert_eq!(row.as_array().map(|r| r.len()), Some(2), "{v}");
    }
    // The tx-bearing block's tip is gas_price - base_fee = 2 gwei.
    assert_eq!(
        reward[0],
        serde_json::json!(["0x77359400", "0x77359400"]),
        "{v}"
    );
    assert_eq!(reward[1], serde_json::json!(["0x0", "0x0"]), "{v}");
}

// ---------------------------------------------------------------------------
// citrate_getMempoolStats / citrate_getToken
// ---------------------------------------------------------------------------

fn econ_io(
    economics: Option<Arc<citrate_economics::UnifiedEconomicsManager>>,
    mempool: Option<Arc<Mempool>>,
) -> jsonrpc_core::IoHandler {
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::economics_rpc::register_economics_methods(&mut io, economics, mempool);
    io
}

fn pending_tx(seed: u8, gas_price: u64, gas_limit: u64) -> Transaction {
    Transaction {
        hash: Hash::new([seed; 32]),
        nonce: 0,
        from: PublicKey::new([seed; 32]),
        to: Some(PublicKey::new([0x02; 32])),
        value: 0,
        gas_limit,
        gas_price,
        data: vec![],
        signature: Signature::new([7u8; 64]),
        chain_id: Some(40204),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_avg_gas_price_is_the_mean_gas_price() {
    let mempool = Arc::new(Mempool::new(MempoolConfig {
        require_valid_signature: false,
        ..Default::default()
    }));
    // Gas limits deliberately far from the prices: the old code averaged limits.
    mempool
        .add_transaction(pending_tx(0x51, 2_000_000_000, 21_000), TxClass::Standard)
        .await
        .expect("admit tx 1");
    mempool
        .add_transaction(pending_tx(0x52, 4_000_000_000, 90_000), TxClass::Standard)
        .await
        .expect("admit tx 2");
    let io = Arc::new(econ_io(None, Some(mempool)));
    let v = tokio::task::spawn_blocking(move || call(&io, "citrate_getMempoolStats", "[]"))
        .await
        .expect("join");
    assert_eq!(v["result"]["pendingTransactions"], 2, "{v}");
    // (2 gwei + 4 gwei) / 2 = 3 gwei = 0xb2d05e00.
    assert_eq!(v["result"]["avgGasPrice"], "0xb2d05e00", "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_avg_gas_price_is_null_for_an_empty_pool() {
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let io = Arc::new(econ_io(None, Some(mempool)));
    let v = tokio::task::spawn_blocking(move || call(&io, "citrate_getMempoolStats", "[]"))
        .await
        .expect("join");
    assert_eq!(v["result"]["pendingTransactions"], 0, "{v}");
    assert!(
        v["result"]["avgGasPrice"].is_null(),
        "no pending tx => no average (was a 1 gwei default): {v}"
    );
}

#[test]
fn mempool_stats_without_a_mempool_reports_nothing() {
    let io = econ_io(None, None);
    let v = call(&io, "citrate_getMempoolStats", "[]");
    for key in [
        "pendingTransactions",
        "totalGasFees",
        "avgGasPrice",
        "aiOperations",
    ] {
        assert!(v["result"][key].is_null(), "{key} must be null: {v}");
    }
}

#[test]
fn average_gas_price_is_floor_mean_or_none() {
    use citrate_api::economics_rpc::average_gas_price;
    use primitive_types::U256;
    assert_eq!(average_gas_price(Vec::<u64>::new()), None);
    assert_eq!(average_gas_price([3, 4]), Some(U256::from(3u64)));
    assert_eq!(
        average_gas_price([u64::MAX, u64::MAX]),
        Some(U256::from(u64::MAX)),
        "summed in U256, no overflow"
    );
}

#[test]
fn get_token_total_minted_is_null_and_supply_is_one_trillion() {
    let one_trillion_salt_wei = primitive_types::U256::from(1_000_000_000_000u128)
        .saturating_mul(primitive_types::U256::exp10(18));
    let expected_supply = format!("0x{:x}", one_trillion_salt_wei);

    let econ = Arc::new(citrate_economics::UnifiedEconomicsManager::new(
        citrate_economics::UnifiedEconomicsConfig::default(),
    ));
    for io in [econ_io(Some(econ), None), econ_io(None, None)] {
        let v = call(&io, "citrate_getToken", "[]");
        let r = &v["result"];
        assert!(
            r["totalMinted"].is_null(),
            "no node component tracks minting: {v}"
        );
        assert_eq!(r["symbol"], "SALT", "{v}");
        assert_eq!(r["decimals"], 18, "{v}");
        assert_eq!(
            r["totalSupply"],
            serde_json::Value::String(expected_supply.clone()),
            "{v}"
        );
    }
}
