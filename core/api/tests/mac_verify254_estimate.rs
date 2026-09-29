// INDEPENDENT VERIFIER (2026-09-28, MAC Lane D): PR #254 RPC side effect,
// adopted as a permanent regression test.
//
// PR #254 (R2-RES-04) makes a failed transaction's receipt report the full
// charged `gas_limit` instead of the gas actually consumed. That fix is correct
// for the receipt/header, but it leaked into `eth_estimateGas`: that method
// simulates with a 15M default limit and returned a buffer over
// `receipt.gas_used`. For a call that REVERTS, `receipt.gas_used` became the
// full simulated limit, so the estimate ballooned to 30,000,000 (2x the 15M
// sim) — a wallet trusting it would submit a max-gas tx and burn
// `gas_limit * gas_price` on the revert, and low-balance senders would be
// refused at admission.
//
// The fix: `eth_estimateGas` returns a JSON-RPC "execution reverted" error for
// a failed simulation (mirroring `eth_call`), and only a SUCCESSFUL simulation
// yields a gas number.
//
// - `v254_estimate_gas_for_reverting_call`  : the revert case (RED before fix).
// - `v254_estimate_gas_success_has_refund`  : the success case — the estimate
//   for a successful call must stay well below the simulation limit. This is
//   the assertion that kills an "always report gas_limit" mutant: a naive
//   implementation returning the full limit for every call would report ~30M
//   here too.
use citrate_api::eth_rpc::register_eth_methods;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{BlockBuilder, Hash};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::{json, Value};
use std::sync::Arc;

async fn estimate(code: Vec<u8>) -> Value {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
    let g = BlockBuilder::new()
        .hash(Hash::new([0xEE; 32]))
        .parent(Hash::default())
        .height(0)
        .build_unhashed();
    storage.blocks.put_block(&g).unwrap();
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let c = citrate_execution::types::Address([0x55; 20]);
    executor.set_code(&c, code);
    let from = citrate_execution::types::Address([0x66; 20]);
    executor.set_balance(
        &from,
        primitive_types::U256::from(10u64).pow(primitive_types::U256::from(24u64)),
    );
    let mut io = jsonrpc_core::IoHandler::new();
    register_eth_methods(
        &mut io,
        storage,
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
    );
    let io = Arc::new(io);
    let req = json!({"jsonrpc":"2.0","id":1,"method":"eth_estimateGas","params":[{"from":"0x6666666666666666666666666666666666666666","to":"0x5555555555555555555555555555555555555555","data":"0xdeadbeef"}]}).to_string();
    tokio::task::spawn_blocking(move || {
        serde_json::from_str::<Value>(&io.handle_request_sync(&req).unwrap()).unwrap()
    })
    .await
    .unwrap()
}

fn hexu(v: &Value) -> Option<u64> {
    v["result"]
        .as_str()
        .and_then(|s| u64::from_str_radix(&s[2..], 16).ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v254_estimate_gas_for_reverting_call() {
    let ok = estimate(vec![0x00]).await; // STOP: succeeds
    let rev = estimate(vec![0x60, 0x00, 0x60, 0x00, 0xfd]).await; // REVERT
    println!("V254 estimateGas success-call -> {ok}");
    println!("V254 estimateGas reverting-call -> {rev}");
    // Record: a reverting call's estimate must not be inflated to the simulation
    // limit (a wallet using it would pay up to that limit on the revert).
    let r = hexu(&rev);
    assert!(
        rev.get("error").is_some() || r.map(|g| g < 1_000_000).unwrap_or(true),
        "reverting call estimated at {r:?} gas (simulation-limit based)"
    );
}

/// Success-refund: the estimate for a SUCCESSFUL call must reflect the gas
/// actually used, not the simulation limit. A naive "always report gas_limit"
/// implementation would return ~30M (2x the 15M default sim) here and fail this
/// assertion, so this test alone kills that mutant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v254_estimate_gas_success_has_refund() {
    let ok = estimate(vec![0x00]).await; // STOP: succeeds
    println!("V254 estimateGas success-call -> {ok}");
    // A successful simulation must return a gas number (no error) ...
    assert!(
        ok.get("error").is_none(),
        "a successful call must not return an error: {ok}"
    );
    let g = hexu(&ok).expect("successful estimate must be a hex gas number");
    // ... and it must be well below the 15M simulation limit / 30M inflation:
    // an "always report gas_limit" implementation would land at ~30M here.
    assert!(
        g < 1_000_000,
        "successful call estimated at {g} gas (simulation-limit based, no refund)"
    );
}
