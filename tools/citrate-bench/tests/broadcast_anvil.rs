//! Broadcast-mode integration test against a live anvil.
//!
//! This test is `#[ignore]` by default because it requires an
//! externally running anvil instance. To run it manually:
//!
//! ```bash
//! # start anvil in a separate terminal:
//! anvil --port 18546 --chain-id 31337 --config-out /tmp/bench-anvil.json
//!
//! # then:
//! CITRATE_BENCH_ANVIL_RPC=http://127.0.0.1:18546 \
//! CITRATE_BENCH_ANVIL_CHAIN_ID=31337 \
//! CITRATE_BENCH_ANVIL_FUNDER_PK="$(jq -r '.private_keys[0]' /tmp/bench-anvil.json)" \
//! cargo test --test broadcast_anvil -- --ignored --nocapture
//! ```
//!
//! The test:
//! 1. verifies the chain id matches
//! 2. creates three ephemeral keystores and funds each from the
//!    provided funder private key
//! 3. runs the broadcast loop for 5 seconds at 100 tps
//! 4. asserts ground_truth_match = true
//! 5. asserts included_total > 0 and mined_nonce_delta > 0

use std::sync::Arc;
use std::time::Duration;

use citrate_bench::rpc::RpcClient;
use citrate_bench::runner::{RunMode, RunOptions, Runner};
use citrate_bench::signers::{keystore, pool::SignerPool};
use citrate_bench::tracker::TrackerOptions;
use citrate_bench::tx::legacy::LegacyTx;
use citrate_bench::workload::transfer::SimpleTransfer;
use citrate_bench::workload::{WorkloadClass, WorkloadContext};

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn skip_if_missing() -> Option<(String, u64, String)> {
    let rpc = env("CITRATE_BENCH_ANVIL_RPC")?;
    let chain_id = env("CITRATE_BENCH_ANVIL_CHAIN_ID")?.parse::<u64>().ok()?;
    let funder = env("CITRATE_BENCH_ANVIL_FUNDER_PK")?;
    Some((rpc, chain_id, funder))
}

/// Send a simple ETH transfer from `funder_pk` to `to` for `value_wei`.
/// Returns the tx hash. Used only by this integration test to fund
/// the ephemeral bench signers.
async fn funder_transfer(
    client: &RpcClient,
    funder_pk_hex: &str,
    chain_id: u64,
    to: [u8; 20],
    value_wei: u128,
) -> citrate_bench::Result<String> {
    use citrate_bench::signers::Signer;
    let key_hex = funder_pk_hex
        .trim()
        .strip_prefix("0x")
        .unwrap_or(funder_pk_hex);
    let bytes = hex::decode(key_hex).expect("funder pk hex");
    let funder = Signer::from_key_bytes(&bytes).expect("funder signer");

    // Query the funder's current nonce so we don't collide with prior
    // activity on the chain.
    let nonce = client
        .get_transaction_count(&funder.address_hex(), "latest")
        .await?;

    let tx = LegacyTx {
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 21_000,
        to: Some(to),
        value: value_wei,
        data: Vec::new(),
        chain_id,
    };
    let signed = tx.sign(&funder)?;
    match client.send_raw_transaction(&signed.raw_hex()).await? {
        citrate_bench::rpc::SendRawOutcome::Accepted(h) => Ok(h),
        citrate_bench::rpc::SendRawOutcome::Rejected { code, message } => {
            Err(citrate_bench::Error::Rpc(format!(
                "funder transfer rejected ({code}): {message}"
            )))
        }
    }
}

async fn wait_for_receipt(client: &RpcClient, hash: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if std::time::Instant::now() > deadline {
            return false;
        }
        if let Ok(Some(_)) = client.get_transaction_receipt(hash).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn make_keystores(
    dir: &std::path::Path,
    count: usize,
    passphrase: &str,
) -> Vec<[u8; 20]> {
    use rand::rngs::OsRng;
    let mut addresses = Vec::with_capacity(count);
    for i in 1..=count {
        let name = format!("bench-{i:02}");
        let mut rng = OsRng;
        let (key_bytes, filename) = eth_keystore::new(dir, &mut rng, passphrase, Some(&name))
            .expect("new keystore");
        let target = dir.join(&name);
        if !target.exists() {
            std::fs::rename(dir.join(&filename), &target).expect("rename");
        }
        let signer = citrate_bench::signers::Signer::from_key_bytes(&key_bytes)
            .expect("signer from raw");
        addresses.push(signer.address);
    }
    addresses
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn broadcast_against_live_anvil() {
    let Some((rpc_url, expected_chain_id, funder_pk)) = skip_if_missing() else {
        eprintln!(
            "SKIP: set CITRATE_BENCH_ANVIL_RPC, CITRATE_BENCH_ANVIL_CHAIN_ID, \
             CITRATE_BENCH_ANVIL_FUNDER_PK to enable"
        );
        return;
    };

    let client = RpcClient::new(&rpc_url, Duration::from_secs(10)).expect("client");

    // 1. Verify chain id.
    let actual_chain_id = client.chain_id().await.expect("chain id");
    assert_eq!(
        actual_chain_id, expected_chain_id,
        "RPC chain id {actual_chain_id} does not match expected {expected_chain_id}"
    );

    // 2. Create + fund 3 ephemeral keystores.
    let dir = tempfile::tempdir().expect("tempdir");
    let passphrase = "anvil-integration-pw";
    let addresses = make_keystores(dir.path(), 3, passphrase);
    let funder_gas_price = 1_000_000_000u128;
    let fund_amount: u128 = 5_000_000_000_000_000_000; // 5 ETH per signer
    let mut last_hash = String::new();
    for addr in &addresses {
        last_hash = funder_transfer(&client, &funder_pk, expected_chain_id, *addr, fund_amount)
            .await
            .expect("fund signer");
    }
    // Wait for the last funding tx to land so balances are visible.
    assert!(
        wait_for_receipt(&client, &last_hash, 30).await,
        "funder tx did not mine"
    );

    // Sanity check every signer now has at least the fund amount.
    for addr in &addresses {
        let hex_addr = format!("0x{}", hex::encode(addr));
        let bal = client.get_balance(&hex_addr, "latest").await.expect("bal");
        assert!(bal >= fund_amount, "{hex_addr} bal {bal} < {fund_amount}");
    }

    // 3. Load signers via the keystore public API.
    let signers = keystore::load_many(
        dir.path(),
        &["bench-01".to_string(), "bench-02".to_string(), "bench-03".to_string()],
        &keystore::PassphraseSource::Literal(passphrase.to_string()),
    )
    .expect("load_many");
    assert_eq!(signers.len(), 3);

    // Verify keystore-derived addresses match what we funded.
    for (i, s) in signers.iter().enumerate() {
        assert_eq!(s.address, addresses[i]);
    }

    // 4. Build the pool with chain-queried starting nonces.
    let mut starting_nonces = Vec::with_capacity(signers.len());
    for s in &signers {
        let n = client
            .get_transaction_count(&s.address_hex(), "latest")
            .await
            .expect("nonce");
        starting_nonces.push(n);
    }
    let pool = Arc::new(
        SignerPool::new(signers, starting_nonces.clone(), 50)
            .expect("pool"),
    );

    // 5. Build + run the broadcast loop.
    let workload: Arc<dyn WorkloadClass> = Arc::new(SimpleTransfer::default_bench());
    let ctx = Arc::new(WorkloadContext::for_dry_run(
        expected_chain_id,
        funder_gas_price,
    ));
    let options = RunOptions {
        duration_secs: 3,
        target_tps: 100,
        sample_cap: 16,
    };
    let runner = Runner::new(pool, ctx, workload, options).expect("runner");

    let tracker_options = TrackerOptions {
        worker_count: 8,
        per_tx_timeout: Duration::from_secs(30),
        ..TrackerOptions::default()
    };
    let mode = RunMode::Broadcast {
        client: client.clone(),
        tracker_options,
        concurrency_cap: 100,
        cooldown_secs: 15,
    };

    let result = runner.run(mode).await.expect("run");
    result.print_summary();

    // 6. Assertions.
    assert!(result.signed_ok > 0);
    assert_eq!(result.signing_errors, 0);
    let b = result.broadcast.expect("broadcast result");
    assert_eq!(b.rpc_rejected, 0, "unexpected rejections: {:?}", b.rejected_reasons);
    assert!(
        b.tracker_stats.included > 0,
        "no txs were included: {:?}",
        b.tracker_stats
    );
    assert!(
        b.mined_nonce_delta_total > 0,
        "no mined nonce delta: {}",
        b.mined_nonce_delta_total
    );
    assert!(
        b.ground_truth_match,
        "ground truth mismatch: mined={} included={}",
        b.mined_nonce_delta_total, b.tracker_stats.included
    );
}
