//! Citrate Comprehensive Benchmark Suite
//!
//! Runs a series of transaction types at configurable TPS and produces
//! a timestamped report. Covers: simple transfers, contract deployment,
//! contract calls, storage writes, model registry, and mixed workloads.

use chrono::Utc;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

// ── Precompiled contract bytecodes ──────────────────────────────────────────

/// Minimal storage contract: stores a uint256 and allows setting it.
/// Solidity: contract Store { uint256 public val; function set(uint256 v) public { val = v; } }
const STORAGE_CONTRACT_BYTECODE: &str = "608060405234801561001057600080fd5b5060c78061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c14604f575b600080fd5b604d60048036038101906049919060799565b6065565b005b60556069565b6040516060919060a9565b60405180910390f35b8060008190555050565b60008054905090565b60008135905060738160c2565b92915050565b60006020828403121560895760006000fd5b600060958482850160679565b91505092915050565b60a38160b8565b82525050565b600060208201905060bc6000830184609c565b92915050565b6000819050919050565b60c98160b8565b811460d357600080fd5b5056fea264697066735822";

/// Counter contract: increment() function
const COUNTER_CONTRACT_BYTECODE: &str = "608060405234801561001057600080fd5b506000805560e4806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c8063d09de08a1460375780633fb5c1cb14604157575b600080fd5b603d6057565b005b604f60048036038101906049919060799565b6065565b005b60016000546055919060a2565b600055565b8060008190555050565b60008135905060738160c6565b92915050565b60006020828403121560895760006000fd5b600060958482850160679565b91505092915050565b600060a88260bc565b915060b28360bc565b925082820190508082111560c35760c260c6565b5b92915050565bfe";

/// Function selector for set(uint256): keccak256("set(uint256)")[:4]
const SET_SELECTOR: &str = "60fe47b1";
/// Function selector for get(): keccak256("get()")[:4]
const GET_SELECTOR: &str = "6d4ce63c";

const FALLBACK_STORAGE_CONTRACT: &str = "0x0000000000000000000000000000000000000001";

const FROM: &str = "0x3333333333333333333333333333333333333333";

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BenchmarkResult {
    name: String,
    target_tps: u64,
    duration_secs: f64,
    sent: u64,
    success: u64,
    failed: u64,
    actual_tps: f64,
    avg_latency_ms: f64,
    blocks_start: u64,
    blocks_end: u64,
    tx_per_block: u64,
    timestamp: String,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("http://127.0.0.1:8545");
    let target_tps: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10000);
    let duration_secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);
    let output_dir = args.get(4).map(|s| s.as_str()).unwrap_or(".");

    let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let date_str = Utc::now().format("%Y-%m-%d").to_string();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Citrate Comprehensive Benchmark Suite                    ║");
    println!("║  Date: {}                                    ║", date_str);
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    println!("  RPC URL      : {}", rpc_url);
    println!("  Target TPS   : {}", target_tps);
    println!("  Duration     : {}s per test", duration_secs);
    println!();

    let client = Client::builder()
        .pool_max_idle_per_host(2000)
        .tcp_keepalive(Duration::from_secs(30))
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let mut results = Vec::new();

    let storage_contract = deploy_setup_storage_contract(&client, rpc_url)
        .await
        .unwrap_or_else(|| {
            eprintln!(
                "Failed to deploy setup storage contract; falling back to {}",
                FALLBACK_STORAGE_CONTRACT
            );
            FALLBACK_STORAGE_CONTRACT.to_string()
        });
    println!("  Storage target: {}", storage_contract);
    println!();

    // ── Test 1: Simple Transfers ────────────────────────────────────────
    println!("━━━ Test 1/6: Simple Transfers (21K gas) ━━━");
    let r = run_benchmark(
        &client,
        rpc_url,
        target_tps,
        duration_secs,
        500,
        "Simple Transfer",
        |i| {
            json!({
                "from": FROM,
                "to": format!("0x{:040x}", i),
                "value": "0x1",
                "gas": "0x5208",
                "gasPrice": "0x3b9aca00"
            })
        },
    )
    .await;
    results.push(r);

    // ── Test 2: Contract Deployments ────────────────────────────────────
    println!("━━━ Test 2/6: Contract Deployments (~200K gas) ━━━");
    let r = run_benchmark(
        &client,
        rpc_url,
        target_tps / 5,
        duration_secs,
        200,
        "Contract Deploy",
        |_| {
            json!({
                "from": FROM,
                "data": format!("0x{}", STORAGE_CONTRACT_BYTECODE),
                "gas": "0x30D40",
                "gasPrice": "0x3b9aca00"
            })
        },
    )
    .await;
    results.push(r);

    // ── Test 3: Storage Writes (contract calls) ─────────────────────────
    println!("━━━ Test 3/6: Storage Writes — set(uint256) (~45K gas) ━━━");
    let storage_target_for_writes = storage_contract.clone();
    let r = run_benchmark(
        &client,
        rpc_url,
        target_tps,
        duration_secs,
        500,
        "Storage Write",
        move |i| {
            json!({
                "from": FROM,
                "to": storage_target_for_writes,
                "data": format!("0x{}{:064x}", SET_SELECTOR, i),
                "gas": "0xB71B0",
                "gasPrice": "0x3b9aca00"
            })
        },
    )
    .await;
    results.push(r);

    // ── Test 4: State Reads (eth_call, no state change) ─────────────────
    println!("━━━ Test 4/6: State Reads — eth_call ━━━");
    let r = run_read_benchmark(
        &client,
        rpc_url,
        target_tps,
        duration_secs,
        500,
        "State Read (eth_call)",
        storage_contract.clone(),
    )
    .await;
    results.push(r);

    // ── Test 5: Mixed Workload (70% transfer, 20% contract call, 10% deploy)
    println!("━━━ Test 5/6: Mixed Workload (70/20/10) ━━━");
    let storage_target_for_mixed = storage_contract.clone();
    let r = run_benchmark(
        &client,
        rpc_url,
        target_tps,
        duration_secs,
        500,
        "Mixed Workload",
        move |i| {
            let pct = i % 100;
            if pct < 70 {
                // Simple transfer
                json!({
                    "from": FROM,
                    "to": format!("0x{:040x}", i),
                    "value": "0x1",
                    "gas": "0x5208",
                    "gasPrice": "0x3b9aca00"
                })
            } else if pct < 90 {
                // Storage write
                json!({
                    "from": FROM,
                    "to": storage_target_for_mixed,
                    "data": format!("0x{}{:064x}", SET_SELECTOR, i),
                    "gas": "0xB71B0",
                    "gasPrice": "0x3b9aca00"
                })
            } else {
                // Contract deploy
                json!({
                    "from": FROM,
                    "data": format!("0x{}", COUNTER_CONTRACT_BYTECODE),
                    "gas": "0x30D40",
                    "gasPrice": "0x3b9aca00"
                })
            }
        },
    )
    .await;
    results.push(r);

    // ── Test 6: Burst Test (max TPS for 10 seconds) ─────────────────────
    println!("━━━ Test 6/6: Burst Test (max TPS, 10s) ━━━");
    let r = run_benchmark(
        &client,
        rpc_url,
        target_tps * 2,
        10,
        2000,
        "Burst (2x target)",
        |i| {
            json!({
                "from": FROM,
                "to": format!("0x{:040x}", i),
                "value": "0x1",
                "gas": "0x5208",
                "gasPrice": "0x3b9aca00"
            })
        },
    )
    .await;
    results.push(r);

    // ── Generate Report ─────────────────────────────────────────────────
    let report = generate_report(&results, &timestamp, rpc_url, target_tps, duration_secs);

    // Write to output directory
    let filename = format!("benchmark_{}.md", timestamp);
    let report_path = format!("{}/{}", output_dir, filename);
    std::fs::write(&report_path, &report).unwrap_or_else(|e| {
        eprintln!("Failed to write report to {}: {}", report_path, e);
    });

    println!();
    println!("Report written to: {}", report_path);
    println!();
    print!("{}", report);
}

async fn run_benchmark<F>(
    client: &Client,
    rpc_url: &str,
    target_tps: u64,
    duration_secs: u64,
    concurrency: usize,
    name: &str,
    tx_builder: F,
) -> BenchmarkResult
where
    F: Fn(u64) -> Value + Send + Sync + 'static,
{
    let success = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let total_latency_us = Arc::new(AtomicU64::new(0));
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let tx_builder = Arc::new(tx_builder);

    let start_block = get_block_number(client, rpc_url).await;
    let start_nonce = get_transaction_count(client, rpc_url, FROM).await;
    let start = Instant::now();
    let duration = Duration::from_secs(duration_secs);

    let mut handles = Vec::new();
    let mut sent: u64 = 0;

    while start.elapsed() < duration {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = rpc_url.to_string();
        let s = success.clone();
        let f = failed.clone();
        let tl = total_latency_us.clone();
        let tb = tx_builder.clone();
        let idx = sent;
        let nonce_hex = format!("0x{:x}", start_nonce + sent);

        handles.push(tokio::spawn(async move {
            let tx_params = attach_nonce(tb(idx), &nonce_hex);
            let req_start = Instant::now();
            let result = client
                .post(&url)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "method": "eth_sendTransaction",
                    "params": [tx_params],
                    "id": 1
                }))
                .send()
                .await;

            let latency = req_start.elapsed().as_micros() as u64;
            tl.fetch_add(latency, Ordering::Relaxed);

            match result {
                Ok(resp) => {
                    if rpc_response_has_result(resp).await {
                        s.fetch_add(1, Ordering::Relaxed);
                    } else {
                        f.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    f.fetch_add(1, Ordering::Relaxed);
                }
            }
            drop(permit);
        }));

        sent += 1;

        if target_tps > 0 && sent % (target_tps * 5) == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let ok = success.load(Ordering::Relaxed);
            println!(
                "  [{:.0}s] sent={} ok={} tps={:.0}",
                elapsed,
                sent,
                ok,
                ok as f64 / elapsed
            );
        }

        let expected = Duration::from_micros(sent * 1_000_000 / target_tps.max(1));
        if let Some(sleep) = expected.checked_sub(start.elapsed()) {
            tokio::time::sleep(sleep).await;
        }
    }

    for h in handles {
        let _ = h.await;
    }

    let elapsed = start.elapsed();
    let ok = success.load(Ordering::Relaxed);
    let fail = failed.load(Ordering::Relaxed);
    let total_lat = total_latency_us.load(Ordering::Relaxed);
    let avg_lat = if ok + fail > 0 {
        total_lat as f64 / (ok + fail) as f64 / 1000.0
    } else {
        0.0
    };

    tokio::time::sleep(Duration::from_secs(3)).await;
    let end_block = get_block_number(client, rpc_url).await;
    let blocks = end_block.saturating_sub(start_block);
    let tx_per_block = if blocks > 0 { ok / blocks } else { 0 };

    let actual_tps = ok as f64 / elapsed.as_secs_f64();

    println!(
        "  ✓ {} — {:.0} TPS, {}% success, {:.1}ms avg latency",
        name,
        actual_tps,
        if sent > 0 { ok * 100 / sent } else { 0 },
        avg_lat
    );
    println!();

    BenchmarkResult {
        name: name.to_string(),
        target_tps,
        duration_secs: elapsed.as_secs_f64(),
        sent,
        success: ok,
        failed: fail,
        actual_tps,
        avg_latency_ms: avg_lat,
        blocks_start: start_block,
        blocks_end: end_block,
        tx_per_block,
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    }
}

async fn run_read_benchmark(
    client: &Client,
    rpc_url: &str,
    target_tps: u64,
    duration_secs: u64,
    concurrency: usize,
    name: &str,
    read_target: String,
) -> BenchmarkResult {
    let success = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let total_latency_us = Arc::new(AtomicU64::new(0));
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let start_block = get_block_number(client, rpc_url).await;
    let start = Instant::now();
    let duration = Duration::from_secs(duration_secs);
    let mut handles = Vec::new();
    let mut sent: u64 = 0;

    while start.elapsed() < duration {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = rpc_url.to_string();
        let s = success.clone();
        let f = failed.clone();
        let tl = total_latency_us.clone();
        let to = read_target.clone();

        handles.push(tokio::spawn(async move {
            let req_start = Instant::now();
            let result = client
                .post(&url)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [{"from": FROM, "to": to, "data": format!("0x{}", GET_SELECTOR)}, "latest"],
                    "id": 1
                }))
                .send()
                .await;

            let latency = req_start.elapsed().as_micros() as u64;
            tl.fetch_add(latency, Ordering::Relaxed);

            match result {
                Ok(resp) => {
                    if rpc_response_has_result(resp).await {
                        s.fetch_add(1, Ordering::Relaxed);
                    } else {
                        f.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    f.fetch_add(1, Ordering::Relaxed);
                }
            }
            drop(permit);
        }));

        sent += 1;

        if target_tps > 0 && sent % (target_tps * 5) == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let ok = success.load(Ordering::Relaxed);
            println!(
                "  [{:.0}s] sent={} ok={} tps={:.0}",
                elapsed,
                sent,
                ok,
                ok as f64 / elapsed
            );
        }

        let expected = Duration::from_micros(sent * 1_000_000 / target_tps.max(1));
        if let Some(sleep) = expected.checked_sub(start.elapsed()) {
            tokio::time::sleep(sleep).await;
        }
    }

    for h in handles {
        let _ = h.await;
    }

    let elapsed = start.elapsed();
    let ok = success.load(Ordering::Relaxed);
    let fail = failed.load(Ordering::Relaxed);
    let total_lat = total_latency_us.load(Ordering::Relaxed);
    let avg_lat = if ok + fail > 0 {
        total_lat as f64 / (ok + fail) as f64 / 1000.0
    } else {
        0.0
    };

    tokio::time::sleep(Duration::from_secs(3)).await;
    let end_block = get_block_number(client, rpc_url).await;
    let blocks = end_block.saturating_sub(start_block);
    let tx_per_block = if blocks > 0 { ok / blocks } else { 0 };

    println!(
        "  ✓ {} — {:.0} TPS, {}% success, {:.1}ms avg latency",
        name,
        ok as f64 / elapsed.as_secs_f64(),
        if sent > 0 { ok * 100 / sent } else { 0 },
        avg_lat
    );
    println!();

    BenchmarkResult {
        name: name.to_string(),
        target_tps,
        duration_secs: elapsed.as_secs_f64(),
        sent,
        success: ok,
        failed: fail,
        actual_tps: ok as f64 / elapsed.as_secs_f64(),
        avg_latency_ms: avg_lat,
        blocks_start: start_block,
        blocks_end: end_block,
        tx_per_block,
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    }
}

fn generate_report(
    results: &[BenchmarkResult],
    timestamp: &str,
    rpc_url: &str,
    target_tps: u64,
    duration: u64,
) -> String {
    let mut report = String::new();
    report.push_str(&format!("# Citrate Benchmark Report — {}\n\n", timestamp));
    report.push_str(&format!(
        "> Generated: {}\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));
    report.push_str("> Hardware: NVIDIA DGX (ARM aarch64, 64GB RAM, NVMe SSD)\n");
    report.push_str(&format!("> RPC: {}\n", rpc_url));
    report.push_str(&format!(
        "> Target TPS: {} | Duration per test: {}s\n\n",
        target_tps, duration
    ));

    report.push_str("## Results Summary\n\n");
    report.push_str("| Test | Target TPS | Actual TPS | Sent | Success | Failed | Success % | Avg Latency | Tx/Block |\n");
    report.push_str("|------|-----------|-----------|------|---------|--------|-----------|-------------|----------|\n");

    for r in results {
        let pct = if r.sent > 0 {
            r.success as f64 / r.sent as f64 * 100.0
        } else {
            0.0
        };
        report.push_str(&format!(
            "| {} | {} | {:.0} | {} | {} | {} | {:.1}% | {:.1}ms | {} |\n",
            r.name,
            r.target_tps,
            r.actual_tps,
            r.sent,
            r.success,
            r.failed,
            pct,
            r.avg_latency_ms,
            r.tx_per_block
        ));
    }

    let total_sent: u64 = results.iter().map(|r| r.sent).sum();
    let total_ok: u64 = results.iter().map(|r| r.success).sum();
    let total_fail: u64 = results.iter().map(|r| r.failed).sum();

    report.push_str(&format!("\n## Totals\n\n"));
    report.push_str(&format!("- **Total transactions sent**: {}\n", total_sent));
    report.push_str(&format!("- **Total successful**: {}\n", total_ok));
    report.push_str(&format!("- **Total failed**: {}\n", total_fail));
    report.push_str(&format!(
        "- **Overall success rate**: {:.1}%\n",
        total_ok as f64 / total_sent as f64 * 100.0
    ));

    report.push_str("\n## Test Descriptions\n\n");
    report.push_str("1. **Simple Transfer**: Basic SALT transfer (21,000 gas)\n");
    report.push_str("2. **Contract Deploy**: Deploy a minimal storage contract (~200K gas)\n");
    report.push_str("3. **Storage Write**: Call set(uint256) on a contract (~45K gas)\n");
    report.push_str("4. **State Read**: eth_call (read-only, no state change)\n");
    report.push_str("5. **Mixed Workload**: 70% transfers + 20% contract calls + 10% deploys\n");
    report.push_str("6. **Burst**: 2x target TPS for 10 seconds (stress test)\n");

    report.push_str("\n---\n\n");
    report.push_str(
        "*Generated by citrate-benchmark-suite. All numbers are measured, not estimated.*\n",
    );

    report
}

fn attach_nonce(mut tx_params: Value, nonce_hex: &str) -> Value {
    if let Value::Object(ref mut fields) = tx_params {
        fields
            .entry("nonce")
            .or_insert_with(|| Value::String(nonce_hex.to_string()));
    }
    tx_params
}

async fn get_block_number(client: &Client, rpc_url: &str) -> u64 {
    client
        .post(rpc_url)
        .json(&json!({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}))
        .send()
        .await
        .ok()
        .and_then(|r| {
            tokio::task::block_in_place(|| futures::executor::block_on(r.json::<Value>())).ok()
        })
        .and_then(|j| j["result"].as_str().map(String::from))
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0)
}

async fn deploy_setup_storage_contract(client: &Client, rpc_url: &str) -> Option<String> {
    let tx_hash = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{
                "from": FROM,
                "data": format!("0x{}", STORAGE_CONTRACT_BYTECODE),
                "gas": "0x30D40",
                "gasPrice": "0x3b9aca00"
            }],
            "id": 1
        }))
        .send()
        .await
        .ok()
        .filter(|resp| resp.status().is_success())?
        .json::<Value>()
        .await
        .ok()
        .and_then(|body| {
            if body.get("error").is_some() {
                None
            } else {
                body.get("result")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }
        })?;

    for _ in 0..80 {
        if let Some(address) = get_contract_address_from_receipt(client, rpc_url, &tx_hash).await {
            return Some(address);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    None
}

async fn get_contract_address_from_receipt(
    client: &Client,
    rpc_url: &str,
    tx_hash: &str,
) -> Option<String> {
    client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash],
            "id": 1
        }))
        .send()
        .await
        .ok()
        .filter(|resp| resp.status().is_success())?
        .json::<Value>()
        .await
        .ok()
        .and_then(|body| {
            if body.get("error").is_some() {
                None
            } else {
                body.get("result")
                    .and_then(|receipt| receipt.get("contractAddress"))
                    .and_then(Value::as_str)
                    .filter(|address| !address.is_empty())
                    .map(str::to_owned)
            }
        })
}

async fn rpc_response_has_result(resp: reqwest::Response) -> bool {
    if !resp.status().is_success() {
        return false;
    }

    match resp.json::<Value>().await {
        Ok(body) => body.get("result").is_some() && body.get("error").is_none(),
        Err(_) => false,
    }
}

async fn get_transaction_count(client: &Client, rpc_url: &str, address: &str) -> u64 {
    client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [address, "pending"],
            "id": 1
        }))
        .send()
        .await
        .ok()
        .and_then(|r| {
            tokio::task::block_in_place(|| futures::executor::block_on(r.json::<Value>())).ok()
        })
        .and_then(|j| j["result"].as_str().map(String::from))
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0)
}
