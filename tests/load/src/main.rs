//! Citrate high-throughput load test client
//! Compiled Rust client with connection pooling for 1000+ TPS testing.

use reqwest::Client;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const FROM: &str = "0x3333333333333333333333333333333333333333";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("http://127.0.0.1:8545");
    let target_tps: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let duration_secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);
    let concurrency: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(500);

    println!("============================================================");
    println!("  Citrate High-Throughput Load Test (Rust)");
    println!("============================================================");
    println!("  RPC URL      : {}", rpc_url);
    println!("  Target TPS   : {}", target_tps);
    println!("  Duration     : {}s", duration_secs);
    println!("  Concurrency  : {}", concurrency);
    println!();

    // Get starting block height
    let client = Client::builder()
        .pool_max_idle_per_host(concurrency)
        .tcp_keepalive(Duration::from_secs(30))
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let start_block = get_block_number(&client, rpc_url).await;
    let start_nonce = get_transaction_count(&client, rpc_url, FROM).await;
    println!("  Start block  : {}", start_block);
    println!("  Start nonce  : {}", start_nonce);
    println!("------------------------------------------------------------");

    let success = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let total_latency_us = Arc::new(AtomicU64::new(0));
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let start = Instant::now();
    let duration = Duration::from_secs(duration_secs);
    let _interval = Duration::from_micros(1_000_000 / target_tps);

    let mut handles = Vec::new();
    let mut sent: u64 = 0;

    while start.elapsed() < duration {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = rpc_url.to_string();
        let s = success.clone();
        let f = failed.clone();
        let tl = total_latency_us.clone();

        let addr = format!("0x{:040x}", rand::random::<u64>());
        let nonce_hex = format!("0x{:x}", start_nonce + sent);

        handles.push(tokio::spawn(async move {
            let success = s;
            let failed = f;
            let total_latency = tl;
            let req_start = Instant::now();
            let result = client
                .post(&url)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "method": "eth_sendTransaction",
                    "params": [{
                        "from": FROM,
                        "to": addr,
                        "value": "0x1",
                        "gas": "0x5208",
                        "gasPrice": "0x3b9aca00",
                        "nonce": nonce_hex
                    }],
                    "id": 1
                }))
                .send()
                .await;

            let latency = req_start.elapsed().as_micros() as u64;
            total_latency.fetch_add(latency, Ordering::Relaxed);

            match result {
                Ok(resp) => {
                    if rpc_response_has_result(resp).await {
                        success.fetch_add(1, Ordering::Relaxed);
                    } else {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                }
            }

            drop(permit);
        }));

        sent += 1;

        // Progress every 5 seconds
        if target_tps > 0 && sent % (target_tps * 5) == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let ok = success.load(Ordering::Relaxed);
            let fail = failed.load(Ordering::Relaxed);
            let actual_tps = if elapsed > 0.0 {
                ok as f64 / elapsed
            } else {
                0.0
            };
            println!(
                "  [{:.0}s] sent={} ok={} fail={} actual_tps={:.0}",
                elapsed, sent, ok, fail, actual_tps
            );
        }

        // Pace to target TPS
        let expected_elapsed = Duration::from_micros(sent * 1_000_000 / target_tps);
        if let Some(sleep_time) = expected_elapsed.checked_sub(start.elapsed()) {
            tokio::time::sleep(sleep_time).await;
        }
    }

    // Wait for in-flight requests
    println!("  Waiting for in-flight requests...");
    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let ok = success.load(Ordering::Relaxed);
    let fail = failed.load(Ordering::Relaxed);
    let total_lat = total_latency_us.load(Ordering::Relaxed);
    let avg_latency_ms = if ok + fail > 0 {
        total_lat / (ok + fail) / 1000
    } else {
        0
    };

    // Get ending block height
    tokio::time::sleep(Duration::from_secs(3)).await;
    let end_block = get_block_number(&client, rpc_url).await;
    let blocks = end_block - start_block;
    let avg_tx_per_block = if blocks > 0 { ok / blocks } else { 0 };

    println!();
    println!("============================================================");
    println!("  Load Test Results");
    println!("============================================================");
    println!("  Duration             : {:.1}s", elapsed.as_secs_f64());
    println!("  Transactions sent    : {}", sent);
    println!("  Successful           : {}", ok);
    println!("  Failed               : {}", fail);
    println!(
        "  Success rate         : {:.1}%",
        ok as f64 / sent as f64 * 100.0
    );
    println!();
    println!("  Target TPS           : {}", target_tps);
    println!(
        "  Actual TPS           : {:.0}",
        ok as f64 / elapsed.as_secs_f64()
    );
    println!("  Avg response time    : {}ms", avg_latency_ms);
    println!();
    println!("  Block height (start) : {}", start_block);
    println!("  Block height (end)   : {}", end_block);
    println!("  Blocks produced      : {}", blocks);
    println!("  Avg tx/block         : {}", avg_tx_per_block);
    println!("============================================================");
}

async fn get_block_number(client: &Client, rpc_url: &str) -> u64 {
    let resp = client
        .post(rpc_url)
        .json(&json!({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}))
        .send()
        .await
        .ok()
        .and_then(|r| futures::executor::block_on(r.json::<serde_json::Value>()).ok())
        .and_then(|j| j["result"].as_str().map(String::from));

    resp.map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0)
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
    let resp = client
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
        .and_then(|r| futures::executor::block_on(r.json::<Value>()).ok())
        .and_then(|j| j["result"].as_str().map(String::from));

    resp.map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0)
}
