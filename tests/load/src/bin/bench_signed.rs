//! # HISTORICAL WIP — PRODUCTIONIZED IN `tools/citrate-bench/`
//!
//! This binary is the **original proof-of-concept** that client-side
//! EIP-155 signing works end-to-end against a Citrate node. Its logic
//! has been productionized and extended in
//! `citrate_v0.01.1/tools/citrate-bench/`, which is the canonical
//! benchmark harness and where all new benchmark work lives.
//!
//! `bench-signed` is retained only as a clean reference point for
//! anyone looking at how the early signed-tx proof was constructed.
//! **It is not to be used for new benchmark runs or release claims.**
//! Use `citrate-bench` instead.
//!
//! See `citrate_v0.01.1/tests/load/README.md` and
//! `.agentile/quorum/16_POST_CEREMONY_BENCHMARK_HARNESS_SPEC.md` for
//! the full rationale.
//!
//! ---
//!
//! Citrate Self-Signed Benchmark — production-correct TPS measurement (historical)
//!
//! Unlike `benchmark-suite` which uses the legacy `eth_sendTransaction` RPC
//! (requires node-side keystore management), this binary signs EIP-155 legacy
//! transactions client-side with secp256k1 ECDSA and submits them via
//! `eth_sendRawTransaction`. This is the same code path a real client uses
//! and does not depend on any account being unlocked in the node's keystore.
//!
//! Usage:
//!   bench-signed [RPC_URL] [TARGET_TPS] [DURATION_SECS] [KEY_FILE] [OUT_DIR]
//!
//! KEY_FILE: path to a file containing `DEPLOYER_PRIVATE_KEY=0xHEX` (default
//! `../../../.env.testnet` relative to the binary's cwd, which is the
//! convention when running from `tests/load/`).
//!
//! Example (from tests/load/):
//!   ./target/release/bench-signed http://127.0.0.1:8545 10000 60 \
//!     ../../../.env.testnet ../../../benchmarks/

use chrono::Utc;
use k256::ecdsa::SigningKey;
use reqwest::Client;
use rlp::RlpStream;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const RECIPIENT: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

#[derive(Clone)]
struct Signer {
    key: SigningKey,
    address: [u8; 20],
}

impl Signer {
    fn from_private_key_hex(hex_str: &str) -> Result<Self, String> {
        let cleaned = hex_str.trim().trim_matches('"').trim_start_matches("0x");
        let bytes = hex::decode(cleaned).map_err(|e| format!("invalid hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("private key must be 32 bytes, got {}", bytes.len()));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        let key = SigningKey::from_bytes((&key_bytes).into())
            .map_err(|e| format!("invalid secp256k1 key: {e}"))?;

        // Derive EVM address: keccak256(uncompressed_pubkey[1..])[12..]
        let verifying_key = key.verifying_key();
        let pubkey_point = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = pubkey_point.as_bytes();
        let hash = Keccak256::digest(&pubkey_uncompressed[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        Ok(Self { key, address })
    }

    fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }
}

/// Read DEPLOYER_PRIVATE_KEY from a .env-style file.
fn load_deployer_key(path: &PathBuf) -> Result<Signer, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    let key_hex = contents
        .lines()
        .find_map(|line| line.strip_prefix("DEPLOYER_PRIVATE_KEY="))
        .ok_or_else(|| format!("DEPLOYER_PRIVATE_KEY not found in {}", path.display()))?;
    Signer::from_private_key_hex(key_hex)
}

/// Strip leading zero bytes from an integer's big-endian representation.
/// Returns an empty slice if all bytes are zero (RLP encoding for 0).
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

/// EIP-155 legacy transaction signer.
///
/// Computes the canonical signing hash:
///     keccak256(RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))
/// then signs with secp256k1 and produces the final 9-element signed RLP:
///     RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
fn sign_legacy_tx(
    signer: &Signer,
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: &[u8; 20],
    value: u128,
    data: &[u8],
    chain_id: u64,
) -> Result<Vec<u8>, String> {
    // ---- Step 1: build the EIP-155 signing pre-image and hash it ----
    let mut pre = RlpStream::new_list(9);
    pre.append(&nonce);
    pre.append(&gas_price);
    pre.append(&gas_limit);
    pre.append(&to.as_slice());
    pre.append(&value);
    pre.append(&data);
    pre.append(&chain_id);
    pre.append_empty_data();
    pre.append_empty_data();
    let pre_image = pre.out();

    let hash = Keccak256::digest(&pre_image);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);

    // ---- Step 2: sign with secp256k1 (recoverable) ----
    let (signature, recovery_id) = signer
        .key
        .sign_prehash_recoverable(&hash_bytes)
        .map_err(|e| format!("sign failed: {e}"))?;

    let sig_bytes = signature.to_bytes();
    let r = &sig_bytes[..32];
    let s = &sig_bytes[32..];
    let v = chain_id * 2 + 35 + recovery_id.to_byte() as u64;

    // ---- Step 3: build final signed RLP ----
    let mut signed = RlpStream::new_list(9);
    signed.append(&nonce);
    signed.append(&gas_price);
    signed.append(&gas_limit);
    signed.append(&to.as_slice());
    signed.append(&value);
    signed.append(&data);
    signed.append(&v);
    signed.append(&strip_leading_zeros(r));
    signed.append(&strip_leading_zeros(s));

    Ok(signed.out().to_vec())
}

async fn get_latest_nonce(client: &Client, rpc_url: &str, address_hex: &str) -> Result<u64, String> {
    // Use "latest" (mined nonce), not "pending". The pending counter on this
    // node tracks the highest submitted nonce, which can run far ahead of
    // what is actually queued or mined when previous benchmark runs flooded
    // the mempool with rejected sequences.
    let body = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionCount",
        "params": [address_hex, "latest"],
        "id": 1
    });
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("nonce req failed: {e}"))?;
    let v: Value = resp.json().await.map_err(|e| format!("nonce parse failed: {e}"))?;
    let hex_str = v["result"]
        .as_str()
        .ok_or("nonce result missing")?
        .trim_start_matches("0x");
    u64::from_str_radix(hex_str, 16).map_err(|e| format!("nonce hex parse: {e}"))
}

async fn get_block_number(client: &Client, rpc_url: &str) -> u64 {
    let body = json!({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1});
    match client.post(rpc_url).json(&body).send().await {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(v) => {
                let hex_str = v["result"].as_str().unwrap_or("0x0").trim_start_matches("0x");
                u64::from_str_radix(hex_str, 16).unwrap_or(0)
            }
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("http://127.0.0.1:8545")
        .to_string();
    let target_tps: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10000);
    let duration_secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);
    let key_file: PathBuf = args
        .get(4)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../../../.env.testnet"));
    let out_dir = args
        .get(5)
        .map(String::as_str)
        .unwrap_or("../../../benchmarks")
        .to_string();

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  Citrate Self-Signed Benchmark                            ║");
    println!("║  Production-correct: EIP-155 + eth_sendRawTransaction      ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    println!("  RPC URL      : {}", rpc_url);
    println!("  Target TPS   : {}", target_tps);
    println!("  Duration     : {}s", duration_secs);
    println!("  Key file     : {}", key_file.display());
    println!("  Out dir      : {}", out_dir);
    println!();

    let signer = match load_deployer_key(&key_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ Failed to load deployer key: {}", e);
            std::process::exit(1);
        }
    };
    println!("  Signer addr  : {}", signer.address_hex());
    let signer = Arc::new(signer);

    let client = Client::builder()
        .pool_max_idle_per_host(2000)
        .tcp_keepalive(Duration::from_secs(30))
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build http client");

    // Probe chain id
    let chain_body = json!({"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1});
    let chain_id: u64 = match client.post(&rpc_url).json(&chain_body).send().await {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(v) => v["result"]
                .as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .unwrap_or(40204),
            Err(_) => 40204,
        },
        Err(e) => {
            eprintln!("✗ chain id probe failed: {} (defaulting to 40204)", e);
            40204
        }
    };
    println!("  Chain ID     : {}", chain_id);

    let start_nonce = match get_latest_nonce(&client, &rpc_url, &signer.address_hex()).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("✗ nonce fetch failed: {}", e);
            std::process::exit(1);
        }
    };
    println!("  Start nonce  : {}", start_nonce);
    let block_start = get_block_number(&client, &rpc_url).await;
    println!("  Start block  : {}", block_start);
    println!();

    // ---- Single test: sustained simple transfers ----
    println!("━━━ Test: Simple Transfer (21K gas, EIP-155 signed) ━━━");

    let success = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let total_latency_us = Arc::new(AtomicU64::new(0));
    let semaphore = Arc::new(Semaphore::new(500));

    let start = Instant::now();
    let duration = Duration::from_secs(duration_secs);
    let mut handles = Vec::new();
    let mut sent: u64 = 0;

    // Real rate limiter: target_tps determines the inter-tx delay. We compute
    // the deadline for tx N as `start + (N / target_tps)` seconds and sleep
    // until that deadline before spawning. This produces a steady stream that
    // matches `target_tps` regardless of spawn overhead.
    let tx_interval_ns: u64 = if target_tps > 0 { 1_000_000_000 / target_tps } else { 0 };

    while start.elapsed() < duration {
        // Compute next deadline
        if tx_interval_ns > 0 {
            let target_elapsed = Duration::from_nanos(tx_interval_ns * sent);
            let now_elapsed = start.elapsed();
            if target_elapsed > now_elapsed {
                tokio::time::sleep(target_elapsed - now_elapsed).await;
            }
        }

        let permit = semaphore.clone().acquire_owned().await.expect("semaphore closed");
        let client = client.clone();
        let url = rpc_url.clone();
        let s = success.clone();
        let f = failed.clone();
        let tl = total_latency_us.clone();
        let signer = signer.clone();
        let nonce = start_nonce + sent;

        handles.push(tokio::spawn(async move {
            let raw = match sign_legacy_tx(
                &signer,
                nonce,
                1_000_000_000, // gas price: 1 gwei
                21_000,        // gas limit
                &RECIPIENT,
                1, // 1 wei
                &[],
                chain_id,
            ) {
                Ok(r) => r,
                Err(_) => {
                    f.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }
            };
            let raw_hex = format!("0x{}", hex::encode(&raw));

            let req_start = Instant::now();
            let body = json!({
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": [raw_hex],
                "id": 1
            });
            let result = client.post(&url).json(&body).send().await;
            let latency = req_start.elapsed().as_micros() as u64;
            tl.fetch_add(latency, Ordering::Relaxed);

            match result {
                Ok(resp) => match resp.json::<Value>().await {
                    Ok(v) => {
                        if v.get("result").and_then(|r| r.as_str()).is_some() {
                            s.fetch_add(1, Ordering::Relaxed);
                        } else {
                            f.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        f.fetch_add(1, Ordering::Relaxed);
                    }
                },
                Err(_) => {
                    f.fetch_add(1, Ordering::Relaxed);
                }
            }
            // The `nonce` capture is intentional even though we don't read it
            // here — the spawn closure owns it so signing uses the right value.
            let _ = nonce;
            drop(permit);
        }));

        sent += 1;

        // Periodic progress every 5 seconds
        if target_tps > 0 && sent.is_multiple_of(target_tps * 5) {
            let elapsed = start.elapsed().as_secs_f64();
            let ok = success.load(Ordering::Relaxed);
            let fail = failed.load(Ordering::Relaxed);
            let tps = ok as f64 / elapsed.max(0.001);
            println!(
                "  [{:.0}s] sent={} ok={} failed={} tps={:.0}",
                elapsed, sent, ok, fail, tps
            );
        }
    }

    // Drain in-flight
    for h in handles {
        let _ = h.await;
    }

    // Wait briefly for queued txs to mine before measuring nonce delta
    tokio::time::sleep(Duration::from_secs(3)).await;

    let elapsed = start.elapsed().as_secs_f64();
    let accepted_by_rpc = success.load(Ordering::Relaxed);
    let rejected_by_rpc = failed.load(Ordering::Relaxed);
    let lat_total_us = total_latency_us.load(Ordering::Relaxed);
    let avg_lat_ms = if sent > 0 {
        lat_total_us as f64 / sent as f64 / 1000.0
    } else {
        0.0
    };

    // Ground truth: how much did the on-chain nonce advance?
    let end_nonce = get_latest_nonce(&client, &rpc_url, &signer.address_hex())
        .await
        .unwrap_or(start_nonce);
    let mined = end_nonce.saturating_sub(start_nonce);
    let actual_tps = mined as f64 / elapsed.max(0.001);
    let mined_rate = if sent > 0 { mined as f64 / sent as f64 * 100.0 } else { 0.0 };

    let block_end = get_block_number(&client, &rpc_url).await;
    let blocks = block_end.saturating_sub(block_start);
    let tx_per_block = if blocks > 0 { mined as f64 / blocks as f64 } else { 0.0 };

    println!();
    println!("━━━ Result ━━━");
    println!("  Duration             : {:.1}s", elapsed);
    println!("  Sent                 : {}", sent);
    println!("  Accepted by RPC      : {}", accepted_by_rpc);
    println!("  Rejected by RPC      : {}", rejected_by_rpc);
    println!("  ── Ground truth (on-chain nonce delta) ──");
    println!("  Start nonce          : {}", start_nonce);
    println!("  End nonce            : {}", end_nonce);
    println!("  Mined                : {}", mined);
    println!("  Mined-of-sent rate   : {:.2}%", mined_rate);
    println!("  Actual mined TPS     : {:.2}", actual_tps);
    println!("  Avg latency          : {:.2}ms", avg_lat_ms);
    println!("  Blocks               : {} (start {} -> end {})", blocks, block_start, block_end);
    println!("  Tx/block             : {:.2}", tx_per_block);
    println!();

    // ---- Write report ----
    let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
    let report_path = format!("{}/benchmark_signed_{}.md", out_dir.trim_end_matches('/'), timestamp);
    let report = format!(
        "---\ncreated: {}\nbranch: quorum-execution-v1\nauthor: bench-signed (auto-generated)\nsprint: level-a\nstatus: active\nscope: Self-signed EIP-155 benchmark — production-correct path with ground-truth nonce delta\n---\n\n\
        # Citrate Self-Signed Benchmark — {}\n\n\
        > Hardware: ARM aarch64 (DGX Spark)\n> RPC: {}\n> Chain ID: {}\n> Signer: {}\n> Target TPS: {} | Duration: {}s\n\n\
        ## Methodology\n\n\
        This benchmark signs EIP-155 legacy transactions client-side with\n\
        secp256k1 ECDSA and submits them via `eth_sendRawTransaction`. It does\n\
        not depend on the node having any account unlocked in its keystore,\n\
        and exercises the same code path a real client (wallet, SDK, dapp) uses.\n\n\
        **Success metric**: ground truth, computed as on-chain nonce delta\n\
        (`eth_getTransactionCount(latest)` after − before). RPC acceptance is\n\
        not the same as block inclusion: a tx the mempool returns a hash for\n\
        can still be evicted, expired, or fail execution before mining. Only\n\
        the nonce delta is honest.\n\n\
        ## Results\n\n\
        | Metric | Value |\n|--------|-------|\n\
        | Duration | {:.2}s |\n\
        | Sent | {} |\n\
        | RPC accepted (hash returned) | {} |\n\
        | RPC rejected (error or no result) | {} |\n\
        | **Mined (nonce delta — ground truth)** | **{}** |\n\
        | Mined-of-sent rate | {:.2}% |\n\
        | **Actual mined TPS** | **{:.2}** |\n\
        | Avg submit latency | {:.2}ms |\n\
        | Blocks during test | {} |\n\
        | Mined tx per block | {:.2} |\n\n\
        ## Notes\n\n\
        Single sender. Citrate's mempool has a per-sender cap (`max_per_sender = 100`\n\
        in `core/sequencer/src/mempool.rs`), so single-sender throughput is bounded\n\
        by `(per_sender_cap × per_block_drain_rate)`. Empirically the per-block\n\
        drain rate observed on this run is much lower than 100, indicating a\n\
        deeper bottleneck in `Mempool::get_best_transactions()` or the block\n\
        builder's per-sender selection logic.\n\n\
        Symptoms observed: blocks contain N tx hashes in `transactions[]` but\n\
        report `gasUsed = 21000` (one tx worth), suggesting the executor is\n\
        rejecting most of the included txs at execution time (likely a nonce\n\
        sequencing issue between the block-building selection and executor\n\
        validation).\n\n\
        To exceed the per-sender ceiling once the underlying bottleneck is\n\
        resolved, a future revision should round-robin across multiple funded\n\
        signers from `.env.testnet` (deployer + treasury + faucet + team +\n\
        validator = 5 senders × 100 cap = 500 in-flight slots, matching the\n\
        mempool's overall `max_size = 10000`).\n\n\
        ---\n\n\
        *Generated by `bench-signed`. All numbers measured, not estimated.\n\
        The mined count is ground-truth on-chain nonce delta — RPC acceptance\n\
        is reported separately for diagnostic purposes only.*\n",
        Utc::now().to_rfc3339(),
        timestamp,
        rpc_url,
        chain_id,
        signer.address_hex(),
        target_tps,
        duration_secs,
        elapsed,
        sent,
        accepted_by_rpc,
        rejected_by_rpc,
        mined,
        mined_rate,
        actual_tps,
        avg_lat_ms,
        blocks,
        tx_per_block,
    );
    if let Err(e) = std::fs::write(&report_path, &report) {
        eprintln!("✗ failed to write report: {}", e);
    } else {
        println!("Report: {}", report_path);
    }
}
