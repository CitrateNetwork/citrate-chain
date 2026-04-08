//! # DEPRECATED FOR TESTNET OR RELEASE CLAIMS
//!
//! This binary is a **devnet rehearsal tool only**. Like its sibling
//! `benchmark-suite`, it uses `eth_sendTransaction` with a hardcoded
//! fake unlocked sender — it only works on permissive local devnet
//! nodes and does **not** exercise the real client signing flow. Its
//! output must **not** be used as evidence for auditors or release
//! claims.
//!
//! **Canonical harness**: `citrate_v0.01.1/tools/citrate-bench/`.
//!
//! See `citrate_v0.01.1/tests/load/README.md` for the full rationale.
//!
//! ---
//!
//! Citrate Live Benchmark — real-time streaming transaction viewer (historical)
//!
//! Watch thousands of transactions per second hit the chain in real time.
//! Designed for developers who want to SEE the throughput, not just read a number.
//!
//! Usage:
//!   live-bench [RPC_URL] [TARGET_TPS] [DURATION_SECS]
//!
//! Examples:
//!   live-bench                                    # 1,000 TPS for 30s against localhost
//!   live-bench http://localhost:8545 5000 60       # 5K TPS for 60s
//!   live-bench https://rpc.citrate.ai 2000 120     # 2K TPS against testnet for 2 min

use reqwest::Client;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const FROM: &str = "0x3333333333333333333333333333333333333333";

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";
const WHITE: &str = "\x1b[37m";
const BG_GREEN: &str = "\x1b[42m";
const BG_RED: &str = "\x1b[41m";

struct LiveStats {
    sent: AtomicU64,
    success: AtomicU64,
    failed: AtomicU64,
    total_latency_us: AtomicU64,
    /// Rolling window: success count at each second boundary
    second_buckets: Vec<AtomicU64>,
}

impl LiveStats {
    fn new(duration_secs: u64) -> Self {
        let mut buckets = Vec::with_capacity((duration_secs + 2) as usize);
        for _ in 0..(duration_secs + 2) {
            buckets.push(AtomicU64::new(0));
        }
        Self {
            sent: AtomicU64::new(0),
            success: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            total_latency_us: AtomicU64::new(0),
            second_buckets: buckets,
        }
    }

    fn record_success(&self, elapsed_secs: u64, latency_us: u64) {
        self.success.fetch_add(1, Ordering::Relaxed);
        self.total_latency_us
            .fetch_add(latency_us, Ordering::Relaxed);
        let idx = elapsed_secs as usize;
        if idx < self.second_buckets.len() {
            self.second_buckets[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_failure(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_sent(&self) {
        self.sent.fetch_add(1, Ordering::Relaxed);
    }

    fn instant_tps(&self, current_sec: u64) -> u64 {
        let idx = current_sec as usize;
        if idx < self.second_buckets.len() {
            self.second_buckets[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    fn avg_tps(&self, elapsed_secs: f64) -> f64 {
        if elapsed_secs > 0.0 {
            self.success.load(Ordering::Relaxed) as f64 / elapsed_secs
        } else {
            0.0
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("http://127.0.0.1:8545");
    let target_tps: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let duration_secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);
    let concurrency: usize = 500.min(target_tps as usize * 2);

    // Print banner
    println!();
    println!("  {BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗{RESET}");
    println!("  {BOLD}{CYAN}║{RESET}  {BOLD}{WHITE}⛏  CITRATE LIVE BENCHMARK{RESET}                               {BOLD}{CYAN}║{RESET}");
    println!("  {BOLD}{CYAN}║{RESET}  {DIM}Watch transactions hit the chain in real time{RESET}           {BOLD}{CYAN}║{RESET}");
    println!("  {BOLD}{CYAN}╚══════════════════════════════════════════════════════════╝{RESET}");
    println!();
    println!("  {DIM}RPC{RESET}        {WHITE}{rpc_url}{RESET}");
    println!("  {DIM}Target{RESET}     {BOLD}{YELLOW}{target_tps} TPS{RESET} for {BOLD}{duration_secs}s{RESET}");
    println!("  {DIM}Workers{RESET}    {concurrency} concurrent connections");
    println!();

    // Build HTTP client with connection pooling
    let client = Client::builder()
        .pool_max_idle_per_host(concurrency)
        .tcp_keepalive(Duration::from_secs(30))
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| Client::new());

    // Check node connectivity
    print!("  {DIM}Connecting to node...{RESET}");
    let chain_id = get_chain_id(&client, rpc_url).await;
    let start_block = get_block_number(&client, rpc_url).await;
    let start_nonce = get_transaction_count(&client, rpc_url, FROM).await;
    if start_block == 0 && chain_id == 0 {
        println!(" {RED}{BOLD}FAILED{RESET}");
        println!();
        println!("  {RED}Cannot connect to {rpc_url}{RESET}");
        println!("  {DIM}Make sure a Citrate node is running:{RESET}");
        println!("    cargo run --release -p citrate-node -- devnet");
        println!();
        std::process::exit(1);
    }
    println!(" {GREEN}{BOLD}OK{RESET} {DIM}(chain={chain_id}, block={start_block}, nonce={start_nonce}){RESET}");
    println!();

    // Check faucet balance
    let balance = get_balance(&client, rpc_url, FROM).await;
    if balance == 0 {
        println!("  {YELLOW}⚠  Faucet account {FROM} has zero balance{RESET}");
        println!("  {DIM}Transactions will fail — fund the account first{RESET}");
        println!();
    }

    // Launch!
    println!("  {BOLD}{GREEN}▶  STARTING{RESET} — press Ctrl+C to stop early");
    println!();
    println!("  {DIM}  Time │   Sent │   OK │ Fail │ TPS (now) │ TPS (avg) │ Latency{RESET}");
    println!("  {DIM}───────┼────────┼──────┼──────┼───────────┼───────────┼────────{RESET}");

    let stats = Arc::new(LiveStats::new(duration_secs));
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let start = Instant::now();
    let duration = Duration::from_secs(duration_secs);
    // Spawn the live reporter
    let reporter_stats = stats.clone();
    let reporter_start = start;
    let reporter_target = target_tps;
    let reporter_duration = duration_secs;
    let reporter = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let elapsed = reporter_start.elapsed();
            let secs = elapsed.as_secs();
            if secs > reporter_duration + 5 {
                break;
            }

            let sent = reporter_stats.sent.load(Ordering::Relaxed);
            let ok = reporter_stats.success.load(Ordering::Relaxed);
            let fail = reporter_stats.failed.load(Ordering::Relaxed);
            let total_lat = reporter_stats.total_latency_us.load(Ordering::Relaxed);
            let completed = ok + fail;
            let avg_lat_ms = if completed > 0 {
                total_lat / completed / 1000
            } else {
                0
            };

            // Get instant TPS (previous completed second)
            let instant = if secs > 0 {
                reporter_stats.instant_tps(secs - 1)
            } else {
                0
            };
            let avg = reporter_stats.avg_tps(elapsed.as_secs_f64());

            // Color the instant TPS based on target achievement
            let tps_color = if instant >= reporter_target {
                GREEN
            } else if instant >= reporter_target * 80 / 100 {
                YELLOW
            } else {
                RED
            };

            // Progress bar
            let pct = (secs as f64 / reporter_duration as f64 * 100.0).min(100.0);
            let bar_width = 20;
            let filled = (pct / 100.0 * bar_width as f64) as usize;
            let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);

            println!(
                "  {DIM}{:>5}s{RESET} │{:>7} │{GREEN}{:>5}{RESET} │{}{:>5}{RESET} │ {tps_color}{BOLD}{:>9}{RESET} │ {:>9.0} │ {:>5}ms  {DIM}{bar}{RESET}",
                secs, sent, ok,
                if fail > 0 { RED } else { DIM },
                fail,
                instant,
                avg,
                avg_lat_ms,
            );
        }
    });

    // Send transactions
    let mut handles = Vec::new();
    let mut nonce: u64 = start_nonce;

    while start.elapsed() < duration {
        let permit = semaphore.clone().acquire_owned().await;
        let permit = match permit {
            Ok(p) => p,
            Err(_) => break,
        };

        let client = client.clone();
        let url = rpc_url.to_string();
        let s = stats.clone();
        let bench_start = start;

        let to_addr = format!("0x{:040x}", rand::random::<u64>());
        let nonce_hex = format!("0x{:x}", nonce);
        nonce += 1;

        stats.record_sent();

        handles.push(tokio::spawn(async move {
            let req_start = Instant::now();
            let result = client
                .post(&url)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "method": "eth_sendTransaction",
                    "params": [{
                        "from": FROM,
                        "to": to_addr,
                        "value": "0x1",
                        "gas": "0x5208",
                        "gasPrice": "0x3b9aca00",
                        "nonce": nonce_hex
                    }],
                    "id": 1
                }))
                .send()
                .await;

            let latency_us = req_start.elapsed().as_micros() as u64;
            let elapsed_secs = bench_start.elapsed().as_secs();

            match result {
                Ok(resp) => {
                    if rpc_response_has_result(resp).await {
                        s.record_success(elapsed_secs, latency_us);
                    } else {
                        s.record_failure();
                    }
                }
                Err(_) => {
                    s.record_failure();
                }
            }

            drop(permit);
        }));

        // Pace to target TPS
        let sent = stats.sent.load(Ordering::Relaxed);
        if target_tps > 0 {
            let expected = Duration::from_micros(sent * 1_000_000 / target_tps);
            if let Some(sleep) = expected.checked_sub(start.elapsed()) {
                tokio::time::sleep(sleep).await;
            }
        }
    }

    // Wait for in-flight
    println!();
    println!("  {DIM}Draining in-flight requests...{RESET}");
    for h in handles {
        let _ = h.await;
    }
    reporter.abort();

    let elapsed = start.elapsed();
    let ok = stats.success.load(Ordering::Relaxed);
    let fail = stats.failed.load(Ordering::Relaxed);
    let sent = stats.sent.load(Ordering::Relaxed);
    let total_lat = stats.total_latency_us.load(Ordering::Relaxed);
    let completed = ok + fail;
    let avg_lat = if completed > 0 {
        total_lat / completed / 1000
    } else {
        0
    };
    let actual_tps = ok as f64 / elapsed.as_secs_f64();

    // End block
    tokio::time::sleep(Duration::from_secs(2)).await;
    let end_block = get_block_number(&client, rpc_url).await;
    let blocks = if end_block > start_block {
        end_block - start_block
    } else {
        0
    };
    let tx_per_block = if blocks > 0 { ok / blocks } else { 0 };

    // Peak TPS (best 1-second window)
    let peak_tps = (0..duration_secs)
        .map(|s| stats.instant_tps(s))
        .max()
        .unwrap_or(0);

    // Success rate
    let success_pct = if sent > 0 {
        ok as f64 / sent as f64 * 100.0
    } else {
        0.0
    };

    // Final report
    println!();
    println!("  {BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗{RESET}");
    println!("  {BOLD}{CYAN}║{RESET}  {BOLD}{WHITE}RESULTS{RESET}                                                {BOLD}{CYAN}║{RESET}");
    println!("  {BOLD}{CYAN}╚══════════════════════════════════════════════════════════╝{RESET}");
    println!();

    // TPS headline — big and bold
    let tps_color = if actual_tps >= target_tps as f64 {
        GREEN
    } else if actual_tps >= target_tps as f64 * 0.8 {
        YELLOW
    } else {
        RED
    };
    println!(
        "  {BOLD}{tps_color}  ▸ {:.0} TPS sustained ({:.1}s){RESET}",
        actual_tps,
        elapsed.as_secs_f64()
    );
    println!(
        "  {BOLD}{MAGENTA}  ▸ {} TPS peak (1s window){RESET}",
        peak_tps
    );
    println!();

    println!("  {DIM}Transactions{RESET}");
    println!("    Sent       {BOLD}{sent}{RESET}");
    println!("    Confirmed  {GREEN}{BOLD}{ok}{RESET}");
    if fail > 0 {
        println!("    Failed     {RED}{BOLD}{fail}{RESET}");
    }
    println!(
        "    Success    {}{BOLD}{:.1}%{RESET}",
        if success_pct >= 99.0 { GREEN } else { YELLOW },
        success_pct
    );
    println!();

    println!("  {DIM}Performance{RESET}");
    println!("    Avg latency   {BOLD}{avg_lat}ms{RESET}");
    println!("    Target TPS    {target_tps}");
    println!(
        "    Actual TPS    {tps_color}{BOLD}{:.0}{RESET}",
        actual_tps
    );
    println!("    Peak TPS      {MAGENTA}{BOLD}{peak_tps}{RESET}");
    println!();

    println!("  {DIM}Chain{RESET}");
    println!("    Blocks produced  {BOLD}{blocks}{RESET} ({start_block} → {end_block})");
    println!("    Avg tx/block     {BOLD}{tx_per_block}{RESET}");
    println!();

    // Grade
    let grade = if actual_tps >= target_tps as f64 && success_pct >= 99.0 {
        format!("{BG_GREEN}{BOLD}{WHITE} A+ {RESET}  Target exceeded with >99% success")
    } else if actual_tps >= target_tps as f64 * 0.9 && success_pct >= 95.0 {
        format!("{BG_GREEN}{BOLD}{WHITE} A  {RESET}  Target nearly met with >95% success")
    } else if actual_tps >= target_tps as f64 * 0.7 && success_pct >= 90.0 {
        format!("{GREEN}{BOLD} B  {RESET}  Solid performance — room to optimize")
    } else if actual_tps >= target_tps as f64 * 0.5 {
        format!("{YELLOW}{BOLD} C  {RESET}  Below target — check node configuration")
    } else {
        format!("{BG_RED}{BOLD}{WHITE} F  {RESET}  Significantly below target — investigate")
    };
    println!("  {BOLD}Grade:{RESET}  {grade}");
    println!();

    // Challenge
    println!("  {DIM}─────────────────────────────────────────────────{RESET}");
    println!(
        "  {BOLD}Think you can beat {tps_color}{:.0} TPS{RESET}{BOLD}?{RESET}",
        actual_tps
    );
    println!(
        "  {DIM}Try:{RESET}  live-bench {rpc_url} {} {duration_secs}",
        target_tps * 2
    );
    println!("  {DIM}─────────────────────────────────────────────────{RESET}");
    println!();
}

async fn get_block_number(client: &Client, url: &str) -> u64 {
    let resp = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}))
        .send()
        .await
        .ok()
        .and_then(|r| {
            let body = futures::executor::block_on(r.json::<Value>());
            body.ok()
        })
        .and_then(|j| j["result"].as_str().map(String::from));

    resp.map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0)
}

async fn get_chain_id(client: &Client, url: &str) -> u64 {
    let resp = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}))
        .send()
        .await
        .ok()
        .and_then(|r| {
            let body = futures::executor::block_on(r.json::<Value>());
            body.ok()
        })
        .and_then(|j| j["result"].as_str().map(String::from));

    resp.map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0)
}

async fn get_balance(client: &Client, url: &str, addr: &str) -> u64 {
    let resp = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","method":"eth_getBalance","params":[addr, "latest"],"id":1}))
        .send()
        .await
        .ok()
        .and_then(|r| {
            let body = futures::executor::block_on(r.json::<Value>());
            body.ok()
        })
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

async fn get_transaction_count(client: &Client, url: &str, addr: &str) -> u64 {
    let resp = client
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [addr, "pending"],
            "id": 1
        }))
        .send()
        .await
        .ok()
        .and_then(|r| {
            let body = futures::executor::block_on(r.json::<Value>());
            body.ok()
        })
        .and_then(|j| j["result"].as_str().map(String::from));

    resp.map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0)
}
