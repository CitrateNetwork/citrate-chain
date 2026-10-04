//! HUP-S6.10: forked state is read from a JSON-RPC endpoint at one pinned block, with read
//! methods only. A loopback JSON-RPC server in this test plays the endpoint; the anvil test
//! runs the same path against a real anvil when one is installed.
mod common;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use citrate_fork::run::{pinned_hardening, ForkConfig, StateSource};
use citrate_fork::state::{redacted_origin, validate_rpc_url};
use citrate_fork::{run, ForkState, Plan, RpcState};
use common::*;
use serde_json::{json, Value};

const BLOCK: u64 = 100_000;

/// Every JSON-RPC method the test endpoint was asked, with its params.
type CallLog = Arc<Mutex<Vec<(String, Value)>>>;

/// Serves canned JSON-RPC answers and records every method called.
fn serve(existing: [u8; 20]) -> (String, CallLog) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    let runtime = fixture("PayoutRuntime");
    let sender_hex = addr_hex(sender());
    let existing_hex = format!("0x{}", hex::encode(existing));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let log = log2.clone();
            let runtime = runtime.clone();
            let sender_hex = sender_hex.clone();
            let existing_hex = existing_hex.clone();
            std::thread::spawn(move || {
                let mut w = match stream.try_clone() {
                    Ok(w) => w,
                    Err(_) => return,
                };
                let mut r = BufReader::new(stream);
                loop {
                    let mut len = 0usize;
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    loop {
                        let mut h = String::new();
                        if r.read_line(&mut h).unwrap_or(0) == 0 {
                            return;
                        }
                        let t = h.trim_end();
                        if t.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = t.split_once(':') {
                            if k.eq_ignore_ascii_case("content-length") {
                                len = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    let mut body = vec![0u8; len];
                    if r.read_exact(&mut body).is_err() {
                        return;
                    }
                    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let method = req["method"].as_str().unwrap_or_default().to_string();
                    let params = req["params"].clone();
                    if let Ok(mut l) = log.lock() {
                        l.push((method.clone(), params.clone()));
                    }
                    let who = params[0].as_str().unwrap_or_default().to_lowercase();
                    let result = match method.as_str() {
                        "eth_chainId" => json!("0x9d0c"),
                        "eth_blockNumber" => json!(format!("0x{BLOCK:x}")),
                        "eth_getBlockByNumber" => json!({
                            "number": params[0],
                            "timestamp": "0x6a000000",
                            "hash": format!("0x{}", "ab".repeat(32)),
                            "miner": format!("0x{}", "cd".repeat(20)),
                        }),
                        "eth_getBalance" if who == sender_hex => json!(format!("{:#x}", salt(7))),
                        "eth_getBalance" => json!("0x0"),
                        "eth_getTransactionCount" if who == sender_hex => json!("0x5"),
                        "eth_getTransactionCount" => json!("0x0"),
                        "eth_getCode" if who == existing_hex => json!(runtime),
                        "eth_getCode" => json!("0x"),
                        "eth_getStorageAt" => json!(format!("0x{}", "0".repeat(64))),
                        _ => Value::Null,
                    };
                    let resp = if result.is_null() {
                        json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32601, "message": "not served" } })
                    } else {
                        json!({ "jsonrpc": "2.0", "id": 1, "result": result })
                    }
                    .to_string();
                    let out = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        resp.len(),
                        resp
                    );
                    if w.write_all(out.as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (url, log)
}

#[test]
fn forked_state_is_read_at_the_pinned_block_with_read_methods_only() {
    let existing = [0x42u8; 20];
    let (url, log) = serve(existing);
    let (st, chain_id, block) = RpcState::connect(&url, None).expect("connect");
    assert_eq!(chain_id, 40204);
    assert_eq!(block.number, BLOCK);
    let cfg = ForkConfig {
        chain_id,
        block,
        hardening_height: pinned_hardening(chain_id),
        hardening_source: "release pin".into(),
        agent_fork_height: citrate_execution::agent_fork::pinned_for(chain_id).flatten(),
        agent_fork_source: "release pin".into(),
        source: StateSource::Rpc {
            origin: redacted_origin(&url),
        },
    };
    // No balance override: the sender's 7 SALT and nonce 5 come from the endpoint.
    let plan = Plan::from_json(
        &json!({
            "from": addr_hex(sender()),
            "steps": [
                { "kind": "call", "to": format!("0x{}", hex::encode(existing)),
                  "data": format!("0x70a08231{}", word_addr(&sender().0 .0)) },
                { "kind": "create", "data": fixture("Payout"), "value": salt(1).to_string() },
            ]
        })
        .to_string(),
    )
    .expect("plan");
    let rep = run(&plan, ForkState::Rpc(st), &cfg).expect("runs");
    assert!(rep.all_steps_succeeded, "{rep:#?}");
    // The existing contract's code came from eth_getCode; it reads the sender's forked balance.
    assert_eq!(abi_u256(&rep.steps[0].output), salt(7));
    // The create address follows the forked nonce: 5 from the endpoint, plus the call step
    // before it (each step is a transaction from the sender).
    let expected = sender().create(6);
    assert_eq!(
        rep.steps[1].contract_address,
        Some(format!("{expected:#x}"))
    );
    assert_eq!(rep.simulated_block, BLOCK + 1);

    let calls = log.lock().expect("log").clone();
    let allowed = [
        "eth_chainId",
        "eth_blockNumber",
        "eth_getBlockByNumber",
        "eth_getBalance",
        "eth_getTransactionCount",
        "eth_getCode",
        "eth_getStorageAt",
    ];
    for (m, p) in &calls {
        assert!(allowed.contains(&m.as_str()), "called {m}");
        if matches!(
            m.as_str(),
            "eth_getBalance" | "eth_getTransactionCount" | "eth_getCode"
        ) {
            assert_eq!(
                p[1],
                json!(format!("0x{BLOCK:x}")),
                "{m} reads the pinned block"
            );
        }
    }
}

#[test]
fn rpc_urls_are_checked_and_redacted() {
    assert!(validate_rpc_url("http://127.0.0.1:8545").is_ok());
    assert!(validate_rpc_url("https://rpc.citrate.ai").is_ok());
    assert!(validate_rpc_url("ftp://x").is_err());
    assert!(validate_rpc_url("http://").is_err());
    assert!(validate_rpc_url("https://user:pw@host/").is_err());
    assert_eq!(
        redacted_origin("https://rpc.example/v1/abc?k=1"),
        "https://rpc.example"
    );
}

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn rpc(url: &str, method: &str, params: Value) -> Value {
    let c = reqwest::blocking::Client::new();
    let v: Value = c
        .post(url)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .expect("send")
        .json()
        .expect("json");
    v["result"].clone()
}

/// Runs against a real anvil (chain id 40204, genesis block 100,000) when `anvil` is on PATH.
/// The contract is placed with anvil's own state-setting methods; nothing is signed.
#[test]
fn anvil_fork_state_is_read_through_the_same_path() {
    if Command::new("anvil").arg("--version").output().is_err() {
        eprintln!("skipped: anvil is not installed");
        return;
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port");
    let child = Command::new("anvil")
        .args([
            "--chain-id",
            "40204",
            "--number",
            "100000",
            "--port",
            &port.to_string(),
            "--silent",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn anvil");
    let _guard = Anvil(child);
    let url = format!("http://127.0.0.1:{port}");
    let mut up = false;
    for _ in 0..100 {
        if reqwest::blocking::Client::new()
            .post(&url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": [] }))
            .send()
            .is_ok()
        {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(up, "anvil did not start");
    let existing = format!("0x{}", "42".repeat(20));
    rpc(
        &url,
        "anvil_setCode",
        json!([existing, fixture("PayoutRuntime")]),
    );
    rpc(
        &url,
        "anvil_setBalance",
        json!([addr_hex(sender()), format!("{:#x}", salt(3))]),
    );

    let (st, chain_id, block) = RpcState::connect(&url, None).expect("connect");
    assert_eq!(chain_id, 40204);
    let cfg = ForkConfig {
        chain_id,
        block,
        hardening_height: pinned_hardening(chain_id),
        hardening_source: "release pin".into(),
        agent_fork_height: citrate_execution::agent_fork::pinned_for(chain_id).flatten(),
        agent_fork_source: "release pin".into(),
        source: StateSource::Rpc {
            origin: redacted_origin(&url),
        },
    };
    let plan = Plan::from_json(
        &json!({
            "from": addr_hex(sender()),
            "steps": [
                { "kind": "call", "to": existing, "data": format!("0x70a08231{}", word_addr(&sender().0 .0)) },
                { "kind": "create", "data": probe_initcode(0x0110, &belnap_input()) },
                { "kind": "call", "to": "created:1", "data": "0xd909b403" },
            ]
        })
        .to_string(),
    )
    .expect("plan");
    let rep = run(&plan, ForkState::Rpc(st), &cfg).expect("runs");
    assert!(rep.all_steps_succeeded, "{rep:#?}");
    assert_eq!(abi_u256(&rep.steps[0].output), salt(3));
    assert_eq!(
        abi_u256(&rep.steps[2].output),
        revm::primitives::U256::from(1),
        "0x0110 answered"
    );
    // The same call on anvil itself reaches an empty account: success, no data.
    let raw = rpc(
        &url,
        "eth_call",
        json!([{ "to": "0x0000000000000000000000000000000000000110", "data": format!("0x{}", hex::encode(belnap_input())) }, "latest"]),
    );
    assert_eq!(
        raw,
        json!("0x"),
        "plain anvil cannot answer a Citrate precompile"
    );
}

#[test]
fn an_oversized_rpc_answer_is_refused() {
    // An endpoint that answers every request with a body over the 4 MiB cap.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut w = match stream.try_clone() {
                    Ok(w) => w,
                    Err(_) => return,
                };
                let mut r = BufReader::new(stream);
                let mut line = String::new();
                // Drain the request head; the body is not needed.
                while r.read_line(&mut line).unwrap_or(0) > 0 {
                    if line == "\r\n" {
                        break;
                    }
                    line.clear();
                }
                let body = format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x{}\"}}",
                    "0".repeat(5 * 1024 * 1024)
                );
                let out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = w.write_all(out.as_bytes());
                let _ = w.write_all(body.as_bytes());
            });
        }
    });
    let e = RpcState::connect(&url, Some(BLOCK))
        .err()
        .expect("an oversized answer must be refused");
    assert!(e.0.contains("larger than"), "{e}");
}
