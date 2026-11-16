//! G4 finding 2026-11-11 (gc2 c5dcf39a): every SIGTERM shutdown panicked with "Cannot drop
//! a runtime in a context where blocking is not allowed". The ceremony stops producers with
//! SIGTERM one at a time, so a clean SIGTERM shutdown is a ceremony requirement.
//!
//! Starts a real node binary (devnet profile, loopback ports, a temp data dir), waits until
//! its RPC answers, sends SIGTERM, and requires: exit status 0, the shutdown line, and no
//! panic anywhere in its output. Unix only.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn rpc_answers(port: u16) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.contains("\"result\"")
}

#[test]
fn sigterm_shuts_the_node_down_without_a_panic() {
    let dir = tempfile::tempdir().expect("data dir");
    let (rpc, p2p) = (free_port(), free_port());
    let log = dir.path().join("node.out");
    let out = std::fs::File::create(&log).expect("log file");
    let err = out.try_clone().expect("log file");
    let mut child = Command::new(env!("CARGO_BIN_EXE_citrate"))
        .args([
            "--data-dir",
            dir.path().join("data").to_str().expect("utf8"),
            "--rpc-addr",
            &format!("127.0.0.1:{rpc}"),
            "--p2p-addr",
            &format!("127.0.0.1:{p2p}"),
            "--coinbase",
            "0x00000000000000000000000000000000000000c0",
            "devnet",
        ])
        .env("LOG_FORMAT", "compact")
        .env("LOG_ANSI", "false")
        .env_remove("RUST_LOG")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("start the node");
    let start = Instant::now();
    while !rpc_answers(rpc) {
        if let Ok(Some(st)) = child.try_wait() {
            panic!(
                "the node exited before its RPC answered ({st}):\n{}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
        assert!(
            start.elapsed() < Duration::from_secs(180),
            "the node's RPC never answered:\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill");
    assert!(status.success());
    let stop = Instant::now();
    let exit = loop {
        if let Some(st) = child.try_wait().expect("wait") {
            break st;
        }
        if stop.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!(
                "the node did not exit within 60 s of SIGTERM:\n{}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let text = std::fs::read_to_string(&log).expect("log");
    assert!(
        !text.contains("PANIC") && !text.contains("panicked"),
        "a panic during the SIGTERM shutdown:\n{text}"
    );
    assert!(
        text.contains("Shutting down (SIGTERM)"),
        "no shutdown line:\n{text}"
    );
    assert!(exit.success(), "exit status {exit}:\n{text}");
}
