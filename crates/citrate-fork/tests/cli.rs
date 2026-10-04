//! HUP-S6.10: the `citrate-fork` binary core's deploy gate runs.
mod common;

use std::io::Write as _;
use std::process::{Command, Stdio};

use common::*;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_citrate-fork"))
}

#[test]
fn precompiles_prints_the_coverage_table() {
    let out = bin()
        .args(["precompiles", "--block", "100000"])
        .output()
        .expect("runs");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["engine"], "citrate-fork");
    assert_eq!(v["chainId"], 40204);
    assert_eq!(v["pbaHardeningSource"], "release pin");
    let rows = v["precompiles"].as_array().expect("rows");
    let row = |a: &str| {
        rows.iter()
            .find(|r| r["address"] == a)
            .cloned()
            .expect("row")
    };
    assert_eq!(row("0x0110")["coverage"], "real");
    assert_eq!(row("0x0100")["coverage"], "unavailable");
}

#[test]
fn run_reads_a_plan_from_stdin_and_prints_a_report() {
    let plan = serde_json::json!({
        "from": addr_hex(sender()),
        "steps": [{ "kind": "create", "data": fixture("Payout") }],
    })
    .to_string();
    let mut child = bin()
        .args(["run", "--plan", "-", "--block", "100000"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(plan.as_bytes())
        .expect("write plan");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["status"], "0x1");
    assert_eq!(v["stateSource"]["kind"], "empty");
}

#[test]
fn a_release_network_hardening_override_is_refused() {
    let out = bin()
        .args(["precompiles", "--pba-hardening-height", "5"])
        .output()
        .expect("runs");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("release network"));
    // A devnet chain id may set it.
    let ok = bin()
        .args([
            "precompiles",
            "--chain-id",
            "1337",
            "--block",
            "10",
            "--pba-hardening-height",
            "5",
        ])
        .output()
        .expect("runs");
    assert!(ok.status.success());
    let v: serde_json::Value = serde_json::from_slice(&ok.stdout).expect("json");
    assert_eq!(v["pbaHardened"], true);
}

#[test]
fn bad_invocations_exit_non_zero_with_a_reason() {
    for args in [
        vec!["run", "--plan", "-"],
        vec!["bogus"],
        vec!["run", "--rpc", "ftp://x", "--plan", "-"],
    ] {
        let out = bin()
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .expect("runs");
        assert!(!out.status.success(), "{args:?}");
        assert!(!out.stderr.is_empty(), "{args:?}");
    }
}
