// citrate/core/api/tests/forge_fork_smoke.rs
//
// chain#425 smoke: a real `forge script` (Foundry fork mode) against this
// crate's RPC server on loopback, over a temp store whose executed head keeps
// advancing while the script runs. Foundry pins its fork reads to the block it
// read at start, so:
//   * strict (default): the reads made after the head moves are refused and
//     the script fails;
//   * `serve_recent_state_tags = 64`: the script completes.
//
// Ignored by default: it needs `forge` and a local solc 0.8.26 (no download).
// Run: FORGE_BIN=~/.foundry/bin/forge SOLC_BIN=~/.svm/0.8.26/solc-0.8.26 \
//      cargo test -p citrate-api --test forge_fork_smoke -- --ignored
// The script runs with HOME set to a temp dir and `--offline`; nothing outside
// the temp dir and the loopback port is touched.

use citrate_consensus::types::{Block, BlockBuilder, Hash};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

const SCRIPT: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface Vm {
    function sleep(uint256 ms) external;
    function getNonce(address who) external view returns (uint64);
}

contract Smoke {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external {
        uint256 before = address(0xA1).balance;
        vm.sleep(2_500); // the node executes several blocks meanwhile
        uint256 b = address(0xB2).balance;
        uint256 c = address(0xC3).code.length;
        uint64 n = vm.getNonce(address(0xD4));
        require(before + b + c + n == 0, "unexpected state");
    }
}
"#;

fn put(storage: &StorageManager, height: u64, parent: Hash) -> Block {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&height.to_be_bytes());
    h[31] = 0xF0;
    let b = BlockBuilder::new()
        .hash(Hash::new(h))
        .parent(parent)
        .height(height)
        .timestamp(1_700_000_000 + height)
        .gas_limit(30_000_000)
        .build_unhashed();
    storage.blocks.put_block(&b).expect("block");
    b
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// Run the smoke with `window`; returns (forge exit success, combined output).
fn run_forge(window: u64) -> (bool, String) {
    let forge = std::env::var("FORGE_BIN").expect("FORGE_BIN");
    let solc = std::env::var("SOLC_BIN").expect("SOLC_BIN");
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");

    let data = TempDir::new().expect("data dir");
    let storage =
        Arc::new(StorageManager::new(data.path(), PruningConfig::default()).expect("storage"));
    let mut tip = put(&storage, 0, Hash::default());
    for h in 1..=10 {
        tip = put(&storage, h, tip.hash());
    }
    storage
        .blocks
        .put_applied_tip(&tip.hash(), 10)
        .expect("tip");

    let port = free_port();
    let cfg = citrate_api::RpcConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().expect("addr"),
        serve_recent_state_tags: window,
        ..Default::default()
    };
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let pm = Arc::new(citrate_network::peer::PeerManager::new(
        citrate_network::peer::PeerManagerConfig::default(),
    ));
    let rpc = citrate_api::RpcServer::new(
        cfg,
        storage.clone(),
        Arc::new(Mempool::new(MempoolConfig::default())),
        pm,
        executor,
        40204,
    );
    let (close, _jh) = rpc.spawn().expect("spawn rpc");

    // The chain keeps executing: one block every 250 ms.
    let stop = Arc::new(AtomicBool::new(false));
    let producer = {
        let (storage, stop) = (storage.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut tip = tip;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(250));
                let next = put(&storage, tip.header.height + 1, tip.hash());
                storage
                    .blocks
                    .put_applied_tip(&next.hash(), next.header.height)
                    .expect("advance");
                tip = next;
            }
        })
    };

    let proj = TempDir::new().expect("project");
    let home = proj.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::write(proj.path().join("Smoke.s.sol"), SCRIPT).expect("script");
    std::fs::write(
        proj.path().join("foundry.toml"),
        format!(
            "[profile.default]\nsrc = \".\"\nscript = \".\"\nout = \"out\"\ncache_path = \"cache\"\n\
             solc = \"{solc}\"\noffline = true\nno_storage_caching = true\n"
        ),
    )
    .expect("foundry.toml");
    let out = std::process::Command::new(forge)
        .current_dir(proj.path())
        .env("HOME", &home)
        .env("FOUNDRY_DISABLE_NIGHTLY_WARNING", "1")
        .args([
            "script",
            "Smoke.s.sol:Smoke",
            "--rpc-url",
            &format!("http://127.0.0.1:{port}"),
            "--offline",
        ])
        .output()
        .expect("run forge");
    stop.store(true, Ordering::Relaxed);
    producer.join().expect("producer");
    close.close();
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
#[ignore = "needs forge and a local solc 0.8.26; see the file header"]
fn forge_script_against_a_moving_head_needs_the_operator_window() {
    let (ok, text) = run_forge(0);
    eprintln!("--- strict ---\n{text}");
    assert!(
        !ok,
        "strict node: the pinned reads after the head moved must fail"
    );
    assert!(
        text.contains("historical state not available"),
        "strict failure must be the state-tag refusal"
    );

    let (ok, text) = run_forge(64);
    eprintln!("--- serve_recent_state_tags = 64 ---\n{text}");
    assert!(ok, "with the operator window the script must complete");
}
