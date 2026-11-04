//! `citrate_getFinalityStatus` (spec 06 §5.5, 02 §3; ADR CV-8): reports the
//! real checkpoint state the node's finality gadget holds, never block depth.
//!
//! Data source: the node's `CheckpointManager` (finalized certificates in
//! `DAG_METADATA` `checkpoint:{h}`, pending checkpoints and their votes) and
//! the compiled enforcement switch, published into a
//! [`FinalityStatusCell`] by the node's finality driver on every pass.

use citrate_api::finality_status::{
    register_finality_status, CheckpointView, FinalityStatusCell, FinalityStatusView,
};
use citrate_consensus::types::Hash;
use jsonrpc_core::IoHandler;
use serde_json::Value;
use std::sync::Arc;

fn call(io: &IoHandler) -> Value {
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"citrate_getFinalityStatus","params":[]}"#;
    let resp = io.handle_request_sync(req).expect("a response");
    let v: Value = serde_json::from_str(&resp).expect("json");
    assert!(v.get("error").is_none(), "no error: {v}");
    v["result"].clone()
}

fn view(height: u64, epoch: u64, voters: usize, voted: u128, total: u128) -> CheckpointView {
    CheckpointView {
        height,
        block_hash: Hash::new([height as u8; 32]),
        epoch,
        state_root: Hash::new([0x51; 32]),
        accepted_root: Hash::new([0xAC; 32]),
        committee_size: 4,
        voters,
        voted_stake: voted,
        total_stake: total,
    }
}

#[test]
fn finality_status_reports_checkpoint_epoch_votes_quorum_and_enforcement() {
    let cell = Arc::new(FinalityStatusCell::default());
    let mut io = IoHandler::new();
    register_finality_status(&mut io, cell.clone());

    // Before the node publishes anything: voting state unknown, no checkpoint.
    let r = call(&io);
    assert_eq!(r["finalized"], Value::Null);
    assert_eq!(r["published"], false);

    cell.publish(FinalityStatusView {
        voting: true,
        enforcement: false,
        mode: "observed".to_string(),
        interval: 50,
        vote_depth: 3,
        finalized: Some(view(100, 1, 3, 3_000, 4_000)),
        pending: vec![view(150, 1, 1, 1_000, 4_000)],
        halted: false,
    });
    let r = call(&io);
    assert_eq!(r["published"], true);
    assert_eq!(r["voting"], true);
    assert_eq!(r["enforcement"], false);
    assert_eq!(r["mode"], "observed");
    let f = &r["finalized"];
    assert_eq!(f["height"], "0x64");
    assert_eq!(f["epoch"], "0x1");
    assert_eq!(f["voters"], 3);
    assert_eq!(f["committeeSize"], 4);
    assert_eq!(f["votedStake"], "3000");
    assert_eq!(f["totalStake"], "4000");
    // 3,000 of 4,000 = 75.00 %, quorum is > 2/3 of the stake.
    assert_eq!(f["quorumPct"], 75.0);
    assert_eq!(f["quorumStake"], "2667");
    assert_eq!(f["hasQuorum"], true);
    let p = &r["pending"][0];
    assert_eq!(p["height"], "0x96");
    assert_eq!(p["quorumPct"], 25.0);
    assert_eq!(p["hasQuorum"], false);
    assert!(
        r["dataSource"].as_str().unwrap_or("").contains("CheckpointManager"),
        "the response names its data source"
    );
}
