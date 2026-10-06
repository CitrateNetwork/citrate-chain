//! HUP-S6.10: differential check against the node itself. The same init code runs once
//! through the node's own REVM entry points (`revm_adapter::execute_contract_create` /
//! `execute_contract_call`, the functions the 40204 executor calls) and once through the
//! fork, and every block and transaction environment word a contract can read must match.
//!
//! This is what catches an EVM setting the fork configures differently from the node (for
//! example a block gas limit the node never sets, which would change the GASLIMIT opcode).
mod common;

use std::sync::Arc;

use citrate_execution::revm_adapter::{execute_contract_call, execute_contract_create};
use citrate_execution::{Address as NodeAddress, StateDB};
use citrate_fork::{run, ForkState, Plan};
use common::*;
use primitive_types::U256 as NodeU256;

/// Above the CREATE-nonce activation and below the 40204 hardening pin, like 40204 today.
const FORK_BLOCK: u64 = 100_000;

/// The environment opcodes compared, each stored in its own slot by the constructor.
/// COINBASE and PREVRANDAO are compared with both sides at zero: the fork cannot know the
/// proposer or VRF output of the block it simulates, and the node test context sets none.
const ENV_OPCODES: [(u8, &str); 9] = [
    (0x45, "GASLIMIT"),
    (0x48, "BASEFEE"),
    (0x3a, "GASPRICE"),
    (0x46, "CHAINID"),
    (0x43, "NUMBER"),
    (0x42, "TIMESTAMP"),
    (0x41, "COINBASE"),
    (0x44, "PREVRANDAO"),
    (0x4a, "BLOBBASEFEE"),
];

/// Init code: `SSTORE(i, <opcode i>)` for every opcode, then return a runtime that answers
/// `SLOAD(calldata[0..32])`.
fn env_probe_initcode() -> Vec<u8> {
    // PUSH0 CALLDATALOAD SLOAD PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
    let runtime: [u8; 9] = [0x5f, 0x35, 0x54, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];
    let mut code = Vec::new();
    for (i, (op, _)) in ENV_OPCODES.iter().enumerate() {
        code.extend_from_slice(&[*op, 0x60, i as u8, 0x55]);
    }
    // PUSH1 len PUSH1 offset PUSH0 CODECOPY PUSH1 len PUSH0 RETURN  (10 bytes)
    let offset = code.len() + 10;
    code.extend_from_slice(&[
        0x60,
        runtime.len() as u8,
        0x60,
        offset as u8,
        0x5f,
        0x39,
        0x60,
        runtime.len() as u8,
        0x5f,
        0xf3,
    ]);
    code.extend_from_slice(&runtime);
    code
}

fn slot_word(i: usize) -> Vec<u8> {
    let mut w = vec![0u8; 32];
    w[31] = i as u8;
    w
}

#[test]
fn every_environment_word_matches_the_node() {
    let init = env_probe_initcode();
    let cfg = config_at(FORK_BLOCK);
    let height = FORK_BLOCK + 1;
    let timestamp = cfg.block.timestamp + 2;

    // The fork.
    let mut steps =
        vec![serde_json::json!({ "kind": "create", "data": format!("0x{}", hex::encode(&init)) })];
    for i in 0..ENV_OPCODES.len() {
        steps.push(serde_json::json!({
            "kind": "call", "to": "created:0", "data": format!("0x{}", hex::encode(slot_word(i)))
        }));
    }
    let plan = Plan::from_json(
        &serde_json::json!({ "from": addr_hex(sender()), "steps": steps }).to_string(),
    )
    .expect("plan");
    let rep = run(&plan, ForkState::Empty, &cfg).expect("fork runs");
    assert!(rep.all_steps_succeeded, "{rep:#?}");

    // The node.
    let db = Arc::new(StateDB::new());
    let deployer = NodeAddress(sender().0 .0);
    let (contract, _, _) = execute_contract_create(
        db.clone(),
        deployer,
        init,
        NodeU256::zero(),
        plan.gas_limit,
        NodeU256::zero(),
        40204,
        height,
        timestamp,
    )
    .expect("node create");

    for (i, (_, name)) in ENV_OPCODES.iter().enumerate() {
        let (node_out, _) = execute_contract_call(
            db.clone(),
            deployer,
            contract,
            slot_word(i),
            NodeU256::zero(),
            plan.gas_limit,
            NodeU256::zero(),
            40204,
            height,
            timestamp,
        )
        .expect("node call");
        assert_eq!(
            rep.steps[i + 1].output,
            format!("0x{}", hex::encode(&node_out)),
            "{name} differs between the fork and the node"
        );
    }
}
