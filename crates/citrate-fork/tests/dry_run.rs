//! HUP-S6.10: the fork runs the node's Citrate precompiles and execution rules, and reports
//! every precompile it cannot reproduce.
mod common;

use citrate_fork::table::Coverage;
use citrate_fork::{run, ForkState, Plan};
use common::*;

/// The block the dry runs sit on: above the CREATE-nonce activation (30,000). The 40204
/// reroll pins the PBA hardening at genesis (0), so every 40204 block is hardened.
const TODAY: u64 = 100_000;
/// A later block, also hardened.
const HARDENED: u64 = 300_000;

fn plan_json(steps: serde_json::Value) -> String {
    serde_json::json!({
        "from": addr_hex(sender()),
        "balances": { addr_hex(sender()): salt(10).to_string() },
        "steps": steps,
    })
    .to_string()
}

fn probe_plan(v: u16, input: &[u8]) -> Plan {
    Plan::from_json(&plan_json(serde_json::json!([
        { "kind": "create", "data": probe_initcode(v, input) },
        { "kind": "call", "to": "created:0", "data": "0xd909b403" },
        { "kind": "call", "to": "created:0", "data": "0xb2a1449b" },
        { "kind": "call", "to": "created:0", "data": "0xa14c0c0e" },
        { "kind": "call", "to": "created:0", "data": "0x37fd23bd" },
    ])))
    .expect("plan parses")
}

#[test]
fn belnap_runs_the_node_implementation_with_40204_evm_settings() {
    let input = belnap_input();
    let rep = run(
        &probe_plan(0x0110, &input),
        ForkState::Empty,
        &config_at(TODAY),
    )
    .expect("runs");
    assert!(rep.all_steps_succeeded, "{rep:#?}");
    assert_eq!(rep.engine, "citrate-fork");
    assert_eq!(rep.status, "0x1");
    assert!(rep.contract_address.is_some());
    // ok() == true
    assert_eq!(
        abi_u256(&rep.steps[1].output),
        revm::primitives::U256::from(1)
    );
    // out() is byte-for-byte what the node's 0x0110 returns.
    let addr = citrate_execution::types::Address(precompile(0x0110));
    let expected = citrate_execution::precompiles::execute_pure(&addr, &input, 1_000_000)
        .expect("node belnap")
        .output;
    assert_eq!(expected.len(), 9, "dim 1 → 9 bytes");
    assert_eq!(abi_bytes(&rep.steps[2].output), expected);
    // GASPRICE reads 0 inside the EVM, as on 40204; CHAINID is 40204.
    assert_eq!(abi_u256(&rep.steps[3].output), revm::primitives::U256::ZERO);
    assert_eq!(
        abi_u256(&rep.steps[4].output),
        revm::primitives::U256::from(40204)
    );
    // The touch is recorded as real, and nothing unavailable was touched.
    assert_eq!(rep.precompiles.touched.len(), 1);
    let t = &rep.precompiles.touched[0];
    assert_eq!(
        (t.address.as_str(), t.coverage, t.calls, t.failed_calls),
        ("0x0110", Coverage::Real, 1, 0)
    );
    assert!(rep.precompiles.unavailable_touched.is_empty());
    assert_eq!(
        rep.steps[0].precompiles_touched.len(),
        1,
        "touched in the constructor"
    );
    assert!(rep.semantics.pba_hardened);
    assert_eq!(rep.semantics.pba_hardening_height, Some(0));
}

#[test]
fn a_bad_precompile_input_fails_the_frame_like_the_node() {
    let rep = run(
        &probe_plan(0x0110, &[1, 2, 3, 4]),
        ForkState::Empty,
        &config_at(TODAY),
    )
    .expect("runs");
    assert!(
        rep.all_steps_succeeded,
        "the probe records the failure, it does not revert"
    );
    assert_eq!(
        abi_u256(&rep.steps[1].output),
        revm::primitives::U256::ZERO,
        "ok() == false"
    );
    let t = &rep.precompiles.touched[0];
    assert_eq!((t.calls, t.failed_calls), (1, 1));
}

#[test]
fn an_inference_precompile_is_flagged_unavailable_and_is_silent_without_hardening() {
    // A chain without the hardening pin (`--pba-hardening-height off`, e.g. a devnet) answers
    // success with no data here. 40204 is hardened from its genesis (see the next test).
    let mut cfg = config_at(TODAY);
    cfg.hardening_height = None;
    cfg.hardening_source = "off".into();
    let rep = run(&probe_plan(0x0100, b"hello"), ForkState::Empty, &cfg).expect("runs");
    assert!(!rep.semantics.pba_hardened);
    assert_eq!(
        abi_u256(&rep.steps[1].output),
        revm::primitives::U256::from(1)
    );
    assert!(abi_bytes(&rep.steps[2].output).is_empty());
    assert_eq!(
        rep.precompiles.unavailable_touched,
        vec!["0x0100".to_string()]
    );
    assert_eq!(rep.precompiles.touched[0].coverage, Coverage::Unavailable);
}

#[test]
fn an_inference_precompile_fails_at_a_hardened_height() {
    for block in [30_000, TODAY, HARDENED] {
        let rep = run(
            &probe_plan(0x0100, b"hello"),
            ForkState::Empty,
            &config_at(block),
        )
        .expect("runs");
        assert!(rep.semantics.pba_hardened, "block {block}");
        assert_eq!(
            abi_u256(&rep.steps[1].output),
            revm::primitives::U256::ZERO,
            "ok() == false at block {block}"
        );
        assert_eq!(
            rep.precompiles.unavailable_touched,
            vec!["0x0100".to_string()]
        );
    }
}

#[test]
fn a_contract_initiated_value_transfer_moves_salt() {
    let recipient = [0x77u8; 20];
    let plan = Plan::from_json(&plan_json(serde_json::json!([
        { "kind": "create", "data": fixture("Payout"), "value": salt(1).to_string() },
        { "kind": "call", "to": "created:0", "data": format!("0x0c11dedd{}", word_addr(&recipient)) },
        { "kind": "call", "to": "created:0", "data": format!("0x70a08231{}", word_addr(&recipient)) },
    ])))
    .expect("plan");
    let rep = run(&plan, ForkState::Empty, &config_at(TODAY)).expect("runs");
    assert!(rep.all_steps_succeeded, "{rep:#?}");
    assert_eq!(
        abi_u256(&rep.steps[2].output),
        salt(1),
        "the recipient holds what the contract sent"
    );
    assert!(rep.precompiles.touched.is_empty());
    assert_eq!(rep.balance_overrides.len(), 1);
}

#[test]
fn a_reverting_step_is_reported_not_hidden() {
    // pay() with no SALT in the contract still succeeds; calling a non-function reverts.
    let plan = Plan::from_json(&plan_json(serde_json::json!([
        { "kind": "create", "data": fixture("Payout") },
        { "kind": "call", "to": "created:0", "data": "0xdeadbeef" },
    ])))
    .expect("plan");
    let rep = run(&plan, ForkState::Empty, &config_at(TODAY)).expect("runs");
    assert_eq!(rep.status, "0x1", "the create succeeded");
    assert_eq!(rep.steps[1].status, "0x0");
    assert_eq!(rep.steps[1].error.as_deref(), Some("reverted"));
    assert!(!rep.all_steps_succeeded);
}

#[test]
fn the_report_mirrors_the_first_step_as_a_receipt() {
    let initcode = fixture("Payout");
    let plan = Plan::from_json(&plan_json(
        serde_json::json!([{ "kind": "create", "data": initcode }]),
    ))
    .expect("plan");
    let rep = run(&plan, ForkState::Empty, &config_at(TODAY)).expect("runs");
    let v = serde_json::to_value(&rep).expect("json");
    assert_eq!(v["status"], "0x1");
    assert_eq!(v["engine"], "citrate-fork");
    assert!(v["contractAddress"]
        .as_str()
        .is_some_and(|a| a.starts_with("0x") && a.len() == 42));
    assert!(v["gasUsed"].as_str().is_some_and(|g| g.starts_with("0x")));
    assert_eq!(
        v["steps"][0]["input"], initcode,
        "the exact init code that ran"
    );
    assert_eq!(v["simulatedBlock"], TODAY + 1);
    assert!(v["precompiles"]["real"]
        .as_array()
        .is_some_and(|r| r.iter().any(|a| a == "0x0110")));
}

#[test]
fn a_block_below_the_create_nonce_activation_is_refused() {
    let plan = Plan::from_json(&plan_json(
        serde_json::json!([{ "kind": "create", "data": fixture("Payout") }]),
    ))
    .expect("plan");
    let e = run(&plan, ForkState::Empty, &config_at(10)).expect_err("refused");
    assert!(e.0.contains("CREATE-nonce"), "{e}");
}

#[test]
fn plans_are_checked() {
    let bad = [
        serde_json::json!({ "from": addr_hex(sender()), "steps": [] }),
        serde_json::json!({ "from": "0x12", "steps": [{ "kind": "create", "data": "0x60" }] }),
        serde_json::json!({ "from": addr_hex(sender()), "steps": [{ "kind": "call", "to": "created:0" }] }),
        serde_json::json!({ "from": addr_hex(sender()), "steps": [
            { "kind": "call", "to": "created:1" }, { "kind": "create", "data": "0x60" }] }),
        serde_json::json!({ "from": addr_hex(sender()), "steps": [{ "kind": "create", "data": "0x60", "value": "-1" }] }),
        serde_json::json!({ "from": addr_hex(sender()), "steps": [{ "kind": "create", "data": "0x" }] }),
        serde_json::json!({ "from": addr_hex(sender()), "gasLimit": 0, "steps": [{ "kind": "create", "data": "0x60" }] }),
        serde_json::json!({ "from": addr_hex(sender()), "steps": [{ "kind": "send", "data": "0x60" }] }),
        serde_json::json!({ "from": addr_hex(sender()), "key": "x", "steps": [{ "kind": "create", "data": "0x60" }] }),
    ];
    for b in bad {
        assert!(Plan::from_json(&b.to_string()).is_err(), "accepted {b}");
    }
    let many: Vec<_> = (0..17)
        .map(|_| serde_json::json!({ "kind": "create", "data": "0x60" }))
        .collect();
    let too_many = serde_json::json!({ "from": addr_hex(sender()), "steps": many });
    assert!(Plan::from_json(&too_many.to_string()).is_err());
}

#[test]
fn a_top_level_call_into_a_precompile_is_traced_too() {
    // A plan step that targets a Citrate precompile directly (not through a contract) must
    // be recorded like a nested call: the tracer sees the transaction's own frame.
    let plan = Plan::from_json(&plan_json(serde_json::json!([
        { "kind": "create", "data": fixture("Payout") },
        { "kind": "call", "to": addr_hex(revm::primitives::Address::from_slice(&precompile(0x0100))), "data": "0x00" },
        { "kind": "call", "to": addr_hex(revm::primitives::Address::from_slice(&precompile(0x0110))),
          "data": format!("0x{}", hex::encode(belnap_input())) },
    ])))
    .expect("plan");
    let rep = run(&plan, ForkState::Empty, &config_at(TODAY)).expect("runs");
    assert_eq!(
        rep.precompiles.unavailable_touched,
        vec!["0x0100".to_string()]
    );
    let real: Vec<_> = rep
        .precompiles
        .touched
        .iter()
        .filter(|t| t.coverage == Coverage::Real)
        .map(|t| t.address.as_str())
        .collect();
    assert_eq!(real, vec!["0x0110"]);
    assert_eq!(rep.steps[1].precompiles_touched.len(), 1);
    assert_eq!(rep.steps[2].precompiles_touched.len(), 1);
}

#[test]
fn the_agent_precompile_fork_follows_the_configured_height() {
    // HUP-S7.2 x S6.10: on a chain where the agent precompile fork is active, the fork runs the
    // node's 0x0121 like the node does and marks it real; with the fork off the same address
    // is reserved and flagged unavailable. 40204 pins the fork at genesis, so it is real there.
    let step = || {
        Plan::from_json(&plan_json(serde_json::json!([
            { "kind": "create", "data": fixture("Payout") },
            { "kind": "call", "to": addr_hex(revm::primitives::Address::from_slice(&precompile(0x0121))), "data": "0x00" },
        ])))
        .expect("plan")
    };
    let mut devnet = config_at(TODAY);
    devnet.chain_id = 31_337;
    devnet.hardening_height = None;
    devnet.agent_fork_height = Some(1);
    let rep = run(&step(), ForkState::Empty, &devnet).expect("runs");
    assert!(rep.semantics.agent_precompiles_active);
    assert_eq!(rep.semantics.agent_precompiles_height, Some(1));
    assert!(rep.precompiles.real.contains(&"0x0121".to_string()));
    assert_eq!(rep.precompiles.touched[0].coverage, Coverage::Real);
    assert!(rep.precompiles.unavailable_touched.is_empty());

    let rep = run(&step(), ForkState::Empty, &config_at(TODAY)).expect("runs");
    assert!(
        rep.semantics.agent_precompiles_active,
        "40204: active from genesis"
    );
    assert_eq!(rep.semantics.agent_precompiles_height, Some(0));
    assert!(rep.precompiles.real.contains(&"0x0121".to_string()));
    assert_eq!(rep.precompiles.touched[0].coverage, Coverage::Real);

    let mut off = config_at(TODAY);
    off.chain_id = 31_337;
    off.agent_fork_height = None;
    let rep = run(&step(), ForkState::Empty, &off).expect("runs");
    assert!(!rep.semantics.agent_precompiles_active);
    assert_eq!(rep.semantics.agent_precompiles_height, None);
    assert!(!rep.precompiles.real.contains(&"0x0121".to_string()));
    assert_eq!(
        rep.precompiles.unavailable_touched,
        vec!["0x0121".to_string()]
    );
}
