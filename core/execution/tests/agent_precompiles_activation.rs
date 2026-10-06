// citrate/core/execution/tests/agent_precompiles_activation.rs
//
// HUP-S7.2 (federation F-2 / F-3): the agent precompile fork through the
// production REVM path.
//
// Every test here runs real EVM bytecode (a forwarder contract) through
// `execute_contract_call_with_context`, the same entry point block execution and
// `eth_call` use, and calls the new addresses with STATICCALL:
//
//   0x0112 LORA_APPLY, 0x0113 LORA_MERGE, 0x0121 MEMORY_ANCHOR_VERIFY, 0x0122 AGENT_OPS
//
// It covers both sides of BOTH activations (the PBA hardening height, which
// turns unbridged addresses into always-failing reserved addresses, and the
// agent precompile fork height), so it proves:
//   * below the fork the four addresses behave exactly like an unassigned
//     reserved address (byte-identical result and gas), under both PBA states;
//   * at and after the fork they return what the precompile functions return,
//     and charge exactly the scheduled gas;
//   * the rest of the precompile set is unchanged at the fork.
//
// Activation heights are process-global; this file is its own test binary, so
// every test sets the SAME heights and only the block number varies.

use std::collections::HashMap;
use std::sync::Arc;

use citrate_execution::activation::set_pba_hardening_height;
use citrate_execution::agent_fork::set_agent_precompiles_height;
use citrate_execution::precompiles::{agent_ops, lora, memory_anchor, q16::Q16, tensor_format};
use citrate_execution::revm_adapter::{
    execute_contract_call_with_context, execute_contract_create, BlockContext, ValueSemantics,
};
use citrate_execution::types::Address;
use citrate_execution::StateDB;
use k256::ecdsa::SigningKey;
use primitive_types::U256;
use sha3::{Digest, Keccak256};

const PBA_ACTIVATION: u64 = 50;
const AGENT_ACTIVATION: u64 = 200;
/// Below both activations.
const LEGACY: u64 = 10;
/// PBA hardening active, agent fork not yet.
const HARDENED: u64 = 100;
/// Both active.
const FORKED: u64 = 300;

fn activate() {
    set_pba_hardening_height(Some(PBA_ACTIVATION));
    set_agent_precompiles_height(Some(AGENT_ACTIVATION));
}

fn short(a: u16) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[18] = (a >> 8) as u8;
    out[19] = (a & 0xff) as u8;
    out
}

const NEW: [u16; 4] = [0x0112, 0x0113, 0x0121, 0x0122];
/// An unassigned address in the same reserved ranges: the control.
const CONTROL: u16 = 0x0114;

/// Forwarder runtime: copies calldata to memory, records GAS, STATICCALLs
/// `target` (with `gas` gas, or all of it when `None`), records GAS again and
/// returns `success (32) || gas_before - gas_after (32) || returndata`.
fn forwarder(target: [u8; 20], gas: Option<u32>) -> Vec<u8> {
    // CALLDATASIZE PUSH0 PUSH0 CALLDATACOPY ; GAS (g0)
    let mut c = vec![0x36, 0x5f, 0x5f, 0x37, 0x5a];
    // retSize, retOffset, argsSize, argsOffset, addr
    c.extend_from_slice(&[0x5f, 0x5f, 0x36, 0x5f, 0x73]);
    c.extend_from_slice(&target);
    match gas {
        Some(g) => {
            c.push(0x63); // PUSH4
            c.extend_from_slice(&g.to_be_bytes());
        }
        None => c.push(0x5a), // GAS
    }
    c.push(0xfa); // STATICCALL -> [success, g0]
                  // GAS (g1) SWAP1 PUSH0 MSTORE (success at 0) SWAP1 SUB (g0 - g1) PUSH1 0x20 MSTORE
    c.extend_from_slice(&[0x5a, 0x90, 0x5f, 0x52, 0x90, 0x03, 0x60, 0x20, 0x52]);
    // RETURNDATASIZE PUSH0 PUSH1 0x40 RETURNDATACOPY
    c.extend_from_slice(&[0x3d, 0x5f, 0x60, 0x40, 0x3e]);
    // RETURNDATASIZE PUSH1 0x40 ADD PUSH0 RETURN
    c.extend_from_slice(&[0x3d, 0x60, 0x40, 0x01, 0x5f, 0xf3]);
    c
}

struct CallOut {
    success: bool,
    /// Gas between the two GAS opcodes (fixed opcode overhead + call cost).
    span: u64,
    ret: Vec<u8>,
}

fn call(target: [u8; 20], calldata: Vec<u8>, block_number: u64, gas: Option<u32>) -> CallOut {
    let state_db = Arc::new(StateDB::new());
    let caller = Address([0x11u8; 20]);
    let fwd = Address([0x22u8; 20]);
    state_db
        .accounts
        .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));
    state_db.set_code(fwd, forwarder(target, gas));
    let ctx = BlockContext {
        coinbase: [0x42; 20],
        prevrandao: [0u8; 32],
        block_hashes: HashMap::new(),
    };
    let (output, _gas, _logs) = execute_contract_call_with_context(
        state_db,
        caller,
        fwd,
        calldata,
        U256::zero(),
        20_000_000,
        U256::from(1_000_000_000u64),
        40204,
        block_number,
        1_000_000,
        ctx,
        None,
        None,
        None,
        ValueSemantics::RevmAuthoritative,
    )
    .expect("forwarder executes");
    assert!(output.len() >= 64, "forwarder always returns two words");
    let mut span = [0u8; 8];
    span.copy_from_slice(&output[56..64]);
    CallOut {
        success: output[31] == 1,
        span: u64::from_be_bytes(span),
        ret: output[64..].to_vec(),
    }
}

/// The span overhead of the forwarder around a warm precompile: measured on
/// IDENTITY (0x04), whose price is 15 + 3 per word.
fn overhead(input_len: usize) -> u64 {
    let id = call(short(0x0004), vec![0u8; input_len], FORKED, None);
    assert!(id.success);
    id.span - (15 + 3 * (input_len as u64).div_ceil(32))
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

fn q16_tensor(shape: &[u32], vals: &[i32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for v in vals {
        bytes.extend_from_slice(&Q16::from_int(*v).0.to_le_bytes());
    }
    tensor_format::encode(shape, tensor_format::Dtype::Q16_16, &bytes).expect("tensor")
}

fn lora_apply_input() -> Vec<u8> {
    [
        q16_tensor(&[2, 2], &[1, 1, 1, 1]),
        q16_tensor(&[2, 1], &[1, 2]),
        q16_tensor(&[1, 2], &[3, 4]),
        q16_tensor(&[], &[2]),
    ]
    .concat()
}

fn lora_merge_input() -> Vec<u8> {
    [
        vec![2u8],
        q16_tensor(&[1, 1], &[2]),
        q16_tensor(&[1, 1], &[3]),
        q16_tensor(&[], &[1]),
        q16_tensor(&[], &[1]),
        q16_tensor(&[1, 2], &[1, 1]),
        q16_tensor(&[2, 1], &[1, 1]),
        q16_tensor(&[], &[4]),
        q16_tensor(&[], &[2]),
    ]
    .concat()
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Sha256;
    let mut h = Sha256::new();
    for p in parts {
        sha2::Digest::update(&mut h, p);
    }
    sha2::Digest::finalize(h).into()
}

fn hx(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex");
    v.as_slice().try_into().expect("32")
}

/// The shared 5-record day vector (see `precompiles::memory_anchor` tests).
fn anchor_input(record: [u8; 32]) -> Vec<u8> {
    let path = [
        hx("dd6b83ae1d8223d23ed4869464289c9952b6caf38b53cc4da7c87cc1f2462717"),
        hx("196bea1e49292cc96d0437940e2437d904130a222cb6812e6bfa53aae78871da"),
        hx("2fa07631df4d01d859eb3e78061cfb4b17ed553b410ce58c7d2b76a04d0c87cf"),
    ];
    let root = hx("e31cc748d04dce3c6ecfcb00dff52dd853d551e0f57bf3f2e516c2f65882a8e4");
    memory_anchor::encode_input(1, 20_362, 40, 44, 5, &root, 43, 3, &record, &path).expect("enc")
}
const ANCHOR_COMMITMENT: &str = "26f10b854266080ba2d272d4042ef80c9a9eb85a90de744e71b4b10c7f9998e8";

fn key(n: u8) -> SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = n;
    scalar[0] = 0x22;
    SigningKey::from_bytes((&scalar).into()).expect("scalar")
}

fn address(k: &SigningKey) -> [u8; 20] {
    let point = k.verifying_key().to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

fn sign(k: &SigningKey, message: &str) -> [u8; 65] {
    let digest = agent_ops::eip191_digest(message.as_bytes());
    let (sig, recid) = k.sign_prehash_recoverable(&digest).expect("sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + recid.to_byte();
    out
}

fn device_link_input(tamper_label: bool) -> Vec<u8> {
    let (mk, dk, wk) = (key(1), key(2), key(3));
    let (m, d, w) = (address(&mk), address(&dk), address(&wk));
    let msg = agent_ops::device_link_message(&m, &d, &w, 2, "Linux box", 1_790_000_000);
    let label: &[u8] = if tamper_label {
        b"Linux Box"
    } else {
        b"Linux box"
    };
    agent_ops::encode_device_link(
        &m,
        &d,
        &w,
        2,
        label,
        1_790_000_000,
        &sign(&mk, &msg),
        &sign(&dk, &msg),
        &sign(&wk, &msg),
    )
    .expect("encode")
}

fn word(v: u8) -> Vec<u8> {
    let mut w = vec![0u8; 32];
    w[31] = v;
    w
}

// ---------------------------------------------------------------------------
// Below the fork: nothing changes.
// ---------------------------------------------------------------------------

#[test]
fn below_the_fork_new_addresses_are_indistinguishable_from_an_unassigned_one() {
    activate();
    let inputs = [
        lora_apply_input(),
        lora_merge_input(),
        anchor_input([7u8; 32]),
        device_link_input(false),
    ];
    for height in [LEGACY, HARDENED, AGENT_ACTIVATION - 1] {
        for (addr, input) in NEW.iter().zip(inputs.iter()) {
            let got = call(short(*addr), input.clone(), height, None);
            let control = call(short(CONTROL), input.clone(), height, None);
            assert_eq!(
                got.success, control.success,
                "0x{addr:04x} at {height}: success"
            );
            assert_eq!(got.ret, control.ret, "0x{addr:04x} at {height}: returndata");
            assert_eq!(got.span, control.span, "0x{addr:04x} at {height}: gas");
        }
    }
    // And the control itself is what it is today: an empty account before the
    // PBA height, a failing reserved address after it.
    let legacy = call(short(CONTROL), vec![0xAB; 4], LEGACY, None);
    assert!(legacy.success && legacy.ret.is_empty());
    let hardened = call(short(CONTROL), vec![0xAB; 4], HARDENED, None);
    assert!(!hardened.success);
}

#[test]
fn activation_boundary_is_exact_and_inclusive() {
    activate();
    let input = lora_apply_input();
    let expected = lora::apply(&input, 1_000_000).expect("apply").output;
    assert!(!call(short(0x0112), input.clone(), AGENT_ACTIVATION - 1, None).success);
    for h in [AGENT_ACTIVATION, AGENT_ACTIVATION + 1] {
        let at = call(short(0x0112), input.clone(), h, None);
        assert!(at.success, "live at {h}");
        assert_eq!(at.ret, expected);
    }
}

// ---------------------------------------------------------------------------
// At and after the fork.
// ---------------------------------------------------------------------------

#[test]
fn lora_apply_and_merge_return_the_precompile_output_and_charge_its_gas() {
    activate();
    for (addr, input) in [
        (0x0112u16, lora_apply_input()),
        (0x0113, lora_merge_input()),
    ] {
        let direct = if addr == 0x0112 {
            lora::apply(&input, 1_000_000)
        } else {
            lora::merge(&input, 1_000_000)
        }
        .expect("direct");
        let out = call(short(addr), input.clone(), FORKED, None);
        assert!(out.success, "0x{addr:04x} succeeds");
        assert_eq!(
            out.ret, direct.output,
            "0x{addr:04x} returns the precompile bytes"
        );
        assert_eq!(
            out.span - overhead(input.len()),
            direct.gas_used,
            "0x{addr:04x} gas"
        );
    }
}

#[test]
fn memory_anchor_verify_returns_the_commitment_or_zero() {
    activate();
    let good = call(short(0x0121), anchor_input(sha(&[b"rec-3"])), FORKED, None);
    assert!(good.success);
    assert_eq!(good.ret, hx(ANCHOR_COMMITMENT).to_vec());
    assert_eq!(
        good.span - overhead(anchor_input([0u8; 32]).len()),
        1_500 + 3 * 150
    );
    let wrong = call(short(0x0121), anchor_input(sha(&[b"rec-2"])), FORKED, None);
    assert!(
        wrong.success,
        "an invalid proof is an answer, not a failure"
    );
    assert_eq!(wrong.ret, vec![0u8; 32]);
    let mut malformed = anchor_input(sha(&[b"rec-3"]));
    malformed.pop();
    assert!(
        !call(short(0x0121), malformed, FORKED, None).success,
        "malformed input fails the frame"
    );
}

#[test]
fn agent_ops_device_link_verifies_through_the_evm() {
    activate();
    let good = call(short(0x0122), device_link_input(false), FORKED, None);
    assert!(good.success);
    assert_eq!(good.ret, word(1));
    let tampered = call(short(0x0122), device_link_input(true), FORKED, None);
    assert!(tampered.success);
    assert_eq!(tampered.ret, word(0));
    assert!(
        !call(short(0x0122), vec![0x7f], FORKED, None).success,
        "unknown op fails the frame"
    );
}

#[test]
fn a_call_with_less_gas_than_the_schedule_fails() {
    activate();
    let input = anchor_input(sha(&[b"rec-3"]));
    let need = (1_500 + 3 * 150) as u32;
    assert!(!call(short(0x0121), input.clone(), FORKED, Some(need - 1)).success);
    assert!(call(short(0x0121), input, FORKED, Some(need)).success);
    let input = lora_apply_input();
    let need = lora::apply(&input, 1_000_000).expect("direct").gas_used as u32;
    assert!(!call(short(0x0112), input.clone(), FORKED, Some(need - 1)).success);
    assert!(call(short(0x0112), input, FORKED, Some(need)).success);
}

#[test]
fn the_rest_of_the_precompile_set_is_unchanged_at_the_fork() {
    activate();
    // An unassigned slot stays reserved.
    for addr in [CONTROL, 0x0123, 0x0104] {
        assert!(
            !call(short(addr), vec![0xAB; 4], FORKED, None).success,
            "0x{addr:04x}"
        );
    }
    // A bridged pure precompile answers the same before and after the fork.
    let input = q16_tensor(&[3], &[1, -2, 3]);
    let relu_before = call(short(0x010D), input.clone(), HARDENED, None);
    let relu_after = call(short(0x010D), input, FORKED, None);
    assert!(relu_before.success && relu_after.success);
    assert_eq!(relu_before.ret, relu_after.ret);
    assert_eq!(relu_before.span, relu_after.span);
}

// ---------------------------------------------------------------------------
// The CREATE path (constructor code) is gated exactly like the call path.
// ---------------------------------------------------------------------------

/// Init code that STATICCALLs `target` with `data` (copied from its own tail)
/// and deploys `success (32) || returndatasize (32)` as the "runtime code", so
/// the constructor's view of the precompile can be read back.
fn probe_init_code(target: [u8; 20], data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len()).expect("small");
    let mut c = Vec::new();
    // CODECOPY(dest 0, offset <patched>, size len)
    c.push(0x61);
    c.extend_from_slice(&len.to_be_bytes());
    c.push(0x61);
    let off_at = c.len();
    c.extend_from_slice(&[0, 0]);
    c.extend_from_slice(&[0x5f, 0x39]);
    // STATICCALL(gas, target, 0, len, 0, 0)
    c.extend_from_slice(&[0x5f, 0x5f, 0x61]);
    c.extend_from_slice(&len.to_be_bytes());
    c.extend_from_slice(&[0x5f, 0x73]);
    c.extend_from_slice(&target);
    c.extend_from_slice(&[0x5a, 0xfa]);
    // MSTORE(0, success) MSTORE(32, RETURNDATASIZE) RETURN(0, 64)
    c.extend_from_slice(&[0x5f, 0x52, 0x3d, 0x60, 0x20, 0x52, 0x60, 0x40, 0x5f, 0xf3]);
    let off = u16::try_from(c.len()).expect("small");
    c[off_at..off_at + 2].copy_from_slice(&off.to_be_bytes());
    c.extend_from_slice(data);
    c
}

fn create_probe(target: [u8; 20], data: &[u8], block_number: u64) -> (u8, u64) {
    let state_db = Arc::new(StateDB::new());
    let deployer = Address([0x55u8; 20]);
    state_db
        .accounts
        .set_balance(deployer, U256::from(10u64).pow(U256::from(18u64)));
    let (_addr, code, _gas) = execute_contract_create(
        state_db,
        deployer,
        probe_init_code(target, data),
        U256::zero(),
        5_000_000,
        U256::from(1_000_000_000u64),
        40204,
        block_number,
        1_000_000,
    )
    .expect("probe deploys");
    assert_eq!(code.len(), 64);
    let mut rds = [0u8; 8];
    rds.copy_from_slice(&code[56..64]);
    (code[31], u64::from_be_bytes(rds))
}

#[test]
fn constructor_code_sees_the_same_gate() {
    activate();
    let data = anchor_input(sha(&[b"rec-3"]));
    // Below the PBA height: an empty account (success, no data).
    assert_eq!(create_probe(short(0x0121), &data, LEGACY), (1, 0));
    // PBA active, fork not: reserved, the call fails.
    assert_eq!(create_probe(short(0x0121), &data, HARDENED), (0, 0));
    // Fork active: the precompile answers with the 32-byte commitment.
    assert_eq!(create_probe(short(0x0121), &data, FORKED), (1, 32));
}
