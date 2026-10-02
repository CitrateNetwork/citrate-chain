// citrate/core/execution/tests/agent_precompiles_solidity_e2e.rs
//
// HUP-S7.2 (US-7.5 AC2/AC3, gate g4-precompiles on a devnet-equivalent path):
// compiled Solidity that uses `contracts/src/lib/CitratePrecompiles.sol` calls
// the agent precompile fork addresses through the production REVM path.
//
// The contract is `PrecompileCaller` from
// `contracts/test/precompiles/CitratePrecompilesFailClosed.t.sol`, compiled by
// forge with the repo's pinned settings (solc 0.8.36, via-IR, cancun). Its
// runtime bytecode is the fixture `fixtures/agent_precompile_caller_runtime.hex`.
// Regenerate after changing the library or the harness:
//
//   cd contracts && forge build && python3 -c "import json; \
//     print(json.load(open('out/CitratePrecompilesFailClosed.t.sol/PrecompileCaller.json')) \
//     ['deployedBytecode']['object'][2:])" \
//     > ../core/execution/tests/fixtures/agent_precompile_caller_runtime.hex
//
// Below the fork height the same calls revert with
// `CitratePrecompiles.PrecompileUnavailable(<address>)`: the contract fails
// closed. At and after it they return exactly what the precompiles return.

use std::collections::HashMap;
use std::sync::Arc;

use citrate_execution::activation::set_pba_hardening_height;
use citrate_execution::agent_fork::set_agent_precompiles_height;
use citrate_execution::precompiles::{agent_ops, lora, memory_anchor, q16::Q16, tensor_format};
use citrate_execution::revm_adapter::{
    execute_contract_call_with_context, BlockContext, ValueSemantics,
};
use citrate_execution::types::{Address, ExecutionError};
use citrate_execution::StateDB;
use k256::ecdsa::SigningKey;
use primitive_types::U256;
use sha3::{Digest, Keccak256};

const PBA_ACTIVATION: u64 = 50;
const AGENT_ACTIVATION: u64 = 200;
const BEFORE_PBA: u64 = 10;
const BEFORE_FORK: u64 = 150;
const FORKED: u64 = 250;

fn activate() {
    set_pba_hardening_height(Some(PBA_ACTIVATION));
    set_agent_precompiles_height(Some(AGENT_ACTIVATION));
}

fn runtime() -> Vec<u8> {
    let hex_code = include_str!("fixtures/agent_precompile_caller_runtime.hex");
    hex::decode(hex_code.trim()).expect("fixture is hex")
}

fn selector(sig: &str) -> [u8; 4] {
    let h = Keccak256::digest(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn pad32(n: usize) -> usize {
    n.div_ceil(32) * 32
}

fn word_u(n: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(n as u64).to_be_bytes());
    w
}

/// ABI-encode `sig(bytes, bytes, ...)` with only dynamic `bytes` arguments.
fn encode_bytes_call(sig: &str, args: &[&[u8]]) -> Vec<u8> {
    let mut out = selector(sig).to_vec();
    let mut tail: Vec<u8> = Vec::new();
    let head_len = 32 * args.len();
    for a in args {
        out.extend_from_slice(&word_u(head_len + tail.len()));
        tail.extend_from_slice(&word_u(a.len()));
        tail.extend_from_slice(a);
        tail.resize(tail.len() + pad32(a.len()) - a.len(), 0);
    }
    out.extend_from_slice(&tail);
    out
}

/// Decode a single dynamic `bytes` return value.
fn decode_bytes_return(ret: &[u8]) -> Vec<u8> {
    assert!(ret.len() >= 64, "ABI bytes return");
    let len = u64::from_be_bytes(ret[56..64].try_into().expect("8 bytes")) as usize;
    ret[64..64 + len].to_vec()
}

fn call(calldata: Vec<u8>, block_number: u64) -> Result<Vec<u8>, ExecutionError> {
    let state_db = Arc::new(StateDB::new());
    let caller = Address([0x11u8; 20]);
    let contract = Address([0x33u8; 20]);
    state_db
        .accounts
        .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));
    state_db.set_code(contract, runtime());
    let ctx = BlockContext {
        coinbase: [0x42; 20],
        prevrandao: [0u8; 32],
        block_hashes: HashMap::new(),
    };
    execute_contract_call_with_context(
        state_db,
        caller,
        contract,
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
    .map(|(out, _gas, _logs)| out)
}

/// The revert data of `PrecompileUnavailable(address(short))`, as hex.
fn unavailable(short: u16) -> String {
    let mut data = selector("PrecompileUnavailable(address)").to_vec();
    let mut w = [0u8; 32];
    w[30] = (short >> 8) as u8;
    w[31] = (short & 0xff) as u8;
    data.extend_from_slice(&w);
    hex::encode(data)
}

fn assert_fails_closed(result: Result<Vec<u8>, ExecutionError>, short: u16) {
    match result {
        Err(ExecutionError::Reverted(msg)) => assert!(
            msg.contains(&unavailable(short)),
            "expected PrecompileUnavailable(0x{short:04x}), got {msg}"
        ),
        other => panic!("expected a revert, got {other:?}"),
    }
}

fn q16_tensor(shape: &[u32], vals: &[i32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for v in vals {
        bytes.extend_from_slice(&Q16::from_int(*v).0.to_le_bytes());
    }
    tensor_format::encode(shape, tensor_format::Dtype::Q16_16, &bytes).expect("tensor")
}

fn hx(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex");
    v.as_slice().try_into().expect("32")
}

fn anchor_proof(record: &[u8]) -> Vec<u8> {
    use sha2::Sha256;
    let rec: [u8; 32] =
        sha2::Digest::finalize(sha2::Digest::chain_update(Sha256::default(), record)).into();
    let path = [
        hx("dd6b83ae1d8223d23ed4869464289c9952b6caf38b53cc4da7c87cc1f2462717"),
        hx("196bea1e49292cc96d0437940e2437d904130a222cb6812e6bfa53aae78871da"),
        hx("2fa07631df4d01d859eb3e78061cfb4b17ed553b410ce58c7d2b76a04d0c87cf"),
    ];
    let root = hx("e31cc748d04dce3c6ecfcb00dff52dd853d551e0f57bf3f2e516c2f65882a8e4");
    memory_anchor::encode_input(1, 20_362, 40, 44, 5, &root, 43, 3, &rec, &path).expect("enc")
}

fn key(n: u8) -> SigningKey {
    let mut scalar = [0u8; 32];
    scalar[31] = n;
    scalar[0] = 0x33;
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

/// The DEVICE_LINK_VERIFY body (the library prepends the op byte).
fn device_link_body() -> Vec<u8> {
    let (mk, dk, wk) = (key(1), key(2), key(3));
    let (m, d, w) = (address(&mk), address(&dk), address(&wk));
    let msg = agent_ops::device_link_message(&m, &d, &w, 0, "Studio Mac", 1_790_000_000);
    let full = agent_ops::encode_device_link(
        &m,
        &d,
        &w,
        0,
        b"Studio Mac",
        1_790_000_000,
        &sign(&mk, &msg),
        &sign(&dk, &msg),
        &sign(&wk, &msg),
    )
    .expect("encode");
    full[1..].to_vec()
}

#[test]
fn solidity_lora_apply_and_merge_succeed_end_to_end_after_the_fork() {
    activate();
    let (w, b, a, alpha) = (
        q16_tensor(&[2, 2], &[1, 0, 0, 1]),
        q16_tensor(&[2, 1], &[1, 2]),
        q16_tensor(&[1, 2], &[3, 4]),
        q16_tensor(&[], &[2]),
    );
    let calldata = encode_bytes_call("loraApply(bytes,bytes,bytes,bytes)", &[&w, &b, &a, &alpha]);
    let direct = lora::apply(
        &[w.clone(), b.clone(), a.clone(), alpha.clone()].concat(),
        1_000_000,
    )
    .expect("direct");
    let out = call(calldata.clone(), FORKED).expect("loraApply succeeds after the fork");
    assert_eq!(decode_bytes_return(&out), direct.output);
    assert_fails_closed(call(calldata.clone(), BEFORE_FORK), 0x0112);
    assert_fails_closed(call(calldata, BEFORE_PBA), 0x0112);

    let merge_in = [
        vec![1u8],
        q16_tensor(&[1, 1], &[2]),
        q16_tensor(&[1, 1], &[3]),
        q16_tensor(&[], &[1]),
        q16_tensor(&[], &[1]),
    ]
    .concat();
    let calldata = encode_bytes_call("loraMerge(bytes)", &[&merge_in]);
    let out = call(calldata.clone(), FORKED).expect("loraMerge succeeds after the fork");
    assert_eq!(
        decode_bytes_return(&out),
        lora::merge(&merge_in, 1_000_000).expect("direct").output
    );
    assert_fails_closed(call(calldata, BEFORE_FORK), 0x0113);
}

#[test]
fn solidity_memory_anchor_returns_the_commitment_after_the_fork() {
    activate();
    let calldata = encode_bytes_call("anchorCommitment(bytes)", &[&anchor_proof(b"rec-3")]);
    let out = call(calldata.clone(), FORKED).expect("anchorCommitment succeeds");
    assert_eq!(
        out,
        hx("26f10b854266080ba2d272d4042ef80c9a9eb85a90de744e71b4b10c7f9998e8").to_vec()
    );
    let wrong = encode_bytes_call("anchorCommitment(bytes)", &[&anchor_proof(b"rec-2")]);
    assert_eq!(
        call(wrong, FORKED).expect("invalid proof answers"),
        vec![0u8; 32]
    );
    assert_fails_closed(call(calldata, BEFORE_FORK), 0x0121);
}

#[test]
fn solidity_device_link_verifies_after_the_fork() {
    activate();
    let calldata = encode_bytes_call("deviceLinkValid(bytes)", &[&device_link_body()]);
    let mut yes = vec![0u8; 32];
    yes[31] = 1;
    assert_eq!(
        call(calldata.clone(), FORKED).expect("deviceLinkValid"),
        yes
    );
    let mut tampered = device_link_body();
    let last = tampered.len() - 1;
    tampered[last] ^= 1; // flip v of the wallet signature
    let calldata_bad = encode_bytes_call("deviceLinkValid(bytes)", &[&tampered]);
    assert_eq!(call(calldata_bad, FORKED).expect("answers"), vec![0u8; 32]);
    assert_fails_closed(call(calldata, BEFORE_FORK), 0x0122);
}

#[test]
fn solidity_model_inference_fails_closed_at_every_height() {
    // 0x0101 is never served to contract code (audit C-01), fork or not.
    activate();
    let mut calldata = selector("modelInference(bytes32,address,bytes)").to_vec();
    calldata.extend_from_slice(&[0xAB; 32]);
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(&[0xCD; 20]);
    calldata.extend_from_slice(&word_u(96));
    calldata.extend_from_slice(&word_u(1));
    let mut data = [0u8; 32];
    data[0] = 0x01;
    calldata.extend_from_slice(&data);
    for h in [BEFORE_PBA, BEFORE_FORK, FORKED] {
        assert_fails_closed(call(calldata.clone(), h), 0x0101);
    }
}
