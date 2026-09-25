// PBA-R2 (lane CHAIN-EXEC): consensus-activation-gated execution hardening.
//
// Every rule here changes which state a block produces, so it switches on at
// `pba_hardening_height` (see `citrate_execution::activation`), never on
// deploy. Each test covers BOTH sides of the activation: below it the legacy
// behaviour is bit-for-bit unchanged (historical blocks replay), at/above it
// the hardened rule applies.
//
// The activation height is process-global (the node publishes it once at
// startup), so every test in this file sets the SAME height and only varies
// the block number.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::activation::set_pba_hardening_height;
use citrate_execution::executor::InferenceService;
use citrate_execution::revm_adapter::{
    execute_contract_call_with_context, BlockContext, ValueSemantics,
};
use citrate_execution::types::{
    AccessPolicy, Address, ExecutionError, ModelId, ModelMetadata, ModelState, UsageStats,
};
use citrate_execution::{Executor, StateDB};
use primitive_types::U256;

const ACTIVATION: u64 = 50;
const BEFORE: u64 = 10;
const AFTER: u64 = 100;

/// Every test sets the SAME height, so concurrent tests never observe a
/// different activation; only the block number varies.
fn activate() {
    set_pba_hardening_height(Some(ACTIVATION));
}

// ---------------------------------------------------------------------------
// PBA-L1a-019 (HIGH): node-local inference inside consensus execution.
// ---------------------------------------------------------------------------

/// Stand-in for one node's local model runtime: each node reports a different
/// provider (its own coinbase), fee and output — exactly the production
/// `node/src/inference.rs` shape that made replays diverge.
struct NodeLocalRuntime {
    provider: Address,
    fee: U256,
    output: Vec<u8>,
}

#[async_trait]
impl InferenceService for NodeLocalRuntime {
    async fn run_inference(
        &self,
        _model_id: ModelId,
        _input: Vec<u8>,
        _max_gas: u64,
    ) -> Result<(Vec<u8>, u64, Address, U256, Option<Vec<u8>>), ExecutionError> {
        Ok((self.output.clone(), 1_000, self.provider, self.fee, None))
    }
}

fn model_id() -> ModelId {
    ModelId(Hash::new([0x4D; 32]))
}

fn sender_key() -> PublicKey {
    PublicKey::new([0x5A; 32]) // native (non-EVM-shaped) sender
}

/// A node's executor over an identical starting state (funded sender, one
/// Public model), wired to that node's own local runtime.
fn node_executor(runtime: NodeLocalRuntime) -> Executor {
    let state = Arc::new(StateDB::new());
    let from = citrate_execution::address_utils::normalize_address(&sender_key());
    state
        .accounts
        .set_balance(from, U256::from(10u64).pow(U256::from(21u64)));
    state
        .register_model(
            model_id(),
            ModelState {
                owner: Address([0xAA; 20]),
                model_hash: Hash::new([0x01; 32]),
                version: 1,
                metadata: ModelMetadata::default(),
                access_policy: AccessPolicy::Public,
                usage_stats: UsageStats::default(),
            },
        )
        .expect("register model");
    Executor::new(state).with_inference_service(Arc::new(runtime))
}

fn inference_tx() -> Transaction {
    let mut data = vec![0x02, 0x00, 0x00, 0x00];
    data.extend_from_slice(model_id().0.as_bytes());
    data.extend_from_slice(b"prompt");
    Transaction {
        hash: Hash::new([0x19; 32]),
        nonce: 0,
        from: sender_key(),
        to: Some(PublicKey::new([0x77; 32])),
        value: 0,
        gas_limit: 2_000_000,
        gas_price: 1_000_000_000,
        data,
        signature: Signature::new([1; 64]),
        chain_id: Some(40204),
        ..Default::default()
    }
}

fn block_at(height: u64) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([height as u8; 32]))
        .parent(Hash::default())
        .height(height)
        .timestamp(1_000_000 + height)
        .build_unhashed()
}

/// Replay one inference tx on two nodes with different local runtimes.
async fn replay_on_two_nodes(height: u64) -> (Hash, Hash, bool, bool, Option<String>) {
    let a = node_executor(NodeLocalRuntime {
        provider: Address([0xA1; 20]),
        fee: U256::from(10u64).pow(U256::from(16u64)),
        output: vec![1, 1, 1],
    });
    let b = node_executor(NodeLocalRuntime {
        provider: Address([0xB2; 20]),
        fee: U256::from(3u64) * U256::from(10u64).pow(U256::from(16u64)),
        output: vec![2, 2],
    });
    let blk = block_at(height);
    let ra = a
        .execute_transaction(&blk, &inference_tx())
        .await
        .expect("node A executes");
    let rb = b
        .execute_transaction(&blk, &inference_tx())
        .await
        .expect("node B executes");
    (
        a.calculate_state_root(),
        b.calculate_state_root(),
        ra.status,
        rb.status,
        ra.revert_reason,
    )
}

#[tokio::test]
async fn pba_l1a_019_nodes_with_different_runtimes_agree_after_activation() {
    activate();
    let (root_a, root_b, ok_a, ok_b, reason) = replay_on_two_nodes(AFTER).await;
    assert_eq!(
        root_a, root_b,
        "after activation two nodes with different local runtimes must compute the same state root"
    );
    assert!(
        !ok_a && !ok_b,
        "the in-consensus inference request reverts deterministically"
    );
    assert!(
        reason.unwrap_or_default().contains("PBA-L1a-019"),
        "revert reason names the rule"
    );
}

#[tokio::test]
async fn pba_l1a_019_legacy_behaviour_is_unchanged_before_activation() {
    activate();
    // Below the activation height the historical (divergent) rule is kept
    // bit-for-bit so already-produced blocks replay: each node pays its own
    // provider, so the roots differ. This is the bug the activation fixes.
    let (root_a, root_b, ok_a, ok_b, _) = replay_on_two_nodes(BEFORE).await;
    assert!(ok_a && ok_b, "legacy path executes the local runtime");
    assert_ne!(
        root_a, root_b,
        "legacy rule: node-local payouts diverge (pre-activation)"
    );
}

// ---------------------------------------------------------------------------
// REVM bridge helpers (same forwarder as revm_precompile_bridge_e2e.rs)
// ---------------------------------------------------------------------------

fn staticcall_forwarder_runtime(target: [u8; 20]) -> Vec<u8> {
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x60, 0x20, 0x5f, 0x36, 0x5f, 0x73];
    code.extend_from_slice(&target);
    code.extend_from_slice(&[0x5a, 0xfa, 0x60, 0x20, 0x52, 0x60, 0x40, 0x5f, 0xf3]);
    code
}

/// STATICCALL `target` with `calldata` through the production REVM path at
/// `block_number`; returns (first returndata word, success word).
fn staticcall_at(target: [u8; 20], calldata: Vec<u8>, block_number: u64) -> ([u8; 32], [u8; 32]) {
    let (ret, ok, _gas) = staticcall_gas_at(target, calldata, block_number);
    (ret, ok)
}

/// As [`staticcall_at`], also returning the gas the outer call used.
fn staticcall_gas_at(
    target: [u8; 20],
    calldata: Vec<u8>,
    block_number: u64,
) -> ([u8; 32], [u8; 32], u64) {
    let state_db = Arc::new(StateDB::new());
    let caller = Address([0x11u8; 20]);
    let forwarder = Address([0x22u8; 20]);
    state_db
        .accounts
        .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));
    state_db.set_code(forwarder, staticcall_forwarder_runtime(target));
    let ctx = BlockContext {
        coinbase: [0x42; 20],
        prevrandao: [0u8; 32],
        block_hashes: HashMap::new(),
    };
    let (output, gas, _logs) = execute_contract_call_with_context(
        state_db,
        caller,
        forwarder,
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
    assert_eq!(output.len(), 64);
    let mut ret = [0u8; 32];
    let mut ok = [0u8; 32];
    ret.copy_from_slice(&output[..32]);
    ok.copy_from_slice(&output[32..]);
    (ret, ok, gas)
}

fn short(a: u16) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[18] = (a >> 8) as u8;
    out[19] = (a & 0xff) as u8;
    out
}

// ---------------------------------------------------------------------------
// PBA-L1a-022 (LOW): reserved precompile addresses behave as empty accounts.
// ---------------------------------------------------------------------------

#[test]
fn pba_l1a_022_reserved_precompile_call_fails_after_activation() {
    activate();
    for addr in [0x0100u16, 0x0104, 0x0106, 0x0112, 0x0203] {
        let (_, ok_before) = staticcall_at(short(addr), vec![0xAB; 4], BEFORE);
        assert_eq!(
            ok_before[31], 1,
            "0x{addr:04x}: legacy = empty account, CALL succeeds"
        );
        let (_, ok_after) = staticcall_at(short(addr), vec![0xAB; 4], AFTER);
        assert_eq!(
            ok_after[31], 0,
            "0x{addr:04x}: reserved address must fail the call"
        );
    }
    // A real bridged precompile is unaffected.
    let reserved = citrate_execution::precompiles::reserved_unbridged_addresses();
    for pure in citrate_execution::precompiles::PURE_PRECOMPILE_ADDRESSES {
        assert!(
            !reserved.contains(&pure),
            "bridged precompile listed as reserved"
        );
    }
}

// ---------------------------------------------------------------------------
// PBA-L1a-013 (MEDIUM): 0x0109 depth-0 / inner-node second preimage.
// ---------------------------------------------------------------------------

fn be32(x: ark_bn254::Fr) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let v = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}

fn merkle_inputs() -> (Vec<u8>, Vec<u8>) {
    use ark_bn254::Fr;
    use citrate_execution::zkp::poseidon_bn254::poseidon_hash;
    let l0 = poseidon_hash(&[Fr::from(0u64), Fr::from(111u64)]);
    let l1 = poseidon_hash(&[Fr::from(1u64), Fr::from(222u64)]);
    let root = poseidon_hash(&[l0, l1]);
    // Forgery (audit PoC): "leaf at index=l0 has value=l1", depth 0.
    let mut forged = Vec::new();
    forged.extend_from_slice(&be32(root));
    forged.extend_from_slice(&be32(l0));
    forged.extend_from_slice(&be32(l1));
    forged.push(0);
    // Honest: leaf (index 1, value 222), depth 1, sibling l0.
    let mut honest = Vec::new();
    honest.extend_from_slice(&be32(root));
    honest.extend_from_slice(&be32(Fr::from(1u64)));
    honest.extend_from_slice(&be32(Fr::from(222u64)));
    honest.push(1);
    honest.extend_from_slice(&be32(l0));
    (forged, honest)
}

#[test]
fn pba_l1a_013_merkle_second_preimage_rejected_after_activation() {
    activate();
    let (forged, honest) = merkle_inputs();
    let addr = short(0x0109);
    let (w, ok) = staticcall_at(addr, forged.clone(), AFTER);
    assert_eq!(ok[31], 1, "the precompile runs");
    assert_eq!(
        w[31], 0,
        "forged depth-0 membership must NOT verify after activation"
    );
    let (w, _) = staticcall_at(addr, honest.clone(), AFTER);
    assert_eq!(w[31], 1, "an honest proof still verifies after activation");
    // Legacy (pre-activation) result is unchanged, forgery included.
    let (w, _) = staticcall_at(addr, forged, BEFORE);
    assert_eq!(w[31], 1, "pre-activation output is frozen");
    let (w, _) = staticcall_at(addr, honest, BEFORE);
    assert_eq!(w[31], 1);
}

#[test]
fn pba_l1a_013_index_must_fit_depth() {
    use citrate_execution::precompiles::verify::merkle_verify_tensor_hardened;
    let (forged, honest) = merkle_inputs();
    // The audit forgery (index = an inner-node hash, depth 0) is rejected by
    // the hardened entry point itself (mutation-killer for the `fits` check).
    assert_eq!(
        merkle_verify_tensor_hardened(&forged, 1_000_000)
            .expect("run")
            .output[31],
        0
    );
    // A depth-32 proof takes every low-32-bit index (no shift overflow).
    let mut deep = vec![0u8; 97 + 32 * 32];
    deep[60..64].copy_from_slice(&u32::MAX.to_be_bytes());
    deep[96] = 32;
    merkle_verify_tensor_hardened(&deep, 10_000_000).expect("depth 32 runs");
    // index 1 at depth 1 fits; index 2 at depth 1 does not.
    let mut bad = honest.clone();
    bad[63] = 2;
    assert_eq!(
        merkle_verify_tensor_hardened(&honest, 1_000_000)
            .expect("run")
            .output[31],
        1
    );
    assert_eq!(
        merkle_verify_tensor_hardened(&bad, 1_000_000)
            .expect("run")
            .output[31],
        0
    );
    // High bytes set => rejected even if the low 32 bits fit.
    let mut high = honest;
    high[32] = 1;
    assert_eq!(
        merkle_verify_tensor_hardened(&high, 1_000_000)
            .expect("run")
            .output[31],
        0
    );
    // A proof that is VALID under the legacy rule but whose index has bits
    // above the low 32 (index = 2^40 + 1, depth 1): legacy accepts it (the
    // path only reads bit 0), hardened must not. Kills `high_zero || ..`.
    use ark_bn254::Fr;
    use citrate_execution::zkp::poseidon_bn254::poseidon_hash;
    let idx = Fr::from((1u64 << 40) + 1);
    let leaf = poseidon_hash(&[idx, Fr::from(5u64)]);
    let sib = Fr::from(77u64);
    let root = poseidon_hash(&[sib, leaf]); // bit 0 = 1 => right child
    let mut wide = Vec::new();
    wide.extend_from_slice(&be32(root));
    wide.extend_from_slice(&be32(idx));
    wide.extend_from_slice(&be32(Fr::from(5u64)));
    wide.push(1);
    wide.extend_from_slice(&be32(sib));
    assert_eq!(
        citrate_execution::precompiles::verify::merkle_verify_tensor(&wide, 1_000_000)
            .expect("run")
            .output[31],
        1,
        "legacy verifies the wide-index proof"
    );
    assert_eq!(
        merkle_verify_tensor_hardened(&wide, 1_000_000)
            .expect("run")
            .output[31],
        0,
        "hardened rejects an index wider than the proof depth"
    );
}

// ---------------------------------------------------------------------------
// PBA-L1a-025 (LOW): 0x0110 Belnap gas ignores n.
// ---------------------------------------------------------------------------

#[test]
fn pba_l1a_025_belnap_gas_scales_with_participants_after_activation() {
    use citrate_execution::precompiles::q16::belnap::gas_for;
    let mut header = Vec::new();
    header.extend_from_slice(&1u32.to_be_bytes()); // dim = 1
    header.extend_from_slice(&1024u32.to_be_bytes()); // n = 1024
    assert_eq!(
        gas_for(&header, false),
        2_050,
        "legacy price is frozen pre-activation"
    );
    assert_eq!(
        gas_for(&header, true),
        2_000 + 50 * 1024,
        "O(n*dim) work priced as such"
    );
    let mut one = Vec::new();
    one.extend_from_slice(&1u32.to_be_bytes());
    one.extend_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        gas_for(&one, true),
        gas_for(&one, false),
        "n=1 costs the same as before"
    );
}

#[test]
fn pba_l1a_025_belnap_charges_the_hardened_price() {
    use citrate_execution::precompiles::q16::belnap::{execute_at, gas_for};
    let mut header = Vec::new();
    header.extend_from_slice(&1u32.to_be_bytes()); // dim = 1
    header.extend_from_slice(&1024u32.to_be_bytes()); // n = 1024
    let need = gas_for(&header, true);
    // One unit short of the hardened price is out of gas even though it is
    // far above the legacy price; the exact price passes the gas check
    // (the truncated body then fails decoding, which is not a gas error).
    let short = execute_at(&header, need - 1, true).expect_err("must be out of gas");
    assert!(short.to_string().contains("insufficient gas"), "{short}");
    let below_base = execute_at(&header, 1_999, true).expect_err("below base");
    assert!(
        below_base.to_string().contains("insufficient gas"),
        "{below_base}"
    );
    let exact = execute_at(&header, need, true).expect_err("truncated body");
    assert!(!exact.to_string().contains("insufficient gas"), "{exact}");
    // dim = 0: the price is exactly GAS_BASE, which must be enough.
    let at_base = execute_at(&[0u8; 8], 2_000, true);
    if let Err(e) = at_base {
        assert!(!e.to_string().contains("insufficient gas"), "{e}");
    }
    let legacy_ok = execute_at(&header, 2_050, false).expect_err("truncated body");
    assert!(
        !legacy_ok.to_string().contains("insufficient gas"),
        "{legacy_ok}"
    );
}

/// The REVM bridge switches exactly at the activation height: H-1 legacy,
/// H and H+1 hardened.
#[test]
fn activation_boundary_is_exact_in_the_revm_bridge() {
    activate();
    let reserved = short(0x0104);
    let (_, ok) = staticcall_at(reserved, vec![0xAB; 4], ACTIVATION - 1);
    assert_eq!(ok[31], 1, "H-1: legacy");
    let (_, ok) = staticcall_at(reserved, vec![0xAB; 4], ACTIVATION);
    assert_eq!(ok[31], 0, "H: hardened");
    let (_, ok) = staticcall_at(reserved, vec![0xAB; 4], ACTIVATION + 1);
    assert_eq!(ok[31], 0, "H+1: hardened");
}

/// 0x0130 through the REVM bridge: below the activation height the call
/// halts exactly as on the verifier-absent fleet build (same result, same
/// gas); from the height on the gated behaviour applies.
#[test]
fn fold_verify_gated_at_activation_in_the_revm_bridge() {
    activate();
    let mut call = vec![0u8; 4];
    for v in [128usize, 1, 0, 160] {
        let mut x = [0u8; 32];
        x[24..].copy_from_slice(&(v as u64).to_be_bytes());
        call.extend_from_slice(&x);
    }
    call.extend_from_slice(&[0u8; 64]);
    // Legacy (verifier-absent) semantics: every call is a precompile error,
    // which halts the frame and consumes its forwarded gas. A call the
    // verifier also rejects (empty proof) is therefore the same halt, so the
    // H-1 call must equal the H call in result AND gas, and equal any
    // earlier height.
    let (ret_wf, ok_wf, gas_wf) = staticcall_gas_at(short(0x0130), call.clone(), ACTIVATION - 1);
    let (ret_old, ok_old, gas_old) = staticcall_gas_at(short(0x0130), call.clone(), BEFORE);
    let (ret_h, ok_h, gas_h) = staticcall_gas_at(short(0x0130), call.clone(), ACTIVATION);
    assert_eq!(ok_wf[31], 0, "H-1: the legacy build rejects every call");
    assert_eq!((ret_wf, ok_wf, gas_wf), (ret_old, ok_old, gas_old));
    assert_eq!(
        (ret_wf, ok_wf, gas_wf),
        (ret_h, ok_h, gas_h),
        "a rejected call halts identically on both sides of H"
    );
    let direct =
        citrate_execution::precompiles::commd_fold_verify::execute_at(&call, 30_000_000, false)
            .expect_err("legacy")
            .to_string();
    assert!(
        direct.contains("requires the `commd-fold-verify` feature"),
        "{direct}"
    );
    let gated =
        citrate_execution::precompiles::commd_fold_verify::execute_at(&call, 30_000_000, true);
    if citrate_execution::build_features::COMMD_FOLD_VERIFY {
        let e = gated.expect_err("empty proof").to_string();
        assert!(
            !e.contains("requires the `commd-fold-verify` feature"),
            "{e}"
        );
    }
}
