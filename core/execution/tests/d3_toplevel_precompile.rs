// citrate/core/execution/tests/d3_toplevel_precompile.rs
//
// D3 (reroll): a top-level transaction or `eth_call` whose `to` is a
// precompile address runs the precompile.
//
// Before D3 the executor only knew the native 0x1000/0x1002/0x1003 handlers.
// Any other precompile address has no code, so a top-level call to it found
// nothing to run and returned `0x`, while contract code calling the same
// address through REVM got the real result. These tests drive the production
// entry points (`Executor::execute_transaction` and
// `Executor::simulate_transaction`, the `eth_call` path) and check that:
//   * standard precompiles (ecrecover 0x01, sha256 0x02, identity 0x04) and a
//     Citrate one (ed25519 verify 0x0120) return their real output;
//   * the precompile's gas is charged on top of the plain-call cost;
//   * reserved (unbridged) Citrate addresses fail the call, as they do for
//     contract code;
//   * before the hardening activation the legacy `0x` behaviour is unchanged;
//   * two executions of the same transactions give the same state root.
//
// The hardening activation is process-global; this file is its own test
// binary and every test sets the SAME height (0, as 40204 pins it on the
// reroll). Genesis (height 0) is never judged active, so blocks at height 0
// exercise the pre-activation path.

use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction as ConsensusTransaction, VrfProof,
};
use citrate_execution::activation::set_pba_hardening_height;
use citrate_execution::revm_adapter::is_revm_precompile_at;
use citrate_execution::{address_utils, types::*, Executor, StateDB};
use ed25519_dalek::{Signer, SigningKey as EdSigningKey};
use k256::ecdsa::SigningKey;
use primitive_types::U256;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::sync::Arc;

const GAS_LIMIT: u64 = 1_000_000;

fn activate() {
    set_pba_hardening_height(Some(0));
}

fn short(a: u16) -> Address {
    let mut out = [0u8; 20];
    out[18] = (a >> 8) as u8;
    out[19] = (a & 0xff) as u8;
    Address(out)
}

/// A 32-byte public key embedding a 20-byte EVM address (last 12 bytes zero),
/// which `normalize_address` maps back to that address.
fn embed(addr: Address) -> PublicKey {
    let mut pk = [0u8; 32];
    pk[..20].copy_from_slice(&addr.0);
    PublicKey::new(pk)
}

fn sender_pk() -> PublicKey {
    let mut pk = [0u8; 32];
    pk[0] = 0x5E;
    PublicKey::new(pk)
}

fn block_at(height: u64) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([0xD3; 32]))
        .height(height)
        .timestamp(1_700_000_000)
        .blue_score(10)
        .blue_work(1000)
        .vrf_reveal(VrfProof {
            proof: vec![0u8; 80],
            output: Hash::default(),
        })
        .build_unhashed()
}

fn call_tx(to: Address, data: Vec<u8>, value: u128, nonce: u64) -> ConsensusTransaction {
    let mut h = [0u8; 32];
    h[0] = nonce as u8;
    h[1..21].copy_from_slice(&to.0);
    h[21] = data.len() as u8;
    h[31] = 0xD3;
    ConsensusTransaction {
        hash: Hash::new(h),
        nonce,
        from: sender_pk(),
        to: Some(embed(to)),
        value,
        gas_limit: GAS_LIMIT,
        gas_price: 1,
        data,
        signature: Signature::new([0u8; 64]),
        tx_type: None,
        ..Default::default()
    }
}

fn funded_executor() -> Executor {
    let executor = Executor::new(Arc::new(StateDB::new()));
    let sender = address_utils::normalize_address(&sender_pk());
    executor.set_balance(&sender, U256::from(10u64).pow(U256::from(24u64)));
    executor
}

async fn send(executor: &Executor, block: &Block, tx: &ConsensusTransaction) -> TransactionReceipt {
    executor
        .execute_transaction(block, tx)
        .await
        .expect("transaction executes")
}

async fn eth_call(block: &Block, to: Address, data: Vec<u8>) -> TransactionReceipt {
    funded_executor()
        .simulate_transaction(block, &call_tx(to, data, 0, 0))
        .await
        .expect("eth_call executes")
}

/// An address that is neither a contract nor a precompile: the plain-call
/// gas baseline a precompile call must exceed.
fn plain_account() -> Address {
    Address([0x77; 20])
}

fn ecrecover_input() -> (Vec<u8>, [u8; 20]) {
    let key = SigningKey::from_slice(&[0x42u8; 32]).expect("valid scalar");
    let digest: [u8; 32] = Keccak256::digest(b"D3 top-level ecrecover").into();
    let (sig, rec) = key.sign_prehash_recoverable(&digest).expect("signs");
    let point = key.verifying_key().to_encoded_point(false);
    let pub_hash: [u8; 32] = Keccak256::digest(&point.as_bytes()[1..]).into();
    let mut signer = [0u8; 20];
    signer.copy_from_slice(&pub_hash[12..]);

    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(&digest);
    let mut v = [0u8; 32];
    v[31] = 27 + rec.to_byte();
    input.extend_from_slice(&v);
    input.extend_from_slice(&sig.to_bytes());
    (input, signer)
}

fn ed25519_input() -> Vec<u8> {
    let key = EdSigningKey::from_bytes(&[0x24u8; 32]);
    let msg = b"D3 top-level ed25519";
    let sig = key.sign(msg);
    let mut input = Vec::new();
    input.extend_from_slice(key.verifying_key().as_bytes());
    input.extend_from_slice(&sig.to_bytes());
    input.extend_from_slice(msg);
    input
}

#[test]
fn registered_set_matches_revm() {
    activate();
    for a in 0x01..=0x09u16 {
        assert!(is_revm_precompile_at(&short(a), 1), "0x{a:04x}");
    }
    assert!(is_revm_precompile_at(&short(0x0107), 1));
    assert!(is_revm_precompile_at(&short(0x0120), 1));
    // Reserved Citrate addresses are registered (always-failing) once hardened.
    assert!(is_revm_precompile_at(&short(0x0100), 1));
    // 0x0a (KZG point evaluation) needs revm's `c-kzg` feature, which no
    // validator build enables; pinned so enabling it is a deliberate change.
    assert!(!is_revm_precompile_at(&short(0x0a), 1));
    assert!(!is_revm_precompile_at(&short(0x0b), 1));
    assert!(!is_revm_precompile_at(&plain_account(), 1));
    // Genesis is never judged hardened: reserved addresses are not registered.
    assert!(!is_revm_precompile_at(&short(0x0100), 0));
}

#[tokio::test]
async fn eth_call_runs_standard_precompiles() {
    activate();
    let block = block_at(1);

    let (input, signer) = ecrecover_input();
    let r = eth_call(&block, short(0x01), input).await;
    assert!(r.status, "{:?}", r.revert_reason);
    let mut want = [0u8; 32];
    want[12..].copy_from_slice(&signer);
    assert_eq!(r.output, want.to_vec(), "ecrecover returns the signer");

    let r = eth_call(&block, short(0x02), b"abc".to_vec()).await;
    assert!(r.status);
    assert_eq!(r.output, Sha256::digest(b"abc").to_vec());

    let r = eth_call(&block, short(0x04), b"citrate identity".to_vec()).await;
    assert!(r.status);
    assert_eq!(r.output, b"citrate identity".to_vec());
}

#[tokio::test]
async fn eth_call_runs_citrate_precompile() {
    activate();
    let block = block_at(1);
    let r = eth_call(&block, short(0x0120), ed25519_input()).await;
    assert!(r.status, "{:?}", r.revert_reason);
    let mut want = [0u8; 32];
    want[31] = 1;
    assert_eq!(r.output, want.to_vec(), "valid ed25519 signature verifies");

    // A corrupted signature still runs the precompile and returns false.
    let mut bad = ed25519_input();
    bad[40] ^= 0xff;
    let r = eth_call(&block, short(0x0120), bad).await;
    assert!(r.status);
    assert_eq!(r.output, [0u8; 32].to_vec());
}

#[tokio::test]
async fn transactions_run_precompiles_and_charge_gas() {
    activate();
    let block = block_at(1);
    let executor = funded_executor();
    let data = vec![0xAB; 64];

    let base = send(
        &executor,
        &block,
        &call_tx(plain_account(), data.clone(), 0, 0),
    )
    .await;
    assert!(base.status);
    assert!(base.output.is_empty());

    let sha = send(&executor, &block, &call_tx(short(0x02), data.clone(), 0, 1)).await;
    assert!(sha.status, "{:?}", sha.revert_reason);
    assert_eq!(sha.output, Sha256::digest(&data).to_vec());
    // SHA256 costs 60 + 12 per word: 84 gas for 64 bytes.
    assert!(
        sha.gas_used >= base.gas_used + 84,
        "precompile gas charged: {} vs base {}",
        sha.gas_used,
        base.gas_used
    );

    let id = send(&executor, &block, &call_tx(short(0x04), data.clone(), 0, 2)).await;
    assert!(id.status);
    assert_eq!(id.output, data);
    assert!(id.gas_used > base.gas_used, "identity gas charged");

    let ed = send(
        &executor,
        &block,
        &call_tx(short(0x0120), ed25519_input(), 0, 3),
    )
    .await;
    assert!(ed.status, "{:?}", ed.revert_reason);
    assert_eq!(ed.output.last(), Some(&1u8));
    assert!(
        ed.gas_used >= 2_000,
        "ed25519 flat gas charged: {}",
        ed.gas_used
    );
}

#[tokio::test]
async fn reserved_citrate_address_fails_like_contract_calls() {
    activate();
    let r = eth_call(&block_at(1), short(0x0114), vec![1, 2, 3]).await;
    assert!(!r.status, "reserved address must fail the call");
}

#[tokio::test]
async fn before_activation_legacy_behaviour_is_unchanged() {
    activate();
    // Height 0 is never judged hardened: the pre-D3 path, `0x` and success.
    let r = eth_call(&block_at(0), short(0x02), b"abc".to_vec()).await;
    assert!(r.status);
    assert!(r.output.is_empty());
}

#[tokio::test]
async fn state_root_is_deterministic() {
    activate();
    let block = block_at(1);
    let (ec_input, _) = ecrecover_input();
    let txs = vec![
        call_tx(short(0x01), ec_input, 0, 0),
        call_tx(short(0x02), b"root".to_vec(), 5, 1),
        call_tx(short(0x04), vec![9; 40], 0, 2),
        call_tx(short(0x0120), ed25519_input(), 0, 3),
        call_tx(short(0x0114), vec![1], 0, 4),
    ];

    let mut roots = Vec::new();
    for _ in 0..2 {
        let executor = funded_executor();
        for tx in &txs {
            let _ = executor.execute_transaction(&block, tx).await;
        }
        roots.push(executor.calculate_state_root());
    }
    assert_eq!(roots[0], roots[1]);
}
