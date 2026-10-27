//! Pins the executor's import-time `tx_root` check (`Executor::apply_block`,
//! the follower path) on its own.
//!
//! Every transaction in these blocks is validly signed, carries its canonical
//! id and is bound to this chain, so the per-transaction checks pass and only
//! the root check can refuse the block. The existing import tests all use
//! bodies that the signature check already refuses, so they stayed green with
//! the root check removed.

use citrate_consensus::crypto;
use citrate_consensus::hardening::PbaHardening;
use citrate_consensus::tx_auth::{native_tx_id, tx_root_for_height};
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Transaction, VrfProof};
use citrate_execution::{address_utils, Executor, StateDB};
use primitive_types::U256;
use std::collections::HashMap;
use std::sync::Arc;

const PAYEE: [u8; 20] = [0xBB; 20];
const COINBASE: [u8; 20] = [0x77; 20];
const CHAIN: u64 = 40204;

fn embedded(addr: [u8; 20]) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&addr);
    PublicKey::new(b)
}

fn funds() -> U256 {
    U256::from(1_000_000_000_000_000_000_000u128)
}

fn signed_transfer(sk: &crypto::Ed25519SigningKey, nonce: u64, value: u128) -> Transaction {
    let mut tx = Transaction {
        nonce,
        to: Some(embedded(PAYEE)),
        value,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(CHAIN),
        ..Default::default()
    };
    crypto::sign_transaction_v2(&mut tx, sk).unwrap();
    tx.hash = native_tx_id(&tx);
    tx
}

fn block_with_root(txs: Vec<Transaction>, state_root: Hash, tx_root: Hash) -> Block {
    let mut b = BlockBuilder::new()
        .version(2)
        .height(1)
        .parent(Hash::default())
        .coinbase(COINBASE)
        .timestamp(1_700_000_000)
        .vrf_reveal(VrfProof {
            proof: vec![1],
            output: Hash::new([0x5A; 32]),
        })
        .transactions(txs)
        .state_root(state_root)
        .build_unhashed();
    b.tx_root = tx_root;
    b.header.block_hash = b.compute_hash();
    b
}

/// Execute `txs` on a fresh producer and return the resulting state root, so
/// the block's `state_root` is the honest one.
async fn honest_state_root(sender: PublicKey, txs: &[Transaction]) -> Hash {
    let producer = Executor::new(Arc::new(StateDB::new()));
    producer.set_pba_hardening(PbaHardening::off());
    producer.set_balance(&address_utils::normalize_address(&sender), funds());
    let template = block_with_root(txs.to_vec(), Hash::default(), Hash::default());
    producer.set_block_context(citrate_execution::revm_adapter::BlockContext {
        coinbase: COINBASE,
        prevrandao: *template.header.vrf_reveal.output.as_bytes(),
        block_hashes: HashMap::new(),
    });
    let mut receipts = Vec::new();
    for tx in &template.transactions {
        receipts.push(producer.execute_transaction(&template, tx).await.unwrap());
    }
    producer
        .settle_block_rewards(
            1,
            COINBASE,
            *template.header.proposer_pubkey.as_bytes(),
            template.header.base_fee_per_gas,
            &template.transactions,
            &receipts,
            &[],
        )
        .await
        .unwrap();
    producer.calculate_state_root()
}

fn follower(sender: PublicKey) -> Executor {
    let f = Executor::with_chain_id(Arc::new(StateDB::new()), CHAIN);
    f.set_pba_hardening(PbaHardening::at(0));
    f.set_balance(&address_utils::normalize_address(&sender), funds());
    f
}

fn payee_balance(f: &Executor) -> U256 {
    f.get_balance(&address_utils::normalize_address(&embedded(PAYEE)))
}

fn setup() -> (crypto::Ed25519SigningKey, PublicKey, Vec<Transaction>) {
    let sk = crypto::Ed25519SigningKey::from_bytes(&[0x21; 32]);
    let sender = PublicKey::new(sk.verifying_key().to_bytes());
    let txs = vec![signed_transfer(&sk, 0, 5), signed_transfer(&sk, 1, 7)];
    (sk, sender, txs)
}

/// Control: the content-bound root applies.
#[tokio::test]
async fn content_bound_root_applies() {
    let (_sk, sender, txs) = setup();
    let state_root = honest_state_root(sender, &txs).await;
    let root = tx_root_for_height(PbaHardening::at(0), 1, &txs);
    let block = block_with_root(txs, state_root, root);
    let f = follower(sender);
    f.apply_block(&block, COINBASE, &[])
        .await
        .expect("honest block applies");
    assert_eq!(payee_balance(&f), U256::from(12u64));
}

/// The pre-activation root (it commits to the `hash` fields, not the bodies)
/// is not accepted once the rule is active.
#[tokio::test]
async fn legacy_root_is_refused_after_activation() {
    let (_sk, sender, txs) = setup();
    let state_root = honest_state_root(sender, &txs).await;
    let legacy = tx_root_for_height(PbaHardening::off(), 1, &txs);
    assert_ne!(legacy, tx_root_for_height(PbaHardening::at(0), 1, &txs));
    let block = block_with_root(txs, state_root, legacy);
    let f = follower(sender);
    let r = f.apply_block(&block, COINBASE, &[]).await;
    assert!(
        r.is_err(),
        "a block whose tx_root is not content-bound must be refused, got {r:?}"
    );
    assert_eq!(
        payee_balance(&f),
        U256::zero(),
        "nothing from the refused block is applied"
    );
}

/// A root computed over a different (reordered) body is refused even though
/// every transaction in the delivered body is valid on its own.
#[tokio::test]
async fn root_of_another_body_is_refused() {
    let (_sk, sender, txs) = setup();
    let state_root = honest_state_root(sender, &txs).await;
    let mut other = txs.clone();
    other.reverse();
    let wrong = tx_root_for_height(PbaHardening::at(0), 1, &other);
    let block = block_with_root(txs, state_root, wrong);
    let f = follower(sender);
    let r = f.apply_block(&block, COINBASE, &[]).await;
    assert!(
        r.is_err(),
        "a root over a different body must be refused, got {r:?}"
    );
    assert_eq!(payee_balance(&f), U256::zero());
}
