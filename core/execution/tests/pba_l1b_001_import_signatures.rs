// PBA-L1b-001 (CRITICAL) regression — from the audit PoC
// `lanes/L1b-chain-consensus-p2p/evidence/pba_l1b_poc.rs::poc_001_*`.
//
// Block import executed transactions without verifying their signatures, and
// `ecdsa_verified` arrived as a deserialized wire field. Any admitted proposer
// (anyone, with registry gating off by default) could include a transaction
// "from" any account and drain it: the PoC moved a victim's 1000 SALT to the
// thief through an honest follower's `apply_block`.
//
// Fix (behind the PBA-R2 activation height): `Executor::apply_block_inner`
// requires every transaction to authenticate from its contents
// (`tx_auth::authenticate`, never the wire flag), to carry its canonical id as
// `hash`, and to be bound to this chain's id — before any state is touched.

use citrate_consensus::crypto;
use citrate_consensus::hardening::PbaHardening;
use citrate_consensus::tx_auth::{native_tx_id, tx_root_for_height};
use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_execution::{address_utils, Executor, StateDB};
use primitive_types::U256;
use std::collections::HashMap;
use std::sync::Arc;

const VICTIM: [u8; 20] = [0xAA; 20];
const THIEF: [u8; 20] = [0xBB; 20];
const COINBASE: [u8; 20] = [0x77; 20];
const CHAIN: u64 = 40204;

fn embedded(addr: [u8; 20]) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&addr);
    PublicKey::new(b)
}

fn funds() -> U256 {
    U256::from(1_000_000_000_000_000_000_000u128) // 1000 SALT
}

/// The PoC's forged transfer: `from = VICTIM`, zero signature, never signed.
fn forged_transfer(value: u128) -> Transaction {
    Transaction {
        hash: Hash::new([0x42; 32]),
        nonce: 0,
        from: embedded(VICTIM),
        to: Some(embedded(THIEF)),
        value,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        signature: Signature::new([0u8; 64]),
        chain_id: Some(CHAIN),
        // As it would arrive deserialized off the wire, flag set by the attacker.
        ecdsa_verified: true,
        ..Default::default()
    }
}

fn native_signed(
    sk: &crypto::Ed25519SigningKey,
    to: [u8; 20],
    value: u128,
    chain: u64,
) -> Transaction {
    let mut tx = Transaction {
        nonce: 0,
        to: Some(embedded(to)),
        value,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(chain),
        ..Default::default()
    };
    // From the activation height native signatures use the chain-bound digest.
    crypto::sign_transaction_v2(&mut tx, sk).unwrap();
    tx.hash = native_tx_id(&tx);
    tx
}

/// Recipient for the tests below.
const PAYEE: [u8; 20] = [0xBB; 20];

/// A native transfer signed with the legacy (V1) digest for `signed_chain`,
/// then labelled with this chain's id.
fn native_v1_for_chain(
    sk: &crypto::Ed25519SigningKey,
    to: [u8; 20],
    value: u128,
    signed_chain: u64,
) -> Transaction {
    let mut tx = Transaction {
        nonce: 0,
        to: Some(embedded(to)),
        value,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(signed_chain),
        ..Default::default()
    };
    crypto::sign_transaction(&mut tx, sk).unwrap();
    tx.chain_id = Some(CHAIN);
    tx.hash = native_tx_id(&tx);
    tx
}

fn build_block(hardening: PbaHardening, txs: Vec<Transaction>, state_root: Hash) -> Block {
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
    b.tx_root = tx_root_for_height(hardening, 1, &b.transactions);
    b.header.block_hash = b.compute_hash();
    b
}

/// The attacker-proposer seals a state root consistent with its own execution
/// (exactly as in the PoC), so only the missing signature check stands between
/// the block and the follower's state.
async fn seal(hardening: PbaHardening, fund: &[(PublicKey, U256)], txs: Vec<Transaction>) -> Block {
    let producer = Executor::new(Arc::new(StateDB::new()));
    producer.set_pba_hardening(PbaHardening::off()); // the attacker's own node checks nothing
    for (pk, v) in fund {
        producer.set_balance(&address_utils::normalize_address(pk), *v);
    }
    let template = build_block(hardening, txs.clone(), Hash::default());
    producer.set_block_context(citrate_execution::revm_adapter::BlockContext {
        coinbase: COINBASE,
        prevrandao: *template.header.vrf_reveal.output.as_bytes(),
        block_hashes: HashMap::new(),
    });
    let mut receipts = Vec::new();
    for tx in &template.transactions {
        receipts.push(
            producer
                .execute_transaction(&template, tx)
                .await
                .expect("executes"),
        );
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
        .expect("settle");
    build_block(hardening, txs, producer.calculate_state_root())
}

fn follower(hardening: PbaHardening, fund: &[(PublicKey, U256)]) -> Executor {
    let f = Executor::with_chain_id(Arc::new(StateDB::new()), CHAIN);
    f.set_pba_hardening(hardening);
    for (pk, v) in fund {
        f.set_balance(&address_utils::normalize_address(pk), *v);
    }
    f
}

#[tokio::test]
async fn pba_l1b_001_forged_sender_block_rejected_after_activation() {
    let pba = PbaHardening::at(0);
    let fund = [(embedded(VICTIM), funds())];
    let steal = funds() - U256::from(21_000u64 * 1_000_000_000u64);
    let block = seal(pba, &fund, vec![forged_transfer(steal.as_u128())]).await;

    let f = follower(pba, &fund);
    let r = f.apply_block(&block, COINBASE, &[]).await;
    assert!(
        r.is_err(),
        "PBA-L1b-001: a block with a forged-sender tx must be rejected on import, got {r:?}"
    );
    assert_eq!(
        f.get_balance(&address_utils::normalize_address(&embedded(VICTIM))),
        funds()
    );
    assert_eq!(
        f.get_balance(&address_utils::normalize_address(&embedded(THIEF))),
        U256::zero()
    );
}

/// Below the activation height legacy validity is unchanged (documented
/// residual until the owner schedules activation on 40204).
#[tokio::test]
async fn pba_l1b_001_before_activation_legacy_import_is_unchanged() {
    let pba = PbaHardening::at(1_000);
    let fund = [(embedded(VICTIM), funds())];
    let block = seal(pba, &fund, vec![forged_transfer(1_000)]).await;
    let f = follower(pba, &fund);
    f.apply_block(&block, COINBASE, &[])
        .await
        .expect("pre-activation: legacy rule");
}

#[tokio::test]
async fn pba_l1b_001_validly_signed_block_applies_after_activation() {
    let pba = PbaHardening::at(0);
    let sk = crypto::Ed25519SigningKey::from_bytes(&[0x11; 32]);
    let sender = PublicKey::new(sk.verifying_key().to_bytes());
    let fund = [(sender, funds())];
    let block = seal(pba, &fund, vec![native_signed(&sk, THIEF, 5, CHAIN)]).await;
    let f = follower(pba, &fund);
    f.apply_block(&block, COINBASE, &[])
        .await
        .expect("an honest signed block applies");
    assert_eq!(
        f.get_balance(&address_utils::normalize_address(&embedded(THIEF))),
        U256::from(5u64)
    );
}

/// A validly signed tx whose `hash` is not its canonical id (the PBA-L1a-006
/// receipt-overwrite shape) is rejected on import.
#[tokio::test]
async fn pba_l1b_001_non_canonical_hash_rejected_after_activation() {
    let pba = PbaHardening::at(0);
    let sk = crypto::Ed25519SigningKey::from_bytes(&[0x12; 32]);
    let sender = PublicKey::new(sk.verifying_key().to_bytes());
    let fund = [(sender, funds())];
    let mut tx = native_signed(&sk, THIEF, 5, CHAIN);
    tx.hash = Hash::new([0x42; 32]); // squats someone else's id
    let block = seal(pba, &fund, vec![tx]).await;
    assert!(follower(pba, &fund)
        .apply_block(&block, COINBASE, &[])
        .await
        .is_err());
}

/// A tx signed for another chain id is not replayable here.
#[tokio::test]
async fn pba_l1b_001_foreign_chain_id_rejected_after_activation() {
    let pba = PbaHardening::at(0);
    let sk = crypto::Ed25519SigningKey::from_bytes(&[0x13; 32]);
    let sender = PublicKey::new(sk.verifying_key().to_bytes());
    let fund = [(sender, funds())];
    let block = seal(pba, &fund, vec![native_signed(&sk, THIEF, 5, 1)]).await;
    assert!(follower(pba, &fund)
        .apply_block(&block, COINBASE, &[])
        .await
        .is_err());
}

/// Tripwire (class-level): the import gate runs first in the single apply
/// atom every import path shares (apply_block / apply_block_trusted /
/// apply_block_no_persist), before any state is snapshotted or touched.
#[test]
fn pba_l1b_001_tripwire_import_gate_precedes_state_mutation() {
    let src = include_str!("../src/executor.rs");
    let atom = src
        .find("async fn apply_block_inner(")
        .expect("apply_block_inner");
    let body = &src[atom..];
    let gate = body
        .find("self.verify_block_body(block)?")
        .expect("PBA-L1b-001: apply_block_inner must call verify_block_body (tx auth + tx_root)");
    let snap = body.find("self.state_db.snapshot()").expect("snapshot");
    let exec = body
        .find("self.execute_transaction(block, tx)")
        .expect("execute");
    assert!(
        gate < snap && gate < exec,
        "the import gate must run before any state work"
    );
    let vb = src
        .find("fn verify_block_body(")
        .expect("verify_block_body");
    assert!(
        src[vb..vb + 2_500].contains("tx_auth::verify_for_block(tx, self.chain_id)"),
        "verify_block_body must authenticate every tx with tx_auth::verify_for_block"
    );
}

/// A V1 native tx signed for another chain and labelled with this one applies
/// below the activation height (legacy validity) and is rejected from it.
#[tokio::test]
async fn v1_native_signed_for_another_chain_applies_below_h_rejected_from_h() {
    let sk = crypto::Ed25519SigningKey::from_bytes(&[0x14; 32]);
    let sender = PublicKey::new(sk.verifying_key().to_bytes());
    let fund = [(sender, funds())];
    let tx = native_v1_for_chain(&sk, PAYEE, 5, 1337);

    // Block height is 1: H = 2 is "below", H = 1 is "at".
    let below = PbaHardening::at(2);
    let block = seal(below, &fund, vec![tx.clone()]).await;
    follower(below, &fund)
        .apply_block(&block, COINBASE, &[])
        .await
        .expect("below H: legacy validity");

    let at = PbaHardening::at(1);
    let block = seal(at, &fund, vec![tx]).await;
    let f = follower(at, &fund);
    let r = f.apply_block(&block, COINBASE, &[]).await;
    assert!(
        matches!(r, Err(ref e) if e.to_string().contains("legacy digest")),
        "at H a V1 native signature is invalid, got {r:?}"
    );
    assert_eq!(
        f.get_balance(&address_utils::normalize_address(&embedded(PAYEE))),
        U256::zero()
    );
}

/// From H even a V1 tx genuinely signed for this chain is invalid; the same
/// transfer signed V2 applies.
#[tokio::test]
async fn v1_native_rejected_v2_applies_from_h() {
    let sk = crypto::Ed25519SigningKey::from_bytes(&[0x15; 32]);
    let sender = PublicKey::new(sk.verifying_key().to_bytes());
    let fund = [(sender, funds())];
    let pba = PbaHardening::at(1);
    let v1 = native_v1_for_chain(&sk, PAYEE, 5, CHAIN);
    let block = seal(pba, &fund, vec![v1]).await;
    assert!(follower(pba, &fund)
        .apply_block(&block, COINBASE, &[])
        .await
        .is_err());
    let block = seal(pba, &fund, vec![native_signed(&sk, PAYEE, 5, CHAIN)]).await;
    follower(pba, &fund)
        .apply_block(&block, COINBASE, &[])
        .await
        .expect("V2 applies at H");
}

/// A native tx "from" a small-order public key, with a signature made without the secret key
/// (R = identity, s = 0) passes non-strict ed25519 verification. From the
/// activation height the block rule verifies strictly and refuses it; below
/// it import is unchanged.
#[tokio::test]
async fn small_order_key_signature_rejected_from_h_applies_below_h() {
    use citrate_consensus::native_sig::{small_order_key_signature, NativeSigVersion};
    let template = Transaction {
        nonce: 0,
        to: Some(embedded(PAYEE)),
        value: 5,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(CHAIN),
        ..Default::default()
    };
    let tx = small_order_key_signature(&template, NativeSigVersion::V2).expect("found");
    let fund = [(tx.from, funds())];

    let at = PbaHardening::at(1);
    let block = seal(at, &fund, vec![tx.clone()]).await;
    let f = follower(at, &fund);
    assert!(f.apply_block(&block, COINBASE, &[]).await.is_err());
    assert_eq!(
        f.get_balance(&address_utils::normalize_address(&embedded(PAYEE))),
        U256::zero()
    );

    let below = PbaHardening::at(2);
    let block = seal(below, &fund, vec![tx]).await;
    follower(below, &fund)
        .apply_block(&block, COINBASE, &[])
        .await
        .expect("below H: legacy import unchanged");
}
