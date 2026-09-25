// PBA-L1a-006 (MEDIUM; root-cause sibling of PBA-L1b-002) regression — from
// the audit PoC `lanes/L1a-chain-execution-rpc/evidence/l1a_mempool_poc.rs::
// pba_l1a_010_wire_hash_squats_victim`.
//
// `tx.hash` was trusted from the wire. An attacker's own validly signed tx
// carrying the VICTIM's hash occupied the dedup slot, so the victim's real tx
// was rejected as `DuplicateTransaction` (targeted censorship), and if mined it
// overwrote the victim's stored tx/receipt keyed by that hash.
//
// Fix: the mempool replaces every authenticated tx's `hash` with the canonical
// id derived from its signed contents (`tx_auth::authenticate`) before dedup;
// after activation, import rejects a tx whose hash is not canonical.

use citrate_consensus::crypto::{sign_transaction, Ed25519SigningKey};
use citrate_consensus::tx_auth;
use citrate_consensus::types::{Hash, PublicKey, Transaction};
use citrate_sequencer::mempool::{Mempool, MempoolConfig, TxClass};

fn signed(seed: u8, nonce: u64, hash_byte: u8) -> Transaction {
    let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let mut tx = Transaction {
        hash: Hash::new([hash_byte; 32]),
        nonce,
        to: Some(PublicKey::new([9u8; 32])),
        value: 0,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        data: vec![],
        chain_id: Some(40204),
        ..Default::default()
    };
    sign_transaction(&mut tx, &sk).unwrap();
    tx
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pba_l1a_006_wire_hash_cannot_squat_a_victim() {
    let mp = Mempool::new(MempoolConfig::default());
    let victim = signed(1, 0, 0x42);
    let attacker = signed(2, 0, 0x42); // different sender, same claimed hash
    assert_ne!(victim.from, attacker.from);
    mp.add_transaction(attacker.clone(), TxClass::Standard)
        .await
        .expect("attacker admitted");
    let r = mp.add_transaction(victim.clone(), TxClass::Standard).await;
    assert!(
        r.is_ok(),
        "PBA-L1a-006: the victim's tx must not be squatted by a claimed hash, got {r:?}"
    );

    // Both are stored under their canonical ids, never the claimed one.
    let vid = tx_auth::authenticate(&victim).unwrap();
    let aid = tx_auth::authenticate(&attacker).unwrap();
    assert_ne!(vid, aid);
    assert!(mp.contains(&vid).await && mp.contains(&aid).await);
    assert!(!mp.contains(&Hash::new([0x42; 32])).await);
    assert_eq!(mp.get_transaction(&vid).await.unwrap().hash, vid);
}

/// Re-submitting the same signed content under a different claimed hash is a
/// duplicate (dedup is by content id, not by the claim).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pba_l1a_006_same_content_different_claimed_hash_is_duplicate() {
    let mp = Mempool::new(MempoolConfig::default());
    mp.add_transaction(signed(3, 0, 0x01), TxClass::Standard)
        .await
        .unwrap();
    assert!(mp
        .add_transaction(signed(3, 0, 0x02), TxClass::Standard)
        .await
        .is_err());
}
