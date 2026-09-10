// Audit finding M-SEQ-01 regression: pre-fix the mempool accepted
// any nonce from a funded sender, even a sparse set like
// (1, 1_000_000, u64::MAX). Each consumed a slot; only the
// consecutive-from-min nonces actually got included in blocks, so
// the rest rotted as gap-junk for an hour (the expiry) while
// filling the global cap.
//
// Fix (WP-C4.1): admission rejects `tx.nonce > min_existing +
// max_nonce_gap` (default 16, matching Geth's `txpool.accountqueue`).

use citrate_consensus::types::{PublicKey, Signature, Transaction};
use citrate_sequencer::mempool::{Mempool, MempoolConfig, MempoolError, TxClass};

fn permissive_config() -> MempoolConfig {
    MempoolConfig {
        require_valid_signature: false,
        min_gas_price: 0,
        chain_id: 40204,
        ..Default::default()
    }
}

fn signed_tx(sender: PublicKey, nonce: u64) -> Transaction {
    Transaction {
        hash: {
            // Make hash unique per nonce so DuplicateTransaction
            // doesn't collide.
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&nonce.to_le_bytes());
            citrate_consensus::types::Hash::new(h)
        },
        nonce,
        from: sender,
        to: Some(PublicKey::new([0xCC; 32])),
        value: 1,
        gas_limit: 21000,
        gas_price: 1_000_000_000,
        data: vec![],
        // WP-E1: non-zero dummy sig — these tests exercise nonce-gap admission, not
        // signatures, and must not rely on the (now removed) devnet zero-sig leniency.
        signature: Signature::new([1u8; 64]),
        tx_type: None,
        chain_id: Some(40204),
        ..Default::default()
    }
}

/// M-SEQ-01.1: a tx with nonce within the gap (≤16 above min) is admitted.
#[tokio::test]
async fn m_seq_01_within_gap_admitted() {
    let mempool = Mempool::new(permissive_config());
    let sender = PublicKey::new([0xAB; 32]);

    mempool
        .add_transaction(signed_tx(sender, 0), TxClass::Standard)
        .await
        .expect("nonce 0 admitted");

    // gap = 16: tx.nonce=16, min_existing=0 → gap=16 ≤ 16. Allowed.
    mempool
        .add_transaction(signed_tx(sender, 16), TxClass::Standard)
        .await
        .expect("nonce within gap admitted");
}

/// M-SEQ-01.2: a tx with nonce beyond the gap is rejected.
#[tokio::test]
async fn m_seq_01_beyond_gap_rejected() {
    let mempool = Mempool::new(permissive_config());
    let sender = PublicKey::new([0xAB; 32]);

    mempool
        .add_transaction(signed_tx(sender, 0), TxClass::Standard)
        .await
        .expect("nonce 0 admitted");

    // gap = 17: rejected.
    let result = mempool
        .add_transaction(signed_tx(sender, 17), TxClass::Standard)
        .await;
    assert!(
        matches!(result, Err(MempoolError::DuplicateNonce { .. })),
        "M-SEQ-01: nonce gap > 16 must be rejected; got {:?}",
        result
    );

    // u64::MAX gap: also rejected.
    let result = mempool
        .add_transaction(signed_tx(sender, u64::MAX), TxClass::Standard)
        .await;
    assert!(
        matches!(result, Err(MempoolError::DuplicateNonce { .. })),
        "M-SEQ-01: u64::MAX nonce must be rejected"
    );
}

/// M-SEQ-01.3: pre-fix the attacker could fill 100 slots with
/// arbitrary-spaced nonces. Post-fix only contiguous-or-near
/// nonces fit; the attacker's 99 gap-junk slots are denied.
#[tokio::test]
async fn m_seq_01_attacker_cannot_fill_with_gap_junk() {
    let mempool = Mempool::new(permissive_config());
    let sender = PublicKey::new([0xCA; 32]);

    mempool
        .add_transaction(signed_tx(sender, 0), TxClass::Standard)
        .await
        .expect("nonce 0");

    // Try to insert 99 attacker-spaced nonces (1_000_000, 2_000_000, …).
    // ALL must be rejected.
    let mut attacker_inserts = 0;
    for i in 1..=99u64 {
        let result = mempool
            .add_transaction(signed_tx(sender, 1_000_000 * i), TxClass::Standard)
            .await;
        if result.is_ok() {
            attacker_inserts += 1;
        }
    }
    assert_eq!(
        attacker_inserts, 0,
        "M-SEQ-01: ALL gap-junk inserts must be rejected; got {} accepted",
        attacker_inserts
    );
}

/// M-SEQ-01.4: the gap window is configurable via MempoolConfig.
/// Setting it to 0 means strictly-consecutive nonces only.
#[tokio::test]
async fn m_seq_01_zero_gap_means_strictly_consecutive() {
    let mut cfg = permissive_config();
    cfg.max_nonce_gap = 0;
    let mempool = Mempool::new(cfg);
    let sender = PublicKey::new([0xCA; 32]);

    mempool
        .add_transaction(signed_tx(sender, 0), TxClass::Standard)
        .await
        .expect("nonce 0");

    // gap = 1, but cap is 0 → reject.
    let result = mempool
        .add_transaction(signed_tx(sender, 1), TxClass::Standard)
        .await;
    assert!(result.is_err(), "M-SEQ-01: zero-gap config rejects nonce+1");
}
