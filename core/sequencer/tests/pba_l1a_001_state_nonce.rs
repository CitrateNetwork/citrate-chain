// PBA-L1a-001 (CRITICAL) regression, state-nonce half — from the audit PoC
// `lanes/L1a-chain-execution-rpc/evidence/l1a_mempool_poc.rs::pba_l1a_009_*`.
//
// A validly signed tx from a brand-new key with `nonce = u64::MAX` was admitted
// under the DEFAULT MempoolConfig (signature checks ON; the per-sender gap check
// only runs when the sender already has pending txs), and the producer's
// selection path (`get_best_transactions`) then panicked on `nonce + 1`
// (`overflow-checks = true` in release). The producer task died silently; the
// tx reaches every miner over P2P gossip, so one packet halted the chain.
//
// Fix: admission rejects `nonce == u64::MAX` on every ingress, bounds the nonce
// against the sender's STATE nonce when a state reader is wired (the node wires
// it), and selection uses `checked_add`. The producer round is also supervised
// (node/src/producer.rs) so a panic can never again end block production.

use citrate_consensus::crypto::{sign_transaction, Ed25519SigningKey};
use citrate_consensus::types::{Hash, PublicKey, Transaction};
use citrate_sequencer::mempool::{Mempool, MempoolConfig, MempoolError, TxClass};
use std::sync::Arc;

fn signed(seed: u8, nonce: u64) -> Transaction {
    let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let mut tx = Transaction {
        hash: Hash::new([seed ^ (nonce as u8); 32]),
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

/// With the node's state reader wired, the nonce is bounded against the
/// sender's on-chain nonce even for a sender with nothing pending (the gap
/// check used to be skipped for new senders — SEQ-M10's root).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pba_l1a_001_state_nonce_bounds_new_sender() {
    let reader: citrate_sequencer::mempool::StateNonceReader = Arc::new(|_pk: &PublicKey| 5u64);
    let mp = Mempool::new(MempoolConfig::default()).with_state_nonce_reader(reader);

    // Stale (below the state nonce).
    let r = mp.add_transaction(signed(1, 4), TxClass::Standard).await;
    assert!(
        matches!(r, Err(MempoolError::NonceTooLow { expected: 5, got: 4 })),
        "stale nonce must be NonceTooLow, got {r:?}"
    );
    // Far future for a sender with nothing pending.
    let r = mp.add_transaction(signed(2, 5 + 17), TxClass::Standard).await;
    assert!(r.is_err(), "nonce beyond state+max_nonce_gap must be rejected, got {r:?}");
    // Exactly at the edges: state nonce and state + gap are admissible.
    mp.add_transaction(signed(3, 5), TxClass::Standard)
        .await
        .expect("nonce == state nonce is admissible");
    mp.add_transaction(signed(4, 5 + 16), TxClass::Standard)
        .await
        .expect("nonce == state nonce + max_nonce_gap is admissible");
}
