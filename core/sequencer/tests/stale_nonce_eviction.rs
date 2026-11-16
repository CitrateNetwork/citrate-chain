// The pool must not keep, or select from, a transaction whose nonce the
// sender's committed state has already used.
//
// r1007 devnet (baseline 56cc2bc8, 2026-11-04): tx 0xa712… (nonce 7) stayed in
// every producer's pool after block 2801 executed a DIFFERENT nonce-7 tx from
// the same sender. Selection started each sender at its lowest POOLED nonce, so
// the pool kept offering the spent nonce-7 tx (which the producer skips) and
// never offered the sender's valid next nonce. The stale copy left only on the
// 3,600 s expiry.

use citrate_consensus::crypto::{sign_transaction, Ed25519SigningKey};
use citrate_consensus::types::{Hash, PublicKey, Transaction};
use citrate_sequencer::mempool::{Mempool, MempoolConfig, StateNonceReader, TxClass};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const SEED: u8 = 0x31;

fn signed(nonce: u64, value: u128) -> Transaction {
    let sk = Ed25519SigningKey::from_bytes(&[SEED; 32]);
    let mut tx = Transaction {
        hash: Hash::new([nonce as u8; 32]),
        nonce,
        to: Some(PublicKey::new([9u8; 32])),
        value,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        data: vec![],
        chain_id: Some(40204),
        ..Default::default()
    };
    sign_transaction(&mut tx, &sk).expect("sign");
    tx
}

fn pool(state: Arc<AtomicU64>) -> Mempool {
    let reader: StateNonceReader = Arc::new(move |_pk: &PublicKey| state.load(Ordering::SeqCst));
    Mempool::new(MempoolConfig::default()).with_state_nonce_reader(reader)
}

async fn pooled_nonces(mp: &Mempool) -> Vec<(u64, u128)> {
    let mut v: Vec<(u64, u128)> = mp
        .get_transactions(usize::MAX)
        .await
        .iter()
        .map(|t| (t.nonce, t.value))
        .collect();
    v.sort();
    v
}

/// The sender's nonce 7 is spent by another tx in a block. The pooled nonce-7
/// tx can never execute: the pool drops it, and offers nonce 8.
#[tokio::test]
async fn pool_evicts_tx_whose_nonce_was_spent_by_another_tx() {
    let state = Arc::new(AtomicU64::new(7));
    let mp = pool(state.clone());
    mp.add_transaction(signed(7, 1), TxClass::Standard)
        .await
        .expect("nonce 7 admitted");
    mp.add_transaction(signed(8, 1), TxClass::Standard)
        .await
        .expect("nonce 8 admitted");

    // A block executes a different nonce-7 tx (value 2) from this sender.
    state.store(8, Ordering::SeqCst);

    let best = mp.get_best_transactions(usize::MAX, usize::MAX).await;
    let offered: Vec<u64> = best.iter().map(|t| t.nonce).collect();
    assert_eq!(offered, vec![8], "only the sender's next nonce is offered");
    assert_eq!(
        pooled_nonces(&mp).await,
        vec![(8, 1)],
        "the tx whose nonce is spent must leave the pool"
    );
}

/// The pool holds a spent nonce (7) and the sender's next valid nonce (9),
/// with nonce 8 executed elsewhere. Selection must start at the committed
/// nonce (9). Starting at the lowest pooled nonce offers only the spent tx,
/// and the sender is stuck until it expires.
#[tokio::test]
async fn selection_starts_at_the_committed_nonce_not_the_lowest_pooled() {
    let state = Arc::new(AtomicU64::new(7));
    let mp = pool(state.clone());
    mp.add_transaction(signed(7, 1), TxClass::Standard)
        .await
        .expect("nonce 7 admitted");
    mp.add_transaction(signed(9, 1), TxClass::Standard)
        .await
        .expect("nonce 9 admitted");

    // Blocks this pool's node did not build executed nonces 7 and 8.
    state.store(9, Ordering::SeqCst);

    let best = mp.get_best_transactions(usize::MAX, usize::MAX).await;
    let offered: Vec<u64> = best.iter().map(|t| t.nonce).collect();
    assert_eq!(
        offered,
        vec![9],
        "the valid nonce-9 tx must be offered (got {offered:?})"
    );
}
