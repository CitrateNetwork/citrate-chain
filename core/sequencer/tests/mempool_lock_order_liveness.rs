// Liveness under concurrent admission + block selection.
//
// `add_transaction` (with a balance reader wired, as the node does) and
// `get_best_transactions` must both make progress when many senders submit
// while the producer selects. Each call takes several of the pool's async
// RwLocks; if two paths take them in different orders, concurrent writers can
// park every task forever. This test drives that mix and fails if it does not
// finish within a generous deadline.

use std::sync::Arc;
use std::time::Duration;

use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use citrate_sequencer::mempool::{Mempool, MempoolConfig, TxClass};

const SENDERS: u8 = 128;
const NONCES_PER_SENDER: u64 = 16;

fn tx(sender: u8, nonce: u64) -> Transaction {
    let mut h = [0u8; 32];
    h[0] = sender;
    h[1..9].copy_from_slice(&nonce.to_le_bytes());
    let mut from = [0u8; 32];
    from[0] = sender;
    from[31] = 0x5A;
    Transaction {
        hash: Hash::new(h),
        nonce,
        from: PublicKey::new(from),
        to: Some(PublicKey::new([0xCC; 32])),
        value: 1,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        data: vec![],
        signature: Signature::new([1; 64]),
        chain_id: Some(40204),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_admission_and_selection_make_progress() {
    let pool = Arc::new(
        Mempool::new(MempoolConfig {
            require_valid_signature: false,
            min_gas_price: 0,
            chain_id: 40204,
            ..Default::default()
        })
        .with_state_balance_reader(Arc::new(|_: &PublicKey| u128::MAX)),
    );

    let work = {
        let pool = pool.clone();
        async move {
            let selector = {
                let pool = pool.clone();
                tokio::spawn(async move {
                    for _ in 0..2_000 {
                        let _ = pool.get_best_transactions(1_000, usize::MAX).await;
                        tokio::task::yield_now().await;
                    }
                })
            };
            let mut adders = Vec::new();
            for s in 0..SENDERS {
                let pool = pool.clone();
                adders.push(tokio::spawn(async move {
                    for n in 0..NONCES_PER_SENDER {
                        let _ = pool.add_transaction(tx(s, n), TxClass::Standard).await;
                    }
                }));
            }
            for a in adders {
                a.await.expect("adder task");
            }
            selector.await.expect("selector task");
        }
    };

    let finished = tokio::time::timeout(Duration::from_secs(60), work).await;
    assert!(
        finished.is_ok(),
        "admission + selection did not finish within 60s: the pool's locks are \
         parked (lock-order inversion between add_transaction and \
         get_best_transactions)"
    );
}
