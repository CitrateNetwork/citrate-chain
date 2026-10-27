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

// The producer reconciles the per-sender nonce index after every block, while
// RPC and gossip keep admitting. Same liveness requirement as above.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_admission_and_reconcile_make_progress() {
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
            let reconciler = {
                let pool = pool.clone();
                tokio::spawn(async move {
                    for _ in 0..2_000 {
                        pool.reconcile_nonces().await;
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
            reconciler.await.expect("reconciler task");
        }
    };

    let finished = tokio::time::timeout(Duration::from_secs(60), work).await;
    assert!(
        finished.is_ok(),
        "admission + reconcile_nonces did not finish within 60s: the two take \
         the pool's locks in different orders"
    );
    assert_eq!(
        pool.stats().await.total_transactions,
        usize::from(SENDERS) * NONCES_PER_SENDER as usize,
        "every admitted transaction is still pooled"
    );
}

// Every pool entry point at once: admission (with eviction from a full pool),
// the producer's select / remove-included / reconcile cycle, and the periodic
// expiry, ban and read paths, across many senders. Each path takes a different
// subset of the pool's locks, so this covers every pair of paths that can
// overlap in a running node. It must finish well inside the deadline.

const STRESS_SENDERS: u16 = 96;
const STRESS_NONCES: u64 = 24;
const STRESS_ROUNDS: usize = 1_500;

fn stress_tx(sender: u16, nonce: u64) -> Transaction {
    let mut h = [0u8; 32];
    h[0..2].copy_from_slice(&sender.to_le_bytes());
    h[2..10].copy_from_slice(&nonce.to_le_bytes());
    h[31] = 0xA7;
    let mut from = [0u8; 32];
    from[0..2].copy_from_slice(&sender.to_le_bytes());
    from[31] = 0x5B;
    Transaction {
        hash: Hash::new(h),
        nonce,
        from: PublicKey::new(from),
        to: Some(PublicKey::new([0xCD; 32])),
        value: 1,
        gas_limit: 21_000,
        // Spread fees so a full pool evicts by priority.
        gas_price: 1_000_000_000 + u64::from(sender % 13) * 7 + nonce,
        data: vec![],
        signature: Signature::new([1; 64]),
        chain_id: Some(40204),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn every_pool_path_concurrently_makes_progress() {
    let pool = Arc::new(
        Mempool::new(MempoolConfig {
            // Small enough that admission keeps evicting.
            max_size: 512,
            require_valid_signature: false,
            min_gas_price: 0,
            // Everything older than the current second counts as expired.
            tx_expiry_secs: 0,
            chain_id: 40204,
            ..Default::default()
        })
        .with_state_balance_reader(Arc::new(|_: &PublicKey| u128::MAX)),
    );

    let work = {
        let pool = pool.clone();
        async move {
            let mut tasks = Vec::new();

            // Producer: select, drop part of the selection as "included",
            // then reconcile, as the node does after each block.
            {
                let pool = pool.clone();
                tasks.push(tokio::spawn(async move {
                    for _ in 0..STRESS_ROUNDS {
                        let picked = pool.get_best_transactions(256, usize::MAX).await;
                        for t in picked.iter().take(picked.len() / 2) {
                            let _ = pool.remove_transaction(&t.hash).await;
                        }
                        pool.reconcile_nonces().await;
                        tokio::task::yield_now().await;
                    }
                }));
            }

            // Housekeeping: expiry sweep, temporary bans, and the read paths
            // RPC serves (stats, pending nonce, lookups).
            {
                let pool = pool.clone();
                tasks.push(tokio::spawn(async move {
                    for i in 0..STRESS_ROUNDS {
                        if i % 8 == 0 {
                            pool.clear_expired().await;
                        }
                        let s = (i as u16) % STRESS_SENDERS;
                        let victim = stress_tx(s, 0).from;
                        if i % 16 == 0 {
                            pool.ban_sender(&victim, Duration::from_millis(1)).await;
                        }
                        let _ = pool.stats().await;
                        let _ = pool.pending_nonce_for(&victim).await;
                        let _ = pool.pending_nonce_matching(|pk| pk == &victim).await;
                        let _ = pool.get_transactions(64).await;
                        let _ = pool.get_ai_transactions(16).await;
                        let _ = pool.contains(&stress_tx(s, 1).hash).await;
                        tokio::task::yield_now().await;
                    }
                }));
            }

            // Admission from many senders at once.
            for s in 0..STRESS_SENDERS {
                let pool = pool.clone();
                tasks.push(tokio::spawn(async move {
                    for n in 0..STRESS_NONCES {
                        let _ = pool
                            .add_transaction(stress_tx(s, n), TxClass::Standard)
                            .await;
                    }
                }));
            }

            for t in tasks {
                t.await.expect("pool task");
            }
        }
    };

    let finished = tokio::time::timeout(Duration::from_secs(60), work).await;
    assert!(
        finished.is_ok(),
        "concurrent admission, selection, reconcile, expiry and reads did not \
         finish within 60s: two paths take the pool's locks in different orders"
    );

    // The pool is still usable afterwards: a fresh sender is admitted and
    // selected.
    let mut fresh = stress_tx(STRESS_SENDERS + 1, 0);
    fresh.gas_price = 10_000_000_000; // outranks anything left in a full pool
    pool.add_transaction(fresh.clone(), TxClass::Standard)
        .await
        .expect("fresh sender admitted after the stress run");
    let picked = pool.get_best_transactions(usize::MAX, usize::MAX).await;
    assert!(picked.iter().any(|t| t.hash == fresh.hash));
}
