// PBA-L1a-001 (CRITICAL) regression — from the audit PoC
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
use citrate_sequencer::mempool::{Mempool, MempoolConfig, TxClass};
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

/// The PoC at the real entry point: default config, validly signed, fresh key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pba_l1a_001_nonce_max_is_rejected_and_selection_never_panics() {
    let mp = Arc::new(Mempool::new(MempoolConfig::default()));
    let r = mp
        .add_transaction(signed(7, u64::MAX), TxClass::Standard)
        .await;
    assert!(
        r.is_err(),
        "PBA-L1a-001: a nonce=u64::MAX tx must be rejected at admission, got {r:?}"
    );

    // Whatever admission let through, selection must not panic.
    let mp2 = mp.clone();
    let sel = tokio::spawn(async move { mp2.get_best_transactions(100, 1 << 20).await }).await;
    assert!(
        sel.is_ok(),
        "PBA-L1a-001: get_best_transactions panicked (producer task would die)"
    );
}

/// Boundary: `u64::MAX - 1` is a legal nonce value in isolation (no state
/// reader wired) and its selection must not overflow either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pba_l1a_001_nonce_max_minus_one_selects_without_overflow() {
    let mp = Arc::new(Mempool::new(MempoolConfig::default()));
    mp.add_transaction(signed(8, u64::MAX - 1), TxClass::Standard)
        .await
        .expect("u64::MAX-1 is admissible without a state reader");
    let mp2 = mp.clone();
    let sel = tokio::spawn(async move { mp2.get_best_transactions(100, 1 << 20).await })
        .await
        .expect("selection must not panic");
    assert_eq!(sel.len(), 1);
    assert_eq!(mp.pending_nonce_for(&sel[0].from).await, Some(u64::MAX));
}

// Tripwire (class-level): selection fuzz over nonce extremes. Whatever mix of
// senders and boundary nonces is offered, admission never keeps a u64::MAX
// nonce and selection never panics.
mod nonce_extremes_fuzz {
    use super::*;
    use proptest::prelude::*;

    fn nonce_strategy() -> impl Strategy<Value = u64> {
        prop_oneof![
            Just(0u64),
            Just(1u64),
            Just(u64::MAX),
            Just(u64::MAX - 1),
            Just(u64::MAX - 16),
            any::<u64>(),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]
        #[test]
        fn admission_and_selection_survive_nonce_extremes(
            offers in proptest::collection::vec((0u8..6, nonce_strategy()), 1..12)
        ) {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let mp = Arc::new(Mempool::new(MempoolConfig::default()));
                for (seed, nonce) in &offers {
                    let _ = mp.add_transaction(signed(*seed + 1, *nonce), TxClass::Standard).await;
                }
                let mp2 = mp.clone();
                let sel = tokio::spawn(async move { mp2.get_best_transactions(100, 1 << 20).await })
                    .await
                    .expect("selection panicked on boundary nonces");
                assert!(sel.iter().all(|t| t.nonce != u64::MAX));
                for (seed, _) in &offers {
                    let from = signed(*seed + 1, 0).from;
                    let _ = mp.pending_nonce_for(&from).await; // must not panic
                }
            });
        }
    }
}
