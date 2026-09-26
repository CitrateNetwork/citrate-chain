// Native signature digest versions in the mempool around the activation
// height H (see `citrate_consensus::native_sig`).
//
// A transaction admitted while the tip is `t` can first be mined at `t + 1`.
// So the pool keeps accepting legacy (V1) native signatures while `t + 1 < H`,
// refuses them from tip `H - 1`, and evicts the ones it already holds at that
// point. Chain-bound (V2) signatures are accepted throughout. EVM transactions
// are not affected.

use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::hardening::PbaHardening;
use citrate_consensus::native_sig::{sign_native, NativeSigVersion};
use citrate_consensus::tx_auth::native_tx_id;
use citrate_consensus::types::{PublicKey, Transaction};
use citrate_sequencer::mempool::{Mempool, MempoolConfig, MempoolError, TxClass};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const H: u64 = 100;

fn native(seed: u8, nonce: u64, version: NativeSigVersion, signed_chain: u64) -> Transaction {
    let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let mut tx = Transaction {
        nonce,
        to: Some(PublicKey::new([9u8; 32])),
        value: 1,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(signed_chain),
        ..Default::default()
    };
    sign_native(&mut tx, &sk, version).unwrap();
    tx.chain_id = Some(40204);
    tx.hash = native_tx_id(&tx);
    tx
}

fn pool(tip: Arc<AtomicU64>) -> Mempool {
    Mempool::new(MempoolConfig::default()).with_native_sig_policy(
        PbaHardening::at(H),
        Arc::new(move || Some(tip.load(Ordering::SeqCst))),
    )
}

/// V1 txs admitted before tip H - 1 stay minable below H, then are refused
/// and evicted once the tip reaches H - 1. V2 is accepted at every tip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v1_minable_below_h_then_refused_and_evicted_from_tip_h_minus_1() {
    let tip = Arc::new(AtomicU64::new(H - 2));
    let mp = pool(tip.clone());

    let v1 = native(1, 0, NativeSigVersion::V1, 40204);
    mp.add_transaction(v1.clone(), TxClass::Standard)
        .await
        .expect("V1 admitted while the next block is below H");
    let v2 = native(2, 0, NativeSigVersion::V2, 40204);
    mp.add_transaction(v2.clone(), TxClass::Standard)
        .await
        .expect("V2 admitted before H");

    // The next block (H - 1) is still legacy: the V1 tx is selectable.
    let best = mp.get_best_transactions(10, usize::MAX).await;
    assert!(
        best.iter().any(|t| t.hash == v1.hash),
        "V1 still minable below H"
    );
    mp.clear_expired().await;
    assert!(
        mp.contains(&v1.hash).await,
        "no eviction while the next block is below H"
    );

    // Tip reaches H - 1: the next block is H.
    tip.store(H - 1, Ordering::SeqCst);
    let late = native(3, 0, NativeSigVersion::V1, 40204);
    let r = mp.add_transaction(late, TxClass::Standard).await;
    assert!(
        matches!(r, Err(MempoolError::InvalidTransaction(ref m)) if m.contains("legacy digest")),
        "V1 refused from tip H - 1, got {r:?}"
    );
    mp.clear_expired().await;
    assert!(
        !mp.contains(&v1.hash).await,
        "pooled V1 evicted from tip H - 1"
    );
    assert!(mp.contains(&v2.hash).await, "V2 kept");
    let best = mp.get_best_transactions(10, usize::MAX).await;
    assert!(best.iter().all(|t| t.hash != v1.hash));

    // V2 accepted at and above H.
    mp.add_transaction(native(4, 0, NativeSigVersion::V2, 40204), TxClass::Standard)
        .await
        .expect("V2 at tip H - 1");
    tip.store(H + 5, Ordering::SeqCst);
    mp.add_transaction(native(5, 0, NativeSigVersion::V2, 40204), TxClass::Standard)
        .await
        .expect("V2 above H");
    let r = mp
        .add_transaction(native(6, 0, NativeSigVersion::V1, 40204), TxClass::Standard)
        .await;
    assert!(r.is_err(), "V1 above H: {r:?}");
}

/// A native tx signed for another chain and labelled with this one: a V1
/// signature does not notice (accepted while legacy is still allowed), a V2
/// one does (rejected at every tip).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_tx_signed_for_another_chain_in_the_pool() {
    let tip = Arc::new(AtomicU64::new(H - 10));
    let mp = pool(tip.clone());
    mp.add_transaction(native(7, 0, NativeSigVersion::V1, 1337), TxClass::Standard)
        .await
        .expect("legacy digest still admitted below H - 1 (the pre-activation rule)");
    let r = mp
        .add_transaction(native(8, 0, NativeSigVersion::V2, 1337), TxClass::Standard)
        .await;
    assert!(r.is_err(), "V2 for another chain must not verify: {r:?}");

    tip.store(H - 1, Ordering::SeqCst);
    let r = mp
        .add_transaction(native(9, 0, NativeSigVersion::V1, 1337), TxClass::Standard)
        .await;
    assert!(
        r.is_err(),
        "V1 for another chain refused from tip H - 1: {r:?}"
    );
}

/// No policy wired and no activation: both versions are accepted and nothing
/// is evicted (the pre-activation behaviour).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_activation_both_versions_accepted() {
    for mp in [
        Mempool::new(MempoolConfig::default()),
        Mempool::new(MempoolConfig::default())
            .with_native_sig_policy(PbaHardening::off(), Arc::new(|| Some(u64::MAX - 1))),
    ] {
        let v1 = native(10, 0, NativeSigVersion::V1, 40204);
        mp.add_transaction(v1.clone(), TxClass::Standard)
            .await
            .expect("V1");
        mp.add_transaction(
            native(11, 0, NativeSigVersion::V2, 40204),
            TxClass::Standard,
        )
        .await
        .expect("V2");
        mp.clear_expired().await;
        assert!(mp.contains(&v1.hash).await);
    }
}

/// When the tip reaches H - 1 the pooled V1 transactions are gone at once
/// (not at the next periodic sweep): the next selection excludes them and the
/// sender can replace one with a V2 signature at the same nonce.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v1_evicted_as_soon_as_the_tip_reaches_h_minus_1() {
    let tip = Arc::new(AtomicU64::new(H - 2));
    let mp = pool(tip.clone());
    let v1 = native(20, 0, NativeSigVersion::V1, 40204);
    mp.add_transaction(v1.clone(), TxClass::Standard)
        .await
        .expect("V1 below the window");

    tip.store(H - 1, Ordering::SeqCst);
    let best = mp.get_best_transactions(10, usize::MAX).await;
    assert!(best.iter().all(|t| t.hash != v1.hash), "V1 not selected");
    assert!(
        !mp.contains(&v1.hash).await,
        "V1 evicted without clear_expired"
    );
    let v2 = native(20, 0, NativeSigVersion::V2, 40204);
    mp.add_transaction(v2.clone(), TxClass::Standard)
        .await
        .expect("same-nonce V2 re-sign accepted");
    assert!(mp.contains(&v2.hash).await);

    // Also on the insert path: a pool that is never asked for a selection.
    let tip = Arc::new(AtomicU64::new(H - 2));
    let mp = pool(tip.clone());
    mp.add_transaction(
        native(21, 0, NativeSigVersion::V1, 40204),
        TxClass::Standard,
    )
    .await
    .unwrap();
    tip.store(H - 1, Ordering::SeqCst);
    mp.add_transaction(
        native(21, 0, NativeSigVersion::V2, 40204),
        TxClass::Standard,
    )
    .await
    .expect("same-nonce V2 re-sign accepted without a selection first");
}

/// A tip reader that cannot answer is treated as at or after the window: the
/// pool refuses V1 (and still accepts V2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tip_reader_failure_closes_the_v1_window() {
    let mp = Mempool::new(MempoolConfig::default())
        .with_native_sig_policy(PbaHardening::at(H), Arc::new(|| None));
    let r = mp
        .add_transaction(
            native(22, 0, NativeSigVersion::V1, 40204),
            TxClass::Standard,
        )
        .await;
    assert!(r.is_err(), "V1 refused when the tip is unknown: {r:?}");
    mp.add_transaction(
        native(23, 0, NativeSigVersion::V2, 40204),
        TxClass::Standard,
    )
    .await
    .expect("V2 accepted");
}

/// From tip H - 1 the pool applies the block rule's strict verification: a
/// signature for a small-order key is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn small_order_key_signature_refused_from_tip_h_minus_1() {
    use citrate_consensus::native_sig::small_order_key_signature;
    let template = Transaction {
        nonce: 0,
        to: Some(PublicKey::new([9u8; 32])),
        value: 1,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(40204),
        ..Default::default()
    };
    let tx = small_order_key_signature(&template, NativeSigVersion::V2).expect("found");
    let tip = Arc::new(AtomicU64::new(H - 1));
    let mp = pool(tip);
    let r = mp.add_transaction(tx, TxClass::Standard).await;
    assert!(r.is_err(), "small-order key refused: {r:?}");
}

/// A failed tip read before `H - 1` does not use up the one-time eviction:
/// when the tip really reaches `H - 1`, pooled V1 transactions are evicted at
/// once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_tip_read_does_not_use_up_the_one_time_eviction() {
    const UNREADABLE: u64 = u64::MAX;
    let tip = Arc::new(AtomicU64::new(H - 2));
    let reader = tip.clone();
    let mp = Mempool::new(MempoolConfig::default()).with_native_sig_policy(
        PbaHardening::at(H),
        Arc::new(move || match reader.load(Ordering::SeqCst) {
            UNREADABLE => None,
            t => Some(t),
        }),
    );
    let early = native(30, 0, NativeSigVersion::V1, 40204);
    mp.add_transaction(early.clone(), TxClass::Standard)
        .await
        .unwrap();

    // A transient read failure while the tip is still H - 2.
    tip.store(UNREADABLE, Ordering::SeqCst);
    let _ = mp.get_best_transactions(10, usize::MAX).await;
    tip.store(H - 2, Ordering::SeqCst);
    assert!(
        mp.contains(&early.hash).await,
        "no eviction on an unreadable tip"
    );
    let late = native(31, 0, NativeSigVersion::V1, 40204);
    mp.add_transaction(late.clone(), TxClass::Standard)
        .await
        .expect("V1 still admissible at tip H - 2");

    tip.store(H - 1, Ordering::SeqCst);
    let best = mp.get_best_transactions(10, usize::MAX).await;
    assert!(best
        .iter()
        .all(|t| t.hash != late.hash && t.hash != early.hash));
    assert!(
        !mp.contains(&late.hash).await,
        "evicted at the real crossing"
    );
    assert!(!mp.contains(&early.hash).await);
}
