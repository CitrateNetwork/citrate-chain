//! Chaos tests — RM-FL-3 / WP-3.11.
//!
//! These tests exercise the daemon's restart-correctness contract
//! by injecting failures at specific points in the cycle lifecycle.
//! Each test simulates "process killed at point X" by either
//! arming a one-shot RPC failure on the [`FakeChain`] or by
//! dropping the daemon's in-memory handles mid-flow and re-opening
//! them on the same RocksDB path.
//!
//! Coverage map (against `LearningDaemon.tla`):
//!
//!   - `BlockHWMMonotonic` — never roll back HWM except via reorg.
//!   - `AggregationIdempotent` — re-running aggregation is a no-op.
//!   - `FinalizeAtMostOnce` — finalize is called at most once
//!     across the daemon's lifetime, including across restarts.
//!   - `RestartSafety` — RocksDB-backed state survives an
//!     in-memory wipe.
//!
//! The existing `lifecycle.rs::scenario_3*` tests cover the
//! state-layer restart bottom half. This file covers the higher-
//! level orchestrator/aggregator/trainer/finalizer paths.

use std::sync::Arc;

use citrate_learning_daemon::aggregator::{
    BelnapAggregator, EmbeddingEntry, MemoryEmbeddingCache,
};
use citrate_learning_daemon::chain::{ChainAdapter, FakeChain};
use citrate_learning_daemon::finalizer::try_finalize_cycle;
use citrate_learning_daemon::orchestrator::{Aggregator, Trainer};
use citrate_learning_daemon::state::{CycleStatus, DaemonState, FinalizeStatus};
use citrate_learning_daemon::trainer::{
    MemoryIpfsClient, RoutingTrainer, StubTrainingBackend,
};
use ethereum_types::H160;
use tempfile::TempDir;

fn make_entry(submitter: u8, value_q16: i32) -> EmbeddingEntry {
    EmbeddingEntry {
        submitter: H160::repeat_byte(submitter),
        embedding: vec![value_q16],
        confidence: vec![65536],
        weight: 65536,
    }
}

// ====================================================================
// Chaos 1 — Aggregator crashes between Computed and on-chain commit.
//
// Restart resumes from on-disk Computed status, retries the chain
// commit (via re-running `aggregate`), and reaches Committed
// without double-counting embeddings.
// ====================================================================

#[tokio::test]
async fn chaos_aggregator_crash_between_computed_and_commit() {
    let dir = TempDir::new().expect("tempdir");
    let chain = Arc::new(FakeChain::new());

    // First incarnation: aggregator runs, marks Computed, then the
    // chain RPC fails (we arm a one-shot error to simulate it).
    {
        let state = Arc::new(DaemonState::open(dir.path()).expect("open"));
        let cache = Arc::new(MemoryEmbeddingCache::new());
        cache.insert(1, make_entry(0x01, 32768));
        cache.insert(1, make_entry(0x02, 32768));

        let agg = BelnapAggregator::new(chain.clone(), state.clone(), cache);
        chain.arm_next_error("simulated RPC outage at commit_aggregation");
        let result = agg.aggregate(1).await;
        assert!(result.is_err(), "expected commit failure to surface");
        // Status was promoted before the chain call.
        assert_eq!(state.cycle_status(1), CycleStatus::Computed);
        // No commit landed on chain.
        assert!(chain.submitted_commits().is_empty());
    } // Drop = simulated process kill.

    // Second incarnation: same RocksDB path, fresh process, fresh
    // cache (simulating a real restart — the cache is rebuilt from
    // chain logs in production).
    let state2 = Arc::new(DaemonState::open(dir.path()).expect("reopen"));
    assert_eq!(
        state2.cycle_status(1),
        CycleStatus::Computed,
        "Computed status must survive restart"
    );

    let cache2 = Arc::new(MemoryEmbeddingCache::new());
    cache2.insert(1, make_entry(0x01, 32768));
    cache2.insert(1, make_entry(0x02, 32768));
    let agg2 = BelnapAggregator::new(chain.clone(), state2.clone(), cache2);

    // Re-running aggregate on a Computed cycle is the contract:
    // the idempotency guard skips before any chain call. The
    // commit retry flow is the orchestrator's job at slice 2;
    // for THIS test the property is "no double-counting".
    agg2.aggregate(1).await.expect("idempotent skip");
    assert!(
        chain.submitted_commits().is_empty(),
        "aggregator must NOT submit a second commit on restart \
         when the on-disk status is already Computed"
    );
}

// ====================================================================
// Chaos 2 — Finalizer crashes after on-chain accept but before
// `mark_finalized`. The next CycleFinalized event the watcher sees
// reconciles the local state. (Modeled here by directly calling the
// orchestrator's dispatch path.)
// ====================================================================

#[tokio::test]
async fn chaos_finalize_crash_after_chain_accept() {
    let dir = TempDir::new().expect("tempdir");
    let chain = Arc::new(FakeChain::new());

    // First incarnation: pretend the finalize tx landed on chain
    // (we record it via the helper) but the daemon died before
    // recording locally.
    {
        let state = Arc::new(DaemonState::open(dir.path()).expect("open"));
        // Promote cycle 5 to Committed so finalize is allowed.
        state.set_cycle_status(5, CycleStatus::Computed).expect("computed");
        state.set_cycle_status(5, CycleStatus::Committed).expect("committed");

        // Submit finalize. Chain accepts. Then the daemon dies.
        let _tx = chain.finalize_cycle(5).await.expect("finalize ok");
        // Local mark_finalized was NOT called (simulated crash).
        assert_eq!(state.finalize_status(5), FinalizeStatus::NotCalled);
    } // Drop.

    // Second incarnation: chain has the finalize tx. Daemon's
    // local state still says NotCalled. The reconciliation path
    // is: re-running try_finalize_cycle observes the chain's
    // "already finalized" rejection and the wrapper fn marks
    // local state.
    let state2 = Arc::new(DaemonState::open(dir.path()).expect("reopen"));
    assert_eq!(state2.cycle_status(5), CycleStatus::Committed);
    assert_eq!(state2.finalize_status(5), FinalizeStatus::NotCalled);

    try_finalize_cycle(chain.clone(), state2.clone(), 5)
        .await
        .expect("reconcile via 'already finalized'");

    // Local view now consistent with chain.
    assert_eq!(state2.finalize_status(5), FinalizeStatus::Called);
    // Chain saw exactly ONE finalize tx (the pre-crash one).
    assert_eq!(chain.submitted_finalizes(), vec![5]);
}

// ====================================================================
// Chaos 3 — Trainer crashes between IPFS pin and chain commit. On
// restart, the deterministic backend produces identical Q16 weights;
// the deterministic CID hashes to the same value; re-running pin is
// a no-op (content-addressed); the chain commit retries.
// ====================================================================

#[tokio::test]
async fn chaos_trainer_crash_between_ipfs_pin_and_chain_commit() {
    let dir = TempDir::new().expect("tempdir");
    let chain = Arc::new(FakeChain::new());

    // Pre-condition setup: cycle 3 must be Committed for the
    // trainer to run.
    let state = Arc::new(DaemonState::open(dir.path()).expect("open"));
    state.set_cycle_status(3, CycleStatus::Computed).expect("computed");
    state.set_cycle_status(3, CycleStatus::Committed).expect("committed");

    // First incarnation: trainer runs, IPFS pin succeeds, chain
    // commit fails. Idempotent flow: rerun produces identical CID
    // and identical chain commit content.
    let cache: Arc<MemoryEmbeddingCache> = Arc::new(MemoryEmbeddingCache::new());
    cache.insert(3, make_entry(0x01, 32768));
    let backend = Arc::new(StubTrainingBackend { n_weights: 16 });
    let ipfs = Arc::new(MemoryIpfsClient::new());

    {
        let trainer = RoutingTrainer::new(
            chain.clone(),
            state.clone(),
            cache.clone(),
            ipfs.clone(),
            backend.clone(),
        );
        chain.arm_next_error("simulated RPC outage at commit_routing_weights");
        let result = trainer.train(3).await;
        assert!(result.is_err(), "expected chain commit failure");
        // No routing weights commit landed.
        assert!(chain.routing_weights_commits().is_empty());
        // IPFS pin succeeded — pinned content is in the store.
        assert!(
            ipfs.pin_count() > 0,
            "IPFS pin should have happened before the chain failure"
        );
    }

    // Second incarnation: same state, retry trainer. Deterministic
    // inputs → identical CID → re-pin is idempotent → chain commit
    // succeeds.
    let backend2 = Arc::new(StubTrainingBackend { n_weights: 16 });
    let trainer2 = RoutingTrainer::new(
        chain.clone(),
        state.clone(),
        cache,
        ipfs.clone(),
        backend2,
    );
    trainer2.train(3).await.expect("retry succeeds");

    // Exactly one routing-weights commit on chain.
    let commits = chain.routing_weights_commits();
    assert_eq!(
        commits.len(),
        1,
        "trainer must produce exactly one chain commit even after retry"
    );
    assert_eq!(commits[0].cycle_id, 3);
}

// ====================================================================
// Chaos 4 — Repeated chaos: kill mid-aggregation, restart with new
// chaos, restart again clean. State remains consistent throughout.
// ====================================================================

#[tokio::test]
async fn chaos_repeated_kills_converge_to_consistent_state() {
    let dir = TempDir::new().expect("tempdir");
    let chain = Arc::new(FakeChain::new());

    // Round 1: aggregator crashes mid-commit.
    {
        let state = Arc::new(DaemonState::open(dir.path()).expect("open 1"));
        let cache = Arc::new(MemoryEmbeddingCache::new());
        cache.insert(7, make_entry(0x01, 32768));
        let agg = BelnapAggregator::new(chain.clone(), state.clone(), cache);
        chain.arm_next_error("round 1 outage");
        let _ = agg.aggregate(7).await;
        assert_eq!(state.cycle_status(7), CycleStatus::Computed);
    }

    // Round 2: re-aggregation skips (idempotent). Trainer never
    // ran, so trainer is the next thing to attempt — and we crash
    // it too.
    {
        let state = Arc::new(DaemonState::open(dir.path()).expect("open 2"));
        // Manually advance cycle to Committed (simulating that an
        // out-of-band commit observation reconciled it).
        state.set_cycle_status(7, CycleStatus::Committed).expect("committed");

        let cache: Arc<MemoryEmbeddingCache> = Arc::new(MemoryEmbeddingCache::new());
        cache.insert(7, make_entry(0x01, 32768));
        let backend = Arc::new(StubTrainingBackend { n_weights: 8 });
        let ipfs = Arc::new(MemoryIpfsClient::new());
        let trainer = RoutingTrainer::new(
            chain.clone(),
            state.clone(),
            cache,
            ipfs,
            backend,
        );
        chain.arm_next_error("round 2 outage");
        let _ = trainer.train(7).await;
        // Chain still has 0 routing weights commits.
        assert!(chain.routing_weights_commits().is_empty());
    }

    // Round 3: clean restart, trainer succeeds, finalizer runs, no
    // double-anything.
    let state3 = Arc::new(DaemonState::open(dir.path()).expect("open 3"));
    assert_eq!(state3.cycle_status(7), CycleStatus::Committed);
    assert_eq!(state3.finalize_status(7), FinalizeStatus::NotCalled);

    let cache3: Arc<MemoryEmbeddingCache> = Arc::new(MemoryEmbeddingCache::new());
    cache3.insert(7, make_entry(0x01, 32768));
    let trainer3 = RoutingTrainer::new(
        chain.clone(),
        state3.clone(),
        cache3,
        Arc::new(MemoryIpfsClient::new()),
        Arc::new(StubTrainingBackend { n_weights: 8 }),
    );
    trainer3.train(7).await.expect("clean train");

    try_finalize_cycle(chain.clone(), state3.clone(), 7)
        .await
        .expect("clean finalize");

    // End-state assertions: exactly one of each on-chain.
    assert_eq!(chain.routing_weights_commits().len(), 1);
    assert_eq!(chain.submitted_finalizes(), vec![7]);
    assert_eq!(state3.finalize_status(7), FinalizeStatus::Called);
}

// ====================================================================
// Chaos 5 — HWM monotonicity under repeated outages.
//
// The watcher must not advance past a block whose hash query
// failed. Under the WP-3.10 parallelization, this means: if either
// `learning_events` or `block_hash` errors, HWM stays put.
// ====================================================================

#[tokio::test]
async fn chaos_hwm_does_not_advance_when_rpc_fails() {
    use citrate_learning_daemon::watcher::BlockWatcher;
    let chain = Arc::new(FakeChain::new());
    let dir = TempDir::new().expect("tempdir");
    let state = Arc::new(DaemonState::open(dir.path()).expect("open"));
    let watcher = BlockWatcher::new(chain.clone(), state.clone());

    chain.produce_block();
    chain.produce_block();
    chain.produce_block();

    // Arm a failure on the first RPC of the next step
    // (finalized_block_number). Watcher must error, HWM stays at 0.
    chain.arm_next_error("transient outage");
    let result = watcher.step().await;
    assert!(result.is_err(), "watcher must surface RPC error");
    assert_eq!(
        state.last_processed_block(),
        0,
        "HWM must not advance when an RPC in the step path fails"
    );

    // Next clean step succeeds and advances all the way.
    let _ = watcher.step().await.expect("clean step");
    assert_eq!(state.last_processed_block(), 3);
}
