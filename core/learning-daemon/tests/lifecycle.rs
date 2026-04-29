//! Integration tests for the learning daemon orchestrator.
//!
//! Mirrors the 8 Gherkin scenarios in
//! `citrate_v0.01.1/specs/gherkin/learning_daemon.feature`. Each
//! scenario maps to ≥1 test here.
//!
//! Tests that depend on the WP-3.6/3.7/3.8 impl path (aggregator,
//! trainer, finalizer) are `#[ignore = "WP-3.X"]` per RM-FL-1
//! retro item #1 — un-ignore them when the impl lands.

use std::sync::Arc;

use citrate_learning_daemon::chain::{FakeChain, LearningEvent};
use citrate_learning_daemon::orchestrator::{
    Aggregator, Finalizer, Orchestrator, StubAggregator, StubFinalizer, StubTrainer, Trainer,
};
use citrate_learning_daemon::state::{CycleStatus, DaemonState, FinalizeStatus};
use citrate_learning_daemon::types::EmbeddingSubmission;
use citrate_learning_daemon::watcher::{BlockWatcher, WatcherStep};
use citrate_learning_daemon::DaemonError;
use ethereum_types::{H160, H256};
use tempfile::TempDir;

/// Build a fresh orchestrator + chain + state for a test.
fn fixture() -> (Arc<FakeChain>, Arc<DaemonState>, TempDir) {
    let chain = Arc::new(FakeChain::new());
    let dir = TempDir::new().expect("tempdir");
    let state = Arc::new(DaemonState::open(dir.path()).expect("state open"));
    (chain, state, dir)
}

fn make_orchestrator(
    chain: Arc<FakeChain>,
    state: Arc<DaemonState>,
) -> Orchestrator<FakeChain> {
    Orchestrator::new(
        chain,
        state,
        Arc::new(StubAggregator),
        Arc::new(StubTrainer),
        Arc::new(StubFinalizer),
    )
}

// ====================================================================
// Block-watcher fundamentals (GREEN — exercised at WP-3.5)
// ====================================================================

#[tokio::test]
async fn watcher_nothing_to_do_when_chain_at_zero() {
    let (chain, state, _dir) = fixture();
    let watcher = BlockWatcher::new(chain.clone(), state.clone());
    let step = watcher.step().await.expect("step");
    assert_eq!(step, WatcherStep::NothingToDo);
    assert_eq!(state.last_processed_block(), 0);
}

#[tokio::test]
async fn watcher_advances_hwm_when_chain_advances() {
    let (chain, state, _dir) = fixture();
    let watcher = BlockWatcher::new(chain.clone(), state.clone());

    chain.produce_block();
    chain.produce_block();
    chain.produce_block();

    let step = watcher.step().await.expect("step");
    if let WatcherStep::Advanced { new_hwm, events } = step {
        assert_eq!(new_hwm, 3);
        assert_eq!(events.len(), 0); // no events emitted
    } else {
        panic!("expected Advanced; got {step:?}");
    }
    assert_eq!(state.last_processed_block(), 3);
}

#[tokio::test]
async fn watcher_picks_up_emitted_events() {
    let (chain, state, _dir) = fixture();
    let watcher = BlockWatcher::new(chain.clone(), state.clone());

    chain.produce_block();
    chain.emit_event(
        1,
        LearningEvent::CycleOpened {
            cycle_id: 5,
            opened_at: 1,
            deadline: 100,
        },
    );

    let step = watcher.step().await.expect("step");
    if let WatcherStep::Advanced { events, .. } = step {
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].cycle_id(), 5);
    } else {
        panic!("expected Advanced");
    }
}

#[tokio::test]
async fn watcher_idempotent_step_after_full_advance() {
    let (chain, state, _dir) = fixture();
    let watcher = BlockWatcher::new(chain.clone(), state.clone());

    chain.produce_block();
    let _ = watcher.step().await.expect("first step");
    let step = watcher.step().await.expect("second step");
    assert_eq!(step, WatcherStep::NothingToDo);
}

// ====================================================================
// Scenario 1 — Happy cycle (GATED — needs WP-3.6 + 3.7 + 3.8)
// ====================================================================

#[tokio::test]
#[ignore = "WP-3.6: aggregator impl pending"]
async fn scenario_1_happy_cycle_open_to_finalized() {
    // Three honest validators, full cycle Open → Collecting →
    // Aggregating → AdapterGen → Finalized. Asserts:
    //   - daemon called 0x0110 (Belnap aggregation)
    //   - daemon committed state vector via commit_aggregation
    //   - daemon called finalizeCycle exactly once
    //   - state.finalize_status[c1] == Called
    unreachable!("ignored test; un-ignore at WP-3.6");
}

// ====================================================================
// Scenario 2 — Missed checkpoint (GATED — needs WP-3.6)
// ====================================================================

#[tokio::test]
#[ignore = "WP-3.6: aggregator backfill from chain history pending"]
async fn scenario_2_missed_checkpoint_recovers_all_submissions() {
    // Daemon starts mid-cycle; backfills all submissions; aggregation
    // matches the live-online case bit-identically.
    unreachable!("ignored test; un-ignore at WP-3.6");
}

// ====================================================================
// Scenario 3 — Mid-cycle restart (GATED — needs WP-3.6 + WP-3.8)
// Partial GREEN coverage at WP-3.5: state survives restart at the
// `DaemonState` layer (already covered by state.rs::tests).
// ====================================================================

#[tokio::test]
async fn scenario_3a_state_survives_restart_at_state_layer() {
    // The bottom half of scenario 3: state.rs already verifies that
    // RocksDB state survives reopen. This is the WP-3.5 deliverable
    // for that scenario; the full SIGKILL+resume integration test
    // is gated at WP-3.6 (which lands the aggregator state machine).
    let dir = TempDir::new().expect("tempdir");
    {
        let state = DaemonState::open(dir.path()).expect("open 1");
        state.set_last_processed_block(50).expect("set hwm");
        state
            .set_cycle_status(7, CycleStatus::Computed)
            .expect("set status");
    } // Drop = restart simulation.
    let state = DaemonState::open(dir.path()).expect("open 2");
    assert_eq!(state.last_processed_block(), 50);
    assert_eq!(state.cycle_status(7), CycleStatus::Computed);
}

#[tokio::test]
#[ignore = "WP-3.6: full SIGKILL+resume integration with aggregator"]
async fn scenario_3b_killed_during_aggregation_resumes_correctly() {
    unreachable!("ignored test; un-ignore at WP-3.6");
}

// ====================================================================
// Scenario 4 — Two daemons against one cycle (GATED — needs WP-3.8)
// ====================================================================

#[tokio::test]
#[ignore = "WP-3.8: finalizer impl pending"]
async fn scenario_4_two_daemons_no_double_finalize() {
    unreachable!("ignored test; un-ignore at WP-3.8");
}

// ====================================================================
// Scenario 5 — RPC outage (GREEN at WP-3.5 — watcher + state are
// the only daemon-side pieces involved)
// ====================================================================

#[tokio::test]
async fn scenario_5_rpc_outage_does_not_advance_hwm() {
    let (chain, state, _dir) = fixture();
    let watcher = BlockWatcher::new(chain.clone(), state.clone());

    chain.produce_block();
    chain.produce_block();

    // Arm an RPC error. The watcher's step must surface it WITHOUT
    // advancing HWM.
    chain.arm_next_error("connection refused");
    let err = watcher.step().await.expect_err("RPC error surfaces");
    assert!(matches!(err, DaemonError::Chain(_)));
    assert_eq!(state.last_processed_block(), 0, "HWM did NOT advance during outage");

    // RPC recovers — next step advances normally.
    let step = watcher.step().await.expect("step");
    if let WatcherStep::Advanced { new_hwm, .. } = step {
        assert_eq!(new_hwm, 2);
    } else {
        panic!("expected Advanced after RPC recovery");
    }
}

// ====================================================================
// Scenario 6 — RocksDB corruption (covered by error.rs tests at
// the DaemonError level; full lifecycle test belongs in the
// daemon binary's startup wrapper, lands at WP-3.5 slice 2)
// ====================================================================

#[tokio::test]
#[ignore = "WP-3.5 slice 2: requires the daemon binary's startup wrapper"]
async fn scenario_6_corrupted_rocksdb_refuses_start() {
    unreachable!("ignored test; un-ignore at WP-3.5 slice 2 (binary startup)");
}

// ====================================================================
// Scenario 7 — Reorg detection (GREEN at WP-3.5)
// ====================================================================

#[tokio::test]
async fn scenario_7_reorg_detected_and_hwm_rolled_back() {
    let (chain, state, _dir) = fixture();
    let watcher = BlockWatcher::new(chain.clone(), state.clone());

    chain.produce_block(); // 1
    chain.produce_block(); // 2
    chain.produce_block(); // 3

    let _ = watcher.step().await.expect("first step advances to 3");
    assert_eq!(state.last_processed_block(), 3);

    // Reorg: rewrite block 3's hash (the cached HWM). The watcher
    // re-checks the hash of `last_processed_block` before processing
    // any new range — that's the seam where a reorg gets caught.
    chain.set_block_hash(3, H256::repeat_byte(0xff));

    // Produce a new block 4 to trigger a watcher step.
    chain.produce_block(); // 4

    let step = watcher.step().await.expect("reorg step");
    if let WatcherStep::ReorgDetected { fork_at, .. } = step {
        // The watcher detected the reorg at HWM (block 3).
        assert_eq!(fork_at, 3);
    } else {
        panic!("expected ReorgDetected; got {step:?}");
    }
    // (Orchestrator-driven rollback is in scenario_7b below.)
}

#[tokio::test]
async fn scenario_7b_orchestrator_rolls_back_hwm_on_reorg() {
    let (chain, state, _dir) = fixture();
    let orchestrator = make_orchestrator(chain.clone(), state.clone());

    chain.produce_block(); // 1
    chain.produce_block(); // 2
    chain.produce_block(); // 3

    // First tick: orchestrator advances HWM to 3.
    orchestrator.tick().await.expect("first tick");
    assert_eq!(state.last_processed_block(), 3);

    // Reorg.
    chain.set_block_hash(3, H256::repeat_byte(0xee));
    chain.produce_block(); // 4

    // Second tick: orchestrator detects reorg, rolls HWM back to 2.
    orchestrator.tick().await.expect("reorg tick");
    assert_eq!(state.last_processed_block(), 2, "rollback to fork_at - 1");
}

// ====================================================================
// Scenario 8 — Mentee with no qualified mentor (GATED — needs the
// mentor matching impl from RM-FL-4; out of scope for RM-FL-3)
// ====================================================================

#[tokio::test]
#[ignore = "RM-FL-4: mentor matching impl"]
async fn scenario_8_mentee_with_no_mentor_handled_gracefully() {
    unreachable!("ignored test; un-ignore in RM-FL-4");
}

// ====================================================================
// Orchestrator-level invariants (GREEN at WP-3.5)
// ====================================================================

#[tokio::test]
async fn orchestrator_finalize_requires_commit() {
    let (chain, state, _dir) = fixture();
    let orchestrator = make_orchestrator(chain, state.clone());

    // Cycle starts pending; try_finalize must reject because the
    // FinalizeRequiresCommit invariant is enforced at the orchestrator
    // layer.
    let err = orchestrator.try_finalize(1).await.expect_err("rejects");
    assert!(format!("{err}").contains("FinalizeRequiresCommit"));
}

#[tokio::test]
async fn orchestrator_finalize_skips_when_already_called() {
    let (chain, state, _dir) = fixture();
    let orchestrator = make_orchestrator(chain, state.clone());

    // Manually fast-forward state to allow finalize.
    state
        .set_cycle_status(1, CycleStatus::Computed)
        .expect("ok");
    state
        .set_cycle_status(1, CycleStatus::Committed)
        .expect("ok");
    orchestrator.try_finalize(1).await.expect("first finalize ok");

    // Second call: orchestrator skips silently (idempotent at this
    // layer; the chain-level guard is the second line of defense).
    orchestrator.try_finalize(1).await.expect("second is no-op");
    assert_eq!(state.finalize_status(1), FinalizeStatus::Called);
}

#[tokio::test]
async fn orchestrator_dispatches_aggregation_committed_event() {
    let (chain, state, _dir) = fixture();
    let orchestrator = make_orchestrator(chain.clone(), state.clone());

    // Pre-set cycle to Computed so dispatch_event can promote it.
    state.set_cycle_status(1, CycleStatus::Computed).expect("ok");

    chain.produce_block();
    chain.emit_event(
        1,
        LearningEvent::AggregationCommitted {
            cycle_id: 1,
            state_hash: H256::repeat_byte(0x99),
        },
    );

    orchestrator.tick().await.expect("tick");
    assert_eq!(state.cycle_status(1), CycleStatus::Committed);
}

#[tokio::test]
async fn orchestrator_dispatches_finalized_event_marks_local() {
    let (chain, state, _dir) = fixture();
    let orchestrator = make_orchestrator(chain.clone(), state.clone());

    chain.produce_block();
    chain.emit_event(1, LearningEvent::CycleFinalized { cycle_id: 7 });

    orchestrator.tick().await.expect("tick");
    assert_eq!(state.finalize_status(7), FinalizeStatus::Called);
}

// ====================================================================
// Hook-trait shape tests (GREEN; the orchestrator must accept
// trait-object hooks — this catches regressions if the trait
// surface narrows accidentally)
// ====================================================================

#[tokio::test]
async fn hooks_compose_via_arc_dyn() {
    let agg: Arc<dyn Aggregator> = Arc::new(StubAggregator);
    let train: Arc<dyn Trainer> = Arc::new(StubTrainer);
    let fin: Arc<dyn Finalizer> = Arc::new(StubFinalizer);

    agg.aggregate(1).await.expect("ok");
    train.train(1).await.expect("ok");
    fin.finalize(1).await.expect("ok");
}

// ====================================================================
// Embedding-submission round-trip (GREEN; sanity check the wire
// types compose with serialization the rest of the codebase uses)
// ====================================================================

#[tokio::test]
async fn embedding_submission_roundtrip_via_event() {
    let (chain, state, _dir) = fixture();
    let watcher = BlockWatcher::new(chain.clone(), state.clone());

    let submission = EmbeddingSubmission {
        cycle_id: 11,
        submitter: H160::from_low_u64_be(0xdead),
        commitment: H256::repeat_byte(0x42),
        block_number: 1,
        log_index: 0,
    };

    chain.produce_block();
    chain.emit_event(1, LearningEvent::EmbeddingSubmitted(submission.clone()));

    let step = watcher.step().await.expect("step");
    if let WatcherStep::Advanced { events, .. } = step {
        assert_eq!(events.len(), 1);
        if let LearningEvent::EmbeddingSubmitted(s) = &events[0] {
            assert_eq!(s, &submission);
        } else {
            panic!("expected EmbeddingSubmitted");
        }
    } else {
        panic!("expected Advanced");
    }
}
