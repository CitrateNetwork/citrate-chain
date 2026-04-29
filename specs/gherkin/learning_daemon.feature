# RM-FL-3 / WP-3.2 — Off-chain learning daemon
#
# Per CORE_RULES Rule 11, every scenario names its data source: the
# TLA+ spec, the on-chain contract or precompile, the persistence
# layer, the RPC method.
#
# Spec sources:
#   - specs/tla/learning/LearningDaemon.tla         (WP-3.1, 9 invariants)
#   - specs/tla/learning/LearningCycleLifecycle.tla (existing — on-chain cycle FSM)
#   - specs/tla/learning/DaemonAdversarial.tla       (WP-3.12, planned)
#
# Code targets (WP-3.5–WP-3.8):
#   - core/learning-daemon/  (new crate, scaffolded at WP-3.5)
#   - daemon → 0x0110 (Belnap, RM-FL-1 LIVE)
#   - daemon → 0x0111 (routing inference, RM-FL-2 LIVE)
#   - daemon → LearningCycleManager.finalizeCycle (testnet 0x20a0…4c4c)
#   - daemon → IPFS (weights publish + CID commit to chain)

Feature: Off-chain learning daemon — orchestrates the federated learning loop
  As an operator running a Citrate validator with the learning daemon
  I want the daemon to observe finalized blocks, aggregate embeddings,
  retrain the routing model, dispatch mentor assignments, and finalize
  cycles, all without manual intervention
  So that the on-chain federated-learning protocol runs end-to-end
  with documented restart safety, idempotent aggregation, and
  at-most-once finalize semantics
  (LearningDaemon.tla 9 invariants).

  Background:
    Given the Citrate testnet (chain id 40204) is live
    And the Belnap precompile is dispatched at 0x0110 (RM-FL-1)
    And the routing-model precompile is dispatched at 0x0111 (RM-FL-2)
    And LearningCycleManager is deployed at 0x20a0B74c766E84B20558ABD76a7a0Fd6434A4c4c
    And LoRAFactory is deployed at 0xAc6Bfb1709BCba5A005FE2823B4D8bC55db2b7D9
    And the daemon binary `citrate-learning-daemon` is built with a configured
      RPC URL, signing key, and RocksDB path
    And the daemon starts in a clean state (no prior cycles in RocksDB)

  # ─────────────────────────────────────────────────────────────────
  # Scenario 1 — Happy cycle (the canonical federated learning loop)
  # ─────────────────────────────────────────────────────────────────

  Scenario: Daemon completes a full Open → Collecting → Aggregating → AdapterGen → Finalized cycle
    # Source: LearningDaemon.tla::FinalizeRequiresCommit + AggregationIdempotent
    Given a fresh learning cycle id `c1` opens on-chain
    And 3 honest validator nodes register and submit embedding contributions
      during the Collecting phase, each within the cycle's checkpoint window
    When the on-chain cycle transitions Collecting → Aggregating
    Then the daemon collects all 3 embedding submissions from finalized blocks
      via `eth_getLogs` against the LearningCycleManager event filter
    And the daemon calls precompile `0x0110` (Belnap aggregation) with the
      collected embeddings + confidences + per-validator weights
    And the daemon commits the aggregated state vector to LearningCycleManager
      via `commitAggregation(cycleId, stateVector, valuesQ16)`
    And the daemon retrains the routing model off-chain (candle SGD) seeded
      from the previous cycle's published weights CID
    And the daemon quantizes the new weights to Q16 and pins them to IPFS
    And the daemon commits the new weights CID to chain via
      `setRoutingWeights(cycleId, cid)`
    When the on-chain cycle transitions AdapterGen → Finalized
    Then the daemon calls `finalizeCycle(cycleId)` exactly once
    And `eth_getTransactionReceipt` confirms the finalize tx succeeded
    And RocksDB shows `finalize_status[c1] = called`

  # ─────────────────────────────────────────────────────────────────
  # Scenario 2 — Missed checkpoint (daemon was offline during Collecting)
  # ─────────────────────────────────────────────────────────────────

  Scenario: Daemon starts mid-cycle and recovers all submissions from chain history
    # Source: LearningDaemon.tla::BlockHWMBoundedByChain
    Given cycle `c1` is in Aggregating phase (Collecting already closed)
    And 4 embedding submissions landed during Collecting while the daemon was offline
    When the daemon starts up with `last_processed_block = 0`
    Then the daemon backfills the block range from genesis-of-cycle-c1 to
      the current finalized head via paginated `eth_getLogs` calls
    And the daemon recovers all 4 embedding submissions for c1
    And the daemon proceeds to call `0x0110` aggregation as if it had been
      online the whole time
    And the resulting state vector is bit-identical to what would have
      resulted had the daemon been online (idempotent aggregation —
      LearningDaemon.tla::AggregationIdempotent)

  # ─────────────────────────────────────────────────────────────────
  # Scenario 3 — Daemon restart mid-cycle (kill -9 then restart)
  # ─────────────────────────────────────────────────────────────────

  Scenario: Daemon killed during Aggregating phase resumes correctly without double-rewards
    # Source: LearningDaemon.tla::RestartSafety + FinalizeAtMostOnce
    Given cycle `c1` is in Aggregating phase
    And the daemon has computed the Belnap aggregation locally
    And the daemon has NOT yet committed the aggregation to chain
    When the daemon process is killed (SIGKILL — no graceful shutdown)
    And the daemon process is restarted from the same RocksDB directory
    Then the daemon reads `cycle_status[c1] = "computed"` from RocksDB
    And the daemon does NOT re-run the aggregation
    And the daemon proceeds directly to commit the aggregation to chain
    When the on-chain cycle reaches Finalized
    Then the daemon calls `finalizeCycle(c1)` exactly once
    And there is exactly ONE `CycleFinalized` event for `c1` on chain
      (no duplicate from a race against the previous incarnation)

  # ─────────────────────────────────────────────────────────────────
  # Scenario 4 — Two daemons running against the same cycle
  # ─────────────────────────────────────────────────────────────────

  Scenario: Concurrent daemon instances do not cause double-finalize
    # Source: LearningDaemon.tla::FinalizeAtMostOnce (chain-level enforcement)
    Given two daemon instances are running with different RocksDB paths
      but the same RPC + signing key configuration
    And both have observed cycle `c1` reach AdapterGen → Finalized
    When daemon A calls `finalizeCycle(c1)` first
    Then daemon A's tx confirms with success
    And daemon B's `finalizeCycle(c1)` tx reverts on chain with
      "cycle already finalized" (LearningCycleManager guard)
    And daemon B observes the revert via receipt and updates its local
      `finalize_status[c1] = "called"` to match the chain truth
    And there is exactly ONE `CycleFinalized` event for `c1` on chain

  # ─────────────────────────────────────────────────────────────────
  # Scenario 5 — RPC outage during Collecting
  # ─────────────────────────────────────────────────────────────────

  Scenario: Daemon survives a 60-second RPC outage and catches up afterwards
    # Source: BlockHWMBoundedByChain — daemon never advances HWM past
    # what the chain confirms
    Given cycle `c1` is in Collecting phase
    And the daemon's RPC endpoint becomes unreachable for 60 seconds
    When `eth_getLogs` calls fail with connection errors
    Then the daemon retries with exponential backoff (capped at 30s)
    And `last_processed_block` does NOT advance during the outage
    When the RPC endpoint recovers
    Then the daemon resumes block processing from where it left off
    And no embedding submissions are dropped (no gap in
      `last_processed_block` coverage)
    And the cycle finalizes normally

  # ─────────────────────────────────────────────────────────────────
  # Scenario 6 — RocksDB corruption (the worst-case persistence failure)
  # ─────────────────────────────────────────────────────────────────

  Scenario: Daemon refuses to start with a corrupt RocksDB (operator must intervene)
    # Source: LearningDaemon.tla::RestartSafety — the daemon's persistence
    # layer is load-bearing; a corrupt one is NOT a recoverable state
    Given the daemon's RocksDB has been damaged (e.g. partial write
      after host kernel panic)
    When the daemon starts up
    Then RocksDB Open returns Err(Corruption)
    And the daemon logs a structured `target=daemon.fatal` ERROR
      naming the column family + offset
    And the daemon exits with code 65 (data corruption — operator step)
    # Operator runbook should reference resyncing from chain history;
    # automated recovery from corruption is OUT OF SCOPE for the daemon.
    And the daemon does NOT attempt automated recovery (which could
      mask a deeper bug)

  # ─────────────────────────────────────────────────────────────────
  # Scenario 7 — Byzantine block (chain reorg or invalid finalized block)
  # ─────────────────────────────────────────────────────────────────

  Scenario: Daemon detects a finalized-block reorg and rolls back HWM
    # Source: LearningDaemon.tla::BlockHWMBoundedByChain (the strict
    # version requires HWM to track the LIVE chain, not a stale view)
    Given the daemon has processed up to `last_processed_block = 100`
    And cycle `c1` has been aggregated locally based on submissions
      from blocks 90-99
    When the chain produces a reorg replacing block 95 with a different
      block at the same height
    Then the daemon detects the reorg via `eth_getBlockByNumber` finding
      a different block hash at height 95
    And the daemon emits a structured `target=daemon.reorg` ERROR
    And the daemon rolls back `last_processed_block` to 94
    And the daemon resets `cycle_status[c1] = "pending"` (re-aggregation
      required) ONLY IF c1 has not been committed on chain yet
    And the daemon refuses to commit if c1's local aggregation result
      no longer matches the post-reorg chain history (consistency check)

  # ─────────────────────────────────────────────────────────────────
  # Scenario 8 — Mentee with no qualified mentor
  # ─────────────────────────────────────────────────────────────────

  Scenario: Daemon handles a mentee whose performance gap matches no available mentor
    # Source: MentorSelection.tla (existing) + Paper III §2 algorithm
    # Daemon-side: graceful degradation, not a chain-halt event
    Given cycle `c1` is in Aggregating phase
    And one mentee node has a per-dimension performance profile that no
      registered mentor's profile is qualified to teach (e.g. mentee is
      a domain outlier)
    When the daemon dispatches mentor assignments for c1
    Then the daemon emits a `MenteeUnmatched` event with the mentee
      address and reason
    And the mentee is excluded from the mentorship round but still
      receives the cycle's base reward
    And cycle `c1` finalizes normally (one unmatched mentee does not
      block the cycle)
    And the next cycle's matchmaker receives the unmatched mentee's
      profile in its candidate pool (carried forward)
