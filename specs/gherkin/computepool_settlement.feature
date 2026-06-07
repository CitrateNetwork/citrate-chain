Feature: ComputePool settlement authority + requester timeout-refund (INFER-S2)
  As the gateway-initiated INFER product (ADR-infer-settlement Option 3)
  I want the executor of record to settle the job it ran
  And the requester to reclaim escrow when a job never terminates
  So that a pooled request settles end-to-end and a timeout refunds the buyer

  # Source: citrate-labs/handoffs/INFER_COMPUTEPOOL_SETTLEMENT_WP.md (PR #11)
  # Verified at citrate-chain@e1266e0; re-verified unchanged at main@8077149.
  # completeJob:410  failJob:431  recordDispatch:664  reassignCoordinator:693

  Background:
    Given a ComputePool deployed on chain 40204
    And a pool "pool-llama" with at least two active members
    And a requester who has paid escrow via requestPoolCompute

  # ── G1: settlement-authority asymmetry (executor of record can settle) ──

  Scenario: the elected coordinator can complete the job it ran
    Given the job has been dispatched by the VRF-elected coordinator (recordDispatch)
    When that coordinator (job.dispatchedBy) calls completeJob
    Then the job becomes Completed
    And payment is distributed proportionally to pool members

  Scenario: the elected coordinator can fail the job it ran
    Given the job has been dispatched by the VRF-elected coordinator
    When that coordinator calls failJob
    Then the job becomes Failed
    And the escrow is refunded to the requester

  Scenario: governance and pool creator can still settle
    When governance or the pool creator calls completeJob
    Then the job becomes Completed
    # backwards compatibility — the existing allow-list members are unchanged

  Scenario: the requester still cannot self-complete
    Given the requester is not the coordinator, creator, or governance
    When the requester calls completeJob
    Then the call reverts with "Not authorized"
    # buyers must never be able to trigger provider payment for unverified work

  Scenario: an unrelated outsider cannot settle
    Given an address that is not governance, creator, nor job.dispatchedBy
    When it calls completeJob or failJob
    Then the call reverts with "Not authorized"

  # ── G2: requester reclaim after a hard deadline (refund-on-timeout) ──

  Scenario: the requester reclaims escrow after JOB_DEADLINE elapses
    Given a job that is still Pending or Executing
    And JOB_DEADLINE blocks have passed since job.createdAt
    When the requester calls reclaimExpiredJob
    Then the job becomes Failed
    And the requester is refunded exactly job.payment
    And a JobReclaimed event is emitted
    And the pool's activeJobCount is decremented

  Scenario: reclaim before the deadline is rejected
    Given a job whose JOB_DEADLINE has not yet elapsed
    When the requester calls reclaimExpiredJob
    Then the call reverts with "Not expired"

  Scenario: a non-requester cannot reclaim
    Given an address that is not the job.requester
    When it calls reclaimExpiredJob after the deadline
    Then the call reverts with "Not requester"

  Scenario: a completed job cannot be reclaimed
    Given a job that has already been Completed
    When the requester calls reclaimExpiredJob after the deadline
    Then the call reverts with "Not open"
    # terminal monotonicity — guards the reclaim-after-complete race

  Scenario: a job cannot be both paid and refunded (no double-spend of escrow)
    Given any reachable sequence of dispatch / complete / fail / reclaim calls
    Then a job's payment is paid out, or refunded, or still escrowed — never two of these
    And reclaimExpiredJob never returns more than job.payment
