Feature: ComputePool InferencePool dispatch (CM-05)
  As a buyer who wants higher reliability and aggregated capacity
  I want to send a request to a pool and let the pool's coordinator
  dispatch to one of its members
  So that I get an answer even when individual providers flake out

  Background:
    Given a Citrate testnet with ComputePool deployed
    And a pool "pool-llama-70b" exists with 3 members:
      | address | gpuCount |
      | 0xa1…   | 1        |
      | 0xa2…   | 2        |
      | 0xa3…   | 1        |
    And each member runs a citrate-pool-coordinator binary
    And the gateway from CM-03 is running and configured to dispatch to pools

  # ── Coordinator election ──

  Scenario: Coordinator is deterministic per epoch
    When I read coordinatorFor(pool, epoch=42) twice
    Then both calls return the same address

  Scenario: Coordinator rotates across epoch boundary
    Given the coordinator at epoch=10 is C1
    When epoch advances to 11 (100 blocks later)
    Then coordinatorFor(pool, epoch=11) MAY be different from C1
    And the on-chain CoordinatorElected event fires for the new epoch

  Scenario: Coordinator weight is proportional to gpuCount
    Given a member with gpuCount=8 and another with gpuCount=1
    When I sample coordinatorFor(pool, epoch=...) across 1000 epochs
    Then the high-gpuCount member is elected approximately 8x as often
    # Statistical assertion; tolerance ±20%

  Scenario: Pool with no members rejects coordinatorFor
    Given a pool with zero current members
    When I call coordinatorFor(pool, epoch=any)
    Then the call reverts with NoMembers

  # ── Dispatch happy path ──

  Scenario: Single chat request reaches a pool member and completes
    Given the gateway treats "pool-llama-70b" as a provider entry
    When I POST /v1/chat/completions with model="pool-llama-70b"
    Then the gateway calls requestPoolCompute on the pool
    And the elected coordinator dispatches to one member via /pool-infer
    And the member returns an OpenAI-shape response
    And the coordinator submits completeJob within 5 blocks
    And payment distributes to all members proportional to gpuCount
    And the gateway returns the completion to me as 200 OK

  Scenario: Round-robin distribution across 9 sequential requests
    When I POST 9 chat completions to the pool sequentially
    Then each member receives exactly 3 dispatches
    # Stateless round-robin via hash(jobId) % memberCount; with 9
    # sequentially-id'd jobs and 3 members, the distribution is exact.

  Scenario: Batch request (10 prompts) splits across pool
    When I POST /v1/batch with 10 chat requests against the pool
    Then the coordinator dispatches each request to a member
    And total payment to each member equals their proportion of gpuCount
    And the batch reaches "completed" within 60s
    And /v1/batch/{id}/output returns 10 results

  # ── Coordinator failover ──

  Scenario: Coordinator goes offline mid-dispatch
    Given the elected coordinator C1 has accepted a job
    And C1 has not submitted completeJob within CoordinationTimeout (20 blocks)
    When any other pool member calls reassignCoordinator(jobId)
    Then the contract emits CoordinatorReassigned(jobId, new=C2)
    And C1 is slashed 0.1% of stake (CoordinatorSlashedForLiveness event)
    And pool.totalStaked decreases by the slash (totalStaked == sum of member stakes)
    And the slash is retained in slashedStakeRetained (governance sweep)
    And C1's activeJobs is decremented
    And C2 picks up dispatch within 5 blocks

  Scenario: Reassignment before timeout is rejected
    Given a coordinator C1 has just dispatched a job (block.number = N)
    When another member calls reassignCoordinator(jobId) at block N+5
    Then the call reverts with "Coordinator has time"

  Scenario: All members offline → job fails after exhausting retries
    Given a 2-member pool where both members are unreachable
    When a job is dispatched and times out
    And reassignment also times out
    Then the job transitions to Failed
    And all paid escrow refunds to the buyer (FailedJobRefundedAll
        invariant from InferencePoolLifecycle.tla)

  # ── Member churn ──

  Scenario: Member joins mid-flight without disrupting in-flight job
    Given a job J is currently Dispatched to member M
    When a new member M_new calls joinPool
    Then J's assignedMember remains M
    And J completes normally
    And M_new becomes eligible for dispatch starting at the NEXT job

  Scenario: Member with in-flight job cannot leave
    Given member M has been dispatched job J (recordDispatch increments M.activeJobs)
    And M called requestLeave and LEAVE_COOLDOWN blocks have passed
    When M calls leavePool
    Then the call reverts with "Has active jobs"
    # Spec: Leave in specs/tla/compute/ComputePoolSettlement.tla requires
    # activeJobs = 0 (NoLeaveWithOpenDispatch). PBA-L2-022.

  Scenario: Leaving is two-step (PBA-L2-022)
    Given member M has no in-flight assignments
    When M calls leavePool without calling requestLeave first
    Then the call reverts with "Leave not requested"
    When M calls requestLeave
    And M calls leavePool before LEAVE_COOLDOWN (150) blocks have passed
    Then the call reverts with "Leave cooldown"
    And M remains an active, slashable member during the cooldown

  Scenario: Member with no in-flight jobs leaves cleanly
    Given member M has no in-flight assignments
    And M called requestLeave at least LEAVE_COOLDOWN blocks ago
    When M calls leavePool
    Then poolMembers no longer contains M
    And M's remaining stake is returned (credited to payoutPending if the transfer fails)

  # ── Pool dissolution ──

  Scenario: Dissolve pool when no in-flight jobs
    Given a pool with no in-flight jobs
    When the pool admin calls dissolvePool
    Then poolState becomes Dissolved
    And new requestPoolCompute calls revert with PoolDissolved

  Scenario: Cannot dissolve pool with in-flight jobs
    Given a pool with at least one Dispatched or Responded job
    When dissolvePool is called
    Then the call reverts
    # DissolvePool precondition in spec.

  # ── Escrow conservation ──

  # Mirrors InferencePoolLifecycle.tla's EscrowBalances +
  # TerminalEscrowSettled invariants. Verified at the implementation
  # layer via integration test that watches the on-chain balances
  # before/after each pool job.
  Scenario: Escrow accounting on completed job
    Given a pool job with paidEscrow = X grains
    When the job reaches Completed
    Then sum(distributed_to_members) = X
    And refunded_to_buyer = 0

  Scenario: Escrow accounting on failed job
    Given a pool job with paidEscrow = X grains
    When the job reaches Failed
    Then refunded_to_buyer = X
    And sum(distributed_to_members) = 0

  # ── Gateway integration ──

  Scenario: Gateway prefers a pool over individual provider when both serve a model
    Given an individual provider with reputation 9000 bps and stake 100 SALT
    And a pool with min-member-reputation 9500 bps and pool stake 500 SALT
    When the gateway selects a provider for the model
    Then the pool is chosen (per pool-vs-individual scoring)
    # Configurable; default weight favors pools when their score is competitive.

  Scenario: Pool appears in /v1/models alongside individual providers
    When I GET /v1/models
    Then the response includes both individual provider model IDs
    And pool model IDs prefixed with "pool-"
