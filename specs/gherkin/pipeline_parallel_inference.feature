Feature: ComputePool PipelineParallel frontier-model inference (CM-08)
  As a buyer who wants inference from a model that does not fit on
  any single GPU
  I want to send a request to a pool whose members each hold one
  stage of the model and cooperatively serve the request
  So that I can use frontier-scale models (70B, 405B) on commodity
  GPU clusters with cryptographic guarantees each stage ran in an
  attested TEE

  Background:
    Given a Citrate testnet with ComputePoolPipeline (CM-08) v1 deployed
    And BulkComputeGateway + StablecoinTreasury from CM-06 for payment
    And the gateway from CM-03 reconfigured to route pipeline-tagged
      models through ComputePoolPipeline
    And a model "llama-3.1-70b" registered with stageCount=4, meaning
      layers split across 4 stages of ~17.5 B parameters each
    And four provider nodes w1..w4 each running
      `citrate-training-worker` (dual-use: inference via pipeline mode)
      with NVIDIA H100 Confidential Computing + Azure MAA attestation

  # ── Happy path ──

  Scenario: Four-stage 70B chat completion serves end-to-end
    Given a pipeline pool exists with stage 0 → w1, stage 1 → w2,
      stage 2 → w3, stage 3 → w4
    And all four workers hold valid TEE attestations (not expired)
    When I POST /v1/chat/completions with model="llama-3.1-70b" and
      a 2048-token prompt
    Then the gateway calls `requestPipelineCompute` on the pool
    And w1 receives the prompt, runs its layer slice in TEE, and
      forwards activation to w2 via libp2p
    And w2 receives the activation, runs its layers, forwards to w3
    And w3 forwards to w4
    And w4 emits generated tokens back to the gateway as a stream
    And the on-chain `PipelineRequestCompleted` event fires with all
      four stages recorded
    And payment distributes per the `PipelineParallelEscrow` spec:
      `share = payment / stageCount` credited to each stage

  # ── Stage fault + reassignment ──

  Scenario: Stage 2 crashes mid-request; replacement re-plays the activation
    Given a pipeline request is mid-flight; activation has reached w3
      (stage 2)
    And w3 crashes before emitting its output
    When a stage owner (or governance) calls `faultStage(jobId, stage=2)`
    Then the `StageFaulted` event fires with `former=w3`
    And w3's own stage stake and accrued earnings are returned to w3
      (credited to payoutPending, claimable via `claimPayout`, if w3's
      receive reverts, so a faulted owner cannot block the fault)
    When an attested worker that holds no other stage calls
      `reassignStage(jobId, stage=2)` posting exactly perStakePerStage
    Then the on-chain `StageReassigned` event fires with
      `former=w3`, `newOwner=<replacement>`
    And w3 cannot take stage 2 back ("Pipeline: former cannot take back")
    And the activation for the in-flight request is re-played to the
      new stage 2 owner from w2's mesh archive
    And the request completes normally from stage 3 onward
    # Per the PipelineParallelInference.tla ReassignStage action and
    # InFlightAtOwnedOrAtFaultBoundary invariant.

  # ── TEE attestation lifecycle ──

  Scenario: Worker re-attests before expiry and keeps serving
    Given w2 has an attestation expiring at block 100
    And the current block is 95
    When w2 calls `submitAttestation(azureMaaSignedEvidence)` with
      a fresh H100 NRAS claim
    Then `attestExpiry[w2]` is bumped to `currentBlock +
      AttestationLifetime`
    And w2's `attestState` remains `Attested`
    And w2 continues serving requests without interruption
    # Per the PipelineParallelTEE.tla Attest action.

  Scenario: Worker's attestation expires; they stop serving until re-attest
    Given w2 has an attestation expiring at block 100
    And the current block passes 100 without re-attestation
    Then w2's `attestState` auto-transitions to `Expired`
    And any `requestPipelineCompute` that would route through w2
      reverts with `ComputePoolPipeline: stage 1 not attested`
    When w2 calls `submitAttestation` at block 110
    Then w2 re-enters `Attested` state and can serve again
    # AttestedHasFutureExpiry + ExpiredHasPastExpiry invariants.

  Scenario: Adversarial worker serves while expired and is slashed
    Given w3's attestation expired at block 80
    And w3 did NOT re-attest
    And w3 bypasses the contract-side check (attempts to respond
      directly to w2's libp2p forward with an activation)
    When an honest observer calls `reportExpiredServe(poolId,
      w3, evidenceSignature, expiredAtBlock=80, servedAtBlock=85)`
    Then `attestState[w3]` moves to `Slashed`
    And w3 is slashed SLASH_BPS (10%) of their posted stake
    And the reporter is rewarded bond + half-slash per the same
      pattern as CM-07's ChallengeResolved
    # SlashedImpliesServedWhileExpired invariant.

  # ── Token streaming ──

  Scenario: Last-stage streaming works incrementally
    Given a pipeline request for a 512-token output is mid-flight
    And the activation has reached w4 (terminal stage)
    When w4 generates token 1
    Then the gateway receives token 1 and streams it to the client
      via SSE / chunked HTTP
    And w4 generates token 2, ..., token 512 in sequence
    And each token arrives at the client within the per-token
      latency SLA (target ≤150 ms at N-hop mesh depth)

  # ── Multi-request concurrency ──

  Scenario: Two requests can share a pipeline without interfering
    Given a pipeline pool with 4 stages is active
    When two independent /v1/chat/completions arrive simultaneously
      (req_A and req_B)
    Then req_A and req_B enter the pipeline concurrently
    And each stage processes req_A and req_B independently — no
      activations cross
    And both requests complete with distinct
      `PipelineRequestCompleted` events
    # StageOwnershipUnique does NOT preclude concurrent requests;
    # only per-stage worker assignment.

  # ── Escrow + partial-serve failure ──

  Scenario: Request fails mid-flight; requester gets partial refund
    Given a pipeline request with payment = 6 SALT, split 4 ways
      (1.5 SALT per stage)
    And the request passed stages 0 and 1 (both paid 1.5 SALT)
    And stage 2 fails and no reassignment succeeds within timeout
    When the request is marked `Failed` on-chain
    Then stage 0 worker keeps 1.5 SALT (earned)
    And stage 1 worker keeps 1.5 SALT (earned)
    And stage 2 worker receives 0 (never served)
    And stage 3 worker receives 0 (never reached)
    And the requester is refunded 3 SALT (6 − 3 served)
    # PaymentConservation + FailedRefundAccountsForUnserved
    # invariants from PipelineParallelEscrow.tla.

  # ── Integration: credits path ──

  Scenario: Buyer pays via BulkComputeGateway credits
    Given the buyer holds PFLOP-hour credits in BulkComputeGateway
    When the buyer submits a pipeline request with
      `paymentMethod = PaymentMethod.BulkCredits`
    Then `msg.value = 0` (NoMixedPayment guard from CM-06)
    And ComputePoolPipeline debits credits via
      `BulkComputeGateway.spendCredits`
    And CreditsSpent fires per the CreditBilling.tla semantics
    And the pipeline lifecycle proceeds identically to the SALT path

  # ── Drain + terminate ──

  Scenario: Pool stops accepting new requests during drain
    Given a pipeline pool is Active and has 2 in-flight requests
    When the pool creator calls `drainPool(poolId)`
    Then the pool transitions to `Draining`
    And any NEW `/v1/chat/completions` for that pool returns
      `PoolDraining` immediately
    And the 2 in-flight requests continue to completion
    When both in-flight requests terminate (Completed or Failed)
    And the creator calls `terminatePool(poolId)`
    Then the pool transitions to `Terminated`
    And all worker stakes return per the `PipelineParallelEscrow`
      spec's terminal conservation
    # StartDraining + TerminateJob actions from
    # PipelineParallelInference.tla + TerminatedIsClean invariant.
