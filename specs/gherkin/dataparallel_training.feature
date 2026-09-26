Feature: ComputePool DataParallel federated training (CM-07)
  As an AI company who wants to train a model on data that shouldn't
  leave the institution perimeter
  I want to pay a heterogeneous pool of providers to run synchronous
  data-parallel training with per-step on-chain commitments
  So that I get a trained model whose integrity is verifiable and
  any cheating worker is slashed

  Background:
    Given a Citrate testnet with ComputePool v3 deployed at 0xpool
    And BulkComputeGateway and StablecoinTreasury deployed for payment
    And the training-job VRF coordinator rotation is wired from CM-05
    And a dataset shard root 0xdataset pinned to IPFS with 4 shards
    And a model start hash 0xmodel0 representing the initial weights
    And three provider nodes w1, w2, w3 each running
      `citrate-training-worker` with GPU access

  # ── Happy path ──

  Scenario: Three-worker job completes two epochs and finalizes
    When a buyer calls requestPoolCompute with:
      | field                  | value         |
      | mode                   | DataParallel  |
      | modelStartHash         | 0xmodel0      |
      | datasetHash            | 0xdataset     |
      | epochCount             | 2             |
      | stepsPerEpoch          | 2             |
      | minWorkers             | 3             |
      | maxWorkers             | 3             |
      | perEpochBudget         | 100 SALT      |
    Then a TrainingJobOpened event fires with jobId=J
    And w1, w2, w3 each call joinTrainingJob(J) posting stake
    And WorkerJoined fires three times
    When the coordinator calls closeRecruitment(J)
    Then RecruitmentClosed fires with workerCount=3
    And the coordinator for epoch=0 is elected via VRF
    When each worker commits step 0 then step 1 for epoch 0
    Then StepCommitted fires 6 times (3 workers × 2 steps)
    When the coordinator calls commitEpoch(J, 0, root0)
    Then EpochCommitted fires for epoch 0
    And epochCommitment[J][0] equals root0
    When the coordinator for epoch 1 repeats the cycle
    Then EpochCommitted fires for epoch 1
    When challengeWindowBlocks elapse with no challenges
    And finalizeTrainingJob(J) is called
    Then TrainingJobCompleted fires with finalWeightsHash=0xmodel2
    And payment distributed via ComputePool.completeJob accounting
    And each worker's remaining stake returned via
      `BulkComputeGateway.withdrawWorkerStake`

  # ── Coordinator failure ──

  Scenario: Coordinator crashes mid-epoch; next epoch elects a new one
    Given job J is in Training state at epoch=0 step=1
    When the coordinator for epoch 0 goes offline mid-epoch
    And StepCommitted events for step 1 from w2 and w3 still land
    But the coordinator never submits commitEpoch(J, 0, _)
    Then the on-chain coordinatorFor(J, epoch=0) remains set (liveness TBD)
    When CoordinationTimeout blocks pass and the requester calls
      `reassignCoordinator(J, newCoordinator)`
    Then the coordinator is replaced by the requester's choice
    And the original coordinator is NOT slashed (a requester swap is not a
      stall adjudication; epochs routinely exceed CoordinationTimeout)
    And training resumes
    # PBA-L2-003: only the requester or governance may appoint a coordinator.
    # A joined worker calling reassignCoordinator reverts "not authorized".

  Scenario: Governance adjudicates a stalled coordinator
    Given job J is in Training state and its coordinator made no progress
      for CoordinationTimeout blocks
    When governance calls `reassignCoordinator(J, newCoordinator)`
    Then the stalled coordinator is liveness-slashed 0.1% of its stake
    And the slash is retained in retainedSlashAndBonds (sweepRetained)

  Scenario: Requester disappears; workers expire the stalled job
    Given job J is in Training state with no commitEpoch for STALL_EXPIRY_BLOCKS
    When any joined worker calls `expireStalledTraining(J)`
    Then J moves to Awaiting and the challenge window starts
    And after the window finalizeTrainingJob pays committed epochs and
      refunds the uncommitted budget to the requester

  # ── Worker drop-out ──

  Scenario: Worker drops out mid-step; epoch cannot commit until resolved
    Given job J is in Training state at epoch=1 step=0
    And w1 has committed step 0 for epoch 1
    When w2 goes offline before committing step 0 of epoch 1
    Then StepCommitted never fires for w2 at <epoch=1, step=0>
    And commitEpoch(J, 1, _) by the coordinator reverts with
      `EpochNotFullyCommitted`
    When governance declares w2 dropped via
      `ComputePool.declareWorkerDropped(J, w2)`
    Then w2's remaining stake is slashed per the drop-out policy
    And the remaining workers continue with epoch reduced to w1, w3
    And the buyer's escrow is partially refunded proportional to
      `CreditBilling.refundPartial` accounting

  # ── Malicious worker ──

  Scenario: Malicious worker submits bogus gradient; challenger slashes them
    Given w1 has committed step 0 for epoch 0 with commitment C1
    And a challenger (another worker or external verifier) recomputes
      step 0 and produces commitment C1' != C1
    When the challenger calls challengeStep(J, 0, 0, w1, C1')
      posting ChallengeBond
    Then ChallengeOpened fires with challenger, target=w1
    When the committee votes Uphold with quorum
    And resolveChallenge(J, 0, 0, w1, recomputationProof) is called
    Then ChallengeResolved fires with winner=challenger, slashed=w1
    And w1's targetSlashed ledger increases by SlashAmount
    And challenger's challengerReward ledger increases by
      `ChallengeBond + SlashAmount/2`
    # Per DataParallelEscrow invariant: `posted == paid + slashed +
    # returned + held` at all times.

  # ── False challenge ──

  Scenario: False challenger forfeits bond; target untouched
    Given w1 has legitimately committed step 0 for epoch 0 with commitment C1
    When a griefer calls challengeStep(J, 0, 0, w1, C_wrong)
      posting ChallengeBond
    Then ChallengeOpened fires
    When the committee votes Reject with quorum
    And resolveChallenge is called
    Then ChallengeResolved fires with winner=w1, slashed=challenger
    And the griefer's challengerForfeit ledger increases by ChallengeBond
    And w1's targetSlashed ledger is unchanged
    And w1's per-epoch payment at commitEpoch proceeds normally

  # ── Committee deadlock → governance ──

  Scenario: Committee deadlocks; governance resolves
    Given a challenge against w1 at epoch=0 step=0 is Opened
    When votes are split 1 Uphold, 1 Reject, 1 Abstain (no quorum)
    And voting window elapses
    Then ComputePool.declareDeadlock(J, 0, 0, w1, challenger) succeeds
    And the challenge moves to Deadlock state
    When governance multi-sig calls governanceResolve(J, 0, 0, w1,
      challenger, decision=Uphold)
    Then GovernanceResolved fires with decision=Uphold
    And the slash + reward bookkeeping applies identically to the
      committee-quorum path

  # ── Stake conservation ──

  Scenario: Per-worker stake accounting holds across the full job
    Given job J has completed three epochs with two payment releases
      and one slash against w2
    When I read w1's ledger via ComputePool.workerLedger(J, w1)
    Then `posted - paid - slashed - returned == held`
    And the sum over all workers of (paid + slashed + returned +
      held) equals the total posted stake
    # Per the DataParallelEscrow.tla StakeConservation invariant.

  # ── Job-level escrow sanity ──

  Scenario: perEpochBudget ceiling is never exceeded
    Given job J has perEpochBudget = 100 SALT and epochCount = 2
    When all payment-release events are summed per epoch
    Then for every epoch e in [0, 1]:
      `epochPaid[J][e] <= 100 SALT`
    # Per the DataParallelEscrow.tla EpochBudgetRespected invariant.

  # ── Integration: payment via credits path ──

  Scenario: Buyer pays via BulkComputeGateway credits instead of SALT
    Given the buyer holds credits in BulkComputeGateway
    When the buyer calls requestPoolCompute with
      `paymentMethod = PaymentMethod.BulkCredits`
    Then `msg.value` on the tx is 0 (NoMixedPayment guard from CM-06)
    And ComputePool debits credits via
      `BulkComputeGateway.spendCredits(buyer, creditAmount)`
    And CreditsSpent fires per the CreditBilling.tla semantics
    And the training lifecycle proceeds identically to the SALT path
