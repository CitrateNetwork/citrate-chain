# RM-FL-4 / WP-4.2 — Mentor-mentee matching + adapter verification
#
# Per CORE_RULES Rule 11, every scenario names its data source: the
# TLA+ spec, the on-chain contract or precompile, the off-chain Rust
# reference impl.
#
# Spec sources:
#   - specs/tla/learning/MentorSelection.tla    (audit GREEN; 7 inv, 112K states)
#   - specs/tla/learning/MentorAdversarial.tla  (WP-4.1; 7 inv, 13.5M states)
#
# Code targets (WP-4.5–WP-4.7):
#   - contracts/src/MentorMatcher.sol           (new at WP-4.5)
#   - contracts/src/ContributionAccounting.sol  (per-dim score at WP-4.6)
#   - contracts/src/LoRAFactory.sol             (verifyAdapterAt at WP-4.7)
#   - core/learning/src/mentor.rs               (existing off-chain reference)
#
# Reference: planset RM_FL_2026_04_28/00_PLANSET.md §RM-FL-4.

Feature: Mentor-mentee matching + adapter verification flow
  As a mentee in the federated learning network
  I want to be paired with a higher-accuracy mentor on my weak dimensions
  And to verify that an adapter advertised by a mentor was actually
    produced by training over the claimed benchmark
  So that mentor-mentee pairings are fair, capacity-bounded, and
    adapter quality is cryptographically backed via 0x0108 INFERENCE_PROOF_VERIFY

  Background:
    Given the Citrate testnet (chain id 40204) is live
    And the inference-proof-verify precompile is dispatched at 0x0108
    And LearningCycleManager is deployed at 0x20a0B74c766E84B20558ABD76a7a0Fd6434A4c4c
    And LoRAFactory is deployed at 0xAc6Bfb1709BCba5A005FE2823B4D8bC55db2b7D9
    And ContributionAccounting is deployed at 0x1AFE000000000000000000000000000000007b6F
    And the MentorMatcher contract is deployed and registered
      with a per-mentor cap M_max = 3 (governance-mutable)
    And the trust floor is set to accuracy >= 0.30 (Q16: 19661)

  # ─────────────────────────────────────────────────────────────────
  # Scenario 1 — Standard match: a clear accuracy gap, no contention
  # ─────────────────────────────────────────────────────────────────
  Scenario: Standard mentor match with adequate accuracy gap
    # Maps to MentorSelection.tla::Pair action;
    # exercises ValidPairing predicate and DomainOverlapPreferred.
    Given mentor M_A has overall accuracy 0.85 and domain {finance}
    And mentee Q_B has overall accuracy 0.40 and domain {finance, tech}
    And the per-dimension gap on `finance` between M_A and Q_B is >= MinAccuracyGap
    And MentorMatcher.mentorLoad[M_A] = 0
    When the matcher's pairing pass runs over the cycle's eligible candidates
    Then a single pairing record [mentor=M_A, mentee=Q_B, dimension=finance]
      is committed to MentorMatcher state via assignMentees(M_A, [Q_B], deadline)
    And MentorMatcher.mentorLoad[M_A] increments to 1
    And the daemon's dashboard cache reflects the new pairing on next tick
    And no `MentorOverCapacity` event fires

  # ─────────────────────────────────────────────────────────────────
  # Scenario 2 — No qualified mentor (gap below threshold or trust floor)
  # ─────────────────────────────────────────────────────────────────
  Scenario: Mentee receives no pairing when no mentor clears trust floor
    # Maps to MentorAdversarial.tla::TrustFloorAtPairing invariant.
    Given mentee Q_B has overall accuracy 0.40
    And every candidate mentor has accuracy < 0.30 (below the trust floor)
    When the matcher's pairing pass runs
    Then no pairing record is committed for Q_B
    And the matcher emits `NoQualifiedMentor(menteeId=Q_B, cycleId=N)` event
    And mentee Q_B's state remains unchanged

  # ─────────────────────────────────────────────────────────────────
  # Scenario 3 — Mentor at capacity declines further mentees
  # ─────────────────────────────────────────────────────────────────
  Scenario: Mentor at capacity is skipped in favor of next-best
    # Maps to MentorAdversarial.tla::CapacityHoldsUnderAdversary.
    Given mentor M_A has accuracy 0.85 and mentorLoad = M_max (3)
    And mentor M_C has accuracy 0.78 and mentorLoad = 0
    And mentee Q_B has accuracy 0.40 — both M_A and M_C clear MinAccuracyGap
    When the matcher's pairing pass runs
    Then the pairing committed is [mentor=M_C, mentee=Q_B] (NOT M_A)
    And M_A's mentorLoad remains at M_max
    And no `Pair` action attempts to add a 4th mentee to M_A on chain

  # ─────────────────────────────────────────────────────────────────
  # Scenario 4 — Adversarial low-blue-score candidate is filtered
  # ─────────────────────────────────────────────────────────────────
  Scenario: Sybil mentor below trust floor cannot capture mentees
    # Maps to MentorAdversarial.tla::NoSybilCaptureAtTrustFloor.
    Given a sybil cluster of three keys [S_1, S_2, S_3] each with
      overall accuracy 0.20 (below the 0.30 trust floor)
    And the sybils each claim a per-dimension accuracy of 0.95 on `finance`
    And mentee Q_B has accuracy 0.40 on `finance`
    When the matcher's pairing pass runs
    Then no pairing record names any sybil as the mentor
    # The trust floor check operates on the sybil's blue-score-weighted
    # overall accuracy, NOT on a per-dimension claim
    And the matcher emits no `Pair` event involving the sybil cluster

  # ─────────────────────────────────────────────────────────────────
  # Scenario 5 — Weight update mid-matching does not retroactively
  # invalidate committed pairings
  # ─────────────────────────────────────────────────────────────────
  Scenario: Mentor accuracy drop after pairing is committed leaves the pairing intact
    # Maps to MentorAdversarial.tla::PairingAccuracyGapPreservedAtCommit.
    # Mirrors RM-FL-3 essay THE_TRAINING_DAEMON_BET — the chain is canonical;
    # local rollback is not an option, so committed pairings encode their
    # mentor's pair-time accuracy.
    Given a pairing record [mentor=M_A, mentee=Q_B, mentorAccAtPair=0.85]
      already exists on chain
    When mentor M_A's accuracy is updated to 0.32 in a later cycle
    Then the existing pairing record is unchanged on chain
    And `MentorMatcher.getPairing(M_A, Q_B)` still returns the record with
      mentorAccAtPair = 0.85
    And future pairing passes use the updated 0.32 accuracy for new candidates,
      potentially skipping M_A on the trust floor

  # ─────────────────────────────────────────────────────────────────
  # Scenario 6 — Adapter verification: success path
  # ─────────────────────────────────────────────────────────────────
  Scenario: Mentee verifies a mentor's adapter via 0x0108
    # Maps to LoRAFactory.verifyAdapterAt → 0x0108 INFERENCE_PROOF_VERIFY.
    Given mentor M_A has registered adapter A_42 on LoRAFactory
    And M_A has published a benchmark input vector and expected output
    And M_A has produced a Halo2 proof bytes blob attesting to the
      benchmark input → expected output mapping
    When mentee Q_B calls
      `LoRAFactory.verifyAdapterAt(adapterId=A_42, benchmark_input,
                                   expected_output, proof_bytes)`
    Then the contract calls precompile 0x0108 with the adapter weights,
      benchmark IO, and proof
    And the precompile returns success
    And LoRAFactory emits `AdapterVerified(adapterId=A_42, verifierAddr=Q_B,
                                          blockNumber=N)`
    And LoRAFactory marks adapter A_42 as proof-backed in its registry

  # ─────────────────────────────────────────────────────────────────
  # Scenario 7 — Adapter verification: failure path (bad proof)
  # ─────────────────────────────────────────────────────────────────
  Scenario: Mentee receives a clean failure when proof is invalid
    Given mentor M_A has registered adapter A_43 on LoRAFactory
    And the proof_bytes provided by M_A do NOT verify against the
      claimed benchmark IO
    When mentee Q_B calls
      `LoRAFactory.verifyAdapterAt(A_43, benchmark_input,
                                   expected_output, bad_proof_bytes)`
    Then the contract calls 0x0108 with the proof
    And the precompile returns failure
    And the LoRAFactory call reverts with `AdapterProofRejected(adapterId=A_43)`
    And no `AdapterVerified` event fires
    And A_43 is NOT marked as proof-backed

  # ─────────────────────────────────────────────────────────────────
  # Scenario 8 — Per-dimension score lookup respects laziness
  # ─────────────────────────────────────────────────────────────────
  Scenario: Per-dimension score is computed on demand, not eagerly
    # Maps to WP-4.9 optimization: lazy mentee profile.
    Given participant P has produced contributions across 5 cycles
    And ContributionAccounting has recorded their per-cycle contributions
    And the matcher has not yet requested per-dimension scores for P
    When the matcher calls `ContributionAccounting.getDimensionScore(P, finance)`
    Then the contract computes the per-dim score from the recorded
      contributions at read time
    And the score is returned to the matcher in a single eth_call
    And no per-dim state was written eagerly per cycle (gas savings)
    And subsequent calls to `getDimensionScore(P, tech)` for the same P
      compute that dimension fresh — caching is the matcher's responsibility,
      not the contract's
