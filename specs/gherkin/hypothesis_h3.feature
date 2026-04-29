# RM-FL-5 / WP-5.2 — Hypothesis H3 experiment harness (30-node testnet).
#
# H3 (Paper II §4): Routing-model parameter drift across checkpoints
# converges (or diverges sub-linearly) under K Byzantine validators,
# for K up to a stated fraction of the validator set (BFT threshold:
# K < N/3).
#
# Per CORE_RULES Rule 11, every scenario names its data source.
#
# Spec sources:
#   - specs/tla/learning/HypothesisH3.tla     (5 inv, 257 states clean)
#   - specs/tla/learning/ByzantineDetection.tla
#   - specs/tla/learning/StrobilationCheckpoint.tla
#
# Code targets:
#   - core/experiment-runner/src/h3.rs        (H3 rig at WP-5.7)
#
# Reference: planset RM_FL_2026_04_28/00_PLANSET.md §RM-FL-5.

Feature: Hypothesis H3 — Byzantine convergence below the BFT threshold
  As a Citrate researcher
  I want to measure routing-model parameter drift under K Byzantine
    validators for K = 0%, 10%, 20%, 30% of the validator set
  So that we can decide whether the protocol converges sub-linearly
    in K up to the BFT threshold (K < N/3)

  Background: 30-node testnet with seeded Byzantine selection
    Given the validator-set RNG seed is pinned in scripts/h3/byzantine_seed.txt
    And 30 validators are running citrate-node + citrate-learning-daemon
    And the BFT committee size is 100 (testnet config) but only the
      first 30 deterministic positions are used for this experiment
    And each cycle is 50 blocks (~25s); the experiment runs 100 cycles
      per K value (~42 minutes per sweep point)

  # ----------------------------------------------------------------
  # HypothesisH3.tla::ByzantineCountWithinThreshold pinned empirically.
  # K = 30% sits AT the BFT threshold (3K = N exactly), expected to
  # show degraded convergence. K > 33% should fail to finalize at all.
  # ----------------------------------------------------------------
  Scenario Outline: Byzantine fraction sweep — measure parameter drift
    Given <K_pct>% of validators are configured Byzantine
    And Byzantine validators submit adversarial embeddings (random Q16
      values in the legal range)
    When the experiment runs for 100 checkpoints
    Then per-checkpoint parameter drift is measured as the L2 norm of
      the delta in routing-model weights vs the K=0% baseline
    And the drift series is recorded under
      experiments_2026_04/h3_K<K_pct>.csv
    And cycle finalization rate is recorded (cycles_finalized / 100)

    Examples:
      | K_pct |
      | 0     |
      | 10    |
      | 20    |
      | 30    |

  # ----------------------------------------------------------------
  # The H3 strong claim: drift grows sub-linearly in K for K < 33%.
  # ----------------------------------------------------------------
  Scenario: Fit drift-vs-K relationship
    Given drift measurements at K ∈ {0, 10, 20, 30}
    When both linear and logarithmic models are fit to drift vs K
    Then the model with the lower BIC (Bayesian Information Criterion)
      is reported as the better fit
    And if the logarithmic model wins, H3's sub-linear claim is
      empirically supported
    And if the linear model wins, H3 is Falsified — drift grows
      proportionally to K, not sub-linearly

  # ----------------------------------------------------------------
  # HypothesisH3.tla::NoByzantineFinalization pinned empirically.
  # ----------------------------------------------------------------
  Scenario: Byzantine-only quorum cannot finalize a checkpoint
    Given 6 validators (out of 30 = 20%) are Byzantine
    And all 6 Byzantine validators vote "commit" with a coordinated
      malicious candidate
    And all 24 honest validators vote "abstain" or "against"
    When checkpoint finalization is attempted
    Then no checkpoint finalizes (commit count = 6 < quorum = 21)
    And the malicious candidate never enters the routing model

  # ----------------------------------------------------------------
  # Above the BFT threshold, the protocol's convergence claim does
  # NOT apply. This scenario verifies that fact — at K = 34%, we
  # expect convergence to break down.
  # ----------------------------------------------------------------
  Scenario: Above-threshold control — K = 34% should fail to converge
    Given 11 validators (out of 30 ≈ 36.7%) are Byzantine
    When the experiment runs for 100 checkpoints
    Then either cycle finalization rate drops below 50% OR drift grows
      without bound (ratio drift_K34 / drift_K0 > 100×)
    And this is reported as the EXPECTED breakdown above the BFT
      threshold, NOT as a falsification of H3

  # ----------------------------------------------------------------
  # Reproducibility — same Byzantine seed picks same validators.
  # WP-5.8 tripwire enforces the seed is pinned.
  # ----------------------------------------------------------------
  Scenario: Same Byzantine-seed produces identical Byzantine set
    Given the experiment was run with seed S
    And the recorded Byzantine validator set is B = {v_i_1, ..., v_i_K}
    When the experiment is re-run with the same seed S
    Then the new run picks the same validator set B in the same order
    And the recorded drift series is within RNG-tolerance of the
      original run (≤ 1% L2 deviation per checkpoint)

  # ----------------------------------------------------------------
  # Falsification gate.
  # ----------------------------------------------------------------
  Scenario: Falsification — drift grows super-linearly below threshold
    Given drift measurements at K ∈ {0, 10, 20, 30}
    When the linear model significantly OUTPERFORMS the logarithmic
      model (BIC delta > 10) AND drift_K30 / drift_K0 > 5×
    Then H3 is reported as FALSIFIED — drift is super-linear, not
      sub-linear
    And Paper II §4 is updated with status Falsified
    And the closing essay names the negative result honestly
