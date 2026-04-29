# RM-FL-5 / WP-5.2 — Hypothesis H1 experiment harness (4-node testnet).
#
# H1 (Paper II §4): Belnap-FOUR aggregation is more robust to mislabel-
# injection adversaries than flat-mean aggregation. Stated operationally:
# given mislabel rate p in one of M regions, the routing model trained
# on Belnap-aggregated embeddings achieves held-out accuracy at least
# equal to the model trained on flat-mean-aggregated embeddings, for
# all p in [0, 0.5].
#
# Per CORE_RULES Rule 11, every scenario names its data source.
#
# Spec sources:
#   - specs/tla/learning/HypothesisH1.tla     (5 inv, 12.7M states clean)
#   - specs/tla/learning/BelnapLattice.tla    (Belnap-FOUR semantics)
#
# Code targets (this sprint):
#   - core/experiment-runner/                 (new crate at WP-5.9)
#   - core/experiment-runner/src/h1.rs        (H1 rig at WP-5.3)
#
# Reference: planset RM_FL_2026_04_28/00_PLANSET.md §RM-FL-5.

Feature: Hypothesis H1 — Belnap-FOUR vs flat-mean aggregation under mislabel injection
  As a Citrate researcher
  I want to measure routing-model accuracy under both aggregation
    methods given a known mislabel rate
  So that we can decide whether to graduate H1 from Specified to
    Verified or Falsified in Gradient Papers v3 Paper II

  Background: 4-region synthetic dataset
    Given the dataset CID is pinned in scripts/h1/dataset_cid.txt
    And the dataset has 4 regions {r1, r2, r3, r4}
    And each region has 1000 labelled training examples
    And the held-out test set has 500 examples disjoint from training
    And the Citrate testnet is running with 4 nodes (one per region)
    And each node runs citrate-learning-daemon attached to its region's slice

  # ----------------------------------------------------------------
  # SANITY: Without any mislabel, both aggregations should agree.
  # If this fails, the experiment is meaningless. This pins
  # HypothesisH1.tla::BelnapMatchesFlatMeanWithoutMislabel at the
  # empirical level.
  # ----------------------------------------------------------------
  Scenario: Sanity — both aggregations agree on clean data
    Given mislabel rate is 0% across all regions
    When the daemons submit embeddings for cycle C
    And the cycle is aggregated under both methods (in parallel runs)
    Then the Belnap-aggregated embedding equals the flat-mean
      embedding within Q16 epsilon (≤ 65 = ~0.001)
    And the routing model trained on either output produces the
      same predictions on the held-out set within 1% accuracy

  # ----------------------------------------------------------------
  # H1's main measurement: 25% mislabel in region r4 alone.
  # ----------------------------------------------------------------
  Scenario: 25% mislabel in r4 — Belnap should not lose to flat-mean
    Given mislabel rate is 0% in regions {r1, r2, r3}
    And mislabel rate is 25% in region r4
    When the daemons submit embeddings for cycle C
    And cycle C is finalized via finalizeCycle
    And the routing model is retrained on the aggregated output
    Then the Belnap-trained model's held-out accuracy is at least
      the flat-mean-trained model's held-out accuracy, minus the
      sampling-noise tolerance (1% absolute)
    And the audit log records the dataset CID, the per-region
      mislabel rate, the aggregation method, and the held-out
      accuracy with a 95% confidence interval

  # ----------------------------------------------------------------
  # The experiment must be reproducible. Tripwire WP-5.4 enforces
  # that the dataset CID is pinned; this scenario verifies the
  # *data path* is honoured.
  # ----------------------------------------------------------------
  Scenario: Reproducibility — same dataset CID + seed produces same outcome
    Given the experiment ran once with dataset CID X and seed S
    And the recorded held-out accuracies are (acc_belnap, acc_flat)
    When the experiment is re-run with the same CID and seed
    Then the new run produces held-out accuracies within Q16 epsilon
      of (acc_belnap, acc_flat)

  # ----------------------------------------------------------------
  # Adversary cannot impersonate. HypothesisH1.tla
  # ::OnlyAdversaryRegionMislabels invariant pinned empirically.
  # ----------------------------------------------------------------
  Scenario: Adversary in r4 cannot submit embeddings claiming region r1
    Given the daemon for r4 attempts to submit an embedding tx with
      region tag set to r1
    When the tx reaches the mempool
    Then the tx reverts with InvalidRegionClaim or is rejected by
      the daemon's pre-submission check
    And no embedding with region tag r1 from the r4 signer key is
      ever included in any aggregated cycle

  # ----------------------------------------------------------------
  # Falsification gate. If THIS scenario passes, H1 is Falsified.
  # The closing essay must report it as such; no reframing.
  # ----------------------------------------------------------------
  Scenario: Falsification — Belnap loses to flat-mean by > 5% on clean-ish data
    Given mislabel rate is 5% in region r4 (low — well under H1's claim)
    When the experiment runs with N=10 trials
    And the mean Belnap held-out accuracy is more than 5% absolute
      below the mean flat-mean held-out accuracy
    Then the experiment reports H1 as FALSIFIED with the measured
      gap and 95% CI
    And the closing essay (THE_HYPOTHESIS_RESULTS.md) records the
      negative result honestly
    And Gradient Papers v3 Paper II is updated with status Falsified
