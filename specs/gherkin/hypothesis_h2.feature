# RM-FL-5 / WP-5.2 — Hypothesis H2 experiment harness (10-node testnet).
#
# H2 (Paper II §4): Aggregate inference accuracy on the union test set
# is monotonically non-decreasing in the number of registered LoRA
# adapters; specifically follows a power law of the form
#       acc(N) = α − β × N^{−γ}      (β, γ > 0; α ≤ 1.0)
#
# Per CORE_RULES Rule 11, every scenario names its data source.
#
# Spec sources:
#   - specs/tla/learning/HypothesisH2.tla     (6 inv, 48 states clean)
#   - specs/tla/learning/AdapterProvenance.tla
#
# Code targets:
#   - core/experiment-runner/src/h2.rs        (H2 rig at WP-5.5)
#   - contracts/src/LoRAFactory.sol           (verifyAdapterAt — RM-FL-4 / WP-4.7)
#
# Reference: planset RM_FL_2026_04_28/00_PLANSET.md §RM-FL-5.

Feature: Hypothesis H2 — Adapter composition power-law growth
  As a Citrate researcher
  I want to measure how aggregate accuracy grows as N adapters are
    composed at inference time
  So that we can fit a power law and decide whether H2 graduates
    to Verified, Falsified, or Inconclusive in Paper II

  Background: 10-node testnet, incremental adapter registration
    Given the training-seed list is pinned in scripts/h2/seeds.txt
    And the test set CID is pinned in scripts/h2/test_set_cid.txt
    And the Citrate testnet is running with 10 nodes
    And each node trains and registers exactly one LoRA adapter per
      sub-experiment step
    And LoRAFactory.verifyAdapterAt is wired to the live 0x0108 precompile

  # ----------------------------------------------------------------
  # The protocol-side claim from HypothesisH2.tla::AccuracyFloorMonotonic.
  # If this empirical scenario fails, the spec is broken or the
  # measurement is broken — either way H2 cannot be graduated.
  # ----------------------------------------------------------------
  Scenario: Monotonicity — aggregate accuracy is non-decreasing in N
    Given the experiment ran with N adapters registered, accuracy = acc(N)
    And the experiment then ran with N+1 adapters registered (the
      first N are unchanged; one new verified adapter added)
    When held-out accuracy is measured on the union test set
    Then acc(N+1) >= acc(N) - sampling_tolerance (1% absolute)

  # ----------------------------------------------------------------
  # The main measurement: incremental registration N=1..100, fit
  # the power law.
  # ----------------------------------------------------------------
  Scenario Outline: Incremental registration — measure acc(N) for N up to 100
    Given <N> adapters have been verified and registered in LoRAFactory
    When the routing model composes all <N> adapters at inference
    And held-out accuracy is measured on 1000 test inputs
    Then the measurement is recorded as (N=<N>, acc=measured_acc, ci=95)

    Examples:
      | N |
      | 1 |
      | 5 |
      | 10 |
      | 25 |
      | 50 |
      | 75 |
      | 100 |

  Scenario: Fit power law from measured points
    Given the (N, acc) measurement series from the prior scenario
    When a power law `acc(N) = α − β × N^{−γ}` is fit to the data
    Then the fit reports (α̂, β̂, γ̂) with 95% confidence intervals
    And the fit reports R² goodness-of-fit
    And if R² < 0.5 the result is reported as INCONCLUSIVE
      (the data does not support the power-law form)

  # ----------------------------------------------------------------
  # Verification gate from HypothesisH2.tla
  # ::EveryRegisteredAdapterIsVerified.
  # ----------------------------------------------------------------
  Scenario: Unverified adapter cannot be registered
    Given a candidate adapter A with no proof verified at 0x0108
    When the daemon attempts to register A in LoRAFactory
    Then the registration tx reverts with AdapterModelCommitmentNotSet
      or AdapterProofRejected
    And A is never counted in any aggregate accuracy measurement

  # ----------------------------------------------------------------
  # Adversary attempts to game the experiment by registering
  # near-duplicate adapters.
  # ----------------------------------------------------------------
  Scenario: Adversary registers 50 near-duplicate adapters to inflate N
    Given an adversary controls 50 adapter slots
    And each adversary adapter is a small perturbation of a single
      base adapter (cosine similarity > 0.99)
    When all 50 adversary adapters are verified and registered
    And aggregate accuracy is measured at N=50 (all adversary)
      vs N=50 (50 honest, diverse)
    Then the all-adversary case should report markedly lower
      diversity-adjusted accuracy
    And the closing essay records this as a known H2 limitation
      ("N counts adapters, not adapter diversity")

  # ----------------------------------------------------------------
  # Falsification gate. The strong claim is power-law growth; the
  # weak claim is monotonicity. Both must hold for H2 to be Verified.
  # ----------------------------------------------------------------
  Scenario: Falsification — accuracy decreases as N grows
    Given measurements at N ∈ {1, 25, 50, 75, 100}
    When the best-fit slope of acc vs N (linear) is significantly
      negative at the 95% confidence level
    Then the experiment reports H2 as FALSIFIED — composition
      DOES NOT improve accuracy
    And Paper II §4 is updated with status Falsified
    And the closing essay records the negative result and proposes
      what the actual relationship looks like
