# RM-FL-1 / WP-1.2 — Belnap-FOUR aggregation precompile (0x0110)
#
# Per CORE_RULES Rule 11, every scenario names its data source: the
# TLA+ spec it derives from, the precompile address it exercises, the
# off-chain reference it cross-checks against (where applicable).
#
# Spec sources:
#   - specs/tla/learning/BelnapLattice.tla            (lattice axioms)
#   - specs/tla/learning/ParaconsistentAggregation.tla (honest-path)
#   - specs/tla/learning/BelnapAdversarial.tla         (adversary model)
#
# Code targets (WP-1.5):
#   - core/execution/src/precompiles/q16/belnap.rs::aggregate
#   - dispatch at 0x0110 in precompiles/mod.rs
#   - off-chain reference: core/learning/src/belnap.rs (f32; oracle is
#     algebraic-equivalence, not byte-equality — see WP-1.1 audit notes)

Feature: Belnap-FOUR aggregation precompile (0x0110)
  As a learning-cycle smart contract on Citrate testnet 40204
  I want to call a precompile that aggregates per-validator Belnap
  classifications into a single state vector + Q16 aggregated value
  per dimension
  So that the on-chain learning protocol (Paper II §3) can settle a
  cycle without a trusted aggregator and is provably resilient to
  Byzantine validators (BelnapAdversarial.tla invariants)

  Background:
    Given the Citrate testnet (chain id 40204) has the Q16 substrate
      live (precompiles 0x010A–0x010F per RM-M2)
    And the Belnap aggregation precompile is dispatched at address
      0x0000000000000000000000000000000000000110
    And the gas schedule is 2000 + 50 * dim
    And the input encoding is:
      | field             | type        | notes                          |
      | dim               | u32 BE      | embedding dimensionality       |
      | n                 | u32 BE      | participant count              |
      | embeddings        | n*dim*i32 Q | participant embedding values   |
      | confidences       | n*dim*i32 Q | per-(participant,dim) conf     |
      | weights           | n*i32 Q     | per-participant trust weight   |
      | threshold_pos     | i32 Q       | classification threshold +     |
      | threshold_neg     | i32 Q       | classification threshold −     |
    And the output encoding is `dim*i32 Q` (aggregated value per dim)
      followed by `dim*u8` (Belnap state per dim, 0=Neither / 1=True /
      2=False / 3=Both — though at the reduced level 2 never appears)

  # ─────────────────────────────────────────────────────────────────
  # Happy path
  # ─────────────────────────────────────────────────────────────────

  Scenario: Three honest validators agree on direction → state=True
    # Source: ParaconsistentAggregation.tla::AgreementProducesTrue
    # Source: BelnapAdversarial.tla::HonestSafety
    Given dim=2 and n=3 participants
    And every participant submits embedding [+0.5, +0.5] in Q16
    And every participant submits confidence [0.9, 0.9] in Q16 (above
      threshold_pos=0.8)
    And every participant has equal weight 1.0 in Q16
    When the contract calls 0x0110 with the encoded inputs
    Then the call succeeds with `2000 + 50*2 = 2100` gas charged
    And the output Belnap states are [True, True]
    And the aggregated values are bit-identical to a Q16 weighted mean
      of the embeddings (deterministic across CPUs)

  # ─────────────────────────────────────────────────────────────────
  # Adversarial — collusion (high-conf opposite under HDA)
  # ─────────────────────────────────────────────────────────────────

  Scenario: Two colluding Byzantine validators submit opposite high-conf
            → state=Both, never aligned with attackers
    # Source: BelnapAdversarial.tla::AdversaryCannotFlipUnderHDA
    # Source: BelnapAdversarial.tla::BothRequiresTwoSides
    Given dim=1 and n=4 participants under Honest Dominance Assumption
      (Σ honest weight > Σ Byzantine weight)
    And 2 honest participants submit embedding [+1.0] with confidence
      [0.9] and weight 1.0 each (total honest weight = 2.0)
    And 2 colluding Byzantine participants submit embedding [-1.0]
      with confidence [0.9] and weight 0.5 each (total Byzantine
      weight = 1.0; HDA holds: 2.0 > 1.0)
    When the contract calls 0x0110
    Then the output Belnap state is [Both]
    And the state is never [False] — adversarial flip is impossible
      under HDA at the reduced state-vector level

  # ─────────────────────────────────────────────────────────────────
  # Adversarial — threshold-edge confidence
  # ─────────────────────────────────────────────────────────────────

  Scenario: Confidence at exact threshold is classified deterministically
    # Q16 boundary case — covered by Rust property tests rather than
    # TLA+ (which abstracts away numeric precision).
    Given dim=1 and n=2 participants
    And participant A submits confidence exactly equal to threshold_pos
      (0.8 in Q16)
    And participant B submits confidence one Q16 ULP below threshold_pos
    And both submit positive embedding sign
    When the contract calls 0x0110 (with threshold_pos=0.8 as the
      inclusive lower bound for "high confidence")
    Then participant A is classified as high-confidence (True)
    And participant B contributes Neither (below threshold)
    And the result is bit-identical across two consecutive calls with
      the same input bytes (determinism guard)

  # ─────────────────────────────────────────────────────────────────
  # Adversarial — weight = 0
  # ─────────────────────────────────────────────────────────────────

  Scenario: Zero-weight validator is filtered before classification
    # Source: BelnapAdversarial.tla::WeightZeroIgnored
    Given dim=1 and n=3 participants
    And 2 honest participants submit positive sign with weight 1.0 and
      high confidence
    And 1 Byzantine participant submits negative sign with weight 0.0
      (and arbitrary high confidence)
    When the contract calls 0x0110
    Then the output Belnap state is [True]
    And the zero-weight participant contributes nothing — gas usage
      matches the 2-participant scenario, not the 3-participant
      scenario, modulo the per-participant decode overhead

  # ─────────────────────────────────────────────────────────────────
  # Adversarial — dimension mismatch
  # ─────────────────────────────────────────────────────────────────

  Scenario: Input dim does not match declared dim → revert
    # Bounds class — covered by tripwire check_belnap_caps_enforced.py.
    Given the encoded input declares dim=4 but provides only 3*i32
      worth of embedding bytes per participant
    When the contract calls 0x0110
    Then the precompile reverts with "input length mismatch" before
      any allocation
    And gas is consumed up to the bounds-check exit (no DoS via
      partial allocation)

  # ─────────────────────────────────────────────────────────────────
  # Adversarial — magnitude / overflow
  # ─────────────────────────────────────────────────────────────────

  Scenario: Maximum-magnitude Q16 inputs produce no overflow
    # Q16 boundary case — fuzzed in WP-1.7. The aggregator must use
    # saturating arithmetic on the weighted-sum path so adversarial
    # max-value inputs never panic and never wrap around silently.
    Given dim=1 and n=2 participants
    And participant A submits embedding i32::MAX (the largest Q16
      value, ≈ +32767.99 in floating-point space)
    And participant B submits embedding i32::MIN
    And both submit weight 1.0 and high confidence
    When the contract calls 0x0110
    Then the call returns successfully (no panic, no revert)
    And the aggregated value is well-defined Q16 (no silent wrap)
    And the Belnap state is [Both] (genuine disagreement)

  # ─────────────────────────────────────────────────────────────────
  # Determinism — cross-CPU bit-identity
  # ─────────────────────────────────────────────────────────────────

  Scenario: Identical input bytes produce identical output bytes on
            x86_64 and aarch64
    # Source: tripwire check_belnap_no_float.py (zero floats in
    # precompiles/q16/belnap.rs is a CI gate). Covered at runtime by a
    # cross-platform fixture test in core/execution/tests/.
    Given a fixed input vector encoding 5 participants, dim=4,
      generated by a seeded RNG
    When the precompile runs on an x86_64 host
    And the precompile runs on an aarch64 host (same fixture)
    Then the two output byte sequences are identical
    And the gas charged is identical (deterministic gas accounting,
      not platform-dependent)
