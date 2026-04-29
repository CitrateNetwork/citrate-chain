# RM-FL-2 / WP-2.2 — Routing-model inference precompile (0x0111)
#
# Per CORE_RULES Rule 11, every scenario names its data source: the
# TLA+ spec it derives from, the precompile address it exercises,
# the reference impl it cross-checks against (where applicable).
#
# Spec sources:
#   - specs/tla/learning/RoutingModelInference.tla    (WP-2.1, 8 invariants)
#   - specs/tla/learning/RoutingAdversarial.tla       (WP-2.10, planned)
#
# Code targets (WP-2.5–2.6):
#   - core/execution/src/precompiles/q16/routing.rs::forward
#   - dispatch at 0x0111 in precompiles/mod.rs (Learning page selector 0x11)
#   - Halo2 multi-layer circuit RoutingCircuit::v1 in zkp/halo2/circuits.rs
#
# Q16-vs-f32 oracle boundary (RM-FL-1 retro item):
#   The off-chain reference (likely candle / PyTorch in RM-FL-3
#   daemon) uses f32 for the forward pass. The precompile uses Q16.
#   These are NOT byte-equivalent oracles. Algebraic-equivalence is
#   the right relationship: sign of confidence preserved, top-k
#   ordering preserved under bounded numeric tolerance, mentor_id +
#   adapter_id selection identical for inputs not at threshold-edges.

Feature: Routing-model inference precompile (0x0111)
  As a learning-cycle smart contract on Citrate testnet 40204
  I want to call a precompile that runs a 3-layer MLP on a 768-dim
  query embedding and returns (mentor_id, adapter_id, confidence)
  So that the on-chain mentor-matching protocol (Paper III §2,
  RM-FL-4) can select a mentor without trusting any off-chain
  inference service, and is provably resistant to weight-poisoning,
  version-downgrade, and shape-mismatch attacks
  (RoutingModelInference.tla invariants).

  Background:
    Given the Citrate testnet (chain id 40204) has the Q16 substrate
      live (precompiles 0x010A–0x010F per RM-M2)
    And the Belnap aggregation precompile is live at 0x0110 (RM-FL-1)
    And the routing-model precompile is dispatched at address
      0x0000000000000000000000000000000000000111
    And the gas schedule is 5000 + 4 * params
    And the architecture version 1 is registered with shape
      (input_dim=768, hidden_dim=128, output_dim=3) — locked at hardfork
    And the canonical shape carries 115,075 parameters
    And the input encoding is:
      | field         | type        | notes                          |
      | arch_version  | u32 BE      | must equal current ARCH_VERSION |
      | input_dim     | u32 BE      | must equal 768                  |
      | hidden_dim    | u32 BE      | must equal 128                  |
      | output_dim    | u32 BE      | must equal 3                    |
      | input         | 768*i32 BE Q16 | query embedding              |
      | W1, b1        | (128*768+128)*i32 BE Q16 | layer 1 weights+bias |
      | W2, b2        | (128*128+128)*i32 BE Q16 | layer 2 weights+bias |
      | W3, b3        | (3*128+3)*i32 BE Q16 | output layer weights+bias |
    And the output encoding is:
      | field         | type    | notes                                  |
      | mentor_id     | u32 BE  | argmax of softmax over output (mentor)  |
      | adapter_id    | u32 BE  | argmax derived (adapter slot)            |
      | confidence    | i32 BE Q16 | max-element of softmax              |

  # ─────────────────────────────────────────────────────────────────
  # Happy path
  # ─────────────────────────────────────────────────────────────────

  Scenario: Forward pass succeeds with canonical shape and valid weights
    # Source: RoutingModelInference.tla::AllInferencesUseRegisteredArch
    # Source: RoutingModelInference.tla::DeterministicOutput
    Given a query embedding with norm ≈ 1.0 in Q16
    And weight matrices initialized from a published RM-FL-3 daemon
      checkpoint (CID stored in LearningCycleManager)
    And arch_version = 1 (matching ARCH_VERSION)
    When the contract calls 0x0111 with the encoded inputs
    Then the call succeeds with `5000 + 4 * 115_075 = 465_300` gas
    And the output decodes to (mentor_id, adapter_id, confidence)
    And confidence is positive Q16
    And the call is bit-deterministic — two consecutive calls with
      the same input bytes return identical output bytes

  # ─────────────────────────────────────────────────────────────────
  # Adversarial — version mismatch
  # ─────────────────────────────────────────────────────────────────

  Scenario: arch_version 0 (uninitialized) is rejected
    # Source: RoutingModelInference.tla::AllInferencesUseRegisteredArch
    Given an encoded input with arch_version = 0
    When the contract calls 0x0111
    Then the precompile reverts with "arch_version unregistered"
    And gas is consumed up to the bounds-check exit (no allocation
      of the weight tensor)

  Scenario: arch_version higher than ARCH_VERSION is rejected
    # Source: RoutingModelInference.tla::NoDowngrade (contrapositive
    # — caller can't claim a future version that isn't registered)
    Given the chain's current ARCH_VERSION is 1
    And an encoded input with arch_version = 2
    When the contract calls 0x0111
    Then the precompile reverts with "arch_version unregistered"

  # ─────────────────────────────────────────────────────────────────
  # Adversarial — version downgrade (governance attack)
  # ─────────────────────────────────────────────────────────────────

  Scenario: Governance cannot lower current ARCH_VERSION
    # Source: RoutingModelInference.tla::NoDowngrade (the chain-wide
    # current_arch pointer is monotonically non-decreasing)
    # NOTE: this scenario asserts the on-chain governance contract's
    # behavior, not the precompile. The precompile is stateless;
    # NoDowngrade lives in the registry contract.
    Given the chain has registered arch_version 1 and 2
    And current ARCH_VERSION = 2
    When governance attempts to set current ARCH_VERSION = 1
    Then the governance call reverts with "no downgrade"
    And reads of current ARCH_VERSION still return 2

  Scenario: Back-compat — caller can still use registered arch_version 1 after upgrade to 2
    # Source: RoutingModelInference.tla::BackCompat
    Given arch_version 1 and 2 are both registered
    And current ARCH_VERSION = 2
    When the contract calls 0x0111 with arch_version = 1 + a v1-shaped weights bundle
    Then the call succeeds (the registry preserves v1's shape)
    And the output is bit-identical to a pre-upgrade call with the
      same v1 input — committed proofs anchored to v1 keep verifying

  # ─────────────────────────────────────────────────────────────────
  # Adversarial — shape (dim) mismatch
  # ─────────────────────────────────────────────────────────────────

  Scenario: input_dim != 768 is rejected before allocation
    # Bounds class — covered by tripwire check_routing_arch_locked.py
    Given an encoded input with input_dim = 256 (instead of 768)
    When the contract calls 0x0111
    Then the precompile reverts with "shape mismatch: input_dim must be 768"
    And no weight tensor is allocated (gas charged for parse only)

  Scenario: hidden_dim != 128 is rejected
    Given an encoded input with hidden_dim = 64
    When the contract calls 0x0111
    Then the precompile reverts with "shape mismatch: hidden_dim must be 128"

  # ─────────────────────────────────────────────────────────────────
  # Adversarial — weight poisoning
  # ─────────────────────────────────────────────────────────────────

  Scenario: Maximum-magnitude weights produce no panic (saturating Q16)
    # Q16 boundary case — covered by Rust property tests (WP-2.3)
    # and WP-2.9 cargo-fuzz target. Aggregator must use saturating
    # arithmetic at every step.
    Given a weights bundle where every entry is i32::MAX or i32::MIN
    And a normal query embedding
    When the contract calls 0x0111
    Then the call returns successfully (no panic, no revert)
    And the output is well-defined Q16 (no silent wrap)
    And confidence is finite Q16 (never NaN, never -infinity — those
      states are unrepresentable in Q16 by construction)

  # ─────────────────────────────────────────────────────────────────
  # Bounded gas — DoS resistance
  # ─────────────────────────────────────────────────────────────────

  Scenario: Truncated input is rejected before full allocation
    Given an encoded input that declares the canonical shape but
      provides only the first 1024 bytes of payload
    When the contract calls 0x0111
    Then the precompile reverts with "input length mismatch" before
      any allocation of W1/W2/W3 tensors
    And gas charged equals the GAS_BASE (5000) — the parse-only
      cost, not the full inference cost

  Scenario: Precompile rejects below-base gas limit
    Given a valid encoded input
    And a gas_limit < 5000
    When the contract calls 0x0111
    Then the precompile rejects with "insufficient gas"
    And no decode work is done

  # ─────────────────────────────────────────────────────────────────
  # Determinism — cross-CPU bit-identity
  # ─────────────────────────────────────────────────────────────────

  Scenario: Identical input bytes produce identical output bytes on x86_64 and aarch64
    # Source: tripwire check_routing_quant_q16_only.py + cross-platform
    # fixture in core/execution/tests/.
    Given a fixed input vector encoding, weights bundle, and
      arch_version, generated by a seeded RNG
    When the precompile runs on an x86_64 host
    And the precompile runs on an aarch64 host (same fixture)
    Then the two output byte sequences are identical
    And the gas charged is identical (deterministic gas accounting,
      not platform-dependent)

  # ─────────────────────────────────────────────────────────────────
  # ZK proof composition — optional via 0x0108
  # ─────────────────────────────────────────────────────────────────

  Scenario: Routing-model output can be verified via 0x0108 with RoutingCircuit::v1
    # Source: RoutingCircuit::v1 (WP-2.5) generalizes RM-M1b's
    # single-layer InferenceCircuit to compose 3 LinearChips +
    # 2 ReLUs + 1 softmax with copy-constraints between layers.
    # The 0x0108 verifier accepts any version registered in
    # citrate-execution/zkp/halo2/mod.rs::CIRCUIT_VERSION_*.
    Given a routing-model proof generated off-chain via RoutingCircuit::v1
    And the proof's public input is the (input || mentor_id || adapter_id || confidence) tuple
    When the contract calls 0x0108 with this proof
    Then the call returns success (proof verifies)
    And committed routing decisions can be replayed after the next
      hardfork as long as RoutingCircuit::v1 stays registered
      (Halo2VerifierVersionMonotonic.tla guarantees the registry
       never drops a registered VK)
