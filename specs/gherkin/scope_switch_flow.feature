# DPF-00 / WP-2 — Scope-switch flow Gherkin
#
# Per CORE_RULES Rule 11, every scenario names its data source.
#
# Spec source:
#   - .agentile/formal/specs/gui/ScopeSwitchFlow.tla
#       (TLC-verified — invariants: BoundaryCrossingRequiresConfirm,
#        AppliedImpliesSigned, ConfirmedOnlyDuringSwitch,
#        TargetScopeConsistent; liveness: AppliedEventuallyStable,
#        CancelledEventuallyStable)
#
# Contract sources:
#   - TenantHierarchy.sol (getPath() — reads the scope chain)
#   - ClassificationRegistry.sol (getClearance() — reads user's max
#     clearance to validate target reachability)
#
# Code targets (DPF-01, post-DPF-00):
#   - citrate_v0.01.1/gui/citrate_defense_prime_kit/ui/primitives/tenant_scope_chip.slint
#   - citrate_v0.01.1/gui/citrate_defense_prime_kit/ui/composables/modal.slint (confirm)
#
# Compliance reference:
#   - FedRAMP AC-3 (access enforcement)
#   - FedRAMP AC-6 (least privilege; classification step-down requires
#     operator confirmation)
#   - This is a SECURITY-SENSITIVE flow (Rule 8): the
#     BoundaryCrossingRequiresConfirm invariant is load-bearing.

Feature: Scope-switch flow — picker, classification confirm, signed apply
  As a Citrate desktop operator
  I need scope switches that cross a classification boundary
  (Public ↔ Proprietary ↔ CUI ↔ ITAR or different ITAR-tagged subtree)
  to require an explicit confirmation step, AND every applied switch
  to record a correlation ID
  So that audit replay can prove no operator silently dropped into a
  lower-classification scope, and so that every switch is traceable.

  Background:
    Given the operator's active scope is "DefensePrime > CommercialUnit > Everett > 777X"
    And the operator's max clearance is CUI
    And the scope chip is in Stable state

  # ----------------------------------------------------------------
  # Same-scope and same-classification (no confirm needed)
  # ----------------------------------------------------------------

  Scenario: Selecting the same scope is a no-op
    When the operator opens the picker
    Then the chip is in Picking state
    When the operator selects the same scope
    Then the chip returns to Stable (no Applied transition)

  Scenario: Switching within the same subtree at same clearance applies directly
    Given the operator's scope is "DefensePrime > CommercialUnit > Everett > 777X" (Proprietary)
    When the operator opens the picker
    And selects target "DefensePrime > CommercialUnit > Everett > 787" (Proprietary, same subtree)
    Then the chip transitions to Applying (no Confirming step)
    And after Apply, correlationId is recorded
    And after ApplyFinalize, activeScope = the target

  # ----------------------------------------------------------------
  # Boundary-crossing requires confirm — the load-bearing scenario
  # ----------------------------------------------------------------

  Scenario: Switching to a lower-clearance scope requires confirmation
    Given the operator's scope is "DefensePrime > CommercialUnit > Everett > 777X" (Proprietary)
    When the operator selects target "DefensePrime > Public > Marketing" (Public)
    Then the chip transitions to Confirming (NOT directly to Applying)
    And the confirm modal is shown
    When the operator clicks Confirm
    Then confirmedThisRound = TRUE
    And the chip transitions to Applying
    When Apply records corr_id
    Then the chip is Applied
    And the TLA+ invariant BoundaryCrossingRequiresConfirm holds.

  Scenario: Switching to a different ITAR subtree requires confirmation
    Given the operator's scope is "DefensePrime > BDS > St.Louis > KC-46" (ITAR subtree A)
    When the operator selects target "DefensePrime > BDS > Mesa > AH-64" (ITAR subtree B)
    Then the chip transitions to Confirming
    And the confirm modal warns about ITAR-subtree boundary

  # ----------------------------------------------------------------
  # Cancel paths
  # ----------------------------------------------------------------

  Scenario: Cancelling from Picking restores Stable with original scope
    Given the chip is in Picking state
    When the operator clicks Cancel (or ESC)
    Then the chip transitions to Cancelled
    And after CancelFinalize, the chip is Stable
    And activeScope is unchanged

  Scenario: Cancelling from Confirming restores Stable with original scope
    Given the chip is in Confirming state with target = "Public > Marketing"
    When the operator clicks Cancel
    Then the chip is in Cancelled
    And after CancelFinalize, activeScope is unchanged
    And targetScope = "none"
    And confirmedThisRound = FALSE

  # ----------------------------------------------------------------
  # Audit-trail anchor
  # ----------------------------------------------------------------

  Scenario: Every applied switch records a correlation ID
    When any switch reaches the Applied state
    Then correlationId is set to a non-"none" value
    # Verified by the TLA+ invariant AppliedImpliesSigned for ANY
    # action sequence reaching Applied.
