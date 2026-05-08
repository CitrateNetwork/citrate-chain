# BFR-00 / WP-2 — Role-escalation timer Gherkin
#
# Per CORE_RULES Rule 11, every scenario names its data source.
#
# Spec source:
#   - .agentile/formal/specs/gui/RoleEscalationTimer.tla
#       (TLC-verified — invariants: WarningImpliesRemainingLt300s,
#        ElevatedImpliesRemainingAboveThreshold, BaseHasNoTimer,
#        ExpiredImpliesRemainingZero, ActiveStateHasGrant; liveness:
#        ExpiredImpliesBaseRoleEventually, ElevatedEventuallyTerminates)
#
# Contract sources:
#   - RoleEscalation.sol (grants[user][tenant] — eth_call polled at 1Hz
#     when elevated; expires_at + state drives the chip render)
#
# Code targets (BFR-01, post-BFR-00):
#   - citrate_v0.01.1/gui/citrate_boeing_kit/ui/primitives/role_escalation_timer.slint
#       (the chip; in-out countdown property; step-down callback)
#
# Compliance reference:
#   - FedRAMP AC-6 (least privilege; time-bounded elevation)
#   - FedRAMP AC-12 (session termination on expiry)
#   - Mirrors existing it_elevation.rs semantics in citrate-edu-app

Feature: Role-escalation timer — chip lifecycle, threshold, expiry, step-down
  As a Citrate desktop operator with elevated privileges
  I need the chip to count down visibly, switch to a warning style
  before expiry, and force me back to base role when time runs out
  So that I cannot accidentally hold elevated privileges past their
  approved window (FedRAMP AC-6) and so that audit replay shows the
  elevation duration was bounded.

  Background:
    Given the operator's base role is "QA Engineer III"
    And the chip is in Base state
    And no elevation grant exists in RoleEscalation.sol

  # ----------------------------------------------------------------
  # Elevation lifecycle
  # ----------------------------------------------------------------

  Scenario: Elevating to Admin starts the countdown above threshold
    When the operator requests elevation to "Admin" for 60 minutes
    And RoleEscalation.requestElevation succeeds
    Then the chip transitions to Elevated
    And remaining = 60*60 = 3600 seconds (or test value 6 ticks)
    And grantedAtTick is recorded

  Scenario: Crossing the warning threshold flips background tint
    Given the chip is in Elevated state with remaining > threshold
    When time advances such that remaining = threshold
    Then the chip transitions to Warning
    And the chip's background tint shifts to error rose

  Scenario: Reaching zero transitions to Expired then Base
    Given the chip is in Warning state with remaining = 1 tick
    When time advances by 1 tick
    Then the chip transitions to Expired with remaining = 0
    When the next tick fires
    Then the chip transitions to Base
    And remaining = 0
    And grantedAtTick = 0
    # The two-step (Expired -> Base) gives the UI time to render an
    # "expired" toast and emit the audit event before the chip resets.

  # ----------------------------------------------------------------
  # Step-down (voluntary termination)
  # ----------------------------------------------------------------

  Scenario: Step-down from Elevated returns to Base immediately
    Given the chip is in Elevated state with remaining = 1800
    When the operator clicks the Step Down button
    Then the chip transitions to Base
    And remaining = 0
    And RoleEscalation.stepDown is called with corr_id

  Scenario: Step-down from Warning also returns to Base
    Given the chip is in Warning state with remaining = 60
    When the operator clicks Step Down
    Then the chip transitions to Base immediately

  # ----------------------------------------------------------------
  # No double-elevation
  # ----------------------------------------------------------------

  Scenario: Re-elevation while already elevated is forbidden
    Given the chip is in Elevated state
    When the operator attempts to request elevation again
    Then the request is rejected by the precondition state = Base
    And the chip remains in Elevated with original remaining

  # ----------------------------------------------------------------
  # Direct-to-warning case (short elevation)
  # ----------------------------------------------------------------

  Scenario: A short elevation enters Warning directly (no Elevated state)
    Given threshold = 5 minutes (300s)
    When the operator requests elevation for 4 minutes (240s)
    Then the chip transitions directly to Warning (NOT Elevated)
    And remaining = 240
    # Verified by the Elevate action: when duration <= WarningThresholdSec,
    # state' = "Warning" not "Elevated."
