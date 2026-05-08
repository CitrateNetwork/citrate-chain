# DPF-00 / WP-1 — Drawer panel lifecycle Gherkin
#
# Per CORE_RULES Rule 11, every scenario names its data source.
#
# Spec source:
#   - .agentile/formal/specs/gui/DrawerLifecycle.tla
#       (TLC-verified — invariants: AtMostOneActive, ClosingOnlyAfterOpen,
#        PendingDrawersAreClosed, CloseReasonOnlyAfterClose,
#        PendingNoDuplicates; liveness: OpeningEventuallyResolves,
#        ClosingEventuallyClosed, PendingEventuallyOpens)
#
# Code targets (DPF-01, post-DPF-00):
#   - citrate_v0.01.1/gui/citrate_defense_prime_kit/ui/composables/drawer_panel.slint
#       (the rendered slide-in panel; state property + close-reason out
#        signal)
#   - citrate_v0.01.1/gui/citrate_defense_prime_kit/src/lib.rs
#       (DrawerStack singleton coordinating the at-most-one invariant)
#
# Compliance reference:
#   - .agentile/planset/2026-05-07-defense_prime-fedramp-slint-rebuild/06_FIDELITY_MATRIX.md
#     (drift = defect; the drawer's slide-in motion is part of the prototype
#     contract, captured in Gherkin via stable transition events)

Feature: Drawer panel lifecycle — slide-in detail surface
  As a Citrate desktop user
  I need detail drawers to slide in from the right edge predictably,
  to never overlap, and to close cleanly with a typed reason
  So that audit trails record WHY a drawer closed (user action vs
  scope switch vs ESC) and so that no half-open animation states
  produce visual glitches on screen.

  Background:
    Given the citrate_defense_prime_kit drawer renderer is mounted
    And no drawer is open
    And the pending-open queue is empty

  # ----------------------------------------------------------------
  # Singleton render
  # ----------------------------------------------------------------

  Scenario: A drawer opens on user action and closes on user action
    When the user clicks "Ask about this" on a Provenance node
    Then the drawer "node-detail-d1" enters Opening
    And after the slide animation finishes, "node-detail-d1" is Open
    When the user clicks the X button
    Then "node-detail-d1" enters Closing with closeReason = "user_action"
    And after the slide animation finishes, "node-detail-d1" is Closed
    And no drawer is active

  Scenario: ESC during Opening cancels back to Closed
    Given a drawer "supplier-detail-s3" is requested open
    And the drawer is in Opening
    When the user presses ESC mid-animation
    Then "supplier-detail-s3" returns directly to Closed
    And closeReason = "esc_key"
    And the drawer never reached the Open state

  # ----------------------------------------------------------------
  # Pending-open queue
  # ----------------------------------------------------------------

  Scenario: Requesting open while another drawer is closing queues the request
    Given drawer "audit-detail-d1" is Open
    When the user presses ESC
    Then "audit-detail-d1" enters Closing with closeReason = "esc_key"
    When the user clicks "Ask about this" on a different node
    Then drawer "node-detail-d2" is added to pendingOpen
    And "node-detail-d2" remains Closed (not Opening)
    When the Closing animation finishes for "audit-detail-d1"
    Then "audit-detail-d1" is Closed
    And "node-detail-d2" is automatically pulled from pendingOpen
    And "node-detail-d2" enters Opening

  # ----------------------------------------------------------------
  # Typed close reason (audit-trail content)
  # ----------------------------------------------------------------

  Scenario Outline: A drawer closes with a typed reason for the audit trail
    Given a drawer "<drawer>" is Open
    When the close trigger is "<trigger>"
    Then closeReason = "<reason>"

    Examples:
      | drawer            | trigger            | reason           |
      | node-detail       | X-button click     | user_action      |
      | supplier-detail   | ESC key            | esc_key          |
      | employee-detail   | scope-switch click | scope_switch     |
      | audit-event       | nav to other panel | navigate_away    |

  # ----------------------------------------------------------------
  # No half-open state visible
  # ----------------------------------------------------------------

  Scenario: A canceled Opening never renders Open content
    Given a drawer "deploy-confirm" is in Opening
    When the user presses ESC mid-animation
    Then the drawer's content area is never displayed at full width
    And "deploy-confirm" returns to Closed without entering Open
    # Verified by the TLA+ invariant: Cancel from Opening goes Closed,
    # not Open; AtMostOneActive holds throughout.
