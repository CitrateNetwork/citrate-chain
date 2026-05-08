# DPF-00 / WP-1 — Toast lifecycle Gherkin
#
# Per CORE_RULES Rule 11, every scenario names its data source.
#
# Spec source:
#   - .agentile/formal/specs/gui/ToastLifecycle.tla
#       (TLC-verified — see CI run logs in .github/workflows/tla-check.yml;
#        invariants: AtMostOneShowing, AuditRelevantNeverAutoDismisses,
#        DismissedIsTerminal, AutoTimerOnlyEphemeral, QueueBounded,
#        TimerArmedImpliesEphemeralShowing; liveness:
#        EveryQueuedEventuallyShows, EveryShowingEventuallyDismisses)
#
# Code targets (DPF-01, post-DPF-00):
#   - citrate_v0.01.1/gui/citrate_defense_prime_kit/ui/composables/toast.slint
#       (the rendered composable; class enum, dismiss callback)
#   - citrate_v0.01.1/gui/citrate_defense_prime_kit/src/lib.rs
#       (ToastClass enum mirroring the spec; Toast spawn/dismiss API)
#
# Compliance reference:
#   - .agentile/planset/2026-05-07-defense_prime-fedramp-slint-rebuild/04_FEDRAMP_COMPLIANCE.md
#     § "AU — Audit and Accountability" (AU-6: audit-relevant events
#     require explicit acknowledgment — toast cannot auto-dismiss)

Feature: Toast lifecycle — DefensePrime-grade notification primitive
  As a Citrate desktop user (engineer, auditor, compliance officer)
  I need notifications to render in a single render slot without overlap,
  to dismiss automatically only for low-stakes events, and to require
  explicit acknowledgment for audit-relevant events
  So that audit-relevant events cannot be missed (FedRAMP AU-6) and
  so that ephemeral notifications do not pile up on screen.

  Background:
    Given the citrate_defense_prime_kit toast renderer is mounted
    And no toast is currently showing
    And the toast queue is empty

  # ----------------------------------------------------------------
  # Singleton render-slot
  # ----------------------------------------------------------------

  Scenario: A single ephemeral toast spawns, shows, and auto-dismisses
    Given an ephemeral toast "saved" is spawned
    When the renderer pulls the queue head
    Then the toast "saved" is in the Showing state
    And the timer is armed
    When the timer fires
    Then the toast "saved" is in the Dismissed state with cause "auto_timer"
    And the timer is disarmed
    And no toast is showing

  Scenario: Two ephemeral toasts queue, only one shows at a time
    Given an ephemeral toast "first" is spawned
    And an ephemeral toast "second" is spawned
    When the renderer pulls the queue head
    Then the toast "first" is in the Showing state
    And the toast "second" is still queued (not Showing)
    When the timer fires for "first"
    Then "first" is Dismissed
    And the renderer pulls the next queue head
    Then "second" is in the Showing state

  # ----------------------------------------------------------------
  # Audit-relevant contract (FedRAMP AU-6)
  # ----------------------------------------------------------------

  Scenario: An audit-relevant toast does NOT auto-dismiss
    Given an audit-relevant toast "ITAR access auto-revoked" is spawned
    When the renderer pulls the queue head
    Then the toast is in the Showing state
    And the timer is NOT armed
    When 10 seconds pass without operator action
    Then the toast is still in the Showing state
    And dismissCause is "none"

  Scenario: An audit-relevant toast dismisses only on manual action
    Given an audit-relevant toast "Foreign-national status changed" is spawned and showing
    When the operator clicks the dismiss button
    Then the toast is in the Dismissed state with cause "manual"

  Scenario: An audit-relevant toast NEVER records dismissCause "auto_timer"
    Given an audit-relevant toast "TINA threshold tripped" is shown for 1 hour
    When the operator finally dismisses it
    Then dismissCause is "manual"
    # The TLA+ invariant AuditRelevantNeverAutoDismisses guarantees this
    # holds for ANY action sequence, not just this scenario.

  # ----------------------------------------------------------------
  # Terminal-state invariant
  # ----------------------------------------------------------------

  Scenario: Once dismissed, a toast cannot be re-shown
    Given an ephemeral toast "deploy succeeded" was shown and auto-dismissed
    When the system attempts to re-spawn the same toast id
    Then the spawn is rejected by the InQueue/Idle precondition
    And the toast remains in the Dismissed state

  # ----------------------------------------------------------------
  # Mixed-class queue
  # ----------------------------------------------------------------

  Scenario: An audit-relevant toast can sit in queue behind ephemeral ones
    Given an ephemeral toast "saved" is spawned
    And an audit-relevant toast "auto-revoke" is spawned
    When the queue drains
    Then "saved" shows and dismisses (auto_timer or manual)
    And then "auto-revoke" shows
    And "auto-revoke" stays Showing until manual dismissal
