# DPF-00 / WP-1 — Modal lifecycle Gherkin
#
# Per CORE_RULES Rule 11, every scenario names its data source.
#
# Spec source:
#   - .agentile/formal/specs/gui/ModalLifecycle.tla
#       (TLC-verified — invariants: AtMostOneShown, TerminalIsTerminal,
#        AcceptedByConsistent, RejectedByConsistent, DismissedHasNoActor,
#        AcceptOrRejectExclusive)
#
# Code targets (DPF-01, post-DPF-00):
#   - citrate_v0.01.1/gui/citrate_defense_prime_kit/ui/composables/modal.slint
#       (the center-screen blocking dialog; accept/reject/dismiss callbacks)
#
# Compliance reference:
#   - .agentile/planset/2026-05-07-defense_prime-fedramp-slint-rebuild/04_FEDRAMP_COMPLIANCE.md
#     § "AC — Access Control" (AC-5 Separation of Duties: multi-sig
#     accept must record the actor, dismiss must record nothing)

Feature: Modal lifecycle — accept / reject / dismiss with actor capture
  As a Citrate desktop operator (engineer, contracting officer, compliance lead)
  I need confirmation modals to capture WHO accepted or rejected,
  to treat ESC and click-backdrop as ambiguous (not accept), and to
  prevent any modal from showing while another is shown
  So that audit logs accurately record decision provenance and so
  that ambiguous input never silently completes a privileged action.

  Background:
    Given the citrate_defense_prime_kit modal renderer is mounted
    And no modal is shown

  # ----------------------------------------------------------------
  # Actor capture on Accept / Reject
  # ----------------------------------------------------------------

  Scenario: Accepting a modal records the actor's identity
    Given a modal "deploy-confirm" is Hidden
    When the system shows "deploy-confirm"
    Then "deploy-confirm" is Shown
    When operator "u-7b3a2f" clicks Accept
    Then "deploy-confirm" is Accepted
    And acceptedBy = "u-7b3a2f"
    And rejectedBy = "none"

  Scenario: Rejecting a modal records the actor's identity
    Given a modal "scope-switch-confirm" is Shown
    When operator "u-9c4e1d" clicks Reject
    Then "scope-switch-confirm" is Rejected
    And rejectedBy = "u-9c4e1d"
    And acceptedBy = "none"

  # ----------------------------------------------------------------
  # Ambiguous-input safety: dismiss != accept
  # ----------------------------------------------------------------

  Scenario: ESC dismisses without recording an actor
    Given a modal "factory-reset-confirm" is Shown
    When the operator presses ESC
    Then "factory-reset-confirm" is Dismissed
    And acceptedBy = "none"
    And rejectedBy = "none"
    # The TLA+ invariant DismissedHasNoActor enforces: a Dismissed
    # modal NEVER records an acceptor. The system cannot infer
    # operator intent from an anonymous dismiss.

  Scenario: Click-backdrop dismisses without recording an actor
    Given a modal "multi-sig-sign" is Shown
    When the operator clicks outside the modal panel
    Then "multi-sig-sign" is Dismissed
    And acceptedBy = "none"
    And rejectedBy = "none"

  # ----------------------------------------------------------------
  # Singleton stack
  # ----------------------------------------------------------------

  Scenario: A second modal cannot show while the first is shown
    Given a modal "sign-1" is Shown
    When the system attempts to show modal "sign-2"
    Then the show is rejected by the AtMostOneShown precondition
    And "sign-2" remains Hidden

  # ----------------------------------------------------------------
  # Terminal-state finality
  # ----------------------------------------------------------------

  Scenario: An Accepted modal cannot be re-shown
    Given a modal "deploy-confirm" is Accepted
    When the system attempts to show "deploy-confirm" again
    Then the show is rejected by the Hidden-state precondition
    And "deploy-confirm" remains in Accepted state
    # Re-confirming requires a NEW modal instance with a new ID;
    # this enforces one-decision-per-instance semantics for the
    # audit log.

  # ----------------------------------------------------------------
  # Mutual exclusion
  # ----------------------------------------------------------------

  Scenario: A modal cannot have both an acceptor and a rejector
    Given a modal "tina-workpaper" is Accepted by "u-7b3a2f"
    Then rejectedBy = "none"
    And the TLA+ invariant AcceptOrRejectExclusive holds.
    # Note: Reject is structurally unreachable from Accepted state
    # because Reject requires Shown precondition.
