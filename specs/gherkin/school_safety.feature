# Track-P4 / WP-P4-14 — School-safety state machine
#
# Per CORE_RULES Rule 11, every scenario names its data source: the
# TLA+ spec, the on-chain artifact, the in-process module, or the
# audit-log destination.
#
# Spec source:
#   - .agentile/formal/specs/gui/SchoolSafety.tla
#       (WP-P4-14, TLC-verified clean: 7,467 distinct states, depth 24,
#        7 invariants — TypeOK, NoElevationByNonAdmin, ElevationRespectsTTL,
#        EveryElevationHasEnterEvent, AuditTrailMonotonic,
#        FilterActiveDuringSession, DaemonRestartClearsElevations)
#
# Code targets:
#   - citrate_v0.01.1/gui/citrate_edu_app/src/it_elevation.rs
#       (admin → IT bridge: ItElevationStore, ItElevation, ItElevationAuditEvent)
#   - citrate_v0.01.1/gui/citrate_edu_app/src/role.rs
#       (EduRole enum: Admin / IT / SuperAdmin / Teacher / Student / TA / None)
#   - Forthcoming: content-filter module (hooks landed but module not yet
#     implemented at HEAD — WP-P4-14 spec verifies the wiring contract that
#     the implementation must honor when it lands)
#
# Compliance reference:
#   - .agentile/compliance/10_COMPLIANCE_CHECKLIST.md § 6 ("Content Safety")
#     line 137-138 ("SchoolSafety TLA+ + Gherkin — Sprint-0 gate blocker")

Feature: School-safety state machine — IT elevation, content filter, audit trail
  As a school IT director (or admin doubling as IT)
  I need the Citrate Learning Center to enforce role-bounded privileges,
  time-limited elevation, and an always-active content filter during
  student sessions
  So that students cannot accidentally or maliciously trigger unfiltered
  AI interactions, and so that any privileged action is auditable

  Background:
    Given the citrate-edu-app daemon is running
    And the audit log is empty
    And the content filter is active by default

  # ------------------------------------------------------------------
  # IT elevation lifecycle (TLA+ invariants 1, 2, 3, 4)
  # ------------------------------------------------------------------

  Scenario: Admin elevates to IT mode after fresh reauth
    Given user "admin@school.test" has role "Admin" on chain
    And the admin has just completed a fresh password reauth
    When the admin requests IT elevation
    Then the elevation is granted with TTL 60 minutes
    And one "Entered" audit event is emitted with the admin's principal_id
    And the elevation expires_at equals granted_at + 60 minutes
    # Maps to TLA+ EnterElevation action and EveryElevationHasEnterEvent invariant

  Scenario: Non-admin cannot elevate to IT mode (NoElevationByNonAdmin)
    Given user "student@school.test" has role "Student" on chain
    And the student has just completed a fresh password reauth
    When the student requests IT elevation
    Then the request is refused
    And one "Refused" audit event is emitted with the student's principal_id
    And no elevation is recorded for the student
    # Maps to TLA+ RefuseElevation action and NoElevationByNonAdmin invariant

  Scenario: Admin without fresh reauth cannot elevate
    Given user "admin@school.test" has role "Admin" on chain
    And no fresh password reauth has been completed in the last 30 seconds
    When the admin requests IT elevation
    Then the request is refused
    And one "Refused" audit event is emitted
    # Maps to the reauth-fresh precondition on TLA+ EnterElevation

  Scenario: Elevation expires when TTL elapses (ElevationRespectsTTL)
    Given user "admin@school.test" has been elevated for 60 minutes
    When the daemon's periodic sweep runs after expires_at has passed
    Then the elevation is removed from the store
    And one "Expired" audit event is emitted with the admin's principal_id
    And subsequent IT-scoped actions by the admin are refused
    # Maps to TLA+ ExpireOne action and ElevationRespectsTTL invariant

  Scenario: Admin manually exits IT mode
    Given user "admin@school.test" is currently elevated
    When the admin clicks "Exit IT mode" in the GUI
    Then the elevation is removed from the store
    And one "Exited" audit event is emitted with the admin's principal_id
    # Maps to TLA+ ExitElevation action

  # ------------------------------------------------------------------
  # Daemon restart drops elevations (TLA+ invariant 6)
  # ------------------------------------------------------------------

  Scenario: Daemon restart clears all in-memory elevations
    Given user "admin@school.test" is currently elevated
    And user "admin2@school.test" is currently elevated
    When the citrate-edu-app daemon restarts
    Then no elevations remain in the in-memory store
    And the admin must complete a fresh reauth and re-elevate to perform IT actions
    # Maps to TLA+ DaemonRestart action and DaemonRestartClearsElevations invariant
    # Backstop: in-memory state is intentionally non-durable per
    # it_elevation.rs design — the audit log on durable storage (separate)
    # is preserved, but live grants are not.

  # ------------------------------------------------------------------
  # Content filter during student sessions (TLA+ invariant 5)
  # ------------------------------------------------------------------

  Scenario: Content filter must be active before a student session can start
    Given the content filter is currently inactive
    When a teacher attempts to start a student session
    Then the start is refused with error "filter must be active for student session"
    # Maps to TLA+ StartStudentSession's filterActive precondition

  Scenario: Filter cannot be disabled while a student session is active
    Given a student session is currently active
    And the content filter is currently active
    When an elevated admin attempts to toggle the content filter off
    Then the toggle is refused with error "cannot disable filter mid-session"
    And the content filter remains active
    # Maps to TLA+ ToggleFilter's ~studentSession precondition and
    # FilterActiveDuringSession invariant
    # Note: even an elevated admin cannot bypass this — the filter is
    # treated as a non-overridable safety property during student-facing time.

  Scenario: Filter can be reconfigured between student sessions
    Given no student session is active
    And an admin is elevated to IT mode
    When the admin disables the content filter
    Then the toggle succeeds
    And the next attempt to start a student session is refused until the filter is re-enabled
    # Maps to ToggleFilter without student-session conflict

  # ------------------------------------------------------------------
  # Audit-trail completeness (TLA+ invariant 4)
  # ------------------------------------------------------------------

  Scenario: Every privileged transition produces exactly one audit event
    Given the audit log is empty
    When admin "a1" reauths
    And admin "a1" elevates
    And the daemon ticks past the TTL deadline
    Then the audit log contains exactly:
      | event   | principal | sequence |
      | Entered | a1        | 1        |
      | Expired | a1        | 2        |
    # Maps to TLA+ auditCount monotonicity and per-action emission

  Scenario: Audit trail survives daemon restart
    Given admin "a1" was previously elevated and the elevation expired
    And the audit log contains the corresponding Entered + Expired events
    When the daemon restarts
    Then the audit log still contains the Entered + Expired events for "a1"
    # Backstop: this scenario verifies the audit log is durable storage
    # (filesystem or chain), distinct from the in-memory elevation store.
    # See it_elevation.rs design note: "Elevation is per-process state
    # (in-memory) and does not survive a daemon restart" — but audit
    # records are written to a persistent destination per the audit-log
    # design.
