# BFR-00 / WP-2 — Assistant pane flow Gherkin
#
# Per CORE_RULES Rule 11, every scenario names its data source.
#
# Spec source:
#   - .agentile/formal/specs/gui/AssistantPaneFlow.tla
#       (TLC-verified — invariants: GenerationAtomic,
#        ToolApprovalBlocksProgress, PendingToolConsistent,
#        ActivePromptConsistent, DecisionLogBounded;
#        liveness: ClosingEventuallyClosed)
#
# Contract sources:
#   - AgentDecisionRegistry.sol (every approval / rejection appends
#     a Decision)
#
# Code targets (BFR-01, post-BFR-00):
#   - citrate_v0.01.1/gui/citrate_boeing_kit/ui/composables/assistant_pane.slint
#       (slide-in pane; conversation log + decision log + tool-approval card)
#
# Compliance reference:
#   - FedRAMP AC-3 (access enforcement): tool approval requires explicit
#     operator action; no auto-approval
#   - FedRAMP AU-2 (event logging): every tool approval/rejection records
#     a corr_id

Feature: Assistant pane flow — generation, tool approval, decision log
  As a Citrate desktop operator using the verifiable agent
  I need the assistant pane to enforce one-generation-at-a-time, to
  block progress on a pending tool approval, and to never lose entries
  from the decision log
  So that audit replay can reconstruct the agent's decision sequence
  exactly (FedRAMP AU-2) and so that no tool runs without my consent.

  Background:
    Given the assistant pane is Closed
    And the decision log is empty

  Scenario: Open / submit / generate / finish round-trip
    When the operator clicks "Ask about this" on a Provenance node
    Then the pane transitions to Conversing
    When the operator submits a prompt "explain the contradiction"
    Then the pane transitions to Generating
    And activePrompt = "explain the contradiction"
    When the LLM generation finishes
    Then a decision corr_id is appended to the log
    And the pane returns to Conversing

  Scenario: Tool request blocks progress until approved
    Given the pane is in Generating state
    When the LLM proposes a tool call "fetch part lineage"
    Then the pane transitions to AwaitingApproval
    And pendingTool = "fetch part lineage"
    When the operator attempts to submit a new prompt
    Then the submit is rejected by the precondition state = Conversing
    And the pane remains in AwaitingApproval

  Scenario: Tool approval appends to decision log and resumes generation
    Given the pane is in AwaitingApproval with pendingTool = "fetch part lineage"
    When the operator clicks Approve
    Then a decision corr_id is appended to the log
    And pendingTool = "none"
    And the pane returns to Generating

  Scenario: Tool rejection aborts generation and returns to Conversing
    Given the pane is in AwaitingApproval with pendingTool = "fetch part lineage"
    When the operator clicks Reject
    Then a decision corr_id is appended to the log (with class=Rejection)
    And the pane returns to Conversing
    And activePrompt = "none"
    And pendingTool = "none"

  Scenario: Closing the pane is forbidden during in-flight generation
    Given the pane is in Generating state
    When the operator attempts to close the pane
    Then the close is rejected by the precondition state = Conversing
    And the pane remains in Generating

  Scenario: Closing transitions cleanly to Closed
    Given the pane is in Conversing state
    When the operator clicks the close button
    Then the pane transitions to Closing
    And after the slide animation finishes, the pane is Closed
    And the decision log is preserved (not cleared)
    # Liveness: ClosingEventuallyClosed

  Scenario: Decision log is append-only across the session
    Given the operator runs 3 prompts in one pane session
    Then the decision log has 3 entries (or more, with tool approvals)
    And the entries are in submission order
    And no entry was removed or reordered
    # The TLA+ invariant DecisionLogBounded combined with the only
    # action that mutates decisionLog being Append() guarantees this.
