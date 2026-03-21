Feature: Batch Operation Safety
  As an AI agent executing multi-step operations
  I must verify each step's pre-conditions and roll back on failure
  So that no orphaned state is created

  Scenario: All steps succeed
    Given step 1 pre-conditions are met
    And step 2 pre-conditions are met
    And step 3 pre-conditions are met
    When the agent executes the batch
    Then all steps should complete successfully
    And no compensating transactions should be needed

  Scenario: Middle step fails
    Given step 1 pre-conditions are met
    And step 2 pre-conditions are NOT met
    When the agent executes the batch
    Then step 1 should be compensated (rolled back)
    And the agent should report which step failed and why
    And no state changes should persist

  Scenario: Compensating transaction fails
    Given a batch step failed and compensation is needed
    And the compensating transaction itself fails
    When the agent handles the compensation failure
    Then the failure should be logged with full context
    And the agent should alert the user
    And a manual recovery path should be suggested

  Scenario: Pre-flight validation
    Given a batch operation is planned
    When the agent validates all steps before execution
    Then each step's pre-conditions should be checked
    And if any pre-condition fails, the entire batch should be blocked
    And the agent should report which step would fail
