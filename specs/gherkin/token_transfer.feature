Feature: Token Transfer Safety
  As an AI agent transferring SALT tokens
  I must verify the sender has sufficient balance and the recipient is valid
  So that transfers succeed and funds are not lost

  Scenario: Sufficient balance for transfer
    Given the sender balance is at least <amount> + gas cost
    And the recipient address is a valid 20-byte hex address
    And the amount is greater than 0
    When the agent requests a token transfer
    Then the transfer should proceed

  Scenario: Insufficient balance blocks transfer
    Given the sender balance is less than <amount> + gas cost
    When the agent requests a token transfer
    Then the transfer should be blocked
    And the agent should report "Insufficient balance"

  Scenario: Zero amount rejected
    Given the sender has sufficient balance
    And the amount is 0
    When the agent requests a token transfer
    Then the transfer should be blocked
    And the agent should report "Transfer amount must be positive"

  Scenario: Invalid recipient rejected
    Given the sender has sufficient balance
    And the recipient address is not a valid hex address
    When the agent requests a token transfer
    Then the transfer should be blocked
    And the agent should report "Invalid recipient address"

  Scenario: Post-transfer verification
    Given a transfer was submitted with hash <tx_hash>
    When the agent verifies the transfer
    Then the receipt should exist with status 1
    And the recipient balance should have increased by <amount>
