Feature: Smart Contract Deployment Safety
  As an AI agent deploying contracts on Citrate
  I must verify all pre-conditions before deployment
  So that user funds are not wasted on failed deployments

  Scenario: Sufficient gas for deployment
    Given the deployer has at least 1000000 gas worth of SALT
    And the bytecode is non-empty
    And the bytecode size is less than 24576 bytes
    When the agent requests contract deployment
    Then the deployment should proceed

  Scenario: Insufficient gas blocks deployment
    Given the deployer has less than 1000000 gas worth of SALT
    When the agent requests contract deployment
    Then the deployment should be blocked
    And the agent should report "Insufficient gas for deployment"

  Scenario: Empty bytecode rejected
    Given the deployer has sufficient gas
    And the bytecode is empty
    When the agent requests contract deployment
    Then the deployment should be blocked
    And the agent should report "Empty bytecode"

  Scenario: Successful deployment verification
    Given a contract was deployed at address <address>
    When the agent verifies the deployment
    Then eth_getCode at <address> should return non-empty bytecode
    And a transaction receipt should exist with status 1
