Feature: Model Deployment Safety
  As an AI agent deploying a model to the Citrate network
  I must verify the model data is valid and IPFS is available
  So that models are properly stored and registered

  Scenario: Valid model with IPFS available
    Given the model file exists at <path>
    And the model file is a valid GGUF or ONNX format
    And IPFS daemon is running
    And the deployer has sufficient SALT for registration fee
    When the agent deploys the model
    Then the model should be uploaded to IPFS
    And the CID should be registered in ModelRegistry
    And the model should appear in the marketplace listing

  Scenario: IPFS not available
    Given the model file is valid
    And IPFS daemon is not running
    When the agent deploys the model
    Then the deployment should be blocked
    And the agent should report "IPFS not available — start IPFS first"

  Scenario: Invalid model format
    Given the file at <path> is not a valid model format
    When the agent deploys the model
    Then the deployment should be blocked
    And the agent should report "Invalid model format"

  Scenario: Insufficient registration fee
    Given the model and IPFS are valid
    And the deployer balance is less than the registration fee
    When the agent deploys the model
    Then the deployment should be blocked
    And the agent should report "Insufficient SALT for registration"
