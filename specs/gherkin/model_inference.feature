Feature: Model Inference Safety
  As an AI agent running model inference
  I must verify the model exists and the provider is available
  So that inference requests succeed and results are valid

  Scenario: Model exists and provider available
    Given the model is registered in the ModelRegistry
    And at least one compute provider is available for this model
    And the requester has sufficient SALT for the inference fee
    When the agent requests inference
    Then the inference should proceed

  Scenario: Model not registered
    Given the model ID does not exist in the ModelRegistry
    When the agent requests inference
    Then the request should be blocked
    And the agent should report "Model not found"

  Scenario: No providers available
    Given the model is registered
    And no compute providers are online for this model
    When the agent requests inference
    Then the request should fall back to local execution if model is available locally
    Or the request should be blocked with "No providers available"

  Scenario: Inference result verification
    Given an inference was completed with proof
    When the agent verifies the result
    Then the proof-of-computation should be valid
    And the result should be deterministic for the same input
