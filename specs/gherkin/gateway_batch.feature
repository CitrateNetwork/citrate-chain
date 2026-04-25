Feature: Gateway batch inference endpoint (WP-03.3)
  As a buyer with many requests to run
  I want to submit a batch and poll for results
  So that I can fan out work without holding N HTTP connections open

  Background:
    Given a gateway with one healthy provider
    And the provider echoes any prompt back as "STUB-RESPONSE: {prompt}"

  Scenario: Submit a batch of 5 requests and observe completion
    When I POST /v1/batch with 5 chat completion requests
    Then the response is 200
    And the body has a "batch_id" string
    And the body has "object" equal to "batch"
    And the body has "status" equal to "submitted"
    And the body has "request_count" equal to 5

  Scenario: Poll status until terminal
    Given I have submitted a batch of 3 requests
    When I GET /v1/batch/{batch_id} repeatedly
    Then status transitions through: submitted → running → completed
    And the terminal body has "completed_count" equal to 3
    And "errored_count" equals 0

  Scenario: Partial failure
    Given the provider rejects request indices [1] with HTTP 500
    And I have submitted a batch of 3 requests
    When the batch reaches a terminal state
    Then status equals "partial_failure"
    And "completed_count" equals 2
    And "errored_count" equals 1

  Scenario: All requests fail
    Given the provider rejects every request with HTTP 500
    And I have submitted a batch of 2 requests
    When the batch reaches a terminal state
    Then status equals "failed"
    And "completed_count" equals 0
    And "errored_count" equals 2

  Scenario: Output endpoint returns JSONL
    Given I have a completed batch of 2 requests
    When I GET /v1/batch/{batch_id}/output
    Then the response Content-Type is "application/x-ndjson"
    And the body has 2 newline-separated JSON objects
    And each line has "request_index", "status", and either "response" or "error"

  Scenario: Unknown batch id returns 404
    When I GET /v1/batch/does-not-exist
    Then the response is 404

  Scenario: Batch size limit
    When I POST /v1/batch with 1001 requests
    Then the response is 400
    And the body says "max 1000 requests per batch"

  # Escrow accounting (mirrors GatewayBatchLifecycle.tla invariants
  # EscrowBalances and TerminalBatchEscrowSettled). On-chain settlement
  # is deferred to slice 2/3 — this scenario asserts the in-memory
  # ledger only.
  Scenario: Escrow accounting on partial failure
    Given the provider rejects request indices [0] with HTTP 500
    And I have submitted a batch of 4 requests
    When the batch reaches a terminal state
    Then "paid_escrow_grains" equals "released_grains" + "refunded_grains"
    And "refunded_grains" reflects exactly 1 errored request
