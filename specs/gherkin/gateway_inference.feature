Feature: Batch Inference Gateway (citrate-inference-gateway)
  As an AI company integrating with the Citrate compute marketplace
  I want an OpenAI-compatible HTTP surface that handles payment + dispatch
  So that I can submit chat completions and batches without learning
  ABI selectors or wei accounting

  # Data sources (Rule 11):
  #   - X402Layer (crates/x402-axum) — inbound payment gating
  #   - ModelRegistry.listModels() — populates GET /v1/models
  #     (contract addr per chain, see DEPLOYED_ADDRESSES.md)
  #   - InferenceRouter.providers() — synchronous dispatch target lookup
  #   - ComputeMarketplace.postJob() — async batch dispatch
  #   - ComputeMarketplace event logs (JobPosted, JobCompleted, JobFailed)
  #     — batch status updates via eth_subscribe newHeads or polling
  #   - ContributionAccounting (out-of-scope for this gateway, but
  #     referenced as the destination of provider earnings)
  #
  # Formal spec:
  #   - .agentile/formal/specs/compute/GatewayBatchLifecycle.tla — batch
  #     state machine with 11 invariants including EscrowBalances and
  #     RefundsMatchErrored.
  #   - .agentile/formal/specs/compute/X402FacilitatorSettle.tla — the
  #     inbound payment layer (gateway is a server)
  #   - .agentile/formal/specs/wallet/X402PaymentFlow.tla — IF the
  #     gateway calls upstream x402-gated providers (it doesn't in v1
  #     since the InferenceRouter providers expose plain HTTPS, but
  #     the spec applies should that change).

  # ── /v1/models ──────────────────────────────────────────────────

  Scenario: GET /v1/models returns OpenAI-compatible model list
    Given the gateway is configured with a chain RPC URL
    And ModelRegistry has at least one model registered
    When a client GETs /v1/models
    Then the response status is 200
    And the response body is JSON matching the OpenAI models-list schema:
      """
      {
        "object": "list",
        "data": [
          { "id": "<model_name>", "object": "model", "owned_by": "<creator>", "created": <unix_seconds> }
        ]
      }
      """
    And no payment is required for this endpoint

  Scenario: GET /v1/models is resilient to chain RPC unreachable
    Given the chain RPC is unreachable
    When a client GETs /health
    Then the response status is 200
    And the response body is {"ok": true}
    # Health intentionally does not depend on chain — load balancers
    # must not take the process out on transient chain blips.

  # ── /v1/chat/completions (sync path) ────────────────────────────

  Scenario: Sync chat completion happy path
    Given a registered provider exists for the requested model
    And a client signs a valid x402 authorization for the gateway's price
    When the client POSTs /v1/chat/completions with messages and the X-PAYMENT header
    Then the gateway settles payment via X402Facilitator.settlePayment
    And the gateway POSTs the prompt to the provider's endpoint URL
    And the provider returns tokens within the 60s timeout
    And the gateway returns an OpenAI-shape response with status 200
    And the response includes a usage object with prompt_tokens and completion_tokens

  Scenario: Sync chat with provider timeout returns 503 (payment retained)
    Given the gateway has settled payment for a chat completion
    And the selected provider does not respond within 60s
    When the gateway gives up on the provider
    Then the gateway tries one fallback provider
    And if that also times out, returns status 503
    And the payment is NOT refunded — documented policy mirrors a
        chargeback (gateway operator absorbs the cost; future v2 may
        add provider-side slashing for SLA breach)

  Scenario: Sync chat with no providers available returns 503
    Given no providers are registered for the requested model
    When a client POSTs /v1/chat/completions (with valid payment)
    Then the gateway returns status 503
    And the response body explains "no providers available"
    And the payment IS refunded via X402Facilitator (out-of-band, since
        it never settled — this is a pre-settle reject)

  Scenario: SSE streaming for stream=true requests
    Given a chat completion request with "stream": true
    When the gateway dispatches and the provider streams tokens
    Then the response uses Server-Sent Events with content-type text/event-stream
    And each event is formatted as "data: {chunk}\n\n"
    And the stream ends with "data: [DONE]\n\n"

  # ── /v1/batch (async path) ──────────────────────────────────────

  Scenario: Submit a batch — receive batch_id and pending status
    Given a client POSTs /v1/batch with an array of 10 requests
    And the X-PAYMENT header authorizes the total estimated cost
    When the gateway accepts the batch
    Then the response status is 200
    And the response body contains:
      | field         | value                          |
      | id            | batch_<random>                 |
      | status        | "pending"                      |
      | request_count | 10                             |
    And the gateway has written the batch to RocksDB
    And the gateway has issued 10 ComputeMarketplace.postJob transactions

  Scenario: Poll batch status — running, completed, failed
    Given a batch was submitted with id batch_abc
    When a client GETs /v1/batch/batch_abc
    Then the response status is 200
    And the response body's "status" field is one of: "pending", "running", "completed", "partial", "failed"
    And "completed_count" reflects the number of JobCompleted events observed for this batch's request ids

  Scenario: Batch with all requests succeeding reaches "completed"
    Given a 10-request batch is dispatched
    And all 10 jobs emit JobCompleted within the configured deadline
    When the client GETs /v1/batch/{id}
    Then "status" is "completed"
    And "completed_count" is 10
    And /v1/batch/{id}/output streams 10 result JSONL lines in submission order

  Scenario: Batch with mixed outcomes reaches "partial"
    Given a 10-request batch is dispatched
    And 7 jobs succeed, 3 jobs emit JobFailed
    When the client GETs /v1/batch/{id}
    Then "status" is "partial"
    And "completed_count" is 7
    And the output JSONL contains 7 results plus 3 per-request error objects

  Scenario: Crash-restart mid-batch recovers from RocksDB
    Given a batch is dispatched with 10 requests, 4 of which have completed
    And the gateway process is killed and restarted
    When the gateway re-subscribes to chain events
    Then it resumes tracking the batch from RocksDB state
    And further JobCompleted events update completed_count correctly
    And no duplicate postJob transactions are issued for already-dispatched requests

  # ── API key authentication (alternative to per-request x402) ────

  Scenario: API key with pre-funded balance bypasses per-request 402
    Given an API key was created with a deposit of 100 SALT (escrowed in wSALT)
    When a client POSTs /v1/chat/completions with "Authorization: Bearer <key>"
    Then the gateway deducts the price from the key's balance
    And the gateway proceeds without an x402 challenge
    And the request succeeds with status 200

  Scenario: API key exhausted returns 402 with top-up instructions
    Given an API key with balance 0 SALT
    When a client POSTs /v1/chat/completions with "Authorization: Bearer <key>"
    Then the response status is 402
    And the body contains BOTH the standard x402 challenge AND a deposit_instructions field
    And deposit_instructions includes the deposit_wallet_address for top-up

  Scenario: Revoked API key returns 401
    Given an API key flagged revoked=true by admin
    When a client POSTs with that key
    Then the response status is 401
    And the response body explains "key revoked"

  # ── /v1/usage (billing visibility) ──────────────────────────────

  Scenario: GET /v1/usage returns per-day token + SALT spend
    Given a key has made 100 requests today, 50 yesterday
    When a client GETs /v1/usage with the Authorization header
    Then the response groups usage by date
    And each row includes input_tokens, output_tokens, salt_spent (NOT raw grains)
    And the totals match RocksDB's usage_daily column-family aggregate

  # ── Operator runbook properties ─────────────────────────────────

  Scenario: Gateway operator wallet running low triggers an alert
    Given the gateway operator wallet balance falls below 10 SALT
    When the next /metrics scrape happens
    Then the metric citrate_gateway_operator_balance_wei reports the current balance
    And the value is below the configured alert threshold
    # Actual alerting is out-of-band (Prometheus AlertManager); this
    # scenario asserts the metric exists for the runbook to consume.

  Scenario: Prometheus counters tick on every settlement
    Given the gateway is wired to a CountersObservability hook
    When N successful settlements occur
    Then citrate_gateway_settlements_total increments by N
    And citrate_gateway_rejections_total{reason="..."} increments per failure mode
    # Inherited from x402-axum's observability hook.

  # ── Provider Protocol v1 conformance ────────────────────────────

  Scenario: Gateway dispatches via the documented provider protocol
    Given a registered provider exists at endpoint URL "https://provider.example/infer"
    When the gateway dispatches a chat completion to that provider
    Then it POSTs to /infer with body matching the provider-protocol-v1 schema
    And it includes a Bearer token from per-pool credentials (rotated quarterly)
    And it sets a 60-second timeout
    # Provider Protocol formalized in ADR-006 (next free ADR number).
