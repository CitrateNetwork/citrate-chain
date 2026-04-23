Feature: x402 HTTP Payment Rails (server-side)
  As the operator of a Citrate HTTP service gated by x402
  I must challenge unpaid clients, verify signed payments, and
  settle on-chain exactly once per nonce
  So that AI companies can pay per-request for inference without
  a trusted middleman billing channel

  # Data sources (Rule 11):
  #   - X402Facilitator.sol — settlePayment(from, to, value, validAfter,
  #     validBefore, nonce, v, r, s). Settles an EIP-3009 authorization
  #     on-chain. Reverts on replay (wSALT nonce mapping).
  #   - WrappedSALT.transferWithAuthorization — called by facilitator.
  #     Marks nonce as used via _authorizationStates mapping.
  #   - core/execution/src/precompiles/x402.rs
  #     - 0x0200 EIP712Verify — recover signer from typed-data digest
  #     - 0x0201 TransferAuthVerify — full authorization verification
  #   - ADR-005-x402-payment-protocol.md — architecture decision record
  #
  # Formal spec:
  #   - .agentile/formal/specs/compute/X402FacilitatorSettle.tla — this
  #     file's scenarios correspond 1:1 to state transitions in the
  #     TLA+ model (IssueChallenge, SettleValid, RejectReplay, etc.)
  #   - .agentile/formal/specs/wallet/X402PaymentFlow.tla — client-side
  #     complement (request, sign, retry)

  Scenario: Unpaid request returns 402 with a challenge body
    Given an axum service behind the X402Layer middleware
    And the request has no "X-PAYMENT" header
    When the service receives the request
    Then the response status is 402
    And the response body is JSON containing:
      | field           | type    | required                         |
      | version         | int     | must equal 1                     |
      | facilitator     | string  | hex address on chain 40204       |
      | token           | string  | WrappedSALT address              |
      | chain_id        | int     | must equal 40204                 |
      | amount          | string  | decimal wei, ≥ configured price  |
      | nonce           | string  | 32-byte hex, never seen before   |
      | valid_after     | int     | unix timestamp                   |
      | valid_before    | int     | valid_after + 300s (5 min)       |
      | recipient       | string  | treasury address                 |
      | digest          | string  | keccak256 of EIP-712 typed data  |
    And the nonce is recorded in the server's issued-nonces set

  Scenario: Valid signature passes through to the wrapped handler
    Given a valid, unexpired, signed authorization in the "X-PAYMENT" header
    And the signing client has sufficient wSALT balance on-chain
    And the nonce has not been settled before
    When the service receives the request
    Then precompile 0x0201 verifies the signature off-chain (free via eth_call)
    And X402Facilitator.settlePayment is submitted as a transaction
    And the receipt contains a PaymentSettled event
    And the nonce is added to the server's settled-nonces set
    And the wrapped handler receives the request with X402Paid attached to extensions
    And the caller receives the handler's response with status 200

  Scenario: Replayed nonce is rejected with a descriptive reason
    Given a signed authorization whose nonce is already in settled-nonces
    When the client re-submits the same "X-PAYMENT" header
    Then the response status is 402
    And the response body field "reason" equals "nonce replayed"
    And no new on-chain transaction is submitted
    And the settled-nonces set is unchanged

  Scenario: Expired authorization is rejected
    Given a signed authorization with valid_before < current unix time
    When the service receives the request
    Then the response status is 402
    And the response body field "reason" equals "expired"
    And precompile 0x0201 is NOT called (save the eth_call round-trip)
    And no on-chain transaction is submitted

  Scenario: Invalid signature is rejected before any on-chain work
    Given an "X-PAYMENT" header with a signature whose recovered signer
    differs from the claimed "from" address
    When the service receives the request
    Then the response status is 402
    And the response body field "reason" equals "signature invalid"
    And no on-chain transaction is submitted

  Scenario: Insufficient wSALT balance at settle time
    Given a signed authorization that passes off-chain verification
    And the claimed payer has 0 wSALT on-chain
    When the service submits settlePayment
    Then the transaction reverts
    And the response status is 402
    And the response body field "reason" begins with "on-chain settle failed"
    And the nonce is NOT added to settled-nonces (may retry with fresh balance)

  Scenario: Client-side budget cap refuses to sign
    Given the X402Client is constructed with a budget cap of 1 SALT per request
    And a service challenges with amount = 2 SALT
    When the client tries to auto-pay via send_paid()
    Then the client returns X402Error::BudgetExceeded
    And no signature is produced
    And no HTTP retry is sent

  Scenario: Ed25519 wallets cannot produce EIP-3009 signatures
    Given a wallet whose key type is Ed25519 (not Secp256k1)
    When the X402Client tries to sign a challenge
    Then the client returns X402Error::UnsupportedKeyType
    And no HTTP request is issued

  Scenario: Receipt-poll timeout degrades gracefully
    Given a signed authorization the server has submitted on-chain
    When the receipt poll exceeds the configured timeout (default 10s)
    Then the response status is 500
    And the response body field "reason" equals "settle pending (timeout)"
    And the nonce may have been settled — server should log the tx hash
    And the nonce is NOT added to settled-nonces locally (prevents false
        replay-rejection if the tx eventually lands)

  Scenario: Successful settlement emits a trail event and Prometheus counter
    Given the X402Layer has been configured with an event bus publisher
    When a settlement succeeds
    Then exactly one AppEvent::X402PaymentSettled is published
    And the event fields include payer, amount_wei (grains — NOT SALT), tx_hash
    And the Prometheus counter citrate_x402_settlements_total increments by 1
    # Grain/SALT note: the trail event carries raw grains by convention
    # (machine-readable archive); any UI surface converts via
    # wallet-core::format::grains_to_salt before display.
