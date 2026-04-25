Feature: Gateway API key auth (WP-03.4)
  As a repeat buyer with predictable spend
  I want a Bearer API key backed by a pre-funded balance
  So that I don't have to manage wSALT for every individual request

  Background:
    Given a gateway with one healthy provider
    And the admin has created an API key "key_42" with 10 SALT balance
    And the provider returns "STUB-RESPONSE: {prompt}" on /infer

  Scenario: Valid key with sufficient balance
    When I POST /v1/chat/completions with "Authorization: Bearer key_42"
    Then the response is 200
    And my key balance drops by the priced amount (single request)
    And the response is a well-formed chat completion

  Scenario: Unknown key is rejected
    When I POST /v1/chat/completions with "Authorization: Bearer nope"
    Then the response is 401
    And the body says "unknown api key"

  Scenario: Revoked key is rejected
    Given "key_42" has been revoked
    When I POST /v1/chat/completions with "Authorization: Bearer key_42"
    Then the response is 401
    And the body says "revoked"

  Scenario: Exhausted key falls through to x402
    Given "key_42" has 0 SALT balance
    When I POST /v1/chat/completions with "Authorization: Bearer key_42"
    Then the response is 402
    And the body includes an x402 challenge envelope
    And the body includes "deposit_instructions" with the key's deposit address

  Scenario: No Authorization header keeps existing x402 path intact
    When I POST /v1/chat/completions without any Authorization header
    Then the response is 402
    And the body includes an x402 challenge envelope
    And the body does NOT include "deposit_instructions"
