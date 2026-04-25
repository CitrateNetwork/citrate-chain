Feature: Gateway usage endpoint (WP-03.5)
  As a buyer with an API key
  I want a /v1/usage endpoint reporting per-day token and SALT spend
  So that I can build my own billing view without re-implementing it

  Background:
    Given a gateway with one healthy provider
    And the admin has created API key "key_42" with 100 SALT balance
    And the provider reports 7 input_tokens and 13 output_tokens per request

  Scenario: Three successful requests appear in usage totals
    When I POST /v1/chat/completions 3 times with "Authorization: Bearer key_42"
    And I GET /v1/usage with "Authorization: Bearer key_42"
    Then the response is 200
    And "total_requests" equals 3
    And "total_input_tokens" equals 21
    And "total_output_tokens" equals 39
    And the body has "salt_spent_grains" as a string U256
    And the body has "salt_spent_display" as a human-readable SALT amount (e.g. "3.0 SALT")

  Scenario: Daily breakdown exists for today
    When I POST /v1/chat/completions twice with "Authorization: Bearer key_42"
    And I GET /v1/usage
    Then "daily" is an array
    And the entry for today has "requests" equal to 2
    And no future-dated entries exist

  Scenario: /v1/usage requires an API key
    When I GET /v1/usage with no Authorization header
    Then the response is 401
    And the body says "Authorization: Bearer <key> required"

  Scenario: /v1/usage for unknown key is 401
    When I GET /v1/usage with "Authorization: Bearer nope"
    Then the response is 401

  Scenario: /v1/usage only reports the caller's own key
    Given a second key "key_other" has 5 requests
    When I GET /v1/usage with "Authorization: Bearer key_42"
    Then "total_requests" counts only key_42's requests
    And no data from key_other appears in the response
