Feature: Gateway credit billing (CM-06)
  As an institutional buyer with prepaid compute credits
  I want to spend credits on inference jobs without managing SALT
  So that my finance team can budget in dollars instead of tokens

  Background:
    Given a Citrate testnet with BulkComputeGateway and ComputeMarketplace deployed
    And the StablecoinTreasury accepts USDC
    And the ComputePricingOracle is fresh (not stale)

  # ── WP-06.1: Contract changes ──

  Scenario: postJob with PaymentMethod.SALT (existing path, no regression)
    Given my wallet has 100 SALT
    When I call postJob with maxPrice=1 SALT and paymentMethod=SALT and msg.value=1 SALT
    Then the job is posted with status=Pending
    And my wallet balance dropped by 1 SALT

  Scenario: postJob with PaymentMethod.BulkCredits — happy path
    Given I have 10 credits in BulkComputeGateway
    And ComputeMarketplace is in BulkComputeGateway.authorizedSpenders
    When I call postJob with maxPrice=1 SALT-equivalent and paymentMethod=BulkCredits and msg.value=0
    Then the job is posted with status=Pending
    And my credit balance dropped by the SALT-to-credits-converted amount
    And no SALT left my wallet
    # Mirrors CreditBilling.tla::PostJobCredits action

  Scenario: postJob with credits but msg.value > 0 reverts
    Given I have credits and ComputeMarketplace is authorized
    When I call postJob with paymentMethod=BulkCredits and msg.value=1 SALT
    Then the call reverts with "Credits path accepts no value"
    # Mirrors CreditBilling.tla::NoMixedPayment invariant

  Scenario: postJob with credits but insufficient balance reverts
    Given I have 0 credits
    When I call postJob with paymentMethod=BulkCredits
    Then the call reverts with "Insufficient credits"
    # Mirrors CreditBilling.tla::PostJobCredits precondition
    # `creditBalance[b] >= JobCost`

  Scenario: postJob with credits but stale oracle reverts
    Given the ComputePricingOracle is stale
    When I call postJob with paymentMethod=BulkCredits
    Then the call reverts with the oracle-stale message
    # Modelled in CreditBilling.tla as a scope-out (oracle staleness
    # is its own spec); the implementation enforces via require()

  Scenario: postJob with credits when ComputeMarketplace NOT authorized reverts
    Given ComputeMarketplace is NOT in BulkComputeGateway.authorizedSpenders
    When I call postJob with paymentMethod=BulkCredits
    Then the spendCredits sub-call reverts
    # CreditBilling.tla::PostJobCredits precondition
    # `marketplace \in authorizedSpenders`

  # ── WP-06.2: Authorization ──

  Scenario: Governance authorizes ComputeMarketplace as spender
    When governance calls BulkComputeGateway.authorizeSpender(ComputeMarketplace_address)
    Then BulkComputeGateway.authorizedSpenders[ComputeMarketplace] equals true
    And SpenderAuthorized event is emitted

  Scenario: Non-governance cannot authorize spenders
    When a non-governance address calls authorizeSpender
    Then the call reverts
    # Mirrors CreditBilling.tla::GrantSpender — only via the
    # governance-controlled action

  # ── Refund routing (load-bearing for "no regression") ──

  Scenario: Failed SALT-paid job refunds in SALT
    Given I posted a job with SALT
    When the job fails
    Then I receive a SALT refund equal to my escrow
    And my credit balance is unchanged
    # CreditBilling.tla::FailedSaltRefundsExactly invariant

  Scenario: Failed credits-paid job refunds credits to BulkComputeGateway balance
    Given I posted a job with credits (debited 1 credit)
    When the job fails
    Then my credit balance increases by 1 credit
    And no SALT is sent to my wallet
    # CreditBilling.tla::FailedCreditsRefundsExactly invariant

  # ── WP-06.3: Webapp /credits page ──

  Scenario: Buy credits flow shows updated balance
    Given I have a connected wallet with 100 USDC and approval set
    When I open /credits and submit Buy form for 50 USDC
    Then my BulkComputeGateway credit balance increases by oracle-rate × 50 USDC
    And the page shows the updated balance
    And the Transactions table shows a new CreditsPurchased row

  Scenario: Buy credits without USDC approval shows Approve button
    Given I have USDC but no approval
    When I open /credits and try to buy
    Then an "Approve USDC" button appears with a clear message

  # ── WP-06.4: Webapp payment-method selector ──

  Scenario: Payment-method selector appears when user has credits
    Given I have > 0 credits
    When I open /jobs/new
    Then a "Pay with credits (N available)" radio appears alongside "Pay with SALT"

  Scenario: Posting a job with credits skips wallet SALT send
    Given I have 5 credits
    When I select "Pay with credits" and submit
    Then the on-chain JobPosted event has paymentMethod=1
    And no SALT value is on the tx

  # ── WP-06.5: Gateway credits-aware API key ──

  Scenario: API key with credits backing debits credits per request
    Given an API key was created with --backing credits and 10 credits
    When I POST /v1/chat/completions with that Bearer key
    Then the gateway dispatches without an x402 challenge
    And BulkComputeGateway.computeCredits[institution] decreases by the per-request cost
    And no wSALT settlement happens

  Scenario: API key with SALT backing unchanged from CM-03 WP-03.4
    Given an API key was created with --backing salt and 10 SALT balance
    When I POST /v1/chat/completions with that Bearer key
    Then the existing wSALT-debit behaviour holds (CM-03 WP-03.4
        `valid_key_with_balance_bypasses_x402`)
