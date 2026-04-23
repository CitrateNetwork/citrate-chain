Feature: Compute Provider Listing Visibility
  As a registered compute provider using the Citrate desktop app
  I must see an accurate, live view of what my node is offering
  So that I know my listing is on-chain, my earnings are tracked,
  and I can react when jobs come in

  # Data sources referenced below, per Rule 11:
  #   - ComputeMarketplace.getProvider(address) returns ProviderProfile
  #     (contract: 0x8951ae72e5479cae28ef7bb3caa4207d5719e24b on chain 40204)
  #   - ContributionAccounting.claimable(address) returns uint256 wei
  #     (contract: 0x1afe987622ab5add275d2fd21248f77f5e00667f on chain 40204)
  #   - ComputeMarketplace event logs: JobAssigned, JobCompleted, JobFailed
  #
  # All numeric balances surfaced to the user MUST transit
  # wallet-core/src/format.rs::grains_to_salt before display.
  # The unit the user sees is SALT, not grains/wei. (2026-04-23 unit
  # discipline; see wallet-core/src/format.rs docstring.)

  Scenario: Registered provider sees their listing card on Compute tab
    Given the user has a secp256k1-compatible wallet unlocked in the desktop app
    And the user has successfully registered on ComputeMarketplace with a 1000 SALT stake
    When the user opens the Compute tab
    Then a "Your listing" card is visible
    And the card displays the stake as "1000 SALT" (not raw grains)
    And the card displays the reputation as a percentage (e.g. "98.5%")
    And the card displays the supported-models summary (e.g. "any (wildcard)" for v1)
    And the card displays current active jobs over max concurrent (e.g. "0 / 10")
    And the card displays claimable earnings in SALT

  Scenario: Non-registered user sees no listing card
    Given the user has a wallet unlocked
    And the user has NOT registered on ComputeMarketplace
    When the user opens the Compute tab
    Then the "Your listing" card is not visible
    And the "List on marketplace (1000 SALT)" register button is visible

  Scenario: Claimable balance updates on block progression
    Given the "Your listing" card is visible with claimable = "0 SALT"
    And a JobCompleted event fires for the user's provider address with a payout of 1 SALT
    When at most 15 seconds have elapsed (background poll cadence)
    Then the card's claimable field reads "1 SALT"
    And the "Claim" button becomes enabled

  Scenario: Manual refresh triggers immediate poll
    Given the "Your listing" card is visible
    When the user clicks the "Refresh" button
    Then the app fetches getProvider and claimable immediately
    And the card values reflect the latest on-chain state within 3 seconds
    And the poll does not wait for the next 15-second tick

  Scenario: Recent activity shows last ten jobs
    Given the user's provider has been assigned and completed 12 jobs on-chain
    When the "Your listing" card is rendered
    Then the recent-activity subsection shows exactly 10 rows
    And the rows are ordered by block number descending
    And each row displays job id, block number, and status
    And the status uses the contract enum labels (Assigned, Completed, Failed)

  Scenario: Empty recent activity shows a welcoming empty state
    Given the user's provider has been registered but no jobs have been assigned
    When the "Your listing" card is rendered
    Then the recent-activity subsection shows "No jobs yet — waiting for first assignment"

  Scenario: Listing poll is gated on tab visibility (RPC cost control)
    Given the user is NOT on the Compute tab
    When 30 seconds elapse
    Then zero eth_call requests for getProvider are issued
    And zero eth_call requests for claimable are issued

  Scenario: Wallet locked hides the listing card
    Given the user is registered and previously saw the listing card
    When the wallet session expires (8h timeout)
    Then the listing card is hidden behind the lock screen
    And opening the lock screen prompts for password before any eth_call fires

  Scenario: Chain unreachable shows a degraded state, not a crash
    Given the user is on the Compute tab with a registered provider
    When the configured RPC endpoint becomes unreachable
    Then the card stays visible with the last-known values
    And a "connection lost" indicator is shown on the card
    And the app does not crash or log panic
