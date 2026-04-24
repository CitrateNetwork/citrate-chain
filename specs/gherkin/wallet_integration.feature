Feature: Buyer-webapp wallet integration (Sprint W-01)
  As a buyer using the Citrate webapp
  I want a wallet that signs my transactions and x402 payments
  So that I don't have to paste a private key into a textarea

  Background:
    Given the buyer-webapp is loaded
    And the gateway URL is configured

  # ── CitrateWallet (primary, in-repo) ──

  Scenario: First-time user creates a Citrate wallet
    When I click "Connect wallet" and choose "Citrate Wallet"
    And there is no existing keystore in localStorage
    Then a "Create wallet" prompt appears
    And I enter a passphrase ≥ 12 chars
    And the wallet generates a new secp256k1 key pair
    And the keystore (Web3 Secret Storage v3 envelope) is saved to
        localStorage encrypted under the passphrase
    And my address appears in the header (truncated 0x…aBcD)

  Scenario: Returning user unlocks existing keystore
    Given a keystore exists in localStorage
    When I click "Connect wallet" and choose "Citrate Wallet"
    Then a passphrase prompt appears
    When I enter the correct passphrase
    Then the wallet unlocks
    And my address appears in the header
    # Mirrors WalletLifecycle.tla::UnlockSuccess

  Scenario: Wrong passphrase increments failed-attempt counter
    Given a keystore exists with passphrase "correct-horse"
    When I enter "wrong-pony"
    Then the unlock fails with "invalid passphrase"
    And the failed-attempt counter increments
    # Mirrors WalletLifecycle.tla::UnlockFail

  Scenario: Lockout after MaxFailedAttempts wrong passphrases
    Given the failed-attempt counter is at MaxFailedAttempts - 1
    When I enter another wrong passphrase
    Then the wallet enters LockedOut state
    And further unlock attempts are refused with "wallet locked out;
        delete keystore to retry"
    # Mirrors WalletLifecycle.tla::LockedOutImpliesAttemptsReachedMax

  Scenario: Session timeout drops wallet back to Locked
    Given my wallet is Unlocked
    When SessionTimeoutTicks elapse with no signing activity
    Then the wallet auto-locks
    And subsequent sign attempts prompt for passphrase again
    # Mirrors WalletLifecycle.tla::Tick auto-lock branch

  Scenario: Signing only succeeds while Unlocked
    Given my wallet is Locked
    When the form attempts to sign a digest
    Then the call rejects with "wallet locked"
    And no signature is emitted
    # Mirrors WalletLifecycle.tla::SignatureRequiresUnlock invariant

  Scenario: Manual lock via wallet button
    Given my wallet is Unlocked
    When I click the wallet button → "Lock"
    Then the wallet returns to Locked
    And my address disappears from the header

  Scenario: Switching accounts within an unlocked wallet
    Given my wallet has 2 accounts and is Unlocked on account A
    When I select account B from the wallet menu
    Then the active account becomes B
    And no passphrase prompt appears
    # Mirrors WalletLifecycle.tla::SwitchAccount

  # ── InjectedSigner (fallback) ──

  Scenario: Connect via injected wallet (MetaMask, Rabby, etc.)
    Given window.ethereum is present
    When I click "Connect wallet" and choose "Browser extension"
    Then the injected provider's request("eth_requestAccounts") is called
    And the connected address appears in the header

  Scenario: Injected wallet on wrong chain prompts switch
    Given window.ethereum is connected to chain id 1 (mainnet)
    When the form attempts to send a Citrate testnet tx
    Then the wallet adapter calls wallet_switchEthereumChain to 40204
    And if the user rejects, the form surfaces "switch to Citrate
        testnet to continue"

  Scenario: window.ethereum absent → only Citrate Wallet offered
    Given window.ethereum is undefined
    When I click "Connect wallet"
    Then only "Citrate Wallet" is shown as an option
    And "Browser extension" is hidden with a footnote linking to
        the Citrate extension install page

  # ── Cross-form integration ──

  Scenario: Connected wallet powers Flow A x402 signing
    Given my wallet is Unlocked
    When I submit the Flow A form on /jobs/new
    Then signChallenge runs against my wallet's account
    And the X-PAYMENT header carries my real signed authorization

  Scenario: Connected wallet powers Flow B postJob tx
    Given my wallet is Unlocked
    When I submit the Flow B form (?flow=direct)
    Then sendTransaction goes through my wallet (no dev-key path)

  Scenario: Connected wallet powers /credits balance reads
    Given my wallet is Unlocked at address X
    When I open /credits
    Then the institution-address field auto-fills with X
    And the balance read fires automatically

  # ── Dev signer demoted ──

  Scenario: Dev key path is hidden in production builds
    Given the webapp is built with NODE_ENV=production
    When I open /settings → "Dev signer"
    Then the section is absent
    # Slice 2 honest-deferral: the dev signer section in /settings
    # remains in dev builds for testing convenience but never ships
    # to a production user.
