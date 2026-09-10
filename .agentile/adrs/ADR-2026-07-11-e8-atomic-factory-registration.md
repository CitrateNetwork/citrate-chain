---
created: 2026-07-11T00:00:00Z
branch: fix/e8-paymaster-registrar
author: Claude Fable 5 (E-8 agent), directed by Larry Klosowski (@SaulBuilds)
status: accepted
work_order: E-8 (citrate-federation planset 2026-07-11-core-upstream-gaps)
repo: citrate-chain
---

# ADR — E-8: factory registers wallets atomically within `deployFor`

## Status

SUPERSEDED (first-op path) by
`ADR-2026-07-11-e8-signature-based-paymaster` after the Rule-8 review
(citrate-security PR #12). The atomic factory→paymaster
`registerWallet` write during `deployFor` was an ERC-7562 cross-entity
storage write (finding E8-1) and has been removed; sponsorship is now
authorized by a signature the paymaster verifies against its own signer.
The EntryPoint-ordering analysis below remains accurate; only the
"register inside deployFor" mechanism is replaced. Retained for
historical context.

## Context

`CitratePaymaster` (contracts/src/aa/paymaster/CitratePaymaster.sol) is
fail-closed: `_validatePaymasterUserOp` reverts
`NotARegisteredCitrateWallet` for any sender with
`isRegistered[sender] == false`, in **every** category including
first-op. Registration is only possible via `registerWallet`, callable
only by the single `registrar` address.

The 40204 ceremony (contracts/script/aa/DeployAA.s.sol) wires
`registrar = CitrateWalletFactory`. But the factory contained **no call
to `registerWallet` anywhere** — so as deployed, no wallet could ever
become registered by anyone, and every sponsorship path was dead:

- **Counterfactual CREATE2 first-op** (the S5 onboarding ceremony):
  EntryPoint v0.7 runs the UserOp's initCode
  (`factory.deployFor`) inside `_validateAccountPrepayment`
  (lib/account-abstraction/contracts/core/EntryPoint.sol L480) and calls
  `paymaster.validatePaymasterUserOp` afterwards, inside the same
  `_validatePrepayment` (L661-666). There is no slot for an out-of-band
  registration transaction between the two — the wallet reaches its
  first sponsored UserOp unregistered and is rejected.
- **Pre-deployed wallet paths** (identity `/aa/enroll-validator` permit →
  factory deploy, then later sponsored ops): the deploy leaves the
  wallet unregistered, so even the *second* transaction is unsponsorable.

Red test reproducing this: `contracts/test/aa/E8FirstOpRegistrar.t.sol`
(committed red-first, per protocol).

## Options

**A. Factory registers atomically within `deployFor`** (chosen).
After a successful (non-idempotent) deploy + init, the factory calls
`paymaster.registerWallet(account)` in the same call frame.

**B. Paymaster accepts factory-predicted addresses for the first-op
category.** The bundler would embed `userId` in the `paymasterAndData`
suffix; the paymaster would accept an unregistered sender iff
`factory.predictAddress(userId) == sender`.

## Decision: Option A

1. **EntryPoint ordering makes A sufficient.** Sender creation
   (initCode → `deployFor`) strictly precedes paymaster validation in
   `EntryPoint._validatePrepayment` (v0.7, vendored: L643 account
   prepayment incl. `_createSenderIfNeeded` at L480, then L661-666
   paymaster prepayment). Registration performed inside `deployFor` is
   therefore visible to `validatePaymasterUserOp` within the same
   UserOp. Proven in-forge with the real EntryPoint
   (`test_E8_realEntryPoint_counterfactualFirstOp_endToEnd`).

2. **A closes the whole gap; B only the first op.** Under B the wallet
   is still unregistered after deployment, so every subsequent
   standard/recovery op still reverts — B would need a registration
   write anyway. A registers once, permanently, closing all paths.

3. **Anti-griefing is preserved, not weakened.** The registry exists so
   the paymaster's deposit only sponsors wallets Citrate actually
   issued. Under A, the registry write stays behind the identity-signer
   permit (`deployFor` verifies the EIP-191 permit before deploying or
   registering; the permit-less idempotent path returns early and never
   registers). Under B, `predictAddress(userId)` succeeds for **any** of
   the 2^256 userIds — the check "sender is a predicted address" is
   vacuous unless the paymaster also verifies the identity permit,
   duplicating factory logic inside validation.

4. **B adds validation-time fragility.** An external call from paymaster
   validation into the factory plus `userId` plumbing through
   `paymasterAndData` and the bundler — more ERC-7562 surface, more
   coupling, for a weaker guarantee.

## Implementation shape

`CitrateWalletFactory` changes (paymaster untouched — it is already
deployed and its registrar model is sound):

- `paymaster` address + `setPaymaster(address)` (owner-gated,
  zero-rejected). A constructor argument is impossible: with CREATE2
  ceremonies the factory and paymaster addresses are mutually dependent
  (paymaster's constructor takes the factory as registrar), so one side
  must be wired post-deploy. The paymaster side is immutable-per-deploy
  via its constructor; the factory side gets the setter.
- `deployFor`: on the initializing path, after init succeeds, calls
  `ICitratePaymasterRegistry(paymaster).registerWallet(account)`.
  **Fail-closed**: if `paymaster` is unwired, `deployFor` reverts
  `PaymasterNotSet` rather than silently minting an unsponsorable wallet
  (that silent degradation *is* the E-8 bug). Registration failures
  bubble up for the same reason.
- The **idempotent path never registers**: a wallet unregistered for
  compromise (paymaster's documented `unregisterWallet` flow) cannot be
  re-registered through the permit-less `deployFor` short-circuit.
- Owner passthroughs `registerDeployedWallet` (requires code at the
  address — backfills wallets deployed before this fix) and
  `unregisterWallet` (incident response). With `registrar = factory`
  permanent, the paymaster's own admin surface is unreachable without
  these; routing them through the factory owner avoids rotating the
  registrar to an EOA, which would break atomic registration.
- `DeployAA.s.sol` wires `factory.setPaymaster(paymaster)` in the same
  broadcast when the broadcaster is the owner, and logs a loud
  `ACTION REQUIRED` line otherwise.

## Consequences / notes for operators and Lane C

- **ERC-7562 note (bundler policy):** during sender creation the factory
  now writes the paymaster's `isRegistered[sender]` slot. That is
  *associated storage of the sender* (mapping keyed by the sender
  address), permitted for a **staked** factory under ERC-7562. Chain
  40204 runs the Citrate bundler, whose policy must stake/whitelist the
  factory accordingly. Flagged in the PR for the bundler operator.
- **Gas:** registration adds one warm external call + one cold SSTORE
  (~25k gas) to the deploy path. The first-op cap
  (`CITRATE_AA_FIRST_OP_CAP`, default 300k) must cover proxy deploy +
  Kernel init + registration + the first action; operators should
  re-check the cap against a measured counterfactual deploy during WP-3
  staging verification.
- **Redeploy required:** the on-chain factory (0x9c0c…68a) predates this
  change; closing the gap on 40204 means redeploying the factory (new
  CREATE2 init code → new address) and pointing the paymaster's
  registrar at it via `setRegistrar` — operator ceremony, Rule-8 gated
  (WP-3, not performed by this work order).
- Wallets deployed by the old factory remain unregistered until
  backfilled via `registerDeployedWallet`.
