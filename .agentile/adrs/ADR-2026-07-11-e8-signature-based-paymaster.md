---
created: 2026-07-11T00:00:00Z
branch: fix/e8-paymaster-registrar
author: Claude Fable 5 (E-8 remediation agent), directed by @SaulBuilds
status: active
work_order: E-8 remediation (Rule-8 review CitrateNetwork/citrate-security PR #12)
repo: citrate-chain
supersedes: ADR-2026-07-11-e8-atomic-factory-registration (first-op path)
closes: security-review #12 findings E8-1, E8-2, E8-3 (PR #67 lens 67-*)
---

# ADR — E-8: signature-based verifying paymaster (supersedes atomic-factory-registration)

## Status

Active. Implemented on `fix/e8-paymaster-registrar` (PR #67). Directed by
the owner after the Rule-8 review (citrate-security PR #12,
`reviews/2026-07-11-rule8-core-membership-and-e8/`). CRIT-1
(factory-address migration) is **owner-DISMISSED** for the sandboxed
testnet (no real funds at counterfactual addresses); address derivation
is unchanged and no migration logic is added.

## Context — what the review found

The predecessor ADR (`ADR-2026-07-11-e8-atomic-factory-registration`)
had the factory call `paymaster.registerWallet(account)` from inside
`deployFor`, which runs as a UserOp's initCode. Three review findings:

- **E8-1 (HIGH).** That call writes a **second entity's** storage
  (`CitratePaymaster.isRegistered[account]`) during the validation
  phase. ERC-7562 associated-storage allowances (STO-020/031/032) are
  scoped to **non-entity** contracts; the paymaster is an entity named in
  the same UserOp (`paymasterAndData`). A strict `debug_traceCall`
  bundler rejects the cross-entity write regardless of factory stake.
- **E8-2 (HIGH).** The paymaster compared a **wei** `maxCost`
  (`requiredPreFund = requiredGas × maxFeePerGas`, EntryPoint L412)
  against caps documented/defaulted as **gas units** (300k/200k/100k).
  At any nonzero gas price the first-op — and standard and recovery —
  reverted `FirstOpCapExceeded`. A naive wei re-tune re-opens an
  over-sponsor drain (inflated `maxFeePerGas` up to a generous wei cap),
  and there is no global spend backstop.
- **E8-3 (HIGH, test-integrity).** The "real EntryPoint e2e" used
  `handleOps` (execution — exempt from validation-time storage rules) at
  `gasFees = 0` (masking E8-2). It proved ordering, not mempool
  acceptance and not the cap fix.

## Decision

### E8-1 — authorize sponsorship by SIGNATURE, not by a validation-time write

The factory **no longer** calls `registerWallet` from `deployFor`. The
counterfactual first op (and every sponsored op) is authorized by an
ECDSA signature from a trusted **`sponsorSigner`** stored in the
paymaster's **own** storage. During validation the paymaster touches
only its own storage + `ecrecover` — no entity writes another entity's
storage. This is the invariant asserted by the new tests.

**Dedicated `sponsorSigner` (not reuse of `identitySigner`).** The
factory's `identitySigner` authorizes *deploys* (factory domain); the
paymaster's `sponsorSigner` authorizes *deposit spend* (paymaster
domain). Separation of duties: a leaked deploy-permit signer must not be
able to drain the paymaster deposit, and vice versa. The deploy script
defaults `sponsorSigner` to `identitySigner` for single-key operators
but SHOULD be set to a distinct key in production
(`CITRATE_AA_SPONSOR_SIGNER`).

**Signed-message schema** (`CitratePaymaster.sponsorDigest`):

```
keccak256(abi.encode(
    block.chainid,     // cross-chain replay protection
    address(this),     // this paymaster — domain separation / cross-paymaster replay
    account,           // op sender — cross-wallet replay protection
    category,          // 0 standard / 1 recovery / 2 first-op — a standard grant can't be spent as first-op
    validUntil,        // uint48 — last valid timestamp (0 == no upper bound)
    validAfter         // uint48 — first valid timestamp
))
```

signed as an EIP-191 personal-sign digest (`toEthSignedMessageHash`),
recovered with OZ `ECDSA.tryRecover` (no malleability accept). The
signature (65 bytes) and window travel in the `paymasterAndData` suffix:

```
[0:20]    address paymaster
[20:36]   uint128 paymasterVerificationGasLimit
[36:52]   uint128 paymasterPostOpGasLimit
[52]      uint8   category
[53:59]   uint48  validUntil
[59:65]   uint48  validAfter
[65:130]  bytes65 sponsorSigner signature (r||s||v)
```

The paymaster returns the packed `validationData`
(`_packValidationData(false, validUntil, validAfter)`) so the EntryPoint
enforces the same `[validAfter, validUntil]` window (belt-and-suspenders
with the in-contract window check).

**Registration is retained but moved out of validation.** `isRegistered`
still gates the **standard** and **recovery** categories (a paymaster
reading its **own** storage during its own validation is legal —
STO-010). First-op does **not** require registration — the signature is
the authorization — so a counterfactual wallet's first op needs zero
cross-entity writes. Registration now happens **outside** the validation
phase via the factory's owner passthrough `registerDeployedWallet`
(post-deploy) — never during a UserOp's initCode.

**Anti-griefing preserved.** Only signer-authorized ops are sponsored.
Mass drain still requires a compromised `sponsorSigner` (pre-existing
trust, now separated from the deploy signer).

**First-op one-per-account.** Kept via `hasUsedFirstOp`, set in
`_postOp` (LOW-1). A same-account same-bundle double-first-op is not
closed by a validation-time transient guard here: forge cannot model the
bundler's intra-bundle sequencing, and a transient-storage guard set in
validation is cleared by the EntryPoint between ops. We rely on the
bundler's standard one-op-per-sender-per-bundle rule (ERC-7562), and the
per-op `firstOpCap` + global daily cap bound the worst case to two
first-op spends. Documented, not silently assumed.

### E8-2 — wei caps + fee ceiling + global backstop

- **All three caps in WEI.** Defaults (40204 `min_gas_price = 1 gwei`,
  `devnet-config.toml:38`):
  - `maxFeePerGasCeiling = 20 gwei` — 20× the 1-gwei floor; the
    load-bearing drain guard.
  - `firstOpCap = 0.02 ether` = 800k gas × 20 gwei. A counterfactual
    proxy deploy + Kernel init + first action ≈ 500k gas; +headroom to
    800k.
  - `recoveryEventCap = 0.01 ether` = ~300k gas × 20 gwei (guardian
    recovery).
  - `dailyCap = 0.01 ether` = ~500k gas × 20 gwei (a few standard
    ops/day).
  - `globalDailyCap = 5 ether/day` aggregate across ALL accounts. At the
    realistic 1-gwei price a first-op costs ~0.0005–0.0008 ether, so
    5 ether/day tolerates thousands of onboardings while capping a
    fee-inflation drain to 5 ether before that day's sponsorship fails
    closed — a loud, self-limiting drain signal.
- **Fee ceiling.** `maxFeePerGas > maxFeePerGasCeiling` reverts. Even at
  the generous 0.02-ether first-op cap, an op cannot claim more than
  20 gwei/gas, so a single op cannot drain more than its wei cap and only
  at ≤20 gwei.
- **Global backstop.** `globalUsage.spentWei` accumulates `actualGasCost`
  (wei) across all accounts in `_postOp`; validation refuses any op that
  would push the day's aggregate over `globalDailyCap`. Own storage only.
- **Units fixed throughout.** `DailyUsage.used` → `usedWei`
  (accumulates `actualGasCost`, which IS wei); comments/errors/events say
  WEI. `DeployAA.s.sol` defaults and header math updated.

All ceilings/caps are `0 == disabled` for backward-compatible tuning,
but the deploy script sets positive production defaults.

### E8-3 — tests that prove the claims

- `test_E8_realEntryPoint_counterfactualFirstOp_nonzeroGasPrice`: a full
  counterfactual first op sponsored end-to-end via `handleOps` at
  **1 gwei** (nonzero). This PASSES with the E8-2 wei caps and would have
  reverted `FirstOpCapExceeded` under the old gas-unit caps.
- `test_E8_simulateValidation_counterfactualFirstOp_noCrossEntityWrite`:
  uses the vendored `EntryPointSimulations.simulateValidation` — the
  account-abstraction harness that runs account validation (initCode →
  `deployFor`) THEN paymaster validation WITHOUT executing the op — and
  asserts (a) paymaster validation succeeds (`paymasterValidationData`
  sig-not-failed), and (b) after simulation the factory left the
  paymaster's `isRegistered[sender]` slot **untouched** (the E8-1
  invariant). Negative tests: wrong signer, cross-wallet, cross-category,
  expired window (paymaster suite); over-sponsor fee-ceiling and
  global-cap exhaustion (paymaster suite).

**What E8-3 can prove in forge / honest residual gap.**
`simulateValidation` proves the validation path *succeeds* and lets us
assert the storage invariant by direct inspection (no factory write to
paymaster storage). Forge **cannot** run the ERC-7562 opcode/storage
**tracer** itself, so it does not independently re-derive a bundler's
banned-storage-access verdict. What the test *does* establish is
stronger than the old `handleOps` test: (1) validation-phase success
with the signature gate, and (2) zero factory writes to paymaster
storage across the whole validation — the exact behavior E8-1 flagged.
Since the factory no longer contains any paymaster-storage write on the
`deployFor` path, the class of violation E8-1 identified is removed at
the source, not merely untested. A live `debug_traceCall` against the
Citrate bundler remains the final acceptance step (WP-3 staging) and is
NOT claimed here.

## Consequences / notes for operators and Lane C

- **Sponsorship signer service.** `auth.citrate.ai` (or a dedicated
  sponsorship service) must sign the `sponsorDigest` for each sponsored
  op and embed it in `paymasterAndData`. The SDK reconstructs the digest
  via `pm.sponsorDigest(account, category, validUntil, validAfter)`.
- **E8-4 (permissionless bundling).** The cross-entity write is gone, so
  the factory no longer *forces* a staked/whitelisted bundler for the
  first-op path. The paymaster is now a standard verifying paymaster
  (signature in `paymasterAndData`), which is portable across ERC-4337
  bundlers. Remaining stake requirements are the ordinary paymaster
  stake, not a policy deviation.
- **MED-1 / MED-2 (registrar reconciliation, arbitrary backfill).** Not
  in scope of E8-1/2/3; unchanged. `registerDeployedWallet` still accepts
  any code-bearing address (owner-trusted). The single-registrar-slot
  reconciliation deadlock is unchanged. Flag for a follow-up.
- **CRIT-1 (address migration).** Owner-dismissed for the sandboxed
  testnet; no derivation change, no migration logic. Must be revisited
  before any mainnet cutover if counterfactual addresses carry real
  funds.
- **Gas.** The deploy path is now *cheaper* (no register SSTORE/external
  call). Validation adds one `ecrecover` + a uint48×2 read + (optional)
  global-cap read — all own storage.
