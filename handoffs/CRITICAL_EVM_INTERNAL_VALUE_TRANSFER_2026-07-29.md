---
created: 2026-07-29
branch: fix/evm-internal-value-transfer
author: Claude (Opus 5), directed by @SaulBuilds
status: CRITICAL — verified on live 40204 + reproduced in a unit test; blocks M-2.0
relates:
  - handoffs/DGX_RESPONSE_CONSENSUS_AND_ALF_2026-07-29.md   (#139 — M-2 build order this blocks)
  - core/execution/src/revm_adapter.rs                      (root cause)
  - core/execution/src/executor.rs                          (the two hand-patched paths)
---

# CRITICAL — contract-initiated native value transfers are silently discarded on 40204

Found while settling the "vault holds 32,000 SALT but the pool's balance is 0" anomaly
that #139 flagged as an open question for M-2.0. It is not an accounting curiosity.
**It is a chain-wide money bug.**

---

## The bug

`StateDBAdapter::commit` (`core/execution/src/revm_adapter.rs:337-345`) deliberately
discards **every balance change REVM computed**, committing only storage and code:

```rust
// ---- Sprint EL-1 Fix (Issue #19) ----
// Do NOT update balance or nonce from REVM. The executor is the
// sole owner of gas/balance/nonce accounting:
```

The executor then re-applies value transfers by hand — but only in **two** places:

1. `execute_call` (`executor.rs:2505-2510`) — the **top-level** `from → to` transfer only.
2. `credit_validator_reward` (`executor.rs:1515-1521`) — one hardcoded system-call path,
   whose own comment reads `// Reflect the value transfer REVM discarded.`

Everything else is dropped. **Any native SALT a contract moves itself — `call{value:}`,
a payable forward, a payout to a user — never moves, while the callee's storage is
committed exactly as if the money had arrived.**

The two hand-patches are evidence the failure mode was known at those two call sites and
generalised from neither.

### Reproduction (red test, committed with this doc)

`core/execution/src/revm_adapter.rs` →
`tests::test_contract_initiated_value_transfer_moves_balance`. A funded contract executes
`CALL(gas, recipient, 1000, 0,0,0,0)`:

```
assertion `left == right` failed: recipient must receive the 1000 wei the contract
CALLed with — a contract-initiated value transfer must not be silently dropped
  left: 0
 right: 1000
```

---

## Confirmed live damage on 40204 (verified 2026-07-29, tip ~82,737)

### 1. `LiquidStakingPool` — 32,000 SALT of phantom accounting

| reading | value |
|---|---|
| `totalPooled` | 32,000 SALT |
| `totalShares` | 32,000 |
| `shares[vault]` | 32,000 |
| `nextWithdrawalId` | **0** — never paid anything out |
| **actual native balance** | **0** |
| `MembershipStakeVault` actual balance | **32,000 SALT** |

Grant tx `0xa17666f3…3809` (block 11,463, status 1): EOA `0xF42a…B483` → vault, value
32,000 SALT. The top-level leg applied correctly. The vault's internal
`pool.deposit{value: 32_000 ether}()` credited the pool's *storage* and minted 32,000
shares — and moved **no SALT**. The 32,000 is still in the vault.

Consequence: the membership money path is already broken end-to-end. `claimReleased`
would drive `pool.claimWithdrawal`, which pays from a pool holding nothing.

### 2. `ValidatorRegistry` — 300 SALT short, and 769,970 SALT about to evaporate

| reading | value |
|---|---|
| 4 active validators × 32,000 stake | 128,000 SALT |
| rewards owed (validator `0x226d0f53…`) | 809,400.000803979 SALT |
| **total obligations** | **937,400.000803979 SALT** |
| **actual native balance** | **937,100.000803979 SALT** |
| **shortfall** | **300.000000000 SALT** (= 30 × the 10-SALT `blockSubsidy`) |

The registry has three value-out paths — `ValidatorRegistry.sol:349` (withdraw), `:360`
(bounty), `:527` (`claimRewards`) — all `payable(msg.sender).call{value: …}("")`, i.e.
all contract-initiated, i.e. **all silently dropped**.

**Active exposure:** validator `0x226d0f53…` has **769,970 SALT claimable right now**.
If they call `claimRewards` today, REVM's balance precheck passes, storage zeroes their
rewards, the call returns success — and they receive nothing. The SALT is unrecoverable
by them afterwards, because the storage claim already happened.

The other three validators have zero rewards accrued and are not yet exposed.

---

## Why this blocks M-2.0 specifically

M-2.0 as specified in #139 replaces the pool-deposit leg with a per-member `MemberBond`
clone that calls `registerValidator{value: principal}`. That is a contract-initiated
value transfer. Under this bug it would register a validator whose 32,000-SALT bond
**does not exist** — injecting phantom stake straight into the consensus-critical
proposer set, with slashing that has nothing to slash.

Building M-2.0 before this is fixed makes the problem materially worse than leaving it
alone. M-2.0 is blocked, not delayed.

---

## What a fix involves (not yet built — owner decision pending)

The principled fix is to stop splitting ownership of balances: let REVM own value
transfer (it already computes it correctly), give REVM a zero gas price so it performs
no gas accounting, keep the executor as owner of gas and nonce, then commit REVM's
balance changes and delete the two hand-patches plus the top-level `journal_transfer`.

Two consequences the owner needs to weigh, and neither is small:

1. **It is a consensus-rule change.** Execution semantics change, so state roots change.
   It needs an activation-height gate (the MP-DEPTH pattern from #138) or a reroll, plus
   a fleet-wide rebuild. This directly contradicts #139's "no reroll, no coordinated
   fleet activation height, contract-only work" premise — that premise was sound given
   what was known then, and is not sound now.

2. **A fix does not heal existing state.** The pool's phantom 32,000 and the registry's
   300-SALT shortfall are already committed to chain state. Repair is a separate
   decision: reroll (clean, and the membership path has exactly one grant to redo), or
   a targeted state migration at the activation height.

---

## Verified vs. assumed

**Verified by direct query or execution:**
chain tip 82,737 / chainId 40204; all balances and accounting readings above; grant tx
hash, block, value and success status; the red test failing as shown; the root-cause
code paths read in full; that no other balance-reconciliation site exists
(`grep` over `core/execution/src`); that no open issue or handoff tracks this.

**Assumed / inferred, not executed:**
that `claimRewards` will drop the payout — this follows necessarily from the proven
mechanism plus the `call{value:}` at `:527`, but I did not spend a validator's real
rewards to confirm it, and should not. The 300-SALT shortfall is *consistent with* 30
un-reconciled block subsidies; I did not isolate which 30 blocks.

**Corrected from the brief I was given:** historical `eth_getBalance` on rpc.citrate.ai
returns latest state for every block parameter (non-archive). Any prior conclusion drawn
from historical balance queries against this endpoint is unsound.
