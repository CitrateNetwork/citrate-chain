---
created: 2026-11-08T22:00:00Z
branch: feat/v060-genesis-workmarket
author: Larry Klosowski + Claude Opus 5.5 (MAC lane, V60-GEN)
status: draft (ceremony-genesis candidate; not deployed; internal audit GEN-AUDIT pending)
spec: citrate-federation .agentile/planset/2026-11-07-v060/06_CONTRACTS.md §2-§4, §6-§8
---

# WorkMarket, FLRoundVerifier, TaskVerifier

Ceremony-genesis candidates (0.6.0 owner answer 7, 2026-11-07; TaskVerifier confirmed 2026-11-08).
**Nothing here is deployed.** r1007 keeps today's contract set. These contracts go into the
ceremony genesis only from the signed `v060-contracts-freeze` tag after the internal audit
(GEN-AUDIT). The design is in the planset; this file records what the code does where the
planset left a choice open, and the constructor parameters (GEN-PARAMS).

Sources: `contracts/src/work/{IVerifier,WorkMarket,FLRoundVerifier,TaskVerifier}.sol`; tests
`contracts/test/work/`.

## Roles

| Role | Who at genesis | What it can do | What it cannot do |
|---|---|---|---|
| Governance (`Governable`, two-step transfer) | the governance timelock (3-of-5 / 48 h) | allow or deny verifiers for **new** offers; pause and unpause **new** offers; set the guardian | touch any escrow, bond or pull balance; change an offer's price, verifier or terms; block `join`, `postPayout`, `dispute`, `settle`, `refund`, `claimBond`, `withdraw` |
| Guardian | the guardian council (2-of-3), or zero | pause new offers | unpause; anything else |
| Poster | any account | open (escrows the budget); dispute; refund what no root can claim; accept a TASK result (TaskVerifier) | take escrow a posted, undisputed root reserves |
| Coordinator | named by the poster at `open` (FL: the round's coordinator; TASK: the selected worker) | post the payout root (with the poster-set bond) once the verifier accepts; claim its bond after an undisputed window | post after the deadline; post more units than the budget buys |
| Dispute admin | named at `open`, group TASK offers only | uphold or reject a subjective dispute | anything on FL offers or open tasks |
| Worker | any account meeting the price floor and allowlist | join; dispute; settle its leaf (anyone can call `settle` for it); claim its join bond; withdraw | be paid twice; be paid without joining |
| FLRoundVerifier | none (no owner) | — | — |
| TaskVerifier | none (no owner) | — | — |

## Where the code chose, and why (spec deltas for review)

Each is also an owner or reviewer question in the sprint file
(`citrate-federation/.agentile/sprints/active/2026-11-08-V60-S0-contracts-genesis.md`).

1. **`open` takes a struct** (`OpenParams`) instead of 14 flat arguments, and gains
   `coordinatorBond` and `disputeAdmin`. 06 §2 stores both in the offer and §2.2 relies on them,
   but `open` had no argument for either.
2. **Payout tree.** `postPayout(id, root, units)` takes the leaves root; the contract stores
   `payoutRoot = keccak256(abi.encode(PAYOUT_TAG, digest, root))` (06 §2.1 "root binds digest").
   Leaves carry an index and a running prefix sum: `payload = keccak256(abi.encode(LEAF_TAG,
   chainid, market, offerId, worker, units, cumBefore))`, `leaf = keccak256(0x00 ‖ uint32 i ‖ payload)`,
   padding leaves are zero, nodes are `keccak256(0x01 ‖ l ‖ r)` (the FederatedRoundLedger tree).
   Leaves sort by strictly ascending worker and precede padding. The index makes the spec's
   sorted-tree non-inclusion proof possible. The prefix sum lets `settle` check
   `cumBefore + units <= payoutUnits` per leaf, and makes over-allocation provable on chain.
   Without it, a root whose leaves sum to more than the posted units pays the first settlers
   and leaves the rest unpaid, with nothing to dispute.
3. **`settle` takes `cumBefore` and `index`** for the same reason.
4. **Objective disputes** (upheld automatically): `MISSING_LEAF` (coordinator-signed receipt
   plus a bracketing pair, a first or last leaf, or an empty tree), `LOW_UNITS` (more distinct
   signed leases than the leaf's units), `ORDER` (neighbours unsorted, prefix sums that do not
   abut, or padding before a real leaf), `FIRST_LEAF` (prefix sum not starting at zero). An
   upheld dispute withdraws the root, slashes the coordinator bond (`SLASH_DISPUTER_BPS` = 50 %
   to a disputer who is not the poster, the rest to the poster), and returns the offer to Running
   so a new root can be posted before the deadline.
   Receipt digest: `keccak256(abi.encode(RECEIPT_TAG, chainid, market, offerId, worker, leaseId,
   deltaHash, true))`, EIP-191-signed by the coordinator (EIP-1271 for contract coordinators).
   The coordinator software (citrate-compute-pool) must sign this exact digest.
5. **Known limit, objective disputes:** a leaf whose payload is not a valid
   `(worker, units, cumBefore)` preimage cannot be opened, so it can hide one absent worker from a
   `MISSING_LEAF` proof. A challenge-response variant (the coordinator must prove inclusion
   within a response window) closes this, at the cost of another window. This is a reviewer
   question.
6. **Subjective disputes (TASK, poster only, one per posted payout):** the offer goes to
   Disputed and settle stops. Group tasks: the dispute admin upholds (root withdrawn, worker's
   bond **returned**, offer Running) or rejects (payout stands). Open tasks: no admin, so the
   poster refunds after `deadline + disputeWindow` and the worker's bond is returned.
7. **Refund after a posted root** returns `budget − payoutUnits × price`, not `budget − paid`.
   06 §2.1 allows `budget − paid` after `deadline + disputeWindow`, but a root posted near the
   deadline only opens for settling at about the same time, so `budget − paid` would let the
   poster take what the root owes unsettled workers (RT-11). The reserve stays settleable with
   no time limit; whether it should return to the poster after a claim period is an owner
   question.
8. **Expired** = the deadline passed with no live root (none can be posted any more); the
   poster may refund at once. 06 §7.5 allows refund before `deadline + window` only when Expired.
9. **Join bonds are never slashed** (06 §2 says "refunded on settle or expiry"). They are
   released on settle, when the offer is Closed or Expired, or after `deadline + disputeWindow`.
   06 §2.1 `refund` mentions "unreleased bonds" going to the poster. The code does not do that,
   pending the owner's answer.
10. **The verifier is fixed at `open`.** De-allowlisting it later blocks new offers only, so
    governance cannot freeze a live offer's payout.
11. **`claimBond(id)`** is new: it releases the caller's join bond and, for the coordinator, the
    coordinator bond once the window has passed undisputed.
12. **FLRoundVerifier `bindRef` = the FRL round id** `roundIdOf(clusterId, ordinal)`. 06 §3
    decodes `(clusterId, ordinal)` from `bindRef`, which a hash does not allow. FRL keys rounds
    by that id, so no registration step is needed.
13. **TaskVerifier keys results by market** (`submit(market, offerId, hash)`,
    `accept(market, offerId, hash)`; `accepted` uses `msg.sender`). WorkMarket's block-0
    allowlist names TaskVerifier, so TaskVerifier's init code cannot name WorkMarket without a
    CREATE2 cycle. TaskVerifier has no dispute of its own: the requester disputes the posted
    payout in WorkMarket (point 6).

## GEN-PARAMS (constructor parameters for the ceremony genesis spec)

No addresses are fixed here. The genesis spec fills them from the ceremony's canonical book
(CV-12). All three are plain contracts (no proxy), deployed by CREATE2 with a fixed salt each, so
their addresses are known before the ceremony.

| Contract | Parameter | Value class | Notes |
|---|---|---|---|
| FLRoundVerifier | `frl_` | the genesis FederatedRoundLedger (CREATE2, already in the r1006 set) | immutable |
| TaskVerifier | `reviewWindow_` | seconds, 1 h ≤ x ≤ 30 d | immutable; owner picks (proposal: 72 h) |
| WorkMarket | `governance_` | the governance timelock | two-step transfer; may not be the CREATE2 factory (Governable) |
| WorkMarket | `guardian_` | the guardian council 2-of-3, or zero | settable later by governance |
| WorkMarket | `initialVerifiers_` | `[FLRoundVerifier, TaskVerifier]` | the CREATE2-predicted addresses above; deploy order: FRL, the two verifiers, then WorkMarket |

Fixed in code (not parameters): `MIN_DISPUTE_WINDOW` = 24 h, `MAX_WORKERS_CAP` = 1024,
`SLASH_DISPUTER_BPS` = 5000, `MAX_RECEIPTS_PER_DISPUTE` = 256. Native SALT only; the market
refuses plain transfers (no `receive`).

The genesis-spec test (GEN-PARAMS red test) is still to write: the block-0 code hash of each
contract must equal the freeze-tag build.
