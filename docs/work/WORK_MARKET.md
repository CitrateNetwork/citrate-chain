---
created: 2026-11-08T22:00:00Z
branch: feat/v060-genesis-workmarket
author: Larry Klosowski + Claude Opus 5.5 (MAC lane, V60-GEN)
status: draft (ceremony-genesis candidate; owner decisions of 2026-11-09 and the #451 review fixes (rounds 1-3) applied; not deployed; internal audit GEN-AUDIT pending)
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
| Guardian | the guardian council (2-of-3); required at construction (`InitialAdmin.check`), governance may later clear it | pause new offers | unpause; anything else |
| Poster | any account | open (escrows the budget); dispute; refund what no root can claim; accept a TASK result (TaskVerifier) | take escrow a posted, undisputed root reserves |
| Coordinator | named by the poster at `open` (FL: the round's coordinator; TASK: the selected worker, who must have joined) | post the payout root (with the poster-set bond) once the verifier accepts; claim its bond after an undisputed window | post after the deadline; post more units than the budget buys; post a tree deeper than `maxWorkers` needs |
| Dispute admin | named at `open`; required on group TASK offers, refused everywhere else | uphold or reject a subjective dispute (upholding waits for open challenges) | anything on FL offers or open tasks |
| Worker | any account meeting the price floor and allowlist | join; dispute; settle its leaf (anyone can call `settle` for it); claim its join bond; withdraw | be paid twice; be paid without joining |
| FLRoundVerifier | none (no owner) | — | — |
| TaskVerifier | none (no owner) | — | — |

## Where the code chose, and why (spec deltas for review)

The owner approved all of them on 2026-11-09 (V60-GEN Q1-Q11; record in
`citrate-federation/.agentile/sprints/active/2026-11-08-V60-S0-contracts-genesis.md` and 06).
Items marked "#451 review" (round 1: the depth argument, index challenges, the post-answer
window, commit-reveal disputes; and the changes they make to points 2-6 and 13) and
"#451 review 2" (round 2: the tree-total dispute, committed-only dispute rewards, the
time-based reveal delay, challenge bonds, the coordinating-poster slash rule) and
"#451 review 3" (round 3: the slash sink, held challenge bonds paid to the coordinator, the
commit deadline, the minimum coordinator bond) come from the independent reviews of chain #451
and are not yet owner-approved. Round 3 changes Q4 where the poster's share is concerned (see
point 4); every other owner answer stands.

1. **`open` takes a struct** (`OpenParams`) instead of 14 flat arguments, and gains
   `coordinatorBond` and `disputeAdmin`. 06 §2 stores both in the offer and §2.2 relies on them,
   but `open` had no argument for either. A `coordinatorBond` of 0 takes the protocol default,
   `defaultCoordinatorBond`, a constructor parameter above zero (Q1).
2. **Payout tree.** `postPayout(id, root, units, depth)` takes the leaves root and the tree depth; the contract stores
   `payoutRoot = keccak256(abi.encode(PAYOUT_TAG, digest, root))` (06 §2.1 "root binds digest").
   Leaves carry an index and a running prefix sum: `payload = keccak256(abi.encode(LEAF_TAG,
   chainid, market, offerId, worker, units, cumBefore))`, `leaf = keccak256(0x00 ‖ uint32 i ‖ payload)`,
   padding leaves are zero, nodes are `keccak256(0x01 ‖ l ‖ r)` (the FederatedRoundLedger tree).
   Leaves sort by strictly ascending worker and precede padding. The depth is stored with the
   root (`payoutDepth`) and may not exceed the depth `maxWorkers` needs (`BadDepth`); every
   opening, in `settle` and in disputes alike, must carry exactly `payoutDepth` siblings and an
   index below `2^payoutDepth`, so a leaf that settles always opens as dispute evidence. The index makes the spec's
   sorted-tree non-inclusion proof possible. The prefix sum lets `settle` check
   `cumBefore + units <= payoutUnits` per leaf. **The tree total must equal `payoutUnits`**
   (#451 review 2): the last real leaf must end exactly at `payoutUnits`. The contract never
   sees the leaves at `postPayout`, so this is enforced by dispute (`DISPUTE_TOTAL`, point 4):
   a root whose leaves sum past the posted units (which would pay the first settlers and leave
   a later worker unable to settle) or short of them (which would let the poster refund work the
   tree pays for) is a provable coordinator fault. Undisputed, `settle` still never pays past
   `payoutUnits`.
3. **`settle` takes `cumBefore` and `index`** for the same reason, and verifies them with the
   same opening rule as disputes (depth and index range).
4. **Objective disputes** (upheld automatically): `MISSING_LEAF` (coordinator-signed receipt
   plus a bracketing pair, a first or last leaf, or an empty tree), `LOW_UNITS` (more distinct
   signed leases than the leaf's units), `ORDER` (neighbours unsorted, prefix sums that do not
   abut, or padding before a real leaf; `ORDER` takes **any two** openable leaves `i < j`, not
   only neighbours, and is proven by `worker_i >= worker_j` or `cumBefore_i + units_i > cumBefore_j`,
   or padding at `i` before a real leaf at `j`; neighbours must still abut exactly),
   `FIRST_LEAF` (prefix sum not starting at zero), `TOTAL` (#451 review 2: any openable real
   leaf with `cumBefore + units > payoutUnits`; or the last real leaf, shown by being the tree's
   last slot or by padding opening in the next slot, ending below `payoutUnits`; or padding at
   slot 0, an empty tree posted with units). An upheld dispute withdraws the root, slashes the
   coordinator bond and returns the offer to Running so a new root can be posted before the
   deadline. The slash (#451 reviews 2 and 3): the poster never takes back a slash it could have
   brought about itself, since its coordinator may be a second address of its own.
   - A direct `dispute()` call, or any dispute or challenge by the poster (committed or not):
     the whole bond goes to `slashSink`, a constructor-set immutable (the governance treasury,
     GEN-PARAMS). So a poster that coordinates through a second address and disputes its own
     root recovers nothing; nor does a copier who lands a revealed dispute through `dispute()`.
   - A revealed commitment (point 5c) or an unanswered challenge, by someone other than the
     poster: the whole bond to the disputer when the poster is the coordinator; otherwise
     `SLASH_DISPUTER_BPS` = 50 % to the disputer and the rest to the poster (Q4).
   This replaces Q4's "the poster disputes and takes 100 %": that path is exactly how a poster
   with a second-address coordinator would undo its own slash. Every upholding path
   (`dispute`, `revealDispute`, `resolveChallenge`, `resolveIndexChallenge`) goes through this
   one rule; the subjective path never slashes (the worker's bond is returned, point 6).
   Receipt digest: `keccak256(abi.encode(RECEIPT_TAG, chainid, market, offerId, worker, leaseId,
   deltaHash, true))`, EIP-191-signed by the coordinator (EIP-1271 for contract coordinators).
   The coordinator software (citrate-compute-pool) must sign this exact digest.
5. **Inclusion challenge (Q11).** A leaf whose payload is not a valid `(worker, units,
   cumBefore)` preimage cannot be opened, so it could hide an absent worker from a
   `MISSING_LEAF` proof. `challengeInclusion(id, receipts)`: inside the window a joined worker or
   the poster presents coordinator-signed receipts for one joined worker. `answerChallenge(id,
   leaf)`: anyone, until `answerBy` (+24 h, `CHALLENGE_RESPONSE_WINDOW`), opens that worker's leaf
   with at least the receipted units. Otherwise `resolveChallenge(id, worker)` upholds it like an
   objective dispute (`DISPUTE_UNANSWERED_CHALLENGE`). Settle, the coordinator bond and the
   poster's refund wait while a challenge is open. The answer records the opened leaf's units, and
   a worker is re-challenged under the same root only with more receipts than that, so a spurious
   challenge costs one answer (a claim above the leaf's units is a `LOW_UNITS` dispute anyway).
5a. **Index challenge (#451 review).** A worker challenge only forces open the challenged
   worker's own leaf, so an unopenable leaf elsewhere could still separate two leaves whose
   ranges overlap. `challengeIndex(id, i)`: inside the window, a joined worker or the poster names
   a slot `i < 2^payoutDepth`. `answerIndexChallenge(id, leaf)`: anyone, until `answerBy` (+24 h),
   opens slot `i` as a real leaf or as padding (the zero leaf). Otherwise
   `resolveIndexChallenge(id, i)` upholds it like an objective dispute. A slot answered under the
   live root cannot be challenged again. With every slot forceable and the any-pair `ORDER`
   proof, two leaves that claim overlapping units are always disputable.
5b. **Disputes stay open after an answer.** Any challenge answer sets `answerGraceUntil = now +
   POST_ANSWER_DISPUTE_WINDOW` (24 h). Disputes stay open, and settle, the coordinator bond and
   the PayoutPosted refund wait, until the later of the window end and that time, so a leaf the
   coordinator opens at the last moment can still be used in a dispute. Challenges themselves
   can only be raised inside the original window, so the extension is bounded: at most
   `CHALLENGE_RESPONSE_WINDOW + POST_ANSWER_DISPUTE_WINDOW` (48 h) past the window end.
5c. **Committed disputes (#451 review; rewards and delay #451 review 2).** Dispute evidence is
   objective, so a copier who sees a dispute transaction before it lands could submit the same
   evidence first. `commitDispute(id, c)` with
   `c = disputeCommitment(id, payoutEpoch, msg.sender, evidence, salt)`, then
   `revealDispute(id, evidence, salt)` at least `DISPUTE_REVEAL_DELAY` (60 s) later, inside the
   dispute window, binds the reward to the committer. `commitDispute` is refused once the reveal
   could no longer land before the dispute end (#451 review 3). The delay is measured in block time, not
   `block.number`: on the BlockDAG, merged parallel blocks can repeat or lower the header
   height. `dispute()` stays callable, so a fault can always be proven at once, but it earns no
   disputer share (the slash goes to `slashSink`, point 4), so copying a reveal into `dispute()`
   earns nothing. What remains: a copier who
   commits after seeing a reveal can only win if that reveal stays unincluded for the whole
   delay; the contract cannot tell which of two hidden commitments came first.
   *Timestamps (#451 review 3).* All windows here are measured in block time and assume the
   r1007 bound on future block timestamps, 15 s (R1007_CHAIN_PARAMS, genesis lane; r1006 main
   allows 900 s, `hardening.rs`). `DISPUTE_REVEAL_DELAY` is kept at least 4x that drift (60 s
   against 15 s), so a producer that stamps a block early cannot open a reveal in the same
   moment as its commitment. If the drift bound is ever raised, the delay must be raised with it.
5d. **Challenge bonds (#451 review 2).** `challengeInclusion` and `challengeIndex` take
   `challengeBondOf(id)` = `CHALLENGE_BOND_BPS` (10 %) of the coordinator bond, rounded up.
   Upheld (unanswered): returned to the challenger with its slash share. Answered: held until
   the root survives its dispute window, then paid to the offer's coordinator; if the root is
   withdrawn instead, returned to the challenger and the coordinator gets nothing (#451 review 3:
   a coordinator no longer profits from a root that turns out bad, and a finder who forced the
   opening that exposed it loses nothing). The coordinator, not whoever answered, is paid, so a
   challenger that answers its own challenge (or answers from a second address) to delay
   settling by up to 48 h pays its bond for the delay; that was chosen over only documenting the
   48 h bound because it costs nothing in honest use (honest challengers are answered by the
   coordinator anyway). `releaseChallengeBond` / `releaseIndexChallengeBond` (anyone may call)
   pay a held bond to whichever party it belongs to; raising a challenge on the same slot or
   worker under a new root also refunds a stale one. Chosen over re-posting after the deadline
   because a bond prices the spam (the late-challenge griefing of point 14 costs the griefer the
   bond per challenge the coordinator answers) without adding a post-deadline state in which the
   poster's refund would have to wait; the remaining risk, a coordinator that fails to answer in
   24 h, is the same liveness the workers already rely on for the coordinator to post at all.
   *For the owner decision list (#451 review 3):* a coordinator that withholds a correct tree
   still earns 10 % of its bond per forced opening, once the root survives. With round 3 it earns
   nothing when the root is then withdrawn, so withholding pays only on honest trees and only from
   workers who chose to challenge. Options if that is unwanted: send dismissed bonds to
   `slashSink`, or require the coordinator to publish the full tree (a data-availability
   commitment) and refund challenges on published slots.
6. **Subjective disputes (TASK, poster only, one per posted payout):** the offer goes to
   Disputed and settle stops. Group tasks (which must name a dispute admin): the dispute admin
   upholds (root withdrawn, worker's bond **returned**, offer Running) or rejects (payout stands).
   Upholding bumps `resultEpochOf(id)`; TaskVerifier keeps the epoch with each result and stops
   counting an older one, so the rejected result cannot be posted again, and the worker may
   submit a corrected result even if the requester had accepted the old one. Open tasks: no
   admin, so the poster refunds after `deadline + disputeWindow` and the worker's bond is
   returned. Upholding, and the refund of a Disputed offer, wait while a challenge is open, so
   the challenger's share of the slash is not lost; resolving the challenge first pays it.
7. **Refund after a posted root** returns `budget − payoutUnits × price`, not `budget − paid`.
   06 §2.1 allows `budget − paid` after `deadline + disputeWindow`, but a root posted near the
   deadline only opens for settling at about the same time, so `budget − paid` would let the
   poster take what the root owes unsettled workers (RT-11). The reserve stays settleable until
   the poster calls `sweepReserve(id)`, allowed after `deadline + disputeWindow + 180 days`
   (`RESERVE_CLAIM_PERIOD`, Q3); settling stops after the sweep.
8. **Expired** = the deadline passed with no live root (none can be posted any more); the
   poster may refund at once. 06 §7.5 allows refund before `deadline + window` only when Expired.
9. **Join bonds are never slashed** (06 §2 says "refunded on settle or expiry"). They are
   released on settle, when the offer is Closed or Expired, or after `deadline + disputeWindow`.
   Owner 2026-11-09 (Q5): join bonds always go back to the worker; 06 §2.1 is corrected.
10. **The verifier is fixed at `open`.** De-allowlisting it later blocks new offers only, so
    governance cannot freeze a live offer's payout.
11. **`claimBond(id)`** is new: it releases the caller's join bond and, for the coordinator, the
    coordinator bond once the window has passed undisputed.
12. **FLRoundVerifier `bindRef` = the FRL round id** `roundIdOf(clusterId, ordinal)`. 06 §3
    decodes `(clusterId, ordinal)` from `bindRef`, which a hash does not allow. FRL keys rounds
    by that id, so no registration step is needed.
13. **TaskVerifier keys results by market and result epoch** (`submit(market, offerId, hash)`,
    `accept(market, offerId, hash)`; `accepted` uses `msg.sender`). WorkMarket's block-0
    allowlist names TaskVerifier, so TaskVerifier's init code cannot name WorkMarket without a
    CREATE2 cycle. TaskVerifier has no dispute of its own: the requester disputes the posted
    payout in WorkMarket (point 6); an upheld one moves the market's `resultEpochOf` and so
    rejects the result here.
14. **Known trade-offs (documented, not fixed in v1).**
    - *Slot squatting.* With `joinBond = 0` and no allowlist, anyone can join until `maxWorkers`
      is reached and so keep honest workers out; joined accounts may also raise challenges. A
      poster who expects that sets a join bond (returned to the worker in every case, Q5) or an
      `allowlistRoot`.
    - *Poster as coordinator (#451 reviews 2, 3).* `open` does not forbid `coordinator == poster`:
      the poster could name a second address it controls, so a ban would only hide the case.
      After `DISPUTE_TOTAL` a coordinating poster cannot under-post units or over-sum the tree
      unpunished: a committed dispute pays its whole bond to the disputer, and its own dispute
      sends the bond to `slashSink`, so it recovers nothing whether it coordinates in its own
      name or through a second address. It can still, like any
      coordinator, never post a root and refund after the deadline: the coordinator's liveness
      is trusted, and the bond prices only bad roots. Workers choose offers by coordinator.
    - *Late-challenge liveness.* A challenge raised just before the window ends delays settling,
      the coordinator bond and the refund by up to `CHALLENGE_RESPONSE_WINDOW`, and an answer
      adds up to `POST_ANSWER_DISPUTE_WINDOW` more (48 h worst case). Any joined worker or the
      poster can challenge every slot (`2^payoutDepth`, at most 1024) and every joined worker, so
      the coordinator may have to answer that many times to keep its bond. That cost is the price
      of making every leaf provable; a coordinator that publishes the full tree to its workers
      leaves them nothing to challenge. Each challenge carries a bond (point 5d), so spam the
      coordinator answers costs the challenger.

## GEN-PARAMS (constructor parameters for the ceremony genesis spec)

No addresses are fixed here. The genesis spec fills them from the ceremony's canonical book
(CV-12). All three are plain contracts (no proxy), deployed by CREATE2 with a fixed salt each, so
their addresses are known before the ceremony.

| Contract | Parameter | Value class | Notes |
|---|---|---|---|
| FLRoundVerifier | `frl_` | the genesis FederatedRoundLedger (CREATE2, already in the r1006 set) | immutable |
| TaskVerifier | `reviewWindow_` | **72 h** (owner 2026-11-09, Q7); the contract bounds it to 1 h–30 d | immutable |
| WorkMarket | `governance_` | the governance timelock | two-step transfer; may not be the CREATE2 factory (Governable) |
| WorkMarket | `guardian_` | the guardian council 2-of-3 | not zero and not the CREATE2 factory (`InitialAdmin.check`); governance may rotate or clear it later |
| WorkMarket | `slashSink_` | the governance treasury: the governance timelock (#451 review 3) | immutable; not zero and not the CREATE2 factory (`InitialAdmin.check`); receives slashes the poster must not take back and withdraws them like any pull balance. The governance timelock is used, not a burn, so slashed SALT stays under governance instead of being lost |
| WorkMarket | `defaultCoordinatorBond_` | SALT wei, above zero (Q1), at least `minCoordinatorBond_` | immutable; the amount is a genesis-spec value tied to the tokenomics decision |
| WorkMarket | `minCoordinatorBond_` | SALT wei, above zero (#451 review 3) | immutable; the least bond an offer may set, so a dust bond cannot neuter the slash or the challenge bond (10 % of it) |
| WorkMarket | `initialVerifiers_` | `[FLRoundVerifier, TaskVerifier]` | the CREATE2-predicted addresses above; deploy order: FRL, the two verifiers, then WorkMarket |

Fixed in code (not parameters): `MIN_DISPUTE_WINDOW` = 24 h, `MAX_WORKERS_CAP` = 1024,
`SLASH_DISPUTER_BPS` = 5000 (Q4), `MAX_RECEIPTS_PER_DISPUTE` = 256,
`CHALLENGE_RESPONSE_WINDOW` = 24 h, `POST_ANSWER_DISPUTE_WINDOW` = 24 h, `RESERVE_CLAIM_PERIOD` = 180 days,
`DISPUTE_REVEAL_DELAY` = 60 s, `CHALLENGE_BOND_BPS` = 1000 (10 % of the coordinator bond).
The payout tree depth is per payout, bounded by `maxWorkers` (at most 10 for 1024 workers). Native SALT only; the market
refuses plain transfers (no `receive`).

The genesis-spec test (GEN-PARAMS red test) is still to write: the block-0 code hash of each
contract must equal the freeze-tag build.
