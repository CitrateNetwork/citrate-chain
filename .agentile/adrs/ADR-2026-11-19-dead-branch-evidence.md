---
created: 2026-11-19T18:00:00Z
branch: fix/toodeep-wedge-autoresync
author: Larry Klosowski
status: proposed
---

# ADR-2026-11-19: When a node may declare its own branch dead

## Status

Proposed on `fix/toodeep-wedge-autoresync` (citrate-chain). Owner merge only.
Builds on ADR-2026-11-17 (ancestor sync, #483) and ADR-2026-11-03 CV-7b/CV-7c
(dead-branch marker, guarded cold resync). Code: `node/src/dead_branch.rs`
(rule), `node/src/ancestor_sync.rs` (fork search), `node/src/finality_sync.rs::judge_foreign_certificate`,
`core/consensus/src/checkpoint_gadget.rs::committee_beyond_held_epochs`,
`node/src/canonical_apply.rs::record_dead_branch_on_evidence`.
Sprint: `.agentile/sprints/active/CHAIN-DEAD-BRANCH-AUTORESYNC-2026-11-19.md`.

## Context

The r1007 fleet was recovered onto HEAVY on 2026-11-19, and HEAVY finalized
checkpoint 283,600 (5 of 7 voters). Member and owner Core nodes (bundled node
f4a0e600) stayed on LIGHT at applied height 274,810. LIGHT forked from HEAVY at
105,024 (HEAVY 105,025 = `0xf69095de…`, LIGHT 105,025 = `0x3ab270f2…`), and no
producer is left on LIGHT. Those nodes report `catching_up`, not `wedged`:
the applicator only records the dead-branch marker when it refuses a switch
(`RefusePruned`), and it never sees HEAVY's ancestry. So the guarded cold
resync never fires. The owner decided (2026-11-19) that Core 0.5.6 must recover
such nodes automatically.

A cold resync moves the chain database aside and syncs from genesis. That is
the risk: if a peer could make an honest node resync by claiming a deep heavier
fork, that peer would have a remote "wipe and resync" button.

### Finding: the merged ancestor sync does not reach TooDeep on these nodes

r1007 runs checkpoint finality in Observed mode (voting on, enforcement off),
so the applicator's reorg floor is never raised and the sync view's finalized
height is 0 on every r1007 node. The locator then runs down to genesis, and a
HEAVY peer answers with the highest locator entry on its chain, about 12,650.
The episode pages 128 headers at a time toward a fork at 105,024 (about 92,000
headers away). It runs into the 20,000-header episode cap and ends
`Budget { fetched: 0 }`, which is a failure with a doubling cooldown, on every
episode. A member never learns its fork is too deep. This is reproduced red on
5fbcbd37 by `ancestor_sync::tests::a_fork_far_below_the_floor_is_located_exactly_without_a_finalized_height`.

## Decisions

### D1. Locate the fork exactly, with a narrowing locator

After an `Ancestor` reply, every locator entry we sent above the reply's common
block is off the peer's executed chain, because the server answers with the
highest one on it. So the fork lies between the highest header-chain block we
hold (`lo`) and the lowest such entry (`upper`). If all of that range is below
the reorg floor, the episode does not page. Instead it sends a narrowing
locator (`refine_locator`): our executed chain's blocks at up to 63 evenly
spaced heights strictly between `lo` and `upper`, plus `lo`. Each answer cuts
the gap by about 63 times, so a 131,000-height gap closes in three rounds. Then
the reply's headers above the common block show the first block of the peer's
branch, and the existing check ends the episode
`TooDeep { fork, fork_hash, diverged: Some(first block of their branch) }`.

The headers between our fork block and `diverged` pass `verify_headers`:
selected-parent link, height + 1, strictly higher blue score,
`blue_work == blue_work_for_score` (CV-3), and not in the future. No body is
fetched. There is no wire change: `serve_ancestor` already takes the highest
entry of any locator. It works against today's 1.3 fleet, and refinement
rounds count against the episode's existing round, time and header budgets. A
common block that is not in the locator we sent still ends the episode
`Faulty`. Below the floor nothing changes: the fork-below-finality case (I4)
still ends at once, with `diverged: None`.

### D2. The evidence rule: all of E1 to E6

A node records the dead-branch marker by itself only when every one of these
holds (`dead_branch::DeadBranch::verdict`):

| | Condition | Why |
|---|---|---|
| E1 | A header-verified TooDeep: `diverged` is set (D1), the fork is below the reorg floor, and the peer claimed more work than our tip. | Only a located fork names a specific other branch whose first headers verified as children of our block. A TooDeep from I4 (the peer lacks our finalized checkpoint) is never evidence: there we are the side finality protects. |
| E2 | At least 2 distinct peers that are connected now gave such a TooDeep within the last hour, agreeing on the fork block and on the first block of the other branch. A later conclusive episode with a peer (Extends, NotHeavier, Fetched, Faulty) withdraws its TooDeep and any certificate it served. | One lying or buggy peer is never enough. A peer that disconnects stops counting. Agreement on `(fork, diverged)` means both describe the same branch. Peer ids are Noise keys, so this is not Sybil-proof by itself. E3 is what costs an attacker something real. |
| E3 | One of the agreeing peers serves a finalized checkpoint certificate that verifies against the committee this node derives itself, for a block not on our executed chain (above our applied tip, or at or below it with another block there) and above the fork. It is fetched with the existing `GetCheckpoint { above: our finalized, at_or_below: u64::MAX }`, so the server returns its latest. It is judged by `judge_foreign_certificate`: size bounds, boundary height, committee >= 4, distinct members holding more than 2/3 of the committee stake, the binding's epoch equal to the committee's, and every ed25519 signature valid over the v2 vote message for this chain and genesis. It is never installed and never raises a floor. | This is the part that cannot be forged. It needs the signing keys of validators this node materialized from its own chain's ValidatorRegistry, holding more than 2/3 of the committee's stake. That is the finality assumption itself. It also answers "is the heavier claim real?": the committee finalized past the height we are stuck at. |
| E4 | The fork is at or above this node's latest finalized checkpoint (any certificate it holds, Observed or Enforced). | A branch that leaves out a block this node holds a finalized certificate for is conflicting finality, a safety alarm, never a resync target. |
| E5 | The newest block of our applied selected chain that this node did not seal is more than 30 minutes old by its own header timestamp (`stall_age_secs`, walking at most 4,096 headers). Own blocks are found by the coinbase the v2 header commits to. | Our branch has stopped, or only this node extends it. It is read from the chain store, so Core's restarts (its stall watchdog restarts a frozen node up to three times) do not reset it. A live branch keeps fresh timestamps from other producers. |
| E6 | `[recovery] cold_resync` is on. When it is off, nothing is recorded and the verdict is logged at WARN. | The existing off switch covers this path too. |

Then the existing guarded path runs unchanged: the monitor waits
`[recovery] cold_resync_after_secs` (default 900 s) from the marker, applies
the minimum interval (6 h), carries the signed-vote record of a voting
validator, requests, and exits non-zero. The supervisor restarts the node, and
`apply_pending` moves the database into `chain-aside/` while keeping
`noise.key`, `proposer.key` and `peer.id`. The marker is written under the
advance lock, only if the applied tip is still the one the verdict was judged
against and the fork block is still canonical. Its reason starts with
`dead-branch evidence:`. If the applied tip moves before the resync fires,
the branch was not dead, and that marker (never an applicator-recorded one)
is cleared.

### D3. The committee for an epoch this node has not reached

The member holds validator snapshots up to S = 274,800. Checkpoint 283,600 is
governed by S = 282,800. `committee_for` returns `None` there (the existing
"no validator snapshot governing the height is held"), so the existing
certificate sync can never judge it. `committee_beyond_held_epochs` draws the
committee exactly as `committee_for` does, with epoch 282,800 and its seed,
from the newest validator set this node holds, on the assumption that the set
did not change in between. If the set did change, the real voters are not all
members or do not reach the quorum, and verification fails closed. It stands
nothing in for a governing snapshot at or below the newest held one that has
been pruned. The certificate must bind the governing epoch.

### D4. Why the certificate is not proven to sit on the TooDeep branch

Headers carry no state roots, so a header chain cannot be hash-verified
(`compute_hash` covers `state_root`, `tx_root`, ...). Serving is forward-only.
Proving that the certified block descends from `diverged` would take a walk of
full blocks back from it (8,790 sequential requests for the member today,
growing about 47,000 a day). That is not done. The tie between the certificate
and the branch is the serving peers' claim, backed by E2 and E5.

Residual risk: an eclipsed node whose branch has stopped, and which sits behind
a genuine certificate on the honest chain, can be made to resync needlessly by
two colluding peers. The damage is liveness only. The database is moved aside,
not deleted, at most once per 6 h, and the node resyncs toward the chain the
committee finalized. An eclipsed node is already at its peers' mercy for
liveness. A former validator set holding more than 2/3 of a stale snapshot
(the long-range case) has the same bound.

## Tests (mutations included)

- Red on 5fbcbd37, green here:
  `ancestor_sync::tests::a_fork_far_below_the_floor_is_located_exactly_without_a_finalized_height`.
- Rule (`dead_branch::tests`):
  - an honest deep split is a verdict;
  - one lying peer (even repeated) is never enough;
  - peers that disagree on the branch do not corroborate;
  - an I4 TooDeep never counts;
  - fabricated headers without a certificate never count, nor does a refused one or one for our own block;
  - a certificate from a peer without a TooDeep is not kept;
  - a certified block on our chain or below the fork is not evidence;
  - a live branch is never marked;
  - a fork below our finalized checkpoint is never resynced to;
  - a fork inside the window or off our chain is not deep;
  - disconnected, stale or withdrawn evidence lapses;
  - certificate requests go one at a time to TooDeep peers;
  - the peer table is bounded;
  - the stall clock is computed as described.
- Certificate (`finality_sync::tests`):
  - a foreign certificate is judged and never installed (above the tip, conflict, our own block);
  - a forged one is refused: foreign keys, too few members, a non-member voter, another block, another binding, another epoch, off-boundary, a voter twice, oversize;
  - beyond our held epochs, it verifies against our newest set, and only with the governing epoch.
- Consensus: `a_node_behind_the_epoch_stands_in_its_newest_set_with_that_epochs_seed`.
- End to end (`split_heal_tests::a_node_stranded_on_a_dead_branch_resyncs_onto_the_finalized_branch`):
  - a light node forked more than twice the reorg floor below its tip, and a heavy pair that finalized above it;
  - it is not marked without the certificate, with one heavy peer connected, or with the off switch;
  - it is then marked;
  - the cold resync's own decision, request and start-up move run, with its identity kept;
  - a fresh start on the same data dir syncs from genesis onto HEAVY.

## Alternatives considered

- **Corroboration by peers alone.** Rejected: peer ids cost nothing.
- **Bodies of the heavier branch as work evidence.** Admission needs the
  parents in the DAG. Near the fork they are pruned, and at the tip they are
  unknown. A body only proves that someone signed a block.
- **A compiled canonical checkpoint (`hardening::CANONICAL_CHECKPOINTS`) for
  r1007 105,025 = HEAVY.** Release-signed and unforgeable, the same tool the
  2026-10-15 rollback used. It would make every LIGHT node conflict
  deterministically and guarantee a resync lands on HEAVY. It is an owner
  consensus decision about this incident, not a general rule, so it is not in
  this change. It can be added alongside.
- **A new message to walk certified ancestry backwards.** It would need the
  fleet upgraded first, so members could not recover against today's servers.
