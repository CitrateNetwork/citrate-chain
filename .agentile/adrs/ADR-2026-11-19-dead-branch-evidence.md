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
| E5 | Our branch has stopped, by BOTH clocks: (i) the applied tip has not moved to a block another node sealed for 30 minutes of this node's own wall clock (`tip_unmoved_secs`; the tip and the time it was first seen are a synced record in `CF_METADATA`), and (ii) the newest block of our applied selected chain that this node did not seal is more than 30 minutes old by its header timestamp (`stall_age_secs`, walking at most 4,096 headers). Own blocks are found by the coinbase the v2 header commits to. | (i) is the rule that matters for a node that is catching up: replaying history, its blocks are always hours old by their timestamps, so (ii) alone held for every such node (review round 1). Its tip moves, so (i) does not. The record is durable, so Core's restarts (its stall watchdog restarts a frozen node up to three times) do not reset the clock; a database without it (a fresh install, or right after a cold resync) starts it, so such a node waits the full window. (ii) is kept as well: it is the stronger statement for the stranded case (no producer has extended the branch in 30 minutes), and it costs nothing. |
| E6 | `[recovery] cold_resync` is on. When it is off, nothing is recorded and the verdict is logged at WARN. | The existing off switch covers this path too. |
| E7 | The catch-up veto: no currently connected peer ended an ancestor episode with `Extends` in the last hour. `Extends` now means only that the peer's executed chain holds our applied tip AND goes above it; a peer level with us or behind us on our chain answers the new `Holds`. | The main defense (review round 1). A node that is catching up has an honest peer ahead of it on its own chain, which `Extends`; that peer is picked by the episode driver (its head is not held here) once the TooDeep peers are cooling (30 min). A stranded member has none: HEAVY peers answer TooDeep, and other stranded members are level with it (`Holds`). An attacker's `Extends` can only veto, never mark. With E7, marking a catching-up node needs a full eclipse of it. |
| E8 | Everyone answered: every currently connected 1.3 peer ended an ancestor episode conclusively (`Extends`, `Holds`, `NotHeavier`, `TooDeep` or `Fetched`) within the last hour. While any deep-fork evidence is fresh, the evidence path asks the driver to probe each unanswered peer itself (`AncestorSync::force_probe`): one waiting at a time, round robin over the connected 1.3 peers, each at most once a minute, taking the next free episode slot whatever the ranking, the evidence gate or the peer's cooldown say. A peer that never answers conclusively blocks the verdict. | Review round 2. E7 alone depended on the driver's ranked choice (deliverers first, then the highest UNVERIFIED advertised head). About five Sybils that advertise a huge head and answer each locate after 14 s with zero work (`NotHeavier`, a 30 s cooldown, never a failure) kept the one episode slot busy, so the honest peer ahead was never asked and E7 never fired. With E8 the honest peer is probed within one episode slot (at most 15 s) of the evidence appearing, and its `Extends` vetoes. Fail closed: an unanswered peer can only delay a mark. A stranded member's fleet peers each answer TooDeep, so they never block it. Peers below 1.3 cannot answer ancestor sync and take no part (stranded 0.5.5 members run 1.2). |

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
is cleared. `cold_resync::evaluate` re-checks it at decision time too: an
evidence marker whose dead tip is no longer the applied tip never resyncs
(and is cleared there), so a tip that moved between evidence ticks, or an
evidence tick that stopped running, cannot fire it.

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

Residual risk, as corrected by review round 1. Before E7 and the wall-clock
half of E5, the risk was much wider than "an eclipsed node": ANY node that is
catching up and whose tip stalls for 15 minutes qualified, cheaply. E1 and E2
cost two peer ids (Noise keys from one host) answering with one of our own
locator hashes and one fabricated header (`verify_headers` does not recompute
the block hash). E3 held with a genuine certificate relayed from any honest
node, because it is above the victim's tip. E4 held because a node that far
behind holds no recent certificate (servers keep 256 in memory, and r1007 has
no certificate between 105,000 and 283,600). E5 held because historical blocks
are old by timestamp. The first resync on a fresh install is not rate limited.

The defense, after review round 2, is E7 and E8 together with E5(i) and the
decision-time re-check. A node catching up has a moving tip, which vetoes on
its own. If its tip is frozen, it still has at least one connected honest
peer ahead of it on its chain. E8 probes that peer outside the ranking, so its
`Extends` vetoes no matter how many Sybils hold the ranked slot or what head
they advertise. Marking such a node therefore needs every one of its connected
1.3 peers to be the attacker's: a full eclipse of its ancestor-sync peers.
Against the stranded r1007 member that is the intended outcome: all of its
peers are fleet nodes on HEAVY.

What is left:
- A node that is fully eclipsed AND whose tip is frozen for 30 minutes while it
  is behind a genuine certificate can be made to resync needlessly. That is
  liveness only. The database is moved aside, not deleted, at most once per
  6 h after the first, and the node resyncs toward the chain the committee
  finalized. An eclipsed node is already at its peers' mercy for liveness.
- A peer that never answers conclusively delays a genuine recovery while it
  stays connected (E8 fails closed). The operator re-seed remains available.
- A former validator set holding more than 2/3 of a stale snapshot (the
  long-range case) has the same bound.
- `chain-aside/` accumulation, which this path makes reachable from peers, is
  #485 (acceptance: a free-disk check and a cap of 2 asides).
- Follow-ups, not fixed here:
  - A forward jump of the local clock by 30 minutes or more satisfies E5(i).
    It needs control of the clock.
  - A stranded node that seals its own blocks never recovers: the marker is
    cleared on any tip move. This does not affect r1007 members, which do not
    seal on LIGHT.
  - A node catching up makes one synced metadata write per tip move.
- A recorded tip time in the future (the clock was set back) restarts the
  clock at once (`tip_unmoved_secs`).

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
  - the stall clock is computed as described;
  - review round 1: an honest peer ahead on our chain vetoes a Sybil verdict
    (red on 7b5d58a7); a catching-up node whose tip moves is never marked;
    only `Extends`, not `Holds`, vetoes; the wall clock is durable across a
    restart and restarts only on another node's block; a certificate our
    chain has since applied is no evidence.
- Review round 2:
  - `hog_sybils_cannot_starve_the_catch_up_veto` (red on c301fe0a);
  - `an_unanswered_peer_blocks_the_verdict_and_hogs_do_not`;
  - `a_stranded_member_with_only_fleet_peers_still_marks`;
  - `episode_probes_are_round_robin_and_bounded`;
  - `a_forced_probe_takes_the_next_slot_outside_the_ranking`;
  - `the_local_view_carries_the_tip_clock_into_the_verdict` (the E5(i) wiring);
  - `a_tip_clock_from_the_future_restarts_now`.
- Applicator guards and the decision-time re-check
  (`an_evidence_marker_is_withdrawn_when_the_tip_moves_and_never_resyncs`,
  red on 7b5d58a7; `only_an_evidence_marker_whose_tip_moved_is_cleared`).
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
