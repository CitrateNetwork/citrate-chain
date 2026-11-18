---
created: 2026-11-17T23:30:00Z
branch: fix/ancestor-sync-reconverge
author: Larry Klosowski
status: proposed
---

# ADR-2026-11-17: Header-first ancestor sync, and what counts as height evidence

## Status

Proposed on `fix/ancestor-sync-reconverge` (citrate-chain). Owner merge only.
Incident record: `citrate-labs/handoffs/FLEET_SPLIT_2026-11-17.md`. Code:
`node/src/ancestor_sync.rs` (driver), `node/src/block_serve.rs::serve_ancestor`
(server), `core/network/src/protocol.rs` (messages, version 1.3),
`node/src/sync_peer.rs::DeferredHeights` (evidence rule).

## Context

On r1007 (chain 40204) the fleet split into six partitions on 2026-11-15 between
00:28:24Z and 00:29:26Z, right after checkpoint 105,000 finalized. All branches
share ancestry up to height 105,012. Missing-parent fetches failed
(`SYNCRECOVERY ... InFlightCap / Unanswered`), producers sealed only on their own
tips, and nothing ever re-converged. Three mechanisms kept it that way:

1. A node on a lighter branch anchored every `GetBlocks` at its own applied
   tip. `serve_blocks` needs the anchor to be held by the server, and above the
   fork point the other branch does not hold it. The blocks it did receive
   (`Validated and imported 32/32 (height 224101-224132)`) were the heavier
   branch's tip blocks, which all deferred on a missing parent.
2. The missing-parent walk is bounded (about 512 heights down, then the step
   budgets) and gives up on `InFlightCap`. The `GetBlocks` bisection probe in
   `sync_rejoin` costs one full blocks round trip per step and is steered by
   advertised heads.
3. Advertised heads and the sync target were raised by evidence nothing
   verified. `PeerInfo::observe_gossiped_head` ran on the raw `NewBlock` before
   any validation, and a deferred block's height went straight into
   `max_seen_height` (the sync target, `eth_syncing.highestBlock`, the "behind"
   verdict) after only gossip validation, which proves a self-signed header and
   nothing more.

By 2026-11-17 the fork is about 121,000 heights deep. The undo window
(`MAX_REORG_DEPTH` = `REORG_UNDO_DEPTH` = 10,000) and the DAG retain window
(`CITRATE_DAG_PRUNE_RETAIN` = 10,000 on the fleet) are both far shallower.

Chain #482 (`hardening/pipeline-far-behind-v2`, commits 508407f1 / 18483dc5)
fixes a different wedge: the #477 pipeline staying "active" when no peer may be
asked, which suppressed the tick's own request. It does not touch how a node on
a side branch finds or fetches the other branch.

## Decisions

### D1. A locator exchange finds the common ancestor in one round trip

New messages, appended after `CheckpointCertificate` so every existing variant
keeps its bincode tag (tags 44 and 45):

```text
GetAncestor { locator: Vec<Hash> }                  // <= MAX_LOCATOR_HASHES (64)
Ancestor    { common: Option<(Hash, u64)>,          // highest locator entry on the
                                                    //   server's executed chain
              tip: (Hash, u64), tip_blue_work: u128, // server's applied tip (claim)
              headers: Vec<BlockHeader> }           // <= MAX_ANCESTOR_HEADERS (128),
                                                    //   executed chain above `common`
```

The locator (`ancestor_sync::build_locator`) is the applied tip, the 15 heights
below it, then heights 2, 4, 8, ... further below, then the finalized checkpoint
and genesis. 34 hashes reach 120,000 heights. The server
(`block_serve::serve_ancestor`) reads at most 64 entries, takes the highest one
that sits on its executed chain at its height (the canonical index, never a
stored side block), and returns up to 128 executed-chain headers above it,
stopping at its applied tip, at a gap, and under the 60 KiB single-message
budget. It is stateless: the next window is asked with a locator that starts at
the last header received, so an episode resumes across windows and a server
that reorged in between answers from a lower entry (the driver then ends with
`PeerMoved`). `GetAncestor` is a serve request (routed to the serving plane,
ADR CV-6, under its per-peer and global budgets); `Ancestor` may use the
reserved inbound lane like `Blocks` and `Headers`.

### D2. Headers and work are checked before any body is fetched

The driver (`ancestor_sync::AncestorSync`) runs one episode at a time with one
request in flight:

1. **Locate** when there is evidence of a branch this node lacks (a block that
   deferred on a missing parent in the last 30 s, or a sync target above the
   applied tip), against a 1.3 peer with a per-peer cooldown (30 s, doubling
   per failure to 30 min). Peers that DELIVERED a deferred block are asked
   first, most recent first; then peers whose advertised head is not fully
   admitted here, highest first. An advertised head alone is weak evidence:
   relayed gossip raises the relaying peer's head whether or not it holds the
   block's branch (in the review's scenario every heavy peer's head was the
   light node's own tip). "Held" always means fully admitted (chain store and
   DAG): a block that deferred is stored but not admitted.
2. **Headers.** Each reply must name a common block that was in the locator
   sent. Each header must link to the one before it by selected parent, be one
   height higher, have a strictly higher blue score, carry
   `blue_work == blue_work_for_score(blue_score)` (CV-3), and not be more than
   15 s in the future. The first header continues from the common block, whose
   header this node holds. The true fork point is the last header that is on
   this node's EXECUTED chain (the canonical index at its height): a side
   block it merely stores never makes a fork look shallower.
3. **Work gate.** Bodies are fetched only once a verified header claims more
   blue work than this node's applied tip. If the peer's reported tip work, or
   every header up to its tip, claims no more, the episode ends
   (`NotHeavier`) with no body fetched. A heavy node therefore never downloads
   a lighter partition's deep branch.
4. **Bodies.** `GetBlocks` anchored at the highest header-chain block held
   (the peer holds it: it is on the peer's executed chain), 32 heights at a
   time, through `SyncManager::request_blocks`. Every block goes through
   `handle_blocks` and `BlockAdmission::admit` as before: hash recomputed,
   signature, VRF and stake eligibility, and GHOSTDAG blue score and work
   recomputed (G7 rejects a header that lied about its work). An answer that
   stores no new header-chain block is a stall; four end the episode.

Only while a body request of the episode is in flight, and an earlier body
answer of the same episode already had a block admitted, do the tick's own
applied-tip request and the #477 pipeline stand aside (review round 3: per-peer
cooldowns do not bound a node-wide stand-aside, so 32 peers taking turns, each
asked for one body it never delivered, held it for 88% of the time). They would only re-ask the anchor the peer
does not hold. Locating and header paging never stand
anything aside, however much work the headers claim: headers carry no
signature, so a claimed work is only refuted once a body is admitted (review
round 2: a peer dripping fabricated high-work headers on top of a side block
we already held kept an episode in its "body phase" for 99% of the time
without ever being asked for a body). Each round's next request goes out as soon
as its answer is in (`AncestorSync::next`), not on the next 2 s tick.

Every episode is bounded whatever its peer does (review of #483, P1-1): 120 s
and 512 requests (a request the sync manager refused counts; four refused in a
row end the episode), and a header phase whose verified headers span the
whole reorg window above the fork without beating our work ends `NotHeavier`.
An episode that runs out of budget ends `Budget { fetched }`: resumable (what
was fetched stays stored). `fetched` counts only heights the cursor moved on
this episode's own body answers, never blocks held before it. A budget ending
with nothing fetched is a fault (doubling cooldown); one with bodies fetched
restarts at once, except that two in a row with one peer that left the applied
tip where it was get the doubling cooldown too.

Claimed heights, claimed work and the peer's reported tip only decide what to
fetch. Fork choice stays with GHOSTDAG over admitted blocks, and whether the
applied tip moves stays with the applicator's strictly-heavier and finality
rules.

### D3. Bounds and DoS caps

| What | Cap |
|---|---|
| Locator read by a server | 64 hashes |
| Headers per reply | 128, and 60 KiB (one Noise message) |
| Headers verified per episode | 2 x `MAX_REORG_DEPTH` (20,000) |
| Header hashes held per episode | the same 20,000 (40 bytes each, under 1 MB) |
| Episodes / requests in flight | 1 / 1 |
| Episode duration / requests | 120 s / 512 (refused ones count; 4 in a row end it) |
| Body window | 32 heights (`SyncConfig` batch) |
| Request timeout | 15 s |
| Stalled body answers | 4 |
| Cooldown table | 256 peers |

A peer cannot make this node fetch unbounded junk. Forged headers (headers carry
no signature) can at most pass the work gate; the bodies they name then cannot
be served, admission rejects anything else, the episode stalls after four
answers and the peer's cooldown doubles. A peer that under-reports its work only
keeps its own branch from being fetched.

### D4. Reorg-depth policy

An episode never fetches a branch whose fork point is below the **reorg floor**:

```text
reorg_floor = max(finalized checkpoint height,
                  applied height - MAX_REORG_DEPTH)      // 10,000, the undo window
```

The finalized checkpoint is always in the locator. A peer whose executed chain
does not hold it forks below finality, and its reply's common block is then
below the checkpoint: the episode ends `TooDeep` with no body fetched (I4: never
revert past finality). The applicator enforces the same floor again on the
reorg itself (`canonical_apply`, I4, CHAIN-B-A002), so this is a second guard,
not the only one.

A fork deeper than the undo window cannot be switched in place: the undo records
end there, and on a pruned DAG store (`MIN_RETAIN_BLOCKS >= MAX_REORG_DEPTH`)
the GHOSTDAG records below the floor are gone and a rebuild from genesis is
refused. Fetching such a branch is unbounded work for nothing, so the episode
ends `TooDeep` and logs a warning that names the fork height and depth. The
recovery for such a node is an operator re-seed of its data dir from a node on
the canonical branch. Every r1007 branch is in this state today (fork about
121,000 deep).

### D5. Height evidence must be verified or corroborated

* `max_seen_height` from a deferred block: `sync_peer::DeferredHeights` keeps
  each delivering peer's highest deferred claim (256 peers at most, oldest
  dropped first; 120 s TTL). Only peers in the sync tick's current connected
  set count, and a peer's claims are dropped when it disconnects, so a peer
  that reconnects under a fresh key is still one peer. A height counts once
  two connected peers' live claims reach it (the second-highest claim), then
  goes through the existing clamp (`record_unverified_height`). A node with a
  single connected peer counts that peer's claim. A "known proposers only"
  filter was rejected: the known set is filled only from admitted blocks
  (`AttestedNetworkHead::observe`), so a cold node would never count the
  network head.
* A peer's advertised head (`PeerInfo::head_height`) rises from gossip only
  after validation and admission: a block this node admitted or already holds;
  a deferred block up to the corroborated height; or a deferred block no more
  than the undo window (10,000) above the higher of that peer's head and this
  node's applied tip (`sync_peer::gossip_raises_head`). So a lone peer's
  far-ahead claim never moves its head or the node-wide evidence, while one
  relaying peer among several still keeps its own head fresh for a cold node.
  A peer's head is advertised and unverified by design; the selector's timeout
  penalty box handles a peer that is not where it says.
* The serving plane does not build an `Ancestor` reply for a peer below 1.3,
  and a `GetAncestor` does not refresh the requester's self-reported head.

### D5b. A scenario the 1.2 recovery heals only slowly

`split_heal_tests::a_heavier_branch_below_our_height_is_rejoined` and
`without_ancestor_sync_a_heavier_branch_below_our_height_heals_far_slower`: the
heavier branch is BELOW the light nodes' height (four producers every other
slot, four blue blocks per height, against one producer every slot), 4,000
slots apart: light 4,000 above the fork and 2,000 above the heavy tip, heavy
2,000 deep. No peer is ahead, no heavy peer is inside the split-pull band, and
the missing-parent walk's node-wide budget cannot descend 2,000 heights in the
40 slots allowed. With every node on 1.2 the light followers have not rejoined
by slot 40 (3 of 3 runs); with 1.3 they rejoin by slot 2 (3 of 3). The 1.2
recovery does get there: with a 400-slot window the reviewer saw the fleet
converge at slot 110 (p0 at 79). So the driver cuts this heal from about 110
slots to 2; it is not the only way back. The test is named for that
(`..._heals_far_slower`).

For r1007 itself the serving-side fix (D6) may well be the decisive one: the
split began with missing-parent fetches failing on `InFlightCap` and
`Unanswered`, and every `GetBlocks` answer then cost a scan of every stored
header (about a million), so serving lanes fell behind exactly when recovery
needed answers. Ancestor sync shortens the heal; cheap serving lets every
recovery path get its answers at all.

### D6. Serving a block window costs the window, not the store

Every `GetBlocks` answer (the tick's, the walk's, the pipeline's and an
episode's body windows) reads one bounded height range through
`BlockStore::hashes_in_height_range`, which scanned every header in
`CF_HEADERS`. On r1007 that is about a million headers per node per answer,
which matches the serving plane falling behind (`serve lane over budget
GetBlocks=5717`) and recovery requests going `Unanswered` / `InFlightCap` at
the split. A range of at most 4,096 heights now reads the S3-7 sibling height
index (`hsib:` ‖ height ‖ hash, written and removed in the same batch as the
block) one height at a time; wider or open-ended ranges (start-up purge,
rollback planner) and stores without the index keep the full scan. Measured on
cnv-build-2 (debug, 18,000 blocks): 200 32-height ranges took 72.7 s before
(one full scan 318 ms each), now well under one full scan.

## P2P compatibility during a rolling upgrade

* `ProtocolVersion::CURRENT` is 1.3 (`ANCESTOR_SYNC`). A minor bump:
  `is_compatible` checks the major only, so 1.0 to 1.2 nodes still accept a 1.3
  handshake and a 1.3 node accepts theirs.
* `Peer::send` withholds `GetAncestor` and `Ancestor` from a peer that did not
  advertise 1.3 (or advertised nothing). An older node would fail to decode the
  unknown variant and drop the connection; with the gate it never sees one.
  The driver also only picks peers that advertised 1.3.
* Every other message is unchanged on the wire (tags pinned by
  `core/network/tests/ancestor_sync_wire.rs`). The evidence rules (D5) are local
  and change nothing on the wire.
* Toward 1.2 peers a 1.3 node keeps the existing recovery paths (the
  `GetBlocks` fork-point search in `sync_rejoin`, the split pull, the
  missing-parent walk), and it still serves 1.2 peers exactly as before.
* So a mixed fleet keeps every connection. Ancestor sync works between any two
  upgraded nodes; a 1.2 node heals only as well as it did before.

## Consequences

* A node that falls onto a lighter branch rejoins the heavier one by itself,
  for any fork depth inside the undo window, in a handful of round trips to
  find the fork and one body window per 32 heights.
* A node forked below its reorg floor says so in its log instead of fetching
  forever, and needs an operator re-seed.
* Heavy nodes spend at most one small locate exchange per light peer per
  cooldown.
* Mixed fleets stay connected; the benefit needs both ends on 1.3.

## Alternatives considered

* **Keep the `GetBlocks` bisection only.** It works against old peers and stays
  as the fallback, but each step moves up to a full blocks reply, it has no
  work check before bodies, and it was steered by inflated heads.
* **A server-side "find common ancestor by height" request.** Rejected: heights
  are branch-relative (the same transaction sat about 360 heights apart on two
  r1007 branches); hashes on the requester's own chain are the only common
  vocabulary.
* **Deep reorgs beyond the undo window by rebuilding from genesis.** Rejected
  for pruned nodes (the GHOSTDAG records are gone), and the applicator already
  refuses it there. Re-seed is the recovery.
