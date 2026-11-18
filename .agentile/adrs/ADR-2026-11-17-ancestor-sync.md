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
   applied tip), against a 1.3 peer whose advertised head this node does not
   store, highest head first, with a per-peer cooldown (30 s, doubling per
   failure to 30 min).
2. **Headers.** Each reply must name a common block that was in the locator
   sent. Each header must link to the one before it by selected parent, be one
   height higher, have a strictly higher blue score, carry
   `blue_work == blue_work_for_score(blue_score)` (CV-3), and not be more than
   15 s in the future. The first header continues from the common block, whose
   header this node holds. The true fork point is the last header whose block
   this node already holds.
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

While an episode is fetching a branch below the applied tip, the tick's own
applied-tip request and the #477 pipeline stand aside (they would only re-ask
the anchor the peer does not hold).

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
  each delivering peer's highest deferred claim (256 peers at most). A height
  counts once two distinct peers' claims reach it (the second-highest claim),
  then goes through the existing clamp (`record_unverified_height`). A node with
  a single connected peer counts that peer's claim (it has nothing to
  corroborate with). A "known proposers only" filter was rejected: the known set
  is filled only from admitted blocks (`AttestedNetworkHead::observe`), so a
  cold node would never count the network head.
* A peer's advertised head (`PeerInfo::head_height`) rises from gossip only
  after validation and admission: a block this node admitted or already holds,
  or a deferred block up to the corroborated height
  (`sync_peer::gossip_raises_head`). A relayed tip block from several peers still
  keeps honest heads fresh during a cold sync; a lone peer's claim no longer
  moves its own head, the sync target or peer selection.

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
