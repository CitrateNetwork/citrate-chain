---
created: 2026-08-28
branch: main
author: saul (Larry Klosowski)
status: proposed
---

# ADR-2026-08-28 — Distinct-genesis reroll isolation

## Status
Proposed (owner-approved direction, 2026-08-28). Design only — no fleet action in this ADR.

## Context

Every reroll of chain 40204 reproduces the **same genesis hash `0xd1a1941e…`**. That is by
construction: `node/src/genesis.rs::create_genesis_block` calls
`shared_genesis::create_canonical_genesis_block(CANONICAL_GENESIS_TIMESTAMP)`, and
`CANONICAL_GENESIS_TIMESTAMP` (`core/economics/src/genesis.rs`) is a **fixed constant**
(`1_767_225_600`). Same timestamp + same canonical accounts/params ⇒ byte-identical genesis
every time. This has been treated as a feature — the "address-neutral reroll": a reroll resets
STATE without reshuffling any contract address, because CREATE2-via-Arachnid addresses do not
depend on the genesis hash.

That determinism is also a **liability for reroll isolation**, and it caused a live incident.

### The incident (2026-08-28, found by the G4 live cold-sync)

After the commd-170 reroll (canonical chain: rpc-1 miner + boot1 + boot3, genesis dated 01:44),
an **abandoned older chain** (reroll-0825, height 38,389, static) was still being served by:
- **boot2** — its commd-170 wipe archived the old data but did not clear the live `.citrate`, so
  it rebooted onto the old chain; and
- **`an external node (IP redacted)`** — an EXTERNAL NAT'd node (not one of the 4 DO droplets) stuck on the old
  chain, dialing out to the fleet.

Because both chains share genesis `d1a1941e` and chain-id 40204, the network handshake
(`core/network/src/transport.rs:269`:
`if network_id != params.network_id || genesis_hash != params.genesis_hash { reject }`)
**accepts old-chain nodes as valid peers**. The old fork (38,389) is *heavier* than canonical
(~27,160), so GhostDAG fork-choice on any node WITHOUT a reorg-window lock — i.e. every fresh or
freshly-wiped node — selects the old fork. Result: **onboarding hijack.** A brand-new node syncs
the dead chain; a surgical re-wipe of boot2 re-synced the dead chain a second time (clean:
crossed activation-2000 with 0 state-root mismatches — the sync machinery is correct; it simply
followed the heavier chain it was offered). The 3 established nodes stay canonical only because
their reorg window locks them.

The genesis-mismatch reject at `transport.rs:269` is exactly the isolation seam we want — it just
never fires between two rerolls, because the genesis hash never changes.

## Decision

**A reroll MUST mint a genesis hash distinct from every prior reroll**, so old-chain nodes are
cryptographically severed at the P2P handshake (wrong `genesis_hash` ⇒ "network mismatch" ⇒
connection refused) and can no longer feed a heavier abandoned fork into onboarding.

Introduce a per-reroll **reroll epoch** nonce that feeds the genesis header:

- Add a `reroll_epoch: u64` (default 0) to the canonical genesis inputs, sourced from a pinned
  constant bumped each reroll (and/or `CITRATE_REROLL_EPOCH`, asserted against the pinned constant
  at boot so a misconfigured node fails fast rather than silently forking). Mix it into the genesis
  header via the block `extra_data` (preferred — leaves `timestamp` semantically a timestamp) OR by
  deriving `timestamp = CANONICAL_GENESIS_TIMESTAMP + reroll_epoch`. Either changes the genesis hash
  deterministically while keeping it reproducible for the current reroll.
- Every node in a given reroll uses the SAME `reroll_epoch` (part of the pinned determinism set,
  alongside DEPLOYER/SALT pins in the reroll runbook), so all 4 nodes compute the identical new
  genesis and the intra-fleet handshake still passes.

### What this deliberately preserves
- **Address-neutrality is UNCHANGED.** Contract addresses are CREATE2 outputs of the Arachnid
  factory `0x4e59…`, independent of the genesis header. Pre-funded account addresses are fixed
  keys. Bumping `reroll_epoch` changes only the genesis *header hash*, not any address. The reroll
  stays "additions/state-reset only" for the address book.

### What it costs
- The expected genesis hash is no longer a forever-constant. Anything that pins it must update per
  reroll: `packages/chain-config` (frontends), `node/src/config.rs` optional `genesis_hash`, the
  reroll runbook's G1 assertion (`GENESIS_HASH_PREFIX` in `scripts/ops/fleet-surgical-wipe.sh`), and
  any `genesis_hash`-pinned test fixtures. This is a small, mechanical, one-place-per-consumer bump —
  and it is the POINT (a new genesis is a new network).

## Companion change (verification gate)

Add a **per-node chain-agreement assert** to `scripts/ops/reroll-orchestrate.sh` (P8 / post-join):
for every node, `eth_getBlockByNumber(checkpoint).hash == miner's` (e.g. block 5000, or any height
> the reorg window). The commd-170 reroll verified only rpc-1's head + the four binaries' md5, so
boot2 sitting on a different chain slipped through. This gate would have failed the reroll loudly
instead of shipping a split fleet. Pair it with a wipe-liveness assert: after the surgical wipe,
assert the node's post-restart genesis timestamp/height is fresh (catches a wipe that did not clear
the live DB — the exact boot2 failure).

## Consequences

- Positive: an abandoned old-chain node (dev box, un-wiped fleet node, stale laptop) can NEVER again
  hijack onboarding — it is refused at handshake. Fresh-node cold-sync (G4) becomes deterministic:
  the only peers it can talk to are on the current genesis.
- Positive: the fix is at the existing handshake seam; no consensus/fork-choice change, no new
  attack surface.
- Negative: genesis hash churns per reroll (mechanical pin updates, listed above).
- Neutral: does NOT retroactively fix the current live split — that needs the an external node (IP redacted) source
  stopped + boot2 re-wiped (owner is handling an external node (IP redacted)). This ADR prevents recurrence.

## References
- Incident + live diagnosis: memory `project_boot2_stale_fork_2026-08-28`.
- Handshake genesis check: `core/network/src/transport.rs:269`.
- Genesis derivation: `node/src/genesis.rs`, `core/economics/src/genesis.rs::CANONICAL_GENESIS_TIMESTAMP`.
- Reroll ops: `scripts/ops/reroll-orchestrate.sh`, `scripts/ops/fleet-surgical-wipe.sh`.
- G9/G4 acceptance: `scripts/ci/restart_reorg_liveness_harness.sh` (both PASS at reroll HEAD 8e967e4).
