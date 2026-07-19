---
created: 2026-07-18
branch: fix/ghostdag-select-tip-determinism
author: Claude Opus 4.8 (1M), directed by @SaulBuilds
status: retrospective
---

# Retrospective — the reroll ceremony + the sync saga (2026-07-18)

## What we set out to do
Execute a deterministic **state-reset reroll** of chain 40204 to activate a batch of merged
work — the i64 Q16 re-freeze, execute-on-receive, VALIDATOR-S1 (stake-gated validator set
with §R' priority-fee reallocation), and a CREATE2 **freeze** of the AA + membership address
book so this would be the *last app-churn reroll* — then reconnect every service to the new
chain and prove the money path end-to-end.

## Outcome (honest)
**The reroll itself: unqualified success.** The chain rerolled cleanly, all 39 core contracts
deployed to their frozen addresses (verified byte-for-byte), 4 validators registered, the chain
crossed the §R' activation height at 2000 producing without a single reject, and the money path
was proven end-to-end (a real membership grant minted an SBT with on-chain art). Identity,
bundler, treasury-signer, and core-membership were all reconnected and verified live. The
consumer address sweep landed, and core-membership got a fresh, migrated, field-encrypted Neon DB.

**Two things were harder than expected**, both consensus/networking, both genuinely valuable to
have surfaced *now* rather than in production:
1. **Multi-producer consensus fork** — enabling a second block producer instantly forked the
   fleet. Root-caused to a one-function non-determinism (`GhostDag::select_tip` had no tie-break)
   and fixed with a tested regression.
2. **Follower sync** — the boot nodes could not catch up a gap. This turned out to be a *stack*
   of five distinct bugs, fixed one by one against a local harness, ending in a genuine cross-region
   nuance and a still-open architectural issue (two competing sync mechanisms).

## What went well
- **Frozen address book held.** Every AA/membership/registry address reproduced exactly from the
  deploy scripts — the CREATE2 freeze worked, and the determinism tripwires caught nothing because
  nothing drifted. Recovering the AA constructor args from the determinism *test* (rather than
  guessing) was the right call and reproduced the frozen factory/paymaster on the first try.
- **Keys never left the box.** The validator-registration ceremony ran from the DGX, signing
  locally and broadcasting via RPC; staker keys were derived deterministically, not stored.
- **A local 2-node harness turned a hall-of-mirrors into a debugger.** Every fleet-sync hypothesis
  was ambiguous against production logs; the harness reproduced follower catch-up deterministically
  and made each fix falsifiable in ~90 seconds instead of a 10-minute deploy cycle.
- **The chain never went down.** Through ~15 diagnostic restarts and a coordinated binary swap,
  rpc-1 stayed canonical and producing; every risky step (rpc-1 restart, genesis clone) was backed
  up first and gated on an explicit go/no-go.

## What went wrong / surprises
- **`cp` over a running binary silently fails (ETXTBSY).** A whole "deploy" appeared to succeed
  while the old binary kept running. Always `stop → cp → start`, never `cp; restart`.
- **`vercel env pull` returns empty for sensitive vars.** CLI 51.8 creates env vars as write-only
  by default, so pulled values read as `""` — which looked like "unset" and cost real time. The
  `--value` flag is required to set them non-interactively.
- **False-positive `pgrep`.** A build-wait loop matched its own `pgrep -f "cargo build…"` SSH
  command and reported "still building" long after the build finished. Poll the *log*, not `pgrep`.
- **The harness had to match the fleet exactly to be valid.** The first harness run (legacy mode,
  no `CITRATE_BLOCK_V2=1`) gave a false negative — a producer's applied tip only advances under
  execute-on-receive. Fidelity to the target environment is non-negotiable.
- **A checked-out ops script broke an unrelated build.** `reroll-reset.ts` had stale type errors
  against the current audit API and failed `next build` on redeploy — a reminder that anything in
  the tree gets type-checked.

## The root-cause pattern worth remembering
Four of the six sync bugs were the **same conceptual error in different places**: the codebase
conflates the **applied tip** (the execute-on-receive selected chain) with the **stored
height-index max** (`get_latest_height`, last-writer-wins, includes gossiped tips stored far ahead
of what's actually applied). That single confusion, replicated across fork-choice, pending-request
retirement, the sync anchor, the head advertisement, and the sync trigger, is what made followers
advertise a fake head, request the wrong range, and never converge. **When one distinction is
wrong in one place, grep for every other place it's used.**

## Open threads (action items)
1. **Sync-path reconciliation (highest value).** There are two competing sync mechanisms; the
   "naive sync" declares completion at a stale target and re-imports blocks it already has. This is
   why b2/b3 stall. Fix against the harness, then redeploy. Well-scoped now that it's understood.
2. **`select_tip` fix is unit-tested but not production-validated under real multi-producer** —
   validate once the fleet is healthy and multi-validator production is safe to enable.
3. **`sync.rs:303` underflow → `saturating_sub`** (done in the fix branch) — keep.
4. **Wire `discovery.mark_disconnected` into the peer-drop path** so a genuinely dropped peer
   re-dials instead of isolating. Exists but has no production caller.
5. **treasury-signer empty-response** — the grant completes on-chain but returns no JSON; the
   orchestrator can't record the txHash. Small `server.mjs` fix.
6. **`reroll-reset.ts` type errors** — fix the two before it's usable for a future reroll with data.
7. **comms relay 502** — pre-existing, unrelated; worth a look.

## Metrics
- Contracts deployed + verified: **39 / 39** core.
- Sync/consensus fixes committed: **6** (`fix/ghostdag-select-tip-determinism`), 118 consensus +
  81 network tests green.
- Chain uptime through the session: **100%** (rpc-1 never interrupted the canonical chain).
- Money path: **proven end-to-end** (grant → SBT → on-chain art).
