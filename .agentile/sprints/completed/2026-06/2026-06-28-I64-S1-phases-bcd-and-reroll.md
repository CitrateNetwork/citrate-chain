---
created: 2026-06-29T00:00:00Z
closed: 2026-06-29
branch: feat/i64-s1-phase-b-deterministic-deploy → -phase-c-ceremony → -phase-d-validation (all merged to main) + fix/sync-liveness-pending-clear
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: ceremony-complete (i64 binary live, bootnodes syncing; AA + table-commit owner-gated)
sprint: I64-S1 (Phases B–D + re-roll)
companion: ../../../../../citrate-federation/.agentile/planset/2026-06-28-i64-s1-q16-unification-and-deterministic-reroll.md
predecessor: 2026-06-28-I64-S1-phase-a.md
---

# I64-S1 Phases B–D + the deterministic re-roll

Phase A made the chain's i64 Q16 agree with the kernel bit-for-bit. Phases B–D
turned that consensus change into a **shippable, additions-only re-roll**: the new
contracts that need deterministic addresses (B), the validation that proves the
widening is safe to run from genesis (D), and the ceremony tooling that lands it
all without moving a single existing address (C). This journal covers B–D as
completed work and leaves the **Ceremony** section as a fill-in for the moment the
re-roll lands.

## Phase B — deterministic deploy + kernel-parity goldens (PR #59)

**WP-B1.** Five federated-learning contracts joined the surface after the last
re-roll and had no deterministic entry: KYCRegistry, IPFSIncentivesV2/V3,
AggregationChallenge, ComputePoolPipeline. `DeployFederatedLearning.s.sol` deploys
each via `new X{salt: Salts.salt("X")}` through the genesis Arachnid factory.

The finding that mattered: re-running the dry-run with a *different sender* moved
four of the five addresses. Only `AggregationChallenge` was sender-independent —
its constructor args are pure literals. The other four embed the
deployer/governance address in their init_code, so they're deterministic **only**
under the canonical deployer + governance=deployer. That turned a vague "they're
CREATE2 so they're stable" into a precise, written determinism contract
(`I64S1_PROJECTION.md`): the exact inputs the ceremony must hold, or the addresses
move. Owner confirmed both (params as-is, governance=deployer) on 2026-06-29.

**WP-B3.** `core/federated` gained a `golden_surfaces` module that proves the
chain's *pinned* kernel rev reproduces nat's three frozen consensus anchors —
aggregate `e79c5a63`, LoRA `9bda1b5b`, patronage `4000/1800/500` — plus chain-Q16
representability of the aggregate output. The point isn't to re-test the kernel
(it self-tests); it's a guard at the **chain's dependency boundary**, so a future
kernel rev-bump that drifts a committed-byte path fails before the chain builds
against it. 9/9 green.

## Phase C — re-roll funding, runbook, app-compat (PR #60)

Authoring only — execution stays owner-gated.

- **WP-C1** `fund-operational-roles.sh`: the genesis preset funds the supply roles;
  the off-chain operator EOAs (bundler, gateway signer, 2× DGX, identity signer)
  have zero balance after a reset. The script tops them up from the deployer,
  idempotent top-up-to-target, dry-run by default, never prints a key, skips unset
  roles instead of inventing addresses. Dry-run verified against the live chain.
- **WP-C2** `I64S1_REROLL_RUNBOOK.md`: the ordered ceremony, each step with a
  verify command. Refreshes the external handoff §11.
- **WP-C3** `I64S1_APP_COMPAT_MATRIX.md`: grounded in a federation-wide grep for the
  6 new contract names — only node-agent matched. So 11 of 12 apps are
  reconnect-only no-ops (RPC unchanged, existing addresses preserved); node-agent
  needs a sync + addrbook bump for the IPFS-incentives addresses.

The non-obvious risk Phase C closed: `regenesis.sh` is the orchestrator, and it had
a hardcoded ceremony list. Without wiring `DeployFederatedLearning.s.sol` into it
(and registering the broadcast + injecting the cross-repo coop factory in
`emit-address-table.sh`), the re-roll would have run clean and **silently not
deployed the 5 new contracts**. That's the kind of gap that only shows up at the
ceremony.

## Phase D — consensus-grade validation (PR #61)

Test-only, zero production delta. The new contribution is the **adversarial
wire-format suite** (`tests/q16_i64_adversarial.rs`) targeting the surface the
widening specifically created — not a re-run of the in-module rejects (routing,
tensor, belnap each already had proptest fuzz). The load-bearing invariant: an
**old i32-width buffer must fail-closed under the i64 decoder** — rejected, never
mis-read as a smaller valid input. Plus misalignment ±the 4-byte delta, saturation
at the new i64 bounds (which would *panic* under overflow-checks if the i128
intermediates were wrong — so green is the proof), and executor-boundary fuzz. 13
tests, green in **both** debug and release — which is also the WP-D4 cross-build
determinism proof: pure integer math + explicit saturation ⇒ byte-identical across
profiles. Gate `g-validation` = MET.

## Ceremony — the re-roll (2026-06-29)

Raw evidence: `scripts/ceremony/I64S1_CEREMONY_CLOSURE.md`. The narrative:

This was the re-roll that finally made the i64 work *real on the wire* — and it
forced a second, unplanned fix that turned out to matter more than the i64
change itself.

**The binary.** The aarch64 dev box can't cross-compile to the amd64 nodes
(rust-toolchain pin → rustup tries to install an x86_64 host toolchain it can't
run). So we stopped fighting cross and built **natively on boot1** — a bootnode
*is* an amd64 box. 55 minutes, zero errors, md5 `017b9b92eae7`. A throwaway
genesis boot-test first (non-destructive) proved it initializes cleanly: state
root `0x9cd39b4b…`, genesis `6b6d8b89…` at height 0. Only then did we touch a
live node.

**The reset.** Bootnodes first, rpc-1 (the sole miner) last, Noise keys
preserved each time, old state archived as `.citrate.preroll-<ts>` (recoverable).
All four came back on the same fresh i64 genesis.

**The fix that mattered.** Going in, the known gap was "bootnodes peer but don't
sync." It was never transient — it was a **3-bug liveness deadlock** in
block-sync (PR `8663b78`):

1. `handle_headers`/`handle_blocks` never *retired* the pending request a
   response answered, so `pending_*` never drained and `check_timeouts` flagged
   the *responding* peer 30s later as if it had gone silent;
2. the sync loop anchored `start_from` on the first request forever (the genesis
   zero-hash), so even with (1) fixed it could never walk past the first batch;
3. five such false timeouts **permanently banned** the peer — and on a
   four-node fleet the peer being banned is rpc-1, the *only* block source.

That third bug is the whole split-brain in one sentence: a bootnode banning its
producer. The live proof on the rerolled chain — bootnodes climbing in lockstep
with the miner (`rpc=89 / boot1=90 / boot2=90 / boot3=91` at t+60s) and **zero**
ban lines — is the first time across ~six re-rolls the fleet has actually
gossiped a chain instead of fracturing into one.

**The contracts.** `regenesis.sh` redeployed all 44 business contracts, every one
verified to have code, `AggregationChallenge.challengeWindow()` answering `150`
through the i64 EVM. The determinism contract from Phase B held **byte-exact**:
all five federated-learning contracts landed on their `I64S1_PROJECTION.md`
addresses. That's the payoff of writing the determinism contract down — we could
*assert* the addresses, not hope for them.

**What the determinism contract bought us — honestly.** It held for everything it
covered. But the run also surfaced what it *didn't* cover: the committed
`40204.json` dates to 2026-06-08, and 11 peripheral contracts (EduStack, x402,
compute marketplace, wSALT, the portable router) have drifted in bytecode since.
No salt changed — CREATE2 just (correctly) puts new bytecode at a new address.
The core surface the live apps use held; the movers are all verticals. The lesson
is that "deterministic" is only as good as the *table you diff against* — a stale
committed table makes a correct deploy look like a scramble. The owner-gated
follow-up (commit the table, sync the few affected consumers) is exactly where the
"don't break the apps" judgment belongs, so the table was left uncommitted for
review rather than auto-propagated into seven app repos overnight.

- **Date / duration:** 2026-06-29, ~1h of live ceremony after a 55m build.
- **Sync fix commit:** `8663b78` on `main` (3-bug deadlock + 2 regression tests).
- **Node reset order held / Noise keys persisted / gossip re-formed:** ✅ all four.
- **Additions-only diff:** ✗ as expected-on-paper — 11 peripheral contracts moved
  on bytecode drift vs the 2026-06-08 table (no salt changed; core held); coop
  factory removed (EIP-170); AA stack stale (no `--with-aa`). Owner-review items.
- **New contracts live:** ✅ 5/5 fed-learning at projected addrs; coop factory
  still EIP-170-blocked.
- **Apps green:** core apps reconnect-only (RPC + core addrs unchanged); explorer
  200, faucet ok. Consumer `sync-addresses` for the 11 movers deferred to owner.
- **Smoke + live signals:** ✅ rpc producing, bootnodes syncing, faucet ok,
  explorer 200, 44 contracts have code.
- **What had to be improvised:** native-on-boot1 build (cross blocked); folding
  the sync fix into the same binary mid-build; killing zombie waiter loops from
  prior sessions that self-matched `pgrep "cargo build"` and would have restarted
  nodes mid-reset.

## Verification at close

| Phase | Evidence |
|---|---|
| B | PR #59; `core/federated` 9/9; dry-run table in `I64S1_PROJECTION.md` |
| C | PR #60; funding-script dry-run vs live chain; runbook + matrix |
| D | PR #61; adversarial 13/13 (debug+release); g-validation report |
| Ceremony | `I64S1_CEREMONY_CLOSURE.md`; sync `8663b78` (live: bootnodes lockstep, 0 bans); 44 contracts have code; 5/5 fed-learning at projected addrs |

## One-line epitaph

The i64 re-roll's real prize wasn't the wider fixed-point — it was a four-node
fleet that finally syncs instead of banning its own miner.
