---
created: 2026-10-26T20:45:00Z
branch: ops/r1006-bringup
author: Larry Klosowski (chain team; DGX session, Claude Opus 5.5)
status: active
updated: 2026-10-29 (FLEET AGREE checks execution; smoke log scan exemptions, hard lines and read errors; forge pinned below the head; start re-arms the height watchdog; committed min_chain_rev; local devnet --keep, option forwarding, stop at the first failed step, rehearsal past activation). Earlier: 2026-10-27 (host allowlist, release-genesis refusal, mining gate, output containment; MIN_CHAIN_REV pre-join, smoke admins in genesis-chain mode; operator endpoint for forge reads, smoke --logs-since)
supersedes: the fleet steps (S1, S3, S5-S7) of citrate-federation R1006_REROLL_RUNBOOK.md (fed#399) for r1006
---

# r1006 bring-up on the 7 producers

This replaces the fleet half of the fed#399 r1006 runbook, which was written before the
2026-10-26 decisions: **the whole contract library is in block 0** (no deploy ceremony on
the live chain), **the validator set is in block 0**, and r1006 runs **privately on the 7
producers** (citrate-prod-1..7) before any cutover. The tool is
[`scripts/ops/r1006_bringup.sh`](../../scripts/ops/r1006_bringup.sh); its header is the
reference for every option. Each step is idempotent and has `--dry-run`.

## Owner approval points

Nothing below runs without the owner's written go on fed#331 (Rule 10). `keys` and
`distribute` change the producer hosts; `start` begins the network; cutover (bootnodes,
rpc.citrate.ai) is a separate approval and is not done by this tool.

## Sequence

From a citrate-chain checkout of `main` on the DGX, after the genesis builder's
validator-set fill has merged:

```bash
B=scripts/ops/r1006_bringup.sh             # state defaults to ~/r1006-state (0700)
SHA=$(git rev-parse origin/main)
$B build --sha "$SHA"                      # on citrate-core-linux-build, ~13 min (aarch64 local: 774 s)
$B keys                                    # mints on each host as citrate; public parts and registration proofs only
#   run the fill (scripts/genesis/r1006/fill_producers.py) on r1006-producers.json,
#   r1006-registration-proofs.json and r1006-stakes.json; it re-pins R1006_GENESIS. Commit,
#   merge to main, then rebuild on the final merged tree (which may re-pin it again):
SHA=$(git rev-parse origin/main); $B build --sha "$SHA"
$B genesis-fill --fill-cmd 'python3 scripts/genesis/r1006/fill_producers.py {producers} {stakes} {out}'
#   kept only if its block 0 is the R1006_GENESIS committed in this checkout AND the build's
$B distribute                              # binary hash-checked; node.toml (r1006 profile, mining off); block 0 probed per host
#   MIN_CHAIN_REV: the reviewed floor committed in scripts/ops/r1006/min_chain_rev
#   (56cc2bc8, 2026-10-29), or --min-chain-rev with the same sha
$B start --mining on                       # pre-join build-rev check; all nodes up with mining off; block 0 checked on every host; then mining on; watchdog re-armed
$B smoke                                   # must end SMOKE PASS
```

Rollback at any point before cutover: `$B stop --state "$ST"`, then `$B wipe --state "$ST"`
(chain data only; keys kept). `--wipe-keys` destroys the host identities and asks for a
typed confirmation.

| Step | Gate (fails closed) |
|---|---|
| every step | every host is one of citrate-prod-1..7 at its pinned IP (`scripts/ops/r1006/guard.py`, not the inventory), and the live `doctl --tag-name citrate-producer` list agrees, before any connection; `build` reaches only the build-only host `citrate-core-linux-build` |
| build | the commit is on `origin/main`; sha256, consensus fingerprint and the compiled r1006 genesis recorded |
| keys | each host also runs `citrate registration-proof --registry <the committed r1006 book's ValidatorRegistry>`; the proof must be exactly the public object for that host's staker and proposer key, and goes into `r1006-registration-proofs.json` (the fill's input). Each host re-serialises its checked public identity; the orchestrator checks it again in memory and writes only that object; any key or password pattern in the host's stdout or stderr fails the step (rc 3) with nothing written or echoed |
| genesis-fill | the fill lists exactly the producers with their stakes; activation height ≥ 800 (r1006: 1000; the node refuses less, also for a genesis validator set); profile `r1006`; no genesis file; registry = the committed book's; block 0 = the `R1006_GENESIS` committed in `core/consensus/src/hardening.rs`, read at run time, which the build must also compile, and never a release network's (r1005 `0x1dcfc490…75f1`, team testnet, mainnet); otherwise the fill is discarded |
| distribute | the same genesis checks, before any host is touched; staged and installed binary sha256 match; every host's isolated probe gives that block 0 (recorded on the host) |
| start | pre-join, before any host starts: MIN_CHAIN_REV is set (`--min-chain-rev` or the reviewed `scripts/ops/r1006/min_chain_rev`; both set must agree; a full sha in this checkout), and each host's installed binary reports (`consensus --json`) a clean `git_sha` that resolves in this checkout and contains MIN_CHAIN_REV (`git merge-base --is-ancestor`). A binary from before chain#398 does not know the r1006 genesis and would run it with every rule off, so it is refused here. Then the same genesis checks; every node starts with mining off and its block 0 must be the r1006 genesis (else every started node is stopped); only then, host by host, the host re-checks its own node's block 0 and switches mining on; ≥6 peers each; blocks from all 7 coinbases within 10 min. After the gates (also with `--skip-producing-gate`), every started host re-arms the height watchdog that `stop` paused for 12 h (`citrate-watchdog-ctl.sh resume`, only where the watchdog is installed; a failed resume fails the step and leaves the nodes running) |
| smoke | every head past block 60; FLEET AGREE, which also requires every node to have **executed** the majority block at the common height and its own block 10 below its head (`citrate_isExecuted`; see below); chain id 40204; `eth_getCode` = genesis alloc; OrangeSeed `story()`; `CheckDeployedAdmins` in chain#398's genesis-chain mode (`GENESIS_CHAIN=1`, `GENESIS_ALLOC` = the fill's block-0 alloc) passes (forge rc 0) with FACTORY-ADMIN, DEPLOYER-ADMIN, NO-CODE, TIMELOCK-HOLDERS and GENESIS-FLOOR each reported once as 0 (the fill's book and alloc are staged under `contracts/addresses/` for forge and removed after; a fill without an alloc fails; forge reads through the operator endpoint, see below, pinned with `--fork-block-number` 10 blocks below that host's head, and with no operator host the check fails naming `serve_recent_state_tags`); no CONFLICT / fork / deep reorg in logs since the start record or `--logs-since EPOCH` (the window is printed in the PASS/FAIL line; see "Log scan" below); finality answers; no contribution recorder configured; RSS < 3 GiB |

## FLEET AGREE checks execution

`eth_getBlockByNumber` and `eth_getBlockByHash` serve stored blocks. A node whose applied
tip is stuck still stores, and so walks, the network's chain: by blocks alone it "agrees"
(seen on 2026-10-29). `scripts/genesis/fleet_agree.sh` therefore also asks every endpoint
`citrate_isExecuted` (params: the bare block hash): for the majority hash at the common
height H the answer must be `{"executed": true, "number": H}`, and for the endpoint's own
block `OWN_BACK` (10) below its head it must be executed at that height. An unreachable
node, an RPC error or an answer that does not parse fails the check.

## Log scan

`host_agent.sh logs-scan` fails a host on any line naming a CONFLICT or a fork except the
known notices. Exempt, because a healthy multi-producer start logs them while each node's
applied tip catches up with fork choice (`node/src/canonical_apply.rs`, `node/src/main.rs`):

- a fork activation (`… fork ACTIVE from height …`), and a converged fork choice
  (`… converged to the fork-choice head`, `rebuilt applied state to the fork-choice head`,
  `canonical recovery: converged to fork-choice head H @ N`);
- `canonical recovery: applied tip … is behind the fork-choice head … on the same chain;
  the drain advances it (no rebuild)` and `periodic drain: … stepped toward it via …`;
- counted and shown as NOTE lines: fork-choice reorgs up to `R1006_MAX_REORG` (6) blocks
  deep, start-up recovery toward a heavier head (`… outranks the applied tip …; fork point
  … (K applied block(s) abandoned)`) with K up to `R1006_MAX_RECOVERY_ABANDON` (100), and
  MP-S1 skipped production rounds.

Always a failure, whatever else the line says: `NOT rebuilding from genesis` and
`CONSENSUS ALARM`. A log the agent cannot read (no log file, a `journalctl` error) fails
that host's scan; it is never counted as 0 matches, and smoke goes on to its other checks.

## Forge pinned below the head

The admins check reads the chain through forge pinned to one block. Pinned to the head, a
one-block sibling reorg (normal with 7 producers) replaces that block, and the node then
correctly refuses state for a block it no longer executes (`historical state not available
… is not the executed`), failing smoke for no fault. Smoke pins forge
(`--fork-block-number`) `R1006_ADMINS_PIN_BACK` (10) blocks below the operator host's
head instead.

## Operator endpoint for forge reads

`forge script` pins every state read to the block it started at. Since chain#425 a node
refuses such a read once its executed head moves (`historical state not available on this
node`), which at 2 s blocks is almost at once, so smoke's `CheckDeployedAdmins` needs a node
with the operator window (`docs/ops/RPC_STATE_BLOCK_TAGS.md`). The inventory designates one
host for that: `citrate-prod-1` has `"serve_recent_state_tags": 1024`. `distribute` writes
`[rpc] serve_recent_state_tags = 1024` into that host's `node.toml` only (its RPC stays on
loopback, reached through the ssh tunnel); every other host stays strict. Smoke runs forge
against that host's tunnel, also under `--only`. `guard.py check-inventory` refuses a value
that is not an integer 0-1024 (the node clamps above 1024).

Sizing: on r1006 the checker's forge run takes about 45 s, about 65 blocks at the observed
~1.4 blocks/s, so a 64-block window ran out mid-run (2026-10-28). 512 then also ran out:
on the chain rerolled 2026-10-29 the same run took about 4 min 20 s (forge's RPC cache was
cold for the new chain) at ~1.9 blocks/s, and the last pinned read was 513 blocks behind.
1024, the node's maximum, gives about nine minutes; it widens only the operator host's
answers, never the public RPC.

To roll the window onto a running fleet (`distribute` replaces the binary, so the node must be
stopped; the binary is the same build and its hash is checked again):

```bash
$B stop --only citrate-prod-1
$B distribute --only citrate-prod-1        # profile + node.toml with the window; block 0 probed
$B start --only citrate-prod-1 --mining on --skip-producing-gate
$B smoke                                   # admins: "forge via citrate-prod-1 ..."
```

A node built without the r1006 profile refuses `genesis_profile = "r1006"` at start
(node/src/genesis.rs) instead of falling back to the chain-id default (r1005's genesis).

The keys step also writes `r1006-public-bootnodes.json` (the producers' `noise_<id>@<ip>:30303`
list) for the network profile at cutover.

## Local rehearsal (`scripts/ops/r1006/local_devnet.sh`)

The rehearsal runs the bring-up on N local hosts in network namespaces inside one
unprivileged user namespace (the script's header has the options). Its steps run in order
and the run stops at the first failed step, with that step's rc. `--min-chain-rev` is
passed to `start`. The namespaces live as long as the script, their PID 1: without
`--keep` the devnet ends when the steps finish; with `--keep` it stays up (a wait loop that
reaps exited processes) until Ctrl-C or SIGTERM to its process group.

**Past activation.** The default fill is a stand-in (`scripts/ops/tests/fixtures/
rehearsal_fill.py`) that keeps the compiled profile's validator set, so the devnet
producers are not registered and the chain halts at the validator activation height
(block 1000; the last block is 999). Both the stand-in and the devnet print a warning. To
run past activation (as done on 2026-10-29):

1. `keys`;
2. `genesis-fill --fill-cmd 'python3 scripts/genesis/r1006/fill_producers.py {producers} {stakes} {out}'`:
   the real fill re-pins `R1006_GENESIS` and is refused against the current build;
3. in a throwaway clone, commit what the fill changed (the r1006 `validators.json` and
   `core/consensus/src/hardening.rs`) on a local branch that is never pushed, and build it
   (`build --sha <that commit> --local-repo <clone> --allow-non-main`);
4. `genesis-fill` again with the same command (now accepted), then `distribute`, `start`, `smoke`.

No devnet genesis is ever committed to a shared branch.

## End-to-end with chain#398, 2026-10-27 (local; nothing on the fleet)

This branch at `6b27b411` was merged with chain#398 at `80fbd6f8`, locally only; the combination was not pushed. The run used 5 hosts in separate network namespaces inside one unprivileged user namespace, throwaway keys minted on each host by the real `citrate host-identity`, and the real fill (`scripts/genesis/r1006/fill_producers.py`).

| Step | Time | Result |
|---|---|---|
| build A (local aarch64, release, 4 jobs) | 356 s | records r1006 genesis `0xa8626a4f…6b55` (the pre-fill pin) |
| keys (5 hosts) | 6.5–8.1 s | 5 identities and 5 `citrate-registration-proof/1` proofs for `0xf511327e…31cd` |
| genesis-fill (first) | 27.1 s | 5 producers registered at block 0, re-pinned to `0x3353e70c…f67d`; **refused** against build A ("rebuild at the commit that pins it"), fill discarded |
| build B (after committing the fill) | 350 s | records `0x3353e70c…f67d` |
| genesis-fill | 6.1 s | accepted |
| distribute (with per-host probes) | 14.5–15.0 s | ok |
| start --mining on | 33.0 s | 5 × block 0 verified with mining off, then mining enabled host by host after each host re-checked its own block 0; ≥ 4 peers; all 5 coinbases produced blocks |
| smoke | 25–68 s | FLEET AGREE (5 endpoints, block 59–60), chain id, code = alloc, OrangeSeed `story()`, no CONFLICT/fork (shallow 1-block reorgs as NOTE), finality answers (block 0, switch off), no contribution recorder, RSS: **PASS**. `CheckDeployedAdmins`: DEPLOYER-ADMIN 0, FACTORY-ADMIN 0, NO-CODE 0, VERIFIER present, but forge exits 1 on TIMELOCK-HOLDERS and GENESIS-FLOOR (role history empty / no GuardianCanceller in the books, which a genesis chain has no events for), so the check reports **FAIL** and smoke ends rc 1 |
| status / stop / wipe | 2.1 / 4.6 / 3.7 s | ok; wipe kept `noise.key`, `proposer.key` and the keystore |

No host key byte appears in the state dir or the run logs (70 needles, 0 hits).

## Dry run, 2026-10-26 (local; nothing on the fleet)

Seven hosts in separate network namespaces on a private bridge, inside one unprivileged user
namespace; throwaway keys minted by the real `citrate host-identity`; binary built by the
`build` step from this branch merged with chain#375 and chain#387 (not pushed).

| Step | Time |
|---|---|
| build (local aarch64, `CARGO_BUILD_JOBS=2`) | 774 s |
| keys (7 hosts) | 3.7–6.7 s |
| genesis-fill | 1.5 s |
| distribute (7 hosts, with probes) | 18.5–20.5 s |
| start (gates passed) | 7.2–22.0 s |
| smoke | 47–124 s (mostly waiting for block 60) |
| stop / wipe | 5.3 s / 3.2 s |

What the dry run does **not** show: the fill command did not exist yet, so a labelled stand-in
selected the compiled `default` devnet genesis (block 0 `0x679a62e8…c4a5`) **without** the
validator set in it, and OrangeSeed and DEPLOYER-ADMIN were skipped. With all 7 mining from
block 0, every run converged (FLEET AGREE at blocks 54–59), after shallow fork-choice reorgs
(at most 3 blocks deep) in the first blocks; smoke reports these as NOTE lines.
