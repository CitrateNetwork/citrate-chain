---
created: 2026-10-26T20:45:00Z
branch: ops/r1006-bringup
author: Larry Klosowski (chain team; DGX session, Claude Opus 5.5)
status: active
updated: 2026-10-27 (host allowlist, release-genesis refusal, mining gate, output containment; MIN_CHAIN_REV pre-join, smoke admins in genesis-chain mode)
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
#   MIN_CHAIN_REV: the full sha of chain#398's merge commit on main (or later), in the
#   reviewed one-line file scripts/ops/r1006/min_chain_rev or passed as --min-chain-rev
$B start --mining on                       # pre-join build-rev check; all nodes up with mining off; block 0 checked on every host; then mining on
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
| start | pre-join, before any host starts: MIN_CHAIN_REV is set (`--min-chain-rev` or the reviewed `scripts/ops/r1006/min_chain_rev`; both set must agree; a full sha in this checkout), and each host's installed binary reports (`consensus --json`) a clean `git_sha` that resolves in this checkout and contains MIN_CHAIN_REV (`git merge-base --is-ancestor`). A binary from before chain#398 does not know the r1006 genesis and would run it with every rule off, so it is refused here. Then the same genesis checks; every node starts with mining off and its block 0 must be the r1006 genesis (else every started node is stopped); only then, host by host, the host re-checks its own node's block 0 and switches mining on; ≥6 peers each; blocks from all 7 coinbases within 10 min |
| smoke | every head past block 60; FLEET AGREE; chain id 40204; `eth_getCode` = genesis alloc; OrangeSeed `story()`; `CheckDeployedAdmins` in chain#398's genesis-chain mode (`GENESIS_CHAIN=1`, `GENESIS_ALLOC` = the fill's block-0 alloc) passes (forge rc 0) with FACTORY-ADMIN, DEPLOYER-ADMIN, NO-CODE, TIMELOCK-HOLDERS and GENESIS-FLOOR each reported once as 0 (the fill's book and alloc are staged under `contracts/addresses/` for forge and removed after; a fill without an alloc fails); no CONFLICT / fork / deep reorg in logs; finality answers; no contribution recorder configured; RSS < 3 GiB |

A node built without the r1006 profile refuses `genesis_profile = "r1006"` at start
(node/src/genesis.rs) instead of falling back to the chain-id default (r1005's genesis).

The keys step also writes `r1006-public-bootnodes.json` (the producers' `noise_<id>@<ip>:30303`
list) for the network profile at cutover.

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
