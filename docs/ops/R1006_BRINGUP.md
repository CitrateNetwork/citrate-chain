---
created: 2026-10-26T20:45:00Z
branch: ops/r1006-bringup
author: Larry Klosowski (chain team; DGX session, Claude Opus 5.5)
status: active
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
B=scripts/ops/r1006_bringup.sh; ST=~/r1006-state
SHA=$(git rev-parse origin/main)
$B build --sha "$SHA" --state "$ST"        # on citrate-core-linux-build, ~13 min (aarch64 local: 774 s)
$B keys --state "$ST"                       # mints on each host as citrate; public parts only
$B genesis-fill --state "$ST" --fill-cmd '<fill command> {producers} {stakes} {out}'
#   -> commit the fill's genesis (compiled r1006 profile) to main, then rebuild at that sha:
SHA=$(git rev-parse origin/main); $B build --sha "$SHA" --state "$ST"
$B distribute --state "$ST" --mining on     # binary + genesis hash-checked; node.toml; block 0 probed per host
$B start --state "$ST"                      # prod-1 alone first; block 0 gate; peers; all 7 produce
$B smoke --state "$ST"                      # must end SMOKE PASS
```

Rollback at any point before cutover: `$B stop --state "$ST"`, then `$B wipe --state "$ST"`
(chain data only; keys kept). `--wipe-keys` destroys the host identities and asks for a
typed confirmation.

| Step | Gate (fails closed) |
|---|---|
| build | the commit is on `origin/main`; sha256 and consensus fingerprint recorded |
| keys | every `identity.pub.json` passes the public schema; keys distinct; staker = coinbase |
| genesis-fill | the fill lists exactly the 7 producers with their stakes |
| distribute | staged and installed binary sha256 match; every host's isolated probe gives the fill's block 0 |
| start | each node's block 0 = the fill's (else every started node is stopped); ≥6 peers each; blocks from all 7 coinbases within 10 min |
| smoke | every head past block 60; FLEET AGREE; chain id 40204; `eth_getCode` = genesis alloc; OrangeSeed `story()`; DEPLOYER-ADMIN 0; no CONFLICT / fork / deep reorg in logs; finality answers; no contribution recorder configured; RSS < 3 GiB |

The keys step also writes `r1006-public-bootnodes.json` (the producers' `noise_<id>@<ip>:30303`
list) for the network profile at cutover.

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
