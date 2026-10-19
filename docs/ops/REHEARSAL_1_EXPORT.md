---
created: 2026-10-19T08:00:00Z
branch: ops/r1-export-procedure
author: Larry Klosowski (chain team; DGX session, Claude Opus 5.5)
status: active — procedure ready; rehearsal-1 inputs pending (see §6)
---

# Rehearsal-1 export: procedure

On rehearsal-1 day (2026-11-13) the chain team hands core and design one bundle: the UI truth
fixture, the frozen address book and the claims file. This document is how that bundle is made.
One command makes it: [`scripts/rehearsal/export-r1.sh`](../../scripts/rehearsal/export-r1.sh).

What the files mean is defined elsewhere and is not repeated here:
- the fixture and every value in it: [`docs/ui-truth/UI_TRUTH_CONTRACT.md`](../ui-truth/UI_TRUTH_CONTRACT.md) §2 and §7;
- the address book: [`contracts/addresses/README.md`](../../contracts/addresses/README.md);
- the claims file and its statuses: [`verification/README.md`](../../verification/README.md).

## 1. Who runs it

The DGX lead (chain team) runs the export. It makes JSON-RPC reads only: no keys, no signing,
no transactions. Core (MAC lane) and design receive the bundle and don't run the export.

## 2. Preconditions

All of these must hold before the export. The script checks the ones it can and refuses when
they fail.

| # | Precondition | Checked by the script |
|---|---|---|
| P1 | The rehearsal-1 genesis is cut and its genesis hash is recorded | Yes: `--expect-genesis` must match block 0 on the RPC |
| P2 | The rehearsal contract set is deployed and the address book is **frozen**: the new `contracts/addresses/40204.json` is merged, with its `deployedAt` | Yes: book and claims must equal `HEAD`; required fields present; the eight contracts the fixture reads are present, non-zero and well-formed |
| P3 | The address-code snapshot was re-probed against the rehearsal chain (`python3 verification/check_address_code.py --probe --rpc <url>`), and `claims.json` `deployed_contracts` updated to match, both committed | Yes: `check_address_code.py --check` runs live and fails on any difference |
| P4 | `claims.json` passes its gate | Yes: `verification/check_claims.py` |
| P5 | The RPC serves the rehearsal chain and is synced | Partly: chain id and genesis are checked. Sync isn't: the operator confirms the RPC is at the producers' head |
| P6 | The export runs from a clean checkout of the commit that holds P2 and P3 | Yes: the manifest records the git SHA and refuses changed inputs |

## 3. The command

From a clean checkout of `citrate-chain` at the freeze commit:

```bash
scripts/rehearsal/export-r1.sh \
  --rpc <rehearsal RPC URL> \
  --expect-genesis <genesis hash recorded at the cut>
```

It writes `out/rehearsal/r1-<UTC date>-<chain id>/` (`out/` is gitignored), containing:

| File | What it is |
|---|---|
| `ui-truth-fixture.json` | A fresh export by `scripts/ui-truth/export-fixtures.sh` against the RPC |
| `addresses-<chain id>.json` | The frozen address book, byte-for-byte |
| `claims.json` | `verification/claims.json`, byte-for-byte |
| `MANIFEST.json` | Mode, generated-at, git SHA and describe, chain id from the book and from the RPC, genesis hash, the RPC block height read just before the fixture export, the address book's `deployedAt`, the gates that passed, and the sha256 and size of each file |
| `SHA256SUMS` | `sha256sum -c SHA256SUMS` verifies the bundle |

The bundle is staged in a temporary directory and moved into place only when complete, so a
refusal leaves nothing behind. An existing non-empty output directory is never overwritten.

Other options: `--out DIR`, `--label NAME` (default `r1`; use `r2` for rehearsal 2), `--book PATH`.
The provenance check covers every bundled input and every tool the export runs: the address
book, `claims.json`, the address-code snapshot, the book schema, `export-r1.sh` itself,
`scripts/ui-truth/export-fixtures.sh`, `verification/check_claims.py`,
`verification/check_address_code.py`, and, offline, the bundled fixture. Online, every contract
the fixture reads (GOVERNANCE and GUARDIAN included) must have code, and the fixture's two
governance `minDelay()` reads must succeed.
`--allow-dirty` accepts inputs that differ from `HEAD` for a scratch run only; the manifest
lists them under `source.inputs_differ_from_head`, and such a bundle isn't handed off.

### Dry run (any day, no network)

```bash
scripts/rehearsal/export-r1.sh --offline
```

This runs every repo-side gate and builds a bundle from the newest committed fixture under
`docs/ui-truth/fixtures/`. Its manifest says `"rehearsal_export": false` and
"OFFLINE DRY RUN", and has no height or genesis. Use it to rehearse the handoff; never hand it
off as the rehearsal export.

Test: `scripts/rehearsal/test-export-r1.sh` covers the dry run, every refusal, and an online run
against the loopback stub RPC (`scripts/ui-truth/stub_rpc.py`). No public network is touched.

## 4. Verification before handoff

1. The command exited 0 and printed `wrote out/rehearsal/r1-…`.
2. `cd out/rehearsal/r1-… && sha256sum -c SHA256SUMS` passes.
3. In `MANIFEST.json`: `rehearsal_export` is `true`, `chain.genesis_hash` is the recorded
   genesis, `source.inputs_differ_from_head` is empty, and `source.git_sha` is the freeze commit.
4. In the fixture: `single_epoch` is `true`. If it's `false`, the export crossed an epoch
   boundary; re-run it into a new `--out` directory (the UI truth contract §7 explains why).
5. Skim the fixture for `unavailable` values. They are honest (the contract forbids filling
   them in), but core and design should be told which numbers are missing.

## 5. Handoff

- **Core (MAC lane):** the bundle directory plus its `MANIFEST.json` sha256. Core vendors the
  address book from this bundle (or from the freeze commit, which is the same bytes) and builds
  fixture-labelled screens from `ui-truth-fixture.json` (contract principle 4).
- **Design:** the same bundle. Design v2 (11-13) uses the fixture values, labelled as fixtures.
- Record the handoff (bundle name, manifest sha256, freeze commit) on the betanet board item
  for the rehearsal-1 export, so later bundles can be compared with it.
- The address book is frozen from this point. A change after rehearsal 1 needs a new bundle
  (`--label r1b`) and a note to both lanes.

## 6. Pending (values that exist only after the cut, and follow-ups)

| Item | Status |
|---|---|
| Rehearsal-1 RPC URL | Pending: DGX lead, at provisioning |
| Genesis hash for `--expect-genesis` | Pending: recorded at the rehearsal-1 cut |
| Frozen address book, re-probed snapshot, updated `deployed_contracts` | Pending: rehearsal-1 deploy (C4) |
| Fixture canonical-checkpoint reads | Follow-up: `export-fixtures.sh` reads the r1005 checkpoint heights 365,784 and 365,785. A new genesis starts with no canonical checkpoints (C2 D10), so those reads must follow the new `CANONICAL_CHECKPOINTS` before the export means anything there |
| Fixture label | Follow-up: the fixture says "captured from 40204". That stays true if D1 keeps 40204; otherwise the exporter changes with the chain id |
| `claims.json` `chain_id` sources | Follow-up: the claim cites `node/config/mainnet.toml`, which the genesis profile work (G1) rewrites |
| Delivery channel for the bundle | Owner/DGX lead: board attachment, a private share, or committing the fixture under `docs/ui-truth/fixtures/` |
