# Verification — Single Source of Truth for Public Claims

`claims.json` is the **single, machine-readable source of truth** for every public
technical claim Citrate makes about `citrate-chain` (supply, chain id, consensus
parameters, test counts, TPS, formal-verification coverage, audit status, …).

This file exists on the top recommendation of an external auditor: every number a
human sees on the website, a deck, a blog post, or a README **must be generated
from `claims.json`**, never hand-typed. If a public surface disagrees with this
file, the public surface is wrong and should be regenerated.

## How to read a claim

Each entry under `claims` is keyed by a stable id and carries:

- `value` — the claim itself (scalar or object). `null` means not established here.
- `scope` — which repo/subsystem the claim is about.
- `source_files` — where the value is defined in the code/config (with line refs).
- `evidence_files` — supporting tests, benches, address tables, or specs.
- `reproduction_command` — how to re-derive or re-measure the value.
- `count_method` — for counts, the exact counting rule used.
- `last_verified_at` — when the value was last checked.
- `verification_status` — how much trust the value has earned (see below).
- `notes` — caveats, discrepancies, and stale-figure warnings.

Top-level `source_commit` pins the exact `citrate-chain` commit the values were
derived from. Re-verify against a new commit before trusting stale values.

## `verification_status` definitions

- **`measured-here`** — the value was measured by running a command at
  `source_commit` and recording the actual output (e.g. `forge test` count).
- **`verified-in-ci`** — the value is asserted and continuously enforced by CI
  (a green pipeline is evidence).
- **`reproducible-from-source`** — the value is a constant or config in the tree;
  the `reproduction_command` re-derives it deterministically, no run required.
- **`derived-from-config`** — the value is arithmetic over in-tree constants/config
  (e.g. throughput = block gas limit / gas per tx / block time); shown with its
  derivation, not an independent live measurement.
- **`measured/derived`** — a live-measured input combined with in-tree config
  (e.g. finality = checkpoint interval x measured block time).
- **`target-pending-protocol-upgrade`** — an aspirational target that is not met
  today and requires a protocol/consensus change that has not shipped; never
  present it as a current capability.
- **`baseline-unreproduced-artifact-pending`** — a historical baseline is recorded,
  but the committed evidence artifact is missing or the run has not been repeated;
  treat as provisional until re-run.
- **`partial`** — the value is real but only partially substantiated (e.g. a subset
  of formal specs have recorded model-check runs; large specs bounded not exhaustive).
- **`documented-pre-audit`** — documented and internally reviewed, but not yet
  confirmed by an external audit or an end-to-end measurement.
- **`not-measured-here`** — the value could not be established in this pass; `value`
  is `null` (or a placeholder). Do NOT publish a number for it.

## Honesty rules

1. Never assert a number that was not actually measured or derived — use `null`
   plus `not-measured-here` instead of a guess or a marketing figure.
2. Marketing/deck figures are not evidence. Where they disagree with a measured
   value, the `notes` field records the stale figure so it can be corrected.
3. Known discrepancies (e.g. `ModelRegistry.sol`'s precompile constant vs the
   canonical dispatcher scheme) are recorded as claims/flags, not hidden.

## Regenerating website facts

Downstream surfaces should read `claims.json` at build time and template the
`value` fields directly. When a claim changes, update `claims.json` (with a fresh
`last_verified_at` and, if the commit moved, `source_commit`) and let the surfaces
regenerate — do not edit the numbers downstream.
