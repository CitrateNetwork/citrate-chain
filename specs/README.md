# Formal Verification Specs

## Canonical Location

The canonical TLA+ specification collection lives at **`.agentile/formal/specs/`** (101 specs today across all domains). That is the authoritative source for spec counts, verification status, and coverage.

## Local Subset (`specs/tla/`)

This directory contains a **subset of 46 specs** organized into six domains (consensus, zk, learning, contracts, compute, gui). These are runnable locally and in CI.

For spec counts, invariant totals, and verification results, always refer to:
- `.agentile/formal/specs/INDEX.md` -- canonical spec index
- `specs/tla/VERIFICATION_REPORT.txt` -- local run results

Do not cite spec counts from this README as authoritative -- they may lag behind the canonical source.

## Running Specs

```bash
# Run local subset (standard, single worker)
cd specs/tla && bash run_all.sh

# Deep verification (16 workers, 45-minute timeout)
cd specs/tla && bash run_deep.sh

# Single spec
java -jar tla2tools.jar -config consensus/GhostDAGConsensus.cfg consensus/GhostDAGConsensus.tla
```

## Prerequisites

- Java 11+ (for TLC model checker)
- TLA+ tools: `tla2tools.jar` (included in `specs/tla/` or download from [GitHub releases](https://github.com/tlaplus/tlaplus/releases))

## GUI Test Coverage

The Slint-native GUI (`gui/citrate_gui_native`) has integration tests covering:
- SALT/wei conversion roundtrips
- Account data mapping
- Balance formatting pipeline
- Background thread type safety (Send + Clone)
- AppCore Send + Sync compile proof

Run with: `cargo test -p citrate-gui-native`
