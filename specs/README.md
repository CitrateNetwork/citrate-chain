# Formal Verification Specs

## Canonical Location

The public TLA+ specifications for this repository live in **`specs/tla/`** (71 `.tla` files across the consensus, zk, learning, contracts, compute, gui and network domains). Count them yourself with `find specs/tla -name '*.tla' | wc -l`.

Some older specs (including `TransactionSigningFlow.tla`) live only in a private internal archive and are not reproducible from this repository. The federation-wide public count and its counting rule are recorded in [`verification/claims.json`](../verification/claims.json) (`tla_specs`).

Local run results: `specs/tla/VERIFICATION_REPORT.txt`.

A spec that model-checks is evidence about the model, not proof that the code runs the mechanism. For example, `consensus/CheckpointVoteSafety.tla` checks checkpoint voting, which is specified but not running on the testnet (see `deterministic_checkpoint_finality` in `claims.json`).

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
