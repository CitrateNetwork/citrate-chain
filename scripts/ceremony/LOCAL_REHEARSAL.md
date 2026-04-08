---
created: 2026-04-07T17:50:00Z
branch: benchmark-rehearsal
author: Codex (OpenAI, GPT-5)
status: active
scope: Disposable local rehearsal for the ceremony runner
---

# Local Rehearsal

## Purpose

This document describes the safe local practice path for the ceremony runner.

It is explicitly a `devnet rehearsal`, not the real `40204` shared testnet.

Use it to verify:

- the ceremony script runs end to end
- Forge keystore account flow works
- contract deployment and address cataloging work
- proof bundle generation works

Do **not** use the addresses or proof artifacts from this rehearsal as canonical testnet truth.

## Rehearsal Profile

- Local RPC: `http://127.0.0.1:18545`
- Local rehearsal chain ID: `40205`
- Mode: `CEREMONY_MODE=rehearsal`
- Foundry home: temporary directory under `/tmp`
- Deployer key: fresh encrypted Foundry keystore account created only for rehearsal

`40205` is intentional. It keeps local rehearsal separated from the real `40204` testnet while staying close enough to the expected transaction environment.

## Procedure

### 1. Create temporary rehearsal workspace

```bash
tmpdir=$(mktemp -d /tmp/citrate-ceremony-rehearsal.XXXXXX)
mkdir -p "$tmpdir/home/.foundry/keystores"
```

### 2. Create a rehearsal deployer account

```bash
CAST_PASSWORD='choose-a-rehearsal-passphrase' \
  cast wallet new --json "$tmpdir/home/.foundry/keystores" rehearsal-deployer \
  > "$tmpdir/deployer.json"
```

Extract the deployer address:

```bash
deployer=$(jq -r '.[0].address' "$tmpdir/deployer.json")
```

### 3. Start a disposable local chain

```bash
anvil \
  --port 18545 \
  --host 127.0.0.1 \
  --chain-id 40205 \
  --config-out "$tmpdir/anvil-config.json" \
  --dump-state "$tmpdir/state"
```

### 4. Fund the rehearsal deployer

Use the first Anvil account only for local rehearsal funding:

```bash
funder_pk=$(jq -r '.private_keys[0]' "$tmpdir/anvil-config.json")
cast send "$deployer" \
  --value 50ether \
  --rpc-url http://127.0.0.1:18545 \
  --private-key "$funder_pk"
```

### 5. Set rehearsal-only addresses

These are placeholders for local practice only:

```bash
signer1=$(jq -r '.available_accounts[1]' "$tmpdir/anvil-config.json")
signer2=$(jq -r '.available_accounts[2]' "$tmpdir/anvil-config.json")
signer3=$(jq -r '.available_accounts[3]' "$tmpdir/anvil-config.json")
relayer=$(jq -r '.available_accounts[4]' "$tmpdir/anvil-config.json")
governance=$(jq -r '.available_accounts[5]' "$tmpdir/anvil-config.json")
```

### 6. Export the rehearsal environment

```bash
export HOME="$tmpdir/home"
export CEREMONY_MODE=rehearsal
export CEREMONY_CHAIN_ID=40205
export CEREMONY_RPC_URL=http://127.0.0.1:18545
export CEREMONY_DEPLOYER_ACCOUNT=rehearsal-deployer
export CEREMONY_DEPLOYER_ADDRESS="$deployer"
export SIGNER_1="$signer1"
export SIGNER_2="$signer2"
export SIGNER_3="$signer3"
export RELAYER="$relayer"
export GOVERNANCE="$governance"
export CEREMONY_OUTPUT_DIR="$tmpdir/ceremony-output"
```

### 7. Run the ceremony

```bash
./citrate_v0.01.1/scripts/ceremony/ceremony.sh
```

## What Success Looks Like

The rehearsal is successful when all of the following are true:

- `20_deployment_txs.jsonl` is written
- `30_address_table.json` exists and shows `36` contracts if `ModelAccessControl` is included
- `40_code_verification.log` reports `0` failures
- `60_proof_bundle.tar.gz` exists
- `99_signatures.txt` is generated

The benchmark may still reveal harness defects. In rehearsal mode that is evidence to investigate, not a reason to confuse the local chain with the real testnet.

## What This Rehearsal Proves

- ceremony runner wiring
- keystore account flow
- contract deployment scope
- address table generation
- bytecode verification
- proof bundle generation

## What This Rehearsal Does Not Prove

- real `40204` testnet stability
- real operator-owned governance addresses
- production DNS / bootnode / RPC topology
- benchmark correctness for signed testnet transactions

## Follow-On

After a clean local rehearsal:

1. run two disposable infra rehearsals per `CEREMONY_CHECKLIST.md`
2. execute the real `40204` ceremony only after those rehearsals are clean

## Clean-Slate Reroll

**When to use**: you ran a rehearsal against a local (non-`anvil`)
`citrate-node`, it produced deploy state under `.citrate-testnet-beta/`,
and you want to start fresh without hand-killing processes and
`rm -rf`'ing directories on the fly. This is exactly the situation
that bit the 2026-04-08 dry run: stale contract state caused
`CreateCollision` on the first DeployAll run.

Run the reroll script, then re-run the ceremony:

```bash
./citrate_v0.01.1/scripts/ceremony/ceremony-reroll.sh --reroll
./citrate_v0.01.1/scripts/ceremony/ceremony.sh
```

The reroll script is safe and reversible:

- It will **not** run without explicit opt-in (`--reroll` flag or
  `CEREMONY_REROLL=1` env var).
- It will **not** run in `CEREMONY_MODE=real` unless you ALSO set
  `CEREMONY_REROLL_REAL=1` — a two-key confirmation for destructive
  real-mode operations.
- It moves the data directory to a timestamped backup via `mv`; it
  does **not** `rm -rf`. The archive path is printed along with the
  exact command to recover it.
- It clears `contracts/broadcast/` and `contracts/cache/` because
  forge will otherwise happily re-use stale deployment records and
  compiler caches.

Override knobs (env vars, all optional):

| Variable | Default | Purpose |
|----------|---------|---------|
| `CEREMONY_DATA_DIR` | `.citrate-testnet-beta` | Node data dir to archive. |
| `CEREMONY_RPC_PORT` | `8545` | Port to probe for a running listener. |
| `CEREMONY_MODE` | `rehearsal` | Set to `real` + `CEREMONY_REROLL_REAL=1` for real-mode reroll. |
| `CITRATE_REPO_ROOT` | (script's grandparent) | Workspace root override — used by the integration test, not needed in normal operation. |

### Integration test

`scripts/ceremony/tests/test_ceremony_reroll.sh` exercises every
acceptance criterion in backlog #111 against a hand-built fake
workspace under `/tmp` so it never touches the real repo. Run it
any time `ceremony-reroll.sh` is modified:

```bash
./citrate_v0.01.1/scripts/ceremony/tests/test_ceremony_reroll.sh
```

Expected: `ALL TESTS PASSED` and exit code 0. Fails loudly with
per-assertion diagnostics otherwise.
3. rebuild the benchmark harness against the frozen testnet truth rather than the old devnet assumptions
