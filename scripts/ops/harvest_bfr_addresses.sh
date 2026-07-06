#!/usr/bin/env bash
# harvest_bfr_addresses.sh — collect deployed BFR contract addresses from the
# Foundry broadcast artifacts into a flat env file + a name→address JSON.
#
# Run AFTER deploy_bfr_40204.sh --broadcast. Reads every
# contracts/broadcast/DeployBfr*.s.sol/<chainId>/run-latest.json and extracts
# each CREATE transaction's (contractName, contractAddress).
#
# Outputs (under contracts/addresses/):
#   bfr-<chainId>.env   — `export BFR_<NAME>=0x...` lines (for WireBfrOperators
#                         + SeedBoeingState env repointing, and shell scripts)
#   bfr-<chainId>.json  — { "<ContractName>": "0x...", ... } (for boeing_binder
#                         + 40204.json patching)
#
# Usage:
#   scripts/ops/harvest_bfr_addresses.sh            # chainId 40204
#   CHAIN_ID=31337 scripts/ops/harvest_bfr_addresses.sh
set -euo pipefail

CHAIN_ID="${CHAIN_ID:-40204}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$(cd "$SCRIPT_DIR/../../contracts" && pwd)"
cd "$CONTRACTS_DIR"

OUT_DIR="addresses"
ENV_OUT="$OUT_DIR/bfr-${CHAIN_ID}.env"
JSON_OUT="$OUT_DIR/bfr-${CHAIN_ID}.json"
mkdir -p "$OUT_DIR"

shopt -s nullglob
runs=(broadcast/DeployBfr*.s.sol/"${CHAIN_ID}"/run-latest.json)
if [[ ${#runs[@]} -eq 0 ]]; then
  echo "!! no broadcast artifacts under broadcast/DeployBfr*.s.sol/${CHAIN_ID}/ — run deploy_bfr_40204.sh --broadcast first." >&2
  exit 1
fi

echo "# BFR deployed addresses on chain ${CHAIN_ID} — harvested $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ENV_OUT"

# Merge all CREATE txns across the run-latest files into one name→address map.
jq -s '
  [ .[].transactions[]
    | select(.transactionType == "CREATE" and .contractName != null and .contractAddress != null)
    | {name: .contractName, addr: (.contractAddress | ascii_downcase)} ]
  | reduce .[] as $t ({}; .[$t.name] = $t.addr)
' "${runs[@]}" > "$JSON_OUT"

# Emit env lines: BFR_TENANTHIERARCHY=0x...
jq -r 'to_entries[] | "export BFR_" + (.key | ascii_upcase) + "=" + .value' "$JSON_OUT" >> "$ENV_OUT"

echo ">>> Harvested $(jq 'length' "$JSON_OUT") contracts across ${#runs[@]} ceremonies:"
jq -r 'to_entries[] | "    " + .key + " = " + .value' "$JSON_OUT"
echo ">>> Wrote $ENV_OUT and $JSON_OUT"
echo ">>> Next: repoint WireBfrOperators + SeedBoeingState (source $ENV_OUT), then patch 40204.json + boeing_binder.rs from $JSON_OUT."
