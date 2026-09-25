#!/usr/bin/env bash
# harvest_dpf_addresses.sh — collect deployed DefensePrime (DPF) contract
# addresses from the Foundry broadcast artifacts into the files the address
# book already carries: contracts/addresses/dpf-<chainId>.env and .json.
#
# Run AFTER the DeployDpf*.s.sol ceremonies broadcast. Reads every
# contracts/broadcast/DeployDpf*.s.sol/<chainId>/run-latest.json and keeps each
# CREATE / CREATE2 transaction's (contractName, contractAddress). Existing
# entries in dpf-<chainId>.json that no broadcast re-deployed are KEPT
# (non-lossy merge: a partial re-run never drops live addresses).
#
# Usage:
#   scripts/ops/harvest_dpf_addresses.sh            # chainId 40204
#   CHAIN_ID=31337 scripts/ops/harvest_dpf_addresses.sh
# Then: scripts/ops/emit-address-table.sh (canonical 40204.json).
set -euo pipefail

command -v jq >/dev/null || { echo "!! jq is required" >&2; exit 1; }
CHAIN_ID="${CHAIN_ID:-40204}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$(cd "$SCRIPT_DIR/../../contracts" && pwd)"
cd "$CONTRACTS_DIR"

OUT_DIR="addresses"
ENV_OUT="$OUT_DIR/dpf-${CHAIN_ID}.env"
JSON_OUT="$OUT_DIR/dpf-${CHAIN_ID}.json"
mkdir -p "$OUT_DIR"

shopt -s nullglob
runs=(broadcast/DeployDpf*.s.sol/"${CHAIN_ID}"/run-latest.json)
if [[ ${#runs[@]} -eq 0 ]]; then
  echo "!! no broadcast artifacts under broadcast/DeployDpf*.s.sol/${CHAIN_ID}/ — broadcast the DPF ceremonies first." >&2
  exit 1
fi

prev='{}'
[[ -f "$JSON_OUT" ]] && prev="$(cat "$JSON_OUT")"

fresh="$(jq -s '
  [ .[].transactions[]
    | select((.transactionType == "CREATE" or .transactionType == "CREATE2")
             and .contractName != null and .contractAddress != null)
    | {name: .contractName, addr: (.contractAddress | ascii_downcase)} ]
  | reduce .[] as $t ({}; .[$t.name] = $t.addr)
' "${runs[@]}")"

jq -n --argjson prev "$prev" --argjson fresh "$fresh" '$prev + $fresh' > "$JSON_OUT.tmp"
mv "$JSON_OUT.tmp" "$JSON_OUT"

echo "# DPF deployed addresses on chain ${CHAIN_ID} — harvested $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ENV_OUT"
jq -r 'to_entries[] | "export DPF_" + (.key | ascii_upcase) + "=" + .value' "$JSON_OUT" >> "$ENV_OUT"

echo ">>> $(jq 'length' <<<"$fresh") contracts from ${#runs[@]} ceremonies; book now has $(jq 'length' "$JSON_OUT") entries."
echo ">>> Wrote $ENV_OUT and $JSON_OUT. Next: scripts/ops/emit-address-table.sh"
