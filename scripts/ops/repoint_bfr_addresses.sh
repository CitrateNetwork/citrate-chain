#!/usr/bin/env bash
# repoint_bfr_addresses.sh — after a chain re-roll + redeploy, rewrite every
# hardcoded BFR address across the scripts, the Rust binder, and the msig test
# from the OLD deploy to the NEW one.
#
# Strategy: pair OLD[name] -> NEW[name] by contract name, then two find-replace
# passes across all target files:
#   1. lowercase(old) -> lowercase(new)   (Rust binder + its regression test)
#   2. checksummed(old) -> checksummed(new) (Solidity .sol + msig.rs test)
# Distinct string forms, so the passes don't collide and together cover both
# casings. Contracts absent from either table (unmapped placeholders) are left
# untouched.
#
# Run AFTER harvest_bfr_addresses.sh has written the NEW bfr-<chain>.json and a
# copy of the previous table exists as bfr-<chain>.old.json.
#
# Usage:  scripts/ops/repoint_bfr_addresses.sh   [CHAIN_ID=40204]
set -euo pipefail

CHAIN_ID="${CHAIN_ID:-40204}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAIN_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LABS_ROOT="$(cd "$CHAIN_ROOT/.." && pwd)"
ADDR_DIR="$CHAIN_ROOT/contracts/addresses"
OLD="$ADDR_DIR/bfr-${CHAIN_ID}.old.json"
NEW="$ADDR_DIR/bfr-${CHAIN_ID}.json"

[[ -f "$OLD" && -f "$NEW" ]] || { echo "need $OLD and $NEW" >&2; exit 1; }

# Target files that hardcode BFR addresses.
FILES=(
  "$CHAIN_ROOT/contracts/script/WireBfrOperators.s.sol"
  "$CHAIN_ROOT/contracts/script/SeedBoeingState.s.sol"
  "$CHAIN_ROOT/contracts/script/SimulateActivity.s.sol"
  "$CHAIN_ROOT/contracts/script/ProvisionWithMultisig.s.sol"
  "$LABS_ROOT/citrate-boeing-shell/gui/citrate_boeing_shell/src/boeing_binder.rs"
  "$LABS_ROOT/citrate-boeing-shell/gui/citrate_boeing_shell/src/msig.rs"
)

count=0
# Iterate contracts present in BOTH tables.
for name in $(jq -r 'keys[]' "$NEW"); do
  old_addr=$(jq -r --arg k "$name" '.[$k] // empty' "$OLD")
  new_addr=$(jq -r --arg k "$name" '.[$k] // empty' "$NEW")
  [[ -z "$old_addr" || -z "$new_addr" || "$old_addr" == "$new_addr" ]] && continue
  # harvest_bfr_addresses.sh stores lowercase, so the json values are already lc.
  old_lc="$old_addr"; new_lc="$new_addr"
  old_cs="$(cast to-check-sum-address "$old_addr")"
  new_cs="$(cast to-check-sum-address "$new_addr")"
  for f in "${FILES[@]}"; do
    [[ -f "$f" ]] || continue
    perl -pi -e "s/\Q${old_lc}\E/${new_lc}/g; s/\Q${old_cs}\E/${new_cs}/g" "$f"
  done
  count=$((count + 1))
done

echo ">>> repointed $count contracts across ${#FILES[@]} files."
echo ">>> next: forge build; run WireBfrOperators + SeedBoeingState; rebuild the shell; re-run msig test."
