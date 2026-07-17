#!/usr/bin/env bash
# WS-5 / VALIDATOR-S1: derive the 4 DETERMINISTIC validator-staker keys from the
# deployer root. Idempotent + reproducible: the same DEPLOYER_PRIVATE_KEY always
# yields the same 4 staker addresses, which are the ones pre-funded in genesis
# (core/economics/src/genesis.rs::testnet_beta, VALIDATOR_STAKER_{1..4}_ADDRESS).
# The registration ceremony reads each staker private key from an env var; this
# script materializes them (or --print-only for addresses).
#
# Derivation:  key_i = keccak256( DEPLOYER_PRIVATE_KEY_bytes || utf8("citrate/validator-staker/{i}/v1") )
#   (identical mechanism to scripts/ops/derive-operator-keys.sh — the deployer key
#    is already the genesis root of trust, so this adds no new secret to back up.)
#
# Usage:  scripts/ops/derive-validator-stakers.sh [--print-only]
#   default        rewrites VALIDATOR_STAKER_{1..4}_{ADDRESS,PRIVATE_KEY} in .env.testnet
#                  (timestamped backup first)
#   --print-only   prints ONLY addresses, writes nothing
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="${CITRATE_ENV_FILE:-$(cd "${REPO_ROOT}/.." && pwd)/.env.testnet}"
PRINT_ONLY="${1:-}"

command -v cast >/dev/null || { echo "cast (foundry) not found" >&2; exit 1; }
[ -f "$ENV_FILE" ] || { echo ".env.testnet not found at $ENV_FILE" >&2; exit 1; }

DK="$(grep -m1 '^DEPLOYER_PRIVATE_KEY=' "$ENV_FILE" | cut -d= -f2)"
[ -n "$DK" ] || { echo "DEPLOYER_PRIVATE_KEY missing in $ENV_FILE" >&2; exit 1; }
DKH="${DK#0x}"

derive() { # $1=label -> "privkey address"
  local lh; lh="$(printf '%s' "$1" | xxd -p | tr -d '\n')"
  local pk; pk="$(cast keccak "0x${DKH}${lh}")"
  echo "$pk $(cast wallet address --private-key "$pk")"
}

declare -a PKS ADDRS
echo "deterministic validator-staker keys (from DEPLOYER_PRIVATE_KEY):"
for i in 1 2 3 4; do
  read -r PK ADDR < <(derive "citrate/validator-staker/${i}/v1")
  PKS[$i]="$PK"; ADDRS[$i]="$ADDR"
  echo "  VALIDATOR_STAKER_${i}_ADDRESS = ${ADDR}"
done

if [ "$PRINT_ONLY" = "--print-only" ]; then exit 0; fi

cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
PY=python3; command -v python3 >/dev/null || PY="uv run python3"
$PY - "$ENV_FILE" "${ADDRS[1]}" "${PKS[1]}" "${ADDRS[2]}" "${PKS[2]}" "${ADDRS[3]}" "${PKS[3]}" "${ADDRS[4]}" "${PKS[4]}" <<'PY'
import sys,re
p=sys.argv[1]; rest=sys.argv[2:]
s=open(p).read()
def setk(s,k,v): return re.sub(rf'(?m)^{k}=.*$',f'{k}={v}',s) if re.search(rf'(?m)^{k}=',s) else s+f'\n{k}={v}\n'
for i in range(4):
    addr=rest[2*i]; pk=rest[2*i+1]
    s=setk(s,f"VALIDATOR_STAKER_{i+1}_ADDRESS",addr)
    s=setk(s,f"VALIDATOR_STAKER_{i+1}_PRIVATE_KEY",pk)
open(p,"w").write(s); print("wrote 4 validator-staker keys to",p)
PY
