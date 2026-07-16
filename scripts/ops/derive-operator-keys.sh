#!/usr/bin/env bash
# Derive the DETERMINISTIC operator keys from the deployer root and write them
# into .env.testnet. Idempotent + reproducible: the same DEPLOYER_PRIVATE_KEY
# always yields the same operator addresses, so a re-roll on ANY box reproduces
# the exact treasury/sponsor/registrar addresses WITHOUT depending on an ad-hoc
# copy of previously-minted random keys.
#
# Derivation:  key = keccak256( DEPLOYER_PRIVATE_KEY_bytes || utf8(label) )
#   citrate/treasury-grant-signer/v1  -> GRANT_SIGNER_*        (owns MembershipStakeVault + CitrateMemberSBT; runs in the droplet treasury-signer)
#   citrate/aa-sponsor-signer/v1      -> AA_SPONSOR_SIGNER_*   (CitratePaymaster sponsorSigner; also CITRATE_AA_SPONSOR_SIGNER pin)
#   citrate/aa-registrar/v1           -> AA_REGISTRAR_*        (legacy EOA registrar; the E-8 factory self-registers, kept for completeness)
#
# The deployer key is already the genesis root of trust (10M SALT, deploys
# everything), so deriving operator keys from it adds no new secret to back up
# and grants no capability that the deployer didn't already have.
#
# Usage:  scripts/ops/derive-operator-keys.sh [--print-only]
#   default        rewrites the operator keys in .env.testnet (timestamped backup first)
#   --print-only   prints addresses, writes nothing
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

read -r GPK GADDR < <(derive "citrate/treasury-grant-signer/v1")
read -r SPK SADDR < <(derive "citrate/aa-sponsor-signer/v1")
read -r RPK RADDR < <(derive "citrate/aa-registrar/v1")

echo "deterministic operator keys (from DEPLOYER_PRIVATE_KEY):"
echo "  GRANT_SIGNER_ADDRESS       = $GADDR"
echo "  AA_SPONSOR_SIGNER_ADDRESS  = $SADDR"
echo "  AA_REGISTRAR_ADDRESS       = $RADDR"

if [ "$PRINT_ONLY" = "--print-only" ]; then exit 0; fi

cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
PY=python3; command -v python3 >/dev/null || PY="uv run python3"
$PY - "$ENV_FILE" "$GPK" "$GADDR" "$SPK" "$SADDR" "$RPK" "$RADDR" <<'PY'
import sys,re
p,gpk,gaddr,spk,saddr,rpk,raddr=sys.argv[1:8]
s=open(p).read()
def setk(s,k,v): return re.sub(rf'(?m)^{k}=.*$',f'{k}={v}',s) if re.search(rf'(?m)^{k}=',s) else s+f'\n{k}={v}\n'
for k,v in [("GRANT_SIGNER_ADDRESS",gaddr),("GRANT_SIGNER_PRIVATE_KEY",gpk),
            ("AA_SPONSOR_SIGNER_ADDRESS",saddr),("AA_SPONSOR_SIGNER_PRIVATE_KEY",spk),
            ("AA_REGISTRAR_ADDRESS",raddr),("AA_REGISTRAR_PRIVATE_KEY",rpk),
            ("CITRATE_AA_SPONSOR_SIGNER",saddr)]:
    s=setk(s,k,v)
open(p,"w").write(s); print("wrote deterministic operator keys to",p)
PY
