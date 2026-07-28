#!/usr/bin/env bash
# post-reroll-quorum-restore.sh — put the RBAC + citrate-quorum contract set back
# after a chain wipe, in one command.
#
# Written after doing it by hand twice (2026-07-27, twice in one day). Every
# gotcha below cost real time on one of those runs; they are encoded here so the
# third wipe is a single command rather than twenty.
#
# ── The gotchas this script exists to encode ─────────────────────────────────
#
#   1. Chain 40204 REJECTS EIP-1559. Every send needs --legacy or it comes back
#      as a bare "contract was not deployed".
#
#   2. `forge create` DOES NOT WORK on this chain. It reports "contract was not
#      deployed" — in one observed case while still consuming a nonce, leaving a
#      mined transaction with no code. `forge script` is reliable (37/37 deploys
#      across two rerolls). `cast send --legacy --create` also works. Do not
#      reach for `forge create`.
#
#   3. `source .env.testnet` SILENTLY yields empty values for some vars. A send
#      with an empty --private-key fails with "Failed to decode private key",
#      which is easy to miss if you are grepping output for lowercase "error".
#      This script extracts values with grep instead, and verifies the key
#      derives the expected deployer before spending anything.
#
#   4. DeployBfr08..17 require DEPLOYER_ADDRESS / CEREMONY_DEPLOYER_ADDRESS in
#      the environment. deploy_bfr_40204.sh neither sets nor documents them.
#
#   5. A STALE ADDRESS BOOK IS MORE DANGEROUS AFTER A REDEPLOY THAN BEFORE IT.
#      CREATE addresses are deployer-nonce-derived, so a fresh deployment walks
#      over the same address space and reassigns those addresses to DIFFERENT
#      contracts. Before: consumers hit empty addresses and fail closed. After:
#      they hit live code of the wrong type. That is why this script re-pins the
#      books in the same run, and refuses to declare success until every entry
#      has been re-verified to have code.
#
# SAFETY: dry-run by default. Nothing is sent without --broadcast.
#
# Usage:
#   scripts/ops/post-reroll-quorum-restore.sh              # plan only
#   scripts/ops/post-reroll-quorum-restore.sh --broadcast  # do it
#
# Env:
#   RPC_URL          default https://rpc.citrate.ai
#   ENV_FILE         default ../.env.testnet (relative to the repo)
#   ROOT_GOVERNANCE  default from ROOT_GOVERNANCE_ADDRESS in ENV_FILE
#   SIGNER_FUNDING   default 50 (CIT per ecosystem signer)
set -euo pipefail

RPC_URL="${RPC_URL:-https://rpc.citrate.ai}"
BROADCAST=0
[[ "${1:-}" == "--broadcast" ]] && BROADCAST=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONTRACTS="$ROOT_DIR/contracts"
ENV_FILE="${ENV_FILE:-$(cd "$ROOT_DIR/.." && pwd)/.env.testnet}"
SIGNER_FUNDING="${SIGNER_FUNDING:-50}"

say() { printf '\n\033[1m>>> %s\033[0m\n' "$*"; }

[ -f "$ENV_FILE" ] || { echo "no env file at $ENV_FILE" >&2; exit 2; }

# Gotcha 3: extract, never source.
getenv() { grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r"'"'"''; }

DEPLOY_KEY="$(getenv DEPLOYER_PRIVATE_KEY)"
DEPLOYER_ADDRESS="$(getenv DEPLOYER_ADDRESS)"
ROOT_GOVERNANCE="${ROOT_GOVERNANCE:-$(getenv ROOT_GOVERNANCE_ADDRESS)}"

[ -n "$DEPLOY_KEY" ] || { echo "DEPLOYER_PRIVATE_KEY not readable from $ENV_FILE" >&2; exit 2; }

# Prove the key is the deployer the book expects BEFORE spending anything.
# Gotcha 6: NEVER put a key on a command line. `--private-key 0x...` is visible
# in `ps aux` to every user on the box. forge and cast both read
# ETH_PRIVATE_KEY from the environment, which is only readable via
# /proc/<pid>/environ by the same user or root. This was found the hard way:
# a hung `forge script` left the deployer key sitting in the process table.
# forge script does NOT read ETH_PRIVATE_KEY — it silently falls back to
# Foundry's default sender and "deploys" to simulation addresses. The only way
# to broadcast without putting the key on argv is a keystore account.
KEYSTORE_ACCOUNT="${KEYSTORE_ACCOUNT:-citrate-deployer-40204}"
PW_FILE="$(mktemp)"; chmod 600 "$PW_FILE"
printf '%s' "$(getenv CAST_PASSWORD)" > "$PW_FILE"
trap 'rm -f "$PW_FILE"' EXIT
WALLET=(--account "$KEYSTORE_ACCOUNT" --password-file "$PW_FILE")

DERIVED="$(cast wallet address "${WALLET[@]}")"
if [ "${DERIVED,,}" != "${DEPLOYER_ADDRESS,,}" ]; then
  echo "key derives $DERIVED but DEPLOYER_ADDRESS is $DEPLOYER_ADDRESS — refusing" >&2
  exit 2
fi

# The three ecosystem signers = the tenant-root admin set. Kept in one place;
# init-tenant-root.sh holds the same list and is the authority for the ceremony.
SIGNERS=(
  0xF4FE9B2c6441Ff7c081B60716a78193127919783
  0x269deEe81cb8Eb5899b2D17945b951608E41774B
  0x671F3F4f9cBb0509a28eE4fa0b416daBBc9375C5
)

has_code() { [ "$(cast code "$1" --rpc-url "$RPC_URL" 2>/dev/null | wc -c)" -gt 3 ]; }
book_addr() { uv run python3 -c "
import json,sys
try: print(json.load(open('$1')).get('$2') or json.load(open('$1'))['contracts']['$2'])
except Exception: print('')
" 2>/dev/null; }

say "chain $(cast chain-id --rpc-url "$RPC_URL") @ block $(cast block-number --rpc-url "$RPC_URL")"
echo "deployer   $DEPLOYER_ADDRESS  ($(cast from-wei "$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL")") CIT)"
echo "governance $ROOT_GOVERNANCE"

if [ "$BROADCAST" -ne 1 ]; then
  say "DRY RUN — would perform:"
  cat <<PLAN
  1. fund ${#SIGNERS[@]} ecosystem signers to ${SIGNER_FUNDING} CIT each (skipped if already funded)
  2. deploy the 14 DeployBfr*.s.sol ceremonies (skipped if TenantHierarchy has code)
  3. harvest addresses/bfr-40204.json from the broadcast artifacts
  4. seed the tenant root (init-tenant-root.sh refuses if already seeded)
  5. deploy the quorum set + AnchorRegistry + MeetingRegistry
  6. patch addresses/40204.json
  7. verify EVERY entry in both books has code, and fail if any does not
PLAN
  echo
  echo "re-run with --broadcast to execute"
  exit 0
fi

# ── 1. signers ───────────────────────────────────────────────────────────────
say "1/7 funding ecosystem signers"
for a in "${SIGNERS[@]}"; do
  bal_wei="$(cast balance "$a" --rpc-url "$RPC_URL")"
  if [ "$bal_wei" != "0" ]; then
    echo "  $a already at $(cast from-wei "$bal_wei") CIT — skipping"
    continue
  fi
  # The RPC 502s intermittently; retry rather than half-fund the set.
  for try in 1 2 3; do
    if cast send "$a" --value "${SIGNER_FUNDING}ether" --legacy \
        "${WALLET[@]}" --rpc-url "$RPC_URL" >/dev/null 2>&1; then
      echo "  $a funded ${SIGNER_FUNDING} CIT"; break
    fi
    echo "  $a attempt $try failed, retrying"; sleep 4
  done
done

# ── 2. RBAC ──────────────────────────────────────────────────────────────────
cd "$CONTRACTS"
export ROOT_GOVERNANCE DEPLOYER_ADDRESS
export CEREMONY_DEPLOYER_ADDRESS="$DEPLOYER_ADDRESS"   # gotcha 4

TH_BOOKED="$(book_addr "$CONTRACTS/addresses/bfr-40204.json" TenantHierarchy)"
if [ -n "$TH_BOOKED" ] && has_code "$TH_BOOKED"; then
  say "2/7 RBAC already live at $TH_BOOKED — skipping the 14 ceremonies"
else
  say "2/7 deploying the 14 BFR ceremonies"
  for s in DeployBfr02Rbac DeployBfr05Provenance DeployBfr06Suppliers DeployBfr07FL \
           DeployBfr08Refresh DeployBfr09AppsContracts DeployBfr10Assistant \
           DeployBfr11Governance DeployBfr12Ontology DeployBfr13Procurement \
           DeployBfr14InterOrg DeployBfr15Compliance DeployBfr16Sponsor DeployBfr17Release; do
    printf '  %-26s ' "$s"
    if forge script "script/$s.s.sol" --rpc-url "$RPC_URL" --broadcast --legacy \
         "${WALLET[@]}" >/dev/null 2>&1; then echo ok; else echo FAILED; fi
  done
  say "3/7 harvesting the bfr book"
  bash "$ROOT_DIR/scripts/ops/harvest_bfr_addresses.sh" >/dev/null
fi

# ── 4. tenant root ───────────────────────────────────────────────────────────
say "4/7 seeding the tenant root"
DEPLOY_KEY="$DEPLOY_KEY" bash "$ROOT_DIR/scripts/ops/init-tenant-root.sh" --broadcast 2>&1 \
  | grep -viE "private-key|0x[0-9a-f]{64}" | tail -4 || echo "  (already seeded, or refused — see above)"

# ── 5. quorum set ────────────────────────────────────────────────────────────
say "5/7 deploying the quorum governance set"
TENANT_HIERARCHY="$(book_addr "$CONTRACTS/addresses/bfr-40204.json" TenantHierarchy)"
has_code "$TENANT_HIERARCHY" || { echo "TenantHierarchy has no code — refusing to bind contracts to it" >&2; exit 1; }
export TENANT_HIERARCHY
OUT="$(forge script script/DeployQuorumS6.s.sol --rpc-url "$RPC_URL" --broadcast --legacy "${WALLET[@]}" 2>&1)"
echo "$OUT" | grep -iE "deployed at" | sed 's/^/  /'
echo "$OUT" | grep -qi "ONCHAIN EXECUTION COMPLETE" || { echo "quorum deploy failed" >&2; exit 1; }

# ── 6. book ──────────────────────────────────────────────────────────────────
say "6/7 patching addresses/40204.json"
echo "$OUT" | grep -iE "deployed at" \
  | sed -E 's/^ *([A-Za-z]+) deployed at: (0x[0-9a-fA-F]{40}).*/\1 \2/' > /tmp/quorum-deployed.txt
uv run python3 - <<'PY'
import json, collections
p='addresses/40204.json'
d=json.load(open(p), object_pairs_hook=collections.OrderedDict)
n=0
for line in open('/tmp/quorum-deployed.txt'):
    parts=line.split()
    if len(parts)==2:
        d['contracts'][parts[0]]=parts[1].lower(); n+=1
json.dump(d, open(p,'w'), indent=2, ensure_ascii=False); open(p,'a').write("\n")
print(f"  patched {n} entries; {len(d['contracts'])} total")
PY

# ── 7. verify ────────────────────────────────────────────────────────────────
say "7/7 verifying every booked address has code"
FAIL=0
for book in addresses/40204.json addresses/bfr-40204.json; do
  while read -r name addr; do
    has_code "$addr" || { echo "  EMPTY  $book  $name  $addr"; FAIL=1; }
  done < <(uv run python3 -c "
import json,sys
d=json.load(open('$book')); d=d.get('contracts',d)
[print(k,v) for k,v in d.items() if isinstance(v,str) and v.startswith('0x')]")
done
[ "$FAIL" -eq 0 ] && echo "  all booked addresses have code" || { echo "VERIFICATION FAILED" >&2; exit 1; }

say "done — next: cd ../citrate-quorum && bash scripts/sync-addresses.sh"
