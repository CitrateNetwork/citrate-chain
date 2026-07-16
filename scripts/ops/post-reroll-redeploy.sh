#!/usr/bin/env bash
# Post-re-roll redeploy ceremony for the EW-S1 ERC-4337 v0.7 AA stack
# (WP-D of the post-re-roll bundle).
#
# Idempotent. Re-running against an already-redeployed chain produces the
# same set of addresses (Forge's deploy scripts are deterministic per
# deployer + nonce + bytecode), so the script can be re-invoked safely
# at any point.
#
# Inputs (read from `.env.testnet` at /home/saul/Projects/Citrate-Labs/):
#   - RPC_URL                                — JSON-RPC for the chain
#   - DEPLOYER_ADDRESS, DEPLOYER_PRIVATE_KEY — ceremony signer
#   - CITRATE_AA_ENTRY_POINT                 — EntryPoint v0.7 (must exist on-chain)
#   - CITRATE_AA_IDENTITY_SIGNER_ADDR        — factory permit signer
#
# Preconditions verified BEFORE the deploy fires:
#   1. The chain is reachable (cast chain-id).
#   2. The Arachnid CREATE2 deployer exists at
#      0x4e59b44847b379578588920cA78FbF26c0B4956C (proves WP-B landed).
#   3. The EntryPoint vendored at CITRATE_AA_ENTRY_POINT has code.
#   4. The deployer has enough SALT to cover the ceremony (>= 1 SALT).
#
# Outputs:
#   1. `forge script DeployAndPinAA --broadcast` — the six AA contracts
#      get deployed via the configured deployer.
#   2. The `CITRATE_AA_*` lines in `.env.testnet` are rewritten in place
#      from the forge script's `EW_S1_PIN:` stdout block. Existing
#      non-AA keys (TREASURY/DEPLOYER/FAUCET/TEAM/VALIDATOR, the
#      bundler operator mnemonic, anything else) are preserved
#      byte-for-byte.
#   3. A timestamped backup of `.env.testnet` is written to
#      `.env.testnet.bak.<timestamp>` so a botched rewrite is recoverable.
#
# Exit codes:
#   0 success
#   1 precondition failed
#   2 forge script failed
#   3 .env.testnet rewrite failed
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTRACTS_DIR="${REPO_ROOT}/contracts"
ENV_TESTNET="${ENV_TESTNET:-/home/saul/Projects/Citrate-Labs/.env.testnet}"

ARACHNID_ADDRESS="0x4e59b44847b379578588920cA78FbF26c0B4956C"

err() { echo "[post-reroll-redeploy] ERROR: $*" >&2; }
log() { echo "[post-reroll-redeploy] $*"; }

# --- precondition checks ---------------------------------------------

command -v forge >/dev/null || { err "forge is required (install via foundryup)"; exit 1; }
command -v cast  >/dev/null || { err "cast is required";  exit 1; }
command -v jq    >/dev/null || { err "jq is required";    exit 1; }

if [[ ! -f "$ENV_TESTNET" ]]; then
  err ".env.testnet not found at $ENV_TESTNET"
  err "  set ENV_TESTNET=/path/to/.env.testnet to override"
  exit 1
fi

get_env() {
  # Strip any inline comments/quotes; the keystore file may not be a
  # strict shell-source target (it has a decorative '=====' header) so
  # we read with grep + cut instead of `source`.
  grep -E "^${1}=" "$ENV_TESTNET" 2>/dev/null | head -1 | cut -d= -f2- | tr -d ' '
}

RPC_URL=$(get_env RPC_URL)
DEPLOYER_ADDRESS=$(get_env DEPLOYER_ADDRESS)
DEPLOYER_PRIVATE_KEY=$(get_env DEPLOYER_PRIVATE_KEY)
CITRATE_AA_ENTRY_POINT=$(get_env CITRATE_AA_ENTRY_POINT)
CITRATE_AA_IDENTITY_SIGNER_ADDR=$(get_env CITRATE_AA_IDENTITY_SIGNER_ADDR)

[[ -n "${RPC_URL:-}" ]]                         || { err "RPC_URL missing from $ENV_TESTNET"; exit 1; }
[[ -n "${DEPLOYER_ADDRESS:-}" ]]                || { err "DEPLOYER_ADDRESS missing";          exit 1; }
[[ -n "${DEPLOYER_PRIVATE_KEY:-}" ]]            || { err "DEPLOYER_PRIVATE_KEY missing";      exit 1; }
[[ -n "${CITRATE_AA_ENTRY_POINT:-}" ]]          || { err "CITRATE_AA_ENTRY_POINT missing";    exit 1; }
[[ -n "${CITRATE_AA_IDENTITY_SIGNER_ADDR:-}" ]] || { err "CITRATE_AA_IDENTITY_SIGNER_ADDR missing"; exit 1; }

# --- E-8: ensure the DETERMINISTIC operator keys exist BEFORE the AA deploy ---
# The E-8 CitratePaymaster constructor requires CITRATE_AA_SPONSOR_SIGNER; the
# deterministic derivation writes it (+ the grant/registrar keys). Without this,
# DeployAA reverts "sponsor signer not set". Idempotent — safe to re-run.
log "deriving deterministic operator keys (grant/sponsor/registrar)…"
CITRATE_ENV_FILE="$ENV_TESTNET" bash "${REPO_ROOT}/scripts/ops/derive-operator-keys.sh" || {
  err "derive-operator-keys.sh failed — CITRATE_AA_SPONSOR_SIGNER would be unset"; exit 1; }
CITRATE_AA_SPONSOR_SIGNER=$(get_env CITRATE_AA_SPONSOR_SIGNER)
export CITRATE_AA_SPONSOR_SIGNER
log "sponsor signer:    ${CITRATE_AA_SPONSOR_SIGNER}"
log ""
log "NOTE: after this AA redeploy, run scripts/ops/post-reroll-membership.sh to"
log "      redeploy the membership money path (contracts owned by the grant"
log "      signer, funding, treasury-signer). See handoffs/REROLL_MASTER_RUNBOOK.md."

log "rpc:               $RPC_URL"
log "deployer:          $DEPLOYER_ADDRESS"
log "entrypoint (env):  $CITRATE_AA_ENTRY_POINT"
log "identity signer:   $CITRATE_AA_IDENTITY_SIGNER_ADDR"

CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || true)
if [[ "$CHAIN_ID" != "40204" ]]; then
  err "chain-id is '$CHAIN_ID' (expected 40204) — wrong RPC?"
  exit 1
fi
log "chain-id:          $CHAIN_ID ✓"

# WP-B gate: the Arachnid CREATE2 deployer MUST exist at its canonical
# address. If it doesn't, the chain hasn't been re-rolled with the WP-B
# genesis allocation and the bundler will restart-loop after this
# redeploy completes. Fail-fast.
ARACHNID_CODE=$(cast code "$ARACHNID_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null || true)
if [[ -z "$ARACHNID_CODE" || "$ARACHNID_CODE" == "0x" ]]; then
  err "Arachnid CREATE2 deployer NOT present at $ARACHNID_ADDRESS"
  err "  Did the re-roll merge WP-B (CitrateNetwork/citrate-chain#36)?"
  err "  This script refuses to deploy without Arachnid — the bundler"
  err "  would restart-loop immediately after."
  exit 1
fi
log "arachnid deployer: present (${#ARACHNID_CODE} hex chars) ✓"

ENTRY_POINT_CODE=$(cast code "$CITRATE_AA_ENTRY_POINT" --rpc-url "$RPC_URL" 2>/dev/null || true)
if [[ -z "$ENTRY_POINT_CODE" || "$ENTRY_POINT_CODE" == "0x" ]]; then
  err "EntryPoint at $CITRATE_AA_ENTRY_POINT has NO code — vendor it first"
  err "  EntryPoint v0.7 is an eth-infinitism contract that must be deployed"
  err "  via its own ceremony before the AA stack can wire to it."
  exit 1
fi
log "entrypoint code:   present (${#ENTRY_POINT_CODE} hex chars) ✓"

DEPLOYER_BALANCE_WEI=$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null || echo 0)
ONE_ETHER_WEI="1000000000000000000"
if (( $(echo "$DEPLOYER_BALANCE_WEI < $ONE_ETHER_WEI" | bc -l) )); then
  err "deployer $DEPLOYER_ADDRESS has < 1 SALT ($DEPLOYER_BALANCE_WEI wei) — top it up first"
  exit 1
fi
log "deployer balance:  $DEPLOYER_BALANCE_WEI wei ✓"

# --- run the redeploy ------------------------------------------------

log "running forge script DeployAndPinAA…"
STDOUT_LOG=$(mktemp)
trap 'rm -f "$STDOUT_LOG"' EXIT

# Pass the env the script needs via shell exports. ScriptEnv reads
# CITRATE_AA_* via vm.envOr cheats.
export CITRATE_AA_ENTRY_POINT
export CITRATE_AA_IDENTITY_SIGNER="$CITRATE_AA_IDENTITY_SIGNER_ADDR"
export CITRATE_AA_OWNER="${CITRATE_AA_OWNER:-$DEPLOYER_ADDRESS}"

if ! (cd "$CONTRACTS_DIR" && forge script script/aa/DeployAndPinAA.s.sol \
  --rpc-url "$RPC_URL" \
  --private-key "$DEPLOYER_PRIVATE_KEY" \
  --sender "$DEPLOYER_ADDRESS" \
  --broadcast \
  2>&1 | tee "$STDOUT_LOG"); then
  err "forge script failed — see $STDOUT_LOG"
  exit 2
fi

# --- parse the EW_S1_PIN lines --------------------------------------

PIN_LINES=$(grep -E '^\s*EW_S1_PIN:\s+CITRATE_AA_[A-Z_]+=0x[0-9a-fA-F]{40}\s*$' "$STDOUT_LOG" || true)
if [[ -z "$PIN_LINES" ]]; then
  err "forge script ran but emitted no EW_S1_PIN lines — see $STDOUT_LOG"
  exit 2
fi
log "parsed pin lines:"
echo "$PIN_LINES" | sed 's/^/  /'

# --- rewrite .env.testnet ------------------------------------------

BACKUP="${ENV_TESTNET}.bak.$(date +%Y%m%d-%H%M%S)"
cp "$ENV_TESTNET" "$BACKUP"
log "backed up $ENV_TESTNET → $BACKUP"

TMP=$(mktemp)
cp "$ENV_TESTNET" "$TMP"

# For each EW_S1_PIN line, in-place replace any existing assignment for the
# same key. If the key doesn't exist yet, append it. Preserves comments,
# whitespace, and ordering for everything else.
update_in_place() {
  local key="$1" value="$2"
  if grep -qE "^${key}=" "$TMP"; then
    # In-place replace using a temp file (portable across BSD + GNU sed).
    awk -v k="$key" -v v="$value" '
      BEGIN { FS=OFS="=" }
      $1 == k { print k "=" v; next }
      { print }
    ' "$TMP" > "${TMP}.next" && mv "${TMP}.next" "$TMP"
  else
    printf '%s=%s\n' "$key" "$value" >> "$TMP"
  fi
}

while IFS= read -r line; do
  # Strip the EW_S1_PIN: prefix and surrounding whitespace.
  payload=$(echo "$line" | sed -E 's/^\s*EW_S1_PIN:\s+//; s/\s*$//')
  key="${payload%%=*}"
  value="${payload#*=}"
  update_in_place "$key" "$value"
done <<< "$PIN_LINES"

if ! mv "$TMP" "$ENV_TESTNET"; then
  err "failed to write $ENV_TESTNET — original preserved at $BACKUP"
  exit 3
fi

log ""
log "post-redeploy state of CITRATE_AA_* pins in $ENV_TESTNET (secrets redacted):"
grep -E '^CITRATE_AA_' "$ENV_TESTNET" | grep -vE '(_KEY|_MNEMONIC|_PRIVATE|_SECRET)=' | sed 's/^/  /'

log ""
log "✓ redeploy complete. Next steps:"
log "  1. ssh root@157.230.55.191  → nano /opt/citrate-identity/.env  → docker compose restart identity"
log "  2. ssh root@159.223.174.220 → nano /opt/citrate-bundler/.env   → docker compose down + up -d"
log "  3. Run citrate-bundler smoke (WP-E): bash ../citrate-bundler/scripts/smoke.sh"
