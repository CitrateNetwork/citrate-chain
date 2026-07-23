#!/usr/bin/env bash
# Fund the operational roles that are NOT pre-funded at genesis (I64-S1 WP-C1).
#
# The chain-40204 `testnet_beta` genesis preset (core/economics/src/genesis.rs)
# pre-funds the on-chain supply roles directly:
#
#     Treasury (= ecosystem fund)   500M SALT   genesis ✓
#     Reserve / legacy faucet        50M SALT   genesis ✓
#     Deployer                       10M SALT   genesis ✓   ← funding SOURCE here
#     Team / Dev                     10M SALT   genesis ✓
#     Validator                       5M SALT   genesis ✓
#     Faucet signer (derived)        10M SALT   genesis ✓
#     Arachnid CREATE2 deployer       0 (code)  genesis ✓
#
# But the OFF-chain operator EOAs that submit transactions on behalf of the
# services have NO genesis balance — after a re-roll their balance is zero and
# they cannot pay gas. This script tops each one up to a target float, paid from
# the genesis-funded deployer. It is the WP-C1 deliverable referenced by the
# re-roll runbook (§11) right after the deploy ceremonies and before the droplet
# restarts.
#
# Roles funded (target floats are testnet operating budgets, not economics):
#
#   Role                     env var (ADDRESS)              target   why it needs gas
#   ----                     ----------------               ------   ----------------
#   Bundler operator         CITRATE_AA_BUNDLER_OPERATOR_ADDR  100   submits batched ERC-4337 UserOps
#   Gateway operator signer  CITRATE_GATEWAY_OPERATOR_ADDRESS  100   inference settlement / pool dispatch txs
#   DGX compute provider     DGX_PROVIDER_ADDRESS               50   provider register + heartbeat txs
#   DGX compute provider v2  DGX_PROVIDER_V2_ADDRESS            50   second provider identity
#   Identity signer          CITRATE_AA_IDENTITY_SIGNER_ADDR    10   admin float (setIdentitySigner; permits are off-chain)
#   EIP-2771 relayer(s)      CITRATE_EDU_RELAYER_ADDRESS*       50   meta-tx relay gas (EduForwarder)  [optional]
#
#   * optional / forward-looking: there is no canonical relayer key in
#     .env.testnet today. If/when one exists, set CITRATE_EDU_RELAYER_ADDRESS
#     (and add more CITRATE_*_RELAYER_ADDRESS rows to RELAYER_VARS below) and
#     this script funds them too. Unset rows are reported and skipped, never
#     invented.
#
# Behaviour:
#   * IDEMPOTENT + top-up semantics: each role is funded to its target only if
#     its current balance is below target; the amount sent is (target - balance).
#     Re-running after a partial run, or after the roles already have gas, is a
#     no-op.
#   * DRY-RUN by default: prints the planned transfers and the role→amount→source
#     checklist, sends nothing. Pass `--broadcast` to actually `cast send`.
#   * A role whose ADDRESS env var is unset/empty is reported and SKIPPED (not an
#     error) — the operator decides whether that role is in scope this re-roll.
#   * NEVER prints private-key material. The deployer key is read from
#     .env.testnet and passed straight to `cast send`.
#
# Inputs (from /home/saul/Projects/Citrate-Labs/.env.testnet):
#   RPC_URL, DEPLOYER_ADDRESS, DEPLOYER_PRIVATE_KEY  — funding source
#   the role ADDRESS vars listed above
#
# Exit codes:
#   0  success (dry-run printed, or broadcast complete)
#   1  precondition failed (env file / RPC / deployer)
#   2  a broadcast transfer failed
set -euo pipefail

ENV_FILE="${ENV_FILE:-/home/saul/Projects/Citrate-Labs/.env.testnet}"
BROADCAST=0
[[ "${1:-}" == "--broadcast" ]] && BROADCAST=1

# GAP-2 fix: on the DGX box bare `python3` is a shim that rejects direct use and
# demands `uv run python3`; under `set -e` a bare `python3 -c` here kills the whole
# funding pass. Prefer uv when present so the big-int math works there and elsewhere.
if command -v uv >/dev/null 2>&1; then PY="uv run python3"; else PY=python3; fi

log()  { printf '%s\n' "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

command -v cast >/dev/null 2>&1 || die "foundry 'cast' not found on PATH"
[[ -f "$ENV_FILE" ]] || die "env file not found: $ENV_FILE"

# Read a single var's value from the env file WITHOUT sourcing the whole file
# (avoids importing every secret into this shell's environment). Strips a
# trailing CR and one layer of surrounding single/double quotes.
env_get() {
  local key="$1" val
  val="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-)"
  val="${val%$'\r'}"
  val="${val#\"}"; val="${val%\"}"
  val="${val#\'}"; val="${val%\'}"
  printf '%s' "$val"
}

RPC_URL="$(env_get RPC_URL)"
DEPLOYER_ADDRESS="$(env_get DEPLOYER_ADDRESS)"
[[ -n "$RPC_URL" ]] || die "RPC_URL not set in $ENV_FILE"
[[ -n "$DEPLOYER_ADDRESS" ]] || die "DEPLOYER_ADDRESS not set in $ENV_FILE"

# Precondition 1: chain reachable + correct id.
CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null)" || die "RPC unreachable at $RPC_URL"
[[ "$CHAIN_ID" == "40204" ]] || die "wrong chain id: got '$CHAIN_ID', expected 40204"
log "chain reachable — id $CHAIN_ID @ $RPC_URL"

# Precondition 2: deployer is funded (genesis gives it 10M SALT).
DEPLOYER_BAL_WEI="$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null)" || die "cannot read deployer balance"
DEPLOYER_BAL_SALT="$(cast to-unit "$DEPLOYER_BAL_WEI" ether 2>/dev/null || echo '?')"
log "deployer $DEPLOYER_ADDRESS balance: ${DEPLOYER_BAL_SALT} SALT"
[[ "$DEPLOYER_BAL_WEI" != "0" ]] || die "deployer has zero balance — did the re-roll genesis land? (expected 10M SALT)"

# Role table — name | address-env-var | target SALT | reason.
# (Bash 3-compatible parallel arrays; no associative arrays.)
ROLE_NAMES=(
  "Bundler operator"
  "Gateway operator signer"
  "DGX compute provider"
  "DGX compute provider v2"
  "Identity signer"
)
ROLE_VARS=(
  "CITRATE_AA_BUNDLER_OPERATOR_ADDR"
  "CITRATE_GATEWAY_OPERATOR_ADDRESS"
  "DGX_PROVIDER_ADDRESS"
  "DGX_PROVIDER_V2_ADDRESS"
  "CITRATE_AA_IDENTITY_SIGNER_ADDR"
)
ROLE_TARGETS=( 100 100 50 50 10 )
ROLE_WHY=(
  "submits batched ERC-4337 UserOps"
  "inference settlement / pool dispatch txs"
  "provider register + heartbeat txs"
  "second provider identity"
  "admin float (permits are off-chain)"
)

# Optional EIP-2771 relayer address vars — add more as they become canonical.
RELAYER_VARS=( "CITRATE_EDU_RELAYER_ADDRESS" )
RELAYER_TARGET=50

PLANNED_WEI_TOTAL=0
FUNDED=0 SKIPPED=0 NOOP=0 FAILED=0

# fund_one <display-name> <env-var> <target-salt> <why>
fund_one() {
  local name="$1" var="$2" target="$3" why="$4"
  local addr; addr="$(env_get "$var")"
  if [[ -z "$addr" ]]; then
    log "  SKIP  ${name} — \$${var} unset/empty"
    SKIPPED=$((SKIPPED+1))
    return 0
  fi
  local bal_wei target_wei
  bal_wei="$(cast balance "$addr" --rpc-url "$RPC_URL" 2>/dev/null)" || { log "  FAIL  ${name} — cannot read balance of $addr"; FAILED=$((FAILED+1)); return 0; }
  target_wei="$(cast to-wei "$target" ether)"
  # Top-up = max(0, target - balance). Done in python because wei exceeds the
  # 64-bit range bash arithmetic can hold.
  local need_wei
  need_wei="$($PY -c "b=int('$bal_wei'); t=int('$target_wei'); print(max(0, t-b))")"
  if [[ "$need_wei" == "0" ]]; then
    log "  NOOP  ${name} ($addr) already >= ${target} SALT"
    NOOP=$((NOOP+1))
    return 0
  fi
  local need_salt; need_salt="$(cast to-unit "$need_wei" ether 2>/dev/null || echo '?')"
  PLANNED_WEI_TOTAL="$($PY -c "print($PLANNED_WEI_TOTAL + $need_wei)")"
  if [[ "$BROADCAST" == "0" ]]; then
    log "  PLAN  ${name} ($addr)  +${need_salt} SALT  → target ${target}  [${why}]"
    return 0
  fi
  log "  SEND  ${name} ($addr)  +${need_salt} SALT ..."
  if cast send "$addr" \
        --value "${need_wei}wei" \
        --rpc-url "$RPC_URL" \
        --private-key "$(env_get DEPLOYER_PRIVATE_KEY)" \
        >/dev/null 2>&1; then
    log "  OK    ${name} funded to ${target} SALT"
    FUNDED=$((FUNDED+1))
  else
    log "  FAIL  ${name} — cast send failed"
    FAILED=$((FAILED+1))
  fi
}

log ""
log "=== I64-S1 WP-C1: fund operational roles (mode: $([[ $BROADCAST == 1 ]] && echo BROADCAST || echo DRY-RUN)) ==="
log "Source: deployer $DEPLOYER_ADDRESS"
log ""
log "Role → target → reason:"
for i in "${!ROLE_NAMES[@]}"; do
  fund_one "${ROLE_NAMES[$i]}" "${ROLE_VARS[$i]}" "${ROLE_TARGETS[$i]}" "${ROLE_WHY[$i]}"
done
for var in "${RELAYER_VARS[@]}"; do
  fund_one "EIP-2771 relayer ($var)" "$var" "$RELAYER_TARGET" "meta-tx relay gas (optional)"
done

PLANNED_SALT="$(cast to-unit "$PLANNED_WEI_TOTAL" ether 2>/dev/null || echo '?')"
log ""
log "Summary: funded=$FUNDED  noop=$NOOP  skipped=$SKIPPED  failed=$FAILED"
if [[ "$BROADCAST" == "0" ]]; then
  log "Planned total transfer: ${PLANNED_SALT} SALT (DRY-RUN — nothing sent)."
  log "Re-run with --broadcast to execute."
fi

[[ "$FAILED" == "0" ]] || exit 2
exit 0
