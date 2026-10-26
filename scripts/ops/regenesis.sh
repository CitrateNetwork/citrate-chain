#!/usr/bin/env bash
# ============================================================================
# regenesis.sh — ordered CREATE2 redeploy of the chain-40204 contract stack.
# ============================================================================
#
# Runs every deterministic-deploy ceremony step in dependency order against a
# freshly re-rolled chain, then regenerates the canonical address table and
# checks CREATE2 determinism. Referenced by scripts/ceremony/I64S1_REROLL_RUNBOOK.md.
#
# FRESH-KEYS REROLL (owner ruling + MAC audit citrate-security): pass `--reroll`
# to deploy the WHOLE stack fresh with brand-new keys. This:
#   * exports CITRATE_REROLL=1 so DeployAll deploys the three otherwise
#     "kept-live" registries (AgentDecisionRegistry / SpecRegistry /
#     MarketMakerAllocation) FRESH (multisig-governed) instead of resolving
#     to a legacy 40204 pin whose code does not exist on the re-rolled chain
#     (which would revert). See contracts/script/DeployAll.s.sol:_keptLive.
#   * derives EVERY key/book address from env at deploy time — no hardcodes.
#     The fresh keys are supplied via the env block below (VALIDATOR_GOVERNANCE,
#     GOVERNANCE, GUARDIAN, MEMBERSHIP_OWNER, CITRATE_AA_*). chainId stays 40204.
#   * accepts that ~57 addresses MOVE (they are re-derived + re-fanned; see
#     scripts/ceremony/REROLL_FANOUT.md).
#
# The ValidatorRegistry address is captured from its broadcast and exported as
# VALIDATOR_REGISTRY so the membership step derives (never hardcodes) it.
#
# MEMBERSHIP: by default the last step is DeployCoreMembership (the r1005 path the reroll
# runbooks use). `--genesis-membership` (the G5 genesis ceremony, scripts/genesis/
# genesis_ceremony.sh P2) runs DeployGenesisMembership instead (chain#331, Track M: the vault's
# upgrade authority is the GOVERNANCE timelock, the grant signer holds only the grant role). It
# needs GOVERNANCE_TIMELOCK, GOVERNANCE_MULTISIG, MEMBERSHIP_GRANTOR and GENESIS_MEMBERSHIP_OUT
# (GENESIS_GOVERNANCE_BOOK is passed through when set), refuses to start without them, and tells
# the address-book generator which broadcast holds the membership (EMIT_MEMBERSHIP_SCRIPT).
#
# Usage:
#   RPC_URL=http://localhost:8545 DEPLOYER_ADDRESS=0x.. \
#     bash scripts/ops/regenesis.sh --reroll --with-aa --broadcast --account deployer
#
# Flags:
#   --reroll        fresh-keys reroll mode (CITRATE_REROLL=1)
#   --genesis-membership  deploy membership with DeployGenesisMembership (chain#331), not
#                   DeployCoreMembership (see MEMBERSHIP above)
#   --with-aa       also run the ERC-4337 AA stack (DeployAA) + P256 verifier
#   --broadcast     actually send txs (omit = simulate only; safe dry-run)
#   --account NAME  forge keystore account to sign with (passed through)
#   --password-file PATH  the keystore password file for --account (passed through to
#                   every forge step as a path; this script never reads or prints it).
#                   A password on the command line (--password) is refused.
#   --private-key K forge private key to sign with (passed through; devnet only)
#
# DEVNET SAFETY: without --broadcast nothing is sent. A broadcast to a non-local
# RPC requires CITRATE_ALLOW_REMOTE=1 (a two-key confirmation for a live reroll).
#
# Exit codes: 0 ok · 1 precondition/arg failure · 2 a ceremony step failed
# ============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTRACTS="${REPO_ROOT}/contracts"
CHAIN_ID=40204

log()  { echo "[regenesis] $*"; }
err()  { echo "[regenesis] ERROR: $*" >&2; }
die()  { err "$*"; exit 1; }

REROLL=0
WITH_AA=0
GENESIS_MEMBERSHIP=0
BROADCAST=0
SIGNER_ARGS=()
ACCOUNT_SET=0
PASSWORD_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reroll)      REROLL=1; shift ;;
    --with-aa)     WITH_AA=1; shift ;;
    --genesis-membership) GENESIS_MEMBERSHIP=1; shift ;;
    --broadcast)   BROADCAST=1; shift ;;
    --account)     SIGNER_ARGS+=(--account "$2"); ACCOUNT_SET=1; shift 2 ;;
    --password-file) PASSWORD_FILE="${2:-}"; shift 2 ;;
    # Never echo the value: it is the password.
    --password | --password=*) die "a keystore password on the command line is refused; pass --password-file PATH" ;;
    --private-key) SIGNER_ARGS+=(--private-key "$2"); shift 2 ;;
    *) die "unknown arg: $1" ;;
  esac
done
# The password file goes to forge as a path. Its value is not echoed on refusal: a caller
# that passed the password itself in its place must not see it in the log.
if [[ -n "$PASSWORD_FILE" ]]; then
  [[ "$ACCOUNT_SET" == 1 ]] || die "--password-file needs --account (it unlocks that keystore)"
  [[ -f "$PASSWORD_FILE" && -r "$PASSWORD_FILE" ]] || die "--password-file must name a readable file (the path to the keystore password, not the password)"
  SIGNER_ARGS+=(--password-file "$PASSWORD_FILE")
fi

command -v forge >/dev/null || die "forge not on PATH"
command -v jq >/dev/null || die "jq is required"
: "${RPC_URL:?set RPC_URL to the RPC of the re-rolled chain}"
: "${DEPLOYER_ADDRESS:?set DEPLOYER_ADDRESS (the fresh ceremony deployer; scripts read it)}"
# The deploy scripts read CEREMONY_DEPLOYER_ADDRESS before DEPLOYER_ADDRESS (ScriptEnv), and
# derive constructor arguments (fee recipients) from it. A preset value that is not exactly
# DEPLOYER_ADDRESS (another address, empty, another case) is refused, never silently used.
if [[ -n "${CEREMONY_DEPLOYER_ADDRESS+x}" && "${CEREMONY_DEPLOYER_ADDRESS}" != "${DEPLOYER_ADDRESS}" ]]; then
  die "CEREMONY_DEPLOYER_ADDRESS (${CEREMONY_DEPLOYER_ADDRESS:-<empty>}) is not exactly DEPLOYER_ADDRESS (${DEPLOYER_ADDRESS}); unset it or set it to the same value"
fi
export CEREMONY_DEPLOYER_ADDRESS="$DEPLOYER_ADDRESS"

# Which membership deploy runs last, and which broadcast the generator reads it from. Checked
# before the build, so a refused input sends nothing.
MEMBERSHIP_SCRIPT="DeployCoreMembership.s.sol"
if [[ "$GENESIS_MEMBERSHIP" == "1" ]]; then
  MEMBERSHIP_SCRIPT="DeployGenesisMembership.s.sol"
  [[ -f "${CONTRACTS}/script/${MEMBERSHIP_SCRIPT}" ]] ||
    die "contracts/script/${MEMBERSHIP_SCRIPT} is missing (chain#331, the genesis membership path, must be merged)"
  for v in GOVERNANCE_TIMELOCK GOVERNANCE_MULTISIG MEMBERSHIP_GRANTOR; do
    [[ "${!v:-}" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "--genesis-membership needs $v (an address; got '${!v:-}')"
  done
  [[ -n "${GENESIS_MEMBERSHIP_OUT:-}" ]] || die "--genesis-membership needs GENESIS_MEMBERSHIP_OUT (the membership book path, relative to contracts/)"
fi
if [[ -n "${EMIT_MEMBERSHIP_SCRIPT:-}" && "$EMIT_MEMBERSHIP_SCRIPT" != "$MEMBERSHIP_SCRIPT" ]]; then
  die "EMIT_MEMBERSHIP_SCRIPT is set to ${EMIT_MEMBERSHIP_SCRIPT}, but this run deploys membership with ${MEMBERSHIP_SCRIPT}; unset it"
fi
export EMIT_MEMBERSHIP_SCRIPT="$MEMBERSHIP_SCRIPT"

if [[ "$REROLL" == "1" ]]; then
  export CITRATE_REROLL=1
  log "FRESH-KEYS REROLL MODE (CITRATE_REROLL=1) — stack deploys fresh; ~57 addresses will move."
else
  export CITRATE_REROLL=0
  log "LIVE mode (non-reroll) — kept-live pins preserved."
fi

# Broadcast/remote safety.
BROADCAST_ARGS=()
if [[ "$BROADCAST" == "1" ]]; then
  if [[ "$RPC_URL" != *localhost* && "$RPC_URL" != *127.0.0.1* && "${CITRATE_ALLOW_REMOTE:-0}" != "1" ]]; then
    die "refusing to --broadcast to a non-local RPC without CITRATE_ALLOW_REMOTE=1 (live-reroll two-key guard)"
  fi
  BROADCAST_ARGS+=(--broadcast)
  log "BROADCAST enabled → $RPC_URL"
else
  log "SIMULATE only (no --broadcast) → $RPC_URL"
fi

# ---------------------------------------------------------------------------
# Step 0 — CLEAN full build (compile-scope determinism, MAC item #5).
# Under via-IR, solc's bytecode for an UNCHANGED contract can depend on which
# other sources share the compilation job. A clean full `forge build` before
# the ceremony pins CitrateMemberSBT (and every other CREATE2 target) to a
# stable init_code hash. The membership gate additionally re-runs under a
# closure-scoped profile (see foundry.toml [profile.membership]).
# ---------------------------------------------------------------------------
log "Step 0: clean full forge build (compile-scope determinism)"
( cd "$CONTRACTS" && forge clean && forge build ) || die "clean build failed"

run_step() {
  local script="$1"; shift
  log "→ ${script}"
  ( cd "$CONTRACTS" && forge script "script/${script}" \
      --rpc-url "$RPC_URL" --sender "$DEPLOYER_ADDRESS" \
      "${SIGNER_ARGS[@]}" "${BROADCAST_ARGS[@]}" "$@" ) \
    || { err "ceremony step failed: ${script}"; exit 2; }
}

# ---------------------------------------------------------------------------
# Ceremony, in dependency order.
# ---------------------------------------------------------------------------
run_step "DeployAll.s.sol"
run_step "DeployValidatorRegistry.s.sol"

# Capture the just-deployed ValidatorRegistry so the membership step derives it.
VR_BROADCAST="${CONTRACTS}/broadcast/DeployValidatorRegistry.s.sol/${CHAIN_ID}/run-latest.json"
if [[ -f "$VR_BROADCAST" ]]; then
  VR_ADDR="$(jq -r '[.transactions[] | select(.contractName=="ValidatorRegistry") | .contractAddress] | last // empty' "$VR_BROADCAST")"
  if [[ -n "$VR_ADDR" && "$VR_ADDR" != "null" ]]; then
    export VALIDATOR_REGISTRY="$VR_ADDR"
    log "captured VALIDATOR_REGISTRY=$VALIDATOR_REGISTRY (fed to ${MEMBERSHIP_SCRIPT%.s.sol})"
  fi
fi
[[ -n "${VALIDATOR_REGISTRY:-}" ]] || log "WARN: VALIDATOR_REGISTRY not captured (simulate mode writes no broadcast); set it before ${MEMBERSHIP_SCRIPT%.s.sol}."

run_step "DeployModelAccessControl.s.sol"
run_step "DeployTEEAttestationRegistry.s.sol"
run_step "DeployComputePoolTraining.s.sol"
run_step "DeployEduStack.s.sol"
run_step "DeployAIGateway.s.sol"

if [[ "$WITH_AA" == "1" ]]; then
  # The passkey validator hard-codes P256.VERIFIER; provision it FIRST from the
  # vendored canonical Daimo init code (script/aa/lib/P256VerifierInitCode.sol),
  # so DeployAA does not fail closed on a fresh chain.
  run_step "aa/DeployP256Verifier.s.sol"
  run_step "aa/DeployAA.s.sol"
fi

# Membership last: it derives VALIDATOR_REGISTRY (env). DeployCoreMembership reads
# MEMBERSHIP_OWNER; DeployGenesisMembership reads GOVERNANCE_TIMELOCK, GOVERNANCE_MULTISIG,
# MEMBERSHIP_GRANTOR, GENESIS_MEMBERSHIP_OUT and GENESIS_GOVERNANCE_BOOK (see MEMBERSHIP above).
if [[ -n "${VALIDATOR_REGISTRY:-}" ]]; then
  run_step "$MEMBERSHIP_SCRIPT"
else
  log "SKIP ${MEMBERSHIP_SCRIPT%.s.sol} (no VALIDATOR_REGISTRY captured — simulate mode)."
fi

# ---------------------------------------------------------------------------
# Post: regenerate the canonical address table + verify CREATE2 determinism.
# ---------------------------------------------------------------------------
# The book names the deployer this run deployed with (EMIT_DEPLOYER), never a pin left in
# .env.testnet. Under EMIT_FRESH_GENESIS=1 (the G5 genesis ceremony) a failed regeneration
# stops the run: the ceremony's later gates read this book.
if [[ "$BROADCAST" == "1" ]]; then
  log "regenerating canonical address table"
  # One canonical spelling (lowercase), the one the G5 ceremony's P2 gate compares against.
  if ! EMIT_DEPLOYER="$(printf '%s' "$DEPLOYER_ADDRESS" | tr 'A-F' 'a-f')" bash "${REPO_ROOT}/scripts/ops/emit-address-table.sh"; then
    if [[ "${EMIT_FRESH_GENESIS:-0}" == "1" ]]; then
      err "emit-address-table failed in a fresh genesis"
      exit 2
    fi
    err "emit-address-table failed (continue: check manually)"
  fi
fi
log "checking CREATE2 determinism"
bash "${REPO_ROOT}/scripts/ci/check-create2-determinism.sh" || die "CREATE2 determinism check failed"

log "✅ regenesis complete (reroll=${REROLL}, with-aa=${WITH_AA}, broadcast=${BROADCAST})."
