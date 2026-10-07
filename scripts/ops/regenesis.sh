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
# VALIDATOR_REGISTRY so DeployCoreMembership derives (never hardcodes) it.
#
# Usage:
#   RPC_URL=http://localhost:8545 DEPLOYER_ADDRESS=0x.. \
#     bash scripts/ops/regenesis.sh --reroll --with-aa --broadcast --account deployer
#
# Flags:
#   --reroll        fresh-keys reroll mode (CITRATE_REROLL=1)
#   --with-aa       also run the ERC-4337 AA stack (DeployAA) + P256 verifier
#   --broadcast     actually send txs (omit = simulate only; safe dry-run)
#   --account NAME  forge keystore account to sign with (passed through)
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
BROADCAST=0
SIGNER_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reroll)      REROLL=1; shift ;;
    --with-aa)     WITH_AA=1; shift ;;
    --broadcast)   BROADCAST=1; shift ;;
    --account)     SIGNER_ARGS+=(--account "$2"); shift 2 ;;
    --private-key) SIGNER_ARGS+=(--private-key "$2"); shift 2 ;;
    *) die "unknown arg: $1" ;;
  esac
done

command -v forge >/dev/null || die "forge not on PATH"
command -v jq >/dev/null || die "jq is required"
: "${RPC_URL:?set RPC_URL to the re-rolled chain's RPC}"
: "${DEPLOYER_ADDRESS:?set DEPLOYER_ADDRESS (the fresh ceremony deployer; scripts read it)}"
export CEREMONY_DEPLOYER_ADDRESS="${CEREMONY_DEPLOYER_ADDRESS:-$DEPLOYER_ADDRESS}"

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

# Capture the just-deployed ValidatorRegistry so DeployCoreMembership derives it.
VR_BROADCAST="${CONTRACTS}/broadcast/DeployValidatorRegistry.s.sol/${CHAIN_ID}/run-latest.json"
if [[ -f "$VR_BROADCAST" ]]; then
  VR_ADDR="$(jq -r '[.transactions[] | select(.contractName=="ValidatorRegistry") | .contractAddress] | last // empty' "$VR_BROADCAST")"
  if [[ -n "$VR_ADDR" && "$VR_ADDR" != "null" ]]; then
    export VALIDATOR_REGISTRY="$VR_ADDR"
    log "captured VALIDATOR_REGISTRY=$VALIDATOR_REGISTRY (fed to DeployCoreMembership)"
  fi
fi
[[ -n "${VALIDATOR_REGISTRY:-}" ]] || log "WARN: VALIDATOR_REGISTRY not captured (simulate mode writes no broadcast); set it before DeployCoreMembership."

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

# CoreMembership last — it derives VALIDATOR_REGISTRY (env) + MEMBERSHIP_OWNER (env).
if [[ -n "${VALIDATOR_REGISTRY:-}" ]]; then
  run_step "DeployCoreMembership.s.sol"
else
  log "SKIP DeployCoreMembership (no VALIDATOR_REGISTRY captured — simulate mode)."
fi

# ---------------------------------------------------------------------------
# Post: regenerate the canonical address table + verify CREATE2 determinism.
# ---------------------------------------------------------------------------
if [[ "$BROADCAST" == "1" ]]; then
  log "regenerating canonical address table"
  bash "${REPO_ROOT}/scripts/ops/emit-address-table.sh" || err "emit-address-table failed (continue: check manually)"
fi
log "checking CREATE2 determinism"
bash "${REPO_ROOT}/scripts/ci/check-create2-determinism.sh" || die "CREATE2 determinism check failed"

log "✅ regenesis complete (reroll=${REROLL}, with-aa=${WITH_AA}, broadcast=${BROADCAST})."
