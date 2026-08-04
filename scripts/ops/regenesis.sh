#!/usr/bin/env bash
# regenesis.sh — full-stack CREATE2 deploy orchestration for chain 40204.
#
# Deploys EVERY business contract via the deterministic (CREATE2) scripts in
# ceremony order, regenerates the canonical address table, and asserts every
# address has code on-chain. Because every `new X{salt: Salts.salt("X")}(…)`
# (see contracts/script/Salts.sol) routes through the genesis Arachnid CREATE2
# deployer (0x4e59…), the resulting contracts/addresses/40204.json is
# byte-identical across rerolls — no more address scramble.
#
# This is the single source of truth for "deploy the whole stack." Run it after
# a fresh re-roll. It is idempotent on a given chain (CREATE2 redeploys revert
# with "already deployed" — re-run on a FRESH chain only).
#
# Prerequisites:
#   - Re-rolled chain live + reachable (chain id 40204).
#   - Arachnid CREATE2 deployer present at 0x4e59… (genesis WP-B).
#   - Deployer EOA funded (DEPLOYER_ADDRESS / DEPLOYER_PRIVATE_KEY).
#   - For the AA step: EntryPoint v0.7 deployed + CITRATE_AA_* env set
#     (handled by scripts/ops/post-reroll-redeploy.sh — run AFTER this, or
#     pass --with-aa to chain it here).
#   - foundry (forge/cast) + jq on PATH.
#
# Usage:
#   ENV_TESTNET=/path/.env.testnet bash scripts/ops/regenesis.sh [--with-aa]
#
# Exit codes: 0 ok · 1 precondition failed · 2 a deploy failed · 3 verify failed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTRACTS_DIR="${REPO_ROOT}/contracts"
ENV_TESTNET="${ENV_TESTNET:-/home/saul/Projects/Citrate-Labs/.env.testnet}"
CHAIN_ID=40204
ARACHNID=0x4e59b44847b379578588920cA78FbF26c0B4956C

err() { echo "[regenesis] ERROR: $*" >&2; }
log() { echo "[regenesis] $*"; }

command -v forge >/dev/null || { err "forge (foundry) required"; exit 1; }
command -v cast  >/dev/null || { err "cast (foundry) required"; exit 1; }
command -v jq    >/dev/null || { err "jq required"; exit 1; }

# --- config from .env.testnet (RPC + deployer) -----------------------
get_env() { grep -E "^$1=" "$ENV_TESTNET" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'\'''; }
RPC_URL="${RPC_URL:-$(get_env RPC_URL)}"
RPC_URL="${RPC_URL:-https://rpc.citrate.ai}"
DEPLOYER_ADDRESS="${DEPLOYER_ADDRESS:-$(get_env DEPLOYER_ADDRESS)}"
DEPLOYER_PRIVATE_KEY="${DEPLOYER_PRIVATE_KEY:-$(get_env DEPLOYER_PRIVATE_KEY)}"
[ -n "$DEPLOYER_ADDRESS" ] || { err "DEPLOYER_ADDRESS not set / not in $ENV_TESTNET"; exit 1; }
[ -n "$DEPLOYER_PRIVATE_KEY" ] || { err "DEPLOYER_PRIVATE_KEY not set"; exit 1; }
export DEPLOYER_ADDRESS   # ScriptEnv.deployerAddress() reads this
# EduStack's InstitutionalVault needs 3 DISTINCT multisig signers; pin them to
# stable genesis EOAs so the CREATE2 addresses stay reroll-deterministic.
export SIGNER_1="${SIGNER_1:-$DEPLOYER_ADDRESS}"
export SIGNER_2="${SIGNER_2:-$(get_env TEAM_ADDRESS)}"
export SIGNER_3="${SIGNER_3:-$(get_env TREASURY_ADDRESS)}"

# --- preconditions ---------------------------------------------------
ON_CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL")
[ "$ON_CHAIN_ID" = "$CHAIN_ID" ] || { err "chain id $ON_CHAIN_ID != $CHAIN_ID"; exit 1; }
[ "$(cast code --rpc-url "$RPC_URL" "$ARACHNID" | wc -c)" -gt 10 ] || { err "Arachnid CREATE2 deployer missing at $ARACHNID — rebuild genesis (WP-B)"; exit 1; }
BAL=$(cast balance --rpc-url "$RPC_URL" "$DEPLOYER_ADDRESS")
[ "$(cast to-unit "$BAL" ether | cut -d. -f1)" -ge 1 ] 2>/dev/null || { err "deployer $DEPLOYER_ADDRESS has < 1 SALT"; exit 1; }
log "chain $CHAIN_ID ✓  Arachnid ✓  deployer $DEPLOYER_ADDRESS funded ✓  rpc=$RPC_URL"

# --- the business-contract ceremony, in dependency order -------------
# Each script deploys via CREATE2 (deterministic). Order matters only for the
# cross-script reads done by post-deploy wiring, not for the addresses.
CEREMONY=(
  "script/DeployAll.s.sol"                  # 28 core contracts (incl. NematocystSlashing)
  "script/DeployModelAccessControl.s.sol"   # 1 (OZ-isolated)
  "script/DeployTEEAttestationRegistry.s.sol" # 1 (CM-08)
  "script/DeployComputePoolTraining.s.sol"  # 1 (CM-07)
  # I64-S1 WP-B1: 5 federated-learning contracts. After DeployAll (so
  # NematocystSlashing exists for the post-deploy setSlashingContract wiring)
  # and after TEE (ComputePoolPipeline references its address). Self-deploys
  # KYCRegistry → IPFS V2/V3 → AggregationChallenge → ComputePoolPipeline.
  "script/DeployFederatedLearning.s.sol"    # 5 (KYC, IPFS V2/V3, AggChal, Pipeline)
  "script/DeployEduStack.s.sol"             # 5 (Learning Center)
  "script/DeployAIGateway.s.sol"            # 3 (edu ai-gateway)
)

for s in "${CEREMONY[@]}"; do
  log "deploying $s …"
  # Simulate (for correct per-CREATE2 gas estimation) + --slow (one tx at a
  # time, await each receipt — reliable on a 2s-block chain). Do NOT use
  # --skip-simulation: it sends with a default gas limit too low for the
  # proxy's CALLDATACOPY of a multi-KB init_code + the CREATE2.
  if ! (cd "$CONTRACTS_DIR" && forge script "$s" \
        --rpc-url "$RPC_URL" \
        --private-key "$DEPLOYER_PRIVATE_KEY" \
        --sender "$DEPLOYER_ADDRESS" \
        --broadcast --slow --gas-estimate-multiplier 130 2>&1 | tail -4); then
    err "deploy failed: $s"; exit 2
  fi
done

# --- AA stack (optional; needs EntryPoint + CITRATE_AA_* env) ---------
if [ "${1:-}" = "--with-aa" ]; then
  log "running AA ceremony via post-reroll-redeploy.sh …"
  ENV_TESTNET="$ENV_TESTNET" bash "${REPO_ROOT}/scripts/ops/post-reroll-redeploy.sh" || { err "AA ceremony failed"; exit 2; }
fi

# --- regenerate the canonical table ----------------------------------
log "regenerating canonical contracts/addresses/40204.json …"
ENV_TESTNET="$ENV_TESTNET" bash "${REPO_ROOT}/scripts/ops/emit-address-table.sh"

# --- verify: every canonical address has code ------------------------
#
# The book contains contracts this script does NOT deploy. The quorum/BFR
# governance set (AnchorRegistry, MeetingRegistry, GovernanceTemplateRegistry,
# GovernanceProtocolFactory, PolicyBinding, CapabilityGrant, VoteAllowance,
# Sortition) is deployed by post-reroll-quorum-restore.sh, which runs AFTER
# this script because emit-address-table.sh above would otherwise overwrite the
# entries it patches in. Verifying the whole book here therefore fails on a
# clean re-roll for contracts that are merely not-deployed-YET — it failed the
# 2026-08-04 ceremony twice, and the same shape lost time on 2026-07-26.
#
# REGENESIS_SKIP_BOOK_VERIFY=1 hands the whole-book check to the caller. The
# orchestrator sets it and then runs the quorum restore, whose own final step
# verifies EVERY booked address has code — so coverage is unchanged, only the
# ordering is. Never set it for a standalone run.
if [ "${REGENESIS_SKIP_BOOK_VERIFY:-0}" = "1" ]; then
  log "SKIPPING the whole-book code verification (REGENESIS_SKIP_BOOK_VERIFY=1)."
  log "  The caller owns it — post-reroll-quorum-restore.sh deploys the quorum/BFR"
  log "  set and verifies every booked address afterwards. If nothing runs that,"
  log "  this re-roll is UNVERIFIED."
  log "✅ full stack deployed + canonical table regenerated (book verify deferred)."
  exit 0
fi
log "verifying eth_getCode != 0x for every canonical contract …"
TABLE="${CONTRACTS_DIR}/addresses/40204.json"
FAIL=0
while IFS=$'\t' read -r name addr; do
  # precompiles + the genesis Arachnid are not CREATE2 contracts; skip empties
  [ -z "$addr" ] && continue
  CODELEN=$(cast code --rpc-url "$RPC_URL" "$addr" | wc -c)
  if [ "$CODELEN" -le 4 ]; then err "NO CODE at $name = $addr"; FAIL=1; fi
done < <(jq -r '.contracts | to_entries[] | "\(.key)\t\(.value)"' "$TABLE")
[ "$FAIL" -eq 0 ] || { err "verification failed — some contracts have no code"; exit 3; }

log "✅ full stack deployed + canonical table regenerated + all addresses have code."
log "next: sync consumers (each repo's sync-addresses) + run the CREATE2 determinism gate (scripts/ci/check-create2-determinism.sh)."
