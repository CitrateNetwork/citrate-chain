#!/usr/bin/env bash
# deploy_bfr_40204.sh — orchestrate the BFR (Boeing) contract suite deploy.
#
# Runs the 14 DeployBfr*.s.sol Foundry ceremonies in dependency order against
# chain 40204 (or any chain via --rpc-url). RBAC foundation (BFR-02) first, then
# the panel-specific registries. BFR-03/04 do not exist (numbering jumps 02→05).
#
# SAFETY: dry-run by default. Broadcasting is HUMAN-IN-LOOP (deployer holds the
# key). Nothing is sent to chain unless you pass --broadcast.
#
# Usage:
#   # Dry-run (default, no broadcast, no key needed):
#   scripts/ops/deploy_bfr_40204.sh
#
#   # Live broadcast (deployer only):
#   DEPLOY_KEY=0x... [ROOT_GOVERNANCE=0x...] \
#     scripts/ops/deploy_bfr_40204.sh --broadcast
#
# Env:
#   RPC_URL          RPC endpoint       (default: https://rpc.citrate.ai)
#   DEPLOY_KEY       deployer priv key  (required only with --broadcast)
#   ROOT_GOVERNANCE  governance addr    (optional; falls back to deployer)
#
# After a successful broadcast, run scripts/ops/emit-address-table.sh to fold the
# new addresses into contracts/addresses/40204.json, then WireBfrOperators.s.sol.
set -euo pipefail

RPC_URL="${RPC_URL:-https://rpc.citrate.ai}"
BROADCAST=0
[[ "${1:-}" == "--broadcast" ]] && BROADCAST=1

# Resolve to contracts/ regardless of where invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$(cd "$SCRIPT_DIR/../../contracts" && pwd)"
cd "$CONTRACTS_DIR"

# Dependency order: RBAC foundation, then panel registries.
SCRIPTS=(
  DeployBfr02Rbac
  DeployBfr05Provenance
  DeployBfr06Suppliers
  DeployBfr07FL
  DeployBfr08Refresh
  DeployBfr09AppsContracts
  DeployBfr10Assistant
  DeployBfr11Governance
  DeployBfr12Ontology
  DeployBfr13Procurement
  DeployBfr14InterOrg
  DeployBfr15Compliance
  DeployBfr16Sponsor
  DeployBfr17Release
)

if [[ "$BROADCAST" == "1" ]]; then
  : "${DEPLOY_KEY:?--broadcast requires DEPLOY_KEY (deployer private key)}"
  echo ">>> LIVE BROADCAST to $RPC_URL — deploying ${#SCRIPTS[@]} BFR ceremonies."
  echo ">>> Deployer will pay SALT gas. Ctrl-C within 5s to abort."
  sleep 5
else
  echo ">>> DRY-RUN against $RPC_URL (no broadcast). Pass --broadcast to send."
fi

for s in "${SCRIPTS[@]}"; do
  echo "──────────────────────────────────────────────────────────"
  echo ">>> $s"
  args=(script "script/${s}.s.sol" --rpc-url "$RPC_URL")
  if [[ "$BROADCAST" == "1" ]]; then
    args+=(--private-key "$DEPLOY_KEY" --broadcast)
  fi
  forge "${args[@]}"
done

echo "──────────────────────────────────────────────────────────"
if [[ "$BROADCAST" == "1" ]]; then
  echo ">>> Broadcast complete. Next:"
  echo "    1) scripts/ops/emit-address-table.sh   # fold BFR addrs into 40204.json"
  echo "    2) forge script script/WireBfrOperators.s.sol --rpc-url $RPC_URL --private-key \$DEPLOY_KEY --broadcast"
  echo "    3) forge script script/SeedBoeingState.s.sol  --rpc-url $RPC_URL --private-key \$DEPLOY_KEY --broadcast"
  echo "    4) commit contracts/broadcast/DeployBfr*.s.sol/*/run-latest.json"
else
  echo ">>> Dry-run complete. Review simulated deploys above."
fi
