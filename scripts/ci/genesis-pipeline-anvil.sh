#!/usr/bin/env bash
# genesis-pipeline-anvil.sh: run the C4 genesis ceremony scripts for real against a throwaway
# anvil chain with chain id 40204, as `forge script --broadcast` (not `forge test`):
#
#   DeployGenesisGovernance -> (KYCRegistry + MembershipSBT stand-ins) -> DeployDormantLedgers
#   -> CheckDeployedAdmins (over both ceremony books), which must report 0 failures.
#
# Catches what `forge test` cannot: forge refusing a script run path (e.g. `address(this)` in a
# script contract), broadcast-vs-simulation differences, and the role history read through a real
# node's eth_getLogs.
#
# Uses ONLY anvil's public test mnemonic ("test ... junk"); no real key is read or needed.
# Env: ANVIL_PORT (default 8545; must be free), KEEP_OUTPUT=1 keeps contracts/genesis/anvil-ci/.
# Requires foundry (anvil, forge, cast) on PATH. Exit 0 = pipeline + gate passed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
PORT="${ANVIL_PORT:-8545}"
RPC="http://127.0.0.1:${PORT}"
OUT_REL="genesis/anvil-ci" # under foundry.toml's read-write ./genesis
OUT="$CONTRACTS/$OUT_REL"
MNEMONIC="test test test test test test test test test test test junk" # anvil's public default
P256_VERIFIER=0xc2b78104907F722DABAc4C69f826a522B2754De4

for t in anvil forge cast; do
  command -v "$t" >/dev/null || { echo "genesis-pipeline-anvil: $t not found" >&2; exit 2; }
done
if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
  echo "genesis-pipeline-anvil: port ${PORT} is in use; set ANVIL_PORT" >&2
  exit 2
fi

mkdir -p "$OUT"
anvil --chain-id 40204 --port "$PORT" --mnemonic "$MNEMONIC" --silent &
ANVIL_PID=$!
cleanup() {
  kill "$ANVIL_PID" 2>/dev/null || true
  wait "$ANVIL_PID" 2>/dev/null || true
  [ "${KEEP_OUTPUT:-0}" = 1 ] || rm -rf "$OUT"
}
trap cleanup EXIT
for _ in $(seq 1 50); do
  cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
  sleep 0.2
done
[ "$(cast chain-id --rpc-url "$RPC")" = 40204 ] || { echo "genesis-pipeline-anvil: anvil not up on 40204" >&2; exit 1; }

KEY="$(cast wallet private-key "$MNEMONIC" 0)"
DEPLOYER="$(cast wallet address --private-key "$KEY")"
export DEPLOYER_ADDRESS="$DEPLOYER"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

# Council seats: placeholder owner addresses (no keys needed; nothing here votes).
export GOV_OWNERS=0x000000000000000000000000000000000000A001,0x000000000000000000000000000000000000A002,0x000000000000000000000000000000000000A003,0x000000000000000000000000000000000000A004,0x000000000000000000000000000000000000A005
export GOV_THRESHOLD=3 GOV_MIN_DELAY=172800
export GRD_OWNERS=0x000000000000000000000000000000000000B001,0x000000000000000000000000000000000000B002,0x000000000000000000000000000000000000B003
export GRD_THRESHOLD=2 GRD_MIN_DELAY=3600
export GENESIS_GOVERNANCE_OUT="$OUT_REL/governance.json"
export DORMANT_LEDGERS_OUT="$OUT_REL/dormant.json"

cd "$CONTRACTS"
run_script() {
  echo "=== forge script $1 --broadcast ==="
  forge script "$1" --rpc-url "$RPC" --broadcast --private-key "$KEY" --slow -q
}

run_script script/DeployGenesisGovernance.s.sol

# PatronageLedger's KYC registry and membership: plain stand-ins with code, deployer-administered
# (they are not part of the gated books; only their presence is required).
create() { # <contract> <constructor args...> (--constructor-args is variadic, so it goes last)
  local contract="$1"
  shift
  forge create "$contract" --rpc-url "$RPC" --private-key "$KEY" --broadcast --json --constructor-args "$@" | grep -o '"deployedTo": *"0x[0-9a-fA-F]*"' | grep -o '0x[0-9a-fA-F]*'
}
KYC="$(create src/KYCRegistry.sol:KYCRegistry 0x0000000000000000000000000000000000000000 "$DEPLOYER")"
MEMBERSHIP="$(create src/coop/MembershipSBT.sol:MembershipSBT "$KYC" "[]" "$DEPLOYER" "$DEPLOYER")"
[ -n "$KYC" ] && [ -n "$MEMBERSHIP" ] || { echo "genesis-pipeline-anvil: stand-in deploy failed" >&2; exit 1; }

GOV_JSON="$OUT/governance.json"
export GOVERNANCE_TIMELOCK="$(sed -n 's/.*"GovernanceTimelock":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$GOV_JSON")"
export GOVERNANCE_MULTISIG="$(sed -n 's/.*"GovernanceMultisig":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$GOV_JSON")"
export PATRONAGE_KYC_REGISTRY="$KYC" PATRONAGE_MEMBERSHIP="$MEMBERSHIP"
run_script script/DeployDormantLedgers.s.sol

# The gate requires the P-256 verifier the passkey validator hard-codes; anvil has none.
cast rpc --rpc-url "$RPC" anvil_setCode "$P256_VERIFIER" 0x600160005260206000f3 >/dev/null

echo "=== forge script CheckDeployedAdmins (read-only) ==="
ADDRESS_BOOK="$GENESIS_GOVERNANCE_OUT" EXTRA_ADDRESS_BOOKS="$DORMANT_LEDGERS_OUT" REQUIRE_ALL_CODE=true \
  forge script script/CheckDeployedAdmins.s.sol --rpc-url "$RPC" 2>&1 | tee "$OUT/gate.log" | grep -E "failures|NO-CODE|VERIFIER|FACTORY|DEPLOYER|TIMELOCK|Error|revert" || true
grep -q "Script ran successfully" "$OUT/gate.log" || { echo "genesis-pipeline-anvil: gate FAILED" >&2; exit 1; }
echo "genesis-pipeline-anvil: PASS (DeployGenesisGovernance -> DeployDormantLedgers -> CheckDeployedAdmins on anvil 40204)"
