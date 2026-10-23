#!/usr/bin/env bash
# genesis-pipeline-anvil.sh: run the C4 genesis ceremony scripts for real against a throwaway
# anvil chain with chain id 40204, as `forge script --broadcast` (not `forge test`):
#
#   DeployGenesisGovernance -> (KYCRegistry + MembershipSBT stand-ins) -> DeployDormantLedgers
#   -> CheckDeployedAdmins (over both ceremony books), which must report 0 failures.
#
# Then the chain#320 negatives, each of which must be refused with nothing sent:
#   - forge simulating another chain id than the 40204 node (--chain-id 1): DeployGenesisGovernance,
#     DeployDormantLedgers and the gate;
#   - a deployer-controlled GOVERNANCE timelock with a hidden PROPOSER/EXECUTOR and
#     TIMELOCK_HISTORY_FROM_BLOCK past that grant (plus a re-emitted constructor pair), for
#     DeployDormantLedgers (window and full history) and the gate.
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

GATE_ENV=(ADDRESS_BOOK="$GENESIS_GOVERNANCE_OUT" EXTRA_ADDRESS_BOOKS="$DORMANT_LEDGERS_OUT" REQUIRE_ALL_CODE=true)
gate() { # <log> [extra forge args...]: run the read-only gate; returns forge's status
  local log="$1"
  shift
  env "${GATE_ENV[@]}" forge script script/CheckDeployedAdmins.s.sol --rpc-url "$RPC" "$@" >"$log" 2>&1
}
fail() {
  echo "genesis-pipeline-anvil: $*" >&2
  exit 1
}

echo "=== forge script CheckDeployedAdmins (read-only) ==="
gate "$OUT/gate.log" || true
grep -E "failures|NO-CODE|VERIFIER|FACTORY|DEPLOYER|TIMELOCK|Error|revert" "$OUT/gate.log" | grep -v "\[" || true
grep -q "Script ran successfully" "$OUT/gate.log" || fail "gate FAILED"
for class in "FACTORY-ADMIN" "DEPLOYER-ADMIN" "TIMELOCK-HOLDERS"; do
  grep -qE "^ *${class} failures: 0$" "$OUT/gate.log" || fail "gate: ${class} failures not 0"
done
echo "genesis-pipeline-anvil: pipeline PASS (0 FACTORY-ADMIN / DEPLOYER-ADMIN / TIMELOCK-HOLDERS)"

# ---- chain#320 negatives (each must be refused) ----
nonce() { cast nonce --rpc-url "$RPC" "$1"; }
MISMATCH="chain id mismatch: node reports 40204, forge simulates 1"

echo "=== negative: forge simulating chain 1 against the 40204 node (--chain-id 1) ==="
before="$(nonce "$DEPLOYER")"
for s in DeployGenesisGovernance DeployDormantLedgers; do
  if forge script "script/$s.s.sol" --rpc-url "$RPC" --broadcast --private-key "$KEY" --chain-id 1 \
    >"$OUT/neg-chainid-$s.log" 2>&1; then fail "$s ran with --chain-id 1"; fi
  grep -q "$MISMATCH" "$OUT/neg-chainid-$s.log" || fail "$s --chain-id 1: not refused on the chain id"
done
[ "$(nonce "$DEPLOYER")" = "$before" ] || fail "a --chain-id 1 run sent a transaction"
if gate "$OUT/neg-chainid-gate.log" --chain-id 1; then fail "gate ran with --chain-id 1"; fi
grep -q "$MISMATCH" "$OUT/neg-chainid-gate.log" || fail "gate --chain-id 1: not refused on the chain id"
echo "refused (DeployGenesisGovernance, DeployDormantLedgers, gate), nothing sent"

# A deployer-controlled GOVERNANCE timelock (test/genesis/anvil/LateHistoryWindowFixture.s.sol):
# ceremony-salt CREATE2 timelock + CREATE2-correct 3-of-5 council, 48 h, self-administered, no
# deploy-account seat, but ROGUE keeps PROPOSER and EXECUTOR from a grant made BEFORE
# LATE_FROM; after LATE_FROM the timelock re-emits its constructor's closing pair
# (RoleGranted(DEFAULT_ADMIN, timelock) + MinDelayChange(0, 48 h)) in one transaction.
echo "=== negative: hidden PROPOSER/EXECUTOR with TIMELOCK_HISTORY_FROM_BLOCK past the grant ==="
FKEY="$(cast wallet private-key "$MNEMONIC" 1)"
FADMIN="$(cast wallet address --private-key "$FKEY")"
ROGUE=0x000000000000000000000000000000000000bAd2
fixture() { # <stage>
  FIXTURE_STAGE="$1" FIXTURE_ADMIN="$FADMIN" FIXTURE_ROGUE="$ROGUE" FIXTURE_OUT="$OUT_REL/late.json" \
    FIXTURE_HELPER="${HELPER:-0x0000000000000000000000000000000000000000}" \
    forge script test/genesis/anvil/LateHistoryWindowFixture.s.sol --tc LateHistoryWindowFixture --rpc-url "$RPC" --broadcast \
    --private-key "$FKEY" --slow -q >"$OUT/fixture-$1.log" 2>&1 || { cat "$OUT/fixture-$1.log" >&2; fail "fixture stage $1"; }
}
fixture 1
LATE_TL="$(sed -n 's/.*"timelock":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$OUT/late.json")"
LATE_MS="$(sed -n 's/.*"multisig":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$OUT/late.json")"
HELPER="$(sed -n 's/.*"helper":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$OUT/late.json")"
LATE_FROM=$(($(cast block-number --rpc-url "$RPC") + 1))
fixture 2
PROPOSER_ROLE="$(cast keccak PROPOSER_ROLE)"
EXECUTOR_ROLE="$(cast keccak EXECUTOR_ROLE)"
[ "$(cast call --rpc-url "$RPC" "$LATE_TL" 'hasRole(bytes32,address)(bool)' "$PROPOSER_ROLE" "$ROGUE")" = true ] &&
  [ "$(cast call --rpc-url "$RPC" "$LATE_TL" 'hasRole(bytes32,address)(bool)' "$EXECUTOR_ROLE" "$ROGUE")" = true ] ||
  fail "fixture: ROGUE does not hold the hidden seats"
[ "$(cast call --rpc-url "$RPC" "$LATE_TL" 'getMinDelay()(uint256)' | cut -d' ' -f1)" = 172800 ] || fail "fixture: delay is not 48 h"
late_dormant() { # <log> [env...]: DeployDormantLedgers against the fixture timelock
  local log="$1"
  shift
  env GOVERNANCE_TIMELOCK="$LATE_TL" GOVERNANCE_MULTISIG="$LATE_MS" "$@" forge script script/DeployDormantLedgers.s.sol \
    --rpc-url "$RPC" --broadcast --private-key "$KEY" >"$log" 2>&1
}
before="$(nonce "$DEPLOYER")"
if late_dormant "$OUT/neg-late-window.log" TIMELOCK_HISTORY_FROM_BLOCK="$LATE_FROM"; then
  fail "DeployDormantLedgers accepted the hidden seat with TIMELOCK_HISTORY_FROM_BLOCK=$LATE_FROM"
fi
grep -q "GOVERNANCE_TIMELOCK: role history does not start at the timelock's construction" "$OUT/neg-late-window.log" ||
  fail "late window: not refused on the construction check"
if late_dormant "$OUT/neg-late-full.log"; then fail "DeployDormantLedgers accepted the hidden seat (full history)"; fi
grep -q "GOVERNANCE_TIMELOCK: PROPOSER_ROLE holders are not exactly the multisig" "$OUT/neg-late-full.log" ||
  fail "full history: hidden PROPOSER not found"
[ "$(nonce "$DEPLOYER")" = "$before" ] || fail "a late-window run sent a transaction"
printf '{"chainId":40204,"deployer":"%s","contracts":{"GovernanceTimelock":"%s","GovernanceMultisig":"%s"},"aaStack":{},"params":{}}' \
  "$DEPLOYER" "$LATE_TL" "$LATE_MS" >"$OUT/late-book.json"
if ADDRESS_BOOK="$OUT_REL/late-book.json" TIMELOCK_HISTORY_FROM_BLOCK="$LATE_FROM" \
  forge script script/CheckDeployedAdmins.s.sol --rpc-url "$RPC" >"$OUT/neg-late-gate.log" 2>&1; then
  fail "gate passed the hidden seat with TIMELOCK_HISTORY_FROM_BLOCK=$LATE_FROM"
fi
grep -E "^ *TIMELOCK-HOLDERS GovernanceTimelock: role history does not start at the timelock's construction" "$OUT/neg-late-gate.log" ||
  fail "gate late window: not a TIMELOCK-HOLDERS construction failure"
echo "refused (deploy from block $LATE_FROM and from 0, gate from block $LATE_FROM), nothing sent"
echo "genesis-pipeline-anvil: PASS (pipeline + chain#320 negatives on anvil 40204)"
