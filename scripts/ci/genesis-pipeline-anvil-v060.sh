#!/usr/bin/env bash
# genesis-pipeline-anvil-v060.sh: rehearse the 0.6.0 ceremony genesis (GENESIS_V060=1) for real
# against a throwaway anvil chain with chain id 40204, as `forge script --broadcast` runs:
#
#   DeployGenesisGovernance (0.6.0 mode: ProviderRegistry + GuardianCancellerV2, CANCELLER to v2)
#   -> (KYCRegistry + MembershipSBT stand-ins) -> DeployDormantLedgers (FederatedRoundLedger)
#   -> the V1 GuardianRecoveryModule at its CREATE2 address (through the Arachnid factory, as P2)
#   -> CitrateMemberSBT, OrganizationSBT and AgentSBT owned by the GOVERNANCE timelock
#   -> DeployV060Genesis, then its on-chain verify step (verifyBook), which must PASS
#   -> CheckDeployedAdmins over the governance, dormant-ledger and 0.6.0 books: 0 failures.
#
# Then the negatives, each of which must be refused:
#   - DeployV060Genesis without the coordinator bonds (required inputs; no default): nothing sent;
#   - DeployV060Genesis with a council owner on the retired list: nothing sent;
#   - DeployV060Genesis with a veto margin other than the owner's decided 7200 s: nothing sent;
#   - verifyBook after the GOVERNANCE timelock (impersonated) changes WorkMarket's verifier
#     allowlist.
#
# Every key-like value here is a public placeholder. The deployer is anvil's public test
# mnemonic; the council owners, the key inventory and the retired keys are test values (the
# owner's are pending). The bonds are the owner's decided rehearsal values (2026-11-11).
# Env: ANVIL_PORT (default 8546; must be free), KEEP_OUTPUT=1 keeps contracts/genesis/anvil-v060/.
# Requires foundry (anvil, forge, cast) and python3 on PATH. Exit 0 = rehearsal + gate passed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
PORT="${ANVIL_PORT:-8546}"
RPC="http://127.0.0.1:${PORT}"
OUT_REL="genesis/anvil-v060" # under foundry.toml's read-write ./genesis
OUT="$CONTRACTS/$OUT_REL"
MNEMONIC="test test test test test test test test test test test junk" # anvil's public default
P256_VERIFIER=0xc2b78104907F722DABAc4C69f826a522B2754De4
FACTORY=0x4e59b44847b379578588920cA78FbF26c0B4956C

for t in anvil forge cast python3; do
  command -v "$t" >/dev/null || { echo "genesis-pipeline-anvil-v060: $t not found" >&2; exit 2; }
done
if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
  echo "genesis-pipeline-anvil-v060: port ${PORT} is in use; set ANVIL_PORT" >&2
  exit 2
fi
fail() {
  echo "genesis-pipeline-anvil-v060: $*" >&2
  exit 1
}

mkdir -p "$OUT"
anvil --chain-id 40204 --port "$PORT" --mnemonic "$MNEMONIC" --silent &
ANVIL_PID=$!
cleanup() {
  kill "$ANVIL_PID" 2>/dev/null || true
  wait "$ANVIL_PID" 2>/dev/null || true
  [ "${KEEP_OUTPUT:-0}" = 1 ] || rm -rf "${OUT:?}"
}
trap cleanup EXIT
for _ in $(seq 1 50); do
  cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
  sleep 0.2
done
[ "$(cast chain-id --rpc-url "$RPC")" = 40204 ] || fail "anvil not up on 40204"

KEY="$(cast wallet private-key "$MNEMONIC" 0)"
DEPLOYER="$(cast wallet address --private-key "$KEY")"
export DEPLOYER_ADDRESS="$DEPLOYER"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

# Councils and the 0.6.0 key parameters (test placeholders; nothing here votes).
GOV_LIST=(0x000000000000000000000000000000000000A001 0x000000000000000000000000000000000000A002
  0x000000000000000000000000000000000000A003 0x000000000000000000000000000000000000A004
  0x000000000000000000000000000000000000A005)
GRD_LIST=(0x000000000000000000000000000000000000B001 0x000000000000000000000000000000000000B002
  0x000000000000000000000000000000000000B003)
export GOV_OWNERS="$(IFS=,; echo "${GOV_LIST[*]}")" GOV_THRESHOLD=3 GOV_MIN_DELAY=172800
export GRD_OWNERS="$(IFS=,; echo "${GRD_LIST[*]}")" GRD_THRESHOLD=2 GRD_MIN_DELAY=3600
export GENESIS_V060=1 GENESIS_GUARDIAN_VETO_MARGIN=7200
export GENESIS_RETIRED_KEYS=0x00000000000000000000000000000000000000E1,0x00000000000000000000000000000000000000E2
GENESIS_KEY_INVENTORY="$(python3 -c '
import json, sys
gov, grd = sys.argv[1].split(","), sys.argv[2].split(",")
print(json.dumps({**{a: ["GOV_OWNERS"] for a in gov}, **{a: ["GRD_OWNERS"] for a in grd}}))' "$GOV_OWNERS" "$GRD_OWNERS")"
export GENESIS_KEY_INVENTORY
BONDS=(WORKMARKET_MIN_COORDINATOR_BOND=100000000000000000000 WORKMARKET_DEFAULT_COORDINATOR_BOND=1000000000000000000000)
export GENESIS_GOVERNANCE_OUT="$OUT_REL/governance.json" GENESIS_GOVERNANCE_BOOK="$OUT_REL/governance.json"
export DORMANT_LEDGERS_OUT="$OUT_REL/dormant.json"
export V060_INPUT_BOOK="$OUT_REL/v060-input-book.json" V060_GENESIS_OUT="$OUT_REL/v060-genesis.json"

cd "$CONTRACTS"
run_script() {
  echo "=== forge script $1 --broadcast ==="
  forge script "$1" --rpc-url "$RPC" --broadcast --private-key "$KEY" --slow -q
}
create() { # <contract> <constructor args...>
  local contract="$1"
  shift
  forge create "$contract" --rpc-url "$RPC" --private-key "$KEY" --broadcast --json --constructor-args "$@" |
    grep -o '"deployedTo": *"0x[0-9a-fA-F]*"' | grep -o '0x[0-9a-fA-F]*'
}
book() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["contracts"][sys.argv[2]])' "$@"; }
nonce() { cast nonce --rpc-url "$RPC" "$1"; }

run_script script/DeployGenesisGovernance.s.sol
GOV_JSON="$OUT/governance.json"
GOVERNANCE_TIMELOCK="$(book "$GOV_JSON" GovernanceTimelock)"
export GOVERNANCE_TIMELOCK GOVERNANCE_MULTISIG="$(book "$GOV_JSON" GovernanceMultisig)"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["params"].get("guardianCancellerVersion") == 2 and "ProviderRegistry" in d["contracts"] else 1)' "$GOV_JSON" ||
  fail "P1 did not run in its 0.6.0 mode (no v2 seat / ProviderRegistry in the governance book)"

KYC="$(create src/KYCRegistry.sol:KYCRegistry 0x0000000000000000000000000000000000000000 "$DEPLOYER")"
MEMBERSHIP="$(create src/coop/MembershipSBT.sol:MembershipSBT "$KYC" "[]" "$DEPLOYER" "$DEPLOYER")"
[ -n "$KYC" ] && [ -n "$MEMBERSHIP" ] || fail "stand-in deploy failed"
export PATRONAGE_KYC_REGISTRY="$KYC" PATRONAGE_MEMBERSHIP="$MEMBERSHIP"
run_script script/DeployDormantLedgers.s.sol

# The V1 recovery module exactly as P2's DeployAA deploys it: CREATE2 under its own salt.
echo "=== V1 GuardianRecoveryModule through the Arachnid factory ==="
V1_INIT="$(forge inspect src/aa/recovery/GuardianRecoveryModule.sol:GuardianRecoveryModule bytecode)"
V1_SALT="$(cast keccak "citrate.v1.GuardianRecoveryModule")"
cast send --rpc-url "$RPC" --private-key "$KEY" "$FACTORY" "${V1_SALT}${V1_INIT#0x}" >/dev/null
V1="$(cast create2 --deployer "$FACTORY" --salt "$V1_SALT" --init-code "$V1_INIT" | awk '{print $1}')"
[[ "$V1" =~ ^0x[0-9a-fA-F]{40}$ ]] || fail "cannot compute the V1 module's CREATE2 address (got '$V1')"
code="$(cast code --rpc-url "$RPC" "$V1")"
[[ -n "$code" && "$code" != 0x ]] || fail "the V1 module is not at its CREATE2 address $V1"

MEMBER_SBT="$(create src/core_membership/CitrateMemberSBT.sol:CitrateMemberSBT "$GOVERNANCE_TIMELOCK")"
ORG_SBT="$(create src/cit_agent/OrganizationSBT.sol:OrganizationSBT "$GOVERNANCE_TIMELOCK")"
AGENT_SBT="$(create src/cit_agent/AgentSBT.sol:AgentSBT "$GOVERNANCE_TIMELOCK" "$ORG_SBT" "$MEMBER_SBT")"
[ -n "$MEMBER_SBT" ] && [ -n "$ORG_SBT" ] && [ -n "$AGENT_SBT" ] || fail "HUP stand-in deploy failed"

python3 - "$CONTRACTS/$V060_INPUT_BOOK" "$GOV_JSON" "$OUT/dormant.json" "$DEPLOYER" "$V1" "$ORG_SBT" "$AGENT_SBT" <<'PY'
import json, sys
out, gov, dorm, dep, v1, org, agent = sys.argv[1:]
c = {}
for p in (gov, dorm):
    c.update(json.load(open(p))["contracts"])
c.update({"OrganizationSBT": org, "AgentSBT": agent})
json.dump({"deployer": dep, "contracts": c, "aaStack": {"GuardianRecoveryModule": v1}}, open(out, "w"), indent=2)
PY

echo "=== negatives before the real run (each refused, nothing sent) ==="
before="$(nonce "$DEPLOYER")"
if forge script script/DeployV060Genesis.s.sol --rpc-url "$RPC" --broadcast --private-key "$KEY" >"$OUT/neg-bonds.log" 2>&1; then
  fail "DeployV060Genesis ran without the coordinator bonds"
fi
grep -q "REQUIRED INPUT: the WorkMarket coordinator bonds" "$OUT/neg-bonds.log" || fail "no-bonds run: not refused on the missing bonds"
if env "${BONDS[@]}" GENESIS_RETIRED_KEYS="${GRD_LIST[1]}" forge script script/DeployV060Genesis.s.sol --rpc-url "$RPC" \
  --broadcast --private-key "$KEY" >"$OUT/neg-retired.log" 2>&1; then
  fail "DeployV060Genesis ran with a council owner on the retired list"
fi
grep -q "GUARDIAN owner is a key retired at the r1007 ceremony" "$OUT/neg-retired.log" || fail "retired-owner run: not refused on the retired key"
if env "${BONDS[@]}" GENESIS_GUARDIAN_VETO_MARGIN=3600 forge script script/DeployV060Genesis.s.sol --rpc-url "$RPC" \
  --broadcast --private-key "$KEY" >"$OUT/neg-margin.log" 2>&1; then
  fail "DeployV060Genesis ran with a margin other than the decided 7200 s"
fi
grep -q "is not the owner's decided value" "$OUT/neg-margin.log" || fail "margin run: not refused on the decided value"
[ "$(nonce "$DEPLOYER")" = "$before" ] || fail "a refused DeployV060Genesis run sent a transaction"
echo "refused (no bonds, retired council owner, undecided margin), nothing sent"

export "${BONDS[@]}"
run_script script/DeployV060Genesis.s.sol
V060_JSON="$OUT/v060-genesis.json"
[ -f "$V060_JSON" ] || fail "DeployV060Genesis wrote no book"

echo "=== forge script DeployV060Genesis --sig verifyBook() (read-only) ==="
forge script script/DeployV060Genesis.s.sol --sig 'verifyBook()' --rpc-url "$RPC" >"$OUT/verify.log" 2>&1 || {
  tail -20 "$OUT/verify.log" >&2
  fail "verifyBook FAILED"
}
grep -q "V060 verify PASS" "$OUT/verify.log" || fail "verifyBook did not report PASS"

cast rpc --rpc-url "$RPC" anvil_setCode "$P256_VERIFIER" 0x600160005260206000f3 >/dev/null
echo "=== forge script CheckDeployedAdmins over the governance, dormant-ledger and 0.6.0 books ==="
env ADDRESS_BOOK="$OUT_REL/governance.json" EXTRA_ADDRESS_BOOKS="$DORMANT_LEDGERS_OUT,$V060_GENESIS_OUT" REQUIRE_ALL_CODE=true \
  forge script script/CheckDeployedAdmins.s.sol --rpc-url "$RPC" >"$OUT/gate.log" 2>&1 || true
grep -q "Script ran successfully" "$OUT/gate.log" || { tail -30 "$OUT/gate.log" >&2; fail "gate FAILED"; }
for class in "FACTORY-ADMIN" "DEPLOYER-ADMIN" "TIMELOCK-HOLDERS" "GENESIS-FLOOR"; do
  grep -qE "^ *${class} failures: 0$" "$OUT/gate.log" || fail "gate: ${class} failures not 0"
done

CANCELLER_ROLE="$(cast keccak CANCELLER_ROLE)"
V2="$(book "$GOV_JSON" GuardianCanceller)"
[ "$(cast call --rpc-url "$RPC" "$GOVERNANCE_TIMELOCK" 'hasRole(bytes32,address)(bool)' "$CANCELLER_ROLE" "$V2")" = true ] ||
  fail "GuardianCancellerV2 does not hold CANCELLER on the GOVERNANCE timelock"
WM="$(book "$V060_JSON" WorkMarket)"
[ "$(cast call --rpc-url "$RPC" "$WM" 'slashSink()(address)' | tr 'A-F' 'a-f')" = "$(echo "$GOVERNANCE_TIMELOCK" | tr 'A-F' 'a-f')" ] ||
  fail "WorkMarket.slashSink is not the GOVERNANCE timelock"
echo "genesis-pipeline-anvil-v060: rehearsal PASS (verifyBook PASS; 0 FACTORY-ADMIN / DEPLOYER-ADMIN / TIMELOCK-HOLDERS / GENESIS-FLOOR)"

echo "=== negative: verifyBook after the allowlist changes (GOVERNANCE impersonated) ==="
TV="$(book "$V060_JSON" TaskVerifier)"
cast rpc --rpc-url "$RPC" anvil_impersonateAccount "$GOVERNANCE_TIMELOCK" >/dev/null
cast rpc --rpc-url "$RPC" anvil_setBalance "$GOVERNANCE_TIMELOCK" 0x56BC75E2D63100000 >/dev/null
cast send --rpc-url "$RPC" --unlocked --from "$GOVERNANCE_TIMELOCK" "$WM" 'setVerifierAllowed(address,bool)' "$TV" false >/dev/null
if forge script script/DeployV060Genesis.s.sol --sig 'verifyBook()' --rpc-url "$RPC" >"$OUT/neg-verify.log" 2>&1; then
  fail "verifyBook passed after the verifier allowlist changed"
fi
grep -q "WorkMarket: verifier allowlist" "$OUT/neg-verify.log" || fail "verifyBook: not refused on the allowlist"
echo "refused (verifyBook caught the changed allowlist)"
echo "genesis-pipeline-anvil-v060: PASS"
