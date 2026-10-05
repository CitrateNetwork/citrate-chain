#!/usr/bin/env bash
# hup-redeploy-dryrun.sh: rehearse the HUP-S7.1 registry redeploy on a LOCAL anvil.
#
# Never touches chain 40204 with a transaction: it starts its own anvil on a free
# loopback port, checks that the endpoint it talks to IS that anvil, deploys with an
# impersonated (unlocked) sender, makes one state-changing smoke call per registry,
# and runs the book tool against a temporary copy of the book.
#
#   scripts/ops/hup-redeploy-dryrun.sh            # fork mode: anvil forks rpc.citrate.ai (chain id 40204)
#   scripts/ops/hup-redeploy-dryrun.sh --fresh    # empty anvil (chain id 31337), timelock deployed by the script
#
# Fork mode exercises the 40204 rules (admin must be a deployed multisig, never the
# deployer; ceremony-owned registries must already have code) against today's chain
# state. After the reroll, point HUP_FORK_RPC at the new chain to rehearse on it.
#
# Env (all optional):
#   HUP_FORK_RPC         read-only RPC to fork (default https://rpc.citrate.ai)
#   HUP_REGISTRY_ADMIN   admin multisig (fork default: the book's CitAgentTimelock)
#   DEPLOYER_ADDRESS     impersonated deployer (fork default: the book's deployer)
#   HUP_DRYRUN_KEEP=1    keep the temp dir (broadcast + book copy) for inspection
#   HUP_DRYRUN_POST_HOOK executable run (fork mode) after the book and provenance tools, with
#                        HUP_DRYRUN_RPC / _BOOK / _GENESIS / _PROVENANCE set; its failure fails the run
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$ROOT/contracts"
BOOK="$CONTRACTS/addresses/40204.json"
MODE=fork
[[ "${1:-}" == "--fresh" ]] && MODE=fresh
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { sed -n '2,24p' "$0"; exit 0; }

for bin in anvil forge cast python3; do
  command -v "$bin" >/dev/null || { echo "dryrun: $bin not found" >&2; exit 2; }
done

TMP="$(mktemp -d "${TMPDIR:-/tmp}/hup-dryrun.XXXXXX")"
ANVIL_PID=""
cleanup() {
  [[ -n "$ANVIL_PID" ]] && kill "$ANVIL_PID" 2>/dev/null || true
  if [[ "${HUP_DRYRUN_KEEP:-0}" == "1" ]]; then echo "dryrun: kept $TMP"; else rm -rf "$TMP"; fi
}
trap cleanup EXIT

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
RPC="http://127.0.0.1:$PORT"

if [[ "$MODE" == fork ]]; then
  FORK="${HUP_FORK_RPC:-https://rpc.citrate.ai}"
  echo "dryrun: forking $FORK on $RPC"
  anvil --fork-url "$FORK" --port "$PORT" --host 127.0.0.1 >"$TMP/anvil.log" 2>&1 &
else
  echo "dryrun: fresh anvil (chain id 31337) on $RPC"
  anvil --chain-id 31337 --port "$PORT" --host 127.0.0.1 >"$TMP/anvil.log" 2>&1 &
fi
ANVIL_PID=$!

for _ in $(seq 1 60); do
  cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
  sleep 1
done
CLIENT="$(cast rpc --rpc-url "$RPC" web3_clientVersion 2>/dev/null | tr -d '"')"
[[ "$CLIENT" == anvil/* ]] || { echo "dryrun: $RPC is not our anvil ($CLIENT); refusing" >&2; exit 3; }
CHAIN="$(cast chain-id --rpc-url "$RPC")"
echo "dryrun: $CLIENT, chain id $CHAIN"

book_get() { python3 -c 'import json,sys; b=json.load(open(sys.argv[1])); print(b.get("contracts",{}).get(sys.argv[2]) or b.get(sys.argv[2]) or "")' "$BOOK" "$1"; }
unlock() {
  cast rpc --rpc-url "$RPC" anvil_impersonateAccount "$1" >/dev/null
  cast rpc --rpc-url "$RPC" anvil_setBalance "$1" 0x56BC75E2D63100000 >/dev/null # 100 SALT
}

export FOUNDRY_BROADCAST="$TMP/broadcast"   # never write the operator's broadcast dir
export HUP_BOOK_PATH="addresses/40204.json"
if [[ "$MODE" == fork ]]; then
  export DEPLOYER_ADDRESS="${DEPLOYER_ADDRESS:-$(book_get deployer)}"
  export HUP_REGISTRY_ADMIN="${HUP_REGISTRY_ADMIN:-$(book_get CitAgentTimelock)}"
  [[ -n "$HUP_REGISTRY_ADMIN" ]] || { echo "dryrun: no admin (set HUP_REGISTRY_ADMIN)" >&2; exit 4; }
else
  export DEPLOYER_ADDRESS="${DEPLOYER_ADDRESS:-0x00000000000000000000000000000000000d3901}"
  export HUP_TIMELOCK_OWNER_0=0x00000000000000000000000000000000000a0001
  export HUP_TIMELOCK_OWNER_1=0x00000000000000000000000000000000000a0002
  export HUP_TIMELOCK_OWNER_2=0x00000000000000000000000000000000000a0003
  unset HUP_REGISTRY_ADMIN
fi
unlock "$DEPLOYER_ADDRESS"

echo "dryrun: deploying (sender $DEPLOYER_ADDRESS)"
( cd "$CONTRACTS" && forge script script/DeployHupRegistries.s.sol \
    --rpc-url "$RPC" --broadcast --unlocked --sender "$DEPLOYER_ADDRESS" --slow ) | tee "$TMP/deploy.log"

pin() { awk -v k="$1" '$0 ~ "^ *"k" +:" {print $NF}' "$TMP/deploy.log" | tail -1; }
ADMIN="$(pin admin)"; ORG="$(pin OrganizationSBT)"; AGENT="$(pin AgentSBT)"; CAPS="$(pin CapsuleRegistry)"
ANCH="$(pin AnchorRegistry)"; BENCH="$(pin BenchmarkRegistry)"; SKILL="$(pin SkillRegistry)"
for v in ADMIN ORG AGENT CAPS ANCH BENCH SKILL; do
  [[ "${!v}" =~ ^0x[0-9a-fA-F]{40}$ ]] || { echo "dryrun: could not read $v from the deploy log" >&2; exit 5; }
done

MEMBER=0x00000000000000000000000000000000000b0001
unlock "$ADMIN"; unlock "$MEMBER"
send() { cast send --rpc-url "$RPC" --unlocked --from "$@" >/dev/null; }
call() { cast call --rpc-url "$RPC" "$@"; }
expect() { [[ "$2" == "$3" ]] || { echo "dryrun: SMOKE FAIL $1: got $2, want $3" >&2; exit 6; }; echo "  ok  $1"; }

echo "dryrun: smoke calls"
ORG_ID="$(call "$ORG" 'nextTokenId()(uint256)')"
send "$ADMIN" "$ORG" 'mintOrg(address,bytes32,address,bytes32[])' "$MEMBER" "$(cast keccak dryrun-org)" "$MEMBER" '[]'
expect "OrganizationSBT.mintOrg by admin" "$(call "$ORG" 'isActive(uint256)(bool)' "$ORG_ID")" true
AGENT_ID="$(call "$AGENT" 'nextTokenId()(uint256)')"
send "$ADMIN" "$AGENT" 'mintAgent(address,uint256,bytes32,bytes32)' "$MEMBER" "$ORG_ID" "$(cast keccak dryrun-agent)" "$(cast keccak dryrun-fp)"
expect "AgentSBT.mintAgent by admin" "$(call "$AGENT" 'ownerOf(uint256)(address)' "$AGENT_ID" | tr 'A-F' 'a-f')" "$(echo "$MEMBER" | tr 'A-F' 'a-f')"
if cast send --rpc-url "$RPC" --unlocked --from "$MEMBER" "$AGENT" 'mintAgent(address,uint256,bytes32,bytes32)' "$MEMBER" "$ORG_ID" "$(cast keccak x)" "$(cast keccak y)" >/dev/null 2>&1; then
  echo "dryrun: SMOKE FAIL AgentSBT.mintAgent accepted a non-admin" >&2; exit 6
fi
echo "  ok  AgentSBT.mintAgent refuses a non-admin"
CAP_ID="$(cast to-dec "$(cast keccak dryrun-capsule)")"
send "$MEMBER" "$CAPS" 'registerCapsule(uint256,bytes32,bytes32,uint8)' "$CAP_ID" "$(cast keccak manifest)" "$(cast keccak did)" 2
expect "CapsuleRegistry.registerCapsule (workspace)" "$(call "$CAPS" 'isRevoked(uint256)(bool)' "$CAP_ID")" false
ROOT_HASH="$(cast keccak dryrun-day)"
send "$MEMBER" "$ANCH" 'anchor(uint8,bytes32)' 2 "$ROOT_HASH"
send "$ADMIN" "$ANCH" 'anchor(uint8,bytes32)' 2 "$ROOT_HASH"   # a second committer of the same root is recorded
expect "AnchorRegistry.anchor (committer 1)" "$(call "$ANCH" 'isAnchoredBy(address,bytes32)(bool)' "$MEMBER" "$ROOT_HASH")" true
expect "AnchorRegistry.anchor (committer 2)" "$(call "$ANCH" 'isAnchoredBy(address,bytes32)(bool)' "$ADMIN" "$ROOT_HASH")" true
expect "AnchorRegistry.rootsByKind max page" "$(call "$ANCH" 'rootsByKind(uint8,uint256,uint256)(bytes32[])' 2 0 "$(cast max-uint)")" "[$ROOT_HASH]"
send "$MEMBER" "$BENCH" 'record(uint256,bytes32,bytes32,uint256)' "$AGENT_ID" "$(cast keccak dryrun-capsule)" "$(cast keccak toolcall_pass)" 87
expect "BenchmarkRegistry.record" "$(call "$BENCH" 'metricCount(address,uint256,bytes32,bytes32)(uint256)' "$MEMBER" "$AGENT_ID" "$(cast keccak dryrun-capsule)" "$(cast keccak toolcall_pass)")" 1
send "$MEMBER" "$SKILL" 'registerSkill(string,string,string,string,string[])' dryrun-skill 1.0.0 "" "rehearsal" '["hermes-learned"]'
expect "SkillRegistry.registerSkill" "$(call "$SKILL" 'skillHashOf(address,string,string)(bytes32)' "$MEMBER" dryrun-skill 1.0.0)" \
  "$(cast keccak "$(cast abi-encode 'f(address,string,string)' "$MEMBER" dryrun-skill 1.0.0)")"

if [[ "$CHAIN" == 40204 ]]; then
  echo "dryrun: book tool against the fork (temp copy of the book)"
  cp "$BOOK" "$TMP/40204.json"
  GEN="$(cast block 0 --rpc-url "$RPC" --field hash)"
  python3 "$ROOT/scripts/ops/hup-book-update.py" \
    --broadcast "$TMP/broadcast/DeployHupRegistries.s.sol/40204/run-latest.json" \
    --book "$TMP/40204.json" --admin "$ADMIN" --rpc "$RPC" --genesis "$GEN"
  echo "dryrun: provenance ledger (temp copy) from the same broadcast"
  cp "$CONTRACTS/addresses/40204.provenance.json" "$TMP/40204.provenance.json"
  python3 "$ROOT/scripts/ops/hup-provenance-update.py" \
    --broadcast "$TMP/broadcast/DeployHupRegistries.s.sol/40204/run-latest.json" \
    --book "$TMP/40204.json" --provenance "$TMP/40204.provenance.json" --rpc "$RPC" --genesis "$GEN" \
    --backfill --scan-rpc "$FORK"
  if [[ -n "${HUP_DRYRUN_POST_HOOK:-}" ]]; then
    # A consumer's rehearsal (for example citrate-core scripts/anvil-sync-addresses.sh) runs
    # here, while the fork is still up, against the temp book.
    echo "dryrun: post hook $HUP_DRYRUN_POST_HOOK"
    HUP_DRYRUN_RPC="$RPC" HUP_DRYRUN_BOOK="$TMP/40204.json" HUP_DRYRUN_GENESIS="$GEN" \
      HUP_DRYRUN_PROVENANCE="$TMP/40204.provenance.json" "$HUP_DRYRUN_POST_HOOK"
  fi
else
  echo "dryrun: book tool skipped (it accepts chain 40204 only; use fork mode)"
fi
echo "dryrun: PASS ($MODE)"
