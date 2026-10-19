#!/usr/bin/env bash
# Export a fixture snapshot of every chain read in the UI truth contract
# (docs/ui-truth/UI_TRUTH_CONTRACT.md), so design and core build against real values.
#
#   scripts/ui-truth/export-fixtures.sh [rpc_url] [out_file]
#
# Read-only: eth_* calls and cast call only. No keys, no transactions. Addresses
# come from contracts/addresses/40204.json, the only address source. Every value is
# recorded with the method that produced it and the block it was read at, so a screen
# showing a fixture can name its source.
set -euo pipefail

cd "$(dirname "$0")/../.."
RPC="${1:-https://rpc.citrate.ai}"
BOOK=contracts/addresses/40204.json
OUT="${2:-docs/ui-truth/fixtures/40204-$(date -u +%Y-%m-%d).json}"
command -v cast >/dev/null || { echo "cast (foundry) is required" >&2; exit 1; }

addr() { jq -er --arg k "$1" '.contracts[$k] // .[$k] // .governance[$k]' "$BOOK"; }
rpc() { curl -fsS -X POST -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$RPC" | jq -c 'if has("result") then .result else {error: .error} end'; }

BLOCK=$(cast block-number --rpc-url "$RPC")
rows=()
row() {  # id source value-json
  rows+=("$(jq -cn --arg id "$1" --arg src "$2" --argjson v "$3" '{id:$id, source:$src, value:$v}')")
}
call() {  # id contract-key signature [args...] — read at the pinned block
  local id=$1 key=$2 sig=$3; shift 3
  local a v; a=$(addr "$key")
  if v=$(cast call --rpc-url "$RPC" --block "$BLOCK" "$a" "$sig" "$@" 2>/dev/null); then
    row "$id" "eth_call $key($a).$sig" "$(jq -cn --arg v "$v" '$v')"
  else
    row "$id" "eth_call $key($a).$sig" '{"error":"call reverted or unavailable"}'
  fi
}

# Node-level (RPC). Only the reads the contract allows; see the "never show" list.
row chain_id        "eth_chainId"                       "$(rpc eth_chainId '[]')"
row genesis_hash    "eth_getBlockByNumber(0x0).hash"    "$(rpc eth_getBlockByNumber '["0x0",false]' | jq -c .hash)"
row head_height     "eth_blockNumber (stored height)"   "$(jq -cn --argjson b "$BLOCK" '$b')"
row syncing         "eth_syncing"                       "$(rpc eth_syncing '[]')"
row peer_count      "net_peerCount (this RPC node's direct peers)" "$(rpc net_peerCount '[]')"
row base_fee        "eth_getBlockByNumber(latest).baseFeePerGas" "$(rpc eth_getBlockByNumber '["latest",false]' | jq -c .baseFeePerGas)"
t1=$(rpc eth_getBlockByNumber "[\"$(printf '0x%x' "$BLOCK")\",false]" | jq -r .timestamp)
t0=$(rpc eth_getBlockByNumber "[\"$(printf '0x%x' $((BLOCK-100)))\",false]" | jq -r .timestamp)
row block_time_s    "timestamp delta over the last 100 blocks" "$(jq -cn --argjson a $((t1)) --argjson b $((t0)) '($a-$b)/100')"
for h in 365784 365785; do
  row "checkpoint_$h" "eth_getBlockByNumber($h).hash (canonical checkpoint)" \
    "$(rpc eth_getBlockByNumber "[\"$(printf '0x%x' $h)\",false]" | jq -c .hash)"
done

# Validators and rewards (ValidatorRegistry is the only producer source).
call validator_active_count ValidatorRegistry "activeCount()(uint256)"
call validator_min_stake    ValidatorRegistry "minStake()(uint256)"
call block_subsidy          ValidatorRegistry "blockSubsidy()(uint256)"
call max_epoch_emission     ValidatorRegistry "maxEpochEmission()(uint256)"
call current_epoch          ValidatorRegistry "currentEpoch()(uint256)"
call validator_active_set   ValidatorRegistry "activeSet()(bytes32[],uint256[])"

# Membership (Track M).
call grants_issued          MembershipStakeVault "nextGrantId()(uint256)"
call member_tokens_minted   CitrateMemberSBT     "nextTokenId()(uint256)"

# Storage, Store registries.
call pin_bond               IPFSIncentivesV3 "BOND()(uint256)"
call pin_reward_total       IPFSIncentivesV3 "REWARD()(uint256)"
call pin_rounds             IPFSIncentivesV3 "ROUNDS()(uint256)"
call skills_registered      SkillRegistry    "totalSkills()(uint256)"
call models_registered      ModelRegistry    "totalModels()(uint256)"

# Governance.
call governance_min_delay_s GOVERNANCE "minDelay()(uint256)"
call guardian_min_delay_s   GUARDIAN   "minDelay()(uint256)"

mkdir -p "$(dirname "$OUT")"
printf '%s\n' "${rows[@]}" | jq -s --arg rpc "$RPC" --argjson block "$BLOCK" \
  --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg book "$(jq -r .deployedAt "$BOOK")" \
  '{fixture: true, label: "FIXTURE — captured from 40204, not live", captured_at: $at,
    rpc: $rpc, read_at_block: $block, address_book_deployed_at: $book, reads: .}' > "$OUT"
echo "wrote $OUT ($(jq '.reads | length' "$OUT") reads at block $BLOCK)"
