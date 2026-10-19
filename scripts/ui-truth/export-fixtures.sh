#!/usr/bin/env bash
# Export a fixture snapshot of every chain read in the UI truth contract
# (docs/ui-truth/UI_TRUTH_CONTRACT.md), so design and core build against real values.
#
#   scripts/ui-truth/export-fixtures.sh [rpc_url] [out_file]
#
# Read-only: eth_* calls and cast call only. No keys, no transactions. Addresses
# come from contracts/addresses/40204.json, the only address source.
#
# The node serves LATEST committed state for every block tag (there are no per-height
# historical state reads; core/api/src/eth_rpc.rs), so an export is not a single-block
# snapshot, and the reads are NOT mutually consistent: registry state (registrations,
# stake changes, executed params) can change in any block. Each read therefore records the
# head it was observed at and is labelled `state: latest`. The file also records whether
# the export crossed an epoch boundary and whether the head moved at all; neither is a
# consistency guarantee.
set -euo pipefail

cd "$(dirname "$0")/../.."
RPC="${1:-https://rpc.citrate.ai}"
BOOK="${UI_TRUTH_BOOK:-contracts/addresses/40204.json}"
OUT="${2:-docs/ui-truth/fixtures/40204-$(date -u +%Y-%m-%d).json}"
EPOCH=1000              # ValidatorRegistry.EPOCH()
PRODUCER_WINDOW=1000    # contract §2: distinct proposers over the last 1,000 blocks
command -v cast >/dev/null || { echo "cast (foundry) is required" >&2; exit 1; }

addr() { jq -er --arg k "$1" '.contracts[$k] // .[$k] // .governance[$k]' "$BOOK"; }
rpc() { curl -fsS -X POST -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$RPC" | jq -c 'if has("result") then .result else {error: .error} end'; }
# The head must be a real quantity: a failed or malformed eth_blockNumber aborts the export
# (no file is written) instead of being recorded as block 0.
head_now() {
  local q; q=$(curl -fsS -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' "$RPC" 2>/dev/null \
    | jq -r '.result // empty' 2>/dev/null) || q=""
  if [[ ! "$q" =~ ^0x[0-9a-fA-F]+$ ]]; then
    echo "export-fixtures: eth_blockNumber unavailable or malformed (${q:-no response}); no fixture written" >&2
    exit 3
  fi
  printf '%d' "$q"
}

HEAD_START=$(head_now)
rows=()
row() {  # id source value-json — stamped with the head observed just before the read
  rows+=("$(jq -cn --arg id "$1" --arg src "$2" --argjson v "$3" --argjson h "$OBSERVED" \
    '{id:$id, source:$src, state:"latest", observed_head:$h, value:$v}')")
}
call() {  # id contract-key signature [args...]
  local id=$1 key=$2 sig=$3; shift 3
  local a v; a=$(addr "$key"); OBSERVED=$(head_now)
  if v=$(cast call --rpc-url "$RPC" "$a" "$sig" "$@" 2>/dev/null); then
    row "$id" "eth_call $key($a).$sig" "$(jq -cn --arg v "$v" '$v')"
  else
    row "$id" "eth_call $key($a).$sig" '{"error":"call reverted or unavailable"}'
  fi
}

# Node-level (RPC). Only the reads the contract allows; see the "never show" list.
OBSERVED=$(head_now); row chain_id      "eth_chainId"                    "$(rpc eth_chainId '[]')"
OBSERVED=$(head_now); row genesis_hash  "eth_getBlockByNumber(0x0).hash" "$(rpc eth_getBlockByNumber '["0x0",false]' | jq -c .hash)"
OBSERVED=$(head_now); row head_height   "eth_blockNumber (stored height)" "$OBSERVED"
OBSERVED=$(head_now); row syncing       "eth_syncing"                    "$(rpc eth_syncing '[]')"
OBSERVED=$(head_now); row peer_count    "net_peerCount (the queried RPC node's direct peers, not a member's node)" "$(rpc net_peerCount '[]')"
OBSERVED=$(head_now); row base_fee      "eth_getBlockByNumber(latest).baseFeePerGas" "$(rpc eth_getBlockByNumber '["latest",false]' | jq -c .baseFeePerGas)"
OBSERVED=$(head_now)
t1=$(rpc eth_getBlockByNumber "[\"$(printf '0x%x' "$OBSERVED")\",false]" | jq -r .timestamp)
t0=$(rpc eth_getBlockByNumber "[\"$(printf '0x%x' $((OBSERVED-100)))\",false]" | jq -r .timestamp)
# RPC values never reach shell arithmetic unvalidated: Bash evaluates expressions (and array
# subscripts) inside $(( )), so only a bounded hex quantity is converted; anything else makes
# the metric unavailable.
if [[ "$t1" =~ ^0x[0-9a-fA-F]{1,15}$ && "$t0" =~ ^0x[0-9a-fA-F]{1,15}$ ]]; then
  bt=$(jq -cn --argjson a "$(printf '%d' "$t1")" --argjson b "$(printf '%d' "$t0")" '($a-$b)/100')
else
  bt='{"unavailable":true,"reason":"block timestamp missing or malformed"}'
fi
row block_time_s "timestamp delta over the 100 blocks ending at observed_head" "$bt"
for h in 365784 365785; do
  OBSERVED=$(head_now)
  row "checkpoint_$h" "eth_getBlockByNumber($h).hash (canonical checkpoint)" \
    "$(rpc eth_getBlockByNumber "[\"$(printf '0x%x' $h)\",false]" | jq -c .hash)"
done

# Producing validators (contract §2): distinct proposerPubkey over the window, fetched in
# JSON-RPC batches of 100 blocks. Every block in the window must come back as a successful
# response with a 32-byte proposer key; otherwise the value is reported as unavailable
# (with how many blocks came back), never as a count. Shown next to active validators.
OBSERVED=$(head_now)
lo=$(( OBSERVED - PRODUCER_WINDOW + 1 )); [ "$lo" -lt 1 ] && lo=1
want=$(( OBSERVED - lo + 1 ))
keys=$(for (( s=lo; s<=OBSERVED; s+=100 )); do
  e=$(( s + 99 )); [ "$e" -gt "$OBSERVED" ] && e=$OBSERVED
  batch=$(for (( h=s; h<=e; h++ )); do printf '{"jsonrpc":"2.0","id":%d,"method":"eth_getBlockByNumber","params":["0x%x",false]},' "$h" "$h"; done)
  # A failed batch (HTTP error, dropped connection, malformed JSON) contributes nothing; the
  # completeness check below then reports the sample as unavailable instead of aborting.
  body=$(curl -fsS -X POST -H 'content-type: application/json' --data "[${batch%,}]" "$RPC" 2>/dev/null) || body=""
  printf '%s' "$body" \
    | jq -r '.[]? | select(.result != null and (.result.proposerPubkey // "" | test("^0x[0-9a-fA-F]{64}$"))) | "\(.id) \(.result.proposerPubkey)"' 2>/dev/null \
    || true
done | sort -u -k1,1n || true)
got=$(printf '%s\n' "$keys" | grep -c . || true)
if [ "$got" -eq "$want" ]; then
  producing=$(jq -cn --argjson n "$(printf '%s\n' "$keys" | awk '{print $2}' | sort -u | grep -c .)" \
    --argjson lo "$lo" --argjson hi "$OBSERVED" '{count:$n, from_block:$lo, to_block:$hi}')
else
  producing=$(jq -cn --argjson got "$got" --argjson want "$want" --argjson lo "$lo" --argjson hi "$OBSERVED" \
    '{unavailable:true, reason:"producer sample incomplete", blocks_returned:$got, blocks_requested:$want, from_block:$lo, to_block:$hi}')
fi
row producing_validators \
  "distinct eth_getBlockByNumber(n).proposerPubkey for n in [$lo, $OBSERVED]" "$producing"

# Validators and rewards (ValidatorRegistry is the only producer source).
call registered_validators  ValidatorRegistry "activeCount()(uint256)"
call validator_min_stake    ValidatorRegistry "minStake()(uint256)"
call block_subsidy          ValidatorRegistry "blockSubsidy()(uint256)"
call max_epoch_emission     ValidatorRegistry "maxEpochEmission()(uint256)"
call current_epoch          ValidatorRegistry "currentEpoch()(uint256)"
call validator_active_set   ValidatorRegistry "activeSet()(bytes32[],uint256[])"

# Eligible validators (LIVE registry): members of the current registry set whose activation
# epoch has come (validatorInfo.actEpoch <= currentEpoch). This is not consensus membership:
# consensus uses the governing epoch snapshot S(E) (node registry_sync / vrf), which no RPC
# exposes yet, so a validator that registered or exited after the snapshot differs here for up
# to an epoch. Consensus membership is exported as unavailable until such a source exists.
OBSERVED=$(head_now)
VR=$(addr ValidatorRegistry)
cur_epoch=$(cast call --rpc-url "$RPC" "$VR" "currentEpoch()(uint256)" 2>/dev/null | awk '{print $1}') || cur_epoch=""
keys_raw=$(cast call --rpc-url "$RPC" "$VR" "activeSet()(bytes32[],uint256[])" 2>/dev/null | head -1) || keys_raw=""
active=0; pending=0; unknown=0
if [[ "$cur_epoch" =~ ^[0-9]+$ ]] && [ -n "$keys_raw" ]; then
  for k in $(printf '%s' "$keys_raw" | tr -d '[] ' | tr ',' ' '); do
    ae=$(cast call --rpc-url "$RPC" "$VR" \
      "validatorInfo(bytes32)(address,uint256,uint256,uint256,uint256,uint64,uint64,uint64,uint8,uint256)" "$k" 2>/dev/null \
      | sed -n 6p | awk '{print $1}') || ae=""
    if [[ ! "$ae" =~ ^[0-9]+$ ]]; then unknown=$((unknown + 1))
    elif [ "$ae" -le "$cur_epoch" ]; then active=$((active + 1))
    else pending=$((pending + 1)); fi
  done
  if [ "$unknown" -eq 0 ]; then
    cav=$(jq -cn --argjson a "$active" --argjson p "$pending" --argjson e "$cur_epoch" \
      '{count:$a, pending_activation:$p, current_epoch:$e}')
  else
    cav=$(jq -cn --argjson u "$unknown" '{unavailable:true, reason:"validatorInfo read failed", unreadable:$u}')
  fi
else
  cav='{"unavailable":true,"reason":"currentEpoch or activeSet read failed"}'
fi
row eligible_validators \
  "live ValidatorRegistry activeSet() members with validatorInfo(pubkey).actEpoch <= currentEpoch()" "$cav"
row consensus_validator_set "governing epoch snapshot S(E) (node-internal)" \
  '{"unavailable":true,"reason":"no RPC exposes the governing consensus snapshot yet (contract §9)"}' 

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

HEAD_END=$(head_now)
mkdir -p "$(dirname "$OUT")"
printf '%s\n' "${rows[@]}" | jq -s --arg rpc "$RPC" --argjson hs "$HEAD_START" --argjson he "$HEAD_END" \
  --argjson ep "$EPOCH" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg book "$(jq -r .deployedAt "$BOOK")" \
  '{fixture: true, label: "FIXTURE — captured from 40204, not live", captured_at: $at, rpc: $rpc,
    state: "latest (the node serves latest committed state for every block tag; no historical reads)",
    head_at_start: $hs, head_at_end: $he,
    epoch_at_start: (($hs / $ep) | floor), epoch_at_end: (($he / $ep) | floor),
    single_epoch: ((($hs / $ep) | floor) == (($he / $ep) | floor)),
    head_moved: ($hs != $he),
    consistency: "none: each read is latest state at its own observed_head",
    address_book_deployed_at: $book, reads: .}' > "$OUT"
consistent=$(jq -r .single_epoch "$OUT")
echo "wrote $OUT ($(jq '.reads | length' "$OUT") reads, head $HEAD_START→$HEAD_END, single_epoch=$consistent)"
[ "$consistent" = true ] || echo "WARNING: export crossed an epoch boundary (validator-set snapshots differ across reads). Re-run if that matters." >&2
