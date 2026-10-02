#!/usr/bin/env bash
# created: 2026-10-01 | branch: hup/n5-chain-fl | author: Larry Klosowski + Claude Opus 5.5 | status: active
#
# HUP-S9.2: one federated LoRA round end to end on a LOCAL devnet (never 40204).
#
#   coordinator (compute-pool) <-> 3 local device workers <-> 0x0110 on the devnet node
#   <-> FederatedRoundLedger record <-> challenge window <-> independent replay
#   <-> settlement (citrate-settlement gate -> PatronageLedger on the devnet)
#
# then a second, deliberately dishonest commit that a challenger proves wrong on chain
# through the same precompile, which settlement then refuses.
#
# Everything signs with throwaway keys on a throwaway devnet: this is the dry run the
# production path never does (there, every transaction is an unsigned intent for the
# operator's ceremony). The training step uses `fl_fixture_trainer`, which follows the
# trainer contract but learns nothing; the receipt says so.
#
# Requirements (all local):
#   CITRATE_NODE_BIN  citrate node binary with `devnet` (default: the installed app's)
#   POOL_BIN          dir with citrate-training-coordinator, citrate-coop-worker,
#                     citrate-fl-round and examples/fl_fixture_trainer (compute-pool target)
#   SETL_BIN          dir with setl-fl-intents (citrate-settlement target)
#   REPLAY_BIN        citrate-fl-replay (this repo, tools/fl-replay)
#   COOP_DIR          citrate-coop/contracts (PatronageLedger source)
#   PROBE_JSON        a real nat divergence probe from this machine
#                     (nat: cargo run --release -p nat-candle --features metal --example divergence_probe)
# Optional:
#   BASE_MODEL        a GGUF base model (default: a tiny synthetic one; the adapter then
#                     cannot be loaded by llama-server, so that check is skipped)
#   LLAMA_SERVER      llama-server binary: load the merged adapter on BASE_MODEL
#   LLAMA_NGL         GPU layers for that check (default 0: CPU)
#   CHUNK_DIM         default 1024 with BASE_MODEL, 16 with the synthetic base
#   WINDOW            challenge window in blocks (default 30, about a minute of devnet blocks)
#   LEASE_SECS        lease per lora_delta job (default 1800; hashing a multi-GB base model
#                     in a debug build is slow)
#   WORK              working directory (default: a fresh temp dir)
#   FIXTURE_OUT       copy the honest round's bundle, deltas and adapters here
set -euo pipefail

say() { printf '\n== %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }
for t in cast forge jq python3 curl; do need "$t"; done

CHAIN_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CITRATE_NODE_BIN="${CITRATE_NODE_BIN:-/Applications/Citrate Core.app/Contents/MacOS/citrate}"
: "${POOL_BIN:?set POOL_BIN}" "${SETL_BIN:?set SETL_BIN}" "${REPLAY_BIN:?set REPLAY_BIN}"
: "${COOP_DIR:?set COOP_DIR}" "${PROBE_JSON:?set PROBE_JSON}"
WINDOW="${WINDOW:-30}"
WORK="${WORK:-$(mktemp -d)}"
RPC_PORT="${RPC_PORT:-18645}"
P2P_PORT="${P2P_PORT:-30645}"
COORD_PORT="${COORD_PORT:-18688}"
RPC="http://127.0.0.1:${RPC_PORT}"
mkdir -p "$WORK"
# Canonical paths: solc refuses imports reached through a symlinked prefix (/var -> /private/var).
WORK="$(cd "$WORK" && pwd -P)"
COOP_DIR="$(cd "$COOP_DIR" && pwd -P)"
RECEIPT="$WORK/receipt.json"
echo '{}' > "$RECEIPT"
note() { jq --arg k "$1" --argjson v "$2" '.[$k] = $v' "$RECEIPT" > "$RECEIPT.tmp" && mv "$RECEIPT.tmp" "$RECEIPT"; }

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

wait_until() { # timeout_secs description command...
  local t="$1" what="$2"; shift 2
  local end=$(( $(date +%s) + t ))
  until "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$end" ] || die "timed out waiting for $what"
    sleep 1
  done
}

# Submit without waiting, then poll for the receipt: under load the node can answer a
# receipt query with null for a while, which is "not yet", not a failure.
receipt() { # txhash -> receipt json (waits up to 120 s)
  local end=$(( $(date +%s) + 120 )) r
  while :; do
    r=$(cast receipt --rpc-url "$RPC" --json "$1" 2>/dev/null || true)
    if [ -n "$r" ] && [ "$(jq -r '.status // empty' <<<"$r" 2>/dev/null)" != "" ]; then
      printf '%s' "$r"; return 0
    fi
    [ "$(date +%s)" -lt "$end" ] || die "no receipt for $1"
    sleep 1
  done
}

send() { # key to sig-or-calldata [args...]
  local key="$1"; shift
  local h r; h=$(cast send --rpc-url "$RPC" --private-key "$key" --async "$@") || die "send failed: $*"
  r=$(receipt "$h")
  [ "$(jq -r .status <<<"$r")" = "0x1" ] || die "transaction reverted: $*"
  printf '%s\n' "$h"
}

create() { # key bytecode
  local h r; h=$(cast send --rpc-url "$RPC" --private-key "$1" --async --create "$2") || die "deploy failed"
  r=$(receipt "$h")
  [ "$(jq -r .status <<<"$r")" = "0x1" ] || die "deploy reverted"
  jq -r .contractAddress <<<"$r"
}

# ── 1. a fresh local devnet ────────────────────────────────────────
say "devnet"
# The foundry test mnemonic, assembled at run time: its first accounts are prefunded in
# the devnet genesis. Throwaway keys on a throwaway chain.
MN="$(printf 'test %.0s' 1 2 3 4 5 6 7 8 9 10 11)junk"
K_FUND="$(cast wallet private-key --mnemonic "$MN" --mnemonic-index 0)"
COINBASE="$(cast wallet address --mnemonic "$MN" --mnemonic-index 1)"
"$CITRATE_NODE_BIN" --data-dir "$WORK/node" --rpc-addr "127.0.0.1:${RPC_PORT}" \
  --p2p-addr "127.0.0.1:${P2P_PORT}" --coinbase "$COINBASE" devnet > "$WORK/node.log" 2>&1 &
PIDS+=($!)
wait_until 60 "the devnet RPC" cast block-number --rpc-url "$RPC"
[ "$(cast chain-id --rpc-url "$RPC")" = "1337" ] || die "not a devnet chain id"
start_block=$(cast block-number --rpc-url "$RPC")
block_past() { test "$(cast block-number --rpc-url "$RPC")" -gt "$1"; }
wait_until 60 "block production" block_past "$start_block"
note chain_id 1337

newkey() { cast wallet new --json | jq -r '.[0].private_key'; }
K_COORD=$(newkey); K_SETTLER=$(newkey); K_CHAL=$(newkey)
A_COORD=$(cast wallet address "$K_COORD"); A_SETTLER=$(cast wallet address "$K_SETTLER")
A_CHAL=$(cast wallet address "$K_CHAL")
for a in "$A_COORD" "$A_SETTLER" "$A_CHAL"; do
  send "$K_FUND" "$a" --value 100ether >/dev/null
done
WK=(); WA=()
for i in 1 2 3; do k=$(newkey); WK+=("$k"); WA+=("$(cast wallet address "$k" | tr 'A-F' 'a-f')"); done

# ── 2. contracts ───────────────────────────────────────────────────
say "deploy FederatedRoundLedger"
( cd "$CHAIN_DIR/contracts" && forge build src/FederatedRoundLedger.sol >/dev/null )
BC=$(jq -r .bytecode.object "$CHAIN_DIR/contracts/out/FederatedRoundLedger.sol/FederatedRoundLedger.json")
LEDGER=$(create "$K_COORD" "$BC")
note ledger "\"$LEDGER\""

# 0x0110 answers through the ledger on this node: the golden vector.
GOLDEN_IN=$(python3 - <<'PY'
import struct
rows=[[65536,-32768,0,100],[32768,-32768,0,50],[-16384,16384,0,25]]
b=struct.pack('>II',4,3)
for r in rows:
    for v in r: b+=struct.pack('>q',v)
for r in rows:
    for v in r: b+=struct.pack('>q',0 if v==0 else 65536)
b+=struct.pack('>qqq',21845,21845,21845)+struct.pack('>qq',32768,-32768)
print('0x'+b.hex())
PY
)
GOLDEN_OUT=$(cast call --rpc-url "$RPC" "$LEDGER" "belnapAggregate(bytes)(bytes)" "$GOLDEN_IN")
[ "$GOLDEN_OUT" = "0x0000000000006aa9ffffffffffffbfff0000000000000000000000000000003903030001" ] \
  || die "0x0110 on this node disagrees with the golden vector: $GOLDEN_OUT"
note golden_vector_on_node true

say "register the cluster"
SALT=$(cast keccak "hup-s9.2-devnet-cluster")
if [ -n "${BASE_MODEL:-}" ]; then CHUNK_DIM="${CHUNK_DIM:-1024}"; else CHUNK_DIM="${CHUNK_DIM:-16}"; fi
send "$K_COORD" "$LEDGER" "registerCluster(bytes32,(uint16,uint32,uint8,int64,int64,uint8,uint8,uint64))" \
  "$SALT" "(3,${CHUNK_DIM},8,32768,-32768,1,1,${WINDOW})" >/dev/null
CLUSTER=$(cast call --rpc-url "$RPC" "$LEDGER" "clusterIdOf(address,bytes32)(bytes32)" "$A_COORD" "$SALT")
note cluster_id "\"$CLUSTER\""

# ── 3. the round: base, start adapter, config, jobs ─────────────────
say "round config"
if [ -z "${BASE_MODEL:-}" ]; then
  BASE_MODEL="$WORK/tiny-base.gguf"
  python3 - "$BASE_MODEL" <<'PY'
# A tiny synthetic base: just enough tensor headers for init-adapter. Not a model.
import struct, sys
def s(x): b=x.encode(); return struct.pack('<Q',len(b))+b
kv=[('general.architecture',8,s('llama'))]
tensors=[]
for l in range(2):
    tensors.append((f'blk.{l}.attn_q.weight',[24,16]))
    tensors.append((f'blk.{l}.attn_v.weight',[24,8]))
h=b'GGUF'+struct.pack('<IQQ',3,len(tensors),len(kv))
for k,t,v in kv: h+=s(k)+struct.pack('<I',t)+v
off=0; datas=[]
for n,d in tensors:
    h+=s(n)+struct.pack('<I',len(d))+b''.join(struct.pack('<Q',x) for x in d)+struct.pack('<IQ',0,off)
    sz=4*d[0]*d[1]; datas.append(sz); off+=(sz+31)//32*32
h+=b'\0'*((-len(h))%32)
for sz in datas: h+=b'\0'*((sz+31)//32*32)
open(sys.argv[1],'wb').write(h)
PY
  SYNTHETIC_BASE=1
else
  SYNTHETIC_BASE=0
fi
BASE_SHA=$(shasum -a 256 "$BASE_MODEL" | cut -d' ' -f1)
"$POOL_BIN/citrate-fl-round" init-adapter --base "$BASE_MODEL" --rank 8 --alpha 16 \
  --targets attn_q,attn_v --seed 7 --out "$WORK/start.gguf" > "$WORK/start.json"
START_SHA=$(jq -r .sha256 "$WORK/start.json")
note start_adapter "$(cat "$WORK/start.json")"

ROSTER=$(printf '%s\n' "${WA[@]}" | sort | jq -R . | jq -s .)
jq -n --arg ledger "$LEDGER" --arg cluster "$CLUSTER" --arg base "0x$BASE_SHA" \
  --arg start "0x$START_SHA" --argjson roster "$ROSTER" --argjson chunk "$CHUNK_DIM" '{
  chain_id: 1337, ledger: $ledger, cluster_id: $cluster,
  base_model_sha256: $base, start_adapter_sha256: $start, roster: $roster,
  min_participants: 3, chunk_dim: $chunk, value_scale_log2: 8,
  threshold_pos: 32768, threshold_neg: -32768,
  confidence: "nonzero", weight: "uniform", max_values: 67108864 }' > "$WORK/round.json"
"$POOL_BIN/citrate-fl-round" config-hash --config "$WORK/round.json" --ordinal 0 > "$WORK/ids.json"
RID=$(jq -r .round_id "$WORK/ids.json")
RID_CHAIN=$(cast call --rpc-url "$RPC" "$LEDGER" "roundIdOf(bytes32,uint64)(bytes32)" "$CLUSTER" 0)
[ "$RID" = "$RID_CHAIN" ] || die "round id: Rust $RID vs ledger $RID_CHAIN"
note round_id "\"$RID\""
"$POOL_BIN/citrate-fl-round" jobs --config "$WORK/round.json" --ordinal 0 --lease-secs "${LEASE_SECS:-1800}" > "$WORK/jobs.json"

# ── 4. coordinator and three device workers ─────────────────────────
say "coordinator + 3 workers"
mkdir -p "$WORK/coord"
# The operator vouches its own cluster's devices, so a job one device declines is
# re-offered to another device at once instead of being held for vetted workers.
VOUCHED=$(IFS=,; echo "${WA[*]}")
CITRATE_COORDINATOR_STATE="$WORK/coord/state.json" CITRATE_COORDINATOR_BIND="127.0.0.1:${COORD_PORT}" \
CITRATE_COORDINATOR_JOBS="$WORK/jobs.json" CITRATE_COORDINATOR_OPEN_TIER=federated \
CITRATE_COORDINATOR_H01_WORKERS="$VOUCHED" \
CITRATE_COORDINATOR_FL_DELTA_DIR="$WORK/coord/deltas" \
  "$POOL_BIN/citrate-training-coordinator" > "$WORK/coordinator.log" 2>&1 &
PIDS+=($!)
wait_until 30 "the coordinator" curl -sf "http://127.0.0.1:${COORD_PORT}/v1/status"

for i in 0 1 2; do
  d="$WORK/w$i"; mkdir -p "$d/fl/models" "$d/fl/adapters"
  ln -sf "$BASE_MODEL" "$d/fl/models/$BASE_SHA.gguf"
  cp "$WORK/start.gguf" "$d/fl/adapters/$START_SHA.gguf"
  # A verified-trajectory export in the S9.3 shape (fixture conversations, distinct per device).
  for n in 1 2 3 4 5; do
    jq -cn --arg u "device $i request $n" --arg a "device $i answer $n" '{
      messages: [{role:"user",content:$u},{role:"assistant",content:$a}],
      metadata: {model:"fixture", workflow:"hello-mint", step:"deploy", verifiers:["forge-test"]}}'
  done > "$d/export.jsonl"
  jq -n --arg r "$RID" '{rounds: [$r]}' > "$d/consent.json"
  CITRATE_COORDINATOR_URL="http://127.0.0.1:${COORD_PORT}" CITRATE_PROBE_PATH="$PROBE_JSON" \
  CITRATE_TRAINING_PRIVATE_KEY_HEX="${WK[$i]}" CITRATE_FL_STORE="$d/fl" \
  CITRATE_FL_DATASET="$d/export.jsonl" CITRATE_FL_CONSENT_FILE="$d/consent.json" \
  CITRATE_LORA_TRAINER="$POOL_BIN/examples/fl_fixture_trainer" \
    "$POOL_BIN/citrate-coop-worker" > "$WORK/worker$i.log" 2>&1 &
  PIDS+=($!)
done
three_done() { test "$(curl -sf "http://127.0.0.1:${COORD_PORT}/v1/status" | jq -r .counts.done)" = "3"; }
wait_until 900 "three submitted deltas" three_done
note workers_done 3

# ── 5. aggregate through 0x0110, replay, commit ─────────────────────
say "aggregate through 0x0110 on the devnet"
"$POOL_BIN/citrate-fl-round" aggregate --config "$WORK/round.json" --ordinal 0 \
  --state "$WORK/coord/state.json" --deltas "$WORK/coord/deltas" --start "$WORK/start.gguf" \
  --rpc "$RPC" --out "$WORK/round0" > "$WORK/aggregate.json"
note aggregate "$(cat "$WORK/aggregate.json")"
MERGED=$(jq -r .merged_adapter "$WORK/aggregate.json")
# The cluster's rules as the chain holds them (getCluster: 10 static words; rules start at word 2).
RULES=$(cast call --rpc-url "$RPC" "$LEDGER" "getCluster(bytes32)" "$CLUSTER" | python3 -c '
import sys
h = sys.stdin.read().strip()[2:]
w = [int(h[i*64:(i+1)*64], 16) for i in range(len(h)//64)]
s = lambda x: x - (1 << 256) if x >> 255 else x
print(",".join(str(v) for v in [w[2], w[3], w[4], s(w[5]), s(w[6])]))')

say "independent replay (chain kernel, in process)"
"$REPLAY_BIN" --bundle "$WORK/round0/bundle.json" --deltas "$WORK/coord/deltas" \
  --start "$WORK/start.gguf" --merged "$MERGED" --rules "$RULES" > "$WORK/replay0.json" \
  || { cat "$WORK/replay0.json"; die "replay disagrees with the coordinator"; }
note replay "$(cat "$WORK/replay0.json")"

# Prepared before the commit so the challenge lands well inside the window.
"$POOL_BIN/citrate-fl-round" proof --bundle "$WORK/round0/bundle.json" --deltas "$WORK/coord/deltas" --chunk 0 > "$WORK/proof0.json"

say "commit the round (devnet dry run of the operator ceremony)"
TO=$(jq -r .to "$WORK/round0/commit-intent.json"); DATA=$(jq -r .data "$WORK/round0/commit-intent.json")
send "$K_COORD" "$TO" "$DATA" >/dev/null
RD_CHAIN=$(cast call --rpc-url "$RPC" "$LEDGER" "recordDigest(bytes32)(bytes32)" "$RID")
RD_BUNDLE=$(jq -r .record_digest "$WORK/round0/bundle.json")
RD_REPLAY=$(jq -r .record_digest "$WORK/replay0.json")
[ "$RD_CHAIN" = "$RD_BUNDLE" ] && [ "$RD_CHAIN" = "$RD_REPLAY" ] \
  || die "record digest: chain $RD_CHAIN bundle $RD_BUNDLE replay $RD_REPLAY"
note record_digest "{\"chain\":\"$RD_CHAIN\",\"bundle\":\"$RD_BUNDLE\",\"replay\":\"$RD_REPLAY\"}"

round_status() { # roundId -> status code (word 11 of getRound)
  cast call --rpc-url "$RPC" "$LEDGER" "getRound(bytes32)" "$1" | python3 -c 'import sys; h=sys.stdin.read().strip()[2:]; print(int(h[11*64:12*64],16))'
}
[ "$(round_status "$RID")" = "1" ] || die "round 0 is not Committed"

say "an honest chunk survives its challenge"
arr() { jq -r "$1 | \"[\" + join(\",\") + \"]\"" "$2"; }
if cast call --rpc-url "$RPC" --from "$A_CHAL" "$LEDGER" \
  "challengeOutput(bytes32,uint32,bytes,bytes32[],bytes32,bytes32[])" "$RID" 0 \
  "$(jq -r .input "$WORK/proof0.json")" "$(arr .input_proof "$WORK/proof0.json")" \
  "$(jq -r .output_hash "$WORK/proof0.json")" "$(arr .output_proof "$WORK/proof0.json")" > "$WORK/honest-challenge.txt" 2>&1; then
  die "a challenge against an honest chunk did not revert"
fi
grep -q -i -E "ChallengeFailed|$(cast sig 'ChallengeFailed()' | cut -c3-)" "$WORK/honest-challenge.txt" \
  || { cat "$WORK/honest-challenge.txt"; die "honest challenge reverted for the wrong reason"; }
note honest_challenge_reverts true

say "the window closes; the round is accepted"
DEADLINE=$(cast call --rpc-url "$RPC" "$LEDGER" "getRound(bytes32)" "$RID" | python3 -c 'import sys; h=sys.stdin.read().strip()[2:]; print(int(h[10*64:11*64],16))')
wait_until $(( WINDOW * 10 + 60 )) "the challenge window" block_past "$DEADLINE"
send "$K_CHAL" "$LEDGER" "finalize(bytes32)" "$RID" >/dev/null
[ "$(round_status "$RID")" = "3" ] || die "round 0 was not accepted"
note round0_status '"Accepted"'

# ── 6. settlement on the accepted record ────────────────────────────
say "settlement: gate, PatronageLedger"
mkdir -p "$WORK/fixture-src"
cp "$CHAIN_DIR/scripts/fl/fixtures/DevnetAllowList.sol" "$WORK/fixture-src/"
forge build --root "$WORK" --contracts "$WORK/fixture-src" --out "$WORK/fixture-out" \
  --cache-path "$WORK/fixture-cache" >/dev/null
( cd "$COOP_DIR" && forge build src/PatronageLedger.sol --out "$WORK/coop-out" \
  --cache-path "$WORK/coop-cache" >/dev/null )
MEMBERS=$(printf '%s,' "${WA[@]}"); MEMBERS="[${MEMBERS%,}]"
ALLOW=$(create "$K_SETTLER" "$(jq -r .bytecode.object "$WORK/fixture-out/DevnetAllowList.sol/DevnetAllowList.json")$(cast abi-encode 'c(address[])' "$MEMBERS" | cut -c3-)")
PATRONAGE=$(create "$K_SETTLER" "$(jq -r .bytecode.object "$WORK/coop-out/PatronageLedger.sol/PatronageLedger.json")$(cast abi-encode 'c(address,address)' "$ALLOW" "$ALLOW" | cut -c3-)")
send "$K_SETTLER" "$PATRONAGE" "grantRole(bytes32,address)" "$(cast keccak SETTLER_ROLE)" "$A_SETTLER" >/dev/null
note patronage_ledger "\"$PATRONAGE\""
# Metering: examples trained x 1000 compute units, full data quality (placeholders,
# pending owner sign-off).
jq '[.participants[] | {member: .worker, compute_metered: (.result.examples * 1000), data_quality_bps: 10000}]' \
  "$WORK/round0/bundle.json" > "$WORK/contributions.json"
"$SETL_BIN/setl-fl-intents" --ledger "$PATRONAGE" --ordinal 0 --status "$(round_status "$RID")" \
  --record-digest "$RD_CHAIN" --contributions "$WORK/contributions.json" --out "$WORK/intents0.jsonl" \
  > "$WORK/setl0.json"
while read -r line; do
  send "$K_SETTLER" "$(jq -r .to <<<"$line")" "$(jq -r .data <<<"$line")" >/dev/null
done < "$WORK/intents0.jsonl"
SETL_RID=$(cast to-uint256 0)
ANCHOR=$(cast call --rpc-url "$RPC" "$PATRONAGE" "roundMergedHash(bytes32)(bytes32)" "$SETL_RID")
[ "$ANCHOR" = "$RD_CHAIN" ] || die "PatronageLedger anchored $ANCHOR, expected the record digest"
for a in "${WA[@]}"; do
  u=$(cast call --rpc-url "$RPC" "$PATRONAGE" "units(address)(uint256)" "$a" | cut -d' ' -f1)
  [ "$u" != "0" ] || die "member $a has no patronage units"
done
note settlement "{\"intents\":$(wc -l < "$WORK/intents0.jsonl" | tr -d ' '),\"anchor\":\"$ANCHOR\"}"

# ── 7. a dishonest commit, proven wrong on chain ────────────────────
say "a dishonest commit (ordinal 1): one chunk's output is a lie"
RID1=$(cast call --rpc-url "$RPC" "$LEDGER" "roundIdOf(bytes32,uint64)(bytes32)" "$CLUSTER" 1)
LIE=$(cast keccak "not what 0x0110 returned")
CH=$(( $(jq .chunks "$WORK/round0/bundle.json") / 2 ))
jq --arg rid "$RID1" --arg lie "$LIE" --argjson k "$CH" \
  '.ordinal = 1 | .round_id = $rid | .output_hashes[$k] = $lie' "$WORK/round0/bundle.json" > "$WORK/lie.json"
"$POOL_BIN/citrate-fl-round" roots --bundle "$WORK/lie.json" > "$WORK/lie-roots.json"
jq --slurpfile r "$WORK/lie-roots.json" '.participants_root = $r[0].participants_root
  | .input_root = $r[0].input_root | .output_root = $r[0].output_root
  | .record_digest = $r[0].record_digest' "$WORK/lie.json" > "$WORK/lie-bundle.json"
"$POOL_BIN/citrate-fl-round" intent --bundle "$WORK/lie-bundle.json" > "$WORK/lie-intent.json"
"$POOL_BIN/citrate-fl-round" proof --bundle "$WORK/lie-bundle.json" --deltas "$WORK/coord/deltas" --chunk "$CH" > "$WORK/lie-proof.json"
send "$K_COORD" "$(jq -r .to "$WORK/lie-intent.json")" "$(jq -r .data "$WORK/lie-intent.json")" >/dev/null
[ "$(round_status "$RID1")" = "1" ] || die "the dishonest round did not commit"
send "$K_CHAL" "$LEDGER" "challengeOutput(bytes32,uint32,bytes,bytes32[],bytes32,bytes32[])" "$RID1" "$CH" \
  "$(jq -r .input "$WORK/lie-proof.json")" "$(arr .input_proof "$WORK/lie-proof.json")" \
  "$(jq -r .output_hash "$WORK/lie-proof.json")" "$(arr .output_proof "$WORK/lie-proof.json")" > "$WORK/lie-challenge.tx"
[ "$(round_status "$RID1")" = "2" ] || die "the dishonest round was not rejected"
note round1 "{\"status\":\"Rejected\",\"chunk\":$CH,\"challenge_tx\":\"$(cat "$WORK/lie-challenge.tx")\"}"
if "$REPLAY_BIN" --bundle "$WORK/lie-bundle.json" --deltas "$WORK/coord/deltas" > "$WORK/replay1.json"; then
  die "the replay accepted the dishonest bundle"
fi
note replay_flags_dishonest "$(jq '.mismatches | length' "$WORK/replay1.json")"
set +e
"$SETL_BIN/setl-fl-intents" --ledger "$PATRONAGE" --ordinal 1 --status "$(round_status "$RID1")" \
  --record-digest "$(cast call --rpc-url "$RPC" "$LEDGER" "recordDigest(bytes32)(bytes32)" "$RID1")" \
  --contributions "$WORK/contributions.json" --out "$WORK/intents1.jsonl" 2> "$WORK/setl1.err"
code=$?
set -e
[ "$code" = "2" ] || die "settlement did not refuse the rejected round (exit $code)"
[ ! -s "$WORK/intents1.jsonl" ] || die "intents were written for a rejected round"
note settlement_refuses_rejected true

# ── 8. the merged adapter loads ─────────────────────────────────────
if [ "$SYNTHETIC_BASE" = "0" ] && [ -n "${LLAMA_SERVER:-}" ]; then
  say "llama-server loads the merged adapter"
  LP=$(( COORD_PORT + 1 ))
  # CPU by default (LLAMA_NGL=0): the check is that the adapter loads and serves, and a
  # GPU shared with other work can run out of memory mid-request.
  "$LLAMA_SERVER" -m "$BASE_MODEL" --lora "$MERGED" --host 127.0.0.1 --port "$LP" -c 512 \
    -ngl "${LLAMA_NGL:-0}" > "$WORK/llama.log" 2>&1 &
  PIDS+=($!)
  wait_until 180 "llama-server" curl -sf "http://127.0.0.1:${LP}/health"
  curl -sf "http://127.0.0.1:${LP}/lora-adapters" | jq -e --arg p "$MERGED" 'any(.[]; .path == $p)' >/dev/null \
    || die "llama-server did not load the merged adapter"
  curl -sf --max-time 300 "http://127.0.0.1:${LP}/completion" -H 'content-type: application/json' \
    -d '{"prompt":"Citrate is","n_predict":8}' \
    | jq -e '.content | length > 0' >/dev/null || die "no completion with the adapter loaded"
  note merged_adapter_loads true
else
  note merged_adapter_loads '"skipped (synthetic base or no LLAMA_SERVER)"'
fi

note training '"fixture trainer: no learning ran; this run proves the round protocol only"'
if [ -n "${FIXTURE_OUT:-}" ]; then
  mkdir -p "$FIXTURE_OUT/deltas"
  cp "$WORK/round0/bundle.json" "$WORK/start.gguf" "$FIXTURE_OUT/"
  cp "$MERGED" "$FIXTURE_OUT/merged.gguf"
  cp "$WORK"/coord/deltas/*.fld "$FIXTURE_OUT/deltas/"
fi
say "PASS"
cat "$RECEIPT"
