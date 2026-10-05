#!/usr/bin/env bash
# created: 2026-10-04 | branch: hup/n7-chain-precompile-followups | author: Larry Klosowski + Claude Opus 5.5 | status: active
#
# HUP-S7.2 follow-up: the devnet check of docs/precompiles/AGENT_PRECOMPILES.md
# section 7, step 1, as a script. It proves the agent precompile fork on a DEVNET
# (never 40204) built from the release commit:
#
#   below the fork height H   every PrecompileCaller helper reverts with
#                             PrecompileUnavailable(<the precompile's address>);
#   at and after H            0x0112 LORA_APPLY, 0x0113 LORA_MERGE,
#                             0x0121 MEMORY_ANCHOR_VERIFY and 0x0122 AGENT_OPS answer
#                             exactly the pinned vectors
#                             (core/execution/tests/fixtures/agent_precompile_vectors.json),
#                             and every node of the devnet answers the same bytes.
#
# The calls are eth_calls through PrecompileCaller (the runtime fixture
# core/execution/tests/fixtures/agent_precompile_caller_runtime.hex), because a top-level
# call whose `to` is a precompile address returns 0x on a Citrate node at every height.
# The only transaction is the PrecompileCaller deployment, signed with a throwaway key on
# the devnet.
#
# Two modes.
#
#   Local (default): starts a single-node devnet from CITRATE_NODE_BIN with
#   CITRATE_AGENT_PRECOMPILES_HEIGHT in its environment, funds a throwaway deployer from
#   the devnet's prefunded test account, and stops the node at the end.
#
#     CITRATE_AGENT_PRECOMPILES_HEIGHT=40 CITRATE_NODE_BIN=target/debug/citrate \
#       scripts/devnet-precompile-check.sh
#
#   Existing devnet (multi-node; the DGX team): every node must have been started with
#   the SAME CITRATE_AGENT_PRECOMPILES_HEIGHT. Pass that value, every node's RPC, and a
#   funded devnet account to deploy from (a file holding its key, never the key itself):
#
#     CITRATE_AGENT_PRECOMPILES_HEIGHT=<H> RPC_URLS=http://n1:8545,http://n2:8545,http://n3:8545 \
#       DEPLOYER_KEY_FILE=/path/to/devnet-funded-key scripts/devnet-precompile-check.sh
#
#   With H still ahead of the tip, the script checks the fail-closed side first, then
#   waits for H (WAIT_SECS, default 900) and checks the answers. With H already passed it
#   checks the answers only and says so in the receipt.
#
# Optional:
#   RPC_PORT, P2P_PORT   local mode ports (default 18791, 30791); both must be free
#   WORK                 working directory (default: a fresh temp dir)
#   EXPECT_CHAIN_ID      the devnet chain id, or a comma-separated list (default 1337, the
#                        `citrate devnet` id); 40204 is always refused
#
# Output: a JSON receipt on stdout (also at $WORK/receipt.json). Exit 0 only on PASS.
set -euo pipefail

say() { printf '\n== %s\n' "$*" >&2; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }
for t in cast jq python3; do need "$t"; done

CHAIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$CHAIN_DIR/core/execution/tests/fixtures"
VECTORS="$FIX/agent_precompile_vectors.json"
CALLER_RUNTIME="$FIX/agent_precompile_caller_runtime.hex"
[ -f "$VECTORS" ] || die "missing $VECTORS"
[ -f "$CALLER_RUNTIME" ] || die "missing $CALLER_RUNTIME"

H="${CITRATE_AGENT_PRECOMPILES_HEIGHT:-}"
[[ "$H" =~ ^[0-9]+$ ]] || die "set CITRATE_AGENT_PRECOMPILES_HEIGHT to the devnet's fork height (a block number)"
EXPECT_CHAIN_ID="${EXPECT_CHAIN_ID:-1337}"
case ",$EXPECT_CHAIN_ID," in *,40204,*) die "this check runs on a devnet, never on 40204" ;; esac
WAIT_SECS="${WAIT_SECS:-900}"
WORK="${WORK:-$(mktemp -d)}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd -P)"
RECEIPT="$WORK/receipt.json"
jq -n --argjson h "$H" '{fork_height: $h}' > "$RECEIPT"
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

# ── 1. the devnet ──────────────────────────────────────────────────
if [ -z "${RPC_URLS:-}" ]; then
  say "local single-node devnet, fork height $H"
  CITRATE_NODE_BIN="${CITRATE_NODE_BIN:-$CHAIN_DIR/target/debug/citrate}"
  [ -x "$CITRATE_NODE_BIN" ] || die "no node binary at $CITRATE_NODE_BIN (set CITRATE_NODE_BIN)"
  RPC_PORT="${RPC_PORT:-18791}"
  P2P_PORT="${P2P_PORT:-30791}"
  # Something else on the port (another devnet, an anvil) would answer in our node's place.
  for p in "$RPC_PORT" "$P2P_PORT"; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
      die "port $p is already in use; stop that process or set RPC_PORT / P2P_PORT"
    fi
  done
  RPCS=("http://127.0.0.1:${RPC_PORT}")
  # The foundry test mnemonic, assembled at run time: its first accounts are prefunded in
  # the devnet genesis. Throwaway keys on a throwaway chain.
  MN="$(printf 'test %.0s' 1 2 3 4 5 6 7 8 9 10 11)junk"
  FUNDER="$(cast wallet private-key --mnemonic "$MN" --mnemonic-index 0)"
  COINBASE="$(cast wallet address --mnemonic "$MN" --mnemonic-index 1)"
  CITRATE_AGENT_PRECOMPILES_HEIGHT="$H" "$CITRATE_NODE_BIN" --data-dir "$WORK/node" \
    --rpc-addr "127.0.0.1:${RPC_PORT}" --p2p-addr "127.0.0.1:${P2P_PORT}" \
    --coinbase "$COINBASE" devnet > "$WORK/node.log" 2>&1 &
  NODE_PID=$!
  PIDS+=("$NODE_PID")
  note mode '"local single node"'
else
  say "existing devnet, fork height $H"
  IFS=',' read -r -a RPCS <<<"$RPC_URLS"
  [ -n "${DEPLOYER_KEY_FILE:-}" ] && [ -r "$DEPLOYER_KEY_FILE" ] || die "set DEPLOYER_KEY_FILE to a readable file holding a funded devnet key"
  FUNDER=""
  note mode "\"existing devnet, ${#RPCS[@]} node(s)\""
fi
RPC="${RPCS[0]}"
for r in "${RPCS[@]}"; do
  if [ -n "${NODE_PID:-}" ] && ! kill -0 "$NODE_PID" 2>/dev/null; then
    die "the devnet node exited; see $WORK/node.log"
  fi
  wait_until 90 "the RPC at $r" cast block-number --rpc-url "$r"
  cid="$(cast chain-id --rpc-url "$r")"
  [ "$cid" != "40204" ] || die "$r is chain 40204; this check never runs there"
  case ",$EXPECT_CHAIN_ID," in *",$cid,"*) ;; *) die "$r is chain $cid, expected one of $EXPECT_CHAIN_ID (set EXPECT_CHAIN_ID)" ;; esac
  CHAIN_ID="$cid"
done
note rpcs "$(printf '%s\n' "${RPCS[@]}" | jq -R . | jq -s .)"
note chain_id "$CHAIN_ID"
tip() { cast block-number --rpc-url "${1:-$RPC}"; }
start_block="$(tip)"
block_past() { test "$(tip "${2:-$RPC}")" -gt "$1"; }
wait_until 90 "block production" block_past "$start_block"
if [ -z "${RPC_URLS:-}" ]; then
  kill -0 "$NODE_PID" 2>/dev/null || die "the devnet node exited; see $WORK/node.log"
  line="$(tr -d '\033' < "$WORK/node.log" | sed 's/\[[0-9;]*m//g' | grep -m1 "Agent precompile fork ACTIVE from height $H " || true)"
  [ -n "$line" ] || die "the node did not log 'Agent precompile fork ACTIVE from height $H'; see $WORK/node.log"
  note node_log_line "$(printf '%s' "${line#*citrate: }" | jq -R .)"
fi

# ── 2. a throwaway deployer and PrecompileCaller ───────────────────
say "deploy PrecompileCaller"
receipt_of() { # txhash -> receipt json (waits up to 120 s)
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
if [ -n "$FUNDER" ]; then
  DEPLOYER="$(cast wallet new --json | jq -r '.[0].private_key')"
  h=$(cast send --rpc-url "$RPC" --private-key "$FUNDER" --async "$(cast wallet address "$DEPLOYER")" --value 1ether) \
    || die "funding the deployer failed"
  [ "$(jq -r .status <<<"$(receipt_of "$h")")" = "0x1" ] || die "funding the deployer reverted"
else
  DEPLOYER="$(tr -d ' \n\r' < "$DEPLOYER_KEY_FILE")"
fi
RUNTIME="$(tr -d ' \n\r' < "$CALLER_RUNTIME")"
INITCODE="$(python3 - "$RUNTIME" <<'PY'
import sys
rt = bytes.fromhex(sys.argv[1])
assert 0 < len(rt) < 0x10000
# PUSH2 len, DUP1, PUSH1 0x0c, PUSH0-free PUSH1 0, CODECOPY, PUSH1 0, RETURN: return the runtime.
init = bytes([0x61]) + len(rt).to_bytes(2, "big") + bytes([0x80, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x00, 0xf3])
assert len(init) == 0x0c
print("0x" + (init + rt).hex())
PY
)"
h=$(cast send --rpc-url "$RPC" --private-key "$DEPLOYER" --async --create "$INITCODE") || die "deploy failed"
r=$(receipt_of "$h")
[ "$(jq -r .status <<<"$r")" = "0x1" ] || die "deploy reverted"
CALLER="$(jq -r .contractAddress <<<"$r")"
for n in "${RPCS[@]}"; do
  has_code() { test "$(cast code --rpc-url "$1" "$CALLER")" = "0x$RUNTIME"; }
  wait_until 120 "PrecompileCaller code on $n" has_code "$n"
done
note caller "\"$CALLER\""
note deployed_at_block "$(jq -r .blockNumber <<<"$r" | xargs printf '%d')"

# ── 3. the calls, from the pinned vectors ──────────────────────────
# Each line: label | precompile address | signature | arg | expected output (decoded by cast)
python3 - "$VECTORS" > "$WORK/calls.tsv" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
def tensor(t):
    b = bytes([len(t["shape"])])
    for d in t["shape"]:
        b += d.to_bytes(4, "big")
    b += b"\x01"
    for x in t["q16"]:
        b += x.to_bytes(8, "little", signed=True)
    return "0x" + b.hex()
def scalar(x):
    return tensor({"shape": [], "q16": [x]})
rows = []
for x in v["lora_apply"]:
    assert tensor(x["w"])[2:] + tensor(x["b"])[2:] + tensor(x["a"])[2:] + scalar(x["alpha"])[2:] == x["input"]
    rows.append(("lora_apply: " + x["name"], "0x0112", "loraApply(bytes,bytes,bytes,bytes)(bytes)",
                 " ".join([tensor(x["w"]), tensor(x["b"]), tensor(x["a"]), scalar(x["alpha"])]), "0x" + x["output"]))
for x in v["lora_merge"]:
    rows.append(("lora_merge: " + x["name"], "0x0113", "loraMerge(bytes)(bytes)", "0x" + x["input"], "0x" + x["output"]))
for x in v["memory_anchor"]:
    rows.append(("memory_anchor: " + x["name"], "0x0121", "anchorCommitment(bytes)(bytes32)", "0x" + x["input"], "0x" + x["output"]))
for x in v["device_link"]:
    rows.append(("device_link: " + x["name"], "0x0122", "deviceLinkValid(bytes)(bool)", "0x" + x["input"][2:], "true" if x["valid"] else "false"))
for x in v["device_revocation"]:
    rows.append(("device_revocation: " + x["name"], "0x0122", "deviceRevocationValid(bytes)(bool)", "0x" + x["input"][2:], "true" if x["valid"] else "false"))
for r in rows:
    print("\t".join(r))
PY
[ -s "$WORK/calls.tsv" ] || die "no vectors"
UNAVAILABLE="$(cast sig 'PrecompileUnavailable(address)')"

call_caller() { # rpc signature args... -> stdout, exit status of cast
  local rpc="$1" sig="$2"; shift 2
  # shellcheck disable=SC2086
  cast call --rpc-url "$rpc" "$CALLER" "$sig" $@ 2>&1
}

fail_closed_side() {
  local rpc="$1" n=0 label addr sig args want out
  while IFS=$'\t' read -r label addr sig args want; do
    if out=$(call_caller "$rpc" "$sig" "$args"); then
      die "below the fork on $rpc, '$label' answered ($out) instead of failing closed"
    fi
    local word
    word="$(printf '%s' "$addr" | python3 -c 'import sys; print(int(sys.stdin.read(),16).to_bytes(32,"big").hex())')"
    grep -qi "${UNAVAILABLE#0x}${word}" <<<"$out" \
      || die "below the fork on $rpc, '$label' reverted without PrecompileUnavailable($addr): $out"
    n=$((n + 1))
  done < "$WORK/calls.tsv"
  printf '%s' "$n"
}

answer_side() {
  local rpc="$1" n=0 label addr sig args want out
  : > "$WORK/answers-$2.txt"
  while IFS=$'\t' read -r label addr sig args want; do
    out=$(call_caller "$rpc" "$sig" "$args") || die "after the fork on $rpc, '$label' failed: $out"
    [ "$out" = "$want" ] || die "after the fork on $rpc, '$label' answered $out, the pinned vector is $want"
    printf '%s\t%s\n' "$label" "$out" >> "$WORK/answers-$2.txt"
    n=$((n + 1))
  done < "$WORK/calls.tsv"
  printf '%s' "$n"
}

# ── 4. below H: fail closed ────────────────────────────────────────
# eth_call runs in the context of the next block, so keep two blocks of margin.
now="$(tip)"
if [ $((now + 2)) -lt "$H" ]; then
  say "below the fork (tip $now, H $H): every helper must revert with PrecompileUnavailable"
  i=0
  for rpc in "${RPCS[@]}"; do
    n=$(fail_closed_side "$rpc")
    i=$((i + 1))
    note "below_fork_node_$i" "{\"rpc\":\"$rpc\",\"tip\":$(tip "$rpc"),\"calls_failed_closed\":$n}"
  done
  [ "$(tip)" -lt "$H" ] || die "the tip reached H while the fail-closed side ran; raise H and run again"
else
  say "tip $now is already at or past H-2 ($H): the fail-closed side cannot be observed"
  note below_fork '"not observed: the devnet tip was already at the fork height"'
fi

# ── 5. at and after H: the pinned answers ──────────────────────────
say "waiting for block $H"
for rpc in "${RPCS[@]}"; do
  wait_until "$WAIT_SECS" "block $H on $rpc" block_past "$H" "$rpc"
done
say "after the fork: every helper must answer the pinned vector"
i=0
for rpc in "${RPCS[@]}"; do
  i=$((i + 1))
  n=$(answer_side "$rpc" "$i")
  note "after_fork_node_$i" "{\"rpc\":\"$rpc\",\"tip\":$(tip "$rpc"),\"calls_matching_vectors\":$n}"
done
if [ "${#RPCS[@]}" -gt 1 ]; then
  for j in $(seq 2 "${#RPCS[@]}"); do
    cmp -s "$WORK/answers-1.txt" "$WORK/answers-$j.txt" || die "node $j answered differently from node 1"
  done
  note nodes_agree true
fi
note vectors "\"$(cd "$CHAIN_DIR" && git rev-parse --short HEAD 2>/dev/null || echo unknown):core/execution/tests/fixtures/agent_precompile_vectors.json\""
note result '"PASS"'
say "PASS"
cat "$RECEIPT"
