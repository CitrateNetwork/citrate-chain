#!/usr/bin/env bash
# SRP-S1 WP-3.2 — the acceptance gate the old "determinism proof" lacked.
#
# A cold follower must match the producer on the state ROOT *and* on per-account
# BALANCE and per-storage-SLOT — not just the root. The live fleet passed a
# roots-match check while coinbase balances silently diverged (same block-2557
# stateRoot 0xef0ca623, different eth_getBalance) because the state root was a
# function of each node's dirty/insertion history rather than committed state.
# See ADR-2026-07-21-state-root-purity. Requires a binary with the SRP pure-root
# fix (state_db.rs calculate_state_root rebuilds from the committed resident set);
# this gate FAILS on the pre-fix accumulator binary.
#
# Usage: scripts/ci/srp_coldsync_gate.sh [/abs/path/to/citrate]
#   binary: $1, else $CITRATE_NODE_BIN, else ./target/release/citrate
#   deployer key: $DEPLOYER_PRIVATE_KEY, else read from $ENV_TESTNET
set -uo pipefail

BIN="${1:-${CITRATE_NODE_BIN:-./target/release/citrate}}"
[ -x "$BIN" ] || { echo "usage: $0 /abs/path/to/citrate (built with the SRP fix)" >&2; exit 2; }

ENV_TESTNET="${ENV_TESTNET:-$HOME/Projects/Citrate-Labs/.env.testnet}"
DK="${DEPLOYER_PRIVATE_KEY:-$(grep -m1 '^DEPLOYER_PRIVATE_KEY=' "$ENV_TESTNET" 2>/dev/null | cut -d= -f2)}"
[ -n "$DK" ] || { echo "no DEPLOYER_PRIVATE_KEY (set env or $ENV_TESTNET)" >&2; exit 2; }
DEP="${DEPLOYER_ADDRESS:-0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732}"
CB="${COINBASE:-0x0ecbcd8557781161A41b34dEE55Ee5A00561363b}"
DEPTH="${DEPTH:-180}"; H="${CMP_HEIGHT:-150}"

DIR=$(mktemp -d -t srp-gate-XXXXXX)
cleanup(){ [ -n "${PPID_PROD:-}" ] && kill "$PPID_PROD" 2>/dev/null; [ -n "${PPID_FOLL:-}" ] && kill "$PPID_FOLL" 2>/dev/null; rm -rf "$DIR"; }
trap cleanup EXIT
# Keep S1 reward settlement OFF so the gate exercises the pre-activation path deterministically.
export CITRATE_VALIDATOR_ACTIVATION_HEIGHT=100000 CITRATE_BLOCK_V2=1

jr(){ curl -s -m5 -X POST "127.0.0.1:$1" -H 'content-type: application/json' \
      --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"; }
# Scalar result ("result":"0x..") — balances, storage words, block number.
num(){ grep -oE '"result":"0x[0-9a-fA-F]*"' | grep -oE '0x[0-9a-fA-F]*' | head -1; }
# Named hex field inside a block object (stateRoot lives in a nested object, so
# a bare "result" regex cannot reach it — extract by field name).
fld(){ grep -oE "\"$1\":\"0x[0-9a-fA-F]+\"" | head -1; }
hi(){ local n; n=$(jr "$1" eth_blockNumber '[]' | num); [ -n "$n" ] && echo $((n)) || echo 0; }

echo "== producer (SRP-fixed binary, mining) =="
setsid nohup "$BIN" --network testnet --mine --coinbase "$CB" --data-dir "$DIR/p" \
  --rpc-addr 127.0.0.1:18700 --p2p-addr 0.0.0.0:30700 --bootstrap >"$DIR/p.log" 2>&1 & disown
PPID_PROD=$!
for i in $(seq 1 20); do sleep 3; [ "$(hi 18700)" -ge 6 ] 2>/dev/null && break; done

# A contract that SSTOREs 0x2a into slot 0 then returns empty code — exercises the
# storage sub-trie (the identical accumulator bug the ADR red-team flagged).
CADDR=""
for n in 1 2 3 4; do
  R=$(cast send --private-key "$DK" --rpc-url http://127.0.0.1:18700 --create 0x602a60005560006000f3 --json 2>/dev/null)
  a=$(echo "$R" | grep -oE '"contractAddress":"0x[0-9a-fA-F]+"' | grep -oE '0x[0-9a-fA-F]+' | head -1)
  [ -n "$a" ] && CADDR=$a
done
cast send --private-key "$DK" --rpc-url http://127.0.0.1:18700 \
  0x00000000000000000000000000000000DeaDBeef --value 12345 >/dev/null 2>&1
for i in $(seq 1 80); do sleep 3; [ "$(hi 18700)" -ge "$DEPTH" ] && break; done
PH=$(hi 18700); echo "   producer head=$PH  contract=$CADDR"

echo "== cold follower (fresh data-dir, bootstraps from producer) =="
setsid nohup "$BIN" --network testnet --data-dir "$DIR/f" \
  --rpc-addr 127.0.0.1:18701 --p2p-addr 0.0.0.0:30701 --bootstrap-nodes 127.0.0.1:30700 >"$DIR/f.log" 2>&1 & disown
PPID_FOLL=$!
for i in $(seq 1 90); do sleep 4; [ "$(hi 18701)" -ge "$PH" ] && break; done
FH=$(hi 18701); echo "   follower head=$FH"
[ "$FH" -ge "$PH" ] || { echo "FAIL: cold follower never reached producer head ($FH < $PH)"; exit 1; }

HX=$(printf '0x%x' "$H"); fail=0
chk(){ if [ -n "$2" ] && [ "$2" = "$3" ]; then echo "   MATCH $1: $2"; else echo "   *** MISMATCH $1: producer=$2 follower=$3"; fail=1; fi; }
chk stateRoot         "$(jr 18700 eth_getBlockByNumber "[\"$HX\",false]"|fld stateRoot)" "$(jr 18701 eth_getBlockByNumber "[\"$HX\",false]"|fld stateRoot)"
chk coinbase-balance  "$(jr 18700 eth_getBalance "[\"$CB\",\"$HX\"]"|num)"  "$(jr 18701 eth_getBalance "[\"$CB\",\"$HX\"]"|num)"
chk deployer-balance  "$(jr 18700 eth_getBalance "[\"$DEP\",\"$HX\"]"|num)" "$(jr 18701 eth_getBalance "[\"$DEP\",\"$HX\"]"|num)"
chk recipient-balance "$(jr 18700 eth_getBalance '["0x00000000000000000000000000000000DeaDBeef","'"$HX"'"]'|num)" "$(jr 18701 eth_getBalance '["0x00000000000000000000000000000000DeaDBeef","'"$HX"'"]'|num)"
if [ -n "$CADDR" ]; then
  chk contract-storage@0 "$(jr 18700 eth_getStorageAt "[\"$CADDR\",\"0x0\",\"$HX\"]"|num)" "$(jr 18701 eth_getStorageAt "[\"$CADDR\",\"0x0\",\"$HX\"]"|num)"
fi
grep -q 'state root mismatch' "$DIR/f.log" && { echo "   *** follower logged a state-root mismatch during sync"; fail=1; }

if [ "$fail" = 0 ]; then
  echo "PASS: cold follower matches producer on root + per-account balance + per-storage-slot"
  exit 0
else
  echo "FAIL: committed-state divergence (SRP regression)"
  exit 1
fi
