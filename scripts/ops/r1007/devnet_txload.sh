#!/usr/bin/env bash
# devnet_txload.sh: sustained transaction load for the r1007 devnet rehearsal (P5), DEVNET ONLY.
#
#   devnet_txload.sh run  --fleet FLEET --work DIR [--tps N] [--seconds N]
#   devnet_txload.sh gate --work DIR
#
# `run` is called by devnet.sh inside its namespaces, right after the producers step. It needs
# `cast` (Foundry) on PATH. For each producer it starts ONE sender inside that producer's network
# namespace:
#   - the sender makes a fresh throwaway key (it never leaves DIR/txload, mode 0700);
#   - it funds that key from the producer's devnet staker keystore, which devnet.sh minted;
#   - it sends 1-wei self-transfers at about TPS/producers per second for SECONDS, to that
#     producer's own RPC.
# Every producer therefore receives load, and the blocks it seals carry transactions that
# the others execute on receive.
#
# `gate` (run by `run` after the load and a 20 s drain, and callable on its own) fails if:
#   - any host's r1007 node log has an "Acceptance commitment mismatch" line;
#   - any host's r1007 node log has a "block disqualified" line;
#   - no load transaction was included (the load would then prove nothing).
# These are the G4 failure signatures found on 2026-11-11 under about 30 tx/s
# (execute-on-receive split). Exit 0 = pass, 1 = fail, 2 = usage.
set -euo pipefail

usage() { echo "usage: devnet_txload.sh run --fleet F --work D [--tps N] [--seconds N] | gate --work D" >&2; exit 2; }
[[ $# -ge 1 ]] || usage
MODE=$1; shift
if [[ "$MODE" == _sender ]]; then  # internal: NAME ROOT RATE SECS WORK, inside a producer's netns
  WORK=$5; TX="$WORK/txload"
fi
FLEET="" WORK="" TPS=30 SECS=120
while [[ "$MODE" != _sender && $# -gt 0 ]]; do
  case "$1" in
    --fleet) FLEET="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --tps) TPS="$2"; shift 2 ;;
    --seconds) SECS="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$WORK" ]] || usage
TX="$WORK/txload"

gate() {
  local mism=0 disq=0 inc=0 sent=0 n f
  for f in "$WORK"/hosts/*/var/lib/citrate/ceremony/node-r1007.log; do
    [[ -f "$f" ]] || continue
    n=$(grep -ci "Acceptance commitment mismatch" "$f" || true); mism=$((mism + n))
    n=$(grep -ci "block disqualified" "$f" || true); disq=$((disq + n))
  done
  for f in "$TX"/*.included; do [[ -f "$f" ]] && inc=$((inc + $(cat "$f"))); done
  for f in "$TX"/*.sent; do [[ -f "$f" ]] && sent=$((sent + $(cat "$f"))); done
  echo "txload gate: sent=$sent included=$inc acceptance_commitment_mismatch=$mism block_disqualified=$disq"
  if [[ $mism -ne 0 || $disq -ne 0 ]]; then echo "txload gate: FAIL (consensus divergence under load)"; return 1; fi
  if [[ $inc -eq 0 ]]; then echo "txload gate: FAIL (no load transaction was included; the load proved nothing)"; return 1; fi
  echo "txload gate: pass"
}

sender() { # NAME ROOT RATE SECS  (runs inside the producer's netns)
  local name=$1 root=$2 rate=$3 secs=$4 rpc=http://127.0.0.1:8545 ks addr key n end period
  ks="$root/etc/citrate/keys"
  key=$(cast wallet new --json | python3 -c 'import json,sys; w=json.load(sys.stdin); w=w.get("data",w) if isinstance(w,dict) else w; w=w[0] if isinstance(w,list) else w; print(w["private_key"])')
  umask 077; printf '%s\n' "$key" > "$TX/$name.key"
  addr=$(ETH_PRIVATE_KEY="$key" cast wallet address)
  cast send --rpc-url "$rpc" --keystore "$ks/staker.keystore.json" --password-file "$ks/staker.password" \
    --legacy --gas-price 2gwei "$addr" --value 10ether >/dev/null
  n=0; end=$(( $(date +%s) + secs ))
  period=$(python3 -c "print(max(0.0, 1.0/$rate))")
  while (( $(date +%s) < end )); do
    tx=$(ETH_PRIVATE_KEY="$key" cast mktx --legacy --gas-price 2gwei --gas-limit 21000 --nonce "$n" --chain 40204 "$addr" --value 1wei)
    cast publish --rpc-url "$rpc" --async "$tx" >/dev/null 2>>"$TX/$name.err" || true
    n=$((n + 1)); echo "$n" > "$TX/$name.sent"
    sleep "$period"
  done
  sleep 20
  cast nonce --rpc-url "$rpc" "$addr" > "$TX/$name.included" 2>/dev/null || echo 0 > "$TX/$name.included"
}

case "$MODE" in
  gate) gate ;;
  run)
    [[ -n "$FLEET" ]] || usage
    command -v cast >/dev/null || { echo "txload: cast (Foundry) is not on PATH" >&2; exit 2; }
    mkdir -p "$TX"; chmod 700 "$TX"
    prods=$(python3 -c "import json,sys; [print(h['name'], h['root'], h['netns_pid']) for h in json.load(open(sys.argv[1]))['hosts'] if h['role']=='producer']" "$FLEET")
    nprod=$(printf '%s\n' "$prods" | grep -c .)
    rate=$(python3 -c "print($TPS/$nprod)")
    echo "txload: $nprod senders, about $TPS tx/s total for ${SECS}s"
    pids=()
    while read -r name root pid; do
      nsenter --net="/proc/$pid/ns/net" bash "$0" _sender "$name" "$root" "$rate" "$SECS" "$WORK" &
      pids+=($!)
    done <<<"$prods"
    rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
    [[ $rc -eq 0 ]] || echo "txload: a sender exited non-zero (see $TX/*.err)"
    gate ;;
  _sender) sender "$1" "$2" "$3" "$4" ;;
  *) usage ;;
esac
