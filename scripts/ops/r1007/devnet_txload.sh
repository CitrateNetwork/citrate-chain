#!/usr/bin/env bash
# devnet_txload.sh: sustained transaction load for the r1007 devnet rehearsal (P5), DEVNET ONLY.
#
#   devnet_txload.sh run  --fleet FLEET --work DIR [--tps N] [--seconds N] [--workers N]
#   devnet_txload.sh gate --work DIR
#
# `run` is called by devnet.sh inside its namespaces, right after the producers step. It needs
# `cast` (Foundry) on PATH and uses throwaway devnet keys only. cast 1.9 reads no key from the
# environment, so these keys go in cast's argv, inside the rehearsal's own namespaces. Never do
# this with a real key.
#
# For each producer, it does this inside that producer's network namespace:
#   - make WORKERS fresh keys (kept in DIR/txload, mode 0700);
#   - fund them ONE AT A TIME from the producer's devnet staker keystore, which devnet.sh
#     minted. Each funding transfer waits for its receipt and is retried, because concurrent
#     sends from one staker race its nonce;
#   - run the workers in parallel. Each sends 1-wei self-transfers to that producer's own RPC
#     at TPS / (producers x WORKERS) per second, for SECONDS.
# One cast worker manages about 2.5 tx/s, so the default of 4 workers per producer covers
# 30 tx/s on 7 producers. Every producer receives load, and the blocks it seals carry
# transactions that the others execute on receive.
#
# `gate` (run by `run` after the load and a 20 s drain, and callable on its own) exits as follows:
#   1  a consensus divergence: any "Acceptance commitment mismatch" or "block disqualified"
#      line in any host's r1007 node log. These are the G4 signatures of 2026-11-11.
#   2  a harness shortfall, which is neither pass nor fail: an expected worker that never ran,
#      zero transactions included, or fewer than 80% of the target sent;
#   0  pass: no divergence and the full load delivered.
# A divergence is reported as 1 even when the load fell short.
set -euo pipefail

usage() { echo "usage: devnet_txload.sh run --fleet F --work D [--tps N] [--seconds N] [--workers N] | gate --work D" >&2; exit 2; }
[[ $# -ge 1 ]] || usage
MODE=$1; shift
FLEET="" WORK="" TPS=30 SECS=120 WORKERS=4
if [[ "$MODE" == _producer ]]; then  # internal: NAME ROOT RATE SECS WORK WORKERS, inside a producer's netns
  WORK=$5
fi
while [[ "$MODE" != _producer && $# -gt 0 ]]; do
  case "$1" in
    --fleet) FLEET="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --tps) TPS="$2"; shift 2 ;;
    --seconds) SECS="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$WORK" ]] || usage
TX="$WORK/txload"

gate() {
  local mism=0 disq=0 inc=0 sent=0 n f missing="" target=0 wid
  for f in "$WORK"/hosts/*/var/lib/citrate/ceremony/node-r1007.log; do
    [[ -f "$f" ]] || continue
    n=$(grep -ci "Acceptance commitment mismatch" "$f" || true); mism=$((mism + n))
    n=$(grep -ci "block disqualified" "$f" || true); disq=$((disq + n))
  done
  for f in "$TX"/*.included; do [[ -f "$f" ]] && inc=$((inc + $(cat "$f"))); done
  for f in "$TX"/*.sent; do [[ -f "$f" ]] && sent=$((sent + $(cat "$f"))); done
  if [[ -f "$TX/expected" ]]; then
    while read -r wid; do
      [[ -n "$wid" ]] || continue
      [[ -f "$TX/$wid.sent" && ! -f "$TX/$wid.failed" ]] || missing="$missing $wid"
    done <"$TX/expected"
  fi
  [[ -f "$TX/target" ]] && target=$(cat "$TX/target")
  echo "txload gate: sent=$sent included=$inc target=$target acceptance_commitment_mismatch=$mism block_disqualified=$disq missing_workers=[${missing# }]"
  if [[ $mism -ne 0 || $disq -ne 0 ]]; then echo "txload gate: FAIL (consensus divergence under load)"; return 1; fi
  if [[ -n "$missing" ]]; then echo "txload gate: HARNESS (workers that never ran:$missing; see $TX/*.failed)"; return 2; fi
  if [[ $inc -eq 0 ]]; then echo "txload gate: HARNESS (no load transaction was included; the load proved nothing)"; return 2; fi
  if (( sent * 10 < target * 8 )); then echo "txload gate: HARNESS (sent $sent is below 80% of the target $target)"; return 2; fi
  echo "txload gate: pass"
}

newkey() {
  cast wallet new --json | python3 -c 'import json,sys; w=json.load(sys.stdin); w=w.get("data",w) if isinstance(w,dict) else w; w=w[0] if isinstance(w,list) else w; print(w["private_key"])'
}

worker() { # WID KEY RATE SECS RPC
  local wid=$1 key=$2 rate=$3 secs=$4 rpc=$5 addr n end period tx
  addr=$(cast wallet address --private-key "$key")
  n=0; end=$(( $(date +%s) + secs ))
  period=$(python3 -c "print(max(0.0, 1.0/$rate))")
  while (( $(date +%s) < end )); do
    tx=$(cast mktx --private-key "$key" --legacy --gas-price 2gwei --gas-limit 21000 --nonce "$n" --chain 40204 "$addr" --value 1wei)
    cast publish --rpc-url "$rpc" --async "$tx" >/dev/null 2>>"$TX/$wid.err" || true
    n=$((n + 1)); echo "$n" > "$TX/$wid.sent"
    sleep "$period"
  done
  sleep 20
  cast nonce --rpc-url "$rpc" "$addr" > "$TX/$wid.included" 2>>"$TX/$wid.err" || echo 0 > "$TX/$wid.included"
}

producer() { # NAME ROOT RATE SECS WORKERS  (runs inside the producer's netns)
  local name=$1 root=$2 rate=$3 secs=$4 workers=$5 rpc=http://127.0.0.1:8545 ks j wid key addr try ok pids=()
  ks="$root/etc/citrate/keys"
  umask 077
  for j in $(seq 1 "$workers"); do
    wid="$name-w$j"
    key=$(newkey); printf '%s\n' "$key" > "$TX/$wid.key"
    addr=$(cast wallet address --private-key "$key")
    ok=0
    for try in 1 2 3 4 5; do
      if cast send --rpc-url "$rpc" --keystore "$ks/staker.keystore.json" --password-file "$ks/staker.password" \
           --legacy --gas-price 2gwei "$addr" --value 10ether >/dev/null 2>>"$TX/$wid.err"; then ok=1; break; fi
      sleep $((try * 3))
    done
    if [[ $ok -ne 1 ]]; then echo "funding failed after 5 tries" > "$TX/$wid.failed"; continue; fi
    worker "$wid" "$key" "$rate" "$secs" "$rpc" &
    pids+=($!)
  done
  for j in "${pids[@]}"; do wait "$j" || true; done
}

case "$MODE" in
  gate) gate ;;
  run)
    [[ -n "$FLEET" ]] || usage
    command -v cast >/dev/null || { echo "txload: cast (Foundry) is not on PATH" >&2; exit 2; }
    mkdir -p "$TX"; chmod 700 "$TX"
    prods=$(python3 -c "import json,sys; [print(h['name'], h['root'], h['netns_pid']) for h in json.load(open(sys.argv[1]))['hosts'] if h['role']=='producer']" "$FLEET")
    nprod=$(printf '%s\n' "$prods" | grep -c .)
    rate=$(python3 -c "print($TPS/($nprod*$WORKERS))")
    : >"$TX/expected"
    while read -r name _root _pid; do
      for j in $(seq 1 "$WORKERS"); do echo "$name-w$j" >>"$TX/expected"; done
    done <<<"$prods"
    echo $((TPS * SECS)) >"$TX/target"
    echo "txload: $nprod producers x $WORKERS workers, about $TPS tx/s total for ${SECS}s"
    pids=()
    while read -r name root pid; do
      nsenter --net="/proc/$pid/ns/net" bash "$0" _producer "$name" "$root" "$rate" "$SECS" "$WORK" "$WORKERS" &
      pids+=($!)
    done <<<"$prods"
    for p in "${pids[@]}"; do wait "$p" || true; done
    gate ;;
  _producer) producer "$1" "$2" "$3" "$4" "$6" ;;
  *) usage ;;
esac
