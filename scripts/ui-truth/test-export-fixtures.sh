#!/usr/bin/env bash
# Offline test for export-fixtures.sh against stub_rpc.py (no network, no chain):
#   1. a steady head inside one epoch  -> single_epoch true, per-read observed_head set
#   2. a head that crosses an epoch boundary mid-export -> single_epoch false + warning
#   3. producing_validators counts the distinct proposers over the sampled window
#   4. hostile or out-of-range RPC values (head, timestamps, epochs) never drive the export
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d); trap 'jobs -p | xargs -r kill 2>/dev/null; rm -rf "$tmp"' EXIT
fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

run() {  # port start step out [fail_mod] [batch_fault]
  python3 -I scripts/ui-truth/stub_rpc.py "$1" "$2" "$3" "${5:-0}" "${6:-}" "$tmp/PWNED" & local pid=$!
  for _ in $(seq 50); do curl -fsS -o /dev/null -X POST -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' "http://127.0.0.1:$1" 2>/dev/null && break; sleep 0.1; done
  scripts/ui-truth/export-fixtures.sh "http://127.0.0.1:$1" "$4" >"$tmp/log" 2>&1 || { cat "$tmp/log"; return 1; }
  kill "$pid"; wait "$pid" 2>/dev/null || true
}

run 18601 500200 0 "$tmp/steady.json"
check "steady: single_epoch true"            '[ "$(jq -r .single_epoch "$tmp/steady.json")" = true ]'
check "steady: every read is labelled latest" '[ "$(jq "[.reads[] | select(.state != \"latest\")] | length" "$tmp/steady.json")" = 0 ]'
check "steady: every read has observed_head"  '[ "$(jq "[.reads[] | select(.observed_head == null)] | length" "$tmp/steady.json")" = 0 ]'
check "steady: no read_at_block claim"        '[ "$(jq "has(\"read_at_block\")" "$tmp/steady.json")" = false ]'
check "registered, eligible and consensus exported separately" '[ "$(jq "[.reads[].id] | (index(\"registered_validators\") != null) and (index(\"eligible_validators\") != null) and (index(\"consensus_validator_set\") != null)" "$tmp/steady.json")" = true ]'
check "eligible: ABI-decoded, 1 eligible + 1 pending at epoch 7" '[ "$(jq -c ".reads[] | select(.id==\"eligible_validators\") | .value" "$tmp/steady.json")" = "{\"count\":1,\"pending_activation\":1,\"current_epoch\":7}" ]'
check "consensus set reported unavailable, not derived" '[ "$(jq ".reads[] | select(.id==\"consensus_validator_set\") | .value.unavailable" "$tmp/steady.json")" = true ]'
check "producers: 2 distinct over 1000 blocks" '[ "$(jq -c ".reads[] | select(.id==\"producing_validators\") | .value | [.count, .to_block - .from_block + 1]" "$tmp/steady.json")" = "[2,1000]" ]'

run 18602 500990 1 "$tmp/drift.json"
check "drift: head moved during export"       '[ "$(jq ".head_at_end > .head_at_start" "$tmp/drift.json")" = true ]'
check "drift: crossing an epoch is flagged"    '[ "$(jq -r .single_epoch "$tmp/drift.json")" = false ]'
check "drift: warning printed"                 'grep -q "crossed an epoch boundary" "$tmp/log"'
check "drift: observed_head increases"         '[ "$(jq "[.reads[].observed_head] | . == sort" "$tmp/drift.json")" = true ]'
check "no consistency guarantee is claimed"    '[ "$(jq -r ".consistency" "$tmp/drift.json")" = "none: each read is latest state at its own observed_head" ]'
check "head_moved reported"                     '[ "$(jq ".head_moved" "$tmp/drift.json")" = true ] && [ "$(jq ".head_moved" "$tmp/steady.json")" = false ]'

run 18603 500200 0 "$tmp/partial.json" 97
check "partial: producer count withheld"       '[ "$(jq ".reads[] | select(.id==\"producing_validators\") | .value | has(\"count\")" "$tmp/partial.json")" = false ]'
check "partial: marked unavailable with tally" '[ "$(jq -c ".reads[] | select(.id==\"producing_validators\") | .value | [.unavailable, .blocks_returned < .blocks_requested]" "$tmp/partial.json")" = "[true,true]" ]'

for fault in http500 badjson; do
  run 1861$([ $fault = http500 ] && echo 0 || echo 1) 500200 0 "$tmp/$fault.json" 0 $fault
  check "$fault: export completes, file written" '[ -s "$tmp/$fault.json" ]'
  check "$fault: final-batch failure → unavailable, 900/1000" '[ "$(jq -c ".reads[] | select(.id==\"producing_validators\") | .value | [.unavailable, .blocks_returned, .blocks_requested]" "$tmp/$fault.json")" = "[true,900,1000]" ]'
done

# A malformed, oversized, zero or hostile eth_blockNumber aborts the export: no file, non-zero
# exit, never a 0 head, and never an unbounded producer loop (each run is under a timeout).
port=18620
for mode in headbad headlong headzero headhostile; do
  port=$((port + 1))
  python3 -I scripts/ui-truth/stub_rpc.py "$port" 500200 0 0 "$mode" & hp=$!
  for _ in $(seq 50); do curl -fsS -o /dev/null -X POST -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' "http://127.0.0.1:$port" 2>/dev/null && break; sleep 0.1; done
  if timeout 60 scripts/ui-truth/export-fixtures.sh "http://127.0.0.1:$port" "$tmp/$mode.json" >"$tmp/log" 2>&1; then hb_rc=0; else hb_rc=$?; fi
  kill "$hp" 2>/dev/null; wait "$hp" 2>/dev/null || true
  check "$mode: export aborts non-zero, not a timeout" '[ "$hb_rc" -ne 0 ] && [ "$hb_rc" -ne 124 ]'
  check "$mode: no fixture written"              '[ ! -e "$tmp/$mode.json" ]'
  check "$mode: says why"                        'grep -q "eth_blockNumber unavailable or malformed" "$tmp/log"'
  check "$mode: abort message is printable ASCII and short" \
    '[ "$(LC_ALL=C grep -c "[^ -~]" "$tmp/log")" = 0 ] && [ "$(wc -L <"$tmp/log")" -le 120 ]'
done
check "headhostile: raw RPC bytes not echoed"     '! grep -q "(id)" "$tmp/log"'

# currentEpoch wider than Bash arithmetic: eligible validators are unavailable, not all pending.
run 18630 500200 0 "$tmp/epochhuge.json" 0 epochhuge
check "epochhuge: eligible unavailable"           '[ "$(jq ".reads[] | select(.id==\"eligible_validators\") | .value.unavailable" "$tmp/epochhuge.json")" = true ]'
check "epochhuge: no pending count reported"      '[ "$(jq ".reads[] | select(.id==\"eligible_validators\") | .value | has(\"pending_activation\")" "$tmp/epochhuge.json")" = false ]'

# Peers are labelled as the queried RPC node's own, not a member's or the network's.
check "peers: exported as rpc_node_peer_count"    '[ "$(jq "[.reads[].id] | (index(\"rpc_node_peer_count\") != null) and (index(\"peer_count\") == null)" "$tmp/steady.json")" = true ]'

# The stub answers eth_getTransactionCount (cast 1.5.1 asks for it on eth_call).
python3 -I scripts/ui-truth/stub_rpc.py 18631 500200 0 & np=$!
for _ in $(seq 50); do curl -fsS -o /dev/null -X POST -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' http://127.0.0.1:18631 2>/dev/null && break; sleep 0.1; done
nonce=$(curl -fsS -X POST -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":["0x0000000000000000000000000000000000000001","latest"]}' http://127.0.0.1:18631 | jq -r .result)
kill "$np" 2>/dev/null; wait "$np" 2>/dev/null || true
check "stub: eth_getTransactionCount answered"   '[ "$nonce" = 0x0 ]'

# Bash 3.2 (stock macOS) in a UTF-8 locale: no unbraced $var directly before a non-ASCII byte.
unbraced='[$][A-Za-z_][A-Za-z0-9_]*[^ -~]'
check "bash 3.2: no unbraced expansion before non-ASCII" \
  '! LC_ALL=C grep -nE "$unbraced" scripts/ui-truth/export-fixtures.sh'

# Hostile RPC: timestamps carry a Bash arithmetic-injection payload. It must not execute.
rm -f "$tmp/PWNED"
run 18613 500200 0 "$tmp/hostile.json" 0 hostilets
check "hostile timestamp: payload never executed"   '[ ! -e "$tmp/PWNED" ]'
check "hostile timestamp: block time unavailable"  '[ "$(jq ".reads[] | select(.id==\"block_time_s\") | .value.unavailable" "$tmp/hostile.json")" = true ]'

exit $fail
