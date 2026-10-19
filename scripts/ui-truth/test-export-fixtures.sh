#!/usr/bin/env bash
# Offline test for export-fixtures.sh against stub_rpc.py (no network, no chain):
#   1. a steady head inside one epoch  -> single_epoch true, per-read observed_head set
#   2. a head that crosses an epoch boundary mid-export -> single_epoch false + warning
#   3. producing_validators counts the distinct proposers over the sampled window
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d); trap 'jobs -p | xargs -r kill 2>/dev/null; rm -rf "$tmp"' EXIT
fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

run() {  # port start step out [fail_mod]
  python3 -I scripts/ui-truth/stub_rpc.py "$1" "$2" "$3" "${5:-0}" & local pid=$!
  for _ in $(seq 50); do curl -fsS -o /dev/null -X POST -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' "http://127.0.0.1:$1" 2>/dev/null && break; sleep 0.1; done
  scripts/ui-truth/export-fixtures.sh "http://127.0.0.1:$1" "$4" >"$tmp/log" 2>&1 || { cat "$tmp/log"; return 1; }
  kill "$pid"; wait "$pid" 2>/dev/null || true
}

run 18601 500200 0 "$tmp/steady.json"
check "steady: single_epoch true"            '[ "$(jq -r .single_epoch "$tmp/steady.json")" = true ]'
check "steady: every read is labelled latest" '[ "$(jq "[.reads[] | select(.state != \"latest\")] | length" "$tmp/steady.json")" = 0 ]'
check "steady: every read has observed_head"  '[ "$(jq "[.reads[] | select(.observed_head == null)] | length" "$tmp/steady.json")" = 0 ]'
check "steady: no read_at_block claim"        '[ "$(jq "has(\"read_at_block\")" "$tmp/steady.json")" = false ]'
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

exit $fail
