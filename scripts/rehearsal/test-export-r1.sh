#!/usr/bin/env bash
# Test for export-r1.sh. No public network: offline mode reads repo files only, and the online
# cases run against scripts/ui-truth/stub_rpc.py on loopback.
#   1. offline dry run: bundle written, manifest provenance, checksums verify, labelled not-a-rehearsal
#   2. refusals: book/claims chain id mismatch, missing fixture contract, malformed address,
#      non-empty output dir, dirty inputs without --allow-dirty, online without --expect-genesis
#   3. online against the stub: happy path records height + genesis; RPC chain id mismatch and
#      genesis mismatch refuse and leave no bundle; a governance address with no code, or whose
#      minDelay() read fails, refuses
#   4. provenance, in a throwaway local clone: a modified verification script, wrapper or
#      offline fixture refuses without --allow-dirty and is recorded with it
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d); trap 'jobs -p | xargs -r kill 2>/dev/null; rm -rf "${tmp:?}"' EXIT
fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
X=scripts/rehearsal/export-r1.sh
refuses() {  # name expected-message args...
  local name=$1 msg=$2; shift 2
  local rc=0; "$X" "$@" >"$tmp/log" 2>&1 || rc=$?
  check "refuses: $name (non-zero)" '[ "$rc" -ne 0 ]'
  check "refuses: $name (says why)" 'grep -q -- "$msg" "$tmp/log"'
}

# ── 1. offline dry run ──
"$X" --offline --out "$tmp/off" >"$tmp/log" 2>&1 || { cat "$tmp/log"; exit 1; }
M="$tmp/off/MANIFEST.json"
check "offline: three files + manifest + sums" '[ -s "$tmp/off/ui-truth-fixture.json" ] && [ -s "$tmp/off/addresses-40204.json" ] && [ -s "$tmp/off/claims.json" ] && [ -s "$M" ] && [ -s "$tmp/off/SHA256SUMS" ]'
check "offline: sha256sum -c passes"       '(cd "$tmp/off" && sha256sum -c --quiet SHA256SUMS)'
check "offline: manifest hashes match files" '[ "$(jq -r ".files[] | \"\(.sha256)  \(.name)\"" "$M")" = "$(cat "$tmp/off/SHA256SUMS")" ]'
check "offline: git sha is HEAD"            '[ "$(jq -r .source.git_sha "$M")" = "$(git rev-parse HEAD)" ]'
check "offline: chain id 40204"             '[ "$(jq .chain.chain_id "$M")" = 40204 ]'
check "offline: no height claimed"          '[ "$(jq .chain.rpc_block_height "$M")" = null ] && [ "$(jq .chain.genesis_hash "$M")" = null ]'
check "offline: labelled not a rehearsal export" '[ "$(jq .rehearsal_export "$M")" = false ] && jq -r .note "$M" | grep -q "OFFLINE DRY RUN"'
check "offline: book copied byte-for-byte"  'cmp -s "$tmp/off/addresses-40204.json" contracts/addresses/40204.json'
check "offline: claims copied byte-for-byte" 'cmp -s "$tmp/off/claims.json" verification/claims.json'
check "offline: inputs clean"               '[ "$(jq ".source.inputs_differ_from_head | length" "$M")" = 0 ]'
check "offline: no staging dir left"        '[ -z "$(ls -A "$tmp" | grep "^\.export-r1")" ]'

# ── 2. refusals ──
refuses "non-empty output dir" "is not empty" --offline --out "$tmp/off"
jq '.chainId = 1' contracts/addresses/40204.json > "$tmp/book-chain.json"
refuses "book vs claims chain id" "chain id mismatch" --offline --allow-dirty --book "$tmp/book-chain.json" --out "$tmp/r1"
jq 'del(.contracts.ValidatorRegistry)' contracts/addresses/40204.json > "$tmp/book-novr.json"
refuses "missing fixture contract" "no usable address for ValidatorRegistry" --offline --allow-dirty --book "$tmp/book-novr.json" --out "$tmp/r2"
jq '.contracts.SkillRegistry = "0x1234"' contracts/addresses/40204.json > "$tmp/book-bad.json"
refuses "malformed address" "malformed address" --offline --allow-dirty --book "$tmp/book-bad.json" --out "$tmp/r3"
cp contracts/addresses/40204.json "$tmp/book-copy.json"
refuses "untracked book without --allow-dirty" "inputs differ from HEAD" --offline --book "$tmp/book-copy.json" --out "$tmp/r4"
refuses "online needs --expect-genesis" "expect-genesis" --rpc http://127.0.0.1:9 --out "$tmp/r5"
check "refusals leave no bundle" '[ ! -e "$tmp/r1" ] && [ ! -e "$tmp/r2" ] && [ ! -e "$tmp/r3" ] && [ ! -e "$tmp/r4" ] && [ ! -e "$tmp/r5" ]'

# The scratch copy with --allow-dirty is accepted and recorded.
"$X" --offline --allow-dirty --book "$tmp/book-copy.json" --out "$tmp/dirty" >"$tmp/log" 2>&1 || { cat "$tmp/log"; exit 1; }
check "allow-dirty: recorded in the manifest" '[ "$(jq ".source.inputs_differ_from_head | length" "$tmp/dirty/MANIFEST.json")" -ge 1 ]'

# ── 3. online against the stub ──
G0=0x$(printf '0%.0s' $(seq 64))
stub() {  # port chain-id-hex
  STUB_CHAIN_ID=$2 python3 -I scripts/ui-truth/stub_rpc.py "$1" 500200 0 & STUB=$!
  for _ in $(seq 50); do curl -fsS -o /dev/null -X POST -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' "http://127.0.0.1:$1" 2>/dev/null && break; sleep 0.1; done
}
stub 18621 0x9d0c
"$X" --rpc http://127.0.0.1:18621 --expect-genesis "$G0" --out "$tmp/on" >"$tmp/log" 2>&1 || { cat "$tmp/log"; exit 1; }
M="$tmp/on/MANIFEST.json"
check "online: rehearsal export"              '[ "$(jq .rehearsal_export "$M")" = true ] && [ "$(jq -r .mode "$M")" = online ]'
check "online: RPC height recorded"           '[ "$(jq .chain.rpc_block_height "$M")" -ge 500200 ]'
check "online: genesis + rpc chain recorded"  '[ "$(jq -r .chain.genesis_hash "$M")" = "$G0" ] && [ "$(jq .chain.rpc_chain_id "$M")" = 40204 ]'
check "online: fixture freshly exported"      '[ "$(jq -r .head_at_start "$tmp/on/ui-truth-fixture.json")" -ge 500200 ]'
check "online: sha256sum -c passes"           '(cd "$tmp/on" && sha256sum -c --quiet SHA256SUMS)'
check "online: live address-code gate ran"    'jq -r ".gates[]" "$M" | grep -q "check_address_code.py --check"'
refuses "genesis mismatch" "genesis mismatch" --rpc http://127.0.0.1:18621 --expect-genesis "0x$(printf 'a%.0s' $(seq 64))" --out "$tmp/r6"
kill "$STUB"; wait "$STUB" 2>/dev/null || true

stub 18622 0x1
refuses "RPC chain id mismatch" "RPC http://127.0.0.1:18622 serves 1" --rpc http://127.0.0.1:18622 --expect-genesis "$G0" --out "$tmp/r7"
kill "$STUB"; wait "$STUB" 2>/dev/null || true
check "online refusals leave no bundle" '[ ! -e "$tmp/r6" ] && [ ! -e "$tmp/r7" ]'

# Governance addresses take part in the live gates.
govs=$(python3 -I - <<'PY'
import json, sys
sys.path.insert(0, "verification")
import check_address_code as c
book = json.load(open("contracts/addresses/40204.json"))
print(" ".join(sorted(n for n, _ in c.book_entries(book) if n.startswith("governance."))))
PY
)
check "address-code entries include governance" '[ "$govs" = "governance.GOVERNANCE governance.GUARDIAN" ]'
GOV=$(jq -r .governance.GOVERNANCE contracts/addresses/40204.json)
GRD=$(jq -r .governance.GUARDIAN contracts/addresses/40204.json)
STUB_CODELESS=${GRD,,} stub 18623 0x9d0c
refuses "governance address without code" "address-code check failed" --rpc http://127.0.0.1:18623 --expect-genesis "$G0" --out "$tmp/r8"
kill "$STUB"; wait "$STUB" 2>/dev/null || true
STUB_CALL_FAIL=$GOV stub 18624 0x9d0c
refuses "governance minDelay() read failed" "governance_min_delay_s failed" --rpc http://127.0.0.1:18624 --expect-genesis "$G0" --out "$tmp/r9"
kill "$STUB"; wait "$STUB" 2>/dev/null || true
check "governance refusals leave no bundle" '[ ! -e "$tmp/r8" ] && [ ! -e "$tmp/r9" ]'

# ── 4. provenance (a throwaway clone; the checkout under test is never modified) ──
R="$tmp/repo"
git clone -q --shared --no-checkout . "$R"
git -C "$R" checkout -q --detach HEAD
# Test the working-tree versions of the files under test, committed in the clone.
for f in scripts/rehearsal/export-r1.sh scripts/rehearsal/test-export-r1.sh scripts/ui-truth/export-fixtures.sh \
         scripts/ui-truth/stub_rpc.py verification/check_address_code.py verification/check_claims.py; do
  cp "$f" "$R/$f"
done
git -C "$R" -c user.email=t@t -c user.name=t -c commit.gpgsign=false commit -q -am "test: files under test" >/dev/null 2>&1 || true
RX="$R/scripts/rehearsal/export-r1.sh"
prov_refuses() {  # name file-to-modify (check() evals in this scope: no $1/$2 inside it)
  local pn=$1 pf=$2 prc=0
  if [[ "$pf" == *.json ]]; then  # keep it valid JSON so only provenance can refuse it
    jq '.local_edit = true' "$R/$pf" > "$tmp/edit.json" && cp "$tmp/edit.json" "$R/$pf"
  else
    echo "# local edit" >> "$R/$pf"
  fi
  "$RX" --offline --out "$tmp/p-$pn" >"$tmp/log" 2>&1 || prc=$?
  check "provenance: modified $pf refuses" '[ "$prc" -ne 0 ] && grep -qF "$pf" "$tmp/log" && grep -q "inputs differ from HEAD" "$tmp/log" && [ ! -e "$tmp/p-$pn" ]'
  prc=0
  "$RX" --offline --allow-dirty --out "$tmp/pd-$pn" >"$tmp/log" 2>&1 || prc=$?
  check "provenance: modified $pf recorded with --allow-dirty" \
    '[ "$prc" -eq 0 ] && jq -e --arg f "$pf" ".source.inputs_differ_from_head | index(\$f)" "$tmp/pd-$pn/MANIFEST.json" >/dev/null'
  git -C "$R" checkout -q -- "$pf"
}
prov_refuses checkclaims verification/check_claims.py
prov_refuses checkcode verification/check_address_code.py
prov_refuses wrapper scripts/rehearsal/export-r1.sh
prov_refuses fixture "$(git -C "$R" ls-files 'docs/ui-truth/fixtures/40204-*.json' | sort | tail -1)"
cp "$R/$(git -C "$R" ls-files 'docs/ui-truth/fixtures/40204-*.json' | sort | tail -1)" "$tmp/fx-copy.json"
rc=0; "$RX" --offline --fixture "$tmp/fx-copy.json" --out "$tmp/p-untracked" >"$tmp/log" 2>&1 || rc=$?
check "provenance: an untracked offline fixture refuses" '[ "$rc" -ne 0 ] && grep -q "inputs differ from HEAD" "$tmp/log"'

exit $fail
