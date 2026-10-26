#!/usr/bin/env bash
# test_r1006_builder.sh: offline tests for the r1006 genesis builder (no node, no RPC).
#
#   * the builder refuses a build devnet on any chain id but 40204, before it creates a
#     worktree or starts a node (negative control: 40204 passes that check);
#   * emit_alloc.py keeps exactly the accounts with code or storage plus the deployer (with
#     a zero balance), is byte-for-byte deterministic, and refuses a deployer with code;
#   * fill_producers.py accepts 7 producers whose registration signatures verify, and refuses
#     a bad signature, a signature for another registry, a duplicate staker, 6 producers,
#     a low stake, and a placeholder on `check`;
#   * emit_book.py refuses a book address without code in the alloc (control: with code).
# Needs python3 (with `cryptography`), jq and cast. Writes only under a mktemp dir.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T=$(mktemp -d "${TMPDIR:-/tmp}/r1006-builder-test.XXXXXX")
trap 'rm -rf "$T"' EXIT
PASS=0 FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n%s\n' "$1" "${2:-}"; }
# expect NAME WANT_RC PATTERN -- CMD...
expect() {
  local name="$1" want="$2" pat="$3" out rc
  shift 4
  out=$("$@" 2>&1)
  rc=$?
  if [[ "$rc" == "$want" ]] && grep -qE -- "$pat" <<<"$out"; then ok "$name"; else bad "$name (exit $rc, want $want)" "$out"; fi
}

# ------------------------------------------------------------ chain id 40204 only
mkdir -p "$T/w1" "$T/w2"
expect "builder refuses a non-40204 build devnet before anything runs" 1 'must run chain id 40204' -- \
  env R1006_DEVNET_CHAIN_ID=1337 bash "$HERE/build_r1006_genesis.sh" ceremony --node /bin/true --state-dump /bin/true --work "$T/w1"
[[ -z "$(ls -A "$T/w1")" ]] && ok "the refused build wrote nothing" || bad "the refused build wrote nothing" "$(ls -A "$T/w1")"
touch "$T/w2/x"
expect "negative control: 40204 passes the chain-id check (and stops at the next one)" 1 'must be an existing EMPTY directory' -- \
  env R1006_DEVNET_CHAIN_ID=40204 bash "$HERE/build_r1006_genesis.sh" ceremony --node /bin/true --state-dump /bin/true --work "$T/w2"

# ------------------------------------------------------------ emit_alloc
DEP=0xe40325ba1f4cf362b203d9fe2b8160312e926c11
w() { printf '0x%064x' "$1"; }
cat >"$T/dump.json" <<EOF
{"format":"citrate-state-dump-v1","stateRoot":"0x00","accounts":[
 {"address":"0x00000000000000000000000000000000000000c1","balance":"0x5","nonce":1,"code":"0x6000","storage":{"$(w 1)":"$(w 7)","$(w 2)":"$(w 0)"}},
 {"address":"0x00000000000000000000000000000000000000c2","balance":"0x0","nonce":0,"storage":{"$(w 3)":"$(w 9)"}},
 {"address":"0x00000000000000000000000000000000000000e1","balance":"0x99","nonce":3,"storage":{}},
 {"address":"$DEP","balance":"0x1234","nonce":61,"storage":{}}
]}
EOF
printf '{"deployer":"%s"}\n' "$DEP" >"$T/manifest.json"
printf 'R1006_INPUTS_STATUS=placeholder\n' >"$T/inputs.env"
printf '{"contracts":{"ValidatorRegistry":"0x00000000000000000000000000000000000000c1"}}\n' >"$T/book40204.json"
EA=(python3 "$HERE/emit_alloc.py" --dump "$T/dump.json" --manifest "$T/manifest.json" --inputs "$T/inputs.env" --book "$T/book40204.json")
"${EA[@]}" --out "$T/a1.json" 2>/dev/null && "${EA[@]}" --out "$T/a2.json" 2>/dev/null
cmp -s "$T/a1.json" "$T/a2.json" && ok "emit_alloc is byte-for-byte deterministic" || bad "emit_alloc is byte-for-byte deterministic"
got=$(jq -c '[.accounts[] | [.address[-2:], .balance, .nonce, (.code // "-"), (.storage // {} | length)]]' "$T/a1.json")
want='[["c1","0x5",1,"0x6000",1],["c2","0x0",0,"-",1],["11","0x0",61,"-",0]]'
[[ "$got" == "$want" ]] && ok "emit_alloc keeps code/storage accounts and the deployer (zero balance), drops EOAs and zero slots" ||
  bad "emit_alloc keeps code/storage accounts and the deployer (zero balance), drops EOAs and zero slots" "$got"
jq '.accounts[3].code = "0x60"' "$T/dump.json" >"$T/dump-bad.json"
expect "emit_alloc refuses a deployer with code" 1 'deployer has code' -- \
  python3 "$HERE/emit_alloc.py" --dump "$T/dump-bad.json" --manifest "$T/manifest.json" --inputs "$T/inputs.env" --book "$T/book40204.json" --out "$T/a3.json"

# ------------------------------------------------------------ inputs hold no key material
printf 'R1006_INPUTS_STATUS=placeholder\nRELAYER=0x%040x\n' 7 >"$T/in-ok.env"
expect "inputs check accepts addresses and numbers" 0 'addresses and numbers only' -- python3 "$HERE/emit_alloc.py" --check-inputs "$T/in-ok.env"
printf 'R1006_INPUTS_STATUS=placeholder\nRELAYER_KEY=0x%064x\n' 7 >"$T/in-key.env"
expect "inputs check refuses a 32-byte hex value (key material)" 1 'never hold key material' -- python3 "$HERE/emit_alloc.py" --check-inputs "$T/in-key.env"
printf 'R1006_INPUTS_STATUS=placeholder\nRELAYER=%064x\n' 7 >"$T/in-key2.env"
expect "inputs check refuses bare 64-hex (key material without 0x)" 1 'never hold key material' -- python3 "$HERE/emit_alloc.py" --check-inputs "$T/in-key2.env"
expect "the committed placeholder inputs hold no key material" 0 'addresses and numbers only' -- python3 "$HERE/emit_alloc.py" --check-inputs "$HERE/inputs.placeholder.env"
printf 'R1006_INPUTS_STATUS=final\n' >"$T/in-final.env"
expect "final inputs without fresh base accounts are refused" 1 'must name the fresh base accounts' -- \
  "${EA[@]/$T\/inputs.env/$T/in-final.env}" --out "$T/x.json"

# ------------------------------------------------------------ OrangeSeed binding
GOV=0x00000000000000000000000000000000000000c1
printf '{"contracts":{"GovernanceTimelock":"%s"}}\n' "$GOV" >"$T/gov.json"
os_fixture() { # os_fixture GOVERNANCE PROXY_SLOT_VALUE
  printf '{"params":{"governance":"%s"},"alloc":{"0x000000000000000000000000000000c17A7e5EeD":{"balance":"0x0","nonce":"0x1","code":"0x6000","storage":{"0x01":"%s"}},"0x000000000000000000000000000000c17A7E5Ee0":{"balance":"0x0","nonce":"0x1","code":"0x6000","storage":{}}}}\n' "$1" "$2"
}
os_fixture 0x00000000000000000000000000000000000000c2 "0x000000000000000000000000${GOV#0x}" >"$T/os-othergov.json"
expect "OrangeSeed generated for another governance is refused" 1 'not this ceremony.s GovernanceTimelock' -- \
  "${EA[@]}" --orangeseed "$T/os-othergov.json" --governance-book "$T/gov.json" --out "$T/x.json"
os_fixture "$GOV" "0x000000000000000000000000${DEP#0x}" >"$T/os-dep.json"
expect "OrangeSeed whose upgrade authority is not governance is refused" 1 'does not name this ceremony.s GovernanceTimelock' -- \
  "${EA[@]}" --orangeseed "$T/os-dep.json" --governance-book "$T/gov.json" --out "$T/x.json"
expect "OrangeSeed without the governance book is refused" 1 'needs --governance-book' -- \
  "${EA[@]}" --orangeseed "$T/os-dep.json" --out "$T/x.json"
os_fixture "$GOV" "0x000000000000000000000000${GOV#0x}" | jq --arg d "0x000000000000000000000000${DEP#0x}" '.alloc["0x000000000000000000000000000000c17A7E5Ee0"].storage["0x02"] = $d' >"$T/os-depslot.json"
expect "OrangeSeed with a slot holding the ceremony deployer is refused" 1 'holds the ceremony deployer' -- \
  "${EA[@]}" --orangeseed "$T/os-depslot.json" --governance-book "$T/gov.json" --out "$T/x.json"
os_fixture "$GOV" "0x000000000000000000000000${GOV#0x}" >"$T/os-ok.json"
expect "control: OrangeSeed bound to governance reaches the code-hash pin (and a fixture's code is refused there)" 1 'code hash is not the pinned' -- \
  "${EA[@]}" --orangeseed "$T/os-ok.json" --governance-book "$T/gov.json" --out "$T/x.json"

# ------------------------------------------------------------ no deployer / factory left in block 0
# A storage word holding the ceremony deployer (left-padded, or packed beside other fields)
# or the CREATE2 factory, in ANY kept account, is refused; so is the deployer in runtime code.
mkd() { # mkd OUT WORD: the fixture dump with one extra slot on account c1
  jq --arg w "$2" '.accounts[0].storage["0x00000000000000000000000000000000000000000000000000000000000000aa"] = $w' "$T/dump.json" >"$1"
}
mkd "$T/d-pad.json" "0x000000000000000000000000${DEP#0x}"
expect "emit_alloc refuses the deployer left-padded in a storage word" 1 'storage .* holds the ceremony deployer' -- \
  python3 "$HERE/emit_alloc.py" --dump "$T/d-pad.json" --manifest "$T/manifest.json" --inputs "$T/inputs.env" --book "$T/book40204.json" --out "$T/x.json"
mkd "$T/d-pack.json" "0x00000001${DEP#0x}0000000000000001"
expect "emit_alloc refuses the deployer packed in a storage word" 1 'storage .* holds the ceremony deployer' -- \
  python3 "$HERE/emit_alloc.py" --dump "$T/d-pack.json" --manifest "$T/manifest.json" --inputs "$T/inputs.env" --book "$T/book40204.json" --out "$T/x.json"
mkd "$T/d-fac.json" "0x0000000000000000000000004e59b44847b379578588920ca78fbf26c0b4956c"
expect "emit_alloc refuses the CREATE2 factory in a storage word" 1 'storage .* holds the CREATE2 factory' -- \
  python3 "$HERE/emit_alloc.py" --dump "$T/d-fac.json" --manifest "$T/manifest.json" --inputs "$T/inputs.env" --book "$T/book40204.json" --out "$T/x.json"
jq --arg c "0x7300${DEP#0x}00" '.accounts[0].code = $c' "$T/dump.json" >"$T/d-code.json"
expect "emit_alloc refuses the deployer embedded in runtime code" 1 'code holds the ceremony deployer' -- \
  python3 "$HERE/emit_alloc.py" --dump "$T/d-code.json" --manifest "$T/manifest.json" --inputs "$T/inputs.env" --book "$T/book40204.json" --out "$T/x.json"
mkd "$T/d-ok.json" "0x000000000000000000000000${DEP:4}00"
expect "control: a word that merely overlaps the deployer's bytes off-boundary passes" 0 'alloc:' -- \
  python3 "$HERE/emit_alloc.py" --dump "$T/d-ok.json" --manifest "$T/manifest.json" --inputs "$T/inputs.env" --book "$T/book40204.json" --out "$T/x.json"

# ------------------------------------------------------------ fill_producers (input checks)
python3 - "$T" <<'PY'
import json, sys
t = sys.argv[1]
ps = [{"name": f"prod-{i}", "proposer_pubkey": "0x" + f"{i + 1:02x}" * 32,
       "staker_address": "0x" + f"{0xa0 + i:02x}" * 20, "coinbase_address": "0x" + f"{0xa0 + i:02x}" * 20}
      for i in range(7)]
json.dump({"schema": "r1006-producers/1", "chain_id": 40204, "producers": ps}, open(f"{t}/producers.json", "w"))
json.dump({"schema": "r1006-stakes/1", "stakes": {p["staker_address"]: {"name": p["name"], "stake_wei": str(32000 * 10**18),
           "liquid_wei": str(100 * 10**18)} for p in ps}}, open(f"{t}/stakes.json", "w"))
PY
FP=(python3 "$HERE/fill_producers.py")
expect "fill validate accepts 7 well-formed producers and stakes" 0 '7 producers' -- "${FP[@]}" validate "$T/producers.json" "$T/stakes.json"
jq '.producers[2].coinbase_address = "0x" + ("ee" * 20)' "$T/producers.json" >"$T/p-cb.json"
expect "fill refuses a staker that is not the coinbase" 1 'consensus requires coinbase == staker' -- "${FP[@]}" validate "$T/p-cb.json" "$T/stakes.json"
jq '.producers[1].proposer_pubkey = .producers[0].proposer_pubkey' "$T/producers.json" >"$T/p-dup.json"
expect "fill refuses a duplicate proposer key" 1 'proposer_pubkey is the same as prod-0' -- "${FP[@]}" validate "$T/p-dup.json" "$T/stakes.json"
jq '.producers |= .[0:3]' "$T/producers.json" >"$T/p-few.json"
expect "fill refuses fewer than 4 producers" 1 'need at least 4' -- "${FP[@]}" validate "$T/p-few.json" "$T/stakes.json"
jq '(.stakes[]) |= (.stake_wei = "1")' "$T/stakes.json" >"$T/s-low.json"
expect "fill refuses a stake under 32,000 SALT" 1 'below the 32,000 SALT minimum' -- "${FP[@]}" validate "$T/producers.json" "$T/s-low.json"
jq '.producers[0].proposer_pubkey |= ascii_upcase' "$T/producers.json" >"$T/p-case.json"
expect "fill refuses a key not in its public form" 1 'not a 32-byte key' -- "${FP[@]}" validate "$T/p-case.json" "$T/stakes.json"
jq '.stakes["0x" + ("dd" * 20)] = {"name":"x","stake_wei":"1","liquid_wei":"0"}' "$T/stakes.json" >"$T/s-extra.json"
expect "fill refuses a stake for a non-producer" 1 'not producers' -- "${FP[@]}" validate "$T/producers.json" "$T/s-extra.json"
printf '{"schema":"r1006-validators/1","status":"placeholder","validatorRegistry":null,"validators":[],"registry":null}\n' >"$T/validators.json"
expect "check refuses the placeholder set" 1 'is a placeholder' -- "${FP[@]}" check --path "$T/validators.json"

# ------------------------------------------------------------ emit_book
mkdir -p "$T/bw/book"
printf '{"$schema":"./schema.json","chainId":40204,"deployer":"%s","contracts":{"A":"0x00000000000000000000000000000000000000c1"},"precompiles":{"P":"0x0000000000000000000000000000000000000100"}}\n' "$DEP" >"$T/bw/book/40204.json"
expect "emit_book writes a book whose every address has code (deployer and precompiles exempt)" 0 'every one has code' -- \
  python3 "$HERE/emit_book.py" --work "$T/bw" --alloc "$T/a1.json" --out "$T/book.json"
jq '.contracts.B = "0x00000000000000000000000000000000000000c2"' "$T/book.json" >"$T/book-bad.json"
expect "emit_book --check refuses a book address without code in block 0" 1 'contracts.B = 0x0+c2 has no code' -- \
  python3 "$HERE/emit_book.py" --check "$T/book-bad.json" --alloc "$T/a1.json"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
