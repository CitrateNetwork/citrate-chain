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

# ------------------------------------------------------------ fill_producers
VR=0x1111111111111111111111111111111111111111
python3 - "$T" "$VR" "$HERE" <<'PY'
import json, sys, subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
t, vr, here = sys.argv[1:4]
sys.path.insert(0, here)
import fill_producers as fp
ps = []
for i in range(7):
    k = Ed25519PrivateKey.from_private_bytes(bytes([i + 1]) * 32)  # throwaway test keys
    pk = "0x" + k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    staker = "0x" + bytes([0xA0 + i]) .hex() * 20
    sig = "0x" + k.sign(fp.digest(vr, staker, pk)).hex()
    ps.append({"name": f"p{i}", "staker": staker, "proposerPubkey": pk, "registrationSig": sig, "stake": str(32000 * 10**18)})
json.dump({"producers": ps}, open(f"{t}/producers.json", "w"))
PY
FP=(python3 "$HERE/fill_producers.py")
expect "fill accepts 7 producers whose signatures verify" 0 '7 producers verified' -- "${FP[@]}" fill --registry "$VR" --from "$T/producers.json" --out "$T/v.json"
expect "check re-verifies the filled file" 0 'OK' -- "${FP[@]}" check --path "$T/v.json"
expect "fill refuses signatures made for another registry" 1 'does not verify' -- "${FP[@]}" fill --registry 0x2222222222222222222222222222222222222222 --from "$T/producers.json" --out "$T/x.json"
jq '.producers[3].registrationSig |= (.[0:-2] + (if .[-2:] == "00" then "01" else "00" end))' "$T/producers.json" >"$T/p-badsig.json"
expect "fill refuses a tampered signature" 1 'p3: registrationSig does not verify' -- "${FP[@]}" fill --registry "$VR" --from "$T/p-badsig.json" --out "$T/x.json"
jq '.producers[1].staker = .producers[0].staker' "$T/producers.json" >"$T/p-dup.json"
expect "fill refuses a duplicate staker" 1 'duplicate staker' -- "${FP[@]}" fill --registry "$VR" --from "$T/p-dup.json" --out "$T/x.json"
jq '.producers |= .[0:6]' "$T/producers.json" >"$T/p-six.json"
expect "fill refuses 6 producers" 1 '6 producers, want 7' -- "${FP[@]}" fill --registry "$VR" --from "$T/p-six.json" --out "$T/x.json"
jq '.producers[2].stake = "1"' "$T/producers.json" >"$T/p-low.json"
expect "fill refuses a stake under 32,000 SALT" 1 'below the 32,000 SALT minimum' -- "${FP[@]}" fill --registry "$VR" --from "$T/p-low.json" --out "$T/x.json"
expect "check refuses the placeholder set" 1 'is a placeholder' -- "${FP[@]}" check --path "$T/validators.json"
d1=$("${FP[@]}" digest --registry "$VR" --staker 0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 --pubkey "$(jq -r '.producers[0].proposerPubkey' "$T/producers.json")")
[[ "$d1" =~ ^0x[0-9a-f]{64}$ ]] && ok "digest prints the 32-byte registration digest" || bad "digest prints the 32-byte registration digest" "$d1"

# ------------------------------------------------------------ emit_book
mkdir -p "$T/bw/book"
printf '{"$schema":"./schema.json","chainId":40204,"deployer":"%s","contracts":{"A":"0x00000000000000000000000000000000000000c1"},"precompiles":{"P":"0x0000000000000000000000000000000000000100"}}\n' "$DEP" >"$T/bw/book/40204.json"
printf '{"KYCRegistry":"0x00000000000000000000000000000000000000c1","MembershipSBT":"0x00000000000000000000000000000000000000c1"}\n' >"$T/bw/standins.json"
expect "emit_book writes a book whose every address has code (deployer and precompiles exempt)" 0 'every one has code' -- \
  python3 "$HERE/emit_book.py" --work "$T/bw" --alloc "$T/a1.json" --out "$T/book.json"
jq '.contracts.B = "0x00000000000000000000000000000000000000c2"' "$T/book.json" >"$T/book-bad.json"
expect "emit_book --check refuses a book address without code in block 0" 1 'contracts.B = 0x0+c2 has no code' -- \
  python3 "$HERE/emit_book.py" --check "$T/book-bad.json" --alloc "$T/a1.json"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]
