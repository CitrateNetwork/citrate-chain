#!/usr/bin/env bash
# test_make_inputs.sh: make_inputs.py takes every governance and guardian owner as a
# parameter (fed #493). Portable (macOS bash 3.2 and Linux); no network, no keys.
#   bash scripts/genesis/r1006/test_make_inputs.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/make-inputs.XXXXXX")"
trap 'rm -rf -- "$T"' EXIT
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; [ -z "${2:-}" ] || printf '%s\n' "$2" | sed 's/^/    | /'; fail=1; }

# The six R2-era owners that r1006 kept. None may reach an inputs file unless passed in.
R2="b4e186cbeab88c8220f3d69f4263fffcf4c6ada9 a6bb945bd72684951721ff99aecfddb48ae22b8b e154af73bb03bc6073a4f08d6868184774014daf cc9ee1f2c11c53e2b9c30c61848ee50f12a690dc 1b0c84e457605a065beb0b2306efa0fb54b33e8a 8547d47d144877a75de0097d5e35da8a355c8e3f"
OTHER="TREASURY FAUCET RELAYER TEAM SIGNER_1 SIGNER_2 SIGNER_3 CITRATE_AA_OWNER CITRATE_AA_IDENTITY_SIGNER CITRATE_AA_SPONSOR_SIGNER MEMBERSHIP_GRANTOR"
COUNCIL="GOV1 GOV2 GOV3 GOV4 GOV5 GRD1 GRD2 GRD3"
addr() { printf '0x%040x' "$1"; }
write() { # file, roles...
  f=$1; shift; : > "$f"; i=0
  for r in "$@"; do i=$((i + 1)); echo "$r=$(addr $((0x1000 + i)))" >> "$f"; done
}

# 1. The r1006 shape (fresh GOV4/GOV5 only) is refused: GOV1-3 and GRD1-3 are required.
write "$T/old.env" $OTHER GOV4 GOV5
if out=$(python3 "$HERE/make_inputs.py" --addresses "$T/old.env" 2>&1); then
  bad "make_inputs: refuses addresses without GOV1-3 and GRD1-3" "$out"
elif printf '%s' "$out" | grep -q "GOV1" && printf '%s' "$out" | grep -q "GRD1"; then
  ok "make_inputs: refuses addresses without GOV1-3 and GRD1-3, and names them"
else
  bad "make_inputs: refuses addresses without GOV1-3 and GRD1-3, and names them" "$out"
fi

# 2. With every owner passed in, the councils are exactly those, and no R2 owner appears.
write "$T/full.env" $OTHER $COUNCIL
if out=$(python3 "$HERE/make_inputs.py" --addresses "$T/full.env" 2>&1); then
  want_gov=""; want_grd=""
  for r in GOV1 GOV2 GOV3 GOV4 GOV5; do want_gov="$want_gov,$(grep "^$r=" "$T/full.env" | cut -d= -f2)"; done
  for r in GRD1 GRD2 GRD3; do want_grd="$want_grd,$(grep "^$r=" "$T/full.env" | cut -d= -f2)"; done
  if printf '%s\n' "$out" | grep -qx "GOV_OWNERS=${want_gov#,}" && printf '%s\n' "$out" | grep -qx "GRD_OWNERS=${want_grd#,}"; then
    ok "make_inputs: GOV_OWNERS = GOV1..GOV5 and GRD_OWNERS = GRD1..GRD3 as passed"
  else
    bad "make_inputs: GOV_OWNERS = GOV1..GOV5 and GRD_OWNERS = GRD1..GRD3 as passed" "$out"
  fi
  leaked=""
  for a in $R2; do printf '%s' "$out" | grep -qi "$a" && leaked="$leaked $a"; done
  [ -z "$leaked" ] && ok "make_inputs: no hard-coded R2 owner in the output" || bad "make_inputs: no hard-coded R2 owner in the output" "$leaked"
else
  bad "make_inputs: accepts a full set of owners" "$out"
fi

# 3. A council owner that also holds another role is refused.
write "$T/dup.env" $OTHER $COUNCIL
sed -i.bak "s/^GRD2=.*/GRD2=$(grep '^TREASURY=' "$T/dup.env" | cut -d= -f2)/" "$T/dup.env"
if python3 "$HERE/make_inputs.py" --addresses "$T/dup.env" >/dev/null 2>&1; then
  bad "make_inputs: refuses an owner in two roles"
else
  ok "make_inputs: refuses an owner in two roles"
fi

# 4. The owner's keygen names the councils GOV_OWNER_1..5 / GRD_OWNER_1..3 (2026-11-11).
#    Both spellings are accepted and give the same councils; mixing them, or naming one seat
#    twice, is refused.
OWNERNAMES="GOV_OWNER_1 GOV_OWNER_2 GOV_OWNER_3 GOV_OWNER_4 GOV_OWNER_5 GRD_OWNER_1 GRD_OWNER_2 GRD_OWNER_3"
write "$T/owner.env" $OTHER $OWNERNAMES
# The owner's file also carries roles make_inputs does not read; they must not break it.
for extra in DEPLOYER POSTGENESIS_DEPLOYER DPF_OPERATOR BUNDLER RADAR_DEPLOYER CHATBOT_RELAYER; do
  echo "$extra=$(addr $((0x2000 + ${#extra})))" >> "$T/owner.env"
done
if out_o=$(python3 "$HERE/make_inputs.py" --addresses "$T/owner.env" 2>&1); then
  # the same seats in the short spelling must give identical councils
  sed -e 's/^GOV_OWNER_/GOV/' -e 's/^GRD_OWNER_/GRD/' "$T/owner.env" > "$T/short.env"
  out_s=$(python3 "$HERE/make_inputs.py" --addresses "$T/short.env" 2>&1) || true
  if [ "$(printf '%s\n' "$out_o" | grep -E '^(GOV|GRD)_OWNERS=')" = "$(printf '%s\n' "$out_s" | grep -E '^(GOV|GRD)_OWNERS=')" ] &&
     printf '%s\n' "$out_o" | grep -q "^GOV_OWNERS=$(grep '^GOV_OWNER_1=' "$T/owner.env" | cut -d= -f2),"; then
    ok "make_inputs: GOV_OWNER_n / GRD_OWNER_n give the same councils as GOVn / GRDn"
  else
    bad "make_inputs: GOV_OWNER_n / GRD_OWNER_n give the same councils as GOVn / GRDn" "$out_o
---
$out_s"
  fi
else
  bad "make_inputs: accepts the owner's GOV_OWNER_n / GRD_OWNER_n names" "$out_o"
fi
write "$T/mixed.env" $OTHER GOV1 GOV2 GOV3 GOV_OWNER_4 GOV_OWNER_5 GRD1 GRD2 GRD3
if out=$(python3 "$HERE/make_inputs.py" --addresses "$T/mixed.env" 2>&1); then
  bad "make_inputs: refuses a file that mixes the two spellings" "$out"
elif printf '%s' "$out" | grep -q "mixes"; then
  ok "make_inputs: refuses a file that mixes the two spellings"
else
  bad "make_inputs: refuses a file that mixes the two spellings (for that reason)" "$out"
fi
write "$T/twice.env" $OTHER $OWNERNAMES
echo "GOV1=$(grep '^GOV_OWNER_1=' "$T/twice.env" | cut -d= -f2)" >> "$T/twice.env"
if out=$(python3 "$HERE/make_inputs.py" --addresses "$T/twice.env" 2>&1); then
  bad "make_inputs: refuses one seat named twice (GOV1 and GOV_OWNER_1)" "$out"
elif printf '%s' "$out" | grep -q "both"; then
  ok "make_inputs: refuses one seat named twice (GOV1 and GOV_OWNER_1)"
else
  bad "make_inputs: refuses one seat named twice (GOV1 and GOV_OWNER_1) (for that reason)" "$out"
fi
write "$T/dupkey.env" $OTHER $OWNERNAMES
echo "GOV_OWNER_2=$(addr 0x3001)" >> "$T/dupkey.env"
if out=$(python3 "$HERE/make_inputs.py" --addresses "$T/dupkey.env" 2>&1); then
  bad "make_inputs: refuses a role line given twice" "$out"
elif printf '%s' "$out" | grep -q "more than once"; then
  ok "make_inputs: refuses a role line given twice"
else
  bad "make_inputs: refuses a role line given twice (for that reason)" "$out"
fi

[ "$fail" -eq 0 ] && echo "make_inputs tests: all passed" || { echo "make_inputs tests: FAIL"; exit 1; }
