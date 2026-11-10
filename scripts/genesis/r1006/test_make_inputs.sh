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

[ "$fail" -eq 0 ] && echo "make_inputs tests: all passed" || { echo "make_inputs tests: FAIL"; exit 1; }
