#!/usr/bin/env bash
# Test fixture for scripts/ops/tests/test_r1006_bringup.py: stands in for
# `citrate host-identity` so the bring-up's key step can be tested without a node build.
# It writes CANARY-marked "secrets" into the same files the real command mints (0600)
# and a public identity derived from nothing secret. FAKE_PUB_EXTRA='"k": "v"' injects
# an extra field into the public file (negative control for the collector).
# Set R1006_TEST_KEYTOOL to a real `citrate` binary to run the tests against the real thing.
set -euo pipefail
[[ "${1:-}" == host-identity ]] || { echo "fake_keytool: only host-identity" >&2; exit 2; }
shift
dir="" ks="" pw="" out="" mint=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity-dir) dir="$2"; shift 2 ;;
    --staker-keystore) ks="$2"; shift 2 ;;
    --staker-password-file) pw="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --mint) mint=1; shift ;;
    *) echo "fake_keytool: unknown $1" >&2; exit 2 ;;
  esac
done
canary="${CANARY:?}"
mk() { [[ -e "$1" ]] && return 0; [[ $mint -eq 1 ]] || { echo "missing $1 (--mint)" >&2; exit 1; }; (umask 077; printf '%s' "$2" >"$1"); }
mk "$dir/noise.key" "$canary-noise"
mk "$dir/proposer.key" "$canary-proposer"
mk "$pw" "$canary-password"
mk "$ks" "{\"address\":\"$(sha256sum <<<"$dir" | cut -c1-40)\",\"crypto\":{\"ciphertext\":\"$canary-staker\"}}"
h=$(sha256sum <<<"$dir" | cut -d' ' -f1)
a=$(cut -c1-40 <<<"$h")
v=$(sha256sum <<<"v$dir" | cut -d' ' -f1)
p=$(sha256sum <<<"p$dir" | cut -d' ' -f1)
json="{\"schema\":\"citrate-host-identity/1\",\"peer_id\":\"noise_$h\",\"noise_pubkey\":\"$h\",\"proposer_pubkey\":\"0x$p\",\"vrf_pubkey\":\"0x02$v\",\"staker_address\":\"0x$a\",\"coinbase_address\":\"0x$a\"${FAKE_PUB_EXTRA:+,$FAKE_PUB_EXTRA}}"
[[ -n "$out" ]] && printf '%s\n' "$json" >"$out"
printf '%s\n' "$json"
