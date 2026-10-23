#!/usr/bin/env bash
# wallet_gate_signing_tripwire.sh — secp256k1 (EVM wallet) signatures are produced inside the
# wallet crates only.
#
# The wallet crates (wallet-core/, wallet-sdk/, wallet-aa/, wallet/) are the gate for EVM
# signing: wallet-core's `sign_recoverable` / `sign_eip155_legacy_tx` normalise low-s, compute
# v per EIP-155, strip leading zeros from r/s in the RLP, and zeroize the signing hash, and
# they carry the vector tests for all of that. A crate that calls the raw ECDSA primitive itself
# re-implements those steps; a slip in one (an r or s with a leading zero byte left in the
# RLP, a v computed for the wrong chain) produces a transaction the node rejects about once
# in 256 signatures, which no happy-path test catches. Everything else calls the wallet-core
# functions, which this check does not flag (they are free functions, not methods).
#
# Flagged: a METHOD call of a raw ECDSA signing primitive — `.sign_prehash_recoverable(`,
# `.sign_prehash(`, `.sign_recoverable(`, `.sign_digest_recoverable(`, `.sign_digest(`,
# `.sign_ecdsa(`, `.sign_ecdsa_recoverable(`, `.sign_ecdsa_low_r(` — in production Rust outside
# the wallet crates. Out of scope: tests/, benches/, examples/, fuzz/ trees, `*_test(s).rs`
# files, and everything after a `#[cfg(test)] mod` (by convention the last item of a file).
# Comments and string contents are stripped (tw_strip_c).
#
# Limits (text scan, not type-checked): the generic `signature::Signer::sign` / `try_sign`
# methods are not flagged, because ed25519 keys (consensus, p2p, proposer proofs — not wallet
# signatures, by design outside the gate) use the same names; a k256 key signed through
# `.sign(` slips past. A `#[cfg(test)]` module placed before production code hides what
# follows it. A wrapper fn in another crate that calls a gate primitive under a new name is
# not followed.
#
# Usage: wallet_gate_signing_tripwire.sh              # scan the tree
#        wallet_gate_signing_tripwire.sh --self-test  # prove the scan still detects its class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures/wallet-gate-signing"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

scan() { # <root> ; prints "path:line: text" per raw ECDSA signing call outside the gate
  (cd "$1" && tw_files . | grep -E '\.rs$' \
     | grep -vE '^wallet(-core|-sdk|-aa)?/' \
     | grep -vE '(^|/)(tests|benches|examples|fuzz)/|_tests?\.rs$' \
     | xargs -r -d '\n' grep -lE 'sign_(prehash|recoverable|digest|ecdsa)' 2>/dev/null \
     | xargs -r -d '\n' bash -c '. "$0"; tw_strip_c "$@"' "$HERE/lib/tripwire_common.sh" \
     | perl -ne '
    BEGIN { $M = qr/\.\s*(sign_prehash_recoverable|sign_prehash|sign_recoverable|sign_digest_recoverable|sign_digest|sign_ecdsa_recoverable|sign_ecdsa_low_r|sign_ecdsa)\s*(::<[^>]*>)?\s*\(/ }
    my ($f, $ln, $code) = /^([^:]+):(\d+): (.*)$/ or next;
    if ($f ne $cur) { ($cur, $done, $pend) = ($f, 0, 0) }
    next if $done;
    # a #[cfg(test)] module ends the production code (a cfg(test) fn does not)
    if ($pend) { next if $code =~ /^\s*(#\[|$)/; $pend = 0; if ($code =~ /^\s*(pub(\([^)]*\))?\s+)?mod\s/) { $done = 1; next } }
    if ($code =~ /^\s*#\[cfg\((all\(|any\()?[^\]]*\btest\b/) { $pend = 1; next }
    if ($code =~ $M) {
      open(my $fh, "<", $f) or next; my @L = <$fh>; close $fh;
      (my $s = $L[$ln - 1]) =~ s/^\s+|\s+$//g; print "$f:$ln: $s\n";
    }') || true
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/pos/faucet/src" "$d/pos/core/x/src" \
           "$d/neg/faucet/src" "$d/neg/wallet-core/src" "$d/neg/core/x/tests" "$d/neg/tools/y/src"
  cp "$FIXTURES/positive.rs" "$d/pos/faucet/src/main.rs"
  cp "$FIXTURES/positive_secp256k1.rs" "$d/pos/core/x/src/lib.rs"
  cp "$FIXTURES/negative.rs" "$d/neg/faucet/src/main.rs"
  # the gate itself, integration tests and a test module may call the primitive
  cp "$FIXTURES/positive.rs" "$d/neg/wallet-core/src/tx.rs"
  cp "$FIXTURES/positive.rs" "$d/neg/core/x/tests/sign.rs"
  cp "$FIXTURES/negative_test_module.rs" "$d/neg/tools/y/src/lib.rs"
  tw_selftest_case "wallet-gate-signing positive" hit scan "$d/pos" || rc=1
  tw_selftest_marked "wallet-gate-signing markers" "$d/pos" scan || rc=1
  tw_selftest_case "wallet-gate-signing negative" clean scan "$d/neg" || rc=1
  tw_selftest_allow "wallet-gate-signing allowlist" wallet-gate-signing scan "$d/pos" || rc=1
  [ $rc -eq 0 ] && echo "wallet-gate-signing tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$REPO_ROOT" | tw_report wallet-gate-signing "$ALLOW" \
  'sign through citrate_wallet_core::{sign_eip155_legacy_tx, sign_recoverable}, not the raw ECDSA primitive'
