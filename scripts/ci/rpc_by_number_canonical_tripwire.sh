#!/usr/bin/env bash
# rpc_by_number_canonical_tripwire.sh — RPC by-number reads follow the executed chain.
#
# `BlockStore::get_block_by_height` reads the STORED height index, which keeps the last block
# stored at a height: a sibling stored after the executed block (a competing producer, a late
# fork delivery, a follower's height-group order) takes the entry, at any depth (chain#421).
# The RPC layer answers by-number questions with `get_canonical_block_by_height`, which names
# the block on the selected-parent chain of the applied tip.
#
# Rule: in core/api/src production code (`*_tests.rs` files and `#[cfg(test)]` modules skipped,
# comments and string contents blanked), every `get_block_by_height(` call must read height 0
# (genesis is the same block in both indexes). Any other argument is flagged.
#
# Usage: rpc_by_number_canonical_tripwire.sh              # scan core/api/src
#        rpc_by_number_canonical_tripwire.sh --self-test  # prove the scan still detects its class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures/rpc-by-number-canonical"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

scan() { # <root>
  (cd "$1" && tw_files . | grep -E '^core/api/src/.*\.rs$' | grep -vE '_tests?\.rs$' \
     | tw_xargs tw_strip_c | perl -ne '
    # input: "path:line: code" (comments and string contents blanked)
    my ($f, $n, $code) = /^([^:]+):(\d+): ?(.*)$/ or next;
    if ($f ne $cur) { ($cur, $skip, $pending) = ($f, 0, 0); }
    next if $skip;
    # a #[cfg(test)] module ends the production code of the file
    if ($code =~ /^\s*#\[cfg\((all\(|any\()?[^\]]*\btest\b/) { $pending = 1; next }
    if ($pending) {
      next if $code =~ /^\s*#\[/;
      if ($code =~ /^\s*(pub(\([^)]*\))?\s+)?mod\s/) { $skip = 1; next }
      $pending = 0;
    }
    # the argument may sit on the next line (rustfmt splits long chains)
    if ($open) {
      $open = 0;
      print "$f:$on: $ol\n" unless $code =~ /^\s*0\s*\)/;
    }
    while ($code =~ /\bget_block_by_height\s*\(([^)]*)(\)?)/g) {
      my ($argtxt, $closed) = ($1, $2);
      (my $s = $code) =~ s/^\s+|\s+$//g;
      if ($closed eq "" && $argtxt =~ /^\s*$/) { ($open, $on, $ol) = (1, $n, $s); next }
      print "$f:$n: $s\n" unless $argtxt =~ /^\s*0\s*$/;
    }
  ') || true
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/pos/core/api/src" "$d/neg/core/api/src" "$d/neg/node/src"
  cp "$FIXTURES/positive.rs" "$d/pos/core/api/src/eth_rpc.rs"
  cp "$FIXTURES/negative.rs" "$d/neg/core/api/src/eth_rpc.rs"
  cp "$FIXTURES/positive.rs" "$d/neg/core/api/src/eth_rpc_tests.rs"   # test files are out of scope
  cp "$FIXTURES/positive.rs" "$d/neg/node/src/admission.rs"           # only core/api is fenced
  tw_selftest_case "rpc-by-number-canonical positive" hit scan "$d/pos" || rc=1
  tw_selftest_marked "rpc-by-number-canonical markers" "$d/pos" scan || rc=1
  tw_selftest_case "rpc-by-number-canonical negative" clean scan "$d/neg" || rc=1
  tw_selftest_allow "rpc-by-number-canonical allowlist" rpc-by-number-canonical scan "$d/pos" || rc=1
  tw_selftest_fail_closed "rpc-by-number-canonical fail-closed" "$d/pos" scan || rc=1
  [ $rc -eq 0 ] && echo "rpc-by-number-canonical tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$REPO_ROOT" | tw_report rpc-by-number-canonical "$ALLOW" \
  'by-number reads use get_canonical_block_by_height (the executed chain), not the stored height index'
