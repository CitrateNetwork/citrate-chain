#!/usr/bin/env bash
# historical_state_read_tripwire.sh — no client code that relies on reading PAST state.
#
# The Citrate node serves account-state reads (eth_getCode, eth_call, eth_getBalance,
# eth_getStorageAt, eth_getTransactionCount) from its latest committed state: a block-number or
# block-hash tag is accepted but not honoured (only `finalized`/`safe` are checked, and refused
# when they are behind the tip). A script or tool that asks for state "at block N" therefore gets
# the state at the tip and silently compares, forks or verifies against the wrong snapshot.
#
#   R1  A JSON-RPC state read whose parameters (the call line, the 3 lines before it and the 6
#       after it) do not pass the literal tag "latest" or "pending". Server-side dispatch (a
#       match arm, `== "eth_call"`, a stub's method table, a request matcher) is skipped.
#   R2  Forking or calling at a past block through Foundry against a Citrate RPC:
#       `--fork-block-number`, `vm.createFork(url, n)`, `vm.createSelectFork(url, n)`,
#       `vm.rollFork(..)`, `cast call|code|balance|storage|nonce … --block`.
#
# Scope: every tracked source/script file outside core/api (the server itself), docs (*.md)
# and vendored trees. Comment lines are skipped. A read that is pinned on purpose (a tool that
# documents the latest-state behaviour, a gate that compares two nodes at the same head) goes in
# the allowlist with its reason.
#
# Usage: historical_state_read_tripwire.sh              # scan the tree
#        historical_state_read_tripwire.sh --self-test  # prove the scan still detects its class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures/rpc-historical-state"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

scan() { # <root>
  (cd "$1" && tw_files . | grep -E '\.(rs|py|sh|bash|ts|tsx|js|mjs|cjs|sol|yml|yaml)$' \
     | grep -vE '^core/api/' \
     | xargs -r -d '\n' grep -lE 'eth_(getCode|call|getBalance|getStorageAt|getTransactionCount)|fork-block-number|createSelectFork|createFork|rollFork|cast[[:space:]]+(call|code|balance|storage|nonce)' 2>/dev/null \
     | xargs -r -d '\n' perl -e '
    for my $f (@ARGV) {
      open(my $fh, "<", $f) or next; my @L = <$fh>; close $fh;
      for my $i (0 .. $#L) {
        my $l = $L[$i];
        next if $l =~ m{^\s*(//|#|\*|/\*|--)};
        my $hit = 0;
        my $read = $l =~ /\\?["\x27]eth_(getCode|call|getBalance|getStorageAt|getTransactionCount)\\?["\x27]/
                # shell helper style: `rpc eth_getBalance "[\"$A\",\"$TAG\"]"`
                || $l =~ /(?<![\w"\x27])eth_(getCode|call|getBalance|getStorageAt|getTransactionCount)\s+["\x27]\[/;
        if ($read) {
          my $dispatch = $l =~ /(==|!=|\bcase\b|\bmatch\b)\s*\\?["\x27]eth_/
                      || $l =~ /\\?["\x27]eth_\w+\\?["\x27]\s*(=>|\bif\b|:\s*[^"\x27\s\[{]|\)\s*:|\})/;
          if (!$dispatch) {
            my $beg = $i < 3 ? 0 : $i - 3;
            my $end = $i + 6 > $#L ? $#L : $i + 6;
            my $win = join "", @L[$beg .. $end];
            $hit = 1 unless $win =~ /\\?["\x27](latest|pending)\\?["\x27]/;
          }
        }
        $hit = 1 if $l =~ /--fork-block-number|\bvm\.(createFork|createSelectFork)\s*\([^)]*,|\bvm\.rollFork\s*\(/;
        $hit = 1 if $l =~ /\bcast\s+(call|code|balance|storage|nonce)\b.*\s(--block|-B)\b/;
        if ($hit) { (my $s = $l) =~ s/^\s+|\s+$//g; print "$f:", $i + 1, ": $s\n" }
      }
    }') || true
}

self_test() {
  local d rc=0 f
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/pos/scripts" "$d/neg/scripts" "$d/neg/core/api/src"
  for f in "$FIXTURES"/positive*; do cp "$f" "$d/pos/scripts/"; done
  for f in "$FIXTURES"/negative*; do cp "$f" "$d/neg/scripts/"; done
  # the server may name the methods freely: core/api is out of scope
  cp "$FIXTURES/positive_reads.py" "$d/neg/core/api/src/server_side.py"
  tw_selftest_case "rpc-historical-state positive" hit scan "$d/pos" || rc=1
  tw_selftest_marked "rpc-historical-state markers" "$d/pos" scan || rc=1
  tw_selftest_case "rpc-historical-state negative" clean scan "$d/neg" || rc=1
  tw_selftest_allow "rpc-historical-state allowlist" rpc-historical-state scan "$d/pos" || rc=1
  [ $rc -eq 0 ] && echo "rpc-historical-state tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$REPO_ROOT" | tw_report rpc-historical-state "$ALLOW" \
  'read latest state and check the head yourself; the node does not serve state at a past block'
