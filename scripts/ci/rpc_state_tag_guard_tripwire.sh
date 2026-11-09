#!/usr/bin/env bash
# rpc_state_tag_guard_tripwire.sh — account-state reads check their block tag.
#
# The node holds one account state: the post-state of the executed head. A state read that
# accepts a block tag and answers from that state labels the head's state as the state of
# whatever block the client named (chain#425). Every handler of eth_call, eth_estimateGas,
# eth_getBalance, eth_getCode, eth_getStorageAt and eth_getTransactionCount must therefore call
# `require_executed_head_state(`, which serves the executed head and refuses any other block.
#
# The scan segments core/api/src production code (`*_tests.rs` files and `#[cfg(test)]` modules
# skipped, comments and string contents blanked except the registered method name) into one unit
# per `add_method("…")` / `add_sync_method("…")` registration and flags a registration of one of
# those methods whose unit has no `require_executed_head_state(` call.
#
# Usage: rpc_state_tag_guard_tripwire.sh              # scan core/api/src
#        rpc_state_tag_guard_tripwire.sh --self-test  # prove the scan still detects its class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures/rpc-state-tag-guard"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

scan() { # <root>
  (cd "$1" && tw_files . | grep -E '^core/api/src/.*\.rs$' | grep -vE '_tests?\.rs$' \
     | tw_xargs perl -e '
    my %state = map { $_ => 1 } qw(eth_call eth_estimateGas eth_getBalance eth_getCode
                                   eth_getStorageAt eth_getTransactionCount);
    sub flush {
      return unless defined $name && $state{$name};
      print "$file:$at: [$name] state read without require_executed_head_state\n"
        unless $seg =~ /\brequire_executed_head_state\s*\(/;
    }
    for $file (@ARGV) {
      open(my $fh, "<", $file) or next;
      my @raw = <$fh>; close $fh;
      ($seg, $name, $at, my $pend) = ("", undef, 0, 0);
      for my $n (0 .. $#raw) {
        my $l = $raw[$n];
        if ($l =~ /^\s*#\[cfg\((all\(|any\()?[^\]]*\btest\b/) {
          my $m = $n + 1; $m++ while $m <= $#raw && $raw[$m] =~ /^\s*#\[/;
          last if $m <= $#raw && $raw[$m] =~ /^\s*(pub(\([^)]*\))?\s+)?mod\s/;
        }
        $l =~ s{//.*$}{};
        my $new;
        if ($pend && $l =~ /^\s*"([^"]+)"/) { $new = $1 }
        $pend = $l =~ /\badd_(?:sync_)?method\s*\(\s*$/;
        if ($l =~ /\badd_(?:sync_)?method\s*\(\s*"([^"]+)"/) { $new = $1 }
        if (defined $new) { flush(); ($seg, $name, $at) = ("", $new, $n + 1) }
        $seg .= $l;
      }
      flush(); $name = undef;
    }') || true
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/pos/core/api/src" "$d/neg/core/api/src" "$d/neg/node/src"
  cp "$FIXTURES/positive.rs" "$d/pos/core/api/src/eth_rpc.rs"
  cp "$FIXTURES/negative.rs" "$d/neg/core/api/src/eth_rpc.rs"
  cp "$FIXTURES/positive.rs" "$d/neg/core/api/src/eth_rpc_tests.rs"   # test files are out of scope
  cp "$FIXTURES/positive.rs" "$d/neg/node/src/client.rs"              # only core/api is fenced
  tw_selftest_case "rpc-state-tag-guard positive" hit scan "$d/pos" || rc=1
  tw_selftest_marked "rpc-state-tag-guard markers" "$d/pos" scan || rc=1
  tw_selftest_case "rpc-state-tag-guard negative" clean scan "$d/neg" || rc=1
  tw_selftest_allow "rpc-state-tag-guard allowlist" rpc-state-tag-guard scan "$d/pos" || rc=1
  tw_selftest_fail_closed "rpc-state-tag-guard fail-closed" "$d/pos" scan || rc=1
  [ $rc -eq 0 ] && echo "rpc-state-tag-guard tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$REPO_ROOT" | tw_report rpc-state-tag-guard "$ALLOW" \
  'state reads call state_tag::require_executed_head_state (serve the executed head, refuse other blocks)'
