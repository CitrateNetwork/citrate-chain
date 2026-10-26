#!/usr/bin/env bash
# rpc_height_index_tripwire.sh — finalized/safe and log ranges never resolve through the
# height index.
#
# The block store's height index (`get_block_by_height`) keeps the LAST block written at a
# height. On a DAG that can be an uncertified sibling of the certified block, or one of several
# executed blocks at that height. So:
#
#   * `finalized` / `safe` must name the certified block (by hash, from the verified
#     finality source), never "the block the height index has at the finalized height";
#   * an eth_getLogs / filter range must walk the executed (canonical) chain, never
#     `for h in from..=to { get_block_by_height(h) }`.
#
# The check segments core/api/src (production code only: `*_tests.rs` files and
# `#[cfg(test)]` modules are skipped, comments are stripped) into units — one per
# registered RPC method (`add_method("…")` / `add_sync_method("…")`) and one per `fn` — and
# flags each `get_block_by_height(` call in a unit that also
#   (a) resolves a finality tag: "finalized" / "safe", resolve_block_tag(, is_finality_tag(,
#       or a finalized-height value; or
#   (b) walks a log range: fromBlock / toBlock / from_block / to_block, or a method whose name
#       contains Logs or Filter.
#   (c) also, in a unit that resolves a finality tag to a bare NUMBER with resolve_block_tag( and
#       then looks a block up (get_block( / get_block_by_number( / get_block_header( /
#       BlockId::Number), the resolve_block_tag( line is flagged — that lookup reaches the
#       height index one call away. A unit that resolves finality by hash (is_finality_tag,
#       resolve_block_id, anchor_for, FinalizedAnchor) is not.
# Lookups of an explicit block number with no finality or range logic are not flagged. Each hit
# is printed with its unit as "[label]", which is what an allowlist key should name.
#
# Usage: rpc_height_index_tripwire.sh              # scan core/api/src
#        rpc_height_index_tripwire.sh --self-test  # prove the scan still detects its class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures/rpc-finality-height-index"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

scan() { # <root>
  (cd "$1" && tw_files . | grep -E '^core/api/src/.*\.rs$' | grep -vE '_tests?\.rs$' \
     | tw_xargs perl -e '
    sub flush {
      my ($f) = @_;
      return unless @hits;
      return if $label =~ /^fn (resolve_block_tag|resolve_block_id)$/;   # the resolvers themselves
      my $fin = $seg =~ /"finalized"|"safe"|\bresolve_block_tag\s*\(|\bis_finality_tag\s*\(|\bfinalized(_height)?\b|\bfinalized_\w+\b/;
      my $rng = $seg =~ /\b(fromBlock|toBlock|from_block|to_block)\b/ || $label =~ /Logs|Filter/i;
      if ($fin || $rng) { print "$f:$_->[0]: [$label] $_->[1]\n" for grep { $_->[2] eq "idx" } @hits }
      # (c) a finality tag resolved to a bare NUMBER and then looked up (the lookup goes through
      #     the height index); units that resolve finality by hash are fine.
      my $byhash = $seg =~ /\b(is_finality_tag|anchor_for|resolve_block_id|FinalizedAnchor)\b/;
      my $lookup = $seg =~ /\.(get_block|get_block_by_number|get_block_header)\s*\(|BlockId::Number\s*\(/;
      if ($fin && $lookup && !$byhash) { print "$f:$_->[0]: [$label] $_->[1]\n" for grep { $_->[2] eq "tag" } @hits }
    }
    for my $f (@ARGV) {
      open(my $fh, "<", $f) or next;
      ($seg, $label, @hits) = ("", "(file)");
      my @raw = <$fh>;
      for my $n (0 .. $#raw) {
        my $l = $raw[$n]; my $ln = $n + 1;
        # a #[cfg(test)] module ends the production code (a cfg(test) fn does not)
        if ($l =~ /^\s*#\[cfg\((all\(|any\()?[^\]]*\btest\b/) {
          my $m = $n + 1; $m++ while $m <= $#raw && $raw[$m] =~ /^\s*#\[/;
          last if $m <= $#raw && $raw[$m] =~ /^\s*(pub(\([^)]*\))?\s+)?mod\s/;
        }
        $l =~ s{//.*$}{};
        my $new;
        if ($pend && $l =~ /^\s*"([^"]+)"/) { $new = $1 }
        $pend = $l =~ /\badd_(?:sync_)?method\s*\(\s*$/;   # name on the next line
        if ($l =~ /\badd_(?:sync_)?method\s*\(\s*"([^"]+)"/) { $new = $1 }
        elsif ($l =~ /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)/) { $new = "fn $1" }
        if (defined $new) { flush($f); ($seg, $label, @hits) = ("", $new) }
        $seg .= $l;
        (my $s = $l) =~ s/^\s+|\s+$//g;
        push @hits, [$ln, $s, "idx"] if $l =~ /\bget_block_by_height\s*\(/;
        push @hits, [$ln, $s, "tag"] if $l =~ /\bresolve_block_tag\s*\(/;
      }
      flush($f);
      close $fh;
    }') || true
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/pos/core/api/src" "$d/neg/core/api/src"
  cp "$FIXTURES/positive.rs" "$d/pos/core/api/src/eth_rpc.rs"
  cp "$FIXTURES/negative.rs" "$d/neg/core/api/src/eth_rpc.rs"
  cp "$FIXTURES/positive.rs" "$d/neg/core/api/src/eth_rpc_tests.rs"   # test files are out of scope
  tw_selftest_case "rpc-finality-height-index positive" hit scan "$d/pos" || rc=1
  tw_selftest_marked "rpc-finality-height-index markers" "$d/pos" scan || rc=1
  tw_selftest_case "rpc-finality-height-index negative" clean scan "$d/neg" || rc=1
  tw_selftest_allow "rpc-finality-height-index allowlist" rpc-finality-height-index scan "$d/pos" || rc=1
  tw_selftest_fail_closed "rpc-finality-height-index fail-closed" "$d/pos" scan || rc=1
  [ $rc -eq 0 ] && echo "rpc-finality-height-index tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$REPO_ROOT" | tw_report rpc-finality-height-index "$ALLOW" \
  'resolve finalized/safe by the certified hash and log ranges over the executed chain'
