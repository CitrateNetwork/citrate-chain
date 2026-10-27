#!/usr/bin/env bash
# finality_range_height_index_tripwire.sh — fence height-index reads in the RPC layer.
#
# The block store's height index (`BlockStore::get_block_by_height`) is NOT a
# canonical index: the LAST block written at a height wins, which can be an
# uncertified sibling. A `finalized`/`safe` read (block lookup or range) must
# resolve through the certified hash and its selected-parent ancestry
# (`citrate_api::finalized_tag::range_block_hashes`), never through this index.
#
# Rule: every `get_block_by_height(` call in core/api/src must carry a
# `height-index:` justification comment on the same line or within the 6 lines
# above it, naming why that read is never a finalized/safe read (latest,
# numeric height, above the certified height, ...). A new unmarked call fails.
#
# Usage: finality_range_height_index_tripwire.sh              # scan the tree
#        finality_range_height_index_tripwire.sh --self-test  # prove the rule still detects its class
set -uo pipefail

REPO_ROOT="${FINALITY_RANGE_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

scan() { # <dir> ; prints violations, returns 0 iff any found
  local out
  out="$(find "$1" -name '*.rs' -not -path '*/target/*' 2>/dev/null | sort \
    | xargs -r perl -ne '
        push @w, $_; shift @w if @w > 7;
        if (/get_block_by_height\(/ && !/^\s*\/\// && !/fn get_block_by_height/) {
          print "$ARGV:$.: unmarked height-index read: $_" unless grep { /height-index:/ } @w;
        }
        if (eof) { close ARGV; @w = (); }')"
  [ -n "$out" ] && { echo "$out"; return 0; }
  return 1
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  printf 'fn f(s: &S, h: u64) {\n    for h in 0..=h {\n        let x = s.blocks.get_block_by_height(h);\n    }\n}\n' > "$d/a.rs"
  scan "$d" >/dev/null || { echo "self-test: did not detect an unmarked height-index read"; rc=1; }
  printf 'fn f(s: &S, h: u64) {\n    // height-index: latest only, never a finality tag.\n    let x = s\n        .blocks\n        .get_block_by_height(h);\n}\n' > "$d/a.rs"
  scan "$d" >/dev/null && { echo "self-test: flagged a marked height-index read"; rc=1; }
  [ $rc -eq 0 ] && echo "finality range height-index tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
if scan "$REPO_ROOT/core/api/src"; then
  echo "finality range height-index tripwire: FAILED (finalized/safe reads go through finalized_tag::range_block_hashes; mark other reads with a 'height-index:' reason)"
  exit 1
fi
echo "finality range height-index tripwire: clean"
