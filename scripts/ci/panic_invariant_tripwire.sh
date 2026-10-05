#!/usr/bin/env bash
# panic_invariant_tripwire.sh — PANIC-S1 G3: no UNJUSTIFIED panic-lint escape hatches.
#
# The panic ratchet (G1) and per-crate deny lints (G2) can be defeated silently
# with an #[allow]. This fence makes every such escape hatch explicit and reviewed:
#
#   R1  An item-level `#[allow(clippy::<panic lint>)]` (or `#[expect(...)]`) in
#       production code must have an `// INVARIANT:` comment on the same line or
#       within the 3 lines above it, stating why the panic cannot fire and which
#       test pins that.
#   R2  A crate/module-level `#![allow(clippy::<panic lint>)]` is forbidden
#       outright: a blanket allow turns the guard off for a whole crate.
#
# Panic lints: unwrap_used expect_used panic unreachable indexing_slicing
#              arithmetic_side_effects string_slice
# Production = *.rs outside tests/ benches/ examples/ fuzz/ target/ and not a
# `*_tests.rs` / `*_test.rs` file.
#
# Usage: panic_invariant_tripwire.sh              # scan the tree
#        panic_invariant_tripwire.sh --self-test  # prove both rules still detect their class
set -uo pipefail

REPO_ROOT="${PANIC_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
LINT_RE='clippy::(unwrap_used|expect_used|panic|unreachable|indexing_slicing|arithmetic_side_effects|string_slice)'

prod_files() { # <root>
  find "$1" -name '*.rs' \
    -not -path '*/target/*' -not -path '*/tests/*' -not -path '*/benches/*' \
    -not -path '*/examples/*' -not -path '*/fuzz/*' -not -path '*/node_modules/*' \
    -not -path '*/contracts/lib/*' -not -name '*_tests.rs' -not -name '*_test.rs' 2>/dev/null
}

scan() { # <root> ; prints violations, returns 0 iff any found
  local root="$1" out
  out="$(prod_files "$root" | xargs -r awk -v LRE="$LINT_RE" '
    FNR == 1 { delete prev; n = 0 }
    {
      line = $0
      if (line ~ /#!\[(allow|expect)\(/ && line ~ LRE) {
        printf "%s:%d: R2 crate-level panic-lint allow is forbidden: %s\n", FILENAME, FNR, line
      } else if (line ~ /#\[(allow|expect)\(/ && line ~ LRE) {
        ok = (line ~ /INVARIANT:/)
        for (k = 1; k <= 3 && !ok; k++) if (prev[k] ~ /\/\/ *INVARIANT:/) ok = 1
        if (!ok) printf "%s:%d: R1 panic-lint allow without // INVARIANT: justification: %s\n", FILENAME, FNR, line
      }
      for (k = 3; k > 1; k--) prev[k] = prev[k-1]
      prev[1] = line
    }')"
  [ -n "$out" ] && { echo "$out"; return 0; }
  return 1
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  mkdir -p "$d/core/x/src" "$d/core/x/tests"
  # R1 positive: unjustified allow must be caught.
  printf 'fn f(v: &[u8]) -> u8 {\n    #[allow(clippy::indexing_slicing)]\n    v[0]\n}\n' > "$d/core/x/src/a.rs"
  scan "$d" >/dev/null || { echo "self-test: R1 did not detect an unjustified allow"; rc=1; }
  # R1 negative: a justified allow must pass.
  printf 'fn f(v: &[u8; 4]) -> u8 {\n    // INVARIANT: fixed-size array, index 0 < 4 (test: pins_len)\n    #[allow(clippy::indexing_slicing)]\n    v[0]\n}\n' > "$d/core/x/src/a.rs"
  scan "$d" >/dev/null && { echo "self-test: R1 flagged a justified allow"; rc=1; }
  # R2 positive: crate-level allow must be caught even with a comment.
  printf '// INVARIANT: nope\n#![allow(clippy::expect_used)]\n' > "$d/core/x/src/lib.rs"
  scan "$d" >/dev/null || { echo "self-test: R2 did not detect a crate-level allow"; rc=1; }
  rm -f "$d/core/x/src/lib.rs"
  # Test code is out of scope.
  printf '#[allow(clippy::unwrap_used)]\nfn t() {}\n' > "$d/core/x/tests/t.rs"
  scan "$d" >/dev/null && { echo "self-test: scanned test code"; rc=1; }
  [ $rc -eq 0 ] && echo "self-test OK: R1 (unjustified allow) and R2 (crate-level allow) both detected"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
if out="$(scan "$REPO_ROOT")"; then
  echo "$out"
  echo "PANIC-S1 G3: justify each allow with '// INVARIANT: <why it cannot panic> (test: <name>)'"
  exit 1
fi
echo "panic-invariant tripwire: clean"
exit 0
