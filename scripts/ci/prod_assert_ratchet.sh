#!/usr/bin/env bash
# prod_assert_ratchet.sh — PANIC-S1: fence production assert!/assert_eq!/assert_ne!.
#
# Clippy's panic lints cannot see assert macros, so they bypass the G1 ratchet and
# the G2 crate denies. This counts them in production code (outside tests/,
# benches/, examples/, fuzz/, *_test(s).rs, build.rs, and any #[cfg(..test..)]
# region) and fails if the count rises above scripts/ci/prod-assert-baseline.txt.
# Compile-time `const _: () = assert!(..)` checks are excluded. When the count
# falls, the baseline is rewritten (the ratchet tightens) and must be committed.
#
# Usage: prod_assert_ratchet.sh [--list]   |   prod_assert_ratchet.sh --self-test
set -uo pipefail
REPO_ROOT="${PROD_ASSERT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BASELINE="$REPO_ROOT/scripts/ci/prod-assert-baseline.txt"

scan() { # <root>
  find "$1" -name '*.rs' -not -path '*/target/*' -not -path '*/tests/*' -not -path '*/benches/*' \
    -not -path '*/examples/*' -not -path '*/fuzz/*' -not -path '*/node_modules/*' \
    -not -path '*/contracts/lib/*' -not -name '*_tests.rs' -not -name '*_test.rs' \
    -not -name 'build.rs' 2>/dev/null \
  | xargs -r perl -ne 'BEGIN{$t=0}
      if (/^\s*#\[cfg\((all\(|any\()?[^\]]*\btest\b/) {$t=1}
      if (!$t && /(?<![\w_])(assert|assert_eq|assert_ne)!\s*\(/ && !/^\s*\/\// && !/const _: \(\) = assert/) {
        print "$ARGV:$.: $_" }
      if (eof) {$t=0; close ARGV}'
}

self_test() {
  local d rc=0; d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  printf 'fn f(x: u8) {\n    assert!(x > 0);\n}\n' > "$d/a.rs"
  [ "$(scan "$d" | wc -l)" -eq 1 ] || { echo "self-test: missed a production assert"; rc=1; }
  printf '#[cfg(test)]\nmod t {\n    fn f() { assert!(true); }\n}\nconst _: () = assert!(1 == 1);\n' > "$d/a.rs"
  [ "$(scan "$d" | wc -l)" -eq 0 ] || { echo "self-test: flagged test/const asserts"; rc=1; }
  [ $rc -eq 0 ] && echo "prod-assert ratchet self-test: ok"; return $rc
}

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  --list) scan "$REPO_ROOT" | sed "s|^$REPO_ROOT/||"; exit 0 ;;
esac
cur=$(scan "$REPO_ROOT" | wc -l | tr -d ' ')
base=$(cat "$BASELINE" 2>/dev/null || echo 0)
if [ "$cur" -gt "$base" ]; then
  echo "prod-assert ratchet: FAILED ($base -> $cur). New production assert!: return an error instead."
  scan "$REPO_ROOT" | sed "s|^$REPO_ROOT/||"
  exit 1
fi
if [ "$cur" -lt "$base" ]; then echo "$cur" > "$BASELINE"; echo "prod-assert ratchet tightened $base -> $cur; commit $BASELINE"; fi
echo "prod-assert ratchet: $cur (baseline $base)"
