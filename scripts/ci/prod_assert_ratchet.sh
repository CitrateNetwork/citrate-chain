#!/usr/bin/env bash
# prod_assert_ratchet.sh — PANIC-S1: fence production assert!/assert_eq!/assert_ne!.
#
# Clippy's panic lints cannot see assert macros, so they bypass the G1 ratchet and
# the G2 crate denies. This counts them in git-tracked production code (outside tests/,
# benches/, examples/, fuzz/, *_test(s).rs, build.rs, and any #[cfg(..test..)]
# region) and fails if the count rises above scripts/ci/prod-assert-baseline.txt.
# Compile-time `const _: () = assert!(..)` checks are excluded. When the count
# falls, the baseline is rewritten (the ratchet tightens) and must be committed.
#
# Usage: prod_assert_ratchet.sh [--list]   |   prod_assert_ratchet.sh --self-test
set -uo pipefail
# Git exports GIT_DIR/GIT_INDEX_FILE/GIT_WORK_TREE to hooks (pre-push runs this script). They
# would override `git -C <dir>` below, so the self-test temp repo would list the outer repo.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_PREFIX GIT_OBJECT_DIRECTORY
REPO_ROOT="${PROD_ASSERT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BASELINE="$REPO_ROOT/scripts/ci/prod-assert-baseline.txt"

# The .rs files to scan under <root>, one absolute path per line.
#
# In a git checkout this is the TRACKED files only (`git ls-files`): a plain
# filesystem walk also counted untracked and gitignored trees, e.g. agent
# worktrees under .claude/worktrees/ (each a full copy of the repo), which
# inflated the count from 18 to 54+ on a developer machine while CI saw 18.
# Outside a git checkout (an exported tree, or the self-test's temp dir) it
# falls back to walking the filesystem. The exclusions apply to the path
# relative to <root>, in both modes.
rs_files() { # <root>
  local root="$1" top=""
  top="$(git -C "$root" rev-parse --show-toplevel 2>/dev/null)" || top=""
  if [ -n "$top" ] && [ "$(cd "$top" && pwd -P)" = "$(cd "$root" && pwd -P)" ]; then
    git -C "$root" ls-files -- '*.rs'
  else
    (cd "$root" && find . -name '*.rs' 2>/dev/null | sed 's|^\./||')
  fi | grep -v -E '(^|/)(target|tests|benches|examples|fuzz|node_modules)/|(^|/)contracts/lib/|_tests?\.rs$|(^|/)build\.rs$' \
     | sed "s|^|$root/|"
}

scan() { # <root>
  rs_files "$1" | tr '\n' '\0' \
  | xargs -0 -r perl -ne 'BEGIN{$t=0}
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
  # Git mode: a tracked production assert counts; the same file in an
  # untracked, gitignored worktree copy (.claude/worktrees/) does not.
  local g="$d/repo"
  mkdir -p "$g/src" "$g/.claude/worktrees/copy/src"
  printf 'fn f(x: u8) {\n    assert!(x > 0);\n}\n' > "$g/src/a.rs"
  cp "$g/src/a.rs" "$g/.claude/worktrees/copy/src/a.rs"
  printf '.claude/worktrees/\n' > "$g/.gitignore"
  if git -C "$g" init -q 2>/dev/null && git -C "$g" add src/a.rs .gitignore 2>/dev/null; then
    [ "$(scan "$g" | wc -l)" -eq 1 ] || { echo "self-test: git mode must count tracked files only"; rc=1; }
  else
    echo "self-test: git unavailable, git-mode case not exercised"; rc=1
  fi
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
