#!/usr/bin/env bash
# test_git_rev_deps_env.sh: git_rev_deps.py must never act on the caller's repository.
#
# git exports GIT_DIR (and, from a worktree, GIT_INDEX_FILE etc.) to hooks, and the
# pre-push hook runs local-ci.sh, which runs `git_rev_deps.py --self-test`. On
# 2026-10-27 that self-test's fixture git calls inherited GIT_DIR and ran
# init/commit/`branch -D main`/`reflog expire --all`/`gc --prune=now` against the
# developer's own repository (and `git init --bare` set core.bare=true on it).
#
# This test points GIT_DIR / GIT_INDEX_FILE / GIT_WORK_TREE at a sentinel repository,
# runs the self-test and the env helper, and fails if the sentinel's refs, config,
# tags, reflogs or HEAD changed. Local only: everything lives under one mktemp dir.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/git-rev-deps-env-XXXX")"
trap 'rm -rf -- "$T"' EXIT
export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
mkdir -p "$HOME"
fail() { echo "FAIL: $*" >&2; exit 1; }

S="$T/sentinel"
git -c init.defaultBranch=main init --quiet "$S"
echo sentinel >"$S/f"
git -C "$S" add f
git -C "$S" -c user.name=s -c user.email=s@invalid -c commit.gpgsign=false commit --quiet -m sentinel
snapshot() {
  { git -C "$S" for-each-ref --format='%(refname) %(objectname)'
    git -C "$S" config --list --local
    git -C "$S" symbolic-ref HEAD
    git -C "$S" rev-parse HEAD
    git -C "$S" reflog --all | wc -l
    git -C "$S" ls-files --stage; } 2>&1
}
before="$(snapshot)"

# 1. The env helper drops every repository-local variable git lists.
GIT_DIR="$S/.git" GIT_WORK_TREE="$S" GIT_INDEX_FILE="$S/.git/index" \
  python3 - "$HERE" <<'PY' || fail "git_env() passes a repository-local variable through"
import os, subprocess, sys
sys.path.insert(0, sys.argv[1])
import git_rev_deps
local = subprocess.run(["git", "rev-parse", "--local-env-vars"], capture_output=True,
                       text=True, check=True).stdout.split()
leaked = sorted(k for k in git_rev_deps.git_env() if k in local)
if leaked:
    print("leaked:", leaked, file=sys.stderr)
    sys.exit(1)
PY

# 2. The self-test, run as the pre-push hook runs it (git exports GIT_DIR), leaves the
#    sentinel untouched.
( cd "$S" && GIT_DIR="$S/.git" \
    python3 "$HERE/git_rev_deps.py" --self-test >"$T/selftest.log" 2>&1 ) \
  || { cat "$T/selftest.log" >&2; fail "self-test failed under a hook environment"; }
after="$(snapshot)"
[[ "$before" == "$after" ]] || { diff <(echo "$before") <(echo "$after") >&2 || true
  fail "the self-test changed the caller's repository"; }
[[ "$(git -C "$S" config --bool core.bare)" == false ]] || fail "core.bare changed"

# 3. Negative control: the same self-test with the old pass-through env helper DOES
#    change a second sentinel, so step 2 is not passing vacuously.
N="$T/neg"
git -c init.defaultBranch=main init --quiet "$N"
echo neg >"$N/f"; git -C "$N" add f
git -C "$N" -c user.name=s -c user.email=s@invalid -c commit.gpgsign=false commit --quiet -m neg
neg_before="$(git -C "$N" for-each-ref --format='%(refname) %(objectname)')"
( cd "$N" && GIT_DIR="$N/.git" \
    python3 - "$HERE" <<'PY' ) >/dev/null 2>&1 || true
import os, sys
sys.path.insert(0, sys.argv[1])
import git_rev_deps
git_rev_deps.git_env = lambda: dict(os.environ)  # the pre-fix helper
git_rev_deps.self_test()
PY
neg_after="$(env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git -C "$N" for-each-ref --format='%(refname) %(objectname)')"
[[ "$neg_before" != "$neg_after" ]] \
  || fail "negative control: the pre-fix helper no longer reaches the sentinel (test is blind)"
echo "test_git_rev_deps_env: ok"
