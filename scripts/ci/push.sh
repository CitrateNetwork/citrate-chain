#!/usr/bin/env bash
# push.sh — run local CI, then push. Use this instead of a bare `git push`.
#
# WHY
#
# git runs the pre-push hook AFTER it has connected to the remote: over ssh
# the session is open, the remote has advertised its refs, and it is waiting
# for the pack. While the hook runs local CI (minutes, mostly clippy) that
# session sits idle. If the remote or anything in between drops it, git
# finishes the hook, the hook prints LOCAL CI PASSED, git writes the pack into
# the closed connection and dies of SIGPIPE: exit 141, nothing pushed.
#
# This script runs local CI first, with no connection open, records the pass
# (local-ci-stamp.sh), then pushes. The hook sees the recorded pass for the
# commit being pushed and returns at once, so the connection is never idle.
#
# Usage:
#   scripts/ci/push.sh [--full] [git push args...]
#     --full   run the full local CI instead of --fast
#
# Exit: 0 pushed (and, for `[remote] [branch]` pushes of the current branch,
# confirmed with ls-remote) · nonzero CI failed or the push did not land.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)" || exit 1
cd "$ROOT" || exit 1

MODE="--fast"
if [ "${1:-}" = "--full" ]; then MODE=""; shift; fi

echo "push.sh: running local CI ${MODE:-(full)} before connecting to the remote"
# shellcheck disable=SC2086  # MODE is empty or a single flag
if ! scripts/ci/local-ci.sh $MODE; then
  echo
  echo "push.sh: local CI failed, not pushing."
  exit 1
fi
scripts/ci/local-ci-stamp.sh record || { echo "push.sh: could not record the CI pass"; exit 1; }

git push "$@"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo
  echo "push.sh: PUSH FAILED (git push exit $rc)."
  if [ "$rc" -eq 141 ]; then
    echo "  141 = SIGPIPE: the connection to the remote closed under git."
  fi
  exit "$rc"
fi

# Confirm with the remote when the target is unambiguous: `push.sh`,
# `push.sh <remote>` or `push.sh <remote> <current-branch>`.
args=()
for a in "$@"; do
  case "$a" in -*) ;; *) args+=("$a") ;; esac
done
branch="$(git symbolic-ref -q --short HEAD || true)"
remote="${args[0]:-$(git config "branch.$branch.remote" || echo origin)}"
if [ -n "$branch" ] && { [ "${#args[@]}" -le 1 ] || { [ "${#args[@]}" -eq 2 ] && [ "${args[1]}" = "$branch" ]; }; }; then
  want="$(git rev-parse HEAD)"
  got="$(git ls-remote "$remote" "refs/heads/$branch" | awk '{print $1}')"
  if [ "$got" != "$want" ]; then
    echo "push.sh: PUSH FAILED: $remote refs/heads/$branch is '${got:-absent}', expected $want."
    exit 1
  fi
  echo "push.sh: confirmed $remote refs/heads/$branch = $want"
fi
