#!/usr/bin/env bash
# local-ci-stamp.sh — remember that local CI passed for the current tree, so
# the pre-push hook does not have to run it again while git holds a
# connection to the remote open.
#
# The pass covers exactly what local-ci.sh checked: HEAD plus the working
# tree (tracked changes and untracked, non-ignored files). Any commit, edit or
# new file changes the key and the pass no longer applies.
#
#   local-ci-stamp.sh record          record a pass for the current tree
#   local-ci-stamp.sh check <sha>...  exit 0 if a pass is recorded for the
#                                     current tree and every <sha> is HEAD
#   local-ci-stamp.sh clear           forget the recorded pass
#
# Only push.sh and the pre-push hook call `record`, and only after
# local-ci.sh exits 0. Recording a pass by hand skips the gate, the same as
# `git push --no-verify`.
set -euo pipefail

STAMP="$(git rev-parse --path-format=absolute --git-path local-ci-pass 2>/dev/null \
         || git rev-parse --git-path local-ci-pass)"

tree_key() {
  local head
  head="$(git rev-parse --verify -q HEAD)" || return 1
  {
    git diff --binary HEAD
    git ls-files --others --exclude-standard -z | xargs -0 -r git hash-object --
  } | git hash-object --stdin | sed "s/^/$head /"
}

case "${1:-}" in
  record)
    tree_key > "$STAMP.tmp" && mv -f "$STAMP.tmp" "$STAMP"
    ;;
  check)
    shift
    [ -f "$STAMP" ] || exit 1
    key="$(tree_key)" || exit 1
    [ "$(cat "$STAMP")" = "$key" ] || exit 1
    head="${key%% *}"
    [ $# -gt 0 ] || exit 1
    for sha in "$@"; do
      [ "$sha" = "$head" ] || exit 1
    done
    ;;
  clear)
    rm -f -- "$STAMP"
    ;;
  *)
    sed -n '2,17p' "$0" >&2
    exit 2
    ;;
esac
