#!/usr/bin/env bash
# git_rev_deps_tripwire.sh: every git dependency pin (Cargo.toml rev/tag/branch
# and Cargo.lock git+...#SHA) in a tracked manifest must resolve on its remote.
# This fences the stranded-pin class: a dependency's history is rewritten, the
# pinned commit is no longer reachable from any ref, and a clean build can't
# fetch it, while warm ~/.cargo caches hide the problem. See git_rev_deps.py.
#
# Usage: git_rev_deps_tripwire.sh              # scan the tree (network: git ls-remote + fetch)
#        git_rev_deps_tripwire.sh --self-test  # negative control on local fixture remotes
# Root override: GIT_REV_DEPS_ROOT=<dir>.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "${1:-}" = "--self-test" ]; then
  exec python3 "$HERE/git_rev_deps.py" --self-test
fi
exec python3 "$HERE/git_rev_deps.py" "${GIT_REV_DEPS_ROOT:-$(cd "$HERE/../.." && pwd)}"
