#!/usr/bin/env bash
# tla_frame_tripwire.sh — no TLA+ action both assigns a variable and keeps it UNCHANGED.
#
# In `/\ x' = e /\ UNCHANGED x` the second conjunct means x' = x, so the action only fires in
# states where e = x. TLC does not complain: the action is just (silently) disabled where it was
# meant to fire, and invariants keep passing because the behaviour is never explored.
#
# The check is scripts/ci/tla_frame_lint.py (ported from citrate-core src-tauri/formal, core#345):
# within one conjunction list of an action, a variable primed by one conjunct (directly or
# through a helper operator defined in the same module) may not appear, directly or through a
# tuple alias such as `vars`, in an UNCHANGED of a sibling conjunct. `\/` disjuncts and the THEN /
# ELSE arms of an IF are separate lists. Comments and string literals are ignored. A hit is
# reported at the first line of the UNCHANGED conjunct, labelled "[Action]".
# Limits: operators from EXTENDS / INSTANCE modules are not followed; CASE arms are treated as
# one list.
#
# Scope: every tracked specs/tla/**/*.tla file.
#
# Usage: tla_frame_tripwire.sh              # scan specs/tla
#        tla_frame_tripwire.sh --self-test  # prove the lint still detects its class
# Exit:  0 clean · 1 violation · 2 malformed allowlist
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${TRIPWIRE_ROOT:-$(cd "$HERE/../.." && pwd)}"
ALLOW="${TRIPWIRE_ALLOWLIST:-$REPO_ROOT/scripts/ci/tripwire-allowlist.txt}"
FIXTURES="$HERE/fixtures/tla-frame"
LINT="$HERE/tla_frame_lint.py"
# shellcheck source=lib/tripwire_common.sh
. "$HERE/lib/tripwire_common.sh"

scan() { # <root> ; prints "path:line: [Action] ..." per clash
  (cd "$1" && tw_files . | grep -E '^specs/tla/.*\.tla$' \
     | tw_xargs python3 -I "$LINT") || true
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "${d:?}"' RETURN
  mkdir -p "$d/pos/specs/tla/m" "$d/neg/specs/tla/m" "$d/neg/docs"
  cp "$FIXTURES/positive.tla" "$d/pos/specs/tla/m/"
  cp "$FIXTURES/negative.tla" "$d/neg/specs/tla/m/"
  cp "$FIXTURES/positive.tla" "$d/neg/docs/"          # outside specs/tla: out of scope
  python3 -I "$LINT" --self-test >/dev/null || { echo "self-test: tla_frame_lint.py --self-test failed"; rc=1; }
  tw_selftest_case "tla-frame positive" hit scan "$d/pos" || rc=1
  tw_selftest_marked "tla-frame markers" "$d/pos" scan || rc=1
  tw_selftest_case "tla-frame negative" clean scan "$d/neg" || rc=1
  tw_selftest_allow "tla-frame allowlist" tla-frame scan "$d/pos" || rc=1
  tw_selftest_fail_closed "tla-frame fail-closed" "$d/pos" scan || rc=1
  [ $rc -eq 0 ] && echo "tla-frame tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$REPO_ROOT" | tw_report tla-frame "$ALLOW" \
  'drop the variable from UNCHANGED (or the assignment): one conjunct may not prime what a sibling keeps'
