#!/usr/bin/env bash
# double_lock_tripwire.sh — fence the "same lock twice in one statement" deadlock.
#
#   x.write().await.f = x.write().await.f + 1;
#
# takes the write guard on the left, then blocks forever acquiring it again on the
# right (tokio and parking_lot locks are not re-entrant). PANIC-S1 introduced and
# caught exactly this in core/network gossip stats. The scan flags any production
# line that acquires a guard on a receiver and acquires a guard on the SAME
# receiver again later on that line, where at least one of the two is write/lock.
#
# Usage: double_lock_tripwire.sh              # scan the tree
#        double_lock_tripwire.sh --self-test  # prove the rule still detects its class
set -uo pipefail

REPO_ROOT="${DOUBLE_LOCK_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

scan() { # <root> ; prints violations, returns 0 iff any found
  local out
  out="$(find "$1" -name '*.rs' -not -path '*/target/*' -not -path '*/node_modules/*' \
           -not -path '*/contracts/lib/*' 2>/dev/null \
    | xargs -r perl -ne '
        while (/([A-Za-z_][\w.]*)\.(write|lock|read)\(\)/g) {
          my ($recv, $kind, $rest) = ($1, $2, substr($_, pos($_)));
          if ($rest =~ /\Q$recv\E\.(write|lock|read)\(\)/ && ($kind ne "read" || $1 ne "read")) {
            print "$ARGV:$.: same lock acquired twice in one statement: $_";
            last;
          }
        }
        close ARGV if eof;')"
  [ -n "$out" ] && { echo "$out"; return 0; }
  return 1
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  printf 'async fn f(s: &S) {\n    s.stats.write().await.n = s.stats.write().await.n + 1;\n}\n' > "$d/a.rs"
  scan "$d" >/dev/null || { echo "self-test: did not detect a double write lock"; rc=1; }
  printf 'async fn f(s: &S) {\n    let mut st = s.stats.write().await;\n    st.n = st.n + 1;\n    let a = s.x.read().await.len() + s.x.read().await.len();\n}\n' > "$d/a.rs"
  scan "$d" >/dev/null && { echo "self-test: flagged a single lock / two read guards"; rc=1; }
  [ $rc -eq 0 ] && echo "double-lock tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
if scan "$REPO_ROOT"; then
  echo "double-lock tripwire: FAILED (take the guard once: let mut g = x.write().await; g.f = ...)"
  exit 1
fi
echo "double-lock tripwire: clean"
