#!/usr/bin/env bash
# direct_value_transfer_tripwire.sh — fence direct balance transfers in tx execution.
#
# Inside a transaction the executor moves value through the per-tx journal
# (`journal_transfer`): the journal is what commits on success and is discarded
# on revert, and it is drained over `state_db` at the end of the tx. A direct
# `state_db.accounts.transfer(..)` from an execution path would not follow the
# transaction's outcome. The only allowed direct transfer is the pre-activation
# legacy arm
# kept for replaying blocks below `supply_hardening_height`, marked on the line
# above with `LEGACY-PRE-SUPPLY-HARDENING`.
#
# Scope: production sources of core/execution/src, excluding the account store
# itself (state/) and #[cfg(test)] modules (everything after `mod tests {`).
#
# Usage: direct_value_transfer_tripwire.sh              # scan the tree
#        direct_value_transfer_tripwire.sh --self-test  # prove the rule detects its class
set -uo pipefail

REPO_ROOT="${DIRECT_TRANSFER_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

scan() { # <dir> ; prints violations, returns 0 iff any found
  local out
  out="$(find "$1" -name '*.rs' -not -path '*/state/*' -not -path '*/target/*' 2>/dev/null \
    | xargs -r perl -ne '
        BEGIN { $prev = ""; $in_tests = 0; }
        $in_tests = 1 if /^\s*mod tests\s*\{/;
        if (!$in_tests && /accounts\s*\.\s*transfer\s*\(|^\s*\.transfer\(&/ && $prev !~ /LEGACY-PRE-SUPPLY-HARDENING/) {
          print "$ARGV:$.: direct state transfer outside the journal: $_";
        }
        $prev = $_;
        if (eof) { close ARGV; $prev = ""; $in_tests = 0; }')"
  [ -n "$out" ] && { echo "$out"; return 0; }
  return 1
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  printf 'fn f(&self) {\n    self.state_db.accounts.transfer(&a, &b, v)?;\n}\n' > "$d/a.rs"
  scan "$d" >/dev/null || { echo "self-test: did not detect a direct transfer"; rc=1; }
  printf 'fn f(&self) {\n    self.state_db\n        .accounts\n        .transfer(&a, &b, v)?;\n}\n' > "$d/a.rs"
  scan "$d" >/dev/null || { echo "self-test: did not detect a split-line direct transfer"; rc=1; }
  printf 'fn f(&self) {\n    // LEGACY-PRE-SUPPLY-HARDENING\n    self.state_db.accounts.transfer(&a, &b, v)?;\n    self.journal_transfer(a, b, v, c)?;\n}\nmod tests {\n    fn t() { m.accounts.transfer(&a, &b, v); }\n}\n' > "$d/a.rs"
  scan "$d" >/dev/null && { echo "self-test: flagged the marked legacy arm / journal / test code"; rc=1; }
  [ $rc -eq 0 ] && echo "direct-value-transfer tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
if scan "$REPO_ROOT/core/execution/src"; then
  echo "direct-value-transfer tripwire: FAILED (move value with journal_transfer inside a tx)"
  exit 1
fi
echo "direct-value-transfer tripwire: clean"
