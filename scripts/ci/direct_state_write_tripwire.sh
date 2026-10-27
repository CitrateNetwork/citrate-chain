#!/usr/bin/env bash
# direct_state_write_tripwire.sh — fence direct state writes in tx execution.
#
# Inside a transaction the executor writes state through the per-tx journal:
# the journal is drained over `state_db` only when the tx commits, and it is
# discarded when the tx reverts or loses its MVCC check. A direct `state_db`
# write from an execution path would not follow the transaction's outcome, so
# every such write must be one of the allowed forms below.
#
# Two rules:
#
#   1. Value transfers, anywhere in core/execution/src outside the account
#      store (state/): a direct `accounts.transfer(..)` is a violation.
#   2. Every state mutator in core/execution/src/executor.rs — `state_db`
#      storage set/delete, model registry, training jobs, balances, nonces,
#      code, and the Executor wrappers `self.set_balance/set_nonce/set_code/
#      add_model_artifact` — is a violation unless it is
#        * the pre-activation legacy arm kept for replaying blocks below
#          `supply_hardening_height`, marked on the line above with
#          `LEGACY-PRE-SUPPLY-HARDENING`, or
#        * inside one of the functions in OUT_OF_TX below, which by design run
#          outside any transaction.
#
# #[cfg(test)] code is excluded (everything after `mod tests {` for rule 1,
# after the first top-level `#[cfg(test)]` for rule 2).
#
# Usage: direct_state_write_tripwire.sh              # scan the tree
#        direct_state_write_tripwire.sh --self-test  # prove the rules detect their class
set -uo pipefail

REPO_ROOT="${DIRECT_STATE_WRITE_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# Functions allowed to write `state_db` directly, and why. Adding a name here
# needs a reason that it can never run inside a transaction.
#   set_balance / set_nonce / set_code     public setters: genesis, admin, tests, drain
#   set_genesis_storage                    genesis only: an alloc's contract storage (r1006)
#   register_genesis_model_from_bytes      genesis construction
#   settle_block_rewards                   end-of-block, after every tx committed
#   credit_validator_reward                end-of-block reward credit
#   drain_journal                          applies a COMMITTED tx's journal
#   simulate_transaction                   writes a throwaway simulation copy
#   add_model_artifact                     API path, never called from a tx
OUT_OF_TX="set_balance set_nonce set_code set_genesis_storage register_genesis_model_from_bytes settle_block_rewards credit_validator_reward drain_journal simulate_transaction add_model_artifact"

scan_transfers() { # <dir> ; prints violations, returns 0 iff any found
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

scan_executor() { # <file> ; prints violations, returns 0 iff any found
  local out
  [ -f "$1" ] || { echo "$1: missing (tripwire scope moved?)"; return 0; }
  out="$(OUT_OF_TX="$OUT_OF_TX" perl -ne '
      BEGIN { %ok = map { $_ => 1 } split / /, $ENV{OUT_OF_TX}; $fn = ""; $prev = ""; $t = 0; }
      $t = 1 if /^#\[cfg\(test\)\]/;
      next if $t;
      $fn = $1 if /^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+(\w+)/;
      my $sd = (/state_db/ || $prev =~ /state_db\s*$|\.accounts\s*$/);
      my $hit = ($sd && /\.\s*(?:set_storage|delete_storage|register_model|update_model|update_training_job|create_training_job|set_balance|set_nonce|transfer|set_code|set_code_hash|apply_journaled_\w+)\s*\(/)
             || /self\s*\.\s*(?:set_balance|set_nonce|set_code|add_model_artifact)\s*\(/;
      if ($hit && $prev !~ /LEGACY-PRE-SUPPLY-HARDENING/ && !$ok{$fn}) {
        print "$ARGV:$.: direct state write in fn $fn outside the journal: $_";
      }
      $prev = $_;' "$1")"
  [ -n "$out" ] && { echo "$out"; return 0; }
  return 1
}

self_test() {
  local d rc=0
  d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  # rule 1
  printf 'fn f(&self) {\n    self.state_db.accounts.transfer(&a, &b, v)?;\n}\n' > "$d/a.rs"
  scan_transfers "$d" >/dev/null || { echo "self-test: did not detect a direct transfer"; rc=1; }
  printf 'fn f(&self) {\n    self.state_db\n        .accounts\n        .transfer(&a, &b, v)?;\n}\n' > "$d/a.rs"
  scan_transfers "$d" >/dev/null || { echo "self-test: did not detect a split-line direct transfer"; rc=1; }
  printf 'fn f(&self) {\n    // LEGACY-PRE-SUPPLY-HARDENING\n    self.state_db.accounts.transfer(&a, &b, v)?;\n    self.journal_transfer(a, b, v, c)?;\n}\nmod tests {\n    fn t() { m.accounts.transfer(&a, &b, v); }\n}\n' > "$d/a.rs"
  scan_transfers "$d" >/dev/null && { echo "self-test: flagged the marked legacy arm / journal / test code"; rc=1; }
  # rule 2: each mutator class in a tx-path function is detected
  local w
  for w in 'self.state_db.set_storage(a, k, v);' 'self.state_db.delete_storage(a, &k);' \
           'self.state_db.register_model(id, m)?;' 'self.state_db.update_model(id, m)?;' \
           'self.state_db.update_training_job(id, j)?;' 'self.state_db.accounts.set_balance(a, b);' \
           'self.set_balance(&a, b);' 'self.add_model_artifact(&h, &c);'; do
    printf 'impl E {\n    async fn execute_thing(&self) {\n        %s\n    }\n}\n' "$w" > "$d/executor.rs"
    scan_executor "$d/executor.rs" >/dev/null || { echo "self-test: did not detect: $w"; rc=1; }
  done
  printf 'impl E {\n    fn execute_thing(&self) {\n        self.state_db\n            .set_storage(a, k, v);\n    }\n}\n' > "$d/executor.rs"
  scan_executor "$d/executor.rs" >/dev/null || { echo "self-test: did not detect a split-line state write"; rc=1; }
  # rule 2: negative controls — legacy arm, allow-listed fn, journal, tests
  printf 'impl E {\n    fn tx_set(&self) {\n        if on { j.record_storage_write(a, k, v); } else {\n            // LEGACY-PRE-SUPPLY-HARDENING\n            self.state_db.set_storage(a, k, v);\n        }\n    }\n    fn drain_journal(&self) {\n        self.state_db.set_storage(a, k, v);\n    }\n}\n#[cfg(test)]\nmod t {\n    fn x() { self.state_db.set_storage(a, k, v); }\n}\n' > "$d/executor.rs"
  scan_executor "$d/executor.rs" >/dev/null && { echo "self-test: flagged a legacy arm / allow-listed fn / test code"; rc=1; }
  [ $rc -eq 0 ] && echo "direct-state-write tripwire self-test: ok"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
fail=0
if scan_transfers "$REPO_ROOT/core/execution/src"; then fail=1; fi
if scan_executor "$REPO_ROOT/core/execution/src/executor.rs"; then fail=1; fi
if [ $fail -eq 1 ]; then
  echo "direct-state-write tripwire: FAILED (write state through the tx journal inside a tx)"
  exit 1
fi
echo "direct-state-write tripwire: clean"
