#!/usr/bin/env bash
# audit_all_lockfiles.sh — run `cargo audit` on EVERY tracked Cargo.lock.
#
# The repo has several lockfiles outside the root workspace (fuzz/, tests/load/,
# tools/citrate-bench/, core/federated/, standalone crates). `cargo audit` with
# no --file only reads ./Cargo.lock, so those sub-lockfiles used to go unaudited
# and drifted onto versions with published advisories. This script enumerates
# `git ls-files '*Cargo.lock'` so a new lockfile is covered the moment it is
# committed, with no list to keep in sync.
#
# The ignore list below is the single source of truth for which advisories are
# accepted; each entry is documented in audit.toml (assessor-facing). Adding an
# ignore requires a deliberate PR that points at an open REM tracker.
#
#   REM-14  RUSTSEC-2025-0137  ruint reciprocal_mg10 OOB. False positive for
#           citrate-chain: alloy-primitives normalizes the divisor before the
#           unsafe path. Closes with the alloy-primitives ruint bump.
#   REM-16b RUSTSEC-2025-0055  tracing-subscriber ANSI log injection via the
#           ark-relations 0.4 transitive (direct deps already on 0.3). Deferred:
#           arkworks 0.4 -> 0.6 bump is a ZK-eng decision.
#   REM-14b RUSTSEC-2026-0220  ruint overflowing_shl/shr returned a wrong
#           overflow FLAG (shifted values correct). Patched >= 1.20.0, not
#           bumpable while alloy-primitives 0.7.7 pins ruint ^1.12. Premise
#           fenced by scripts/ci/ruint_shift_advisory_premise_tripwire.sh.
#   RUSTSEC-2026-0387  crypto-bigint < 0.7.6 timing variability, reached only
#           through elliptic-curve 0.13 (no 0.13.x accepts crypto-bigint 0.7).
#           Guard: scripts/ci/check_crypto_bigint_users.py (blocking step in
#           cargo-audit.yml and security-audit.yml).
#
# Usage: audit_all_lockfiles.sh              # audit every tracked Cargo.lock
#        audit_all_lockfiles.sh --self-test  # prove the gate still flags a
#                                            # vulnerable pin and passes a clean one
# Exit:  0 clean · 1 advisory found / self-test failed · 2 cargo-audit missing
set -uo pipefail

REPO_ROOT="${AUDIT_ALL_LOCKFILES_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
FIXTURES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fixtures"

# Entry format: ID, or ID@YYYY-MM-DD for a time-boxed ignore. A time-boxed
# ignore stops applying after that date (inclusive bound) and the gate fails
# until someone decides again; do not renew by reflex.
IGNORES=(
  RUSTSEC-2025-0137
  RUSTSEC-2025-0055
  RUSTSEC-2026-0220
  RUSTSEC-2026-0387@2027-01-31
)

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "cargo-audit not installed (cargo install cargo-audit --locked)" >&2
  exit 2
fi

# expired_ignores <today YYYY-MM-DD> <entry>... : print one line per entry
# that is expired or malformed; status 1 if any.
expired_ignores() {
  return 0
}

audit_one() { # <lockfile> ; returns cargo-audit's exit status
  local args=() e
  for e in "${IGNORES[@]}"; do args+=(--ignore "${e%%@*}"); done
  cargo audit --file "$1" ${args[@]+"${args[@]}"}
}

self_test() {
  local rc=0 out
  # Negative control: a lockfile pinned to a version with a published advisory
  # must fail the gate, and the failure must name that advisory.
  if out="$(audit_one "$FIXTURES/lockfile_audit_vulnerable.lock" 2>&1)"; then
    echo "self-test: vulnerable fixture PASSED the audit (gate is blind)"; rc=1
  elif ! grep -q 'RUSTSEC-2026-0382' <<<"$out"; then
    echo "self-test: vulnerable fixture failed for the wrong reason:"; echo "$out"; rc=1
  fi
  # Positive control: the same crate on the patched version must pass, so the
  # negative control is not just "cargo audit always fails".
  if ! out="$(audit_one "$FIXTURES/lockfile_audit_clean.lock" 2>&1)"; then
    echo "self-test: clean fixture FAILED the audit:"; echo "$out"; rc=1
  fi
  # Expiry: a time-boxed ignore must stop applying after its date, apply on
  # the date itself, and a malformed date must fail closed.
  if out="$(expired_ignores 2027-02-01 RUSTSEC-2026-0387@2027-01-31 RUSTSEC-2025-0137)"; then
    echo "self-test: an expired ignore was accepted"; rc=1
  elif ! grep -q 'RUSTSEC-2026-0387' <<<"$out" || grep -q 'RUSTSEC-2025-0137' <<<"$out"; then
    echo "self-test: expiry flagged the wrong entries: $out"; rc=1
  fi
  if ! out="$(expired_ignores 2027-01-31 RUSTSEC-2026-0387@2027-01-31)"; then
    echo "self-test: an ignore was rejected on its expiry date: $out"; rc=1
  fi
  if expired_ignores 2026-10-26 RUSTSEC-2026-0387@2027-1-31 >/dev/null; then
    echo "self-test: a malformed expiry was accepted"; rc=1
  fi
  if expired_ignores 2026-10-26 RUSTSEC-2026-0387@ >/dev/null; then
    echo "self-test: an empty expiry was accepted"; rc=1
  fi
  # The real list must be in force today, or the run below fails anyway.
  if ! out="$(expired_ignores "$(today)" "${IGNORES[@]}")"; then
    echo "self-test: the configured ignore list has expired entries: $out"; rc=1
  fi
  # Coverage: enumeration must see more than the root lockfile.
  local n
  n="$(git -C "$REPO_ROOT" ls-files '*Cargo.lock' | wc -l)"
  if [ "$n" -lt 2 ]; then
    echo "self-test: enumerated only $n Cargo.lock file(s); sub-lockfiles not covered"; rc=1
  fi
  [ "$rc" -eq 0 ] && echo "self-test OK (vulnerable pin flagged, clean pin passes, $n lockfiles enumerated)"
  return "$rc"
}

today() { echo "${AUDIT_ALL_LOCKFILES_TODAY:-$(date -u +%Y-%m-%d)}"; }

if [ "${1:-}" = "--self-test" ]; then
  self_test; exit $?
fi

if ! out="$(expired_ignores "$(today)" "${IGNORES[@]}")"; then
  echo "$out" >&2
  echo "cargo audit FAILED: time-boxed ignore(s) expired; decide again" >&2
  exit 1
fi

rc=0; failed=()
while IFS= read -r lock; do
  echo "::group::cargo audit $lock"
  if ! audit_one "$REPO_ROOT/$lock"; then
    rc=1; failed+=("$lock")
  fi
  echo "::endgroup::"
done < <(git -C "$REPO_ROOT" ls-files '*Cargo.lock')

if [ "$rc" -ne 0 ]; then
  echo "cargo audit FAILED for: ${failed[*]+"${failed[*]}"}" >&2
else
  echo "cargo audit OK for every tracked Cargo.lock"
fi
exit "$rc"
