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
#
# Usage: audit_all_lockfiles.sh              # audit every tracked Cargo.lock
#        audit_all_lockfiles.sh --self-test  # prove the gate still flags a
#                                            # vulnerable pin and passes a clean one
# Exit:  0 clean · 1 advisory found / self-test failed · 2 cargo-audit missing
set -uo pipefail

REPO_ROOT="${AUDIT_ALL_LOCKFILES_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
FIXTURES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fixtures"

IGNORES=(
  RUSTSEC-2025-0137
  RUSTSEC-2025-0055
  RUSTSEC-2026-0220
)

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "cargo-audit not installed (cargo install cargo-audit --locked)" >&2
  exit 2
fi

audit_one() { # <lockfile> ; returns cargo-audit's exit status
  local args=() id
  for id in "${IGNORES[@]}"; do args+=(--ignore "$id"); done
  cargo audit --file "$1" "${args[@]}"
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
  # Coverage: enumeration must see more than the root lockfile.
  local n
  n="$(git -C "$REPO_ROOT" ls-files '*Cargo.lock' | wc -l)"
  if [ "$n" -lt 2 ]; then
    echo "self-test: enumerated only $n Cargo.lock file(s); sub-lockfiles not covered"; rc=1
  fi
  [ "$rc" -eq 0 ] && echo "self-test OK (vulnerable pin flagged, clean pin passes, $n lockfiles enumerated)"
  return "$rc"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test; exit $?
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
  echo "cargo audit FAILED for: ${failed[*]}" >&2
else
  echo "cargo audit OK for every tracked Cargo.lock"
fi
exit "$rc"
