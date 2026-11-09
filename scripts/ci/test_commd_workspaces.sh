#!/usr/bin/env bash
# test_commd_workspaces.sh — run the tests of the CommD fold prover and verifier.
#
# Both crates are their own Cargo workspaces (excluded from the root workspace so
# Nova's deps never unify with the pinned halo2 stack), so `cargo test --workspace`
# does not reach them. This script is the single place CI (rust-ci.yml,
# job commd-workspaces) and local-ci.sh run them.
#
# --release: the folding tests prove real Nova proofs; in a debug build the fold
# suite alone takes ~7 minutes, in release ~40 seconds.
#
# PINNED lists tests that must run and pass BY NAME. If one is renamed, deleted or
# filtered out, the gate fails even though `cargo test` itself passed.
#
# Usage: test_commd_workspaces.sh              # run the suites
#        test_commd_workspaces.sh --self-test  # prove the pinned-test check still works
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PINNED=(
  "crates/citrate-commd-verify|tests::non_canonical_initial_state_is_rejected_before_proof_decode"
  "crates/citrate-commd-verify|tests::non_canonical_public_input_is_rejected"
  "crates/citrate-commd-verify|tests::verifies_a_real_fold_proof_and_rejects_tampering"
  "crates/citrate-commd-verify|cry_c2_forged_initial_state_is_rejected"
)

# check_pinned <crate-dir> <log> ; prints missing pinned tests, returns 0 iff all ran ok
check_pinned() {
  local dir="$1" log="$2" entry name rc=0
  for entry in "${PINNED[@]}"; do
    [ "${entry%%|*}" = "$dir" ] || continue
    name="${entry#*|}"
    if ! grep -qxF "test $name ... ok" "$log"; then
      echo "pinned test did not run and pass: $dir $name"; rc=1
    fi
  done
  return "$rc"
}

run_one() { # <crate-dir>
  local dir="$1" log rc
  log="$(mktemp "${TMPDIR:-/tmp}/commd-ws-test.XXXXXX")"
  echo "== cargo test --release --locked --no-fail-fast --manifest-path $dir/Cargo.toml"
  cargo test --release --locked --no-fail-fast --manifest-path "$REPO_ROOT/$dir/Cargo.toml" 2>&1 | tee "$log"
  rc="${PIPESTATUS[0]}"
  if [ "$rc" -ne 0 ]; then
    echo "FAIL: $dir tests (cargo exit $rc)"
  elif ! check_pinned "$dir" "$log"; then
    rc=1
  fi
  rm -f -- "$log"
  return "$rc"
}

self_test() {
  local tmp rc=0
  tmp="$(mktemp "${TMPDIR:-/tmp}/commd-ws-selftest.XXXXXX")"
  printf 'test tests::non_canonical_public_input_is_rejected ... ok\ntest tests::verifies_a_real_fold_proof_and_rejects_tampering ... ok\ntest cry_c2_forged_initial_state_is_rejected ... ok\n' > "$tmp"
  # One pinned test missing -> must fail.
  if check_pinned crates/citrate-commd-verify "$tmp" >/dev/null; then
    echo "self-test: a missing pinned test was not detected"; rc=1
  fi
  # Present but FAILED -> must fail.
  printf 'test tests::non_canonical_initial_state_is_rejected_before_proof_decode ... FAILED\n' >> "$tmp"
  if check_pinned crates/citrate-commd-verify "$tmp" >/dev/null; then
    echo "self-test: a failed pinned test was accepted"; rc=1
  fi
  # All present and ok -> must pass.
  printf 'test tests::non_canonical_initial_state_is_rejected_before_proof_decode ... ok\n' >> "$tmp"
  if ! check_pinned crates/citrate-commd-verify "$tmp" >/dev/null; then
    echo "self-test: a complete passing log was rejected"; rc=1
  fi
  rm -f -- "$tmp"
  [ "$rc" -eq 0 ] && echo "test_commd_workspaces self-test OK"
  return "$rc"
}

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  "") ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

rc=0
run_one crates/citrate-commd-fold || rc=1
run_one crates/citrate-commd-verify || rc=1
[ "$rc" -eq 0 ] && echo "commd workspace tests OK"
exit "$rc"
