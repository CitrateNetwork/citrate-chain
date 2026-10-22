#!/usr/bin/env bash
# check_fuzz_targets.sh — every fuzz target is registered and compiles.
#
# fuzz/ is its own workspace, so `cargo test --workspace` never builds it, and
# the nightly fuzz workflow is scheduled, not a PR gate. Two targets
# (fuzz_mempool_logic, fuzz_gossip_validation) stopped compiling against the
# current mempool / block APIs and nothing noticed: a harness that does not
# build protects nothing. This gate makes that rot a PR failure.
#
# Checks:
#   1. registration — every fuzz/fuzz_targets/*.rs is a [[bin]] in
#      fuzz/Cargo.toml (an unregistered file is never compiled), every [[bin]]
#      path exists, and every [[bin]] is in the .github/workflows/fuzz.yml
#      matrix (an unlisted target is never run).
#   2. compile — `cargo check --locked --bins` in fuzz/ (stable toolchain is
#      enough to type-check; the sanitizer build stays in fuzz.yml).
#
# Usage: check_fuzz_targets.sh                # registration + compile
#        check_fuzz_targets.sh --no-compile   # registration only (fast)
#        check_fuzz_targets.sh --self-test    # prove the registration check
#                                             # flags a broken fixture and
#                                             # passes a clean one
# Env:   CHECK_FUZZ_TARGETS_ROOT  repo root to check (default: this repo)
# Exit:  0 ok · 1 a check failed / self-test failed
set -uo pipefail

ROOT="${CHECK_FUZZ_TARGETS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

registration() {
  local root="$1" rc=0 f name
  local manifest="$root/fuzz/Cargo.toml" matrix="$root/.github/workflows/fuzz.yml"
  [ -f "$manifest" ] || { echo "missing $manifest"; return 1; }
  [ -f "$matrix" ] || { echo "missing $matrix"; return 1; }

  for f in "$root"/fuzz/fuzz_targets/*.rs; do
    [ -e "$f" ] || continue
    f="fuzz_targets/$(basename "$f")"
    if ! grep -qE "^path = \"$f\"" "$manifest"; then
      echo "unregistered fuzz target (no [[bin]] in fuzz/Cargo.toml): $f"; rc=1
    fi
  done

  while read -r f; do
    [ -f "$root/fuzz/$f" ] || { echo "[[bin]] path does not exist: fuzz/$f"; rc=1; }
  done < <(sed -nE 's/^path = "([^"]+)"/\1/p' "$manifest")

  while read -r name; do
    if ! grep -qE "^[[:space:]]*-[[:space:]]+$name[[:space:]]*$" "$matrix"; then
      echo "fuzz target not in the fuzz.yml matrix: $name"; rc=1
    fi
  done < <(awk '/^\[\[bin\]\]/{b=1;next} b&&/^name = /{gsub(/"/,"",$3);print $3;b=0}' "$manifest")

  return $rc
}

compile() {
  local root="$1"
  (cd "$root/fuzz" && cargo check --locked --bins)
}

self_test() {
  local tmp rc=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/check-fuzz-targets.XXXXXX")" || return 1
  # shellcheck disable=SC2064
  trap "rm -rf -- '$tmp'" RETURN
  mkdir -p "$tmp/fuzz/fuzz_targets" "$tmp/.github/workflows"
  printf '[[bin]]\nname = "fuzz_a"\npath = "fuzz_targets/fuzz_a.rs"\n' > "$tmp/fuzz/Cargo.toml"
  printf 'jobs:\n  fuzz:\n    strategy:\n      matrix:\n        target:\n          - fuzz_a\n' \
    > "$tmp/.github/workflows/fuzz.yml"
  : > "$tmp/fuzz/fuzz_targets/fuzz_a.rs"

  if ! registration "$tmp" >/dev/null; then
    echo "self-test: clean fixture was flagged"; rc=1
  fi

  : > "$tmp/fuzz/fuzz_targets/fuzz_b.rs"          # unregistered target
  if registration "$tmp" >/dev/null; then
    echo "self-test: unregistered target was not flagged"; rc=1
  fi
  rm -f "$tmp/fuzz/fuzz_targets/fuzz_b.rs"

  printf '[[bin]]\nname = "fuzz_c"\npath = "fuzz_targets/fuzz_c.rs"\n' >> "$tmp/fuzz/Cargo.toml"
  : > "$tmp/fuzz/fuzz_targets/fuzz_c.rs"          # registered, not in matrix
  if registration "$tmp" >/dev/null; then
    echo "self-test: target missing from the matrix was not flagged"; rc=1
  fi

  [ $rc -eq 0 ] && echo "self-test: ok"
  return $rc
}

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  --no-compile) registration "$ROOT"; exit $? ;;
  "") ;;
  *) echo "unknown arg: $1" >&2; exit 1 ;;
esac

rc=0
registration "$ROOT" || rc=1
compile "$ROOT" || { echo "fuzz targets do not compile (cargo check --locked --bins in fuzz/)"; rc=1; }
[ $rc -eq 0 ] && echo "fuzz targets: registered and compiling"
exit $rc
