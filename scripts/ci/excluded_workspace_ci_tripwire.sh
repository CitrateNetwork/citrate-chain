#!/usr/bin/env bash
# excluded_workspace_ci_tripwire.sh — every crate the root workspace EXCLUDES must
# still have its tests run by CI.
#
# A crate listed in the root Cargo.toml `exclude = [...]` is its own Cargo
# workspace, so `cargo test --workspace` never reaches it. Unless a workflow runs
# it explicitly, its tests (including load-bearing rejection tests) can break with
# nothing noticing. This scan requires, for each excluded path P, that either
#   - a workflow under .github/workflows/ contains `--manifest-path P/Cargo.toml`, or
#   - a scripts/ci/*.sh script that a workflow invokes names P on a non-comment line,
# unless P is in ALLOW below with the reason it cannot run in CI.
#
# Usage: excluded_workspace_ci_tripwire.sh              # scan the tree
#        excluded_workspace_ci_tripwire.sh --self-test  # prove the rule still detects its class
set -uo pipefail

REPO_ROOT="${EXCLUDED_WS_TRIPWIRE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# Excluded paths CI cannot test. Each entry needs a reason.
#   core/federated — depends on the private git repo citrate-fed-types, which the
#                    public CI runner cannot fetch. Run it locally (see Cargo.toml).
ALLOW=("core/federated")

excluded_paths() { # <root> ; prints one excluded path per line
  perl -0ne 'if (/^exclude\s*=\s*\[(.*?)\]/ms) { my $l = $1; while ($l =~ /"([^"]+)"/g) { print "$1\n" } }' \
    "$1/Cargo.toml"
}

is_allowed() {
  local p="$1" a
  for a in "${ALLOW[@]}"; do [ "$a" = "$p" ] && return 0; done
  return 1
}

scan() { # <root> ; prints violations, returns 0 iff any found
  local root="$1" p found=1 wf scripts=() s covered
  local wfs=("$root"/.github/workflows/*.yml)
  # Scripts the workflows invoke.
  while IFS= read -r s; do
    [ -f "$root/$s" ] && scripts+=("$root/$s")
  done < <(grep -ohE 'scripts/ci/[A-Za-z0-9_.-]+\.sh' "${wfs[@]}" 2>/dev/null | sort -u)
  local paths
  paths="$(excluded_paths "$root")"
  if [ -z "$paths" ]; then
    echo "$root/Cargo.toml: could not parse any workspace exclude entries"
    return 0
  fi
  while IFS= read -r p; do
    is_allowed "$p" && continue
    covered=0
    if grep -qF -- "--manifest-path $p/Cargo.toml" "${wfs[@]}" 2>/dev/null; then
      covered=1
    else
      for s in "${scripts[@]}"; do
        if grep -vE '^\s*#' "$s" | grep -qF -- "$p"; then covered=1; break; fi
      done
    fi
    if [ "$covered" -eq 0 ]; then
      echo "Cargo.toml: '$p' is excluded from the workspace but no CI workflow runs its tests"
      found=0
    fi
  done <<<"$paths"
  return "$found"
}

self_test() {
  local tmp rc=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/excl-ws-tripwire.XXXXXX")"
  mkdir -p "$tmp/.github/workflows" "$tmp/scripts/ci"
  printf '[workspace]\nmembers = ["a"]\nexclude = ["core/federated", "crates/x", "crates/y"]\n' > "$tmp/Cargo.toml"

  # Neither excluded crate is run -> must flag both.
  printf 'jobs:\n  t:\n    steps:\n      - run: cargo test --workspace\n' > "$tmp/.github/workflows/ci.yml"
  local out; out="$(scan "$tmp")"
  if ! grep -q "'crates/x'" <<<"$out" || ! grep -q "'crates/y'" <<<"$out"; then
    echo "self-test: uncovered excluded crates were not flagged"; rc=1
  fi
  if grep -q "core/federated" <<<"$out"; then
    echo "self-test: allowlisted path was flagged"; rc=1
  fi

  # A path named only in a comment of an invoked script does not count.
  printf '# crates/x\n# crates/y\n' > "$tmp/scripts/ci/run.sh"
  printf 'jobs:\n  t:\n    steps:\n      - run: scripts/ci/run.sh\n' > "$tmp/.github/workflows/ci.yml"
  if ! scan "$tmp" >/dev/null; then
    echo "self-test: a comment-only mention was accepted as coverage"; rc=1
  fi

  # Covered: x via --manifest-path in a workflow, y via an invoked script.
  printf 'run_one crates/y\n' > "$tmp/scripts/ci/run.sh"
  printf 'jobs:\n  t:\n    steps:\n      - run: cargo test --manifest-path crates/x/Cargo.toml --locked\n      - run: scripts/ci/run.sh\n' \
    > "$tmp/.github/workflows/ci.yml"
  if out="$(scan "$tmp")"; then
    echo "self-test: fully covered tree was flagged: $out"; rc=1
  fi

  # A script that exists but no workflow invokes does not count.
  printf 'jobs:\n  t:\n    steps:\n      - run: cargo test --manifest-path crates/x/Cargo.toml --locked\n' \
    > "$tmp/.github/workflows/ci.yml"
  out="$(scan "$tmp")"
  if ! grep -q "'crates/y'" <<<"$out"; then
    echo "self-test: an un-invoked script was accepted as coverage"; rc=1
  fi

  # Mentions that are not a run step do not count: a `paths:` filter entry, a
  # YAML comment, a commented-out step, a shell comment inside a run block,
  # and an invocation that only runs the script's own --self-test.
  printf 'run_one crates/x\nrun_one crates/y\n' > "$tmp/scripts/ci/run.sh"
  cat > "$tmp/.github/workflows/ci.yml" <<'YAML'
on:
  pull_request:
    paths:
      - 'scripts/ci/run.sh'
# scripts/ci/run.sh
jobs:
  t:
    steps:
      - name: self-test only
        run: scripts/ci/run.sh --self-test
      # - run: scripts/ci/run.sh
      # - run: cargo test --manifest-path crates/x/Cargo.toml --locked
      - name: shell comment
        run: |
          # scripts/ci/run.sh
          # cargo test --manifest-path crates/x/Cargo.toml
          echo done
YAML
  out="$(scan "$tmp")"
  if ! grep -q "'crates/x'" <<<"$out" || ! grep -q "'crates/y'" <<<"$out"; then
    echo "self-test: a non-run mention of a script or --manifest-path was accepted as coverage"; rc=1
  fi

  # Negative control on the real tree: rust-ci.yml with the step that runs the
  # commd suites deleted (paths: entries and the --self-test step left in
  # place) must leave both commd crates uncovered; the unmodified copy passes.
  local real="$REPO_ROOT"
  if [ -f "$real/.github/workflows/rust-ci.yml" ] && [ -f "$real/scripts/ci/test_commd_workspaces.sh" ]; then
    rm -f "$tmp"/.github/workflows/*.yml "$tmp"/scripts/ci/*.sh
    cp "$real/Cargo.toml" "$tmp/Cargo.toml"
    cp "$real/scripts/ci/test_commd_workspaces.sh" "$tmp/scripts/ci/"
    cp "$real/.github/workflows/rust-ci.yml" "$tmp/.github/workflows/"
    if out="$(scan "$tmp")"; then
      echo "self-test: the real rust-ci.yml copy was flagged: $out"; rc=1
    fi
    perl -0pi -e 's/\n      - name: Test commd fold[^\n]*\n        run: scripts\/ci\/test_commd_workspaces\.sh\n/\n/' \
      "$tmp/.github/workflows/rust-ci.yml"
    if grep -q 'Test commd fold' "$tmp/.github/workflows/rust-ci.yml"; then
      echo "self-test: could not delete the commd run step from the rust-ci.yml copy"; rc=1
    fi
    out="$(scan "$tmp")"
    if ! grep -q "'crates/citrate-commd-fold'" <<<"$out" || ! grep -q "'crates/citrate-commd-verify'" <<<"$out"; then
      echo "self-test: rust-ci.yml without the commd run step still counted as coverage"; rc=1
    fi
    printf '[workspace]\nmembers = ["a"]\nexclude = ["core/federated", "crates/x", "crates/y"]\n' > "$tmp/Cargo.toml"
  fi

  # An unparseable exclude list must fail closed.
  printf '[workspace]\nmembers = ["a"]\n' > "$tmp/Cargo.toml"
  if ! scan "$tmp" >/dev/null; then
    echo "self-test: an unparseable exclude list passed"; rc=1
  fi

  case "$tmp" in "${TMPDIR:-/tmp}"/excl-ws-tripwire.*) rm -rf -- "$tmp" ;; esac
  [ "$rc" -eq 0 ] && echo "excluded_workspace_ci_tripwire self-test OK"
  return "$rc"
}

case "${1:-}" in
  --self-test) self_test; exit $? ;;
  "") ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

if out="$(scan "$REPO_ROOT")"; then
  echo "$out"
  echo "FAIL: excluded workspace crate(s) without CI test coverage. Add a job to .github/workflows/rust-ci.yml."
  exit 1
fi
echo "excluded_workspace_ci_tripwire OK"
