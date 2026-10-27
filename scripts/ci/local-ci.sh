#!/usr/bin/env bash
# local-ci.sh — run the CI gates locally, without GitHub Actions.
#
# WHY THIS EXISTS
#
# Org-wide GitHub Actions have been dead since ~2026-07-18 (every private-repo
# run fails `startup_failure` at 0s). Between then and 2026-08-04 that meant a
# breaking CONSENSUS change merged to main with `checks=0` and nothing but a
# developer's local runs behind it. This script makes "what CI would have run"
# a single reproducible command, so the gate is real again and lives on a
# machine you control.
#
# It mirrors .github/workflows/rust-ci.yml plus the CLAUDE.md rules that were
# only ever enforced by convention.
#
# Usage:
#   scripts/ci/local-ci.sh              # everything (default)
#   scripts/ci/local-ci.sh --fast       # fmt + clippy + panic ratchet + tripwires
#   scripts/ci/local-ci.sh --no-forge   # skip solidity (no forge installed)
#   scripts/ci/local-ci.sh --list       # show the gates and exit
#
# Exit: 0 all gates pass · 1 one or more failed. Every gate runs even if an
# earlier one fails (you get the full picture in one pass, not one-at-a-time),
# EXCEPT that a compile failure makes later cargo gates redundant and they are
# reported as SKIP rather than pretending to be green.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FAST=0; NO_FORGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --fast) FAST=1; shift ;;
    --no-forge) NO_FORGE=1; shift ;;
    --list)
      echo "gates: fmt-changed, clippy, panic-ratchet, consensus-tripwires, git-rev-deps, audit-lockfiles, fuzz-targets-compile, ci-scripts, test-workspace, test-commd, forge-build, forge-test, genesis-pipeline"
      exit 0 ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
[ -t 1 ] || { BOLD=""; RED=""; GRN=""; YEL=""; RST=""; }

declare -a NAMES=() RESULTS=() TIMES=()
FAILED=0
COMPILE_BROKEN=0

# Run one gate. `gate <name> <command...>`
gate() {
  local name="$1"; shift
  local start end dur out rc
  printf "%s▶ %s%s\n" "$BOLD" "$name" "$RST"
  start=$(date +%s)
  out="$("$@" 2>&1)"; rc=$?
  end=$(date +%s); dur=$((end - start))
  NAMES+=("$name"); TIMES+=("${dur}s")
  if [ $rc -eq 0 ]; then
    RESULTS+=("PASS")
    printf "  %sPASS%s (%ss)\n" "$GRN" "$RST" "$dur"
  else
    RESULTS+=("FAIL")
    FAILED=1
    printf "  %sFAIL%s (%ss)\n" "$RED" "$RST" "$dur"
    # Show only the actionable tail — full output on a failing gate is noise.
    echo "$out" | grep -E "^(error|warning|thread|test result:|FAILED|Error)" | head -25 | sed 's/^/    /'
    [ -n "$out" ] || echo "    (no output)"
  fi
}

skip() {
  NAMES+=("$1"); RESULTS+=("SKIP"); TIMES+=("-")
  printf "%s▶ %s%s\n  %sSKIP%s — %s\n" "$BOLD" "$1" "$RST" "$YEL" "$RST" "$2"
}

# ── gate: formatting (CHANGED FILES ONLY) ───────────────────────────────────
# `cargo fmt --all --check` fails on this tree today, and always has: there was
# never a fmt step in .github/workflows/rust-ci.yml, so nothing enforced it.
# ~30 pre-existing files in cli/ are unformatted. A gate that fails on day one
# for reasons the author did not cause is a gate that gets ignored, and a
# flag-day reformat would bury real history under a giant diff.
#
# So: check only files this branch actually touches versus main. The rule is
# enforced going forward, the debt stays visible, and it can be paid down
# deliberately (`cargo fmt --all` once, on its own commit) whenever you choose.
fmt_changed() {
  local base files
  base=$(git merge-base HEAD origin/main 2>/dev/null || git rev-parse HEAD~1 2>/dev/null || echo "")
  if [ -z "$base" ]; then
    echo "no diff base — skipping (nothing to compare against)"
    return 0
  fi
  files=$(git diff --name-only --diff-filter=ACMR "$base" HEAD -- '*.rs' 2>/dev/null
          git diff --name-only --diff-filter=ACMR -- '*.rs' 2>/dev/null)
  files=$(echo "$files" | sort -u | grep -v '^$' || true)
  if [ -z "$files" ]; then
    echo "no changed .rs files"
    return 0
  fi
  echo "checking $(echo "$files" | wc -l | tr -d ' ') changed file(s)"
  local bad=0
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    if ! rustfmt --edition 2021 --check "$f" >/dev/null 2>&1; then
      echo "  unformatted: $f"
      bad=1
    fi
  done <<< "$files"
  [ "$bad" -eq 0 ] || { echo "run: cargo fmt -- \$(git diff --name-only $base HEAD -- '*.rs')"; return 1; }
  return 0
}
gate "fmt-changed" fmt_changed

# ── gate: clippy (the repo rule is -D warnings, not "mostly clean") ──────────
gate "clippy" cargo clippy --workspace --all-targets -- -D warnings
# A clippy failure is usually a real compile error; remember that so the test
# gate does not re-pay a 5-minute build only to report the same breakage.
[ "${RESULTS[-1]}" = "FAIL" ] && COMPILE_BROKEN=1

# ── gate: production panic ratchet (PANIC-S1 G1) ────────────────────────────
# Replaces the old `.unwrap()` grep ratchet. That one counted test code (3,803
# of its 3,804 hits were in #[cfg(test)] / tests/), so it blocked pushes over test
# hygiene while measuring none of the real risk: production had ZERO unwraps, but
# 2,293 other ways to panic. This gate counts what can actually take a node down:
# clippy's panic lints over production targets only (--lib --bins), including
# unchecked indexing and arithmetic (release has overflow-checks = true). No
# (crate, lint) count may rise above scripts/ci/panic-baseline.json; decreases
# tighten the baseline. See citrate-federation PANIC-S1 sprint.
panic_ratchet() {
  local cur; cur="$(mktemp)"
  scripts/ci/panic-inventory.sh --summary "$cur" || { rm -f "$cur"; return 1; }
  python3 scripts/ci/panic_ratchet.py scripts/ci/panic-baseline.json "$cur"
  local rc=$?; rm -f "$cur"; return $rc
}
if [ "$COMPILE_BROKEN" -eq 1 ]; then
  skip "panic-ratchet" "clippy failed to compile — fix that first"
else
  gate "panic-ratchet" panic_ratchet
fi

# ── gate: consensus tripwires (source-level regression fences) ──────────────
# Each tripwire is a cheap source scan that fences a specific consensus bug CLASS
# we have already been burned by. They run in --fast too: a wedge-the-chain
# regression is exactly what you want caught before push, and they cost ~0s.
# Append-only — never delete a tripwire "to make room"; add the new one here.
# The 2026-10-19 set (forge script chain id / address(this), historical state reads, finality
# tags via the height index, finalization publish order, shell rm/pipefail, synthetic-pid
# signals, TLA+ frame clashes, installer tests without a sandboxed HOME, signing outside the
# wallet crates) shares scripts/ci/tripwire-allowlist.txt for reviewed exceptions; CI runs the
# same list in .github/workflows/tripwires.yml.
consensus_tripwires() {
  local rc=0 t
  for t in \
    "scripts/ci/fork_choice_add_block_parity_tripwire.sh" \
    "scripts/ci/check_pba_exec_tripwires.sh" \
    "scripts/ci/panic_invariant_tripwire.sh" \
    "scripts/ci/double_lock_tripwire.sh" \
    "scripts/ci/prod_assert_ratchet.sh" \
    "scripts/ci/forge_script_tripwire.sh" \
    "scripts/ci/historical_state_read_tripwire.sh" \
    "scripts/ci/rpc_height_index_tripwire.sh" \
    "scripts/ci/finalization_publish_order_tripwire.sh" \
    "scripts/ci/shell_safety_tripwire.sh" \
    "scripts/ci/synthetic_pid_signal_tripwire.sh" \
    "scripts/ci/tla_frame_tripwire.sh" \
    "scripts/ci/installer_test_sandbox_tripwire.sh" \
    "scripts/ci/wallet_gate_signing_tripwire.sh" \
    "scripts/ci/excluded_workspace_ci_tripwire.sh" \
    "scripts/ci/salt_supply_tripwire.sh" \
    "scripts/ci/finality_range_height_index_tripwire.sh" \
    "scripts/ci/finality_certificate_durable_write_tripwire.sh" \
    "scripts/ci/finality_finalize_retry_wired_tripwire.sh" \
  ; do
    if [ ! -x "$t" ]; then
      echo "missing/!executable tripwire: $t"; rc=1; continue
    fi
    # Prove the tripwire's own engine still detects its bug class (self-test),
    # then run it against the tree. A blind tripwire is worse than none.
    if ! "$t" --self-test >/dev/null 2>&1; then
      echo "tripwire self-test FAILED (engine no longer detects its bug class): $t"; rc=1
    fi
    if ! out="$("$t" 2>&1)"; then
      echo "$out"; rc=1
    fi
  done
  return "$rc"
}
gate "consensus-tripwires" consensus_tripwires

# ── gate: git dependency pins resolve on their remotes ──────────────────────
# A Cargo git pin can be stranded from outside this repo: the dependency's
# history is rewritten and the pinned commit is no longer served. Warm
# ~/.cargo/git caches hide it, so only a fresh fetch notices. Needs network
# (git ls-remote + a shallow fetch per pinned commit). Runs in --fast.
git_rev_deps() {
  scripts/ci/git_rev_deps_tripwire.sh --self-test >/dev/null 2>&1 \
    || { echo "git-rev-deps self-test FAILED (the check no longer detects a stranded pin)"; return 1; }
  scripts/ci/git_rev_deps_tripwire.sh
}
gate "git-rev-deps" git_rev_deps

# ── gate: cargo audit on every tracked Cargo.lock ───────────────────────────
# Sub-lockfiles (fuzz/, tests/load/, tools/citrate-bench/, ...) are not covered
# by a root `cargo audit`. Full mode only: it fetches the advisory DB, which a
# pre-push --fast run should not depend on. Self-test first (negative control).
audit_lockfiles() {
  local t="scripts/ci/audit_all_lockfiles.sh"
  "$t" --self-test || return 1
  "$t"
}
if [ "$FAST" -eq 1 ]; then
  skip "audit-lockfiles" "--fast"
elif ! command -v cargo-audit >/dev/null 2>&1; then
  skip "audit-lockfiles" "cargo-audit not installed"
else
  gate "audit-lockfiles" audit_lockfiles
fi

# ── gate: every fuzz target is registered and compiles ──────────────────────
# fuzz/ is its own workspace; nothing else builds it. Full mode only (it is a
# full compile of the fuzz crate). Self-test first (negative control).
fuzz_targets_compile() {
  local t="scripts/ci/check_fuzz_targets.sh"
  "$t" --self-test || return 1
  "$t"
}
if [ "$FAST" -eq 1 ]; then
  skip "fuzz-targets-compile" "--fast"
else
  gate "fuzz-targets-compile" fuzz_targets_compile
fi

# ── gate: the CI scripts' own tests ─────────────────────────────────────────
# The pre-push hook and push.sh are the only gate between a branch and the
# remote; test them end to end against a throwaway bare remote. ~20s of
# deliberate sleeps (it simulates a slow CI run), so full mode only.
if [ "$FAST" -eq 1 ]; then
  skip "ci-scripts" "--fast"
else
  gate "ci-scripts" scripts/ci/test_pre_push_hook.sh
fi

if [ "$FAST" -eq 1 ]; then
  skip "test-workspace" "--fast"
  skip "test-commd" "--fast"
  skip "forge-build" "--fast"
  skip "forge-test" "--fast"
  skip "genesis-pipeline" "--fast"
else
  # ── gate: workspace tests (mirrors rust-ci.yml core-workspace) ────────────
  # Failures already on main are tracked in known-test-failures.txt so this gate
  # is red for regressions you caused and green for debt you inherited. Any test
  # that fails and is NOT listed there fails the gate.
  test_workspace() {
    local known="scripts/ci/known-test-failures.txt" out failing new
    out="$(cargo test --workspace --quiet 2>&1)"
    failing="$(echo "$out" | grep -oE '^---- [^ ]+ stdout' | awk '{print $2}' | sort -u)"
    if [ -z "$failing" ]; then
      echo "$out" | grep -E "^test result:" | tail -3
      return 0
    fi
    echo "failing tests:"; echo "$failing" | sed 's/^/  /'
    if [ ! -f "$known" ]; then
      echo "no $known — every failure is unexplained"
      return 1
    fi
    # Anything failing that is not an uncommented line in the known file.
    new="$(comm -23 <(echo "$failing") \
                   <(grep -vE '^\s*(#|$)' "$known" | tr -d ' \t' | sort -u))"
    if [ -n "$new" ]; then
      echo "NEW failure(s) not in $known:"; echo "$new" | sed 's/^/  /'
      return 1
    fi
    echo "all failures are known/tracked in $known — see it for owner + reason"
    return 0
  }
  if [ "$COMPILE_BROKEN" -eq 1 ]; then
    skip "test-workspace" "clippy failed to compile — fix that first"
  else
    gate "test-workspace" test_workspace
  fi

  # ── gate: commd fold/verify workspaces (mirrors rust-ci.yml commd-workspaces)
  # Own Cargo workspaces, so test-workspace above never reaches them.
  gate "test-commd" bash -c "'$REPO_ROOT/scripts/ci/test_commd_workspaces.sh' --self-test && '$REPO_ROOT/scripts/ci/test_commd_workspaces.sh'"

  # ── gates: solidity ──────────────────────────────────────────────────────
  if [ "$NO_FORGE" -eq 1 ]; then
    skip "forge-build" "--no-forge"; skip "forge-test" "--no-forge"; skip "genesis-pipeline" "--no-forge"
  elif ! command -v forge >/dev/null 2>&1; then
    skip "forge-build" "forge not installed"; skip "forge-test" "forge not installed"
    skip "genesis-pipeline" "forge not installed"
  else
    gate "forge-build" bash -c "cd '$REPO_ROOT/contracts' && forge build"
    gate "forge-test"  bash -c "cd '$REPO_ROOT/contracts' && forge test"
    # Real `forge script --broadcast` run of the C4 genesis ceremony on anvil 40204: catches
    # script-only failures (e.g. `address(this)` on a run path) that `forge test` cannot.
    gate "genesis-pipeline" "$REPO_ROOT/scripts/ci/genesis-pipeline-anvil.sh"
  fi
fi

# ── summary ─────────────────────────────────────────────────────────────────
echo
printf "%s──────── local CI summary ────────%s\n" "$BOLD" "$RST"
for i in "${!NAMES[@]}"; do
  case "${RESULTS[$i]}" in
    PASS) c="$GRN" ;; FAIL) c="$RED" ;; *) c="$YEL" ;;
  esac
  printf "  %s%-6s%s %-16s %s\n" "$c" "${RESULTS[$i]}" "$RST" "${NAMES[$i]}" "${TIMES[$i]}"
done
echo
if [ "$FAILED" -eq 1 ]; then
  printf "%s%sLOCAL CI FAILED%s\n" "$BOLD" "$RED" "$RST"
  exit 1
fi
printf "%s%sLOCAL CI PASSED%s\n" "$BOLD" "$GRN" "$RST"
