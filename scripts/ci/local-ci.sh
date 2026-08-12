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
#   scripts/ci/local-ci.sh --fast       # fmt + clippy + unwrap ratchet only
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
      echo "gates: fmt-changed, clippy, unwrap-ratchet, consensus-tripwires, test-workspace, forge-build, forge-test"
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

# ── gate: .unwrap() ratchet ─────────────────────────────────────────────────
# CLAUDE.md: "Zero .unwrap() in production AND test code". The tree is not at
# zero today, so a hard gate would fail every run and be ignored within a day.
# Ratchet instead: the count may never INCREASE. The baseline is committed, so
# tightening it is a deliberate act.
unwrap_ratchet() {
  local baseline_file="scripts/ci/unwrap-baseline.txt"
  local count
  count=$(grep -rn '\.unwrap()' --include='*.rs' core node cli 2>/dev/null \
            | grep -v 'unwrap_or' | wc -l | tr -d ' ')
  if [ ! -f "$baseline_file" ]; then
    echo "$count" > "$baseline_file"
    echo "baseline created: $count"
    return 0
  fi
  local baseline; baseline=$(tr -d ' \n' < "$baseline_file")
  echo "current=$count baseline=$baseline"
  if [ "$count" -gt "$baseline" ]; then
    echo "error: .unwrap() count rose $baseline -> $count. Use ? or .expect(\"context\")."
    return 1
  fi
  if [ "$count" -lt "$baseline" ]; then
    echo "$count" > "$baseline_file"
    echo "ratchet tightened to $count — commit scripts/ci/unwrap-baseline.txt"
  fi
  return 0
}
gate "unwrap-ratchet" unwrap_ratchet

# ── gate: consensus tripwires (source-level regression fences) ──────────────
# Each tripwire is a cheap source scan that fences a specific consensus bug CLASS
# we have already been burned by. They run in --fast too: a wedge-the-chain
# regression is exactly what you want caught before push, and they cost ~0s.
# Append-only — never delete a tripwire "to make room"; add the new one here.
consensus_tripwires() {
  local rc=0 t
  for t in \
    "scripts/ci/fork_choice_add_block_parity_tripwire.sh" \
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

if [ "$FAST" -eq 1 ]; then
  skip "test-workspace" "--fast"
  skip "forge-build" "--fast"
  skip "forge-test" "--fast"
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

  # ── gates: solidity ──────────────────────────────────────────────────────
  if [ "$NO_FORGE" -eq 1 ]; then
    skip "forge-build" "--no-forge"; skip "forge-test" "--no-forge"
  elif ! command -v forge >/dev/null 2>&1; then
    skip "forge-build" "forge not installed"; skip "forge-test" "forge not installed"
  else
    gate "forge-build" bash -c "cd '$REPO_ROOT/contracts' && forge build"
    gate "forge-test"  bash -c "cd '$REPO_ROOT/contracts' && forge test"
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
