#!/usr/bin/env bash
# RUSTSEC-2026-0220 (ruint shift flags) — ignore-premise tripwire.
#
# WHY THIS EXISTS
#   deny.toml and audit.toml both ignore RUSTSEC-2026-0220. That ignore is not a
#   shrug: it rests on two verified facts, and it is only honest for as long as
#   BOTH hold.
#
#     1. The advisory affects the FLAGS returned by `overflowing_shl/_shr` and
#        everything built on them — `checked_*`, `strict_*`, `saturating_*` — plus
#        `wrapping_shl/_shr` truncating the shift amount mod 2^32, plus a
#        `to_base_be` infinite loop on no-alloc builds. The advisory states the
#        SHIFTED VALUES were correct; only the flag was wrong.
#
#     2. citrate-chain reaches ruint only transitively (revm -> revm-primitives ->
#        alloy-primitives -> ruint) and NEVER calls any affected API itself, and
#        revm's SHL/SHR/SAR clamp `shift < 256` before using plain `<<` / `>>` /
#        `arithmetic_shr` — never the checked/saturating family
#        (revm-interpreter-6.0.0/src/instructions/bitwise.rs:83-118).
#
#   Fact 2 is the part that can silently stop being true: somebody adds a
#   `checked_shl` in our own code and the ignore quietly becomes a real exposure
#   with a stale justification attached. This gate FAILS if any affected API
#   appears in our source, which forces the ignore to be re-argued rather than
#   inherited.
#
#   The ignore cannot simply be removed instead: the fix is ruint >= 1.20.0, which
#   needs proptest with the `no_std` feature, which needs proptest 1.11+, which
#   needs rand 0.9 — pinned at `proptest = "=1.5.0"` workspace-wide and tracked as
#   BACKLOG #124. The newest ruint compatible with that pin is 1.11.0, still
#   vulnerable, so no partial upgrade helps.
#
# Usage: scripts/ci/ruint_shift_advisory_premise_tripwire.sh   (from repo root)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# The APIs RUSTSEC-2026-0220 actually implicates.
AFFECTED='checked_shl|checked_shr|overflowing_shl|overflowing_shr|saturating_shl|saturating_shr|wrapping_shl|wrapping_shr|strict_shl|strict_shr|to_base_be'

# Our first-party source only. Vendored/registry code is upstream's problem and is
# covered by fact 2 above.
HITS=$(grep -rnE "$AFFECTED" \
        --include='*.rs' \
        "$ROOT/core" "$ROOT/node" "$ROOT/cli" 2>/dev/null \
        | grep -v '/target/' || true)

if [ -n "$HITS" ]; then
  echo "RUSTSEC-2026-0220 ignore-premise BROKEN." >&2
  echo >&2
  echo "The ignore in deny.toml / audit.toml is justified by citrate-chain never" >&2
  echo "calling a shift API affected by the advisory. These call sites break that:" >&2
  echo >&2
  echo "$HITS" >&2
  echo >&2
  echo "Either remove the call, or re-argue the ignore against the new usage." >&2
  echo "Do NOT just add the file to this gate's exclusions." >&2
  exit 1
fi

echo "OK: no affected ruint shift API in first-party source; RUSTSEC-2026-0220 ignore premise holds."
