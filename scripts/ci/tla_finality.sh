#!/usr/bin/env bash
# WP-S.3 Stage 2 (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §8.4): bounded TLC
# model checking of checkpoint finality, run in CI (.github/workflows/tla-finality.yml)
# and locally (`scripts/ci/tla_finality.sh`).
#
#   MUST PASS  specs/tla/consensus/CheckpointVoteSafety.cfg       (H-01 / H-02 vote admission)
#   MUST PASS  specs/tla/consensus/CheckpointFinalitySafety.cfg   (S1 + S2, f = 1 of 4)
#   MUST FAIL  CheckpointFinalitySafety_byz2.cfg      NoConflictingFinality (f >= n/3)
#   MUST FAIL  CheckpointFinalitySafety_norecord.cfg  NoConflictingFinality (no signed-vote record)
#   MUST PASS  specs/tla/consensus/CheckpointFinalitySafety_strict.cfg (§5 S2 as written:
#              floor raised at finalization)
#   MUST FAIL  CheckpointFinalitySafety_pollonly.cfg  FinalizedStaysCanonical (the floor
#              follows only the verifier poll, after finalization)
#   MUST PASS  specs/tla/consensus/CheckpointFinalitySafety_restart.cfg (S2 across restarts:
#              the boot check consults every stored certificate)
#   MUST FAIL  CheckpointFinalitySafety_bootlimit.cfg FinalizedNeverReverted (the boot check
#              consults only the latest stored certificate)
#   MUST FAIL  CheckpointFinalitySafety_committees.cfg NoConflictingFinality (open finding:
#              committees are drawn per candidate block, so siblings can be finalized
#              by different committees without any equivocation)
#
# The MUST-FAIL configs are mutation checks: they prove the model can see the
# violations the passing config rules out. If one of them starts passing, the
# model (or the code it mirrors) changed and this script fails until the
# expectation is updated on purpose.
#
# The two-height model (CheckpointFinalitySafety_deep.cfg) is too large for CI;
# run it on demand: TLA_FINALITY_DEEP=1 scripts/ci/tla_finality.sh
#
# Requires Java 8+. tla2tools.jar: $TLC_JAR, else specs/tla/tla2tools.jar (the
# path specs/tla/run_all.sh uses), else downloaded (TLC 1.7.1, sha256-pinned).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SPECS="$ROOT/specs/tla/consensus"
JAR="${TLC_JAR:-$ROOT/specs/tla/tla2tools.jar}"
TLC_URL="https://github.com/tlaplus/tlaplus/releases/download/v1.7.1/tla2tools.jar"
TLC_SHA256="d532ba31aafe17afba1130f92410d9257454ff7393d1eb2fe032f0c07f352da5"
WORKERS="${TLC_WORKERS:-2}"
HEAP="${TLC_HEAP:-2g}"
TIMEOUT="${TLC_TIMEOUT:-600}"

if [ ! -f "$JAR" ]; then
    echo "Downloading TLC 1.7.1 -> $JAR"
    curl -sSfLo "$JAR" "$TLC_URL"
fi
got="$(sha256sum "$JAR" | cut -d' ' -f1)"
if [ "$got" != "$TLC_SHA256" ]; then
    echo "tla2tools.jar sha256 $got != pinned $TLC_SHA256 (TLC 1.7.1)" >&2
    exit 1
fi

fails=0

# run_tlc <spec> <cfg> -> prints TLC output, returns 0 always
run_tlc() {
    local spec="$1" cfg="$2" tmp
    tmp="$(mktemp -d)"
    (cd "$tmp" && timeout "$TIMEOUT" java "-Xmx${HEAP}" -XX:+UseParallelGC -cp "$JAR" \
        tlc2.TLC -config "$SPECS/$cfg" "$SPECS/$spec.tla" -workers "$WORKERS" -deadlock 2>&1) || true
    rm -rf "${tmp:?}"
}

states() { grep -oE '[0-9,]+ distinct states found' | tail -1 | tr -d ','; }

expect_pass() {
    local spec="$1" cfg="$2" out
    out="$(run_tlc "$spec" "$cfg")"
    if grep -q "Model checking completed. No error has been found." <<<"$out"; then
        printf '  PASS        %-45s (%s)\n' "$cfg" "$(states <<<"$out")"
    else
        printf '  FAIL        %-45s expected no violation\n' "$cfg"
        grep -E "Error|violated|Exception" <<<"$out" | head -5 | sed 's/^/      /'
        fails=$((fails + 1))
    fi
}

expect_violation() {
    local spec="$1" cfg="$2" inv="$3" out
    out="$(run_tlc "$spec" "$cfg")"
    if grep -qE "(Invariant|[Pp]roperty) $inv is violated" <<<"$out"; then
        printf '  VIOLATES    %-45s %s (expected)\n' "$cfg" "$inv"
    else
        printf '  FAIL        %-45s expected a %s counterexample\n' "$cfg" "$inv"
        grep -E "Error|violated|No error|Exception" <<<"$out" | head -5 | sed 's/^/      /'
        fails=$((fails + 1))
    fi
}

echo "=== TLA+ checkpoint finality (TLC 1.7.1, workers $WORKERS) ==="
expect_pass CheckpointVoteSafety CheckpointVoteSafety.cfg
expect_pass CheckpointFinalitySafety CheckpointFinalitySafety.cfg
expect_violation CheckpointFinalitySafety CheckpointFinalitySafety_byz2.cfg NoConflictingFinality
expect_violation CheckpointFinalitySafety CheckpointFinalitySafety_norecord.cfg NoConflictingFinality
expect_pass CheckpointFinalitySafety CheckpointFinalitySafety_strict.cfg
expect_violation CheckpointFinalitySafety CheckpointFinalitySafety_pollonly.cfg FinalizedStaysCanonical
expect_pass CheckpointFinalitySafety CheckpointFinalitySafety_restart.cfg
expect_violation CheckpointFinalitySafety CheckpointFinalitySafety_bootlimit.cfg FinalizedNeverReverted
expect_violation CheckpointFinalitySafety CheckpointFinalitySafety_committees.cfg NoConflictingFinality
if [ "${TLA_FINALITY_DEEP:-0}" = "1" ]; then
    TIMEOUT="${TLC_DEEP_TIMEOUT:-7200}" expect_pass CheckpointFinalitySafety CheckpointFinalitySafety_deep.cfg
fi

if [ "$fails" -ne 0 ]; then
    echo "TLA+ finality: $fails check(s) failed" >&2
    exit 1
fi
echo "TLA+ finality: all checks as expected"
