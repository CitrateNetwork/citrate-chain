#!/usr/bin/env bash
# forge_resume.sh: a `forge` for the r1006 ceremony devnet (put on PATH as `forge`).
#
# On a Citrate node, forge sometimes gives up on a transaction that was mined: it gets a
# null response while polling and stops the broadcast part-way (R1006_GAPS G-11). This
# wrapper runs the real forge and, when a `forge script ... --broadcast` stops on that
# receipt error, re-runs the same command with `--resume` (forge continues from its own
# broadcast record and sends only what is missing). Any other failure is returned as is.
# Used only by build_r1006_genesis.sh inside its private network namespace.
set -uo pipefail
REAL="${R1006_REAL_FORGE:?R1006_REAL_FORGE must name the real forge}"
is_broadcast_script=0
if [[ "${1:-}" == script ]]; then
  for a in "$@"; do [[ "$a" == --broadcast ]] && is_broadcast_script=1; done
fi
# One transaction at a time (forge waits for each receipt): with the devnet mining on demand,
# every transaction then gets its own block, at a height fixed by the ceremony's order.
if [[ $is_broadcast_script == 1 ]]; then
  slow=0
  for a in "$@"; do [[ "$a" == --slow ]] && slow=1; done
  [[ $slow == 1 ]] || set -- "$@" --slow
fi
log=$(mktemp "${TMPDIR:-/tmp}/forge-resume.XXXXXX")
trap 'rm -f "$log"' EXIT
"$REAL" "$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
tries=0
while [[ $rc -ne 0 && $is_broadcast_script == 1 && $tries -lt 6 ]] &&
  grep -qiE 'null response|tries remaining|failed to get receipt|timed out waiting|transaction dropped|not found after' "$log"; do
  tries=$((tries + 1))
  echo "forge_resume: receipt polling failed; resuming the broadcast (attempt $tries)" >&2
  sleep 4
  "$REAL" "$@" --resume 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
done
exit "$rc"
