#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCENARIOS=(
  "01_restart_recovery.sh"
  "02_network_partition.sh"
  "03_mempool_flood.sh"
  "04_concurrent_rpc.sh"
  "05_rapid_restart.sh"
)

declare -a RESULTS=()
declare -a DURATIONS=()
TOTAL=0
PASSED=0
FAILED=0

echo "============================================"
echo "  Citrate Chaos Test Suite"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
echo ""

for scenario in "${SCENARIOS[@]}"; do
  TOTAL=$((TOTAL + 1))
  script_path="${SCRIPT_DIR}/${scenario}"

  if [[ ! -x "$script_path" ]]; then
    echo "[SKIP] ${scenario} — not found or not executable"
    RESULTS+=("SKIP")
    DURATIONS+=("-")
    FAILED=$((FAILED + 1))
    continue
  fi

  echo "-----------------------------------------------"
  echo "[RUN]  ${scenario}"
  echo "-----------------------------------------------"

  start_ts=$(date +%s)
  set +e
  bash "$script_path"
  exit_code=$?
  set -e
  end_ts=$(date +%s)
  elapsed=$((end_ts - start_ts))
  DURATIONS+=("${elapsed}s")

  if [[ $exit_code -eq 0 ]]; then
    RESULTS+=("PASS")
    PASSED=$((PASSED + 1))
    echo "[PASS] ${scenario} (${elapsed}s)"
  else
    RESULTS+=("FAIL")
    FAILED=$((FAILED + 1))
    echo "[FAIL] ${scenario} (${elapsed}s, exit=${exit_code})"
  fi
  echo ""
done

echo ""
echo "============================================"
echo "  Summary"
echo "============================================"
printf "%-35s %-8s %s\n" "SCENARIO" "RESULT" "TIME"
printf "%-35s %-8s %s\n" "-----------------------------------" "------" "----"
for i in "${!SCENARIOS[@]}"; do
  printf "%-35s %-8s %s\n" "${SCENARIOS[$i]}" "${RESULTS[$i]}" "${DURATIONS[$i]}"
done
echo ""
echo "Total: ${TOTAL}  Passed: ${PASSED}  Failed: ${FAILED}"
echo "============================================"

if [[ $FAILED -gt 0 ]]; then
  exit 1
fi
exit 0
