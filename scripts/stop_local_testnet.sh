#!/usr/bin/env bash
# ============================================================
# Citrate v3 — Local Testnet Stop Script
# Gracefully stops all 3 bootstrap nodes
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PID_DIR="$PROJECT_ROOT/.testnet-pids"

echo -e "${YELLOW}Stopping Citrate local testnet...${NC}"

STOPPED=0

if [ -d "$PID_DIR" ]; then
    for pid_file in "$PID_DIR"/boot-*.pid; do
        if [ -f "$pid_file" ]; then
            pid=$(cat "$pid_file")
            node=$(basename "$pid_file" .pid)

            if kill -0 "$pid" 2>/dev/null; then
                echo -e "  Stopping ${node} (PID ${pid})..."
                kill "$pid" 2>/dev/null || true
                STOPPED=$((STOPPED + 1))
            else
                echo -e "  ${node} already stopped (stale PID ${pid})"
            fi
            rm -f "$pid_file"
        fi
    done

    # Wait for graceful shutdown
    if [ $STOPPED -gt 0 ]; then
        echo -e "  Waiting for graceful shutdown..."
        sleep 3

        # Force kill any remaining
        for pid_file in "$PID_DIR"/boot-*.pid; do
            if [ -f "$pid_file" ]; then
                pid=$(cat "$pid_file")
                if kill -0 "$pid" 2>/dev/null; then
                    echo -e "  ${RED}Force killing PID ${pid}${NC}"
                    kill -9 "$pid" 2>/dev/null || true
                fi
                rm -f "$pid_file"
            fi
        done
    fi
else
    echo "  No PID directory found — testnet may not be running."
fi

# Also check for any orphaned citrate processes on testnet ports
for port in 30303 30304 30305; do
    orphan_pid=$(lsof -ti ":${port}" 2>/dev/null || true)
    if [ -n "$orphan_pid" ]; then
        echo -e "  ${YELLOW}Killing orphaned process on port ${port} (PID ${orphan_pid})${NC}"
        kill "$orphan_pid" 2>/dev/null || true
    fi
done

echo ""
echo -e "${GREEN}Local testnet stopped.${NC}"
echo "  Data preserved in .citrate-testnet-boot-{1,2,3}/"
echo "  Logs preserved in run-logs/testnet/"
echo "  To wipe data: ./scripts/launch_local_testnet.sh --clean"
