#!/usr/bin/env bash
# ============================================================================
# sync-gui-addresses.sh — update GUI contract addresses from a ceremony output
# ============================================================================
#
# Reads a 30_address_table.json from a completed ceremony run and writes
# the fresh contract addresses into citrate_edu_app/src/config.rs, plus
# updates DEPLOYED_ADDRESSES.md header.
#
# Usage:
#   ./sync-gui-addresses.sh path/to/30_address_table.json [repo_root]
#
# Idempotent: re-running produces the same file if addresses don't change.
#
# ============================================================================
set -euo pipefail

ADDR_JSON="${1:-}"
REPO_ROOT="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

if [ -z "$ADDR_JSON" ] || [ ! -f "$ADDR_JSON" ]; then
    echo "usage: $0 path/to/30_address_table.json [repo_root]" >&2
    exit 1
fi

command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

EDU_CONFIG="$REPO_ROOT/gui/citrate_edu_app/src/config.rs"
DEPLOYED_MD="$REPO_ROOT/contracts/DEPLOYED_ADDRESSES.md"

[ -f "$EDU_CONFIG" ] || { echo "not found: $EDU_CONFIG" >&2; exit 1; }

addr_of() {
    local name="$1"
    jq -r --arg n "$name" '.contracts[] | select(.name == $n) | .address' "$ADDR_JSON"
}

vault=$(addr_of InstitutionalVault)
cluster=$(addr_of ClassroomClusterV1)
forwarder=$(addr_of Forwarder)
budget=$(addr_of BudgetAllocation)
cashout=$(addr_of CashoutRequest)
learning=$(addr_of LearningCycleManager)

for pair in "vault:$vault" "cluster:$cluster" "forwarder:$forwarder" \
            "budget:$budget" "cashout:$cashout" "learning:$learning"; do
    name="${pair%%:*}"; val="${pair#*:}"
    if [ -z "$val" ] || [ "$val" = "null" ]; then
        echo "ERROR: $name not found in $ADDR_JSON" >&2
        exit 1
    fi
    echo "  $name = $val"
done

# Use sed to replace each address. Each line uses its unique field name
# (vault:, cluster:, etc.) so we can match anchoring on the struct field.
sed -i \
    -e "s|vault: *\"0x[a-fA-F0-9]\{40\}\"|vault: \"$vault\"|" \
    -e "s|cluster: *\"0x[a-fA-F0-9]\{40\}\"|cluster: \"$cluster\"|" \
    -e "s|forwarder: *\"0x[a-fA-F0-9]\{40\}\"|forwarder: \"$forwarder\"|" \
    -e "s|budget: *\"0x[a-fA-F0-9]\{40\}\"|budget: \"$budget\"|" \
    -e "s|cashout: *\"0x[a-fA-F0-9]\{40\}\"|cashout: \"$cashout\"|" \
    -e "s|learning_cycle_manager: *\"0x[a-fA-F0-9]\{40\}\"|learning_cycle_manager: \"$learning\"|" \
    "$EDU_CONFIG"

echo "updated: $EDU_CONFIG"

# Update DEPLOYED_ADDRESSES.md header with the new snapshot timestamp.
if [ -f "$DEPLOYED_MD" ]; then
    today=$(date -u +%Y-%m-%d)
    count=$(jq -r '.contracts | length' "$ADDR_JSON")
    sed -i \
        -e "s|^- \*\*Snapshot last verified\*\*:.*|- **Snapshot last verified**: $today, post-reroll|" \
        -e "s|^- \*\*Contract count\*\*:.*|- **Contract count**: **$count** (from $(basename "$ADDR_JSON"))|" \
        "$DEPLOYED_MD"
    echo "updated: $DEPLOYED_MD header"
fi

echo
echo "next steps:"
echo "  1. cargo check -p citrate-edu-app  # verify config.rs still compiles"
echo "  2. git diff  # review the changes"
echo "  3. commit when satisfied"
