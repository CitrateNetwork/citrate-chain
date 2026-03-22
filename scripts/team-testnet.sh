#!/usr/bin/env bash
set -euo pipefail

# Start a Citrate node configured for the team testnet.
#
# Usage:
#   ./scripts/team-testnet.sh                          # Build release + run
#   ./scripts/team-testnet.sh --no-build               # Skip cargo build
#   ./scripts/team-testnet.sh --bootstrap 100.64.1.2   # Add a bootstrap peer
#   ./scripts/team-testnet.sh --data-dir /tmp/team      # Override data directory
#
# Extra flags after "--" are forwarded to the citrate binary:
#   ./scripts/team-testnet.sh -- --mine --max-peers 30

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$PROJECT_ROOT/node/config/team-testnet.toml"
BINARY="$PROJECT_ROOT/target/release/citrate"

SKIP_BUILD=false
BOOTSTRAP_PEERS=()
EXTRA_ARGS=()

# Parse script-specific arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)
            SKIP_BUILD=true
            shift
            ;;
        --bootstrap)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --bootstrap requires an IP address argument" >&2
                exit 1
            fi
            BOOTSTRAP_PEERS+=("$2:30303")
            shift 2
            ;;
        --)
            shift
            EXTRA_ARGS+=("$@")
            break
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# Build release binary if needed
if [[ "$SKIP_BUILD" == false ]]; then
    echo "==> Building citrate (release)..."
    cd "$PROJECT_ROOT"
    cargo build --release -p citrate-node 2>&1 | tail -5
    echo "    Build complete."
fi

if [[ ! -x "$BINARY" ]]; then
    echo "Error: Binary not found at $BINARY" >&2
    echo "Run without --no-build to compile first." >&2
    exit 1
fi

# Build bootstrap node arguments
BOOTSTRAP_ARGS=()
for peer in "${BOOTSTRAP_PEERS[@]}"; do
    BOOTSTRAP_ARGS+=(--bootstrap-nodes "$peer")
done

echo "==> Starting Citrate team testnet node"
echo "    Config:    $CONFIG_FILE"
echo "    Binary:    $BINARY"
echo "    RPC:       http://0.0.0.0:8545"
echo "    P2P:       0.0.0.0:30303"
if [[ ${#BOOTSTRAP_PEERS[@]} -gt 0 ]]; then
    echo "    Bootstrap: ${BOOTSTRAP_PEERS[*]}"
else
    echo "    Bootstrap: (none — this node starts solo or uses TOML config)"
fi
echo ""

exec "$BINARY" \
    --config "$CONFIG_FILE" \
    ${BOOTSTRAP_ARGS[@]+"${BOOTSTRAP_ARGS[@]}"} \
    ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
