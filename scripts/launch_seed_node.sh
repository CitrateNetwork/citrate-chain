#!/bin/bash

# Launch a single seed node for the Citrate testnet beta.
# Designed for VPS deployment. Reads configuration from environment.
#
# Required env vars:
#   CITRATE_COINBASE     - Validator address (hex, no 0x prefix)
#
# Optional env vars:
#   CITRATE_CONFIG       - Path to TOML config file (default: node/config/testnet-beta.toml)
#   CITRATE_API_KEY      - RPC API key for authentication
#   CITRATE_DATA_DIR     - Data directory (default: .citrate-testnet-beta)
#   CITRATE_P2P_ADDR     - P2P listen address (default: 0.0.0.0:30303)
#   CITRATE_RPC_ADDR     - RPC listen address (default: 0.0.0.0:8545)
#   CITRATE_BOOTSTRAP    - Comma-separated bootstrap nodes (peer_id@ip:port)

set -e

# Defaults
DATA_DIR="${CITRATE_DATA_DIR:-.citrate-testnet-beta}"
P2P_ADDR="${CITRATE_P2P_ADDR:-0.0.0.0:30303}"
RPC_ADDR="${CITRATE_RPC_ADDR:-0.0.0.0:8545}"
CONFIG_FILE="${CITRATE_CONFIG:-node/config/testnet-beta.toml}"
COINBASE="${CITRATE_COINBASE:-}"

if [ -z "$COINBASE" ]; then
    echo "ERROR: CITRATE_COINBASE must be set (hex address, no 0x prefix)"
    echo "  Example: export CITRATE_COINBASE=f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    exit 1
fi

# Ensure data dir exists
mkdir -p "$DATA_DIR"

# Check binary
CITRATE_BIN="${CITRATE_BIN:-./target/release/citrate}"
if [ ! -f "$CITRATE_BIN" ]; then
    echo "Building citrate..."
    cargo build --release --bin citrate
fi

# Show Noise identity (will be generated on first run if not present)
NOISE_KEY_PATH="$DATA_DIR/noise.key"
if [ -f "$NOISE_KEY_PATH" ]; then
    echo "Noise key found at $NOISE_KEY_PATH"
    echo "Share the Noise public key with the network operator for whitelist enrollment."
else
    echo "Noise key will be generated on first start."
    echo "After startup, share the Noise public key from the logs for whitelist enrollment."
fi

# Build CLI args
ARGS=(
    --config "$CONFIG_FILE"
    --data-dir "$DATA_DIR"
    --p2p-addr "$P2P_ADDR"
    --rpc-addr "$RPC_ADDR"
    --coinbase "$COINBASE"
    --mine
)

# Add API key if set
if [ -n "$CITRATE_API_KEY" ]; then
    ARGS+=(--api-key "$CITRATE_API_KEY")
    echo "API key authentication enabled"
fi

# Add bootstrap nodes if set
if [ -n "$CITRATE_BOOTSTRAP" ]; then
    IFS=',' read -ra BOOTS <<< "$CITRATE_BOOTSTRAP"
    for boot in "${BOOTS[@]}"; do
        ARGS+=(--bootstrap-nodes "$boot")
    done
fi

# If running as first seed, add --bootstrap flag
if [ "${CITRATE_IS_SEED:-}" = "true" ] || [ "${CITRATE_IS_SEED:-}" = "1" ]; then
    ARGS+=(--bootstrap)
    echo "Running as seed node (no outbound bootstrap connections)"
fi

echo ""
echo "Starting Citrate seed node:"
echo "  Config:    $CONFIG_FILE"
echo "  Data dir:  $DATA_DIR"
echo "  P2P:       $P2P_ADDR"
echo "  RPC:       $RPC_ADDR"
echo "  Coinbase:  $COINBASE"
echo ""

exec "$CITRATE_BIN" "${ARGS[@]}"
