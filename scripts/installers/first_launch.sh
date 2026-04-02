#!/usr/bin/env bash
# first_launch.sh — Common first-launch initialization for all platforms
# Called on first app startup or bootstrap to prepare directories, modern config
# profiles, and optional IPFS state.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CITRATE_DATA_DIR="${CITRATE_DATA_DIR:-$HOME/.citrate}"
CONFIG_DIR="$CITRATE_DATA_DIR/configs"

echo "=== Citrate First Launch Setup ==="
echo "Data directory: $CITRATE_DATA_DIR"

rewrite_storage_dir() {
    local template="$1"
    local target="$2"
    local data_dir="$3"

    awk -v data_dir="$data_dir" '
        /^data_dir = / {
            print "data_dir = \"" data_dir "\""
            next
        }
        { print }
    ' "$template" > "$target"
}

# Step 1: Create directory structure
echo "[1/4] Creating directory structure..."
mkdir -p "$CITRATE_DATA_DIR"/{logs,keystore,ipfs,models,graphs,devnet,testnet-beta}
mkdir -p "$CONFIG_DIR"
echo "  Created: logs, keystore, ipfs, models, graphs, configs"

# Step 2: Prepare modern config profiles
echo "[2/4] Writing current config profiles..."
DEVNET_TEMPLATE="$PROJECT_ROOT/node/config/devnet.toml"
TESTNET_TEMPLATE="$PROJECT_ROOT/node/config/testnet-beta.toml"
DEVNET_CONFIG="$CONFIG_DIR/devnet.toml"
TESTNET_CONFIG="$CONFIG_DIR/testnet-beta.toml"

if [ -f "$DEVNET_TEMPLATE" ]; then
    rewrite_storage_dir "$DEVNET_TEMPLATE" "$DEVNET_CONFIG" "$CITRATE_DATA_DIR/devnet"
    echo "  Wrote: $DEVNET_CONFIG"
else
    echo "  WARNING: Missing template $DEVNET_TEMPLATE"
fi

if [ -f "$TESTNET_TEMPLATE" ]; then
    rewrite_storage_dir "$TESTNET_TEMPLATE" "$TESTNET_CONFIG" "$CITRATE_DATA_DIR/testnet-beta"
    echo "  Wrote: $TESTNET_CONFIG"
else
    echo "  WARNING: Missing template $TESTNET_TEMPLATE"
fi

# Step 3: Initialize IPFS repo
if [ ! -d "$CITRATE_DATA_DIR/ipfs/config" ] && [ ! -f "$CITRATE_DATA_DIR/ipfs/config" ]; then
    echo "[3/4] Initializing IPFS repository..."
    if command -v ipfs &>/dev/null; then
        IPFS_PATH="$CITRATE_DATA_DIR/ipfs" ipfs init --profile server 2>/dev/null || {
            echo "  WARNING: IPFS initialization failed. Will retry on first use."
        }
    else
        echo "  Skipping IPFS init (ipfs not in PATH). Install: https://docs.ipfs.tech/install/"
    fi
else
    echo "[3/4] IPFS repo already exists, skipping."
fi

# Step 4: Print binary status and next steps
echo "[4/4] Checking local binary availability..."
if command -v citrate &>/dev/null; then
    echo "  Found citrate in PATH: $(command -v citrate)"
else
    echo "  Citrate binary not found in PATH yet. Build with:"
    echo "    cargo build --release -p citrate-node -p citrate-cli -p citrate-faucet"
fi

echo ""
echo "=== First launch setup complete ==="
echo "Suggested start commands:"
echo "  citrate --config $DEVNET_CONFIG"
echo "  citrate --config $TESTNET_CONFIG"
