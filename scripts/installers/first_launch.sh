#!/usr/bin/env bash
# first_launch.sh — Common first-launch initialization for all platforms
# Called on first app startup to set up data directory, keypair, and IPFS
set -euo pipefail

CITRATE_DATA_DIR="${CITRATE_DATA_DIR:-$HOME/.citrate}"

echo "=== Citrate First Launch Setup ==="
echo "Data directory: $CITRATE_DATA_DIR"

# Step 1: Create directory structure
echo "[1/4] Creating directory structure..."
mkdir -p "$CITRATE_DATA_DIR"/{logs,keystore,ipfs,models,graphs}
echo "  Created: logs, keystore, ipfs, models, graphs"

# Step 2: Generate node keypair (ed25519)
if [ ! -f "$CITRATE_DATA_DIR/keystore/node.key" ]; then
    echo "[2/4] Generating node keypair..."
    if command -v citrate-node &>/dev/null; then
        citrate-node keygen --output "$CITRATE_DATA_DIR/keystore/node.key" 2>/dev/null || {
            # Fallback: generate with openssl
            openssl genpkey -algorithm ed25519 -out "$CITRATE_DATA_DIR/keystore/node.key" 2>/dev/null || {
                echo "  WARNING: Could not generate keypair. Will be created on first node start."
            }
        }
    else
        echo "  Skipping keypair generation (citrate-node not in PATH)"
    fi
    chmod 600 "$CITRATE_DATA_DIR/keystore/node.key" 2>/dev/null || true
else
    echo "[2/4] Keypair already exists, skipping."
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

# Step 4: Create default config
CONFIG_FILE="$CITRATE_DATA_DIR/config.toml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[4/4] Writing default configuration..."
    cat > "$CONFIG_FILE" <<'TOML'
# Citrate Node Configuration (auto-generated)
[network]
mode = "devnet"
chain_id = 40204
rpc_port = 8545
ws_port = 8546
p2p_port = 30303

[consensus]
algorithm = "ghostdag"
k_parameter = 18
max_parents = 10

[storage]
data_dir = "~/.citrate"
pruning_enabled = false

[metrics]
enabled = true
address = "127.0.0.1:9090"
TOML
    echo "  Config written to $CONFIG_FILE"
else
    echo "[4/4] Config already exists, skipping."
fi

echo ""
echo "=== First launch setup complete ==="
echo "Start the node: citrate-node devnet --data-dir $CITRATE_DATA_DIR"
