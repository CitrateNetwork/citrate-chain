#!/usr/bin/env bash
# ============================================================
# Citrate v3 — Bootstrap Node Deployment Script
# WP-S.5: Deploy or update a bootstrap node on a remote VM
# ============================================================
#
# Usage:
#   ./scripts/deploy_bootstrap.sh <user@host> [node-index]
#
# Prerequisites (on the remote VM):
#   - Ubuntu 22.04+ / Debian 12+
#   - SSH key access
#   - Ports open: 30303 (P2P), 9090 (metrics)
#   - RPC (8545/8546) bound to loopback — expose via nginx/ngrok
#
# Examples:
#   ./scripts/deploy_bootstrap.sh root@boot1.testnet.citrate.network 1
#   ./scripts/deploy_bootstrap.sh root@boot2.testnet.citrate.network 2
#   ./scripts/deploy_bootstrap.sh root@boot3.testnet.citrate.network 3
#
set -euo pipefail

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_ROOT/target/release/citrate"
CONFIG="$PROJECT_ROOT/node/config/testnet-bootstrap.toml"
SERVICE_NAME="citrate-bootstrap"
REMOTE_BIN="/usr/local/bin/citrate"
REMOTE_CONFIG="/etc/citrate/testnet-bootstrap.toml"
REMOTE_DATA="/var/lib/citrate-testnet"

# ---- Argument parsing ----
if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: $0 <user@host> [node-index]${NC}"
    echo "  node-index: 1, 2, or 3 (default: 1)"
    exit 1
fi

REMOTE_HOST="$1"
NODE_INDEX="${2:-1}"

echo -e "${CYAN}======================================${NC}"
echo -e "${CYAN}  Citrate Bootstrap Node Deployment${NC}"
echo -e "${CYAN}======================================${NC}"
echo ""
echo -e "  Remote:      ${GREEN}$REMOTE_HOST${NC}"
echo -e "  Node index:  ${GREEN}$NODE_INDEX${NC}"
echo ""

# ---- Step 1: Check local binary ----
if [ ! -f "$BINARY" ]; then
    echo -e "${YELLOW}[1/6] Building release binary...${NC}"
    cd "$PROJECT_ROOT"
    cargo build --release -p citrate-node
else
    echo -e "${GREEN}[1/6] Release binary found: $BINARY${NC}"
fi

# ---- Step 2: Upload binary ----
echo -e "${YELLOW}[2/6] Uploading binary to $REMOTE_HOST...${NC}"
scp "$BINARY" "$REMOTE_HOST:/tmp/citrate"
ssh "$REMOTE_HOST" "sudo mv /tmp/citrate $REMOTE_BIN && sudo chmod +x $REMOTE_BIN"

# ---- Step 3: Upload config ----
echo -e "${YELLOW}[3/6] Uploading config...${NC}"
ssh "$REMOTE_HOST" "sudo mkdir -p /etc/citrate && sudo mkdir -p $REMOTE_DATA"
scp "$CONFIG" "$REMOTE_HOST:/tmp/testnet-bootstrap.toml"
ssh "$REMOTE_HOST" "sudo mv /tmp/testnet-bootstrap.toml $REMOTE_CONFIG"

# ---- Step 4: Create systemd service ----
echo -e "${YELLOW}[4/6] Installing systemd service...${NC}"
ssh "$REMOTE_HOST" "sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null" << 'UNIT'
[Unit]
Description=Citrate v3 Testnet Bootstrap Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/citrate --config /etc/citrate/testnet-bootstrap.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Hardening
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

# Environment
Environment=RUST_LOG=info,citrate_network=debug
Environment=CITRATE_METRICS_ADDR=0.0.0.0:9090

[Install]
WantedBy=multi-user.target
UNIT

ssh "$REMOTE_HOST" "sudo systemctl daemon-reload"

# ---- Step 5: Enable and start ----
echo -e "${YELLOW}[5/6] Starting service...${NC}"
ssh "$REMOTE_HOST" "sudo systemctl enable ${SERVICE_NAME} && sudo systemctl restart ${SERVICE_NAME}"

# ---- Step 6: Verify ----
echo -e "${YELLOW}[6/6] Verifying...${NC}"
sleep 2
ssh "$REMOTE_HOST" "sudo systemctl is-active ${SERVICE_NAME}" && \
    echo -e "${GREEN}Bootstrap node $NODE_INDEX is RUNNING on $REMOTE_HOST${NC}" || \
    echo -e "${RED}Bootstrap node failed to start. Check: ssh $REMOTE_HOST journalctl -u ${SERVICE_NAME} -n 50${NC}"

echo ""
echo -e "${CYAN}--- Post-deployment steps ---${NC}"
echo "1. Check logs:     ssh $REMOTE_HOST journalctl -u ${SERVICE_NAME} -f"
echo "2. Get peer ID:    ssh $REMOTE_HOST journalctl -u ${SERVICE_NAME} | grep 'Peer ID'"
echo "3. Health check:   ./scripts/health_check_bootstrap.sh $REMOTE_HOST"
echo "4. Metrics:        curl http://$REMOTE_HOST:9090/metrics"
echo ""
echo -e "${GREEN}Done.${NC}"
