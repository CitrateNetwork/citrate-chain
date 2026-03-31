#!/usr/bin/env bash
# ============================================================
# Citrate v3 — Monitoring Stack Deployment
# WP-S.7: Deploy Prometheus + Grafana + Alertmanager
# ============================================================
#
# Usage:
#   ./scripts/deploy_monitoring.sh [local|remote user@host]
#
# Local: runs docker-compose on this machine
# Remote: copies monitoring config and starts on a remote VM
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
MONITORING_DIR="$(dirname "$SCRIPT_DIR")/citrate_v0.01.1/node/monitoring"

# If run from within citrate_v0.01.1
if [ ! -d "$MONITORING_DIR" ]; then
    MONITORING_DIR="$(dirname "$SCRIPT_DIR")/node/monitoring"
fi

MODE="${1:-local}"

echo -e "${CYAN}======================================${NC}"
echo -e "${CYAN}  Citrate Monitoring Deployment${NC}"
echo -e "${CYAN}======================================${NC}"
echo ""

if [ "$MODE" = "local" ]; then
    echo -e "${YELLOW}[1/3] Starting local monitoring stack...${NC}"

    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Docker not found. Install Docker first.${NC}"
        exit 1
    fi

    cd "$MONITORING_DIR"

    echo -e "${YELLOW}[2/3] Starting services...${NC}"
    docker compose up -d

    echo -e "${YELLOW}[3/3] Verifying...${NC}"
    sleep 3

    echo ""
    echo -e "${GREEN}Monitoring stack is running:${NC}"
    echo "  Prometheus:   http://localhost:9091"
    echo "  Grafana:      http://localhost:3000  (admin / citrate123)"
    echo "  Alertmanager: http://localhost:9093"
    echo ""
    echo -e "${CYAN}Dashboards:${NC}"
    echo "  - Testnet Overview:  citrate-testnet-overview"
    echo "  - Consensus Health:  citrate-consensus-health"
    echo "  - Network Health:    citrate-network-health"
    echo ""
    echo "To stop: cd $MONITORING_DIR && docker compose down"

else
    REMOTE_HOST="$MODE"
    REMOTE_DIR="/opt/citrate-monitoring"

    echo -e "${YELLOW}[1/4] Uploading monitoring config to $REMOTE_HOST...${NC}"
    ssh "$REMOTE_HOST" "mkdir -p $REMOTE_DIR"
    scp -r "$MONITORING_DIR/"* "$REMOTE_HOST:$REMOTE_DIR/"

    echo -e "${YELLOW}[2/4] Installing Docker if needed...${NC}"
    ssh "$REMOTE_HOST" "command -v docker || (curl -fsSL https://get.docker.com | sh)"

    echo -e "${YELLOW}[3/4] Starting monitoring stack...${NC}"
    ssh "$REMOTE_HOST" "cd $REMOTE_DIR && docker compose up -d"

    echo -e "${YELLOW}[4/4] Verifying...${NC}"
    sleep 3
    ssh "$REMOTE_HOST" "docker compose -f $REMOTE_DIR/docker-compose.yml ps"

    echo ""
    echo -e "${GREEN}Monitoring stack deployed to $REMOTE_HOST${NC}"
    echo "  Prometheus:   http://$REMOTE_HOST:9091"
    echo "  Grafana:      http://$REMOTE_HOST:3000  (admin / citrate123)"
    echo "  Alertmanager: http://$REMOTE_HOST:9093"
fi

echo ""
echo -e "${GREEN}Done.${NC}"
