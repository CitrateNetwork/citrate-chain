#!/usr/bin/env bash
# prerm.sh — Pre-removal script for Citrate
set -euo pipefail

# Stop services before removal
if systemctl is-active --quiet citrate-node 2>/dev/null; then
    systemctl stop citrate-node
    echo "Stopped citrate-node service"
fi

if systemctl is-active --quiet citrate-ipfs 2>/dev/null; then
    systemctl stop citrate-ipfs
    echo "Stopped citrate-ipfs service"
fi

# Disable services
systemctl disable citrate-node 2>/dev/null || true
systemctl disable citrate-ipfs 2>/dev/null || true

echo "Citrate services stopped and disabled."
echo "Data directory preserved at /var/lib/citrate"
