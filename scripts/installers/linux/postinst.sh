#!/usr/bin/env bash
# postinst.sh — Post-installation script for Citrate (Debian/RPM)
set -euo pipefail

CITRATE_USER="citrate"
CITRATE_HOME="/var/lib/citrate"

# Create citrate system user if not exists
if ! id "$CITRATE_USER" &>/dev/null; then
    useradd --system --home-dir "$CITRATE_HOME" --create-home \
        --shell /usr/sbin/nologin "$CITRATE_USER"
    echo "Created system user: $CITRATE_USER"
fi

# Create data directories
mkdir -p "$CITRATE_HOME"/{logs,ipfs,keystore}
chown -R "$CITRATE_USER:$CITRATE_USER" "$CITRATE_HOME"
chmod 700 "$CITRATE_HOME/keystore"

# Install systemd units
if [ -d /etc/systemd/system ]; then
    cp /usr/share/citrate/citrate-node.service /etc/systemd/system/
    cp /usr/share/citrate/citrate-ipfs.service /etc/systemd/system/
    systemctl daemon-reload
    echo "systemd units installed. Enable with:"
    echo "  sudo systemctl enable --now citrate-node"
fi

# Generate keypair on first install
if [ ! -f "$CITRATE_HOME/keystore/node.key" ]; then
    if command -v citrate-node &>/dev/null; then
        su -s /bin/bash "$CITRATE_USER" -c "citrate-node keygen --output $CITRATE_HOME/keystore/node.key" 2>/dev/null || true
    fi
fi

echo ""
echo "=== Citrate Node installed ==="
echo "Data directory: $CITRATE_HOME"
echo "Start the node:  sudo systemctl start citrate-node"
echo "View logs:        journalctl -u citrate-node -f"
echo ""
