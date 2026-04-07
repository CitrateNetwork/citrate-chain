#!/usr/bin/env bash
# ============================================================================
# Citrate Ceremony Host Provisioning
# ============================================================================
#
# Prepares a fresh host (rehearsal or real) for the ceremony.
# Runs on Ubuntu 22.04 LTS — the canonical pilot OS.
#
# USAGE:
#   sudo ./provision-host.sh <role>
#
# ROLES:
#   bootnode    — public bootnode with peer discovery
#   rpc         — public RPC endpoint with TLS and rate limiting
#   deployer    — ceremony deployer host (Foundry + keystore)
#   validator   — consensus validator
#
# WHAT IT DOES:
#   1. System deps (build-essential, curl, jq, rust, foundry)
#   2. Dedicated `citrate` user and directory layout
#   3. Systemd unit (role-specific)
#   4. UFW firewall rules
#   5. Health check endpoint
#   6. Does NOT deploy contracts — that's ceremony.sh's job
#
# NON-GOALS:
#   - Does NOT start the node (operator does that after review)
#   - Does NOT import keys (operator does that via keystore_protocol.md)
#   - Does NOT touch DNS or TLS certs (separate procurement)
#
# ============================================================================
set -euo pipefail

readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
readonly ROLE="${1:-}"
readonly CITRATE_USER="citrate"
readonly CITRATE_HOME="/var/lib/citrate"
readonly CITRATE_LOG="/var/log/citrate"
readonly CITRATE_ETC="/etc/citrate"

# ---- Colors ----
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

log_step() { echo -e "\n${CYAN}[$(date -u +%H:%M:%S)]${NC} ${BOLD}$1${NC}"; }
log_ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
log_err()  { echo -e "  ${RED}✗${NC} $1" >&2; }

# ---- Preflight ----
if [ "$EUID" -ne 0 ]; then
    log_err "This script must be run as root (use sudo)"
    exit 1
fi

case "$ROLE" in
    bootnode|rpc|deployer|validator)
        ;;
    *)
        log_err "Unknown role: $ROLE"
        log_err "Usage: sudo $0 <bootnode|rpc|deployer|validator>"
        exit 1
        ;;
esac

if [ ! -f /etc/os-release ] || ! grep -q "Ubuntu" /etc/os-release; then
    log_warn "This script is designed for Ubuntu 22.04 LTS. Continuing anyway."
fi

log_step "Provisioning host as role: $ROLE"

# ---- Step 1: System dependencies ----
log_step "Step 1: Install system dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    jq \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    libfontconfig1-dev \
    ufw \
    ca-certificates
log_ok "System dependencies installed"

# ---- Step 2: Rust toolchain ----
log_step "Step 2: Install Rust toolchain (as citrate user)"
if ! id -u "$CITRATE_USER" &>/dev/null; then
    useradd --system --shell /bin/bash --home-dir "$CITRATE_HOME" --create-home "$CITRATE_USER"
    log_ok "Created system user: $CITRATE_USER"
else
    log_ok "User $CITRATE_USER already exists"
fi

if ! sudo -u "$CITRATE_USER" bash -c 'command -v cargo &>/dev/null'; then
    sudo -u "$CITRATE_USER" bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable'
    log_ok "Rust installed for $CITRATE_USER"
else
    log_ok "Rust already installed for $CITRATE_USER"
fi

# ---- Step 3: Foundry (deployer role only) ----
if [ "$ROLE" = "deployer" ]; then
    log_step "Step 3: Install Foundry (deployer host)"
    if ! sudo -u "$CITRATE_USER" bash -c 'command -v forge &>/dev/null'; then
        sudo -u "$CITRATE_USER" bash -c 'curl -L https://foundry.paradigm.xyz | bash'
        sudo -u "$CITRATE_USER" bash -c 'source ~/.bashrc && foundryup'
        log_ok "Foundry installed for $CITRATE_USER"
    else
        log_ok "Foundry already installed"
    fi
else
    log_warn "Skipping Foundry install (role: $ROLE)"
fi

# ---- Step 4: Directory layout ----
log_step "Step 4: Create directory layout"
mkdir -p "$CITRATE_HOME"/{data,keystore} "$CITRATE_LOG" "$CITRATE_ETC"
chown -R "$CITRATE_USER:$CITRATE_USER" "$CITRATE_HOME" "$CITRATE_LOG"
chmod 700 "$CITRATE_HOME/keystore"
log_ok "Directories created with correct permissions"

# ---- Step 5: Firewall (role-specific) ----
log_step "Step 5: Configure UFW firewall"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'

case "$ROLE" in
    bootnode)
        ufw allow 30303/tcp comment 'Citrate P2P'
        ufw allow 30303/udp comment 'Citrate discovery'
        log_ok "Bootnode ports opened: 30303/tcp, 30303/udp"
        ;;
    rpc)
        ufw allow 80/tcp comment 'HTTP (Caddy redirect)'
        ufw allow 443/tcp comment 'HTTPS (Caddy TLS)'
        ufw allow 8545/tcp comment 'JSON-RPC (internal; use Caddy for public)'
        ufw allow 8546/tcp comment 'WebSocket (internal)'
        log_ok "RPC ports opened: 80, 443, 8545, 8546"
        ;;
    deployer)
        log_ok "Deployer host: no incoming ports opened (outbound-only)"
        ;;
    validator)
        ufw allow 30303/tcp comment 'Citrate P2P'
        ufw allow 30303/udp comment 'Citrate discovery'
        ufw allow 9090/tcp comment 'Prometheus metrics (internal)'
        log_ok "Validator ports opened: 30303, 9090"
        ;;
esac

ufw --force enable
log_ok "UFW enabled"

# ---- Step 6: Systemd unit template ----
log_step "Step 6: Install systemd unit template for role: $ROLE"
local_unit_file="/etc/systemd/system/citrate-$ROLE.service"

cat > "$local_unit_file" <<EOF
[Unit]
Description=Citrate $ROLE
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CITRATE_USER
Group=$CITRATE_USER
WorkingDirectory=$CITRATE_HOME
ExecStart=/usr/local/bin/citrate --data-dir $CITRATE_HOME/data --config $CITRATE_ETC/$ROLE.toml
Restart=on-failure
RestartSec=5s
StandardOutput=append:$CITRATE_LOG/$ROLE.log
StandardError=append:$CITRATE_LOG/$ROLE-error.log
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CITRATE_HOME $CITRATE_LOG

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
log_ok "Systemd unit installed at $local_unit_file (not started — operator decides)"

# ---- Step 7: Placeholder config ----
log_step "Step 7: Write placeholder config"
local_config_file="$CITRATE_ETC/$ROLE.toml"
if [ ! -f "$local_config_file" ]; then
    cat > "$local_config_file" <<EOF
# Citrate $ROLE configuration
# Populated by ceremony.sh during the freeze event.
# Do NOT edit manually after the ceremony.

[node]
role = "$ROLE"
chain_id = 40204
data_dir = "$CITRATE_HOME/data"

[network]
# Bootnodes are populated post-ceremony
bootnodes = []

[rpc]
# Enabled only for rpc role
enabled = false
bind = "127.0.0.1:8545"

# ============================================================================
# Config is intentionally incomplete. Run the ceremony to fill it in.
# ============================================================================
EOF
    chown "$CITRATE_USER:$CITRATE_USER" "$local_config_file"
    log_ok "Placeholder config at $local_config_file"
else
    log_warn "Config already exists at $local_config_file — not overwriting"
fi

# ---- Done ----
echo
echo -e "${GREEN}${BOLD}Provisioning complete${NC}"
echo
echo "Host role: $ROLE"
echo "User: $CITRATE_USER"
echo "Home: $CITRATE_HOME"
echo "Logs: $CITRATE_LOG"
echo "Config: $CITRATE_ETC"
echo
echo "Next steps:"
case "$ROLE" in
    deployer)
        echo "  1. Import ceremony signing keys (see keystore_protocol.md)"
        echo "  2. Clone the citrate repo at a signed commit"
        echo "  3. Run ceremony.sh in rehearsal mode first"
        ;;
    bootnode|rpc|validator)
        echo "  1. Deploy the citrate binary to /usr/local/bin/citrate"
        echo "  2. Do NOT start the service yet — ceremony.sh populates config"
        echo "  3. Wait for ceremony output before running systemctl start"
        ;;
esac
