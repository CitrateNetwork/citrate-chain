#!/usr/bin/env bash
# ============================================================
# Citrate Testnet — Single-Command VPS Deployment
# ============================================================
#
# Deploys a fully-operational Citrate testnet node on a fresh
# Ubuntu 22.04+ server with TLS-terminated RPC via Caddy.
#
# Usage:
#   sudo ./deploy_testnet.sh <domain> --version <tag> --coinbase <0x-address>
#   sudo ./deploy_testnet.sh testnet.citrate.ai --version v0.5.0-beta1 --coinbase 0xYourAddress
#   sudo ./deploy_testnet.sh testnet.citrate.ai --version v0.5.0-beta1 --coinbase 0x... --build-from-source
#   sudo ./deploy_testnet.sh testnet.citrate.ai --version v0.5.0-beta1 --coinbase 0x... --skip-tls
#
# Supply chain (PBA-L6-001): binaries come only from
# github.com/CitrateNetwork/citrate-chain releases at the explicit --version,
# and are installed only after the SHA-256 checksum AND the cosign keyless
# signature (issued to CitrateNetwork/citrate-chain release workflows) verify.
# Any verification failure aborts; there is no fallback. Requires `cosign`.
#
# Prerequisites:
#   - Ubuntu 22.04+ (Debian 12+ also works)
#   - Root or sudo access
#   - Domain A-record pointed to this server's public IP
#   - Ports 80, 443, 8545, 30303 reachable from the internet
#
# What it does:
#   1. Installs system dependencies
#   2. Installs Rust toolchain + builds node OR downloads pre-built binary
#   3. Creates a citrate system user and data directories
#   4. Writes testnet.toml with funded genesis coinbase
#   5. Installs a systemd service (citrate-testnet.service)
#   6. Installs Caddy reverse proxy with automatic TLS
#   7. Configures UFW firewall
#   8. Starts everything and runs a health check
#
set -euo pipefail

# ---- Constants ----
CHAIN_ID=40204
CHAIN_ID_HEX="0x$(printf '%x' $CHAIN_ID)"
SERVICE_NAME="citrate-testnet"
CITRATE_USER="citrate"
DATA_DIR="/var/lib/citrate-testnet"
CONFIG_DIR="/etc/citrate"
CONFIG_FILE="$CONFIG_DIR/testnet.toml"
LOG_DIR="/var/log/citrate"
BIN_PATH="/usr/local/bin/citrate"
RELEASE_REPO="CitrateNetwork/citrate-chain"
COSIGN_IDENTITY_RE='^https://github\.com/CitrateNetwork/citrate-chain/\.github/workflows/(release|release-tier2)\.yml@refs/(heads/main|tags/v[0-9A-Za-z._-]+)$'
RPC_PORT=8545
WS_PORT=8546
P2P_PORT=30303
METRICS_PORT=9090

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---- Helpers ----
log_step()    { echo -e "\n${CYAN}[$(date +%H:%M:%S)]${NC} ${BOLD}$1${NC}"; }
log_ok()      { echo -e "  ${GREEN}OK${NC} $1"; }
log_warn()    { echo -e "  ${YELLOW}WARN${NC} $1"; }
log_err()     { echo -e "  ${RED}ERROR${NC} $1"; }
log_info()    { echo -e "  $1"; }

bail() { log_err "$1"; exit 1; }

# ---- Argument parsing ----
DOMAIN=""
VERSION=""
COINBASE=""
BUILD_FROM_SOURCE=false
SKIP_TLS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-from-source) BUILD_FROM_SOURCE=true; shift ;;
        --skip-tls)          SKIP_TLS=true; shift ;;
        --version)           VERSION="${2:-}"; shift 2 || bail "--version needs a value" ;;
        --coinbase)          COINBASE="${2:-}"; shift 2 || bail "--coinbase needs a value" ;;
        --help|-h)
            echo "Usage: sudo $0 <domain> --version <tag> --coinbase <0x-address> [--build-from-source] [--skip-tls]"
            echo ""
            echo "  <domain>              FQDN for TLS (e.g., testnet.citrate.ai)"
            echo "  --version <tag>       citrate-chain release tag to install (required; never 'latest')"
            echo "  --coinbase <address>  20-byte 0x address you control, for block rewards (required)"
            echo "  --build-from-source   Clone $RELEASE_REPO at --version and compile instead of downloading"
            echo "  --skip-tls            Skip Caddy/TLS setup (RPC on plain HTTP only)"
            echo ""
            exit 0
            ;;
        -*)
            bail "Unknown flag: $1  (try --help)"
            ;;
        *)
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$1"
            else
                bail "Unexpected argument: $1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    bail "Domain is required.  Usage: sudo $0 <domain> --version <tag> --coinbase <0x-address>"
fi
if [[ -z "$VERSION" ]]; then
    bail "--version <tag> is required (e.g. --version v0.5.0-beta1). Unpinned installs are not supported."
fi
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
    bail "--version must be a release tag like v0.5.0-beta1 (got '$VERSION')"
fi
if [[ -z "$COINBASE" ]]; then
    bail "--coinbase <0x-address> is required: rewards go to an address whose key you hold."
fi
if [[ ! "$COINBASE" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    bail "--coinbase must be a 0x-prefixed 20-byte address (got '$COINBASE')"
fi

# ---- Pre-flight checks ----
if [[ $EUID -ne 0 ]]; then
    bail "This script must be run as root (use sudo)."
fi

if ! grep -qiE 'ubuntu|debian' /etc/os-release 2>/dev/null; then
    log_warn "This script is tested on Ubuntu 22.04+ / Debian 12+. Proceeding anyway."
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Citrate Testnet Deployment${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "  Domain:       ${GREEN}$DOMAIN${NC}"
echo -e "  Chain ID:     ${GREEN}$CHAIN_ID ($CHAIN_ID_HEX)${NC}"
echo -e "  Build mode:   ${GREEN}$(if $BUILD_FROM_SOURCE; then echo "from source"; else echo "pre-built binary"; fi)${NC}"
echo -e "  TLS:          ${GREEN}$(if $SKIP_TLS; then echo "disabled"; else echo "Caddy auto-TLS"; fi)${NC}"
echo -e "  Data dir:     ${GREEN}$DATA_DIR${NC}"
echo ""

# ---- Step 1: System dependencies ----
log_step "[1/9] Installing system dependencies..."

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    build-essential \
    clang \
    llvm-dev \
    libclang-dev \
    pkg-config \
    cmake \
    curl \
    wget \
    git \
    zlib1g-dev \
    libssl-dev \
    jq \
    ufw \
    > /dev/null 2>&1

log_ok "System packages installed."

# ---- Step 2: Install or build the Citrate binary ----
log_step "[2/9] Installing Citrate node binary..."

if $BUILD_FROM_SOURCE; then
    # Install Rust if not present
    if ! command -v rustc &>/dev/null; then
        log_info "Installing Rust toolchain..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        source "$HOME/.cargo/env"
    fi

    RUST_VERSION=$(rustc --version)
    log_ok "Rust: $RUST_VERSION"

    # Clone the canonical repo at the pinned release tag (release tags are
    # protected by the protect-release-tags ruleset).
    BUILD_DIR="$(mktemp -d /tmp/citrate-build.XXXXXX)"
    log_info "Cloning $RELEASE_REPO at $VERSION..."
    git clone --depth 1 --branch "$VERSION" "https://github.com/$RELEASE_REPO.git" "$BUILD_DIR"

    log_info "Building release binary (this takes 5-15 minutes)..."
    (cd "$BUILD_DIR" && cargo build --release --locked -p citrate-node)

    install -m 0755 "$BUILD_DIR/target/release/citrate" "$BIN_PATH"
    rm -rf "$BUILD_DIR"
else
    # Download the pinned release asset and verify it before installing.
    # No fallback: any failure below aborts the deploy.
    command -v cosign &>/dev/null \
        || bail "cosign is required to verify the release signature. Install it (https://docs.sigstore.dev/cosign/system_config/installation/) or use --build-from-source."

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  TRIPLE="x86_64-unknown-linux-gnu" ;;
        aarch64) TRIPLE="aarch64-unknown-linux-gnu" ;;
        *)       bail "Unsupported architecture: $ARCH" ;;
    esac

    ASSET="citrate-chain-${TRIPLE}.tar.gz"
    BASE_URL="https://github.com/$RELEASE_REPO/releases/download/$VERSION"
    DL_DIR="$(mktemp -d /tmp/citrate-dl.XXXXXX)"
    log_info "Downloading $ASSET ($VERSION) from $RELEASE_REPO..."
    for f in "$ASSET" "$ASSET.sha256" "$ASSET.sig" "$ASSET.pem"; do
        curl --proto '=https' --tlsv1.2 -fsSL -o "$DL_DIR/$f" "$BASE_URL/$f" \
            || bail "Download failed: $BASE_URL/$f (does release $VERSION exist?)"
    done

    log_info "Verifying SHA-256 checksum..."
    (cd "$DL_DIR" && sha256sum -c "$ASSET.sha256") \
        || bail "Checksum verification FAILED for $ASSET. Not installing."

    log_info "Verifying cosign signature (issuer + CitrateNetwork workflow identity)..."
    cosign verify-blob "$DL_DIR/$ASSET" \
        --signature "$DL_DIR/$ASSET.sig" \
        --certificate "$DL_DIR/$ASSET.pem" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
        || bail "Signature verification FAILED for $ASSET. Not installing."
    log_ok "Checksum and signature verified."

    tar -xzf "$DL_DIR/$ASSET" -C "$DL_DIR"
    install -m 0755 "$DL_DIR/citrate-chain-${TRIPLE}/citrate-node" "$BIN_PATH"
    rm -rf "$DL_DIR"
    log_ok "Binary installed to $BIN_PATH"
fi

if [[ ! -x "$BIN_PATH" ]]; then
    bail "Binary not found at $BIN_PATH after installation."
fi
log_ok "Citrate binary ready at $BIN_PATH"

# ---- Step 3: Create system user and directories ----
log_step "[3/9] Creating citrate user and directories..."

if ! id "$CITRATE_USER" &>/dev/null; then
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$CITRATE_USER"
    log_ok "Created system user: $CITRATE_USER"
else
    log_ok "User $CITRATE_USER already exists."
fi

mkdir -p "$DATA_DIR" "$CONFIG_DIR" "$LOG_DIR"
chown -R "$CITRATE_USER:$CITRATE_USER" "$DATA_DIR" "$LOG_DIR"

log_ok "Directories created."

# ---- Step 4: Generate coinbase address and write config ----
log_step "[4/9] Writing testnet configuration..."

# Coinbase comes from the operator (--coinbase, validated above) so block
# rewards land at an address whose key the operator holds. Config format is
# the 20-byte address without 0x, right-padded to 32 bytes.
COINBASE_HEX=$(echo "${COINBASE#0x}" | tr 'A-F' 'a-f')
COINBASE_ADDR="${COINBASE_HEX}000000000000000000000000"

cat > "$CONFIG_FILE" << TOML
# Citrate Testnet Configuration
# Auto-generated by deploy_testnet.sh on $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# Domain: $DOMAIN

[chain]
chain_id = $CHAIN_ID
genesis_hash = ""
block_time = 1
ghostdag_k = 18

[network]
listen_addr = "0.0.0.0:$P2P_PORT"
bootstrap_nodes = [
    # This bootnode does not bootstrap from itself; partners point HERE.
    # Canonical partner multiaddr (mirrored in node/config/testnet.toml):
    #   noise_24402d5e3009b8004bef53a7a29c4b34138afe4d59cb52e1ba353bb08108eb2e@159.65.227.42:30303
    # Pubkey derived from /var/lib/citrate/noise.key on droplet 560906847 (nyc1).
    # Track-DISCOVERY will replace static IP with HTTPS-fetched seed list.
]
max_peers = 50

[rpc]
enabled = true
listen_addr = "0.0.0.0:$RPC_PORT"
ws_addr = "0.0.0.0:$WS_PORT"
cors_origins = ["https://$DOMAIN", "http://localhost:*"]

[storage]
data_dir = "$DATA_DIR"
pruning = false
keep_blocks = 100000

[mining]
enabled = true
coinbase = "$COINBASE_ADDR"
target_block_time = 1
min_gas_price = 1000000000

[vrf]
strict_vrf = false
migration_mode = true

[checkpoint]
interval = 50
committee_size = 100
quorum_threshold = 67
TOML

chown "$CITRATE_USER:$CITRATE_USER" "$CONFIG_FILE"
log_ok "Config written to $CONFIG_FILE"
log_info "Coinbase: 0x${COINBASE_ADDR:0:40}"

# ---- Step 5: Create systemd service ----
log_step "[5/9] Installing systemd service..."

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << UNIT
[Unit]
Description=Citrate Testnet Node ($DOMAIN)
Documentation=https://docs.citrate.ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CITRATE_USER
Group=$CITRATE_USER

ExecStart=$BIN_PATH \\
    --config $CONFIG_FILE \\
    --data-dir $DATA_DIR \\
    --mine

Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# Environment
Environment=RUST_LOG=info,citrate_api=debug,citrate_network=info
Environment=CITRATE_METRICS_ADDR=127.0.0.1:$METRICS_PORT
Environment=CITRATE_REQUIRE_VALID_SIGNATURE=0

# Hardening
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
log_ok "Systemd service installed and enabled."

# ---- Step 6: Configure firewall ----
log_step "[6/9] Configuring firewall (UFW)..."

# Ensure SSH is allowed before enabling UFW (safety)
ufw allow OpenSSH > /dev/null 2>&1 || ufw allow 22/tcp > /dev/null 2>&1

# Application ports
ufw allow "$P2P_PORT/tcp" comment "Citrate P2P" > /dev/null 2>&1

if $SKIP_TLS; then
    ufw allow "$RPC_PORT/tcp" comment "Citrate RPC (no TLS)" > /dev/null 2>&1
else
    ufw allow 80/tcp  comment "HTTP (Caddy ACME)" > /dev/null 2>&1
    ufw allow 443/tcp comment "HTTPS (Caddy TLS)" > /dev/null 2>&1
fi

# Enable UFW non-interactively if not already active
if ! ufw status | grep -q "Status: active"; then
    echo "y" | ufw enable > /dev/null 2>&1
fi

log_ok "Firewall configured."
ufw status numbered 2>/dev/null | head -20

# ---- Step 7: Install and configure Caddy (TLS reverse proxy) ----
if ! $SKIP_TLS; then
    log_step "[7/9] Installing Caddy reverse proxy with auto-TLS..."

    # Install Caddy via official apt repo
    if ! command -v caddy &>/dev/null; then
        apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https > /dev/null 2>&1
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
            gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
            tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
        apt-get update -qq > /dev/null 2>&1
        apt-get install -y -qq caddy > /dev/null 2>&1
    fi

    # Write Caddyfile
    cat > /etc/caddy/Caddyfile << CADDY
# Citrate Testnet RPC — auto-managed TLS via Let's Encrypt
$DOMAIN {
    # JSON-RPC endpoint
    reverse_proxy /ws localhost:$WS_PORT {
        # WebSocket upgrade for subscriptions
    }

    reverse_proxy localhost:$RPC_PORT {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
    }

    # Rate limiting: 100 requests per second per IP
    # (Caddy Enterprise feature; community edition relies on upstream rate limiting)

    # CORS headers
    header {
        Access-Control-Allow-Origin  "*"
        Access-Control-Allow-Methods "POST, GET, OPTIONS"
        Access-Control-Allow-Headers "Content-Type"
    }

    # Health endpoint passthrough
    handle /health {
        reverse_proxy localhost:$METRICS_PORT
    }

    log {
        output file /var/log/caddy/citrate-access.log {
            roll_size 50MiB
            roll_keep 5
        }
    }
}
CADDY

    mkdir -p /var/log/caddy

    systemctl enable caddy --quiet
    systemctl restart caddy
    log_ok "Caddy installed and configured for $DOMAIN"
else
    log_step "[7/9] Skipping TLS setup (--skip-tls)."
    log_warn "RPC is accessible on plain HTTP at port $RPC_PORT."
fi

# ---- Step 8: Start the node ----
log_step "[8/9] Starting Citrate testnet node..."

systemctl start "$SERVICE_NAME"
sleep 3

# Check if the service is running
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_ok "Service $SERVICE_NAME is running."
else
    log_err "Service failed to start. Dumping last 30 log lines:"
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager
    bail "Fix the issue above and run: sudo systemctl restart $SERVICE_NAME"
fi

# ---- Step 9: Health check ----
log_step "[9/9] Running health check..."

MAX_RETRIES=10
RETRY_DELAY=3

for i in $(seq 1 $MAX_RETRIES); do
    RESPONSE=$(curl -s -m 5 -X POST "http://127.0.0.1:$RPC_PORT" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || true)

    if echo "$RESPONSE" | jq -e '.result' &>/dev/null; then
        BLOCK_HEX=$(echo "$RESPONSE" | jq -r '.result')
        BLOCK_DEC=$((BLOCK_HEX))
        log_ok "RPC responding. Current block: $BLOCK_DEC ($BLOCK_HEX)"
        break
    fi

    if [[ $i -eq $MAX_RETRIES ]]; then
        log_warn "RPC not responding yet after ${MAX_RETRIES} attempts."
        log_info "The node may still be initializing. Check: journalctl -u $SERVICE_NAME -f"
    else
        log_info "Waiting for RPC... (attempt $i/$MAX_RETRIES)"
        sleep "$RETRY_DELAY"
    fi
done

# Verify chain ID
CHAIN_RESPONSE=$(curl -s -m 5 -X POST "http://127.0.0.1:$RPC_PORT" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' 2>/dev/null || true)

if echo "$CHAIN_RESPONSE" | jq -e '.result' &>/dev/null; then
    REPORTED_CHAIN=$(echo "$CHAIN_RESPONSE" | jq -r '.result')
    log_ok "Chain ID: $REPORTED_CHAIN (expected: $CHAIN_ID_HEX)"
fi

# ---- Done ----
PUBLIC_IP=$(curl -s -m 5 ifconfig.me 2>/dev/null || curl -s -m 5 icanhazip.com 2>/dev/null || echo "<server-ip>")

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Deployment Complete${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

if $SKIP_TLS; then
    RPC_URL="http://${PUBLIC_IP}:${RPC_PORT}"
    WS_URL="ws://${PUBLIC_IP}:${WS_PORT}"
else
    RPC_URL="https://${DOMAIN}"
    WS_URL="wss://${DOMAIN}/ws"
fi

echo -e "  ${BOLD}RPC endpoint:${NC}    ${GREEN}$RPC_URL${NC}"
echo -e "  ${BOLD}WebSocket:${NC}       ${GREEN}$WS_URL${NC}"
echo -e "  ${BOLD}P2P address:${NC}     ${GREEN}${PUBLIC_IP}:${P2P_PORT}${NC}"
echo -e "  ${BOLD}Chain ID:${NC}        ${GREEN}$CHAIN_ID ($CHAIN_ID_HEX)${NC}"
echo -e "  ${BOLD}Coinbase:${NC}        ${GREEN}0x${COINBASE_ADDR:0:40}${NC}"
echo ""
echo -e "${BOLD}--- Quick verification ---${NC}"
echo ""
echo "  # Check block height"
echo "  curl -s -X POST $RPC_URL \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}'"
echo ""
echo "  # Check chain ID"
echo "  curl -s -X POST $RPC_URL \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}'"
echo ""
echo -e "${BOLD}--- MetaMask / SDK configuration ---${NC}"
echo ""
echo "  Network Name:   Citrate Testnet"
echo "  RPC URL:        $RPC_URL"
echo "  Chain ID:       $CHAIN_ID"
echo "  Currency:       CIT"
echo "  Symbol:         CIT"
echo "  Block Explorer: (none yet)"
echo ""
echo -e "${BOLD}--- Management commands ---${NC}"
echo ""
echo "  sudo systemctl status  $SERVICE_NAME   # Check status"
echo "  sudo systemctl restart $SERVICE_NAME   # Restart node"
echo "  sudo systemctl stop    $SERVICE_NAME   # Stop node"
echo "  sudo journalctl -u $SERVICE_NAME -f    # Follow logs"
echo "  sudo journalctl -u $SERVICE_NAME -n 50 # Last 50 lines"
if ! $SKIP_TLS; then
echo "  sudo systemctl status  caddy           # Check reverse proxy"
echo "  sudo caddy validate --config /etc/caddy/Caddyfile"
fi
echo ""
echo -e "${BOLD}--- Files ---${NC}"
echo ""
echo "  Binary:    $BIN_PATH"
echo "  Config:    $CONFIG_FILE"
echo "  Data:      $DATA_DIR"
echo "  Service:   /etc/systemd/system/${SERVICE_NAME}.service"
if ! $SKIP_TLS; then
echo "  Caddyfile: /etc/caddy/Caddyfile"
fi
echo ""
