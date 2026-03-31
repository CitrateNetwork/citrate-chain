#!/usr/bin/env bash
# scripts/packaging/linux/create-deb.sh
# Creates a Debian .deb package containing:
#   - /usr/local/bin/citrate              (unified CLI binary)
#   - /opt/citrate/citrate-gui            (GUI AppImage or binary)
#   - /usr/share/applications/citrate.desktop  (desktop launcher)
#   - /etc/systemd/system/citrate-node.service (systemd unit)
#   - /usr/share/bash-completion/completions/citrate (shell completions)
#
# Usage:
#   ./scripts/packaging/linux/create-deb.sh [--arch amd64|arm64] [--version X.Y.Z]
#
# Prerequisites:
#   - CLI binary built:   cargo build --release -p citrate-node
#   - GUI built (optional): cd gui/citrate-core && npm run tauri:build
#   - dpkg-deb available

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# --- Defaults ---
ARCH="${ARCH:-amd64}"
VERSION="${VERSION:-0.1.0}"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/dist}"
MAINTAINER="${MAINTAINER:-Citrate AI <dev@citrate.ai>}"

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)    ARCH="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --output)  OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Normalize arch names
case "$ARCH" in
  amd64|x86_64)    DEB_ARCH="amd64"; RUST_TARGET="x86_64-unknown-linux-gnu" ;;
  arm64|aarch64)   DEB_ARCH="arm64"; RUST_TARGET="aarch64-unknown-linux-gnu" ;;
  *) echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac

PKG_NAME="citrate_${VERSION}_${DEB_ARCH}"
STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGING_DIR"' EXIT

echo "=== Citrate Linux DEB Packager ==="
echo "  Version:  $VERSION"
echo "  Arch:     $DEB_ARCH ($RUST_TARGET)"
echo "  Output:   $OUTPUT_DIR/$PKG_NAME.deb"
echo ""

# --- Locate CLI binary ---
CLI_BIN=""
for candidate in \
  "$PROJECT_ROOT/target/$RUST_TARGET/release/citrate" \
  "$PROJECT_ROOT/target/release/citrate"; do
  if [[ -x "$candidate" ]]; then
    CLI_BIN="$candidate"
    break
  fi
done

if [[ -z "$CLI_BIN" ]]; then
  echo "Error: citrate CLI binary not found. Build with:"
  echo "  cargo build --release --target $RUST_TARGET -p citrate-node"
  exit 1
fi
echo "  CLI binary: $CLI_BIN"

# --- Locate GUI binary (Slint-native) ---
GUI_BIN=""
for candidate in \
  "$PROJECT_ROOT/target/release/citrate-gui-native" \
  "$PROJECT_ROOT/gui-binary/citrate-gui-native"; do
  if [[ -f "$candidate" ]]; then
    GUI_BIN="$candidate"
    break
  fi
done

if [[ -z "$GUI_BIN" ]]; then
  echo "Warning: Citrate GUI binary not found — DEB will contain CLI only."
  echo "  Build GUI with: cargo build --release -p citrate-gui-native"
fi

# --- Build DEB directory structure ---
echo ""
echo "Building package structure..."
DEB_ROOT="$STAGING_DIR/$PKG_NAME"

# Binary
mkdir -p "$DEB_ROOT/usr/local/bin"
cp "$CLI_BIN" "$DEB_ROOT/usr/local/bin/citrate"
chmod 755 "$DEB_ROOT/usr/local/bin/citrate"
echo "  Installed /usr/local/bin/citrate"

# GUI (if available)
if [[ -n "$GUI_BIN" ]]; then
  mkdir -p "$DEB_ROOT/opt/citrate"
  cp "$GUI_BIN" "$DEB_ROOT/opt/citrate/citrate-gui"
  chmod 755 "$DEB_ROOT/opt/citrate/citrate-gui"
  echo "  Installed /opt/citrate/citrate-gui"

  # Desktop entry
  mkdir -p "$DEB_ROOT/usr/share/applications"
  cat > "$DEB_ROOT/usr/share/applications/citrate.desktop" << 'DESKTOP_EOF'
[Desktop Entry]
Type=Application
Name=Citrate
Comment=AI-Native Layer-1 Blockchain
Exec=/opt/citrate/citrate-gui
Icon=citrate
Categories=Finance;Network;
Terminal=false
StartupWMClass=Citrate
DESKTOP_EOF
  echo "  Installed /usr/share/applications/citrate.desktop"
fi

# Systemd service
mkdir -p "$DEB_ROOT/etc/systemd/system"
cat > "$DEB_ROOT/etc/systemd/system/citrate-node.service" << 'SERVICE_EOF'
[Unit]
Description=Citrate Blockchain Node
Documentation=https://docs.citrate.ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=citrate
Group=citrate
ExecStart=/usr/local/bin/citrate devnet --data-dir /var/lib/citrate
WorkingDirectory=/var/lib/citrate
Restart=on-failure
RestartSec=10
LimitNOFILE=65535

# Security hardening
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=citrate-node

[Install]
WantedBy=multi-user.target
SERVICE_EOF
echo "  Installed /etc/systemd/system/citrate-node.service"

# Shell completions (generate if binary supports it)
if "$DEB_ROOT/usr/local/bin/citrate" completions bash &>/dev/null; then
  # Bash
  mkdir -p "$DEB_ROOT/usr/share/bash-completion/completions"
  "$DEB_ROOT/usr/local/bin/citrate" completions bash \
    > "$DEB_ROOT/usr/share/bash-completion/completions/citrate" 2>/dev/null || true

  # Zsh
  mkdir -p "$DEB_ROOT/usr/share/zsh/vendor-completions"
  "$DEB_ROOT/usr/local/bin/citrate" completions zsh \
    > "$DEB_ROOT/usr/share/zsh/vendor-completions/_citrate" 2>/dev/null || true

  # Fish
  mkdir -p "$DEB_ROOT/usr/share/fish/vendor_completions.d"
  "$DEB_ROOT/usr/local/bin/citrate" completions fish \
    > "$DEB_ROOT/usr/share/fish/vendor_completions.d/citrate.fish" 2>/dev/null || true

  echo "  Generated shell completions."
fi

# --- DEBIAN control files ---
mkdir -p "$DEB_ROOT/DEBIAN"

# Calculate installed size (in KB)
INSTALLED_SIZE=$(du -sk "$DEB_ROOT" | cut -f1)

# Determine dependencies (Slint-native GUI has no GTK/WebKit deps)
DEPENDS="libc6 (>= 2.31), libssl3 | libssl1.1"

cat > "$DEB_ROOT/DEBIAN/control" << CONTROL_EOF
Package: citrate
Version: ${VERSION}
Architecture: ${DEB_ARCH}
Maintainer: ${MAINTAINER}
Depends: ${DEPENDS}
Installed-Size: ${INSTALLED_SIZE}
Section: net
Priority: optional
Homepage: https://citrate.ai
Description: Citrate - AI-Native Layer-1 Blockchain
 Citrate is an AI-native Layer-1 BlockDAG blockchain using GhostDAG
 consensus, paired with an EVM-compatible execution environment and
 Model Context Protocol (MCP) layer. Deploy, run, and monetize AI
 models on-chain.
 .
 This package includes the unified CLI (node, wallet, CLI tools)
 and the desktop GUI application.
CONTROL_EOF

# Post-install script
cat > "$DEB_ROOT/DEBIAN/postinst" << 'POSTINST_EOF'
#!/bin/sh
set -e

# Create citrate system user for the node service
if ! getent passwd citrate >/dev/null 2>&1; then
  adduser --system --group --home /var/lib/citrate --no-create-home citrate
fi

# Create data directory
mkdir -p /var/lib/citrate
chown citrate:citrate /var/lib/citrate

# Reload systemd
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

echo ""
echo "Citrate installed successfully!"
echo ""
echo "Quick start:"
echo "  citrate devnet              # Start local devnet"
echo "  citrate --help              # Show all commands"
echo ""
echo "To run as a system service:"
echo "  sudo systemctl enable citrate-node"
echo "  sudo systemctl start citrate-node"
echo ""
POSTINST_EOF
chmod 755 "$DEB_ROOT/DEBIAN/postinst"

# Pre-remove script
cat > "$DEB_ROOT/DEBIAN/prerm" << 'PRERM_EOF'
#!/bin/sh
set -e

# Stop the service if running
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet citrate-node 2>/dev/null; then
    systemctl stop citrate-node
  fi
  if systemctl is-enabled --quiet citrate-node 2>/dev/null; then
    systemctl disable citrate-node
  fi
fi
PRERM_EOF
chmod 755 "$DEB_ROOT/DEBIAN/prerm"

# Post-remove script
cat > "$DEB_ROOT/DEBIAN/postrm" << 'POSTRM_EOF'
#!/bin/sh
set -e

if [ "$1" = "purge" ]; then
  # Remove data directory on purge
  rm -rf /var/lib/citrate

  # Remove citrate user
  if getent passwd citrate >/dev/null 2>&1; then
    deluser --system citrate 2>/dev/null || true
  fi
fi

# Reload systemd
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi
POSTRM_EOF
chmod 755 "$DEB_ROOT/DEBIAN/postrm"

# --- Build .deb ---
echo ""
echo "Building .deb package..."
mkdir -p "$OUTPUT_DIR"

dpkg-deb --build --root-owner-group "$DEB_ROOT" "$OUTPUT_DIR/$PKG_NAME.deb"

# Generate checksum
cd "$OUTPUT_DIR"
sha256sum "$PKG_NAME.deb" > "${PKG_NAME}.deb.sha256"

echo ""
echo "=== Done ==="
echo "  Package:  $OUTPUT_DIR/$PKG_NAME.deb"
echo "  Checksum: $OUTPUT_DIR/${PKG_NAME}.deb.sha256"
echo "  Size:     $(du -h "$OUTPUT_DIR/$PKG_NAME.deb" | cut -f1)"
echo ""
echo "Install with:"
echo "  sudo dpkg -i $PKG_NAME.deb"
echo "  sudo apt-get install -f  # resolve dependencies"
