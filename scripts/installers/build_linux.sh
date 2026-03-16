#!/usr/bin/env bash
# build_linux.sh — Build Linux .deb and .rpm installers for Citrate
#
# Produces:
#   - Debian .deb package (via cargo-deb or Tauri bundler)
#   - RPM package (via Tauri bundler)
#   - AppImage (via Tauri bundler)
#   - systemd service unit
#
# Prerequisites:
#   - Rust toolchain
#   - Node.js 18+ and npm
#   - cargo-deb (for standalone .deb: cargo install cargo-deb)
#   - dpkg-deb, rpm-build (for respective package formats)
#
# Usage:
#   ./scripts/installers/build_linux.sh [--release|--debug]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GUI_DIR="$PROJECT_ROOT/gui/citrate_gui_v2"
BUILD_TYPE="${1:---release}"

echo "=== Citrate Linux Installer Build ==="
echo "Project root: $PROJECT_ROOT"
echo "Build type: $BUILD_TYPE"

# Step 1: Build the node binary
echo ""
echo "[1/5] Building citrate-node binary..."
cd "$PROJECT_ROOT"

if [ "$BUILD_TYPE" = "--release" ]; then
    cargo build --release -p citrate-node
    NODE_BIN="$PROJECT_ROOT/target/release/citrate-node"
else
    cargo build -p citrate-node
    NODE_BIN="$PROJECT_ROOT/target/debug/citrate-node"
fi

if [ ! -f "$NODE_BIN" ]; then
    echo "ERROR: citrate-node binary not found at $NODE_BIN"
    exit 1
fi
echo "Node binary: $NODE_BIN"

# Step 2: Install sidecar
echo ""
echo "[2/5] Installing node binary as Tauri sidecar..."

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  SIDECAR_SUFFIX="x86_64-unknown-linux-gnu" ;;
    aarch64) SIDECAR_SUFFIX="aarch64-unknown-linux-gnu" ;;
    *)       SIDECAR_SUFFIX="$ARCH-unknown-linux-gnu" ;;
esac

SIDECAR_DIR="$GUI_DIR/src-tauri/binaries"
mkdir -p "$SIDECAR_DIR"
cp "$NODE_BIN" "$SIDECAR_DIR/citrate-node-$SIDECAR_SUFFIX"
echo "Sidecar installed"

# Step 3: Install systemd unit
echo ""
echo "[3/5] Preparing systemd service unit..."
SYSTEMD_SRC="$SCRIPT_DIR/linux/systemd/citrate-node.service"
SYSTEMD_DEST="$GUI_DIR/src-tauri/resources/citrate-node.service"
mkdir -p "$(dirname "$SYSTEMD_DEST")"
if [ -f "$SYSTEMD_SRC" ]; then
    cp "$SYSTEMD_SRC" "$SYSTEMD_DEST"
    echo "systemd unit: $SYSTEMD_DEST"
else
    echo "WARNING: systemd unit not found at $SYSTEMD_SRC (skipping)"
fi

# Copy IPFS systemd unit
IPFS_SYSTEMD_SRC="$SCRIPT_DIR/linux/systemd/citrate-ipfs.service"
IPFS_SYSTEMD_DEST="$GUI_DIR/src-tauri/resources/citrate-ipfs.service"
if [ -f "$IPFS_SYSTEMD_SRC" ]; then
    cp "$IPFS_SYSTEMD_SRC" "$IPFS_SYSTEMD_DEST"
    echo "IPFS systemd unit: $IPFS_SYSTEMD_DEST"
fi

# Copy post-install and pre-remove scripts
for script in postinst.sh prerm.sh; do
    SRC="$SCRIPT_DIR/linux/$script"
    DEST="$GUI_DIR/src-tauri/resources/$script"
    if [ -f "$SRC" ]; then
        cp "$SRC" "$DEST"
        chmod +x "$DEST"
        echo "Script: $DEST"
    fi
done

# Step 4: Build Tauri packages
echo ""
echo "[4/5] Building Tauri packages (.deb, .rpm, .AppImage)..."
cd "$GUI_DIR"
npm install --prefer-offline 2>/dev/null || npm install

if [ "$BUILD_TYPE" = "--release" ]; then
    npm run tauri build 2>&1
else
    npm run tauri build -- --debug 2>&1
fi

# Step 5: Report output
echo ""
echo "[5/5] Build complete!"
BUNDLE_DIR="$GUI_DIR/src-tauri/target/release/bundle"
echo ""
echo "Packages:"
[ -d "$BUNDLE_DIR/deb" ] && ls -lh "$BUNDLE_DIR/deb"/*.deb 2>/dev/null || echo "  .deb: not found"
[ -d "$BUNDLE_DIR/rpm" ] && ls -lh "$BUNDLE_DIR/rpm"/*.rpm 2>/dev/null || echo "  .rpm: not found"
[ -d "$BUNDLE_DIR/appimage" ] && ls -lh "$BUNDLE_DIR/appimage"/*.AppImage 2>/dev/null || echo "  .AppImage: not found"

echo ""
echo "=== Linux build complete ==="
