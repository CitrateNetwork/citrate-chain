#!/usr/bin/env bash
# build_macos.sh — Build macOS .dmg installer for Citrate
#
# Produces a universal (Intel + Apple Silicon) .dmg with:
#   - Citrate GUI app (.app bundle via Tauri)
#   - Citrate node binary (sidecar)
#   - LaunchAgent plist for auto-start
#
# Prerequisites:
#   - Rust toolchain with aarch64-apple-darwin and x86_64-apple-darwin targets
#   - Node.js 18+ and npm
#   - Tauri CLI (npm run tauri:build)
#
# Usage:
#   ./scripts/installers/build_macos.sh [--release|--debug] [--sign]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GUI_DIR="$PROJECT_ROOT/gui/citrate_gui_v2"
BUILD_TYPE="${1:---release}"
SIGN_FLAG="${2:-}"

echo "=== Citrate macOS Installer Build ==="
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

# Optional: Build universal binary
if [ "${3:-}" = "--universal" ]; then
    echo ""
    echo "[1b/5] Building universal binary (Intel + Apple Silicon)..."
    # Build for both architectures
    cargo build --release -p citrate-node --target aarch64-apple-darwin
    cargo build --release -p citrate-node --target x86_64-apple-darwin

    # Create universal binary with lipo
    UNIVERSAL_BIN="$PROJECT_ROOT/target/release/citrate-node-universal"
    lipo -create \
        "$PROJECT_ROOT/target/aarch64-apple-darwin/release/citrate-node" \
        "$PROJECT_ROOT/target/x86_64-apple-darwin/release/citrate-node" \
        -output "$UNIVERSAL_BIN"
    NODE_BIN="$UNIVERSAL_BIN"
    echo "Universal binary: $NODE_BIN"
fi

# Step 2: Copy node binary as Tauri sidecar
echo ""
echo "[2/5] Installing node binary as Tauri sidecar..."

# Detect current architecture for sidecar naming
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  SIDECAR_SUFFIX="x86_64-apple-darwin" ;;
    arm64)   SIDECAR_SUFFIX="aarch64-apple-darwin" ;;
    aarch64) SIDECAR_SUFFIX="aarch64-apple-darwin" ;;
    *)       SIDECAR_SUFFIX="$ARCH-apple-darwin" ;;
esac

SIDECAR_DIR="$GUI_DIR/src-tauri/binaries"
mkdir -p "$SIDECAR_DIR"
cp "$NODE_BIN" "$SIDECAR_DIR/citrate-node-$SIDECAR_SUFFIX"
echo "Sidecar installed: $SIDECAR_DIR/citrate-node-$SIDECAR_SUFFIX"

# Step 3: Install LaunchAgent plist template
echo ""
echo "[3/5] Preparing LaunchAgent plist..."
PLIST_SRC="$SCRIPT_DIR/macos/com.citrate.node.plist"
PLIST_DEST="$GUI_DIR/src-tauri/resources/com.citrate.node.plist"
mkdir -p "$(dirname "$PLIST_DEST")"
if [ -f "$PLIST_SRC" ]; then
    cp "$PLIST_SRC" "$PLIST_DEST"
    echo "LaunchAgent plist: $PLIST_DEST"
else
    echo "WARNING: LaunchAgent plist not found at $PLIST_SRC (skipping)"
fi

# Copy first-launch script to resources
FIRST_LAUNCH_SRC="$SCRIPT_DIR/first_launch.sh"
FIRST_LAUNCH_DEST="$GUI_DIR/src-tauri/resources/first_launch.sh"
if [ -f "$FIRST_LAUNCH_SRC" ]; then
    cp "$FIRST_LAUNCH_SRC" "$FIRST_LAUNCH_DEST"
    chmod +x "$FIRST_LAUNCH_DEST"
fi

# Step 4: Build Tauri app
echo ""
echo "[4/5] Building Tauri .dmg..."
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
DMG_DIR="$GUI_DIR/src-tauri/target/release/bundle/dmg"
if [ -d "$DMG_DIR" ]; then
    echo "DMG files:"
    ls -lh "$DMG_DIR"/*.dmg 2>/dev/null || echo "  (no .dmg found — check build output)"
else
    echo "DMG directory not found at $DMG_DIR"
    echo "Check $GUI_DIR/src-tauri/target/release/bundle/ for output"
fi

# Optional: Sign with Developer ID
if [ "$SIGN_FLAG" = "--sign" ]; then
    echo ""
    echo "Code signing requested..."
    echo "NOTE: Apple Developer ID certificate required."
    echo "For pilot deployment, use ad-hoc signing:"
    echo "  codesign --force --deep --sign - <app_path>"
    echo ""
    echo "For production, configure APPLE_CERTIFICATE in CI/CD environment."
fi

echo ""
echo "=== macOS build complete ==="
