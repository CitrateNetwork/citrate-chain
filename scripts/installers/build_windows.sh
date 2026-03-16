#!/usr/bin/env bash
# build_windows.sh — Build Windows .msi/.exe installer for Citrate
#
# Designed to run in GitHub Actions CI with Windows runner.
# Can also run locally with cross-compilation toolchain.
#
# Produces:
#   - NSIS .exe installer (per-user install)
#   - WiX .msi installer (system-wide install, optional)
#   - citrate-node.exe as bundled sidecar
#
# Prerequisites:
#   - Rust with x86_64-pc-windows-msvc target (or cross)
#   - Node.js 18+ and npm
#   - WiX Toolset 3.x (for .msi, optional)
#
# Usage:
#   ./scripts/installers/build_windows.sh [--release|--debug]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GUI_DIR="$PROJECT_ROOT/gui/citrate_gui_v2"
BUILD_TYPE="${1:---release}"

echo "=== Citrate Windows Installer Build ==="
echo "Project root: $PROJECT_ROOT"
echo "Build type: $BUILD_TYPE"

# Detect if running on Windows or cross-compiling
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    PLATFORM="native"
    TARGET=""
    EXE_SUFFIX=".exe"
else
    PLATFORM="cross"
    TARGET="--target x86_64-pc-windows-msvc"
    EXE_SUFFIX=".exe"
    echo "Cross-compiling from $OSTYPE — ensure cross-compilation toolchain is installed"
fi

# Step 1: Build the node binary
echo ""
echo "[1/4] Building citrate-node for Windows..."
cd "$PROJECT_ROOT"

if [ "$BUILD_TYPE" = "--release" ]; then
    cargo build --release -p citrate-node $TARGET 2>&1
    if [ "$PLATFORM" = "native" ]; then
        NODE_BIN="$PROJECT_ROOT/target/release/citrate-node${EXE_SUFFIX}"
    else
        NODE_BIN="$PROJECT_ROOT/target/x86_64-pc-windows-msvc/release/citrate-node${EXE_SUFFIX}"
    fi
else
    cargo build -p citrate-node $TARGET 2>&1
    if [ "$PLATFORM" = "native" ]; then
        NODE_BIN="$PROJECT_ROOT/target/debug/citrate-node${EXE_SUFFIX}"
    else
        NODE_BIN="$PROJECT_ROOT/target/x86_64-pc-windows-msvc/debug/citrate-node${EXE_SUFFIX}"
    fi
fi

if [ ! -f "$NODE_BIN" ]; then
    echo "WARNING: citrate-node binary not found at $NODE_BIN"
    echo "On CI, this is built in a separate step. Continuing..."
else
    echo "Node binary: $NODE_BIN"
fi

# Step 2: Install sidecar
echo ""
echo "[2/4] Installing node binary as Tauri sidecar..."
SIDECAR_DIR="$GUI_DIR/src-tauri/binaries"
mkdir -p "$SIDECAR_DIR"
if [ -f "$NODE_BIN" ]; then
    cp "$NODE_BIN" "$SIDECAR_DIR/citrate-node-x86_64-pc-windows-msvc.exe"
    echo "Sidecar installed"
fi

# Copy Windows service installer to resources
echo ""
echo "[2b/4] Bundling Windows service scripts..."
WIN_SCRIPTS_SRC="$SCRIPT_DIR/windows"
WIN_SCRIPTS_DEST="$GUI_DIR/src-tauri/resources"
mkdir -p "$WIN_SCRIPTS_DEST"
if [ -f "$WIN_SCRIPTS_SRC/install_service.ps1" ]; then
    cp "$WIN_SCRIPTS_SRC/install_service.ps1" "$WIN_SCRIPTS_DEST/"
    echo "Bundled: install_service.ps1"
fi

# Step 3: Build Tauri app
echo ""
echo "[3/4] Building Tauri installer..."
cd "$GUI_DIR"
npm install --prefer-offline 2>/dev/null || npm install

if [ "$BUILD_TYPE" = "--release" ]; then
    npm run tauri build 2>&1
else
    npm run tauri build -- --debug 2>&1
fi

# Step 4: Report output
echo ""
echo "[4/4] Build complete!"
echo ""
echo "Installers:"
NSIS_DIR="$GUI_DIR/src-tauri/target/release/bundle/nsis"
MSI_DIR="$GUI_DIR/src-tauri/target/release/bundle/msi"
[ -d "$NSIS_DIR" ] && ls -lh "$NSIS_DIR"/*.exe 2>/dev/null || echo "  NSIS: not found"
[ -d "$MSI_DIR" ] && ls -lh "$MSI_DIR"/*.msi 2>/dev/null || echo "  MSI: not found"

echo ""
echo "=== Windows build complete ==="
