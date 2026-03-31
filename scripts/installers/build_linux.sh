#!/usr/bin/env bash
# build_linux.sh — Build Linux installer for Citrate (Slint-native GUI)
#
# Produces:
#   - citrate (node binary)
#   - citrate-gui-native (Slint desktop GUI)
#   - Debian .deb package (via scripts/packaging/linux/create-deb.sh)
#
# Prerequisites:
#   - Rust toolchain (stable)
#   - System deps: libclang-dev pkg-config libssl-dev cmake

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "============================================"
echo " Citrate Linux Build"
echo "============================================"
echo ""

# Step 1: Build all Rust binaries
echo "[1/3] Building Rust workspace (release)..."
cd "$PROJECT_ROOT"
cargo build --release -p citrate-node -p citrate-gui-native -p citrate-cli

echo "  Node binary: target/release/citrate"
echo "  GUI binary:  target/release/citrate-gui-native"
echo "  CLI binary:  target/release/citrate-cli"

# Step 2: Run tests
echo ""
echo "[2/3] Running test suite..."
cargo test --workspace --quiet 2>&1 | tail -5

# Step 3: Package
echo ""
echo "[3/3] Packaging..."
if [[ -f "$PROJECT_ROOT/scripts/packaging/linux/create-deb.sh" ]]; then
    bash "$PROJECT_ROOT/scripts/packaging/linux/create-deb.sh" \
        --version "${VERSION:-0.1.0}" --arch amd64 --output "$PROJECT_ROOT/dist"
    echo ""
    echo "Package output: $PROJECT_ROOT/dist/"
    ls -lh "$PROJECT_ROOT/dist/" 2>/dev/null || true
else
    echo "  Packaging script not found — binaries available in target/release/"
fi

echo ""
echo "Build complete."
