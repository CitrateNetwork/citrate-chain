#!/usr/bin/env bash
# scripts/packaging/macos/create-dmg.sh
# Creates a macOS DMG installer containing:
#   - Citrate.app (Tauri GUI)
#   - citrate CLI binary (unified node/wallet/cli)
#   - Shell completions (bash, zsh, fish)
#
# Usage:
#   ./scripts/packaging/macos/create-dmg.sh [--arch arm64|x86_64] [--version X.Y.Z]
#
# Prerequisites:
#   - Tauri GUI built:   cd gui/citrate-core && npm run tauri:build
#   - CLI binary built:  cargo build --release -p citrate-node
#   - hdiutil (ships with macOS)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# --- Defaults ---
ARCH="${ARCH:-$(uname -m)}"
VERSION="${VERSION:-0.1.0}"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/dist}"

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)   ARCH="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --output)  OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Normalize arch names
case "$ARCH" in
  arm64|aarch64) ARCH_LABEL="arm64"; RUST_TARGET="aarch64-apple-darwin" ;;
  x86_64|amd64)  ARCH_LABEL="x86_64"; RUST_TARGET="x86_64-apple-darwin" ;;
  *) echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac

DMG_NAME="Citrate-${VERSION}-${ARCH_LABEL}.dmg"
STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGING_DIR"' EXIT

echo "=== Citrate macOS DMG Packager ==="
echo "  Version:  $VERSION"
echo "  Arch:     $ARCH_LABEL ($RUST_TARGET)"
echo "  Output:   $OUTPUT_DIR/$DMG_NAME"
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
  echo "Warning: Citrate GUI binary not found — DMG will contain CLI only."
  echo "  Build GUI with: cargo build --release -p citrate-gui-native"
fi

# --- Stage DMG contents ---
echo ""
echo "Staging DMG contents..."
DMG_ROOT="$STAGING_DIR/Citrate"
mkdir -p "$DMG_ROOT"

# Copy GUI binary if available
if [[ -n "$GUI_BIN" ]]; then
  echo "  Copying citrate-gui-native..."
  cp "$GUI_BIN" "$DMG_ROOT/citrate-gui"
  chmod 755 "$DMG_ROOT/citrate-gui"
fi

# Create cli/ directory with the unified binary
mkdir -p "$DMG_ROOT/cli"
cp "$CLI_BIN" "$DMG_ROOT/cli/citrate"
chmod +x "$DMG_ROOT/cli/citrate"

# Generate shell completions if the binary supports it
if "$DMG_ROOT/cli/citrate" completions bash &>/dev/null; then
  mkdir -p "$DMG_ROOT/cli/completions"
  "$DMG_ROOT/cli/citrate" completions bash > "$DMG_ROOT/cli/completions/citrate.bash" 2>/dev/null || true
  "$DMG_ROOT/cli/citrate" completions zsh  > "$DMG_ROOT/cli/completions/_citrate"     2>/dev/null || true
  "$DMG_ROOT/cli/citrate" completions fish > "$DMG_ROOT/cli/completions/citrate.fish" 2>/dev/null || true
  echo "  Generated shell completions."
fi

# Create install script for CLI
cat > "$DMG_ROOT/install-cli.sh" << 'INSTALL_EOF'
#!/usr/bin/env bash
# Install the Citrate CLI to /usr/local/bin
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/bin"

echo "Installing Citrate CLI..."

if [[ ! -f "$SCRIPT_DIR/cli/citrate" ]]; then
  echo "Error: citrate binary not found in cli/ directory."
  exit 1
fi

# Install binary
sudo cp "$SCRIPT_DIR/cli/citrate" "$INSTALL_DIR/citrate"
sudo chmod +x "$INSTALL_DIR/citrate"

# Install shell completions if available
if [[ -d "$SCRIPT_DIR/cli/completions" ]]; then
  # Bash completions
  if [[ -f "$SCRIPT_DIR/cli/completions/citrate.bash" ]]; then
    BASH_COMP_DIR="/usr/local/etc/bash_completion.d"
    if [[ -d "$BASH_COMP_DIR" ]] || mkdir -p "$BASH_COMP_DIR" 2>/dev/null; then
      sudo cp "$SCRIPT_DIR/cli/completions/citrate.bash" "$BASH_COMP_DIR/citrate"
      echo "  Installed bash completions."
    fi
  fi

  # Zsh completions
  if [[ -f "$SCRIPT_DIR/cli/completions/_citrate" ]]; then
    ZSH_COMP_DIR="/usr/local/share/zsh/site-functions"
    if [[ -d "$ZSH_COMP_DIR" ]] || sudo mkdir -p "$ZSH_COMP_DIR" 2>/dev/null; then
      sudo cp "$SCRIPT_DIR/cli/completions/_citrate" "$ZSH_COMP_DIR/_citrate"
      echo "  Installed zsh completions."
    fi
  fi

  # Fish completions
  if [[ -f "$SCRIPT_DIR/cli/completions/citrate.fish" ]]; then
    FISH_COMP_DIR="${HOME}/.config/fish/completions"
    mkdir -p "$FISH_COMP_DIR" 2>/dev/null || true
    cp "$SCRIPT_DIR/cli/completions/citrate.fish" "$FISH_COMP_DIR/citrate.fish"
    echo "  Installed fish completions."
  fi
fi

echo ""
echo "Citrate CLI installed to $INSTALL_DIR/citrate"
echo "Run 'citrate --help' to get started."
INSTALL_EOF
chmod +x "$DMG_ROOT/install-cli.sh"

# Create a README
cat > "$DMG_ROOT/README.txt" << README_EOF
Citrate ${VERSION} for macOS (${ARCH_LABEL})
==========================================

CONTENTS:
  Citrate.app    - GUI desktop application
  cli/citrate    - Unified command-line tool (node, wallet, CLI tools)
  install-cli.sh - Script to install CLI to /usr/local/bin

QUICK START:

  1. Drag Citrate.app to your Applications folder.

  2. Install the CLI:
     Open Terminal and run:
       ./install-cli.sh

  3. Start a local devnet:
       citrate devnet

  4. Open the GUI and connect to http://127.0.0.1:8545

For documentation, visit: https://docs.citrate.ai
README_EOF

# Create Applications symlink for drag-to-install
if [[ -n "$GUI_APP" ]]; then
  ln -s /Applications "$DMG_ROOT/Applications"
fi

# --- Create DMG ---
echo ""
echo "Creating DMG..."
mkdir -p "$OUTPUT_DIR"

# Remove existing DMG if present
rm -f "$OUTPUT_DIR/$DMG_NAME"

# Create DMG using hdiutil
hdiutil create \
  -volname "Citrate ${VERSION}" \
  -srcfolder "$DMG_ROOT" \
  -ov \
  -format UDZO \
  "$OUTPUT_DIR/$DMG_NAME"

# Generate checksum
cd "$OUTPUT_DIR"
shasum -a 256 "$DMG_NAME" > "${DMG_NAME}.sha256"

echo ""
echo "=== Done ==="
echo "  DMG:      $OUTPUT_DIR/$DMG_NAME"
echo "  Checksum: $OUTPUT_DIR/${DMG_NAME}.sha256"
echo "  Size:     $(du -h "$OUTPUT_DIR/$DMG_NAME" | cut -f1)"
