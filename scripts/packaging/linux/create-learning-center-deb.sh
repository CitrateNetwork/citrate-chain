#!/usr/bin/env bash
# Create a Debian package for the Citrate Learning Center pilot app.
#
# Produces:
#   dist/learning-center/citrate-learning-center_<version>_<arch>.deb
#
# This packages the deterministic AI Guide and release packet. If
# --ai-bundle-dir or CITRATE_AI_BUNDLE_DIR is supplied, it also packages an
# offline AI sidecar bundle under /usr/local/share/citrate-learning-center/ai/bundles/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RELEASE_PACKET_DIR="$PROJECT_ROOT/gui/citrate_learning_center/release"
COMMON_HELPER="$SCRIPT_DIR/../common/learning-center-ai-bundle.sh"

source "$COMMON_HELPER"

VERSION="${VERSION:-0.1.0}"
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64) DEFAULT_ARCH="amd64" ;;
  aarch64|arm64) DEFAULT_ARCH="arm64" ;;
  *) DEFAULT_ARCH="$HOST_ARCH" ;;
esac
ARCH="${ARCH:-$DEFAULT_ARCH}"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/dist/learning-center}"
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
AI_BUNDLE_DIR="${CITRATE_AI_BUNDLE_DIR:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --ai-bundle-dir) AI_BUNDLE_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

case "$ARCH" in
  amd64|x86_64) DEB_ARCH="amd64" ;;
  arm64|aarch64) DEB_ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required to build the Learning Center .deb package."
  exit 1
fi

cd "$PROJECT_ROOT"
cargo build --release -p citrate-learning-center

BINARY="$TARGET_DIR/release/citrate-learning-center"
if [[ ! -x "$BINARY" ]]; then
  echo "Learning Center binary not found at $BINARY"
  exit 1
fi

BINARY_KIND="$(file "$BINARY")"
case "$DEB_ARCH" in
  amd64)
    if [[ "$BINARY_KIND" != *"x86-64"* ]]; then
      echo "Package architecture mismatch: requested amd64 but binary is: $BINARY_KIND"
      echo "Build on an x86_64 host or provide a cross-compiled x86_64 binary before packaging amd64."
      exit 1
    fi
    ;;
  arm64)
    if [[ "$BINARY_KIND" != *"aarch64"* && "$BINARY_KIND" != *"ARM aarch64"* ]]; then
      echo "Package architecture mismatch: requested arm64 but binary is: $BINARY_KIND"
      echo "Build on an aarch64 host or provide a cross-compiled aarch64 binary before packaging arm64."
      exit 1
    fi
    ;;
esac

STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGING_DIR"' EXIT

PKG_NAME="citrate-learning-center_${VERSION}_${DEB_ARCH}"
DEB_ROOT="$STAGING_DIR/$PKG_NAME"
DOC_DIR="$DEB_ROOT/usr/share/doc/citrate-learning-center"
AI_INSTALL_DIR="usr/local/share/citrate-learning-center/ai/bundles"
RESOLVED_AI_BUNDLE_DIR=""

if RESOLVED_AI_BUNDLE_DIR="$(learning_center_resolve_ai_bundle_dir "$AI_BUNDLE_DIR")"; then
  :
else
  RESOLVED_AI_BUNDLE_DIR=""
fi

mkdir -p "$DEB_ROOT/usr/local/bin" "$DOC_DIR" "$DEB_ROOT/usr/share/applications"
install -m 0755 "$BINARY" "$DEB_ROOT/usr/local/bin/citrate-learning-center"

cp "$RELEASE_PACKET_DIR/INSTALL.md" "$DOC_DIR/"
cp "$RELEASE_PACKET_DIR/P2_RELEASE_MANIFEST.toml" "$DOC_DIR/"
cp "$RELEASE_PACKET_DIR/AI_GUIDE_MANIFEST.toml" "$DOC_DIR/"
cp "$RELEASE_PACKET_DIR/IT_DEPLOYMENT_RUNBOOK.md" "$DOC_DIR/"
cp "$RELEASE_PACKET_DIR/INCIDENT_RESPONSE_RUNBOOK.md" "$DOC_DIR/"
# Note: P2_CLOSURE_REPORT_2026-04-10.md was branch-historical and is
# intentionally not carried forward to main (see WP-A5 port).
mkdir -p "$DOC_DIR/ai"
cp "$RELEASE_PACKET_DIR/ai/GEMMA4_E2B_CANDIDATE_MANIFEST.toml" "$DOC_DIR/ai/"
cp "$RELEASE_PACKET_DIR/ai/GEMMA4_E4B_UPGRADE_CANDIDATE_MANIFEST.toml" "$DOC_DIR/ai/"
cp "$RELEASE_PACKET_DIR/ai/BUNDLE_MANIFEST_TEMPLATE.toml" "$DOC_DIR/ai/"
cp "$RELEASE_PACKET_DIR/ai/AI_BUNDLE_LAYOUT.md" "$DOC_DIR/ai/"
mkdir -p "$DOC_DIR/examples"
cp "$RELEASE_PACKET_DIR/examples/credential-slip-sample.html" "$DOC_DIR/examples/"
cp "$RELEASE_PACKET_DIR/examples/guardian-setup-packet-sample.html" "$DOC_DIR/examples/"

if [[ -n "$RESOLVED_AI_BUNDLE_DIR" ]]; then
  learning_center_copy_ai_bundle_into_root "$RESOLVED_AI_BUNDLE_DIR" "$DEB_ROOT" "$AI_INSTALL_DIR"
fi

cat > "$DEB_ROOT/usr/share/applications/citrate-learning-center.desktop" << 'DESKTOP_EOF'
[Desktop Entry]
Type=Application
Name=Citrate Learning Center
Comment=Education-first interface for school-managed Citrate pilots
Exec=/usr/local/bin/citrate-learning-center
Categories=Education;Network;
Terminal=false
DESKTOP_EOF

mkdir -p "$DEB_ROOT/DEBIAN"
INSTALLED_SIZE="$(du -sk "$DEB_ROOT" | cut -f1)"

cat > "$DEB_ROOT/DEBIAN/control" << CONTROL_EOF
Package: citrate-learning-center
Version: ${VERSION}
Architecture: ${DEB_ARCH}
Maintainer: Citrate Learning Center <support@citrate.local>
Installed-Size: ${INSTALLED_SIZE}
Section: education
Priority: optional
Homepage: https://citrate.local
Description: Citrate Learning Center pilot desktop application
 Education-first desktop interface for school-managed Citrate pilots.
 Includes the deterministic out-of-box Citrate AI Guide and P-2 release packet.
 Gemma model weights are not silently downloaded during install.
 $(if [[ -n "$RESOLVED_AI_BUNDLE_DIR" ]]; then echo "Includes a district-supplied offline AI sidecar bundle in the standard install layout."; else echo "Supports an optional district-supplied offline AI sidecar bundle in the standard install layout."; fi)
CONTROL_EOF

mkdir -p "$OUTPUT_DIR"
dpkg-deb --root-owner-group --build "$DEB_ROOT" "$OUTPUT_DIR/$PKG_NAME.deb"
sha256sum "$OUTPUT_DIR/$PKG_NAME.deb" > "$OUTPUT_DIR/$PKG_NAME.deb.sha256"

echo "$OUTPUT_DIR/$PKG_NAME.deb"
