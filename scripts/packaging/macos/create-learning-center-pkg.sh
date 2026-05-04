#!/usr/bin/env bash
# Build a macOS .pkg for Citrate Learning Center.
#
# Must be run on macOS with pkgbuild available.
# If --ai-bundle-dir or CITRATE_AI_BUNDLE_DIR is supplied, the package also
# includes the offline AI sidecar bundle under /usr/local/share/citrate-learning-center/ai/bundles/.

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS pkg build requires a macOS host with pkgbuild." >&2
  exit 1
fi

if ! command -v pkgbuild >/dev/null 2>&1; then
  echo "pkgbuild is required for macOS package creation." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RELEASE_PACKET_DIR="$PROJECT_ROOT/gui/citrate_learning_center/release"
COMMON_HELPER="$SCRIPT_DIR/../common/learning-center-ai-bundle.sh"
source "$COMMON_HELPER"

VERSION="${VERSION:-0.1.0-p2}"
PKG_VERSION="${VERSION%%-*}"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/dist/learning-center}"
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
AI_BUNDLE_DIR="${CITRATE_AI_BUNDLE_DIR:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; PKG_VERSION="${VERSION%%-*}"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --ai-bundle-dir) AI_BUNDLE_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

cd "$PROJECT_ROOT"
cargo build --release -p citrate-learning-center

BINARY="$TARGET_DIR/release/citrate-learning-center"
if [[ ! -x "$BINARY" ]]; then
  echo "Learning Center binary not found at $BINARY" >&2
  exit 1
fi

STAGING_DIR="$(mktemp -d /tmp/citrate-learning-center-pkg.XXXXXX)"
trap 'rm -rf "$STAGING_DIR"' EXIT
DOC_DIR="$STAGING_DIR/usr/local/share/doc/citrate-learning-center"
AI_INSTALL_DIR="usr/local/share/citrate-learning-center/ai/bundles"
RESOLVED_AI_BUNDLE_DIR=""
if RESOLVED_AI_BUNDLE_DIR="$(learning_center_resolve_ai_bundle_dir "$AI_BUNDLE_DIR")"; then
  :
else
  RESOLVED_AI_BUNDLE_DIR=""
fi

mkdir -p "$STAGING_DIR/usr/local/bin" "$DOC_DIR/ai" "$DOC_DIR/examples"
install -m 0755 "$BINARY" "$STAGING_DIR/usr/local/bin/citrate-learning-center"
cp "$RELEASE_PACKET_DIR/INSTALL.md" "$DOC_DIR/"
cp "$RELEASE_PACKET_DIR/P2_RELEASE_MANIFEST.toml" "$DOC_DIR/"
# Note: P2_CLOSURE_REPORT_2026-04-10.md was branch-historical
# (feat/learning-center-phase-a's local closure record) and is intentionally
# not carried forward to main per WP-A5 port. P2_RELEASE_MANIFEST.toml +
# CLEAN_MACHINE_INSTALL_PROTOCOL.md (in the active sprint dir) supersede it.
cp "$RELEASE_PACKET_DIR/AI_GUIDE_MANIFEST.toml" "$DOC_DIR/"
cp "$RELEASE_PACKET_DIR/IT_DEPLOYMENT_RUNBOOK.md" "$DOC_DIR/"
cp "$RELEASE_PACKET_DIR/INCIDENT_RESPONSE_RUNBOOK.md" "$DOC_DIR/"
cp "$RELEASE_PACKET_DIR/ai/GEMMA4_E2B_CANDIDATE_MANIFEST.toml" "$DOC_DIR/ai/"
cp "$RELEASE_PACKET_DIR/ai/GEMMA4_E4B_UPGRADE_CANDIDATE_MANIFEST.toml" "$DOC_DIR/ai/"
cp "$RELEASE_PACKET_DIR/ai/BUNDLE_MANIFEST_TEMPLATE.toml" "$DOC_DIR/ai/"
cp "$RELEASE_PACKET_DIR/ai/AI_BUNDLE_LAYOUT.md" "$DOC_DIR/ai/"
cp "$RELEASE_PACKET_DIR/examples/credential-slip-sample.html" "$DOC_DIR/examples/"
cp "$RELEASE_PACKET_DIR/examples/guardian-setup-packet-sample.html" "$DOC_DIR/examples/"

if [[ -n "$RESOLVED_AI_BUNDLE_DIR" ]]; then
  learning_center_copy_ai_bundle_into_root "$RESOLVED_AI_BUNDLE_DIR" "$STAGING_DIR" "$AI_INSTALL_DIR"
fi

mkdir -p "$OUTPUT_DIR"
PKG_PATH="$OUTPUT_DIR/CitrateLearningCenter-$VERSION-macos.pkg"
pkgbuild \
  --root "$STAGING_DIR" \
  --identifier com.citrate.learningcenter \
  --version "$PKG_VERSION" \
  --install-location / \
  "$PKG_PATH"

sha256sum "$PKG_PATH" > "$PKG_PATH.sha256"
echo "$PKG_PATH"
