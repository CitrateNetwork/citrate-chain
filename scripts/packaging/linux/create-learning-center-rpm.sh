#!/usr/bin/env bash
# Create an RPM package for the Citrate Learning Center pilot app.
#
# Requires rpmbuild and a binary built for the requested architecture.
# If --ai-bundle-dir or CITRATE_AI_BUNDLE_DIR is supplied, the package also
# includes the offline AI sidecar bundle under /usr/share/citrate-learning-center/ai/bundles/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
RELEASE_PACKET_DIR="$PROJECT_ROOT/gui/citrate_learning_center/release"
COMMON_HELPER="$SCRIPT_DIR/../common/learning-center-ai-bundle.sh"

source "$COMMON_HELPER"

VERSION="${VERSION:-0.1.0-p2}"
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64) DEFAULT_ARCH="x86_64" ;;
  aarch64|arm64) DEFAULT_ARCH="aarch64" ;;
  *) DEFAULT_ARCH="$HOST_ARCH" ;;
esac
RPM_ARCH="${RPM_ARCH:-$DEFAULT_ARCH}"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/dist/learning-center}"
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
AI_BUNDLE_DIR="${CITRATE_AI_BUNDLE_DIR:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --arch) RPM_ARCH="$2"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --ai-bundle-dir) AI_BUNDLE_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

case "$RPM_ARCH" in
  amd64|x86_64) RPM_ARCH="x86_64"; EXPECTED_KIND="x86-64" ;;
  arm64|aarch64) RPM_ARCH="aarch64"; EXPECTED_KIND="aarch64|ARM aarch64" ;;
  *) echo "Unsupported RPM architecture: $RPM_ARCH"; exit 1 ;;
esac

if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "rpmbuild is required to build the Learning Center RPM package."
  echo "This host does not have rpmbuild; run this script on a Fedora/RHEL-family builder."
  exit 1
fi

RPM_VERSION="${VERSION%%-*}"
RPM_RELEASE="${VERSION#*-}"
if [[ "$RPM_RELEASE" == "$VERSION" ]]; then
  RPM_RELEASE="1"
fi
RPM_RELEASE="${RPM_RELEASE//-/_}"

cd "$PROJECT_ROOT"
cargo build --release -p citrate-learning-center

BINARY="$TARGET_DIR/release/citrate-learning-center"
if [[ ! -x "$BINARY" ]]; then
  echo "Learning Center binary not found at $BINARY" >&2
  exit 1
fi

BINARY_KIND="$(file "$BINARY")"
if ! grep -Eq "$EXPECTED_KIND" <<< "$BINARY_KIND"; then
  echo "Package architecture mismatch: requested $RPM_ARCH but binary is: $BINARY_KIND" >&2
  exit 1
fi

TOPDIR="$(mktemp -d /tmp/citrate-learning-center-rpm.XXXXXX)"
trap 'rm -rf "$TOPDIR"' EXIT
mkdir -p "$TOPDIR/BUILD" "$TOPDIR/BUILDROOT" "$TOPDIR/RPMS" "$TOPDIR/SOURCES" "$TOPDIR/SPECS" "$TOPDIR/SRPMS"

SOURCE_ROOT="$TOPDIR/citrate-learning-center-$RPM_VERSION"
DOC_DIR="$SOURCE_ROOT/usr/share/doc/citrate-learning-center"
AI_INSTALL_DIR="usr/share/citrate-learning-center/ai/bundles"
RESOLVED_AI_BUNDLE_DIR=""
if RESOLVED_AI_BUNDLE_DIR="$(learning_center_resolve_ai_bundle_dir "$AI_BUNDLE_DIR")"; then
  :
else
  RESOLVED_AI_BUNDLE_DIR=""
fi

mkdir -p "$SOURCE_ROOT/usr/local/bin" "$DOC_DIR/ai" "$DOC_DIR/examples"
install -m 0755 "$BINARY" "$SOURCE_ROOT/usr/local/bin/citrate-learning-center"
cp "$RELEASE_PACKET_DIR/INSTALL.md" "$DOC_DIR/"
cp "$RELEASE_PACKET_DIR/P2_RELEASE_MANIFEST.toml" "$DOC_DIR/"
# Note: P2_CLOSURE_REPORT_2026-04-10.md was branch-historical and is
# intentionally not carried forward to main (see WP-A5 port).
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
  learning_center_copy_ai_bundle_into_root "$RESOLVED_AI_BUNDLE_DIR" "$SOURCE_ROOT" "$AI_INSTALL_DIR"
fi

tar -C "$TOPDIR" -czf "$TOPDIR/SOURCES/citrate-learning-center-$RPM_VERSION.tar.gz" "citrate-learning-center-$RPM_VERSION"

SPEC="$TOPDIR/SPECS/citrate-learning-center.spec"
cat > "$SPEC" << SPEC_EOF
Name: citrate-learning-center
Version: $RPM_VERSION
Release: $RPM_RELEASE%{?dist}
Summary: Citrate Learning Center pilot desktop application
License: BUSL-1.1
URL: https://citrate.local
BuildArch: $RPM_ARCH
Source0: %{name}-%{version}.tar.gz

%description
Citrate Learning Center is an education-first desktop interface for pilot
schools using local Citrate nodes. P-2 includes the deterministic AI Guide and
does not silently download Gemma model weights during install.
$(if [[ -n "$RESOLVED_AI_BUNDLE_DIR" ]]; then echo "This RPM includes a district-supplied offline AI sidecar bundle in the standard install layout."; else echo "This RPM supports an optional district-supplied offline AI sidecar bundle in the standard install layout."; fi)

%prep
%setup -q

%build

%install
mkdir -p %{buildroot}
cp -a usr %{buildroot}/

%files
/usr/local/bin/citrate-learning-center
/usr/share/doc/citrate-learning-center
$(if [[ -n "$RESOLVED_AI_BUNDLE_DIR" ]]; then echo "/usr/share/citrate-learning-center"; fi)

%changelog
* Fri Apr 10 2026 Citrate Learning Center <support@citrate.local> - $RPM_VERSION-$RPM_RELEASE
- P-2 pilot package for native RPM lab validation.
SPEC_EOF

rpmbuild --define "_topdir $TOPDIR" --target "$RPM_ARCH" -bb "$SPEC"

mkdir -p "$OUTPUT_DIR"
RPM_PATH="$(find "$TOPDIR/RPMS" -type f -name '*.rpm' | head -n 1)"
cp "$RPM_PATH" "$OUTPUT_DIR/"
sha256sum "$OUTPUT_DIR/$(basename "$RPM_PATH")" > "$OUTPUT_DIR/$(basename "$RPM_PATH").sha256"

echo "$OUTPUT_DIR/$(basename "$RPM_PATH")"
