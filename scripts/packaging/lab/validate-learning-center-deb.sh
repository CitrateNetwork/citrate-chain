#!/usr/bin/env bash
# Validate a Citrate Learning Center .deb without installing it on the host.
#
# This is a package-inspection gate, not a substitute for clean-machine install.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/learning-center-ai-bundle.sh"

DEB_PATH="${1:-}"
if [[ -z "$DEB_PATH" ]]; then
  echo "usage: $0 path/to/citrate-learning-center_VERSION_ARCH.deb" >&2
  exit 2
fi

if [[ ! -f "$DEB_PATH" ]]; then
  echo "package not found: $DEB_PATH" >&2
  exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required for .deb validation" >&2
  exit 1
fi

TMPDIR="$(mktemp -d /tmp/citrate-learning-center-deb-validate.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

dpkg-deb --info "$DEB_PATH" > "$TMPDIR/info.txt"
dpkg-deb --contents "$DEB_PATH" > "$TMPDIR/contents.txt"
dpkg-deb -x "$DEB_PATH" "$TMPDIR/root"

grep -q "Package: citrate-learning-center" "$TMPDIR/info.txt"
grep -q "Architecture:" "$TMPDIR/info.txt"
grep -q "Gemma model weights are not silently downloaded during install" "$TMPDIR/info.txt"

BIN="$TMPDIR/root/usr/local/bin/citrate-learning-center"
DOC="$TMPDIR/root/usr/share/doc/citrate-learning-center"
AI_BUNDLES_ROOT="$TMPDIR/root/usr/local/share/citrate-learning-center/ai/bundles"

test -x "$BIN"
test -f "$DOC/INSTALL.md"
test -f "$DOC/P2_RELEASE_MANIFEST.toml"
test -f "$DOC/P2_CLOSURE_REPORT_2026-04-10.md"
test -f "$DOC/AI_GUIDE_MANIFEST.toml"
test -f "$DOC/ai/GEMMA4_E2B_CANDIDATE_MANIFEST.toml"
test -f "$DOC/examples/credential-slip-sample.html"
test -f "$DOC/examples/guardian-setup-packet-sample.html"

grep -q "works_without_configuration = true" "$DOC/AI_GUIDE_MANIFEST.toml"
grep -q "sha256_sidecar" "$DOC/P2_RELEASE_MANIFEST.toml"
grep -q "P-2 core is" "$DOC/P2_CLOSURE_REPORT_2026-04-10.md"
grep -q "required_before_school_ai_launch = true" "$DOC/ai/GEMMA4_E2B_CANDIDATE_MANIFEST.toml"

if [[ "${CITRATE_EXPECT_AI_BUNDLE:-false}" == "true" ]]; then
  find "$AI_BUNDLES_ROOT" -mindepth 2 -maxdepth 2 -name BUNDLE_MANIFEST.toml | grep -q "BUNDLE_MANIFEST.toml"
  while IFS= read -r manifest_path; do
    learning_center_validate_ai_bundle_dir "$(dirname "$manifest_path")"
  done < <(find "$AI_BUNDLES_ROOT" -mindepth 2 -maxdepth 2 -name BUNDLE_MANIFEST.toml | sort)
fi

file "$BIN" > "$TMPDIR/binary-kind.txt"
if ! grep -Eq "aarch64|x86-64" "$TMPDIR/binary-kind.txt"; then
  echo "unexpected binary architecture:" >&2
  cat "$TMPDIR/binary-kind.txt" >&2
  exit 1
fi

echo "OK: validated $DEB_PATH"
