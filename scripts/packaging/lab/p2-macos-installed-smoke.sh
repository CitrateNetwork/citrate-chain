#!/usr/bin/env bash
# Run this on a clean macOS machine after installing the P-2 package.

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS installed smoke requires a macOS host." >&2
  exit 1
fi

BIN="${CITRATE_LEARNING_CENTER_BIN:-/usr/local/bin/citrate-learning-center}"
DOC="${CITRATE_LEARNING_CENTER_DOC:-/usr/local/share/doc/citrate-learning-center}"
AI_BUNDLES_ROOT="${CITRATE_AI_BUNDLES_ROOT:-/usr/local/share/citrate-learning-center/ai/bundles}"

test -x "$BIN"
test -f "$DOC/INSTALL.md"
test -f "$DOC/P2_RELEASE_MANIFEST.toml"
test -f "$DOC/P2_CLOSURE_REPORT_2026-04-10.md"
test -f "$DOC/AI_GUIDE_MANIFEST.toml"
test -f "$DOC/ai/GEMMA4_E2B_CANDIDATE_MANIFEST.toml"
test -f "$DOC/examples/credential-slip-sample.html"
test -f "$DOC/examples/guardian-setup-packet-sample.html"

grep -q "works_without_configuration = true" "$DOC/AI_GUIDE_MANIFEST.toml"
grep -q "allow_silent_network_download_during_install = false" "$DOC/ai/GEMMA4_E2B_CANDIDATE_MANIFEST.toml"

if [[ "${CITRATE_EXPECT_AI_BUNDLE:-false}" == "true" ]]; then
  find "$AI_BUNDLES_ROOT" -mindepth 2 -maxdepth 2 -name BUNDLE_MANIFEST.toml | grep -q "BUNDLE_MANIFEST.toml"
fi

if [[ "${CITRATE_DEMO_MODE:-false}" == "true" ]]; then
  echo "CITRATE_DEMO_MODE must not be true in a pilot lab smoke" >&2
  exit 1
fi

echo "OK: P-2 macOS installed smoke passed for $BIN"
