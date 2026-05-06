#!/usr/bin/env bash
# Run this on a clean Linux machine after installing the P-2 package.
#
# It verifies install layout and release-packet contents without launching the
# Slint GUI. It should be paired with the interactive guardian/SIS smoke script
# in the release runbook when a display is available.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/learning-center-ai-bundle.sh"

BIN="${CITRATE_LEARNING_CENTER_BIN:-/usr/local/bin/citrate-learning-center}"
DOC="${CITRATE_LEARNING_CENTER_DOC:-/usr/share/doc/citrate-learning-center}"
STATE_DIR="${CITRATE_STATE_DIR:-$HOME/.citrate-edu}"
AI_BUNDLES_ROOT="${CITRATE_AI_BUNDLES_ROOT:-/usr/local/share/citrate-learning-center/ai/bundles}"

test -x "$BIN"
test -d "$DOC"
test -f "$DOC/INSTALL.md"
test -f "$DOC/P2_RELEASE_MANIFEST.toml"
test -f "$DOC/P2_CLOSURE_REPORT_2026-04-10.md"
test -f "$DOC/AI_GUIDE_MANIFEST.toml"
test -f "$DOC/ai/GEMMA4_E2B_CANDIDATE_MANIFEST.toml"
test -f "$DOC/examples/credential-slip-sample.html"
test -f "$DOC/examples/guardian-setup-packet-sample.html"

grep -q "works_without_configuration = true" "$DOC/AI_GUIDE_MANIFEST.toml"
grep -q "allow_silent_network_download_during_install = false" "$DOC/ai/GEMMA4_E2B_CANDIDATE_MANIFEST.toml"
grep -q "P-2 core is" "$DOC/P2_CLOSURE_REPORT_2026-04-10.md"

if [[ "${CITRATE_EXPECT_AI_BUNDLE:-false}" == "true" ]]; then
  find "$AI_BUNDLES_ROOT" -mindepth 2 -maxdepth 2 -name BUNDLE_MANIFEST.toml | grep -q "BUNDLE_MANIFEST.toml"
  while IFS= read -r manifest_path; do
    learning_center_validate_ai_bundle_dir "$(dirname "$manifest_path")"
  done < <(find "$AI_BUNDLES_ROOT" -mindepth 2 -maxdepth 2 -name BUNDLE_MANIFEST.toml | sort)
fi

if [[ "${CITRATE_DEMO_MODE:-false}" == "true" ]]; then
  echo "CITRATE_DEMO_MODE must not be true on a pilot clean-machine smoke" >&2
  exit 1
fi

mkdir -p "$STATE_DIR"
test -d "$STATE_DIR"

echo "OK: P-2 Linux installed smoke passed for $BIN"
