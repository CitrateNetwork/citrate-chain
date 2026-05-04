#!/usr/bin/env bash
# Chromebook-class AI Guide benchmark harness.
#
# Default mode is intentionally no-download and deterministic. If a district
# later supplies CITRATE_AI_BUNDLE_DIR or CITRATE_GEMMA_MODEL_PATH, this script
# records model artifact availability but does not download weights.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/target/p2-benchmarks}"
AI_BUNDLE_DIR="${CITRATE_AI_BUNDLE_DIR:-}"
MODEL_PATH="${CITRATE_GEMMA_MODEL_PATH:-}"
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MANIFEST_PATH=""

mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/chromebook-ai-guide-benchmark.json"

if [[ -n "$AI_BUNDLE_DIR" ]]; then
  MANIFEST_PATH="$AI_BUNDLE_DIR/BUNDLE_MANIFEST.toml"
  if [[ -f "$MANIFEST_PATH" ]]; then
    MODEL_STATE="bundle_ready_candidate"
  else
    MODEL_STATE="model_error"
  fi
elif [[ -n "$MODEL_PATH" && ! -f "$MODEL_PATH" ]]; then
  MODEL_STATE="model_error"
elif [[ -n "$MODEL_PATH" ]]; then
  MODEL_STATE="model_ready_candidate"
else
  MODEL_STATE="model_unavailable"
fi

SECONDS=0
(
  cd "$PROJECT_ROOT"
  cargo test -p citrate-learning-center --bin citrate-learning-center ai_guide_opens_out_of_box_without_model_configuration -- --nocapture
)
DURATION_SECONDS="$SECONDS"

cat > "$REPORT" << REPORT_EOF
{
  "schema_version": 1,
  "started_at": "$START_TS",
  "host_arch": "$(uname -m)",
  "mode": "deterministic_no_download",
  "model_state": "$MODEL_STATE",
  "bundle_dir_set": $(if [[ -n "$AI_BUNDLE_DIR" ]]; then echo true; else echo false; fi),
  "bundle_manifest_found": $(if [[ -n "$MANIFEST_PATH" && -f "$MANIFEST_PATH" ]]; then echo true; else echo false; fi),
  "model_path_set": $(if [[ -n "$MODEL_PATH" ]]; then echo true; else echo false; fi),
  "duration_seconds": $DURATION_SECONDS,
  "network_download_allowed": false,
  "test_command": "cargo test -p citrate-learning-center --bin citrate-learning-center ai_guide_opens_out_of_box_without_model_configuration -- --nocapture",
  "result": "passed"
}
REPORT_EOF

echo "$REPORT"
