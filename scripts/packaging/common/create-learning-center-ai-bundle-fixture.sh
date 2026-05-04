#!/usr/bin/env bash
# Create a deterministic local AI bundle fixture for packaging validation.
#
# This does not claim school-AI launch readiness. It exists to prove the
# install/bundle lane with a small checksum-pinned sidecar.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/learning-center-ai-bundle.sh"

OUTPUT_DIR="${1:-}"
if [[ -z "$OUTPUT_DIR" ]]; then
  echo "usage: $0 /absolute/or/relative/output-dir" >&2
  exit 2
fi

BUNDLE_DIR="$OUTPUT_DIR/gemma-4-e2b-validation-fixture"
mkdir -p "$BUNDLE_DIR/weights" "$BUNDLE_DIR/runtime"

printf 'fixture-weights-for-packaging-validation\n' > "$BUNDLE_DIR/weights/model.gguf"
cat > "$BUNDLE_DIR/runtime/runner" <<'RUNNER_EOF'
#!/usr/bin/env bash
echo "Citrate Learning Center validation runtime placeholder"
RUNNER_EOF
chmod 0755 "$BUNDLE_DIR/runtime/runner"

cat > "$BUNDLE_DIR/LICENSE.txt" <<'LICENSE_EOF'
Validation fixture only.

This bundle is used to prove package layout, checksum validation, and runtime
discovery behavior. It is not a real Gemma distribution artifact.
LICENSE_EOF

cat > "$BUNDLE_DIR/MODEL_CARD.md" <<'MODEL_CARD_EOF'
# Gemma 4 E2B Validation Fixture

- purpose: packaging validation only
- scope: checksum-pinned local bundle fixture
- not_for_distribution: true
- school_ai_launch_ready: false
MODEL_CARD_EOF

WEIGHTS_SHA256="$(learning_center_sha256_file "$BUNDLE_DIR/weights/model.gguf")"
RUNTIME_SHA256="$(learning_center_sha256_file "$BUNDLE_DIR/runtime/runner")"

cat > "$BUNDLE_DIR/BUNDLE_MANIFEST.toml" <<MANIFEST_EOF
schema_version = 1
status = "bundle-ready"
model_id = "gemma-4-e2b-validation-fixture"
display_name = "Gemma 4 E2B Validation Fixture"
weights_path = "weights/model.gguf"
runtime_path = "runtime/runner"
weights_sha256 = "$WEIGHTS_SHA256"
runtime_sha256 = "$RUNTIME_SHA256"
license_file = "LICENSE.txt"
model_card = "MODEL_CARD.md"
MANIFEST_EOF

learning_center_validate_ai_bundle_dir "$BUNDLE_DIR"

printf '%s\n' "$BUNDLE_DIR"
