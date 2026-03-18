#!/usr/bin/env bash
# bundle_model.sh — Download and prepare a curriculum model for bundling
# Used at build time to include a pre-loaded model in the installer
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODELS_DIR="$PROJECT_ROOT/models/curriculum"
MODEL_NAME="${1:-curriculum-assistant}"
MODEL_VERSION="${2:-1.0.0}"

echo "=== Curriculum Model Bundler ==="
echo "Model: $MODEL_NAME v$MODEL_VERSION"

mkdir -p "$MODELS_DIR"

# Model manifest with provenance
MANIFEST="$MODELS_DIR/manifest.json"
cat > "$MANIFEST" <<EOF
{
  "name": "$MODEL_NAME",
  "version": "$MODEL_VERSION",
  "description": "Pre-loaded curriculum assistant for Citrate school pilot nodes",
  "framework": "gguf",
  "license": "Apache-2.0",
  "provenance": {
    "source": "Citrate AI Foundation",
    "buildDate": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "buildHost": "$(hostname)",
    "integrityAlgorithm": "SHA-256"
  },
  "systemPrompt": "You are a helpful curriculum assistant running on a Citrate school node. You help students and teachers with educational questions. You provide age-appropriate, accurate, and supportive responses. You do not generate harmful, inappropriate, or off-topic content.",
  "capabilities": ["text-generation", "question-answering", "summarization"],
  "resourceRequirements": {
    "minRamMb": 2048,
    "recommendedRamMb": 4096,
    "diskMb": 500
  }
}
EOF
echo "Manifest written: $MANIFEST"

# System prompt template
PROMPT_FILE="$MODELS_DIR/system_prompt.txt"
cat > "$PROMPT_FILE" <<'EOF'
You are a helpful curriculum assistant running on a Citrate school node.

## Guidelines
- Provide age-appropriate, accurate, and supportive responses
- Help students understand concepts rather than just giving answers
- Encourage critical thinking and curiosity
- Support teachers with lesson planning and resource suggestions
- Never generate harmful, inappropriate, or off-topic content
- If you don't know something, say so honestly

## Subjects
You can help with: Mathematics, Science, English Language Arts, History, Geography, Computer Science, and general study skills.

## Citrate Integration
- Your responses are anchored on the Citrate blockchain for provenance
- Students can verify the model version and training data via on-chain records
- All interactions are logged locally for teacher review (not shared externally)
EOF
echo "System prompt: $PROMPT_FILE"

# Integrity verification script
VERIFY_SCRIPT="$MODELS_DIR/verify_integrity.sh"
cat > "$VERIFY_SCRIPT" <<'BASH'
#!/usr/bin/env bash
# Verify model file integrity using SHA-256
set -euo pipefail

MODEL_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKSUM_FILE="$MODEL_DIR/checksums.sha256"

if [ ! -f "$CHECKSUM_FILE" ]; then
    echo "No checksum file found. Generating..."
    cd "$MODEL_DIR"
    find . -type f ! -name "checksums.sha256" ! -name "verify_integrity.sh" -exec sha256sum {} \; > "$CHECKSUM_FILE"
    echo "Checksums generated: $CHECKSUM_FILE"
else
    echo "Verifying model integrity..."
    cd "$MODEL_DIR"
    if sha256sum -c "$CHECKSUM_FILE" 2>/dev/null || shasum -a 256 -c "$CHECKSUM_FILE" 2>/dev/null; then
        echo "PASS: All files verified."
    else
        echo "FAIL: Integrity check failed!"
        exit 1
    fi
fi
BASH
chmod +x "$VERIFY_SCRIPT"
echo "Verify script: $VERIFY_SCRIPT"

# Generate initial checksums
cd "$MODELS_DIR"
find . -type f ! -name "checksums.sha256" ! -name "verify_integrity.sh" -exec shasum -a 256 {} \; > checksums.sha256 2>/dev/null || \
find . -type f ! -name "checksums.sha256" ! -name "verify_integrity.sh" -exec sha256sum {} \; > checksums.sha256 2>/dev/null || true

echo ""
echo "=== Model bundle ready ==="
echo "Directory: $MODELS_DIR"
echo ""
echo "To include a model file, download it to $MODELS_DIR/ and re-run this script."
echo "The manifest.json and system_prompt.txt are ready for registration."
