#!/usr/bin/env bash
# Shared helpers for optional Citrate Learning Center AI sidecar bundles.

set -euo pipefail

learning_center_manifest_value() {
  local manifest_path="$1"
  local key="$2"
  sed -n "s/^${key}[[:space:]]*=[[:space:]]*\"\\(.*\\)\"[[:space:]]*$/\\1/p" "$manifest_path" | head -n1
}

learning_center_sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print tolower($1)}'
    return 0
  fi

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print tolower($1)}'
    return 0
  fi

  echo "No SHA-256 tool available (expected sha256sum or shasum)." >&2
  exit 1
}

learning_center_validate_ai_bundle_dir() {
  local bundle_dir="$1"
  local manifest_path="$bundle_dir/BUNDLE_MANIFEST.toml"
  local weights_path
  local runtime_path
  local weights_sha256
  local runtime_sha256
  local license_file
  local model_card
  local weights_abs
  local runtime_abs
  local license_abs
  local model_card_abs
  local actual_weights_sha256
  local actual_runtime_sha256
  local expected_weights_sha256
  local expected_runtime_sha256

  if [[ ! -d "$bundle_dir" ]]; then
    echo "AI bundle directory not found: $bundle_dir" >&2
    exit 1
  fi

  if [[ ! -f "$manifest_path" ]]; then
    echo "AI bundle directory is missing BUNDLE_MANIFEST.toml: $bundle_dir" >&2
    exit 1
  fi

  weights_path="$(learning_center_manifest_value "$manifest_path" "weights_path")"
  runtime_path="$(learning_center_manifest_value "$manifest_path" "runtime_path")"
  weights_sha256="$(learning_center_manifest_value "$manifest_path" "weights_sha256")"
  runtime_sha256="$(learning_center_manifest_value "$manifest_path" "runtime_sha256")"
  license_file="$(learning_center_manifest_value "$manifest_path" "license_file")"
  model_card="$(learning_center_manifest_value "$manifest_path" "model_card")"

  if [[ -z "$weights_path" || -z "$runtime_path" || -z "$weights_sha256" || -z "$runtime_sha256" || -z "$license_file" || -z "$model_card" ]]; then
    echo "AI bundle manifest is incomplete and must define weights_path, runtime_path, weights_sha256, runtime_sha256, license_file, and model_card: $manifest_path" >&2
    exit 1
  fi

  weights_abs="$bundle_dir/$weights_path"
  runtime_abs="$bundle_dir/$runtime_path"
  license_abs="$bundle_dir/$license_file"
  model_card_abs="$bundle_dir/$model_card"

  if [[ ! -f "$weights_abs" ]]; then
    echo "AI bundle weights file not found: $weights_abs" >&2
    exit 1
  fi
  if [[ ! -f "$runtime_abs" ]]; then
    echo "AI bundle runtime file not found: $runtime_abs" >&2
    exit 1
  fi
  if [[ ! -f "$license_abs" ]]; then
    echo "AI bundle license file not found: $license_abs" >&2
    exit 1
  fi
  if [[ ! -f "$model_card_abs" ]]; then
    echo "AI bundle model card not found: $model_card_abs" >&2
    exit 1
  fi

  actual_weights_sha256="$(learning_center_sha256_file "$weights_abs")"
  actual_runtime_sha256="$(learning_center_sha256_file "$runtime_abs")"
  expected_weights_sha256="$(printf '%s' "$weights_sha256" | tr '[:upper:]' '[:lower:]')"
  expected_runtime_sha256="$(printf '%s' "$runtime_sha256" | tr '[:upper:]' '[:lower:]')"
  if [[ "$actual_weights_sha256" != "$expected_weights_sha256" ]]; then
    echo "AI bundle weights checksum mismatch for $weights_abs: expected $weights_sha256, got $actual_weights_sha256" >&2
    exit 1
  fi
  if [[ "$actual_runtime_sha256" != "$expected_runtime_sha256" ]]; then
    echo "AI bundle runtime checksum mismatch for $runtime_abs: expected $runtime_sha256, got $actual_runtime_sha256" >&2
    exit 1
  fi
}

learning_center_resolve_ai_bundle_dir() {
  local candidate="${1:-${CITRATE_AI_BUNDLE_DIR:-}}"
  if [[ -z "$candidate" ]]; then
    return 1
  fi

  learning_center_validate_ai_bundle_dir "$candidate"

  printf '%s\n' "$(cd "$candidate" && pwd)"
}

learning_center_ai_bundle_name() {
  local bundle_dir="$1"
  basename "$bundle_dir"
}

learning_center_copy_ai_bundle_into_root() {
  local bundle_dir="$1"
  local pkg_root="$2"
  local install_rel="$3"
  local bundle_name
  bundle_name="$(learning_center_ai_bundle_name "$bundle_dir")"

  mkdir -p "$pkg_root/$install_rel"
  cp -R "$bundle_dir" "$pkg_root/$install_rel/$bundle_name"
}
