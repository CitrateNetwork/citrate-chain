// node/src/bundled_model.rs
//
// Auto-register pre-loaded curriculum model on first launch.
// Reads manifest from models/curriculum/manifest.json and registers
// in the local model registry if not already present.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Model manifest matching models/curriculum/manifest.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundledModelManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub framework: String,
    pub license: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(rename = "systemPrompt")]
    #[serde(default)]
    pub system_prompt: String,
}

/// Result of loading a bundled model
#[derive(Debug)]
pub struct BundledModelInfo {
    pub manifest: BundledModelManifest,
    pub manifest_hash: String,
    pub model_dir: PathBuf,
}

/// Discover bundled models in the given directory
pub fn discover_bundled_models(models_dir: &Path) -> Vec<BundledModelInfo> {
    let mut models = Vec::new();

    let curriculum_dir = models_dir.join("curriculum");
    let manifest_path = curriculum_dir.join("manifest.json");

    if manifest_path.exists() {
        match std::fs::read_to_string(&manifest_path) {
            Ok(content) => {
                // Compute SHA-256 of manifest for integrity
                let mut hasher = Sha256::new();
                hasher.update(content.as_bytes());
                let hash = hex::encode(hasher.finalize());

                match serde_json::from_str::<BundledModelManifest>(&content) {
                    Ok(manifest) => {
                        tracing::info!(
                            "Discovered bundled model: {} v{} (hash: {})",
                            manifest.name, manifest.version, &hash[..16]
                        );
                        models.push(BundledModelInfo {
                            manifest,
                            manifest_hash: hash,
                            model_dir: curriculum_dir,
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse bundled model manifest: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to read bundled model manifest: {}", e);
            }
        }
    }

    models
}

/// Verify integrity of all files in a model directory against checksums.sha256
pub fn verify_model_integrity(model_dir: &Path) -> Result<bool, String> {
    let checksum_path = model_dir.join("checksums.sha256");
    if !checksum_path.exists() {
        return Ok(true); // No checksums = skip verification
    }

    let content = std::fs::read_to_string(&checksum_path)
        .map_err(|e| format!("Failed to read checksums: {}", e))?;

    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(2, "  ").collect();
        if parts.len() != 2 {
            continue;
        }
        let expected_hash = parts[0].trim();
        let file_path = model_dir.join(parts[1].trim().trim_start_matches("./"));

        if !file_path.exists() {
            return Err(format!("Missing file: {}", parts[1]));
        }

        let file_bytes = std::fs::read(&file_path)
            .map_err(|e| format!("Failed to read {}: {}", parts[1], e))?;

        let mut hasher = Sha256::new();
        hasher.update(&file_bytes);
        let actual_hash = hex::encode(hasher.finalize());

        if actual_hash != expected_hash {
            return Err(format!(
                "Integrity check failed for {}: expected {}, got {}",
                parts[1], expected_hash, actual_hash
            ));
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_discover_no_models() {
        let dir = TempDir::new().unwrap();
        let models = discover_bundled_models(dir.path());
        assert!(models.is_empty());
    }

    #[test]
    fn test_discover_curriculum_model() {
        let dir = TempDir::new().unwrap();
        let curriculum = dir.path().join("curriculum");
        fs::create_dir_all(&curriculum).unwrap();
        fs::write(
            curriculum.join("manifest.json"),
            r#"{"name":"test","version":"1.0","description":"test model","framework":"gguf","license":"Apache-2.0"}"#,
        ).unwrap();

        let models = discover_bundled_models(dir.path());
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].manifest.name, "test");
        assert_eq!(models[0].manifest.version, "1.0");
    }

    #[test]
    fn test_verify_integrity_no_checksums() {
        let dir = TempDir::new().unwrap();
        assert!(verify_model_integrity(dir.path()).unwrap());
    }

    #[test]
    fn test_verify_integrity_valid() {
        let dir = TempDir::new().unwrap();
        let test_content = b"hello world";
        fs::write(dir.path().join("test.txt"), test_content).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(test_content);
        let hash = hex::encode(hasher.finalize());

        fs::write(
            dir.path().join("checksums.sha256"),
            format!("{}  ./test.txt\n", hash),
        ).unwrap();

        assert!(verify_model_integrity(dir.path()).unwrap());
    }

    #[test]
    fn test_verify_integrity_tampered() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("test.txt"), b"hello world").unwrap();
        fs::write(
            dir.path().join("checksums.sha256"),
            "0000000000000000000000000000000000000000000000000000000000000000  ./test.txt\n",
        ).unwrap();

        assert!(verify_model_integrity(dir.path()).is_err());
    }
}
