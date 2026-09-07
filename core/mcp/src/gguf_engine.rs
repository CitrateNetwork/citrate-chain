// citrate/core/mcp/src/gguf_engine.rs

/// GGUF Model Inference Engine using llama.cpp
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;
use tracing::{debug, info, warn};

/// GGUF model types supported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelType {
    /// Embedding model (e.g., BGE-M3)
    Embedding,
    /// Text generation model (e.g., Mistral, Llama)
    TextGeneration,
}

/// GGUF inference engine configuration
#[derive(Debug, Clone)]
pub struct GGUFEngineConfig {
    /// Path to llama.cpp build directory
    pub llama_cpp_path: PathBuf,
    /// Path to models directory for caching
    pub models_dir: PathBuf,
    /// Number of threads for inference
    pub threads: usize,
    /// Context size for LLMs
    pub context_size: usize,
}

impl Default for GGUFEngineConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            llama_cpp_path: home.join("llama.cpp"),
            models_dir: home.join(".citrate/models"),
            threads: num_cpus::get(),
            context_size: 32768,
        }
    }
}

/// GGUF inference engine
pub struct GGUFEngine {
    config: GGUFEngineConfig,
}

impl GGUFEngine {
    /// Create a new GGUF inference engine
    pub fn new(config: GGUFEngineConfig) -> Result<Self> {
        // Verify llama.cpp exists
        let main_binary = config.llama_cpp_path.join("build/bin/llama-cli");
        let embedding_binary = config.llama_cpp_path.join("build/bin/llama-embedding");

        if !main_binary.exists() && !config.llama_cpp_path.join("build/bin/main").exists() {
            warn!(
                "llama.cpp binary not found at {:?}, inference will be limited",
                main_binary
            );
        }

        if !embedding_binary.exists() && !config.llama_cpp_path.join("build/bin/embedding").exists() {
            warn!(
                "llama.cpp embedding binary not found at {:?}",
                embedding_binary
            );
        }

        // Create models directory if it doesn't exist
        std::fs::create_dir_all(&config.models_dir)?;

        Ok(Self { config })
    }

    /// Execute text generation inference
    pub async fn generate_text(
        &self,
        model_path: &Path,
        prompt: &str,
        max_tokens: usize,
        temperature: f32,
    ) -> Result<String> {
        info!(
            "Generating text with model: {:?}, max_tokens: {}, temp: {}",
            model_path, max_tokens, temperature
        );

        // Find llama.cpp binary (try both old and new names)
        let binary = self.find_llama_binary("llama-cli", "main")?;

        // CHAIN-B-D015: when this runs INSIDE consensus transaction execution, the output
        // (and the gas derived from it) is committed to state, so it MUST be deterministic
        // across nodes. `temperature` (caller-supplied) and `-t num_cpus::get()` made two
        // honest validators with different core counts / RNG reach different outputs and
        // therefore different state roots — a fork on ordinary traffic. Force greedy,
        // single-threaded, seeded decoding regardless of caller input. (Residual
        // cross-architecture floating-point divergence is a deeper limitation; the sound
        // long-term fix is to move inference out of consensus and commit only a hash — see
        // the finding. This closes the finding's exact scenario: differing core counts.)
        let _ = temperature; // deliberately ignored on the consensus path
        let args =
            deterministic_generate_args(model_path, prompt, max_tokens, self.config.context_size);

        // Build command
        let output = Command::new(binary)
            .args(&args)
            .output()
            .context("Failed to execute llama.cpp")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("llama.cpp execution failed: {}", stderr));
        }

        let text = String::from_utf8_lossy(&output.stdout);
        Ok(text.trim().to_string())
    }

    /// Execute embedding inference
    pub async fn generate_embeddings(
        &self,
        model_path: &Path,
        texts: &[String],
    ) -> Result<Vec<Vec<f32>>> {
        info!(
            "Generating embeddings with model: {:?} for {} texts",
            model_path,
            texts.len()
        );

        let binary = self.find_llama_binary("llama-embedding", "embedding")?;

        let mut all_embeddings = Vec::new();

        for text in texts {
            let output = Command::new(&binary)
                .arg("-m")
                .arg(model_path)
                .arg("-p")
                .arg(text)
                .arg("-t")
                .arg(self.config.threads.to_string())
                .output()
                .context("Failed to execute llama-embedding")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Embedding generation failed: {}", stderr);
                // Return zero embedding as fallback
                all_embeddings.push(vec![0.0; 1024]);
                continue;
            }

            // Parse embedding output (llama.cpp outputs embeddings as JSON or space-separated)
            let output_str = String::from_utf8_lossy(&output.stdout);
            let embedding = self.parse_embedding_output(&output_str)?;
            all_embeddings.push(embedding);
        }

        Ok(all_embeddings)
    }

    /// Execute chat completion with message history
    pub async fn chat_completion(
        &self,
        model_path: &Path,
        messages: &[ChatMessage],
        max_tokens: usize,
        temperature: f32,
    ) -> Result<String> {
        // Format messages into a prompt
        let prompt = self.format_chat_prompt(messages);

        // Use standard text generation
        self.generate_text(model_path, &prompt, max_tokens, temperature)
            .await
    }

    /// Load model from bytes (for genesis-embedded models)
    pub async fn load_model_from_bytes(
        &self,
        model_id: &str,
        model_bytes: &[u8],
    ) -> Result<PathBuf> {
        let model_path = self.config.models_dir.join(format!("{}.gguf", model_id));

        // Check if already cached
        if model_path.exists() {
            let existing_size = fs::metadata(&model_path).await?.len();
            if existing_size == model_bytes.len() as u64 {
                debug!("Model {} already cached at {:?}", model_id, model_path);
                return Ok(model_path);
            }
        }

        // Write model to disk
        info!("Caching model {} to {:?}", model_id, model_path);
        fs::write(&model_path, model_bytes).await?;

        Ok(model_path)
    }

    /// Get model path from IPFS download
    pub fn get_ipfs_model_path(&self, model_id: &str) -> PathBuf {
        self.config.models_dir.join(format!("{}.gguf", model_id))
    }

    /// Find llama.cpp binary (supporting both old and new naming)
    fn find_llama_binary(&self, new_name: &str, old_name: &str) -> Result<PathBuf> {
        let new_path = self.config.llama_cpp_path.join("build/bin").join(new_name);
        let old_path = self.config.llama_cpp_path.join("build/bin").join(old_name);

        if new_path.exists() {
            Ok(new_path)
        } else if old_path.exists() {
            Ok(old_path)
        } else {
            Err(anyhow!(
                "llama.cpp binary not found. Tried: {:?} and {:?}",
                new_path,
                old_path
            ))
        }
    }

    /// Parse embedding output from llama.cpp
    fn parse_embedding_output(&self, output: &str) -> Result<Vec<f32>> {
        // llama.cpp outputs embeddings in various formats
        // Try JSON first
        if let Ok(json_array) = serde_json::from_str::<Vec<f32>>(output.trim()) {
            return Ok(json_array);
        }

        // Try space-separated
        let values: Result<Vec<f32>, _> = output
            .split_whitespace()
            .map(|s| s.parse::<f32>())
            .collect();

        if let Ok(embedding) = values {
            if !embedding.is_empty() {
                return Ok(embedding);
            }
        }

        // Fallback: return zero embedding
        warn!("Failed to parse embedding output, using zeros");
        Ok(vec![0.0; 1024])
    }

    /// Format chat messages into a prompt
    fn format_chat_prompt(&self, messages: &[ChatMessage]) -> String {
        let mut prompt = String::new();

        for msg in messages {
            match msg.role.as_str() {
                "system" => prompt.push_str(&format!("### System:\n{}\n\n", msg.content)),
                "user" => prompt.push_str(&format!("### User:\n{}\n\n", msg.content)),
                "assistant" => prompt.push_str(&format!("### Assistant:\n{}\n\n", msg.content)),
                _ => prompt.push_str(&format!("### {}:\n{}\n\n", msg.role, msg.content)),
            }
        }

        prompt.push_str("### Assistant:\n");
        prompt
    }
}

/// Chat message for structured conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// CHAIN-B-D015: build the `llama-cli` argument vector for a DETERMINISTIC text generation.
///
/// Inference output committed to consensus state must be reproducible across nodes, so the
/// decoder is pinned to greedy (`--top-k 1 --temp 0`), seeded (`--seed 0`), single-threaded
/// (`-t 1`) generation — independent of any caller-supplied temperature or the host core
/// count. Factored into a pure function so a test can assert these flags are present without
/// spawning the subprocess.
fn deterministic_generate_args(
    model_path: &Path,
    prompt: &str,
    max_tokens: usize,
    context_size: usize,
) -> Vec<String> {
    vec![
        "-m".to_string(),
        model_path.to_string_lossy().into_owned(),
        "-p".to_string(),
        prompt.to_string(),
        "-n".to_string(),
        max_tokens.to_string(),
        // Deterministic decoding (consensus-safety): seeded, greedy, zero-temperature.
        "--seed".to_string(),
        "0".to_string(),
        "--top-k".to_string(),
        "1".to_string(),
        "--temp".to_string(),
        "0".to_string(),
        // Single thread: thread count must not change the result across differently-sized nodes.
        "-t".to_string(),
        "1".to_string(),
        "-c".to_string(),
        context_size.to_string(),
        "--no-display-prompt".to_string(),
    ]
}

/// Compute cosine similarity between two embeddings
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }

    let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let magnitude_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let magnitude_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if magnitude_a == 0.0 || magnitude_b == 0.0 {
        return 0.0;
    }

    dot_product / (magnitude_a * magnitude_b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CHAIN-B-D015 tripwire: consensus inference must pin deterministic decoding flags and
    /// a single thread, and must NOT thread the host core count or a caller temperature into
    /// the subprocess. If any of these regress, two honest validators fork.
    #[test]
    fn generate_args_are_deterministic_and_thread_count_independent() {
        let args = deterministic_generate_args(Path::new("/models/m.gguf"), "hello", 128, 4096);

        // Helper: value following a flag.
        let val = |flag: &str| -> Option<String> {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1).cloned())
        };

        assert_eq!(val("--seed").as_deref(), Some("0"), "must seed the RNG");
        assert_eq!(
            val("--top-k").as_deref(),
            Some("1"),
            "must be greedy (top-k 1)"
        );
        assert_eq!(
            val("--temp").as_deref(),
            Some("0"),
            "must be zero-temperature"
        );
        assert_eq!(
            val("-t").as_deref(),
            Some("1"),
            "must be single-threaded; a num_cpus-derived thread count forks the fleet"
        );
        // The host core count must never appear as the thread argument.
        let cpus = num_cpus::get();
        if cpus != 1 {
            assert_ne!(
                val("-t").as_deref(),
                Some(cpus.to_string().as_str()),
                "thread count must not be derived from num_cpus::get()"
            );
        }
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 2.0, 3.0];
        let b = vec![4.0, 5.0, 6.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim > 0.9); // Similar vectors
    }

    #[test]
    fn test_format_chat_prompt() {
        let config = GGUFEngineConfig::default();
        let engine = GGUFEngine::new(config).unwrap();

        let messages = vec![
            ChatMessage {
                role: "user".to_string(),
                content: "Hello".to_string(),
            },
        ];

        let prompt = engine.format_chat_prompt(&messages);
        assert!(prompt.contains("### User:"));
        assert!(prompt.contains("Hello"));
        assert!(prompt.contains("### Assistant:"));
    }
}
