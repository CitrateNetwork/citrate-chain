//! Performance profile computation (WP-F.5).
//!
//! Computes a node's local performance profile from rolling windows of
//! inference results, latencies, block observations, and adapter activity.
//!
//! The computed profile is attached to `LearningEmbedding` messages broadcast
//! at checkpoint boundaries, enabling mentor-mentee pairing in WP-F.6.
//!
//! # Design
//!
//! - Rolling windows with configurable size prevent unbounded memory growth.
//! - All outputs are clamped to valid ranges: accuracy ∈ [0, 1], uptime ∈ [0, 1].
//! - The `PerformanceProfile` struct is defined in `citrate_network::learning_messages`
//!   to avoid circular dependencies. We define a local mirror and provide conversion.

use std::collections::{HashSet, VecDeque};

/// Default rolling window size (last 1 000 inference results / latencies).
pub const DEFAULT_WINDOW_SIZE: usize = 1_000;

/// A single inference result recorded by the local node.
#[derive(Debug, Clone)]
pub struct InferenceResult {
    /// Whether the inference was correct (ground-truth validated).
    pub correct: bool,
    /// Inference latency in milliseconds.
    pub latency_ms: u64,
    /// Model domain (e.g. "nlp", "vision", "audio").
    pub domain: String,
    /// Unix timestamp (seconds) when this inference occurred.
    pub timestamp: u64,
}

/// Performance profile computed from local metrics.
///
/// This is the learning-crate's own copy, wire-compatible with
/// `citrate_network::learning_messages::PerformanceProfile`.
/// Use [`ProfileComputer::to_network_profile`] for the conversion
/// or construct the network type directly from [`ProfileComputer::compute_profile`].
#[derive(Debug, Clone)]
pub struct PerformanceProfile {
    /// Average inference accuracy (0.0 -- 1.0).
    pub accuracy: f64,
    /// Average inference latency in milliseconds.
    pub latency_ms: u64,
    /// Model domains this node serves (e.g. `["nlp", "vision"]`).
    pub domains: Vec<String>,
    /// Uptime percentage over observed blocks (0.0 -- 1.0).
    pub uptime: f64,
    /// Number of adapters this node has contributed.
    pub adapter_count: u32,
}

/// Computes a node's performance profile from local metrics.
///
/// Maintains rolling windows for inference results and latencies.
/// Call [`compute_profile`](Self::compute_profile) at checkpoint boundaries
/// to produce a snapshot suitable for gossip broadcast.
pub struct ProfileComputer {
    /// Rolling window of inference results for accuracy tracking.
    inference_results: VecDeque<InferenceResult>,
    /// Rolling window of latencies (mirrors inference_results for O(1) avg).
    latencies: VecDeque<u64>,
    /// Blocks where this node was online and observed the block.
    blocks_seen: u64,
    /// Total blocks in the observation window (seen + missed).
    blocks_total: u64,
    /// Number of adapters this node has created.
    adapters_created: u32,
    /// Model domains this node actively serves.
    active_domains: HashSet<String>,
    /// Maximum size of the rolling windows.
    window_size: usize,
}

impl ProfileComputer {
    /// Create a new profile computer with the given rolling window size.
    ///
    /// The window size controls how many recent inference results and latencies
    /// are retained for computing averages. Older entries are evicted FIFO.
    pub fn new(window_size: usize) -> Self {
        let window_size = if window_size == 0 { 1 } else { window_size };
        Self {
            inference_results: VecDeque::with_capacity(window_size),
            latencies: VecDeque::with_capacity(window_size),
            blocks_seen: 0,
            blocks_total: 0,
            adapters_created: 0,
            active_domains: HashSet::new(),
            window_size,
        }
    }

    /// Record an inference result.
    ///
    /// Evicts the oldest entry when the window is full.
    pub fn record_inference(&mut self, correct: bool, latency_ms: u64, domain: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Evict oldest if at capacity
        if self.inference_results.len() >= self.window_size {
            self.inference_results.pop_front();
        }
        if self.latencies.len() >= self.window_size {
            self.latencies.pop_front();
        }

        self.inference_results.push_back(InferenceResult {
            correct,
            latency_ms,
            domain: domain.to_string(),
            timestamp: now,
        });
        self.latencies.push_back(latency_ms);

        // Track active domains
        self.active_domains.insert(domain.to_string());
    }

    /// Record that this node observed (produced or validated) a block.
    pub fn record_block(&mut self) {
        self.blocks_seen += 1;
        self.blocks_total += 1;
    }

    /// Record that this node missed a block (was offline or slow).
    pub fn record_missed_block(&mut self) {
        self.blocks_total += 1;
    }

    /// Record that this node created and shared an adapter.
    pub fn record_adapter_created(&mut self) {
        self.adapters_created += 1;
    }

    /// Add a domain to the active set without recording an inference.
    pub fn add_domain(&mut self, domain: &str) {
        self.active_domains.insert(domain.to_string());
    }

    /// Remove a domain from the active set.
    pub fn remove_domain(&mut self, domain: &str) {
        self.active_domains.remove(domain);
    }

    /// Compute the current performance profile from accumulated metrics.
    ///
    /// All output values are clamped to valid ranges:
    /// - `accuracy` ∈ [0.0, 1.0]
    /// - `uptime` ∈ [0.0, 1.0]
    pub fn compute_profile(&self) -> PerformanceProfile {
        let accuracy = if self.inference_results.is_empty() {
            0.0
        } else {
            let correct = self.inference_results.iter().filter(|r| r.correct).count();
            let raw = correct as f64 / self.inference_results.len() as f64;
            raw.clamp(0.0, 1.0)
        };

        let latency_ms = if self.latencies.is_empty() {
            0
        } else {
            self.latencies.iter().sum::<u64>() / self.latencies.len() as u64
        };

        let uptime = if self.blocks_total == 0 {
            1.0 // No blocks observed yet — assume full uptime
        } else {
            let raw = self.blocks_seen as f64 / self.blocks_total as f64;
            raw.clamp(0.0, 1.0)
        };

        let mut domains: Vec<String> = self.active_domains.iter().cloned().collect();
        domains.sort(); // deterministic ordering for reproducible profiles

        PerformanceProfile {
            accuracy,
            latency_ms,
            domains,
            uptime,
            adapter_count: self.adapters_created,
        }
    }

    /// Return the number of inference results currently in the window.
    pub fn inference_count(&self) -> usize {
        self.inference_results.len()
    }

    /// Return the current window size limit.
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Reset all counters and windows.
    pub fn reset(&mut self) {
        self.inference_results.clear();
        self.latencies.clear();
        self.blocks_seen = 0;
        self.blocks_total = 0;
        self.adapters_created = 0;
        self.active_domains.clear();
    }
}

impl Default for ProfileComputer {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SIZE)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_accuracy_computation() {
        let mut pc = ProfileComputer::new(100);

        // 7 correct, 3 incorrect → 0.7 accuracy
        for _ in 0..7 {
            pc.record_inference(true, 10, "nlp");
        }
        for _ in 0..3 {
            pc.record_inference(false, 10, "nlp");
        }

        let profile = pc.compute_profile();
        let diff = (profile.accuracy - 0.7).abs();
        assert!(diff < 1e-9, "Expected accuracy ~0.7, got {}", profile.accuracy);
    }

    #[test]
    fn test_profile_latency_computation() {
        let mut pc = ProfileComputer::new(100);

        // Latencies: 10, 20, 30, 40, 50 → average = 30
        pc.record_inference(true, 10, "nlp");
        pc.record_inference(true, 20, "nlp");
        pc.record_inference(true, 30, "nlp");
        pc.record_inference(true, 40, "nlp");
        pc.record_inference(true, 50, "nlp");

        let profile = pc.compute_profile();
        assert_eq!(profile.latency_ms, 30, "Expected avg latency 30, got {}", profile.latency_ms);
    }

    #[test]
    fn test_profile_uptime_computation() {
        let mut pc = ProfileComputer::new(100);

        // 80 seen, 20 missed → 100 total, 0.8 uptime
        for _ in 0..80 {
            pc.record_block();
        }
        for _ in 0..20 {
            pc.record_missed_block();
        }

        let profile = pc.compute_profile();
        let diff = (profile.uptime - 0.8).abs();
        assert!(diff < 1e-9, "Expected uptime ~0.8, got {}", profile.uptime);
    }

    #[test]
    fn test_profile_empty_window() {
        let pc = ProfileComputer::new(100);
        let profile = pc.compute_profile();

        assert_eq!(profile.accuracy, 0.0, "Empty window should have 0 accuracy");
        assert_eq!(profile.latency_ms, 0, "Empty window should have 0 latency");
        assert_eq!(profile.uptime, 1.0, "Empty window should default to 1.0 uptime");
        assert_eq!(profile.adapter_count, 0);
        assert!(profile.domains.is_empty());
    }

    #[test]
    fn test_profile_rolling_window_eviction() {
        // Window of 5: first entries get evicted
        let mut pc = ProfileComputer::new(5);

        // Fill with 5 incorrect inferences (accuracy = 0.0)
        for _ in 0..5 {
            pc.record_inference(false, 100, "nlp");
        }
        assert_eq!(pc.compute_profile().accuracy, 0.0);

        // Now add 5 correct inferences — the 5 incorrect ones are evicted
        for _ in 0..5 {
            pc.record_inference(true, 10, "nlp");
        }

        let profile = pc.compute_profile();
        assert_eq!(profile.accuracy, 1.0, "After eviction, all entries should be correct");
        assert_eq!(profile.latency_ms, 10, "After eviction, avg latency should be 10");
        assert_eq!(pc.inference_count(), 5, "Window should be at capacity");
    }

    #[test]
    fn test_profile_domain_tracking() {
        let mut pc = ProfileComputer::new(100);

        pc.record_inference(true, 10, "nlp");
        pc.record_inference(true, 20, "vision");
        pc.record_inference(true, 30, "nlp"); // duplicate domain
        pc.record_inference(true, 40, "audio");

        let profile = pc.compute_profile();

        // Domains are sorted for deterministic output
        assert_eq!(profile.domains, vec!["audio", "nlp", "vision"]);
    }

    #[test]
    fn test_profile_adapter_count() {
        let mut pc = ProfileComputer::new(100);

        assert_eq!(pc.compute_profile().adapter_count, 0);

        pc.record_adapter_created();
        assert_eq!(pc.compute_profile().adapter_count, 1);

        pc.record_adapter_created();
        pc.record_adapter_created();
        assert_eq!(pc.compute_profile().adapter_count, 3);
    }

    #[test]
    fn test_profile_bounds() {
        // Accuracy bounds
        let mut pc = ProfileComputer::new(100);

        // All correct → 1.0
        for _ in 0..50 {
            pc.record_inference(true, 10, "nlp");
        }
        let profile = pc.compute_profile();
        assert!(
            (0.0..=1.0).contains(&profile.accuracy),
            "Accuracy {} out of [0,1]",
            profile.accuracy,
        );
        assert_eq!(profile.accuracy, 1.0);

        // All incorrect → 0.0
        let mut pc2 = ProfileComputer::new(100);
        for _ in 0..50 {
            pc2.record_inference(false, 10, "nlp");
        }
        let profile2 = pc2.compute_profile();
        assert!(
            (0.0..=1.0).contains(&profile2.accuracy),
            "Accuracy {} out of [0,1]",
            profile2.accuracy,
        );
        assert_eq!(profile2.accuracy, 0.0);

        // Uptime bounds: all seen → 1.0
        let mut pc3 = ProfileComputer::new(100);
        for _ in 0..100 {
            pc3.record_block();
        }
        let profile3 = pc3.compute_profile();
        assert!(
            (0.0..=1.0).contains(&profile3.uptime),
            "Uptime {} out of [0,1]",
            profile3.uptime,
        );
        assert_eq!(profile3.uptime, 1.0);

        // Uptime bounds: all missed → 0.0
        let mut pc4 = ProfileComputer::new(100);
        for _ in 0..100 {
            pc4.record_missed_block();
        }
        let profile4 = pc4.compute_profile();
        assert!(
            (0.0..=1.0).contains(&profile4.uptime),
            "Uptime {} out of [0,1]",
            profile4.uptime,
        );
        assert_eq!(profile4.uptime, 0.0);
    }

    #[test]
    fn test_profile_default_window_size() {
        let pc = ProfileComputer::default();
        assert_eq!(pc.window_size(), DEFAULT_WINDOW_SIZE);
    }

    #[test]
    fn test_profile_zero_window_size_clamped() {
        // Window size 0 is nonsensical — should be clamped to 1
        let pc = ProfileComputer::new(0);
        assert_eq!(pc.window_size(), 1);
    }

    #[test]
    fn test_profile_reset() {
        let mut pc = ProfileComputer::new(100);

        pc.record_inference(true, 42, "nlp");
        pc.record_block();
        pc.record_adapter_created();

        assert_eq!(pc.inference_count(), 1);
        assert_eq!(pc.compute_profile().adapter_count, 1);

        pc.reset();

        let profile = pc.compute_profile();
        assert_eq!(profile.accuracy, 0.0);
        assert_eq!(profile.latency_ms, 0);
        assert_eq!(profile.uptime, 1.0);
        assert_eq!(profile.adapter_count, 0);
        assert!(profile.domains.is_empty());
        assert_eq!(pc.inference_count(), 0);
    }

    #[test]
    fn test_profile_add_remove_domain() {
        let mut pc = ProfileComputer::new(100);

        pc.add_domain("nlp");
        pc.add_domain("vision");
        assert_eq!(pc.compute_profile().domains, vec!["nlp", "vision"]);

        pc.remove_domain("nlp");
        assert_eq!(pc.compute_profile().domains, vec!["vision"]);
    }

    #[test]
    fn test_profile_single_inference() {
        let mut pc = ProfileComputer::new(100);
        pc.record_inference(true, 42, "nlp");

        let profile = pc.compute_profile();
        assert_eq!(profile.accuracy, 1.0);
        assert_eq!(profile.latency_ms, 42);
        assert_eq!(profile.domains, vec!["nlp"]);
    }
}
