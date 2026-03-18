// citrate/core/mcp/src/provider.rs

// Provider registry for compute providers
use crate::types::{ComputeCapacity, HardwareType, ModelId, ProviderInfo};
use anyhow::Result;
use citrate_execution::Address;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Provider registry for compute providers
pub struct ProviderRegistry {
    providers: Arc<RwLock<HashMap<Address, ProviderInfo>>>,
    model_providers: Arc<RwLock<HashMap<ModelId, Vec<Address>>>>,
    reputation_scores: Arc<RwLock<HashMap<Address, ReputationScore>>>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            model_providers: Arc::new(RwLock::new(HashMap::new())),
            reputation_scores: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReputationScore {
    pub total_jobs: u64,
    pub successful_jobs: u64,
    pub failed_jobs: u64,
    pub average_latency: u64,
    pub uptime_percentage: f64,
    pub last_active: u64,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            model_providers: Arc::new(RwLock::new(HashMap::new())),
            reputation_scores: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new provider
    pub async fn register_provider(&self, info: ProviderInfo) -> Result<()> {
        let address = info.address;

        // Initialize reputation score
        let reputation = ReputationScore {
            total_jobs: 0,
            successful_jobs: 0,
            failed_jobs: 0,
            average_latency: 0,
            uptime_percentage: 100.0,
            last_active: chrono::Utc::now().timestamp() as u64,
        };

        self.providers.write().await.insert(address, info.clone());
        self.reputation_scores
            .write()
            .await
            .insert(address, reputation);

        info!(
            "Provider registered: {} with capacity: {} GB memory, {} compute units",
            hex::encode(&address.0[..8]),
            info.capacity.total_memory / (1024 * 1024 * 1024),
            info.capacity.total_compute
        );

        Ok(())
    }

    /// Register provider for a specific model
    pub async fn register_model_provider(
        &self,
        provider: Address,
        model_id: ModelId,
    ) -> Result<()> {
        // Check provider exists
        if !self.providers.read().await.contains_key(&provider) {
            return Err(anyhow::anyhow!("Provider not registered"));
        }

        // Add to model providers
        let mut model_providers = self.model_providers.write().await;
        model_providers
            .entry(model_id)
            .or_insert_with(Vec::new)
            .push(provider);

        debug!(
            "Provider {} registered for model {:?}",
            hex::encode(&provider.0[..8]),
            hex::encode(&model_id.0[..8])
        );

        Ok(())
    }

    /// Select best provider for a model
    pub async fn select_provider(
        &self,
        model_id: &ModelId,
        requirements: &crate::types::ComputeRequirements,
    ) -> Result<Address> {
        // Get available providers for model
        let model_providers = self.model_providers.read().await;
        let providers = model_providers
            .get(model_id)
            .ok_or_else(|| anyhow::anyhow!("No providers for model"))?;

        // Filter by capacity and requirements
        let provider_infos = self.providers.read().await;
        let reputation_scores = self.reputation_scores.read().await;

        let mut candidates: Vec<(Address, f64)> = Vec::new();

        for provider_addr in providers {
            if let Some(info) = provider_infos.get(provider_addr) {
                // Check if provider meets requirements
                if !self.meets_requirements(&info.capacity, requirements) {
                    continue;
                }

                // Calculate score based on reputation and availability
                let score = self
                    .calculate_provider_score(&info.capacity, reputation_scores.get(provider_addr));

                candidates.push((*provider_addr, score));
            }
        }

        if candidates.is_empty() {
            return Err(anyhow::anyhow!("No suitable providers available"));
        }

        // Sort by score and select best
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        Ok(candidates[0].0)
    }

    /// Update provider reputation
    pub async fn update_reputation(
        &self,
        provider: Address,
        success: bool,
        latency: u64,
    ) -> Result<()> {
        let mut scores = self.reputation_scores.write().await;
        let score = scores
            .get_mut(&provider)
            .ok_or_else(|| anyhow::anyhow!("Provider not found"))?;

        score.total_jobs += 1;
        if success {
            score.successful_jobs += 1;
        } else {
            score.failed_jobs += 1;
        }

        // Update average latency
        score.average_latency =
            (score.average_latency * (score.total_jobs - 1) + latency) / score.total_jobs;
        score.last_active = chrono::Utc::now().timestamp() as u64;

        // Update provider info reputation
        if let Some(info) = self.providers.write().await.get_mut(&provider) {
            info.reputation = score.successful_jobs * 100 / score.total_jobs;
            info.total_executions = score.total_jobs;
        }

        Ok(())
    }

    /// Check if provider meets requirements
    fn meets_requirements(
        &self,
        capacity: &ComputeCapacity,
        requirements: &crate::types::ComputeRequirements,
    ) -> bool {
        // Check memory
        if capacity.available_memory < requirements.min_memory {
            return false;
        }

        // Check compute
        if capacity.available_compute < requirements.min_compute {
            return false;
        }

        // Check GPU requirement
        if requirements.gpu_required {
            let has_gpu = capacity
                .hardware
                .iter()
                .any(|h| matches!(h, HardwareType::GPU(_)));
            if !has_gpu {
                return false;
            }
        }

        true
    }

    /// Calculate provider score
    fn calculate_provider_score(
        &self,
        capacity: &ComputeCapacity,
        reputation: Option<&ReputationScore>,
    ) -> f64 {
        let mut score = 0.0;

        // Capacity score (0-40 points)
        let memory_ratio = capacity.available_memory as f64 / capacity.total_memory as f64;
        let compute_ratio = capacity.available_compute as f64 / capacity.total_compute as f64;
        score += memory_ratio * 20.0 + compute_ratio * 20.0;

        // Reputation score (0-60 points)
        if let Some(rep) = reputation {
            let success_rate = if rep.total_jobs > 0 {
                rep.successful_jobs as f64 / rep.total_jobs as f64
            } else {
                1.0 // New provider gets benefit of doubt
            };

            score += success_rate * 30.0;
            score += rep.uptime_percentage * 0.2;

            // Latency score (lower is better)
            if rep.average_latency > 0 {
                let latency_score = (1000.0 / rep.average_latency as f64).min(10.0);
                score += latency_score;
            }
        } else {
            score += 30.0; // Default score for new providers
        }

        score
    }

    /// Get provider info
    pub async fn get_provider(&self, address: &Address) -> Result<ProviderInfo> {
        self.providers
            .read()
            .await
            .get(address)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Provider not found"))
    }

    /// List all providers
    pub async fn list_providers(&self) -> Vec<ProviderInfo> {
        self.providers.read().await.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ComputeRequirements;

    fn create_test_provider(id: u8, memory_gb: u64, compute: u64) -> ProviderInfo {
        let mut addr = [0u8; 20];
        addr[0] = id;
        ProviderInfo {
            address: Address(addr),
            name: format!("Provider {}", id),
            endpoint: format!("http://provider{}.example.com", id),
            capacity: ComputeCapacity {
                total_memory: memory_gb * 1024 * 1024 * 1024,
                available_memory: memory_gb * 1024 * 1024 * 1024 / 2,
                total_compute: compute,
                available_compute: compute / 2,
                hardware: vec![HardwareType::CPU],
            },
            reputation: 100,
            total_executions: 0,
        }
    }

    fn create_test_provider_with_gpu(id: u8, memory_gb: u64, compute: u64) -> ProviderInfo {
        let mut info = create_test_provider(id, memory_gb, compute);
        info.capacity.hardware = vec![
            HardwareType::CPU,
            HardwareType::GPU("NVIDIA A100".to_string()),
        ];
        info
    }

    #[tokio::test]
    async fn test_provider_registry_new() {
        let registry = ProviderRegistry::new();
        let providers = registry.list_providers().await;
        assert!(providers.is_empty());
    }

    #[tokio::test]
    async fn test_provider_registry_default() {
        let registry = ProviderRegistry::default();
        let providers = registry.list_providers().await;
        assert!(providers.is_empty());
    }

    #[tokio::test]
    async fn test_register_provider() {
        let registry = ProviderRegistry::new();
        let provider = create_test_provider(1, 16, 100);

        registry.register_provider(provider.clone()).await.unwrap();

        let providers = registry.list_providers().await;
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name, "Provider 1");
    }

    #[tokio::test]
    async fn test_get_provider() {
        let registry = ProviderRegistry::new();
        let provider = create_test_provider(1, 16, 100);
        let address = provider.address;

        registry.register_provider(provider).await.unwrap();

        let retrieved = registry.get_provider(&address).await.unwrap();
        assert_eq!(retrieved.name, "Provider 1");
    }

    #[tokio::test]
    async fn test_get_nonexistent_provider() {
        let registry = ProviderRegistry::new();
        let address = Address([99u8; 20]);

        let result = registry.get_provider(&address).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_register_model_provider() {
        let registry = ProviderRegistry::new();
        let provider = create_test_provider(1, 16, 100);
        let address = provider.address;
        let model_id = ModelId([1u8; 32]);

        registry.register_provider(provider).await.unwrap();
        registry
            .register_model_provider(address, model_id)
            .await
            .unwrap();

        // Provider should be registered for the model
        let requirements = ComputeRequirements {
            min_memory: 1000,
            min_compute: 10,
            gpu_required: false,
            supported_hardware: vec![HardwareType::CPU],
        };

        let selected = registry.select_provider(&model_id, &requirements).await;
        assert!(selected.is_ok());
        assert_eq!(selected.unwrap(), address);
    }

    #[tokio::test]
    async fn test_register_model_provider_unregistered() {
        let registry = ProviderRegistry::new();
        let address = Address([1u8; 20]);
        let model_id = ModelId([1u8; 32]);

        let result = registry.register_model_provider(address, model_id).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not registered"));
    }

    #[tokio::test]
    async fn test_select_provider_no_providers() {
        let registry = ProviderRegistry::new();
        let model_id = ModelId([1u8; 32]);

        let requirements = ComputeRequirements {
            min_memory: 1000,
            min_compute: 10,
            gpu_required: false,
            supported_hardware: vec![HardwareType::CPU],
        };

        let result = registry.select_provider(&model_id, &requirements).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_select_provider_gpu_required() {
        let registry = ProviderRegistry::new();
        let model_id = ModelId([1u8; 32]);

        // Register CPU-only provider
        let cpu_provider = create_test_provider(1, 32, 200);
        registry.register_provider(cpu_provider.clone()).await.unwrap();
        registry
            .register_model_provider(cpu_provider.address, model_id)
            .await
            .unwrap();

        // Request with GPU requirement
        let requirements = ComputeRequirements {
            min_memory: 1000,
            min_compute: 10,
            gpu_required: true,
            supported_hardware: vec![HardwareType::GPU("any".to_string())],
        };

        // Should fail - no GPU provider
        let result = registry.select_provider(&model_id, &requirements).await;
        assert!(result.is_err());

        // Now register a GPU provider
        let gpu_provider = create_test_provider_with_gpu(2, 32, 200);
        registry.register_provider(gpu_provider.clone()).await.unwrap();
        registry
            .register_model_provider(gpu_provider.address, model_id)
            .await
            .unwrap();

        // Should succeed
        let result = registry.select_provider(&model_id, &requirements).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), gpu_provider.address);
    }

    #[tokio::test]
    async fn test_select_provider_memory_requirement() {
        let registry = ProviderRegistry::new();
        let model_id = ModelId([1u8; 32]);

        // Register provider with 8GB memory (4GB available)
        let provider = create_test_provider(1, 8, 100);
        registry.register_provider(provider.clone()).await.unwrap();
        registry
            .register_model_provider(provider.address, model_id)
            .await
            .unwrap();

        // Request requiring more memory than available
        let requirements = ComputeRequirements {
            min_memory: 10 * 1024 * 1024 * 1024, // 10GB
            min_compute: 10,
            gpu_required: false,
            supported_hardware: vec![HardwareType::CPU],
        };

        let result = registry.select_provider(&model_id, &requirements).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_update_reputation_success() {
        let registry = ProviderRegistry::new();
        let provider = create_test_provider(1, 16, 100);
        let address = provider.address;

        registry.register_provider(provider).await.unwrap();

        // Successful job with 100ms latency
        registry.update_reputation(address, true, 100).await.unwrap();

        let info = registry.get_provider(&address).await.unwrap();
        assert_eq!(info.total_executions, 1);
        assert_eq!(info.reputation, 100); // 1/1 success = 100%
    }

    #[tokio::test]
    async fn test_update_reputation_failure() {
        let registry = ProviderRegistry::new();
        let provider = create_test_provider(1, 16, 100);
        let address = provider.address;

        registry.register_provider(provider).await.unwrap();

        // One success, one failure
        registry.update_reputation(address, true, 100).await.unwrap();
        registry.update_reputation(address, false, 200).await.unwrap();

        let info = registry.get_provider(&address).await.unwrap();
        assert_eq!(info.total_executions, 2);
        assert_eq!(info.reputation, 50); // 1/2 success = 50%
    }

    #[tokio::test]
    async fn test_update_reputation_unknown_provider() {
        let registry = ProviderRegistry::new();
        let address = Address([99u8; 20]);

        let result = registry.update_reputation(address, true, 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multiple_providers_scoring() {
        let registry = ProviderRegistry::new();
        let model_id = ModelId([1u8; 32]);

        // Register provider 1 with lower specs
        let provider1 = create_test_provider(1, 8, 50);
        registry.register_provider(provider1.clone()).await.unwrap();
        registry
            .register_model_provider(provider1.address, model_id)
            .await
            .unwrap();

        // Register provider 2 with higher specs
        let provider2 = create_test_provider(2, 32, 200);
        registry.register_provider(provider2.clone()).await.unwrap();
        registry
            .register_model_provider(provider2.address, model_id)
            .await
            .unwrap();

        // Give provider2 good reputation
        registry.update_reputation(provider2.address, true, 50).await.unwrap();
        registry.update_reputation(provider2.address, true, 50).await.unwrap();

        let requirements = ComputeRequirements {
            min_memory: 1000,
            min_compute: 10,
            gpu_required: false,
            supported_hardware: vec![HardwareType::CPU],
        };

        // Should select provider with better score
        let selected = registry.select_provider(&model_id, &requirements).await.unwrap();
        // Provider 2 should have higher score due to more capacity and good reputation
        assert_eq!(selected, provider2.address);
    }

    #[tokio::test]
    async fn test_list_providers() {
        let registry = ProviderRegistry::new();

        for i in 1..=5u8 {
            let provider = create_test_provider(i, 16, 100);
            registry.register_provider(provider).await.unwrap();
        }

        let providers = registry.list_providers().await;
        assert_eq!(providers.len(), 5);
    }
}
