// citrate/core/mcp/src/cache.rs

// LRU cache for models
use crate::execution::Model;
use crate::types::ModelId;
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// LRU cache for models
pub struct ModelCache {
    cache: Arc<RwLock<HashMap<ModelId, CachedModel>>>,
    lru_queue: Arc<RwLock<VecDeque<ModelId>>>,
    max_size: u64,
    current_size: Arc<RwLock<u64>>,
}

#[derive(Clone)]
struct CachedModel {
    model: Model,
    size: u64,
    last_accessed: u64,
    access_count: u64,
}

impl ModelCache {
    pub fn new(max_size: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            lru_queue: Arc::new(RwLock::new(VecDeque::new())),
            max_size,
            current_size: Arc::new(RwLock::new(0)),
        }
    }

    /// Get model from cache
    pub async fn get(&self, model_id: &ModelId) -> Option<Model> {
        // CHAIN-B-D018: release the `cache` lock BEFORE taking `lru_queue` in
        // `update_lru`. Previously `get` held `cache` (write) across
        // `update_lru` (which takes `lru_queue`), while `evict_lru` takes the
        // two in the opposite order — an ABBA inversion that permanently
        // deadlocks a validator under concurrent `get` + evicting `put`.
        let model = {
            let mut cache = self.cache.write().await;
            match cache.get_mut(model_id) {
                Some(cached) => {
                    cached.last_accessed = chrono::Utc::now().timestamp() as u64;
                    cached.access_count += 1;
                    Some(cached.model.clone())
                }
                None => None,
            }
        }; // `cache` guard dropped here

        if model.is_some() {
            // Move to front of LRU queue (no `cache` guard held).
            self.update_lru(model_id).await;
            debug!("Cache hit for model {:?}", hex::encode(&model_id.0[..8]));
        }

        model
    }

    /// Put model in cache
    pub async fn put(&self, model_id: ModelId, model: Model) -> Result<()> {
        let model_size = self.calculate_model_size(&model);

        // Check if model fits in cache
        if model_size > self.max_size {
            return Err(anyhow::anyhow!("Model too large for cache"));
        }

        // CHAIN-B-D018: if this key is already cached, remove its old accounting
        // first. Previously a re-insert replaced the map entry but still did
        // `*current_size += model_size` and pushed a duplicate into
        // `lru_queue`, so `current_size` drifted upward until the eviction loop
        // below could never satisfy its condition and spun forever.
        {
            let existing = self.cache.write().await.remove(&model_id);
            if let Some(old) = existing {
                *self.current_size.write().await -= old.size;
                self.lru_queue.write().await.retain(|id| id != &model_id);
            }
        }

        // Evict models if necessary. `evict_lru` now reports whether it actually
        // evicted anything; if the queue is empty we stop rather than spin.
        while *self.current_size.read().await + model_size > self.max_size {
            if !self.evict_lru().await? {
                break;
            }
        }

        // Add to cache
        let cached = CachedModel {
            model,
            size: model_size,
            last_accessed: chrono::Utc::now().timestamp() as u64,
            access_count: 1,
        };

        self.cache.write().await.insert(model_id, cached);
        self.lru_queue.write().await.push_front(model_id);
        *self.current_size.write().await += model_size;

        debug!(
            "Cached model {:?} (size: {} bytes)",
            hex::encode(&model_id.0[..8]),
            model_size
        );

        Ok(())
    }

    /// Remove model from cache
    pub async fn remove(&self, model_id: &ModelId) -> Option<Model> {
        let mut cache = self.cache.write().await;

        if let Some(cached) = cache.remove(model_id) {
            *self.current_size.write().await -= cached.size;

            // Remove from LRU queue
            let mut queue = self.lru_queue.write().await;
            queue.retain(|id| id != model_id);

            info!(
                "Removed model {:?} from cache",
                hex::encode(&model_id.0[..8])
            );
            return Some(cached.model);
        }

        None
    }

    /// Clear entire cache
    pub async fn clear(&self) {
        self.cache.write().await.clear();
        self.lru_queue.write().await.clear();
        *self.current_size.write().await = 0;

        info!("Cache cleared");
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let current_size = *self.current_size.read().await;

        let total_models = cache.len();
        let total_accesses: u64 = cache.values().map(|c| c.access_count).sum();

        CacheStats {
            total_models,
            current_size,
            max_size: self.max_size,
            utilization: (current_size as f64 / self.max_size as f64) * 100.0,
            total_accesses,
        }
    }

    /// Preload models into cache
    pub async fn preload(&self, models: Vec<(ModelId, Model)>) -> Result<()> {
        for (model_id, model) in models {
            self.put(model_id, model).await?;
        }

        info!(
            "Preloaded {} models into cache",
            self.cache.read().await.len()
        );
        Ok(())
    }

    /// Update LRU queue
    async fn update_lru(&self, model_id: &ModelId) {
        let mut queue = self.lru_queue.write().await;

        // Remove from current position
        queue.retain(|id| id != model_id);

        // Add to front
        queue.push_front(*model_id);
    }

    /// Evict least recently used model.
    ///
    /// CHAIN-B-D018: returns `true` iff an entry was popped from the LRU queue.
    /// The `put` eviction loop uses this to terminate when there is nothing left
    /// to evict, instead of spinning forever on a drifted `current_size`.
    async fn evict_lru(&self) -> Result<bool> {
        let mut queue = self.lru_queue.write().await;

        if let Some(model_id) = queue.pop_back() {
            if let Some(cached) = self.cache.write().await.remove(&model_id) {
                *self.current_size.write().await -= cached.size;

                debug!(
                    "Evicted model {:?} from cache (LRU)",
                    hex::encode(&model_id.0[..8])
                );
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Calculate model size
    fn calculate_model_size(&self, model: &Model) -> u64 {
        let mut size = 0u64;
        size += model.architecture.len() as u64;
        size += model.weights.len() as u64;
        size += model.metadata.len() as u64;
        size += 32; // ModelId size
        size
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_models: usize,
    pub current_size: u64,
    pub max_size: u64,
    pub utilization: f64,
    pub total_accesses: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ModelId;

    fn create_test_model(id: [u8; 32], size: usize) -> Model {
        Model {
            id: ModelId(id),
            architecture: vec![1; 100],
            weights: vec![2; size],
            metadata: vec![3; 50],
        }
    }

    #[tokio::test]
    async fn test_cache_new() {
        let cache = ModelCache::new(1024 * 1024);
        let stats = cache.stats().await;
        assert_eq!(stats.total_models, 0);
        assert_eq!(stats.current_size, 0);
        assert_eq!(stats.max_size, 1024 * 1024);
    }

    #[tokio::test]
    async fn test_cache_put_and_get() {
        let cache = ModelCache::new(1024 * 1024);
        let model_id = ModelId([1u8; 32]);
        let model = create_test_model([1u8; 32], 500);

        cache.put(model_id, model.clone()).await.unwrap();

        let retrieved = cache.get(&model_id).await;
        assert!(retrieved.is_some());
        let retrieved_model = retrieved.unwrap();
        assert_eq!(retrieved_model.id, model_id);
    }

    #[tokio::test]
    async fn test_cache_get_nonexistent() {
        let cache = ModelCache::new(1024 * 1024);
        let model_id = ModelId([99u8; 32]);

        let retrieved = cache.get(&model_id).await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_cache_remove() {
        let cache = ModelCache::new(1024 * 1024);
        let model_id = ModelId([1u8; 32]);
        let model = create_test_model([1u8; 32], 500);

        cache.put(model_id, model).await.unwrap();
        assert!(cache.get(&model_id).await.is_some());

        let removed = cache.remove(&model_id).await;
        assert!(removed.is_some());
        assert!(cache.get(&model_id).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_remove_nonexistent() {
        let cache = ModelCache::new(1024 * 1024);
        let model_id = ModelId([99u8; 32]);

        let removed = cache.remove(&model_id).await;
        assert!(removed.is_none());
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = ModelCache::new(1024 * 1024);

        // Add multiple models
        for i in 0..5u8 {
            let model_id = ModelId([i; 32]);
            let model = create_test_model([i; 32], 100);
            cache.put(model_id, model).await.unwrap();
        }

        let stats = cache.stats().await;
        assert_eq!(stats.total_models, 5);

        cache.clear().await;

        let stats = cache.stats().await;
        assert_eq!(stats.total_models, 0);
        assert_eq!(stats.current_size, 0);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = ModelCache::new(10000);
        let model = create_test_model([1u8; 32], 500);
        let model_id = ModelId([1u8; 32]);

        cache.put(model_id, model).await.unwrap();

        let stats = cache.stats().await;
        assert_eq!(stats.total_models, 1);
        assert!(stats.current_size > 0);
        assert!(stats.utilization > 0.0);
    }

    #[tokio::test]
    async fn test_cache_lru_eviction() {
        // Create cache with small size to force eviction
        let cache = ModelCache::new(1000); // 1KB

        // Add first model (should fit)
        let model1 = create_test_model([1u8; 32], 300);
        cache.put(ModelId([1u8; 32]), model1).await.unwrap();

        // Add second model (should fit)
        let model2 = create_test_model([2u8; 32], 300);
        cache.put(ModelId([2u8; 32]), model2).await.unwrap();

        // Add third model - should evict first model (LRU)
        let model3 = create_test_model([3u8; 32], 300);
        cache.put(ModelId([3u8; 32]), model3).await.unwrap();

        // First model should be evicted
        assert!(cache.get(&ModelId([1u8; 32])).await.is_none());
        // Third model should exist
        assert!(cache.get(&ModelId([3u8; 32])).await.is_some());
    }

    #[tokio::test]
    async fn test_cache_model_too_large() {
        let cache = ModelCache::new(100); // Very small cache

        let large_model = create_test_model([1u8; 32], 200); // Larger than cache

        let result = cache.put(ModelId([1u8; 32]), large_model).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn test_cache_access_count() {
        let cache = ModelCache::new(1024 * 1024);
        let model_id = ModelId([1u8; 32]);
        let model = create_test_model([1u8; 32], 500);

        cache.put(model_id, model).await.unwrap();

        // Access multiple times
        cache.get(&model_id).await;
        cache.get(&model_id).await;
        cache.get(&model_id).await;

        let stats = cache.stats().await;
        // Initial put counts as 1, plus 3 gets = 4 total
        assert!(stats.total_accesses >= 3);
    }

    #[tokio::test]
    async fn test_cache_preload() {
        let cache = ModelCache::new(1024 * 1024);

        let models: Vec<(ModelId, Model)> = (0..3u8)
            .map(|i| {
                let id = ModelId([i; 32]);
                let model = create_test_model([i; 32], 100);
                (id, model)
            })
            .collect();

        cache.preload(models).await.unwrap();

        let stats = cache.stats().await;
        assert_eq!(stats.total_models, 3);

        // Verify all models are accessible
        for i in 0..3u8 {
            assert!(cache.get(&ModelId([i; 32])).await.is_some());
        }
    }

    #[tokio::test]
    async fn test_cache_utilization_calculation() {
        let cache = ModelCache::new(10000);

        let stats_empty = cache.stats().await;
        assert_eq!(stats_empty.utilization, 0.0);

        let model = create_test_model([1u8; 32], 500);
        cache.put(ModelId([1u8; 32]), model).await.unwrap();

        let stats = cache.stats().await;
        assert!(stats.utilization > 0.0);
        assert!(stats.utilization < 100.0);
    }

    /// CHAIN-B-D018 tripwire: re-inserting the same key must not drift
    /// `current_size` or push duplicate LRU entries. Pre-fix, `put` on an
    /// existing key still did `*current_size += model_size`, so the size grew
    /// each time until the eviction loop could never terminate.
    #[tokio::test]
    async fn d018_reinsert_does_not_drift_size() {
        let cache = ModelCache::new(10_000);
        let id = ModelId([7u8; 32]);
        let model = create_test_model([7u8; 32], 500);

        cache
            .put(id, model.clone())
            .await
            .expect("first put under cap");
        let size_after_first = cache.stats().await.current_size;

        for _ in 0..5 {
            cache
                .put(id, model.clone())
                .await
                .expect("re-put under cap");
        }

        let stats = cache.stats().await;
        assert_eq!(
            stats.current_size, size_after_first,
            "re-inserting the same key must not drift current_size"
        );
        assert_eq!(stats.total_models, 1, "re-insert must not duplicate the entry");
    }
}
