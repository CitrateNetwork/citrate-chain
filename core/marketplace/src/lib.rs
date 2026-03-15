// citrate/core/marketplace/src/lib.rs

//! Citrate Marketplace Discovery Engine
//!
//! Provides full-text search, IPFS metadata indexing, and recommendation algorithms
//! for the decentralized AI model marketplace.

// LOCK ORDERING — acquire in this order to prevent deadlocks:
//
//   Level 1 (outermost — acquire first):
//     storage_simple.rs  MarketplaceStorage.interactions  (Arc<RwLock<Vec<UserInteraction>>>)
//     indexing.rs         IndexingService.task_queue       (Arc<RwLock<Vec>>)
//
//   Level 2:
//     storage_simple.rs  MarketplaceStorage.stats         (Arc<RwLock<MarketplaceStats>>)
//     indexing.rs         IndexingService.stats            (Arc<RwLock<IndexingStats>>)
//     discovery.rs        DiscoveryEngine.stats            (Arc<RwLock<DiscoveryStats>>)
//     search.rs           SearchEngine.writer              (RwLock<IndexWriter>)
//
//   Level 3 (innermost — acquire last):
//     performance_tracker.rs  PerformanceTracker.alert_history  (Arc<RwLock<VecDeque>>)
//
//   Lock-free (DashMap, no ordering constraint):
//     storage_simple.rs       MarketplaceStorage.models    (Arc<DashMap>)
//     storage_simple.rs       MarketplaceStorage.reviews   (Arc<DashMap>)
//     search_simple.rs        SearchEngine.models          (Arc<DashMap>)
//     search_simple.rs        SearchEngine.text_index      (Arc<DashMap>)
//     metadata.rs             MetadataCache.*              (Arc<DashMap>)
//     rating_system.rs        RatingSystem.*               (Arc<DashMap>)
//     performance_tracker.rs  PerformanceTracker.*         (Arc<DashMap>) except alert_history
//
//   Fixed violation (2026-03-15):
//     storage_simple.rs get_marketplace_stats previously held stats (write) while
//     acquiring interactions (read) — reversed vs clear_all's interactions -> stats.
//     Fixed: get_marketplace_stats now snapshots interactions first, drops the lock,
//     then acquires stats (write). Both paths now follow interactions-before-stats.

use std::sync::Arc;

pub mod analytics_engine;
pub mod discovery;
pub mod indexing;
pub mod metadata;
pub mod performance_tracker;
pub mod rating_system;
pub mod recommendations;
pub mod search_simple;
pub mod storage_simple;
pub mod types;

// Re-export simplified modules with clean names
pub use search_simple as search;
pub use storage_simple as storage;

pub use discovery::DiscoveryEngine;
pub use types::*;

// Re-export key types for easy access
pub use crate::{
    analytics_engine::{AnalyticsEngine, ModelAnalyticsReport},
    discovery::DiscoveryConfig,
    indexing::{IndexingService, BatchIndexer},
    metadata::{ModelMetadata, MetadataCache},
    performance_tracker::{PerformanceTracker, PerformanceConfig, ModelHealthStatus},
    rating_system::{RatingSystem, RatingConfig, ModelRating, EnhancedUserReview},
    recommendations::RecommendationEngine,
    search::{SearchEngine, SearchQuery, SearchResult},
    storage::MarketplaceStorage,
};

/// Initialize the marketplace discovery system
pub async fn init_marketplace(config: DiscoveryConfig) -> anyhow::Result<DiscoveryEngine> {
    DiscoveryEngine::new(config).await
}

/// Initialize the complete marketplace system with ratings and analytics
pub async fn init_complete_marketplace(
    discovery_config: DiscoveryConfig,
    rating_config: RatingConfig,
    performance_config: PerformanceConfig,
) -> anyhow::Result<MarketplaceSystem> {
    // Initialize core components
    let discovery_engine = Arc::new(DiscoveryEngine::new(discovery_config).await?);
    let rating_system = Arc::new(RatingSystem::new(rating_config));
    let performance_tracker = Arc::new(PerformanceTracker::new(performance_config));
    let analytics_engine = Arc::new(AnalyticsEngine::new(
        Arc::clone(&rating_system),
        Arc::clone(&performance_tracker),
    ));

    // Start background monitoring
    performance_tracker.start_monitoring().await?;

    Ok(MarketplaceSystem {
        discovery_engine,
        rating_system,
        performance_tracker,
        analytics_engine,
    })
}

/// Complete marketplace system
pub struct MarketplaceSystem {
    pub discovery_engine: Arc<DiscoveryEngine>,
    pub rating_system: Arc<RatingSystem>,
    pub performance_tracker: Arc<PerformanceTracker>,
    pub analytics_engine: Arc<AnalyticsEngine>,
}