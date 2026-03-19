# citrate-marketplace

Model marketplace discovery engine for Citrate -- full-text search, IPFS metadata indexing, rating system, performance tracking, analytics, and collaborative-filtering recommendations.

## Overview

citrate-marketplace provides the discovery and quality infrastructure for the decentralized AI model marketplace. It enables users to search for models by text, category, framework, and tags; maintains aggregated ratings with time-weighted decay and spam detection; tracks real-time inference performance; and generates personalized recommendations through collaborative filtering.

The crate is designed around a `MarketplaceSystem` coordinator that wires together the `DiscoveryEngine`, `RatingSystem`, `PerformanceTracker`, and `AnalyticsEngine`. The discovery engine combines a DashMap-backed full-text search engine, an IPFS metadata cache with configurable TTL, and an in-memory storage layer. A background `IndexingService` processes model additions, updates, and removals in priority-ordered batches. The analytics engine follows a fail-loud design: when data is unavailable, errors are returned rather than fabricated zeros.

Lock ordering is carefully documented in the crate root to prevent deadlocks. All concurrent data structures use either `DashMap` (lock-free) or `RwLock` with a defined 3-level acquisition hierarchy.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `lib` | `lib.rs` | `MarketplaceSystem` coordinator, `init_marketplace` and `init_complete_marketplace` entry points |
| `types` | `types.rs` | Core types: `ModelId`, `Address`, `ModelCategory` (11 variants), `MarketplaceModel`, `UserReview`, `UserInteraction` |
| `discovery` | `discovery.rs` | `DiscoveryEngine` -- coordinates search, metadata, storage, recommendations; `DiscoveryConfig` |
| `search_simple` | `search_simple.rs` | `SearchEngine` -- DashMap-backed full-text search with `SearchQuery`, `SearchResult`, `SortOrder` |
| `storage_simple` | `storage_simple.rs` | `MarketplaceStorage` -- in-memory model/review/interaction storage with marketplace stats |
| `metadata` | `metadata.rs` | `MetadataCache` -- IPFS metadata fetching and caching with TTL; `ModelMetadata` with technical specs, benchmarks, hardware requirements |
| `indexing` | `indexing.rs` | `IndexingService`, `BatchIndexer` -- background model indexing with priority queue, retry, and statistics |
| `rating_system` | `rating_system.rs` | `RatingSystem` -- aggregated `ModelRating` with time-weighted decay, sentiment analysis, spam detection; `RatingConfig`, `EnhancedUserReview` |
| `recommendations` | `recommendations.rs` | `RecommendationEngine` -- collaborative filtering with user profiles, model similarity computation |
| `analytics_engine` | `analytics_engine.rs` | `AnalyticsEngine` -- `ModelAnalyticsReport` generation from performance + rating data; fail-loud on missing data |
| `performance_tracker` | `performance_tracker.rs` | `PerformanceTracker` -- real-time inference metrics, sliding windows, alert thresholds, `ModelHealthStatus`; `PerformanceConfig` |

## Public API

### Entry Points

- **`init_marketplace(config) -> DiscoveryEngine`** -- Initialize core discovery system
- **`init_complete_marketplace(discovery_config, rating_config, performance_config) -> MarketplaceSystem`** -- Initialize full system with ratings, performance tracking, and analytics

### Key Structs

- **`MarketplaceSystem`** -- Holds `DiscoveryEngine`, `RatingSystem`, `PerformanceTracker`, `AnalyticsEngine`
- **`DiscoveryEngine`** -- Main search/discovery coordinator
- **`SearchEngine`** -- Full-text search with category/tag/price filters and multiple sort orders (Relevance, Price, Rating, Recent, Downloads)
- **`MarketplaceStorage`** -- In-memory model and review storage
- **`RatingSystem`** -- Review aggregation with `ModelRating` (average, weighted, distribution, confidence, sentiment)
- **`PerformanceTracker`** -- Inference performance monitoring with alerting
- **`AnalyticsEngine`** -- Report generation combining performance and rating data
- **`RecommendationEngine`** -- Collaborative filtering recommendations
- **`IndexingService`** -- Background batch indexing with priority queue

### Key Types

- `ModelCategory` -- 11 variants: LanguageModel, ImageGeneration, Embedding, Translation, etc.
- `SearchQuery` -- Text, category, framework, tags, price range, sort order, pagination
- `ModelRating` -- Average/weighted rating, distribution, confidence, sentiment score
- `ModelHealthStatus` -- Real-time model health derived from performance metrics

## Tests

```bash
cargo test -p citrate-marketplace
```

39 tests, all passing.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `dashmap` | Lock-free concurrent maps for models, reviews, search index |
| `reqwest` | HTTP client for IPFS metadata fetching |
| `uuid` | Unique identifiers |
| `sha3`, `blake3` | Hashing |
| `chrono` | Time-weighted rating decay |
| `futures` | Async utilities |
| `proptest` (dev) | Property-based testing |
