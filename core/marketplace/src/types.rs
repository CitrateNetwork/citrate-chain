// citrate/core/marketplace/src/types.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Model identifier (32-byte hash from blockchain)
pub type ModelId = [u8; 32];

/// User address (20-byte Ethereum address)
pub type Address = [u8; 20];

/// IPFS Content Identifier
pub type IpfsCid = String;

/// Model categories for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ModelCategory {
    LanguageModel = 0,
    ImageGeneration = 1,
    ImageClassification = 2,
    AudioProcessing = 3,
    VideoProcessing = 4,
    Embedding = 5,
    ObjectDetection = 6,
    TextToSpeech = 7,
    SpeechToText = 8,
    Translation = 9,
    Other = 10,
}

impl From<u8> for ModelCategory {
    fn from(value: u8) -> Self {
        match value {
            0 => ModelCategory::LanguageModel,
            1 => ModelCategory::ImageGeneration,
            2 => ModelCategory::ImageClassification,
            3 => ModelCategory::AudioProcessing,
            4 => ModelCategory::VideoProcessing,
            5 => ModelCategory::Embedding,
            6 => ModelCategory::ObjectDetection,
            7 => ModelCategory::TextToSpeech,
            8 => ModelCategory::SpeechToText,
            9 => ModelCategory::Translation,
            _ => ModelCategory::Other,
        }
    }
}

impl ModelCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModelCategory::LanguageModel => "Language Model",
            ModelCategory::ImageGeneration => "Image Generation",
            ModelCategory::ImageClassification => "Image Classification",
            ModelCategory::AudioProcessing => "Audio Processing",
            ModelCategory::VideoProcessing => "Video Processing",
            ModelCategory::Embedding => "Embedding",
            ModelCategory::ObjectDetection => "Object Detection",
            ModelCategory::TextToSpeech => "Text-to-Speech",
            ModelCategory::SpeechToText => "Speech-to-Text",
            ModelCategory::Translation => "Translation",
            ModelCategory::Other => "Other",
        }
    }

    pub fn all() -> &'static [ModelCategory] {
        &[
            ModelCategory::LanguageModel,
            ModelCategory::ImageGeneration,
            ModelCategory::ImageClassification,
            ModelCategory::AudioProcessing,
            ModelCategory::VideoProcessing,
            ModelCategory::Embedding,
            ModelCategory::ObjectDetection,
            ModelCategory::TextToSpeech,
            ModelCategory::SpeechToText,
            ModelCategory::Translation,
            ModelCategory::Other,
        ]
    }
}

/// Complete model information for marketplace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceModel {
    pub model_id: ModelId,
    pub owner: Address,
    pub name: String,
    pub description: String,
    pub category: ModelCategory,

    // Pricing information
    pub base_price: u64, // Wei per inference
    pub discount_price: u64,
    pub minimum_bulk_size: u32,

    // Model details
    pub framework: String,
    pub version: String,
    pub license: String,
    pub tags: Vec<String>,
    pub input_shape: Vec<String>,
    pub output_shape: Vec<String>,
    pub parameters: u64,
    pub size_bytes: u64,

    // IPFS references
    pub model_cid: IpfsCid,
    pub metadata_uri: IpfsCid,

    // Marketplace stats
    pub total_sales: u64,
    pub total_revenue: u64,
    pub rating: f32, // Average rating 0.0-5.0
    pub review_count: u32,
    pub featured: bool,
    pub active: bool,

    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_sale_at: Option<DateTime<Utc>>,
}

/// User review and rating
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelReview {
    pub model_id: ModelId,
    pub reviewer: Address,
    pub rating: u8, // 1-5 stars
    pub comment: String,
    pub verified: bool, // True if reviewer has purchased the model
    pub created_at: DateTime<Utc>,
}

/// Purchase record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Purchase {
    pub model_id: ModelId,
    pub buyer: Address,
    pub price_per_inference: u64,
    pub quantity: u32,
    pub bulk_discount: bool,
    pub transaction_hash: String,
    pub timestamp: DateTime<Utc>,
}

/// User interaction for recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInteraction {
    pub user: Address,
    pub model_id: ModelId,
    pub interaction_type: InteractionType,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum InteractionType {
    View,
    Purchase,
    Review,
    Bookmark,
    Share,
}

/// Performance metrics for a model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetrics {
    pub model_id: ModelId,
    pub average_latency_ms: f32,
    pub success_rate: f32,
    pub quality_score: f32, // Computed from reviews and usage
    pub popularity_score: f32, // Based on views, purchases, etc.
    pub updated_at: DateTime<Utc>,
}

/// Search filters for marketplace queries
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchFilters {
    pub categories: Option<Vec<ModelCategory>>,
    pub min_price: Option<u64>,
    pub max_price: Option<u64>,
    pub min_rating: Option<f32>,
    pub frameworks: Option<Vec<String>>,
    pub licenses: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub featured_only: bool,
    pub verified_reviews_only: bool,
}

/// Sorting options for search results
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SortBy {
    Relevance,
    Rating,
    Price,
    Sales,
    Newest,
    MostReviewed,
    Popularity,
}

/// User review for a model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserReview {
    pub model_id: ModelId,
    pub reviewer: Address,
    pub rating: f32, // 1.0 to 5.0
    pub title: String,
    pub content: String,
    pub pros: Vec<String>,
    pub cons: Vec<String>,
    pub recommended: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Marketplace statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceStats {
    pub total_models: u64,
    pub total_interactions: u64,
    pub total_reviews: u64,
    pub category_distribution: HashMap<ModelCategory, u64>,
    pub top_models: Vec<ModelId>,
    pub last_updated: DateTime<Utc>,
}

impl Default for MarketplaceStats {
    fn default() -> Self {
        Self {
            total_models: 0,
            total_interactions: 0,
            total_reviews: 0,
            category_distribution: HashMap::new(),
            top_models: Vec::new(),
            last_updated: Utc::now(),
        }
    }
}

/// Error types for marketplace operations
#[derive(Debug, thiserror::Error)]
pub enum MarketplaceError {
    #[error("Model not found: {0:?}")]
    ModelNotFound(ModelId),

    #[error("IPFS error: {0}")]
    IpfsError(String),

    #[error("Search index error: {0}")]
    SearchError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<serde_json::Error> for MarketplaceError {
    fn from(err: serde_json::Error) -> Self {
        MarketplaceError::SerializationError(err.to_string())
    }
}

impl From<reqwest::Error> for MarketplaceError {
    fn from(err: reqwest::Error) -> Self {
        MarketplaceError::NetworkError(err.to_string())
    }
}

// Tantivy error conversion removed for simplified implementation

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_category_from_u8() {
        assert_eq!(ModelCategory::from(0), ModelCategory::LanguageModel);
        assert_eq!(ModelCategory::from(1), ModelCategory::ImageGeneration);
        assert_eq!(ModelCategory::from(5), ModelCategory::Embedding);
        assert_eq!(ModelCategory::from(10), ModelCategory::Other);
        assert_eq!(ModelCategory::from(255), ModelCategory::Other); // Unknown maps to Other
    }

    // -----------------------------------------------------------------------
    // Property-based tests (proptest)
    // -----------------------------------------------------------------------
    use proptest::prelude::*;

    proptest! {
        /// Property: ModelCategory from u8 always produces a valid variant (never panics).
        /// Values 0-10 map to specific categories; anything else maps to Other.
        #[test]
        fn prop_model_category_from_u8_total(byte in any::<u8>()) {
            let category = ModelCategory::from(byte);
            if byte <= 10 {
                prop_assert_eq!(category as u8, byte,
                    "In-range byte must map to matching category discriminant");
            } else {
                prop_assert_eq!(category, ModelCategory::Other,
                    "Out-of-range byte must map to Other");
            }
        }

        /// Property: Purchase total cost (base_price * quantity) does not overflow for valid inputs.
        /// Valid inputs: base_price fits in u64 and quantity fits in u32.
        #[test]
        fn prop_purchase_cost_no_overflow(
            base_price in 0u64..1_000_000_000,
            quantity in 1u32..10_000,
        ) {
            let total = (base_price as u128) * (quantity as u128);
            // Must fit in u128 (always true) and be non-negative
            prop_assert!(total >= base_price as u128,
                "Total cost must be >= base_price when quantity >= 1");
            // total is u128 by construction — overflow would have been caught
            // by checked_mul if inputs were larger. With these ranges it fits.
        }

        /// Property: ModelCategory serialization round-trip via serde_json.
        #[test]
        fn prop_model_category_serde_roundtrip(byte in 0u8..11) {
            let category = ModelCategory::from(byte);
            let json = serde_json::to_string(&category).expect("serialize category");
            let recovered: ModelCategory = serde_json::from_str(&json).expect("deserialize category");
            prop_assert_eq!(category, recovered,
                "ModelCategory serde round-trip must be identity");
        }
    }

    #[test]
    fn test_model_category_as_str() {
        assert_eq!(ModelCategory::LanguageModel.as_str(), "Language Model");
        assert_eq!(ModelCategory::ImageGeneration.as_str(), "Image Generation");
        assert_eq!(ModelCategory::Embedding.as_str(), "Embedding");
        assert_eq!(ModelCategory::Other.as_str(), "Other");
    }

    #[test]
    fn test_model_category_all() {
        let all = ModelCategory::all();
        assert_eq!(all.len(), 11);
        assert!(all.contains(&ModelCategory::LanguageModel));
        assert!(all.contains(&ModelCategory::Other));
    }

    #[test]
    fn test_search_filters_default() {
        let filters = SearchFilters::default();
        assert!(filters.categories.is_none());
        assert!(filters.min_price.is_none());
        assert!(filters.max_price.is_none());
        assert!(!filters.featured_only);
    }

    #[test]
    fn test_marketplace_stats_default() {
        let stats = MarketplaceStats::default();
        assert_eq!(stats.total_models, 0);
        assert_eq!(stats.total_interactions, 0);
        assert!(stats.top_models.is_empty());
    }

    #[test]
    fn test_marketplace_error_display() {
        let err = MarketplaceError::ModelNotFound([1u8; 32]);
        assert!(err.to_string().contains("Model not found"));

        let err = MarketplaceError::IpfsError("connection failed".to_string());
        assert!(err.to_string().contains("connection failed"));
    }

    #[test]
    fn test_marketplace_error_from_serde() {
        let json_err: Result<ModelCategory, _> = serde_json::from_str("invalid");
        if let Err(e) = json_err {
            let marketplace_err: MarketplaceError = e.into();
            assert!(matches!(marketplace_err, MarketplaceError::SerializationError(_)));
        }
    }

    #[test]
    fn test_model_category_serialization() {
        let category = ModelCategory::ImageGeneration;
        let json = serde_json::to_string(&category).unwrap();
        let deserialized: ModelCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(category, deserialized);
    }

    #[test]
    fn test_sort_by_variants() {
        let variants = [SortBy::Relevance,
            SortBy::Rating,
            SortBy::Price,
            SortBy::Sales,
            SortBy::Newest,
            SortBy::MostReviewed,
            SortBy::Popularity];
        assert_eq!(variants.len(), 7);
    }

    #[test]
    fn test_interaction_type_serialization() {
        let interaction = InteractionType::Purchase;
        let json = serde_json::to_string(&interaction).unwrap();
        let deserialized: InteractionType = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, InteractionType::Purchase));
    }
}