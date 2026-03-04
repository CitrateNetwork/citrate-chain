// citrate/core/marketplace/src/search_simple.rs

use crate::types::*;
use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: String,
    pub category: Option<ModelCategory>,
    pub framework: Option<String>,
    pub tags: Vec<String>,
    pub min_price: Option<u64>,
    pub max_price: Option<u64>,
    pub sort_by: Option<SortOrder>,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortOrder {
    Relevance,
    Price,
    Rating,
    Recent,
    Downloads,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            text: String::new(),
            category: None,
            framework: None,
            tags: Vec::new(),
            min_price: None,
            max_price: None,
            sort_by: Some(SortOrder::Relevance),
            limit: 20,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub model: MarketplaceModel,
    pub score: f32,
    pub snippet: String,
}

/// Simple in-memory search engine
pub struct SearchEngine {
    models: Arc<DashMap<ModelId, MarketplaceModel>>,
    text_index: Arc<DashMap<String, HashSet<ModelId>>>,
}

impl SearchEngine {
    /// Create a new search engine
    pub async fn new<P: AsRef<Path>>(_index_path: P) -> Result<Self> {
        info!("Search engine initialized (in-memory)");
        Ok(Self {
            models: Arc::new(DashMap::new()),
            text_index: Arc::new(DashMap::new()),
        })
    }

    /// Index a model
    pub async fn index_model(&self, model: &MarketplaceModel) -> Result<()> {
        // Store the model
        self.models.insert(model.model_id, model.clone());

        // Build text index
        let text_content = format!(
            "{} {} {} {} {}",
            model.name,
            model.description,
            model.framework,
            model.license,
            model.tags.join(" ")
        );

        // Simple tokenization
        let tokens = self.tokenize(&text_content);

        for token in tokens {
            self.text_index
                .entry(token)
                .or_default()
                .insert(model.model_id);
        }

        debug!(model_id = ?model.model_id, "Model indexed");
        Ok(())
    }

    /// Remove a model from the index
    pub async fn remove_model(&self, model_id: &ModelId) -> Result<()> {
        // Remove from models
        if let Some((_, model)) = self.models.remove(model_id) {
            // Remove from text index
            let text_content = format!(
                "{} {} {} {} {}",
                model.name,
                model.description,
                model.framework,
                model.license,
                model.tags.join(" ")
            );

            let tokens = self.tokenize(&text_content);
            for token in tokens {
                if let Some(mut entry) = self.text_index.get_mut(&token) {
                    entry.remove(model_id);
                    if entry.is_empty() {
                        drop(entry);
                        self.text_index.remove(&token);
                    }
                }
            }
        }

        debug!(model_id = ?model_id, "Model removed from index");
        Ok(())
    }

    /// Search for models
    pub async fn search(&self, query: &SearchQuery) -> Result<Vec<SearchResult>> {
        let mut candidates = HashSet::new();

        // Text search
        if !query.text.trim().is_empty() {
            let tokens = self.tokenize(&query.text);
            for token in tokens {
                if let Some(model_ids) = self.text_index.get(&token) {
                    candidates.extend(model_ids.iter());
                }
            }
        } else {
            // If no text query, include all models
            candidates.extend(self.models.iter().map(|entry| *entry.key()));
        }

        // Apply filters and collect results
        let mut results = Vec::new();

        for model_id in candidates {
            if let Some(model) = self.models.get(&model_id) {
                let model = model.value();

                // Filter by category
                if let Some(category) = &query.category {
                    if model.category != *category {
                        continue;
                    }
                }

                // Filter by framework
                if let Some(framework) = &query.framework {
                    if model.framework != *framework {
                        continue;
                    }
                }

                // Filter by tags
                if !query.tags.is_empty() {
                    let has_any_tag = query.tags.iter().any(|tag| model.tags.contains(tag));
                    if !has_any_tag {
                        continue;
                    }
                }

                // Filter by price
                if let Some(min_price) = query.min_price {
                    if model.base_price < min_price {
                        continue;
                    }
                }

                if let Some(max_price) = query.max_price {
                    if model.base_price > max_price {
                        continue;
                    }
                }

                // Calculate relevance score
                let score = self.calculate_score(model, query);

                // Create snippet
                let snippet = if query.text.trim().is_empty() {
                    model.description.chars().take(200).collect()
                } else {
                    self.create_snippet(&model.description, &query.text)
                };

                results.push(SearchResult {
                    model: model.clone(),
                    score,
                    snippet,
                });
            }
        }

        // Sort results
        self.sort_results(&mut results, query);

        // Apply pagination
        let start = query.offset;
        let end = (start + query.limit).min(results.len());

        Ok(results[start..end].to_vec())
    }

    /// Get trending models (most interacted with)
    pub async fn get_trending_models(&self, limit: usize) -> Result<Vec<MarketplaceModel>> {
        // For simplicity, just return models sorted by name for now
        let mut models: Vec<MarketplaceModel> = self.models
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        models.sort_by(|a, b| a.name.cmp(&b.name));
        models.truncate(limit);

        Ok(models)
    }

    /// Get similar models based on tags and category
    pub async fn get_similar_models(&self, model_id: &ModelId, limit: usize) -> Result<Vec<MarketplaceModel>> {
        let target_model = match self.models.get(model_id) {
            Some(model) => model.value().clone(),
            None => return Ok(Vec::new()),
        };

        let mut scores = Vec::new();

        for entry in self.models.iter() {
            let model = entry.value();
            if model.model_id == *model_id {
                continue;
            }

            let score = self.calculate_similarity(&target_model, model);
            if score > 0.1 {
                scores.push((model.clone(), score));
            }
        }

        // Sort by similarity score
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(limit);

        Ok(scores.into_iter().map(|(model, _)| model).collect())
    }

    /// Get search statistics
    pub async fn get_stats(&self) -> Result<(usize, usize)> {
        let docs = self.models.len();
        let segments = 1; // Simple in-memory has just one "segment"
        Ok((docs, segments))
    }

    /// Commit changes (no-op for in-memory)
    pub async fn commit(&self) -> Result<()> {
        debug!("Search index commit (no-op for in-memory)");
        Ok(())
    }

    /// Optimize index (no-op for in-memory)
    pub async fn optimize(&self) -> Result<()> {
        debug!("Search index optimization (no-op for in-memory)");
        Ok(())
    }

    // Private helper methods

    fn tokenize(&self, text: &str) -> Vec<String> {
        text.to_lowercase()
            .split_whitespace()
            .filter(|token| token.len() > 2)
            .map(|token| {
                // Remove punctuation
                token.chars()
                    .filter(|c| c.is_alphanumeric())
                    .collect::<String>()
            })
            .filter(|token: &String| !token.is_empty())
            .collect()
    }

    fn calculate_score(&self, model: &MarketplaceModel, query: &SearchQuery) -> f32 {
        let mut score = 0.0;

        if !query.text.trim().is_empty() {
            let query_tokens = self.tokenize(&query.text);
            let model_text = format!(
                "{} {} {} {}",
                model.name, model.description, model.framework, model.tags.join(" ")
            );
            let model_tokens = self.tokenize(&model_text);

            // Simple TF scoring
            for query_token in &query_tokens {
                let count = model_tokens.iter().filter(|&token| token == query_token).count();
                score += count as f32;
            }

            // Boost for exact name matches
            if model.name.to_lowercase().contains(&query.text.to_lowercase()) {
                score += 10.0;
            }
        } else {
            score = 1.0; // Base score when no text query
        }

        // Category match boost
        if let Some(category) = &query.category {
            if model.category == *category {
                score += 5.0;
            }
        }

        // Framework match boost
        if let Some(framework) = &query.framework {
            if model.framework == *framework {
                score += 3.0;
            }
        }

        // Tag match boost
        for tag in &query.tags {
            if model.tags.contains(tag) {
                score += 2.0;
            }
        }

        score
    }

    fn calculate_similarity(&self, model1: &MarketplaceModel, model2: &MarketplaceModel) -> f32 {
        let mut similarity = 0.0;

        // Category similarity
        if model1.category == model2.category {
            similarity += 0.4;
        }

        // Framework similarity
        if model1.framework == model2.framework {
            similarity += 0.3;
        }

        // Tag similarity (Jaccard index)
        let tags1: HashSet<_> = model1.tags.iter().collect();
        let tags2: HashSet<_> = model2.tags.iter().collect();

        let intersection = tags1.intersection(&tags2).count();
        let union = tags1.union(&tags2).count();

        if union > 0 {
            similarity += (intersection as f32 / union as f32) * 0.2;
        }

        // License similarity
        if model1.license == model2.license {
            similarity += 0.1;
        }

        similarity.min(1.0)
    }

    fn create_snippet(&self, text: &str, query: &str) -> String {
        let query_lower = query.to_lowercase();
        let text_lower = text.to_lowercase();

        if let Some(pos) = text_lower.find(&query_lower) {
            let start = pos.saturating_sub(50);
            let end = (pos + query.len() + 50).min(text.len());

            let mut snippet = text[start..end].to_string();
            if start > 0 {
                snippet = format!("...{}", snippet);
            }
            if end < text.len() {
                snippet = format!("{}...", snippet);
            }

            snippet
        } else {
            text.chars().take(200).collect()
        }
    }

    fn sort_results(&self, results: &mut [SearchResult], query: &SearchQuery) {
        match query.sort_by.as_ref().unwrap_or(&SortOrder::Relevance) {
            SortOrder::Relevance => {
                results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
            }
            SortOrder::Price => {
                results.sort_by(|a, b| a.model.base_price.cmp(&b.model.base_price));
            }
            SortOrder::Rating => {
                // For now, sort by model ID as a proxy
                results.sort_by(|a, b| a.model.model_id.cmp(&b.model.model_id));
            }
            SortOrder::Recent => {
                results.sort_by(|a, b| b.model.created_at.cmp(&a.model.created_at));
            }
            SortOrder::Downloads => {
                // For now, sort by model ID as a proxy
                results.sort_by(|a, b| a.model.model_id.cmp(&b.model.model_id));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_model(id: u8, name: &str, category: ModelCategory, framework: &str, tags: Vec<&str>) -> MarketplaceModel {
        let mut model_id = [0u8; 32];
        model_id[0] = id;

        MarketplaceModel {
            model_id,
            owner: [1u8; 20],
            name: name.to_string(),
            description: format!("A test model for {}", name),
            category,
            base_price: (id as u64) * 100,
            discount_price: (id as u64) * 90,
            minimum_bulk_size: 10,
            framework: framework.to_string(),
            version: "1.0.0".to_string(),
            license: "MIT".to_string(),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            input_shape: vec!["batch".to_string(), "512".to_string()],
            output_shape: vec!["batch".to_string(), "768".to_string()],
            parameters: 1_000_000,
            size_bytes: 100_000_000,
            model_cid: "QmTest".to_string(),
            metadata_uri: "QmMeta".to_string(),
            total_sales: 0,
            total_revenue: 0,
            rating: 4.5,
            review_count: 10,
            featured: false,
            active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_sale_at: None,
        }
    }

    #[test]
    fn test_search_query_default() {
        let query = SearchQuery::default();
        assert!(query.text.is_empty());
        assert!(query.category.is_none());
        assert_eq!(query.limit, 20);
        assert_eq!(query.offset, 0);
    }

    #[tokio::test]
    async fn test_search_engine_creation() {
        let engine = SearchEngine::new("/tmp/test_index").await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_index_and_search_model() {
        let engine = SearchEngine::new("/tmp/test_index").await.unwrap();
        let model = create_test_model(1, "Language Model Clone", ModelCategory::LanguageModel, "PyTorch", vec!["nlp", "llm"]);

        engine.index_model(&model).await.unwrap();

        let query = SearchQuery {
            text: "language model".to_string(),
            ..Default::default()
        };

        let results = engine.search(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].model.name, "Language Model Clone");
    }

    #[tokio::test]
    async fn test_search_by_category() {
        let engine = SearchEngine::new("/tmp/test_index").await.unwrap();

        let model1 = create_test_model(1, "LLM Model", ModelCategory::LanguageModel, "PyTorch", vec!["nlp"]);
        let model2 = create_test_model(2, "Image Model", ModelCategory::ImageGeneration, "TensorFlow", vec!["vision"]);

        engine.index_model(&model1).await.unwrap();
        engine.index_model(&model2).await.unwrap();

        let query = SearchQuery {
            category: Some(ModelCategory::LanguageModel),
            ..Default::default()
        };

        let results = engine.search(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].model.category, ModelCategory::LanguageModel);
    }

    #[tokio::test]
    async fn test_search_by_price_range() {
        let engine = SearchEngine::new("/tmp/test_index").await.unwrap();

        let model1 = create_test_model(1, "Cheap Model", ModelCategory::Embedding, "PyTorch", vec![]);
        let model2 = create_test_model(5, "Expensive Model", ModelCategory::Embedding, "PyTorch", vec![]);

        engine.index_model(&model1).await.unwrap();
        engine.index_model(&model2).await.unwrap();

        let query = SearchQuery {
            max_price: Some(200),
            ..Default::default()
        };

        let results = engine.search(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].model.base_price <= 200);
    }

    #[tokio::test]
    async fn test_search_by_tags() {
        let engine = SearchEngine::new("/tmp/test_index").await.unwrap();

        let model1 = create_test_model(1, "NLP Model", ModelCategory::LanguageModel, "PyTorch", vec!["nlp", "transformer"]);
        let model2 = create_test_model(2, "Vision Model", ModelCategory::ImageClassification, "TensorFlow", vec!["cnn", "vision"]);

        engine.index_model(&model1).await.unwrap();
        engine.index_model(&model2).await.unwrap();

        let query = SearchQuery {
            tags: vec!["nlp".to_string()],
            ..Default::default()
        };

        let results = engine.search(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].model.tags.contains(&"nlp".to_string()));
    }

    #[tokio::test]
    async fn test_remove_model() {
        let engine = SearchEngine::new("/tmp/test_index").await.unwrap();

        let model = create_test_model(1, "Test Model", ModelCategory::Embedding, "PyTorch", vec![]);
        engine.index_model(&model).await.unwrap();

        // Verify it's indexed
        let (count, _) = engine.get_stats().await.unwrap();
        assert_eq!(count, 1);

        // Remove it
        engine.remove_model(&model.model_id).await.unwrap();

        // Verify it's removed
        let (count, _) = engine.get_stats().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_get_similar_models() {
        let engine = SearchEngine::new("/tmp/test_index").await.unwrap();

        let model1 = create_test_model(1, "PyTorch LLM", ModelCategory::LanguageModel, "PyTorch", vec!["nlp", "llm"]);
        let model2 = create_test_model(2, "Another PyTorch LLM", ModelCategory::LanguageModel, "PyTorch", vec!["nlp", "transformer"]);
        let model3 = create_test_model(3, "TensorFlow Vision", ModelCategory::ImageGeneration, "TensorFlow", vec!["vision"]);

        engine.index_model(&model1).await.unwrap();
        engine.index_model(&model2).await.unwrap();
        engine.index_model(&model3).await.unwrap();

        let similar = engine.get_similar_models(&model1.model_id, 5).await.unwrap();

        // Model 2 should be more similar to Model 1 than Model 3
        assert!(!similar.is_empty());
        // First result should be Model 2 (same category, same framework, overlapping tags)
        if similar.len() >= 2 {
            assert_eq!(similar[0].model_id[0], 2); // Model 2 is most similar
        }
    }

    #[tokio::test]
    async fn test_get_trending_models() {
        let engine = SearchEngine::new("/tmp/test_index").await.unwrap();

        let model1 = create_test_model(1, "Alpha Model", ModelCategory::Embedding, "PyTorch", vec![]);
        let model2 = create_test_model(2, "Beta Model", ModelCategory::Embedding, "PyTorch", vec![]);

        engine.index_model(&model1).await.unwrap();
        engine.index_model(&model2).await.unwrap();

        let trending = engine.get_trending_models(10).await.unwrap();
        assert_eq!(trending.len(), 2);
    }

    #[tokio::test]
    async fn test_search_pagination() {
        let engine = SearchEngine::new("/tmp/test_index").await.unwrap();

        // Add 5 models with different prices for deterministic sorting
        for i in 1..=5 {
            let mut model = create_test_model(i, &format!("Model {}", i), ModelCategory::Embedding, "PyTorch", vec![]);
            model.base_price = (i as u64) * 100; // Prices: 100, 200, 300, 400, 500
            engine.index_model(&model).await.unwrap();
        }

        // Get first page (2 items) sorted by price
        let query1 = SearchQuery {
            limit: 2,
            offset: 0,
            sort_by: Some(SortOrder::Price),
            ..Default::default()
        };
        let results1 = engine.search(&query1).await.unwrap();
        assert_eq!(results1.len(), 2);

        // Get second page sorted by price
        let query2 = SearchQuery {
            limit: 2,
            offset: 2,
            sort_by: Some(SortOrder::Price),
            ..Default::default()
        };
        let results2 = engine.search(&query2).await.unwrap();
        assert_eq!(results2.len(), 2);

        // First page should have cheaper models than second page
        assert!(results1[0].model.base_price < results2[0].model.base_price);
    }

    #[tokio::test]
    async fn test_search_empty_results() {
        let engine = SearchEngine::new("/tmp/test_index").await.unwrap();

        let model = create_test_model(1, "Test Model", ModelCategory::Embedding, "PyTorch", vec![]);
        engine.index_model(&model).await.unwrap();

        let query = SearchQuery {
            text: "nonexistent_term_xyz123".to_string(),
            ..Default::default()
        };

        let results = engine.search(&query).await.unwrap();
        assert!(results.is_empty());
    }
}