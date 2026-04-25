// citrate/core/consensus/src/tip_selection.rs

use crate::dag_store::DagStore;
use crate::ghostdag::GhostDag;
use crate::types::{Hash, Tip};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Error, Debug)]
pub enum TipSelectionError {
    #[error("No tips available")]
    NoTips,

    #[error("Block not found: {0}")]
    BlockNotFound(Hash),

    #[error("DAG error: {0}")]
    DagError(String),
}

/// Tip selection strategy
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SelectionStrategy {
    /// Select tip with highest blue score
    HighestBlueScore,

    /// Select tip with highest blue score, break ties by hash
    HighestBlueScoreWithTieBreak,

    /// Random selection weighted by blue score
    WeightedRandom,
}

/// Tip selector for choosing the best chain tip
pub struct TipSelector {
    dag_store: Arc<DagStore>,
    ghostdag: Arc<GhostDag>,
    strategy: SelectionStrategy,
    tip_cache: Arc<RwLock<HashMap<Hash, TipInfo>>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct TipInfo {
    pub(crate) hash: Hash,
    pub(crate) blue_score: u64,
    pub(crate) height: u64,
    pub(crate) timestamp: u64,
}

/// Comparator for sorting tips during parent selection.
///
/// Establishes a strict total order on `TipInfo`:
///   1. higher `blue_score` precedes lower (descending),
///   2. ties broken by lower `hash` first (ascending lexicographic).
///
/// This closes audit finding **H-08** (`select_parents` non-deterministic
/// with equal blue scores). The hash tie-break MUST NOT be removed —
/// without it, `Vec::sort_by` is stable but produces input-order-dependent
/// output across validators whose `dag_store::get_tips()` iteration differs
/// (e.g., RocksDB key order vs. HashMap entropy).
pub(crate) fn cmp_tip_for_parent_selection(a: &TipInfo, b: &TipInfo) -> std::cmp::Ordering {
    b.blue_score
        .cmp(&a.blue_score)
        .then_with(|| a.hash.cmp(&b.hash))
}

impl TipSelector {
    pub fn new(
        dag_store: Arc<DagStore>,
        ghostdag: Arc<GhostDag>,
        strategy: SelectionStrategy,
    ) -> Self {
        Self {
            dag_store,
            ghostdag,
            strategy,
            tip_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Select the best tip from given hashes
    pub async fn select_tip(&self, tip_hashes: &[Hash]) -> Result<Hash, TipSelectionError> {
        if tip_hashes.is_empty() {
            return Err(TipSelectionError::NoTips);
        }

        // If only one tip, return it
        if tip_hashes.len() == 1 {
            return Ok(tip_hashes[0]);
        }

        // Get blue scores for each tip
        let mut best_tip = tip_hashes[0];
        let mut best_score = 0u64;

        for &hash in tip_hashes {
            // Try to get block from DAG store
            if let Ok(block) = self.dag_store.get_block(&hash).await {
                if let Ok(score) = self.ghostdag.calculate_blue_score(&block).await {
                    if score > best_score || (score == best_score && hash > best_tip) {
                        best_tip = hash;
                        best_score = score;
                    }
                }
            }
        }

        Ok(best_tip)
    }

    /// Select the best tip according to the configured strategy (using current DAG tips)
    pub async fn select_current_tip(&self) -> Result<Hash, TipSelectionError> {
        let tips = self.dag_store.get_tips().await;

        if tips.is_empty() {
            return Err(TipSelectionError::NoTips);
        }

        match self.strategy {
            SelectionStrategy::HighestBlueScore => self.select_highest_blue_score(&tips).await,
            SelectionStrategy::HighestBlueScoreWithTieBreak => {
                self.select_highest_blue_score_with_tiebreak(&tips).await
            }
            SelectionStrategy::WeightedRandom => self.select_weighted_random(&tips).await,
        }
    }

    /// Select multiple parent tips for a new block
    pub async fn select_parents(&self, max_parents: usize) -> Result<Vec<Hash>, TipSelectionError> {
        let tips = self.dag_store.get_tips().await;

        if tips.is_empty() {
            return Err(TipSelectionError::NoTips);
        }

        // Get tip info with blue scores using block-based scoring to avoid hash lookup races
        let mut tip_infos = Vec::new();
        for tip in &tips {
            let block = self
                .dag_store
                .get_block(&tip.hash)
                .await
                .map_err(|_| TipSelectionError::BlockNotFound(tip.hash))?;
            let blue_score = self
                .ghostdag
                .calculate_blue_score(&block)
                .await
                .map_err(|e| TipSelectionError::DagError(e.to_string()))?;
            tip_infos.push(TipInfo {
                hash: tip.hash,
                blue_score,
                height: block.header.height,
                timestamp: block.header.timestamp,
            });
        }

        // Sort by blue score (descending), break ties by hash (ascending) —
        // see `cmp_tip_for_parent_selection` doc + audit finding H-08.
        tip_infos.sort_by(cmp_tip_for_parent_selection);

        // Select top tips up to max_parents
        let selected: Vec<Hash> = tip_infos
            .into_iter()
            .take(max_parents)
            .map(|info| info.hash)
            .collect();

        info!("Selected {} parent tips", selected.len());
        Ok(selected)
    }

    /// Select tip with highest blue score
    async fn select_highest_blue_score(&self, tips: &[Tip]) -> Result<Hash, TipSelectionError> {
        let mut best_tip = None;
        let mut best_score = 0;

        for tip in tips {
            let score = self.get_blue_score(&tip.hash).await?;
            if score > best_score {
                best_score = score;
                best_tip = Some(tip.hash);
            }
        }

        best_tip.ok_or(TipSelectionError::NoTips)
    }

    /// Select tip with highest blue score, breaking ties deterministically
    async fn select_highest_blue_score_with_tiebreak(
        &self,
        tips: &[Tip],
    ) -> Result<Hash, TipSelectionError> {
        let mut candidates = Vec::new();
        let mut max_score = 0;

        // Find all tips with maximum blue score
        for tip in tips {
            let score = self.get_blue_score(&tip.hash).await?;
            if score > max_score {
                max_score = score;
                candidates.clear();
                candidates.push(tip.hash);
            } else if score == max_score {
                candidates.push(tip.hash);
            }
        }

        // Break ties by hash (deterministic)
        candidates.sort();

        candidates.first().copied().ok_or(TipSelectionError::NoTips)
    }

    /// Select tip using weighted random selection based on blue score
    async fn select_weighted_random(&self, tips: &[Tip]) -> Result<Hash, TipSelectionError> {
        use rand::prelude::*;

        let mut weights = Vec::new();
        let mut tip_hashes = Vec::new();

        for tip in tips {
            let score = self.get_blue_score(&tip.hash).await?;
            weights.push(score as f64);
            tip_hashes.push(tip.hash);
        }

        if weights.is_empty() {
            return Err(TipSelectionError::NoTips);
        }

        // Normalize weights
        let total: f64 = weights.iter().sum();
        if total == 0.0 {
            // All tips have zero score, select randomly
            let mut rng = thread_rng();
            return tip_hashes
                .choose(&mut rng)
                .copied()
                .ok_or(TipSelectionError::NoTips);
        }

        // Weighted random selection
        let mut rng = thread_rng();
        let random_value: f64 = rng.gen::<f64>() * total;

        let mut cumulative = 0.0;
        for (i, weight) in weights.iter().enumerate() {
            cumulative += weight;
            if cumulative >= random_value {
                return Ok(tip_hashes[i]);
            }
        }

        // Fallback to last tip
        tip_hashes.last().copied().ok_or(TipSelectionError::NoTips)
    }

    /// Get blue score for a block
    async fn get_blue_score(&self, hash: &Hash) -> Result<u64, TipSelectionError> {
        self.ghostdag
            .get_blue_score(hash)
            .await
            .map_err(|e| TipSelectionError::DagError(e.to_string()))
    }

    /// Get comprehensive tip information
    #[allow(dead_code)]
    async fn get_tip_info(&self, hash: &Hash) -> Result<TipInfo, TipSelectionError> {
        // Check cache first
        if let Some(info) = self.tip_cache.read().await.get(hash) {
            return Ok(info.clone());
        }

        let block = self
            .dag_store
            .get_block(hash)
            .await
            .map_err(|_| TipSelectionError::BlockNotFound(*hash))?;

        let blue_score = self.get_blue_score(hash).await?;

        let info = TipInfo {
            hash: *hash,
            blue_score,
            height: block.header.height,
            timestamp: block.header.timestamp,
        };

        // Cache the result
        self.tip_cache.write().await.insert(*hash, info.clone());

        Ok(info)
    }

    /// Clear tip cache
    pub async fn clear_cache(&self) {
        self.tip_cache.write().await.clear();
        info!("Cleared tip selection cache");
    }
}

/// Parent selection for new blocks
pub struct ParentSelector {
    tip_selector: Arc<TipSelector>,
    max_parents: usize,
    min_parents: usize,
}

impl ParentSelector {
    pub fn new(tip_selector: Arc<TipSelector>, min_parents: usize, max_parents: usize) -> Self {
        Self {
            tip_selector,
            min_parents,
            max_parents,
        }
    }

    /// Select parents for a new block
    pub async fn select_parents(&self) -> Result<(Hash, Vec<Hash>), TipSelectionError> {
        let all_parents = self.tip_selector.select_parents(self.max_parents).await?;

        if all_parents.is_empty() {
            return Err(TipSelectionError::NoTips);
        }

        // First parent becomes selected parent
        let selected_parent = all_parents[0];

        // Rest become merge parents (up to max_parents - 1)
        let merge_parents: Vec<Hash> = all_parents
            .into_iter()
            .skip(1)
            .take(self.max_parents - 1)
            .collect();

        // Enforce minimum number of parents (selected + merge)
        let total_parents = 1 + merge_parents.len();
        if total_parents < self.min_parents {
            return Err(TipSelectionError::NoTips);
        }

        info!(
            "Selected parent: {}, merge parents: {}",
            selected_parent,
            merge_parents.len()
        );

        Ok((selected_parent, merge_parents))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    async fn setup_test_env() -> (Arc<DagStore>, Arc<GhostDag>, Arc<TipSelector>) {
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
        let tip_selector = Arc::new(TipSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            SelectionStrategy::HighestBlueScoreWithTieBreak,
        ));

        (dag_store, ghostdag, tip_selector)
    }

    fn create_test_block(hash: [u8; 32], blue_score: u64) -> Block {
        BlockBuilder::new()
            .hash(Hash::new(hash))
            .blue_score(blue_score)
            .build_unhashed()
    }

    #[tokio::test]
    async fn test_tip_selection_highest_score() {
        let (dag_store, _ghostdag, _tip_selector) = setup_test_env().await;

        // Add blocks with different blue scores
        let block1 = create_test_block([1; 32], 10);
        let block2 = create_test_block([2; 32], 20);
        let block3 = create_test_block([3; 32], 15);

        dag_store.store_block(block1).await.unwrap();
        dag_store.store_block(block2.clone()).await.unwrap();
        dag_store.store_block(block3).await.unwrap();

        // Mock blue scores in ghostdag
        // Note: In real implementation, these would be calculated

        // Select tip - should be block2 with highest score
        // This test would need proper mocking or test setup
    }

    #[tokio::test]
    async fn test_parent_selection() {
        let (dag_store, _ghostdag, tip_selector) = setup_test_env().await;
        let _parent_selector = ParentSelector::new(tip_selector, 1, 3);

        // Add some blocks
        let block1 = create_test_block([1; 32], 10);
        dag_store.store_block(block1).await.unwrap();

        // Test parent selection
        // This would need proper setup with tips
    }

    // ===================================================================
    // H-08 regression: parent-selection comparator is a strict total order
    // ===================================================================

    fn ti(hash_byte: u8, blue: u64) -> TipInfo {
        TipInfo {
            hash: Hash::new([hash_byte; 32]),
            blue_score: blue,
            height: 0,
            timestamp: 0,
        }
    }

    #[test]
    fn h08_higher_blue_score_strictly_precedes_lower() {
        // Higher blue score must come first regardless of hash order.
        let lo_score_lo_hash = ti(0x10, 5);
        let hi_score_hi_hash = ti(0xF0, 50);
        assert_eq!(
            cmp_tip_for_parent_selection(&hi_score_hi_hash, &lo_score_lo_hash),
            std::cmp::Ordering::Less,
        );
        assert_eq!(
            cmp_tip_for_parent_selection(&lo_score_lo_hash, &hi_score_hi_hash),
            std::cmp::Ordering::Greater,
        );
    }

    #[test]
    fn h08_equal_blue_score_breaks_tie_by_lower_hash() {
        // The lower hash strictly precedes the higher hash when scores are equal.
        // This is the load-bearing tie-break that closes H-08.
        let lo_hash = ti(0x10, 42);
        let hi_hash = ti(0xF0, 42);
        assert_eq!(
            cmp_tip_for_parent_selection(&lo_hash, &hi_hash),
            std::cmp::Ordering::Less,
        );
        assert_eq!(
            cmp_tip_for_parent_selection(&hi_hash, &lo_hash),
            std::cmp::Ordering::Greater,
        );
    }

    #[test]
    fn h08_identical_tip_compares_equal() {
        let a = ti(0x42, 100);
        let b = ti(0x42, 100);
        assert_eq!(
            cmp_tip_for_parent_selection(&a, &b),
            std::cmp::Ordering::Equal,
        );
    }

    #[test]
    fn h08_sort_is_deterministic_across_input_permutations() {
        // Construct 8 tips with mixed blue scores including ties, sort them
        // under multiple input permutations, assert canonical order.
        let canonical = [
            ti(0x01, 50), // highest score, lowest hash
            ti(0x02, 50), // highest score, second-lowest hash
            ti(0x03, 50), // highest score, third-lowest hash
            ti(0x10, 30), // mid score, lowest hash
            ti(0x20, 30), // mid score, higher hash
            ti(0xA0, 10), // lowest score, lowest hash among low-score
            ti(0xB0, 10),
            ti(0xC0, 10),
        ];
        let canonical_hashes: Vec<Hash> = canonical.iter().map(|t| t.hash).collect();

        // Try several non-trivial permutations including reverse + interleaved.
        let permutations: Vec<Vec<usize>> = vec![
            vec![7, 6, 5, 4, 3, 2, 1, 0], // reverse
            vec![0, 7, 1, 6, 2, 5, 3, 4], // interleaved
            vec![3, 1, 7, 0, 5, 2, 6, 4], // arbitrary
            (0..8).map(|i| (i + 5) % 8).collect(),
        ];

        for perm in &permutations {
            let mut shuffled: Vec<TipInfo> = perm.iter().map(|&i| canonical[i].clone()).collect();
            shuffled.sort_by(cmp_tip_for_parent_selection);
            let sorted_hashes: Vec<Hash> = shuffled.iter().map(|t| t.hash).collect();
            assert_eq!(
                sorted_hashes, canonical_hashes,
                "tip-selection sort produced different output for permutation {:?}",
                perm
            );
        }
    }

    proptest::proptest! {
        // 1024 cases of equal-blue-score tip sets sorted under arbitrary
        // input permutation MUST produce identical output. This is the
        // proptest gate the planset calls for at WP-B1.1.
        #![proptest_config(proptest::test_runner::Config {
            cases: 1024,
            ..proptest::test_runner::Config::default()
        })]

        #[test]
        fn prop_tip_selection_deterministic_under_tie(
            // Up to 12 distinct hash bytes; blue scores in 0..3 so ties are
            // common. We use distinct hashes to model the structural
            // requirement that no two tips share a hash on a healthy chain.
            hash_bytes in proptest::collection::vec(0u8..=255, 1..=12),
            scores in proptest::collection::vec(0u64..3, 1..=12),
        ) {
            // Match the two vectors and dedup hashes — proptest may produce
            // duplicates; we filter to a unique set so the property is
            // about the comparator, not the input shape.
            let mut seen = std::collections::HashSet::new();
            let tips: Vec<TipInfo> = hash_bytes
                .iter()
                .zip(scores.iter().cycle())
                .filter_map(|(h, s)| {
                    if seen.insert(*h) {
                        Some(ti(*h, *s))
                    } else {
                        None
                    }
                })
                .collect();
            if tips.len() < 2 {
                return Ok(());
            }

            // Canonical sort.
            let mut canonical = tips.clone();
            canonical.sort_by(cmp_tip_for_parent_selection);
            let canonical_order: Vec<Hash> = canonical.iter().map(|t| t.hash).collect();

            // Several permutations.
            let mut shuffled = tips.clone();
            shuffled.reverse();
            shuffled.sort_by(cmp_tip_for_parent_selection);
            let reversed_then_sorted: Vec<Hash> = shuffled.iter().map(|t| t.hash).collect();
            proptest::prop_assert_eq!(reversed_then_sorted, canonical_order.clone());

            // Pairwise swap permutations.
            for i in 0..tips.len().saturating_sub(1) {
                let mut swapped = tips.clone();
                swapped.swap(i, i + 1);
                swapped.sort_by(cmp_tip_for_parent_selection);
                let swapped_then_sorted: Vec<Hash> = swapped.iter().map(|t| t.hash).collect();
                proptest::prop_assert_eq!(swapped_then_sorted, canonical_order.clone());
            }
        }
    }
}
