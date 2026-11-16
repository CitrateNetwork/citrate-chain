// citrate/core/consensus/src/ordering.rs

//! GHOSTDAG total order (r1007 spec 06 §3.2, ADR CV-4a).
//!
//! The execution order of the DAG is the concatenation, for each selected-chain
//! block C in increasing height, of [`consensus_ordered_mergeset`]`(C)`: the
//! selected parent SP(C) first, then `Mergeset*(C)` (the blocks C merges that
//! are not in past(SP(C))), blues and reds interleaved, in ASCENDING
//! fork-choice key `(blue_work, vrf_output, hash)`. This is rusty-kaspa
//! `GhostdagData::consensus_ordered_mergeset` with Citrate's key. It is a
//! linear extension of the DAG: the key strictly grows along every parent edge
//! of a validly-scored DAG (blue_work grows by at least one unit along SP
//! edges and SP is the heaviest parent).
//!
//! The former `TotalOrderIterator` (walk to genesis, mergesets from merge
//! parents only, DESCENDING score) is replaced. [`TotalOrdering`] keeps its
//! API for the DAG-wide order and is built on the same rule, computing each
//! chain block's `Mergeset*` structurally from the DAG.

use crate::acceptance::InclusionColor;
use crate::dag_store::DagStore;
use crate::ghostdag::GhostDag;
use crate::types::{ForkChoiceKey, GhostdagData, Hash};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Error, Debug)]
pub enum OrderingError {
    #[error("Block not found: {0}")]
    BlockNotFound(Hash),

    #[error("Invalid ordering state")]
    InvalidState,

    #[error("Cycle detected in ordering")]
    CycleDetected,

    #[error("DAG store error: {0}")]
    DagStoreError(String),

    /// RM-B1 / WP-B4.1 (audit C-03): error from the GhostDAG engine.
    #[error("DAG error: {0}")]
    DagError(String),
}

/// One block of an accepting block's ordered mergeset, with its color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderedMember {
    pub hash: Hash,
    pub color: InclusionColor,
}

/// Spec 06 §3.2: the blocks chain block C accepts, in execution order.
///
/// `data` is C's GHOSTDAG record (its `mergeset_blues` start with SP). The
/// result is SP first, then every other block of `mergeset_blues` and
/// `mergeset_reds` sorted ascending by its fork-choice key, which `key_of`
/// supplies from committed header fields. Genesis (no selected parent)
/// accepts nothing. A block whose key is unavailable fails closed with
/// `BlockNotFound`: the order is never guessed.
pub fn consensus_ordered_mergeset<F>(
    data: &GhostdagData,
    mut key_of: F,
) -> Result<Vec<OrderedMember>, OrderingError>
where
    F: FnMut(&Hash) -> Option<ForkChoiceKey>,
{
    if data.selected_parent == Hash::default() {
        return Ok(Vec::new());
    }
    let mut rest: Vec<(ForkChoiceKey, OrderedMember)> = Vec::with_capacity(
        data.mergeset_blues
            .len()
            .saturating_add(data.mergeset_reds.len()),
    );
    for h in data
        .mergeset_blues
        .iter()
        .filter(|h| **h != data.selected_parent)
    {
        let key = key_of(h).ok_or(OrderingError::BlockNotFound(*h))?;
        rest.push((
            key,
            OrderedMember {
                hash: *h,
                color: InclusionColor::Blue,
            },
        ));
    }
    for h in &data.mergeset_reds {
        let key = key_of(h).ok_or(OrderingError::BlockNotFound(*h))?;
        rest.push((
            key,
            OrderedMember {
                hash: *h,
                color: InclusionColor::Red,
            },
        ));
    }
    rest.sort_by_key(|(key, _)| *key);
    let mut out = Vec::with_capacity(rest.len().saturating_add(1));
    out.push(OrderedMember {
        hash: data.selected_parent,
        color: InclusionColor::SelectedParent,
    });
    out.extend(rest.into_iter().map(|(_, m)| m));
    Ok(out)
}

/// Result of ordering a range of blocks
#[derive(Debug, Clone)]
pub struct OrderedBlockRange {
    /// Blocks in total order (oldest first)
    pub blocks: Vec<Hash>,

    /// Transactions in total order (for execution)
    pub transaction_order: Vec<TransactionRef>,

    /// Starting block hash
    pub from: Hash,

    /// Ending block hash
    pub to: Hash,
}

/// Reference to a transaction within a block
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionRef {
    /// Block containing the transaction
    pub block_hash: Hash,

    /// Index within the block's transaction list
    pub tx_index: usize,

    /// Transaction hash
    pub tx_hash: Hash,
}

/// `Mergeset*(chain)` computed structurally: every block reachable from
/// `chain`'s merge parents that is not in `seen` (which must hold
/// past(SP(chain)) ∪ {SP(chain)}), sorted ascending by fork-choice key.
async fn structural_mergeset_star(
    dag_store: &DagStore,
    merge_parents: &[Hash],
    seen: &HashSet<Hash>,
) -> Result<Vec<Hash>, OrderingError> {
    let mut found: HashMap<Hash, ForkChoiceKey> = HashMap::new();
    let mut queue: VecDeque<Hash> = merge_parents.iter().copied().collect();
    while let Some(h) = queue.pop_front() {
        if seen.contains(&h) || found.contains_key(&h) || h == Hash::default() {
            continue;
        }
        let header = dag_store
            .get_header(&h)
            .await
            .map_err(|_| OrderingError::BlockNotFound(h))?;
        found.insert(h, ForkChoiceKey::of_header(&header));
        queue.push_back(header.selected_parent_hash);
        queue.extend(header.merge_parent_hashes.iter().copied());
    }
    let mut ms: Vec<(ForkChoiceKey, Hash)> = found.into_iter().map(|(h, k)| (k, h)).collect();
    ms.sort();
    Ok(ms.into_iter().map(|(_, h)| h).collect())
}

/// The selected chain from `tip` down to genesis, tip first.
async fn selected_chain(dag_store: &DagStore, tip: Hash) -> Result<Vec<Hash>, OrderingError> {
    let mut chain = Vec::new();
    let mut current = tip;
    loop {
        chain.push(current);
        let header = dag_store
            .get_header(&current)
            .await
            .map_err(|_| OrderingError::BlockNotFound(current))?;
        if header.selected_parent_hash == Hash::default() {
            break;
        }
        if chain.len() > 50_000_000 {
            return Err(OrderingError::CycleDetected);
        }
        current = header.selected_parent_hash;
    }
    Ok(chain)
}

/// Total ordering manager
pub struct TotalOrdering {
    dag_store: Arc<DagStore>,
    /// Kept for API compatibility; the order reads committed header keys only.
    #[allow(dead_code)]
    ghostdag: Arc<GhostDag>,

    /// Cache of ordered ranges
    order_cache: tokio::sync::RwLock<HashMap<(Hash, Hash), Vec<Hash>>>,
}

impl TotalOrdering {
    pub fn new(dag_store: Arc<DagStore>, ghostdag: Arc<GhostDag>) -> Self {
        Self {
            dag_store,
            ghostdag,
            order_cache: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Get total order of all blocks from genesis to tip
    pub async fn get_total_order(&self, tip: Hash) -> Result<Vec<Hash>, OrderingError> {
        // Check cache
        let cache_key = (Hash::default(), tip);
        if let Some(cached) = self.order_cache.read().await.get(&cache_key) {
            return Ok(cached.clone());
        }

        // Calculate order: genesis, then for each chain block C_i (i >= 1)
        // its selected parent C_{i-1} and Mergeset*(C_i) ascending by key,
        // then the tip itself (which its future chain child accepts first).
        let mut chain = selected_chain(&self.dag_store, tip).await?;
        chain.reverse();
        let mut order: Vec<Hash> = Vec::new();
        let mut seen: HashSet<Hash> = HashSet::new();
        if let Some(g) = chain.first() {
            order.push(*g);
            seen.insert(*g);
        }
        for i in 1..chain.len() {
            let (Some(sp), Some(c)) = (chain.get(i.saturating_sub(1)), chain.get(i)) else {
                return Err(OrderingError::InvalidState);
            };
            if seen.insert(*sp) {
                order.push(*sp);
            }
            let header = self
                .dag_store
                .get_header(c)
                .await
                .map_err(|_| OrderingError::BlockNotFound(*c))?;
            let ms = structural_mergeset_star(&self.dag_store, &header.merge_parent_hashes, &seen)
                .await?;
            for h in ms {
                if seen.insert(h) {
                    order.push(h);
                }
            }
        }
        if chain.len() > 1 && seen.insert(tip) {
            order.push(tip);
        }

        // Cache result
        self.order_cache
            .write()
            .await
            .insert(cache_key, order.clone());

        info!(
            "Computed total order of {} blocks ending at {}",
            order.len(),
            tip
        );

        Ok(order)
    }

    /// Get ordered blocks between two points (exclusive of from, inclusive of to)
    pub async fn get_ordered_blocks(
        &self,
        from: Hash,
        to: Hash,
    ) -> Result<OrderedBlockRange, OrderingError> {
        // Get full order to tip
        let full_order = self.get_total_order(to).await?;

        // Find starting point
        let from_idx = if from == Hash::default() {
            0
        } else {
            full_order
                .iter()
                .position(|h| *h == from)
                .ok_or(OrderingError::BlockNotFound(from))?
                .saturating_add(1) // Exclusive of 'from'
        };

        // Slice the relevant portion
        // from_idx <= len (position < len, plus one), so this is never None.
        let blocks: Vec<Hash> = full_order
            .get(from_idx..)
            .map(<[Hash]>::to_vec)
            .unwrap_or_default();

        // Build transaction order
        let mut transaction_order = Vec::new();
        for block_hash in &blocks {
            let block = self
                .dag_store
                .get_block(block_hash)
                .await
                .map_err(|_| OrderingError::BlockNotFound(*block_hash))?;

            for (tx_index, tx) in block.transactions.iter().enumerate() {
                transaction_order.push(TransactionRef {
                    block_hash: *block_hash,
                    tx_index,
                    tx_hash: tx.hash,
                });
            }
        }

        debug!(
            "Ordered {} blocks with {} transactions from {} to {}",
            blocks.len(),
            transaction_order.len(),
            from,
            to
        );

        Ok(OrderedBlockRange {
            blocks,
            transaction_order,
            from,
            to,
        })
    }

    /// Get transaction execution order for a range
    pub async fn get_transaction_order(
        &self,
        from: Hash,
        to: Hash,
    ) -> Result<Vec<TransactionRef>, OrderingError> {
        let range = self.get_ordered_blocks(from, to).await?;
        Ok(range.transaction_order)
    }

    /// Verify that two orderings are consistent
    pub fn verify_ordering_consistency(order1: &[Hash], order2: &[Hash]) -> bool {
        if order1.len() != order2.len() {
            return false;
        }

        order1.iter().zip(order2.iter()).all(|(a, b)| a == b)
    }

    /// Clear the order cache (e.g., after reorg)
    pub async fn clear_cache(&self) {
        self.order_cache.write().await.clear();
        debug!("Cleared total ordering cache");
    }

    /// Invalidate cache entries that include a specific block
    pub async fn invalidate_block(&self, block: &Hash) {
        let mut cache = self.order_cache.write().await;
        cache.retain(|(_, to), order| *to != *block && !order.contains(block));
        debug!("Invalidated cache entries containing block {}", block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn create_test_block(
        hash: [u8; 32],
        selected_parent: Hash,
        merge_parents: Vec<Hash>,
        height: u64,
        blue_score: u64,
    ) -> Block {
        BlockBuilder::new()
            .hash(Hash::new(hash))
            .parent(selected_parent)
            .merge_parents(merge_parents)
            .height(height)
            .blue_score(blue_score)
            .build_unhashed()
    }

    #[tokio::test]
    async fn test_linear_chain_ordering() {
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));

        // Create linear chain: G -> A -> B -> C
        // Use non-zero hash for genesis to avoid confusion with Hash::default()
        let genesis = create_test_block([0xFF; 32], Hash::default(), vec![], 0, 1);
        let block_a = create_test_block([1; 32], genesis.hash(), vec![], 1, 2);
        let block_b = create_test_block([2; 32], block_a.hash(), vec![], 2, 3);
        let block_c = create_test_block([3; 32], block_b.hash(), vec![], 3, 4);

        dag_store.store_block(genesis.clone()).await.unwrap();
        dag_store.store_block(block_a.clone()).await.unwrap();
        dag_store.store_block(block_b.clone()).await.unwrap();
        dag_store.store_block(block_c.clone()).await.unwrap();

        let ordering = TotalOrdering::new(dag_store.clone(), ghostdag.clone());
        let order = ordering.get_total_order(block_c.hash()).await.unwrap();

        assert_eq!(order.len(), 4);
        assert_eq!(order[0], genesis.hash());
        assert_eq!(order[1], block_a.hash());
        assert_eq!(order[2], block_b.hash());
        assert_eq!(order[3], block_c.hash());
    }

    #[tokio::test]
    async fn test_simple_fork_ordering() {
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));

        // Create fork:
        //     G
        //    / \
        //   A   B
        //    \ /
        //     C (selects A, merges B)

        let genesis = create_test_block([0xFF; 32], Hash::default(), vec![], 0, 1);
        let block_a = create_test_block([1; 32], genesis.hash(), vec![], 1, 2);
        let block_b = create_test_block([2; 32], genesis.hash(), vec![], 1, 2);
        let block_c = create_test_block([3; 32], block_a.hash(), vec![block_b.hash()], 2, 4);

        dag_store.store_block(genesis.clone()).await.unwrap();
        dag_store.store_block(block_a.clone()).await.unwrap();
        dag_store.store_block(block_b.clone()).await.unwrap();
        dag_store.store_block(block_c.clone()).await.unwrap();

        let ordering = TotalOrdering::new(dag_store.clone(), ghostdag.clone());
        let order = ordering.get_total_order(block_c.hash()).await.unwrap();

        // Order should be: G, A, B (via mergeset), C
        // or G, A, C, B depending on when B is picked up
        assert_eq!(order.len(), 4);
        assert_eq!(order[0], genesis.hash()); // Genesis first
        assert_eq!(order[1], block_a.hash()); // Selected parent chain
                                              // B should appear before or at C since it's in C's mergeset
        assert!(order.contains(&block_b.hash()));
        assert!(order.contains(&block_c.hash()));

        // C must come after A (its selected parent)
        let a_pos = order.iter().position(|h| *h == block_a.hash()).unwrap();
        let c_pos = order.iter().position(|h| *h == block_c.hash()).unwrap();
        assert!(c_pos > a_pos);
    }

    #[tokio::test]
    async fn test_ordering_determinism() {
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));

        // Create a more complex DAG
        let genesis = create_test_block([0xFF; 32], Hash::default(), vec![], 0, 1);
        let block_a = create_test_block([1; 32], genesis.hash(), vec![], 1, 2);
        let block_b = create_test_block([2; 32], genesis.hash(), vec![], 1, 2);
        let block_c = create_test_block([3; 32], block_a.hash(), vec![], 2, 3);
        let block_d = create_test_block([4; 32], block_c.hash(), vec![block_b.hash()], 3, 5);

        dag_store.store_block(genesis.clone()).await.unwrap();
        dag_store.store_block(block_a.clone()).await.unwrap();
        dag_store.store_block(block_b.clone()).await.unwrap();
        dag_store.store_block(block_c.clone()).await.unwrap();
        dag_store.store_block(block_d.clone()).await.unwrap();

        let ordering = TotalOrdering::new(dag_store.clone(), ghostdag.clone());

        // Run ordering multiple times to verify determinism
        let order1 = ordering.get_total_order(block_d.hash()).await.unwrap();

        // Clear cache and recompute
        ordering.clear_cache().await;
        let order2 = ordering.get_total_order(block_d.hash()).await.unwrap();

        assert!(TotalOrdering::verify_ordering_consistency(&order1, &order2));
    }

    #[tokio::test]
    async fn test_ordered_blocks_range() {
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));

        // Linear chain
        let genesis = create_test_block([0xFF; 32], Hash::default(), vec![], 0, 1);
        let block_a = create_test_block([1; 32], genesis.hash(), vec![], 1, 2);
        let block_b = create_test_block([2; 32], block_a.hash(), vec![], 2, 3);
        let block_c = create_test_block([3; 32], block_b.hash(), vec![], 3, 4);

        dag_store.store_block(genesis.clone()).await.unwrap();
        dag_store.store_block(block_a.clone()).await.unwrap();
        dag_store.store_block(block_b.clone()).await.unwrap();
        dag_store.store_block(block_c.clone()).await.unwrap();

        let ordering = TotalOrdering::new(dag_store.clone(), ghostdag.clone());

        // Get range from A (exclusive) to C (inclusive)
        let range = ordering
            .get_ordered_blocks(block_a.hash(), block_c.hash())
            .await
            .unwrap();

        assert_eq!(range.blocks.len(), 2); // B and C
        assert_eq!(range.blocks[0], block_b.hash());
        assert_eq!(range.blocks[1], block_c.hash());
    }

    #[tokio::test]
    async fn test_transaction_ordering() {
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));

        // Create blocks with transactions
        let tx1 = Transaction {
            hash: Hash::new([0x11; 32]),
            nonce: 1,
            from: PublicKey::new([1; 32]),
            to: Some(PublicKey::new([2; 32])),
            value: 100,
            gas_limit: 21000,
            gas_price: 1,
            data: vec![],
            signature: Signature::new([0; 64]),
            tx_type: Some(TransactionType::Standard),
            ..Default::default()
        };

        let tx2 = Transaction {
            hash: Hash::new([0x22; 32]),
            nonce: 2,
            from: PublicKey::new([1; 32]),
            to: Some(PublicKey::new([2; 32])),
            value: 200,
            gas_limit: 21000,
            gas_price: 1,
            data: vec![],
            signature: Signature::new([0; 64]),
            tx_type: Some(TransactionType::Standard),
            ..Default::default()
        };

        let mut genesis = create_test_block([0xFF; 32], Hash::default(), vec![], 0, 1);
        genesis.transactions.push(tx1.clone());

        let mut block_a = create_test_block([1; 32], genesis.hash(), vec![], 1, 2);
        block_a.transactions.push(tx2.clone());

        dag_store.store_block(genesis.clone()).await.unwrap();
        dag_store.store_block(block_a.clone()).await.unwrap();

        let ordering = TotalOrdering::new(dag_store.clone(), ghostdag.clone());
        let tx_order = ordering
            .get_transaction_order(Hash::default(), block_a.hash())
            .await
            .unwrap();

        assert_eq!(tx_order.len(), 2);
        assert_eq!(tx_order[0].tx_hash, tx1.hash);
        assert_eq!(tx_order[0].block_hash, genesis.hash());
        assert_eq!(tx_order[1].tx_hash, tx2.hash);
        assert_eq!(tx_order[1].block_hash, block_a.hash());
    }

    fn key(work: u128, vrf: u8, h: u8) -> ForkChoiceKey {
        ForkChoiceKey {
            blue_work: work,
            vrf_output: Hash::new([vrf; 32]),
            hash: Hash::new([h; 32]),
        }
    }

    /// Spec 06 §3.2: SP first, then blues and reds interleaved ascending by
    /// (blue_work, vrf_output, hash), whatever order the record lists them in.
    #[test]
    fn consensus_order_is_sp_then_ascending_key_interleaving_colors() {
        let sp = Hash::new([9; 32]);
        let keys: HashMap<Hash, ForkChoiceKey> = [
            (Hash::new([1; 32]), key(3, 7, 1)),
            (Hash::new([2; 32]), key(2, 9, 2)),
            (Hash::new([3; 32]), key(3, 5, 3)),
            (Hash::new([4; 32]), key(2, 9, 4)),
        ]
        .into_iter()
        .collect();
        let mut data = GhostdagData::with_selected_parent(sp, Hash::default());
        data.mergeset_blues.push(Hash::new([1; 32]));
        data.mergeset_blues.push(Hash::new([4; 32]));
        data.mergeset_reds.push(Hash::new([3; 32]));
        data.mergeset_reds.push(Hash::new([2; 32]));
        let order = consensus_ordered_mergeset(&data, |h| keys.get(h).copied()).expect("order");
        let got: Vec<(u8, InclusionColor)> = order
            .iter()
            .map(|m| (m.hash.as_bytes()[0], m.color))
            .collect();
        assert_eq!(
            got,
            vec![
                (9, InclusionColor::SelectedParent),
                (2, InclusionColor::Red),
                (4, InclusionColor::Blue),
                (3, InclusionColor::Red),
                (1, InclusionColor::Blue),
            ]
        );
    }

    #[test]
    fn consensus_order_of_genesis_is_empty_and_missing_key_fails_closed() {
        assert!(
            consensus_ordered_mergeset(&GhostdagData::genesis(), |_| None)
                .expect("genesis")
                .is_empty()
        );
        let mut data = GhostdagData::with_selected_parent(Hash::new([9; 32]), Hash::default());
        data.mergeset_reds.push(Hash::new([1; 32]));
        assert!(matches!(
            consensus_ordered_mergeset(&data, |_| None),
            Err(OrderingError::BlockNotFound(_))
        ));
    }
}
