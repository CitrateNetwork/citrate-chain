// citrate/core/api/src/methods/chain.rs
use crate::types::{
    error::ApiError,
    request::{BlockId, BlockTag},
    response::{BlockResponse, TransactionResponse},
};
use citrate_consensus::types::{Block, BlockHeader, Hash};
use citrate_execution::types::TransactionReceipt;
use citrate_storage::StorageManager;
use std::sync::Arc;

/// Chain-related API methods
pub struct ChainApi {
    storage: Arc<StorageManager>,
}

impl ChainApi {
    pub fn new(storage: Arc<StorageManager>) -> Self {
        Self { storage }
    }

    /// Get block by ID
    pub async fn get_block(&self, block_id: BlockId) -> Result<BlockResponse, ApiError> {
        let block = match block_id {
            BlockId::Hash(hash) => self
                .storage
                .blocks
                .get_block(&hash)
                .map_err(|e| ApiError::InternalError(e.to_string()))?
                .ok_or_else(|| ApiError::BlockNotFound(format!("{:?}", hash)))?,
            BlockId::Number(height) => {
                // The executed chain's block at this height (chain#421), never a
                // later-stored sibling. Finality tags resolve by hash in eth_rpc.
                let hash = self
                    .storage
                    .blocks
                    .get_canonical_block_by_height(height)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?
                    .ok_or_else(|| ApiError::BlockNotFound(format!("height {}", height)))?;

                self.storage
                    .blocks
                    .get_block(&hash)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?
                    .ok_or_else(|| ApiError::BlockNotFound(format!("{:?}", hash)))?
            }
            BlockId::Tag(tag) => {
                let height = match tag {
                    BlockTag::Latest => self.get_latest_height().await?,
                    BlockTag::Earliest => 0,
                    BlockTag::Pending => {
                        return Err(ApiError::InvalidParams(
                            "Pending blocks not supported".into(),
                        ))
                    }
                };

                // latest / earliest tag, on the executed chain (finality tags never reach here).
                let hash = self
                    .storage
                    .blocks
                    .get_canonical_block_by_height(height)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?
                    .ok_or_else(|| ApiError::BlockNotFound(format!("height {}", height)))?;

                self.storage
                    .blocks
                    .get_block(&hash)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?
                    .ok_or_else(|| ApiError::BlockNotFound(format!("{:?}", hash)))?
            }
        };

        Ok(accepting_view(&self.storage, block))
    }

    /// r1007 S3-3b (spec 06 §5.1): whether `hash` is the applied chain's block
    /// at `height` (the canonical height index, which tip writes keep at the
    /// applied chain).
    pub fn is_on_applied_chain(&self, hash: &Hash, height: u64) -> bool {
        matches!(
            self.storage.blocks.get_canonical_block_by_height(height),
            Ok(Some(h)) if h == *hash
        )
    }

    /// Get block header by ID
    pub async fn get_block_header(&self, block_id: BlockId) -> Result<BlockHeader, ApiError> {
        let header = match block_id {
            BlockId::Hash(hash) => self
                .storage
                .blocks
                .get_header(&hash)
                .map_err(|e| ApiError::InternalError(e.to_string()))?
                .ok_or_else(|| ApiError::BlockNotFound(format!("{:?}", hash)))?,
            BlockId::Number(height) => {
                // The executed chain's block at this height (chain#421), never a
                // later-stored sibling. Finality tags resolve by hash in eth_rpc.
                let hash = self
                    .storage
                    .blocks
                    .get_canonical_block_by_height(height)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?
                    .ok_or_else(|| ApiError::BlockNotFound(format!("height {}", height)))?;

                self.storage
                    .blocks
                    .get_header(&hash)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?
                    .ok_or_else(|| ApiError::BlockNotFound(format!("{:?}", hash)))?
            }
            BlockId::Tag(tag) => {
                let height = match tag {
                    BlockTag::Latest => self.get_latest_height().await?,
                    BlockTag::Earliest => 0,
                    BlockTag::Pending => {
                        return Err(ApiError::InvalidParams(
                            "Pending blocks not supported".into(),
                        ))
                    }
                };

                // latest / earliest tag, on the executed chain (finality tags never reach here).
                let hash = self
                    .storage
                    .blocks
                    .get_canonical_block_by_height(height)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?
                    .ok_or_else(|| ApiError::BlockNotFound(format!("height {}", height)))?;

                self.storage
                    .blocks
                    .get_header(&hash)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?
                    .ok_or_else(|| ApiError::BlockNotFound(format!("{:?}", hash)))?
            }
        };

        Ok(header)
    }

    /// Get transaction by hash
    pub async fn get_transaction(&self, hash: Hash) -> Result<TransactionResponse, ApiError> {
        let tx = self
            .storage
            .transactions
            .get_transaction(&hash)
            .map_err(|e| ApiError::InternalError(e.to_string()))?
            .ok_or_else(|| ApiError::TransactionNotFound(format!("{:?}", hash)))?;

        Ok(tx.into())
    }

    /// Get transaction receipt
    pub async fn get_receipt(&self, hash: Hash) -> Result<TransactionReceipt, ApiError> {
        self.storage
            .transactions
            .get_receipt(&hash)
            .map_err(|e| ApiError::InternalError(e.to_string()))?
            .ok_or_else(|| ApiError::TransactionNotFound(format!("Receipt for {:?}", hash)))
    }

    /// Get current chain height
    pub async fn get_height(&self) -> Result<u64, ApiError> {
        self.get_latest_height().await
    }

    /// Get current DAG tips
    pub async fn get_tips(&self) -> Result<Vec<Hash>, ApiError> {
        let mut tips = self
            .storage
            .blocks
            .get_tips()
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

        if tips.is_empty() {
            let height = self.get_latest_height().await?;
            // Latest height, only when there are no DAG tips.
            if let Some(hash) = self
                .storage
                .blocks
                .get_canonical_block_by_height(height)
                .map_err(|e| ApiError::InternalError(e.to_string()))?
            {
                tips.push(hash);
            }
        }

        Ok(tips)
    }

    // Helper method
    /// r1007 S3-3b (spec 06 §5.1): `eth_blockNumber` / `latest` is the APPLIED
    /// tip (the block whose post-state the node serves and whose executed
    /// list is indexed), not the highest stored block, which can be admitted
    /// but not yet executed. A store with no applied tip (no block executed
    /// yet, or a pre-tip store) falls back to the stored head.
    async fn get_latest_height(&self) -> Result<u64, ApiError> {
        if let Ok(Some((_, h))) = self.storage.blocks.get_applied_tip() {
            return Ok(h);
        }
        self.storage
            .blocks
            .get_latest_height()
            .map_err(|e| ApiError::InternalError(e.to_string()))
    }
}

/// r1007 S3-3b (spec 06 §5.2): the RPC view of `block`. A block that accepted
/// a mergeset (`accepted_root` set) lists the transactions it EXECUTED, in
/// execution order (`canonical_logs::executed_transactions`: the receipt index
/// and stored bodies); its own list stays in `included_transactions`. A
/// pre-r1007 block executed its own list and is served as stored.
pub fn accepting_view(storage: &StorageManager, block: Block) -> BlockResponse {
    let accepting = block.accepted_root != Hash::default();
    let executed = if accepting {
        crate::canonical_logs::executed_transactions(storage, &block).ok()
    } else {
        None
    };
    let mut resp: BlockResponse = block.into();
    if let Some(list) = executed {
        resp.transactions = list.into_iter().map(|(t, _)| t.into()).collect();
    }
    resp
}
