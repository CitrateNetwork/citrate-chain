// citrate/core/api/src/methods/mempool.rs
use crate::types::{
    error::ApiError,
    response::{
        MempoolStatus, PendingTransactionSummary, PendingTransactionsResponse, TransactionResponse,
    },
};
use citrate_consensus::types::Hash;
use citrate_sequencer::mempool::Mempool;
use serde_json::Value;
use std::sync::Arc;

pub const DEFAULT_PENDING_LIMIT: usize = 25;
pub const MAX_PENDING_LIMIT: usize = 100;
pub const MAX_PENDING_OFFSET: usize = 10_000;
pub const MAX_PENDING_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingQuery {
    pub offset: usize,
    pub limit: usize,
}

impl PendingQuery {
    pub fn from_params_map(map: &serde_json::Map<String, Value>) -> Result<Self, ApiError> {
        let offset = parse_usize_field(map.get("offset"), "offset", 0)?;
        if offset > MAX_PENDING_OFFSET {
            return Err(ApiError::InvalidParams(format!(
                "offset exceeds maximum {}",
                MAX_PENDING_OFFSET
            )));
        }

        let requested_limit = parse_usize_field(map.get("limit"), "limit", DEFAULT_PENDING_LIMIT)?;
        let limit = requested_limit.min(MAX_PENDING_LIMIT);

        Ok(Self { offset, limit })
    }
}

fn parse_usize_field(
    value: Option<&Value>,
    field: &str,
    default: usize,
) -> Result<usize, ApiError> {
    match value {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Number(n)) => {
            n.as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .ok_or_else(|| {
                    ApiError::InvalidParams(format!("{} must be a non-negative integer", field))
                })
        }
        Some(Value::String(s)) => s.parse::<usize>().map_err(|_| {
            ApiError::InvalidParams(format!("{} must be a non-negative integer", field))
        }),
        Some(_) => Err(ApiError::InvalidParams(format!(
            "{} must be a non-negative integer",
            field
        ))),
    }
}

/// Mempool-related API methods
pub struct MempoolApi {
    mempool: Arc<Mempool>,
}

impl MempoolApi {
    pub fn new(mempool: Arc<Mempool>) -> Self {
        Self { mempool }
    }

    /// Get mempool status
    pub async fn get_status(&self) -> Result<MempoolStatus, ApiError> {
        let stats = self.mempool.stats().await;

        Ok(MempoolStatus {
            pending: stats.total_transactions,
            queued: 0, // Not tracking queued separately for now
            total_size: stats.total_size,
            max_size: 10_000_000, // 10MB default max size
        })
    }

    /// Get pending transaction
    pub async fn get_transaction(
        &self,
        hash: Hash,
    ) -> Result<Option<TransactionResponse>, ApiError> {
        let tx = self.mempool.get_transaction(&hash).await;
        Ok(tx.map(Into::into))
    }

    /// List pending transactions as bounded, redacted summaries.
    pub async fn get_pending(
        &self,
        query: PendingQuery,
    ) -> Result<PendingTransactionsResponse, ApiError> {
        let stats = self.mempool.stats().await;
        let total = stats.total_transactions;
        let fetch_limit = query.offset.saturating_add(query.limit).min(total);
        let txs = self.mempool.get_transactions(fetch_limit).await;

        let mut pending = Vec::new();
        let mut approx_bytes = 128usize;
        let mut response_truncated = fetch_limit < total;

        for tx in txs.into_iter().skip(query.offset) {
            let summary = PendingTransactionSummary::from(tx);
            let encoded_len = serde_json::to_vec(&summary)
                .map_err(|e| {
                    ApiError::InternalError(format!("mempool summary serialization failed: {}", e))
                })?
                .len();
            if approx_bytes.saturating_add(encoded_len) > MAX_PENDING_RESPONSE_BYTES {
                response_truncated = true;
                break;
            }
            approx_bytes = approx_bytes.saturating_add(encoded_len);
            pending.push(summary);
        }

        Ok(PendingTransactionsResponse {
            returned: pending.len(),
            pending,
            total_transactions: total,
            total_bytes: stats.total_size,
            offset: query.offset,
            limit: query.limit,
            truncated: response_truncated || query.offset.saturating_add(query.limit) < total,
        })
    }

    /// Clear mempool (admin only)
    pub async fn clear(&self) -> Result<(), ApiError> {
        self.mempool.clear().await;
        Ok(())
    }
}
