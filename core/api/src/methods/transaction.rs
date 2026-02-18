// citrate/core/api/src/methods/transaction.rs
use crate::types::{
    error::ApiError,
    request::{CallRequest, TransactionRequest},
};
use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, TxClass};
use std::sync::Arc;

/// Transaction-related API methods
pub struct TransactionApi {
    mempool: Arc<Mempool>,
    executor: Arc<Executor>,
    chain_id: u64,
}

impl TransactionApi {
    pub fn new(mempool: Arc<Mempool>, executor: Arc<Executor>, chain_id: u64) -> Self {
        Self { mempool, executor, chain_id }
    }

    /// Send raw transaction
    pub async fn send_raw_transaction(&self, raw_tx: Vec<u8>) -> Result<Hash, ApiError> {
        // Deserialize transaction
        let tx: Transaction = bincode::deserialize(&raw_tx)
            .map_err(|e| ApiError::InvalidTransaction(e.to_string()))?;

        let hash = tx.hash;

        // Add to mempool
        self.mempool
            .add_transaction(tx, TxClass::Standard)
            .await
            .map_err(|e| ApiError::InvalidTransaction(e.to_string()))?;

        Ok(hash)
    }

    /// Create and send transaction
    pub async fn send_transaction(&self, request: TransactionRequest) -> Result<Hash, ApiError> {
        // Get nonce if not provided
        let nonce = match request.nonce {
            Some(n) => n,
            None => self.executor.get_nonce(&request.from),
        };

        // Create transaction hash from nonce + from + to + timestamp
        let mut hash_data = [0u8; 32];
        hash_data[0..8].copy_from_slice(&nonce.to_le_bytes());
        hash_data[8..16].copy_from_slice(&request.from.0[0..8]);
        if let Some(to) = &request.to {
            hash_data[16..24].copy_from_slice(&to.0[0..8]);
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        hash_data[24..32].copy_from_slice(&ts.to_le_bytes());

        // Embed 20-byte EVM addresses into 32-byte PublicKey fields (padded with trailing zeros)
        // This matches the "embedded EVM address" convention used by Address::from_public_key
        let mut from_bytes = [0u8; 32];
        from_bytes[..20].copy_from_slice(&request.from.0);

        let to_pubkey = request.to.map(|addr| {
            let mut to_bytes = [0u8; 32];
            to_bytes[..20].copy_from_slice(&addr.0);
            PublicKey::new(to_bytes)
        });

        // Create transaction
        // SECURITY (C-02): This method is only reachable when allow_eth_send_transaction
        // is true (devnet mode). The dummy signature is acceptable because the RPC server
        // gates access; ecdsa_verified is set so the verifier accepts this trusted local tx.
        let mut tx = Transaction {
            hash: Hash::new(hash_data),
            nonce,
            from: PublicKey::new(from_bytes),
            to: to_pubkey,
            value: request.value.unwrap_or_default().as_u128(),
            gas_limit: request.gas.unwrap_or(21000),
            gas_price: request.gas_price.unwrap_or(1_000_000_000),
            data: request.data.unwrap_or_default(),
            signature: Signature::new([1; 64]), // Devnet-only: unsigned transaction
            tx_type: None,
            ecdsa_verified: true, // Trusted: devnet mode gated by RPC config
            chain_id: Some(self.chain_id), // M-01: always bind to chain domain
            ..Default::default()
        };

        // Determine transaction type from data
        tx.determine_type();

        let hash = tx.hash;

        // Add to mempool
        self.mempool
            .add_transaction(tx, TxClass::Standard)
            .await
            .map_err(|e| ApiError::InvalidTransaction(e.to_string()))?;

        Ok(hash)
    }

    /// Estimate gas for transaction
    pub async fn estimate_gas(&self, request: CallRequest) -> Result<u64, ApiError> {
        // Basic gas estimation
        let base_gas = 21000u64;
        let data_gas = request.data.as_ref().map_or(0, |d| {
            d.iter()
                .map(|&byte| if byte == 0 { 4 } else { 68 })
                .sum::<u64>()
        });

        Ok(base_gas + data_gas)
    }

    /// Get current gas price
    pub async fn get_gas_price(&self) -> Result<u64, ApiError> {
        // Return minimum gas price for now
        Ok(1_000_000_000) // 1 Gwei
    }

    /// Get transaction count (nonce) for address
    pub async fn get_transaction_count(
        &self,
        address: citrate_execution::types::Address,
    ) -> Result<u64, ApiError> {
        Ok(self.executor.get_nonce(&address))
    }
}
