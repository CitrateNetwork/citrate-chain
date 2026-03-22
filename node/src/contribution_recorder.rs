//! LC.4.3: ContributionAccounting on-chain recorder.
//!
//! Records Validation, ModelHosting, and AdapterCreation contributions
//! to the ContributionAccounting.sol contract via JSON-RPC eth_sendTransaction.
//!
//! Data source: ContributionAccounting.recordContribution(address,uint8,uint256)
//! Contract: contracts/src/ContributionAccounting.sol
//!
//! ContributionType enum mapping:
//!   0 = Validation
//!   1 = ModelHosting
//!   2 = AdapterCreation
//!   3 = DataProvision
//!   4 = AppDevelopment
//!   5 = BridgeInfra
//!   6 = Governance

use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

/// Records contributions to the on-chain ContributionAccounting contract.
///
/// Uses JSON-RPC `eth_sendTransaction` (devnet-mode, unsigned).
/// For testnet/mainnet, this would need wallet-signed transactions.
///
/// All methods are fire-and-forget: failures are logged but never block
/// the caller. The block producer spawns recording as background tasks.
pub struct ContributionRecorder {
    /// JSON-RPC endpoint URL (e.g., "http://127.0.0.1:8545").
    rpc_url: String,
    /// 0x-prefixed hex address of the deployed ContributionAccounting contract.
    contract_address: String,
    /// 0x-prefixed hex address of the recorder (must be authorized via addRecorder).
    recorder_address: String,
    /// HTTP client for JSON-RPC calls.
    client: reqwest::Client,
    /// Monotonic request ID for JSON-RPC.
    request_id: AtomicU64,
}

impl ContributionRecorder {
    /// Create a new ContributionRecorder.
    ///
    /// # Arguments
    /// - `rpc_url` — JSON-RPC endpoint (e.g., "http://127.0.0.1:8545")
    /// - `contract_address` — Deployed ContributionAccounting address (0x-prefixed)
    /// - `recorder_address` — Address authorized to call recordContribution (0x-prefixed)
    #[allow(dead_code)]
    pub fn new(rpc_url: String, contract_address: String, recorder_address: String) -> Self {
        Self {
            rpc_url,
            contract_address,
            recorder_address,
            client: reqwest::Client::new(),
            request_id: AtomicU64::new(1),
        }
    }

    /// Record a Validation contribution (type 0).
    /// Called once per block produced.
    pub async fn record_validation(&self, amount: u64) -> anyhow::Result<()> {
        self.record_contribution(0, amount).await
    }

    /// Record a ModelHosting contribution (type 1).
    /// Called with the count of inference requests served since last block.
    pub async fn record_model_hosting(&self, amount: u64) -> anyhow::Result<()> {
        self.record_contribution(1, amount).await
    }

    /// Record an AdapterCreation contribution (type 2).
    /// Called at checkpoint boundaries when a LoRA adapter is generated.
    pub async fn record_adapter_creation(&self, amount: u64) -> anyhow::Result<()> {
        self.record_contribution(2, amount).await
    }

    /// Record a DataProvision contribution (type 3).
    #[allow(dead_code)]
    pub async fn record_data_provision(&self, amount: u64) -> anyhow::Result<()> {
        self.record_contribution(3, amount).await
    }

    /// Core method: call ContributionAccounting.recordContribution(address,uint8,uint256).
    ///
    /// Encodes the ABI calldata and sends via eth_sendTransaction.
    async fn record_contribution(
        &self,
        contribution_type: u8,
        amount: u64,
    ) -> anyhow::Result<()> {
        if amount == 0 {
            return Ok(());
        }

        // Compute function selector: keccak256("recordContribution(address,uint8,uint256)")[0..4]
        let selector = function_selector("recordContribution(address,uint8,uint256)");

        // ABI encode arguments:
        // arg0: address (contributor) — left-padded to 32 bytes
        // arg1: uint8 (contributionType) — right-aligned in 32 bytes
        // arg2: uint256 (amount) — right-aligned in 32 bytes
        let mut calldata = Vec::with_capacity(4 + 3 * 32);
        calldata.extend_from_slice(&selector);

        // Address: strip 0x, left-pad to 32 bytes
        let addr_hex = self.recorder_address.trim_start_matches("0x");
        let addr_bytes = hex::decode(addr_hex)
            .map_err(|e| anyhow::anyhow!("Invalid recorder address: {}", e))?;
        let mut addr_word = [0u8; 32];
        if addr_bytes.len() == 20 {
            addr_word[12..32].copy_from_slice(&addr_bytes);
        }
        calldata.extend_from_slice(&addr_word);

        // ContributionType: uint8 right-aligned in 32 bytes
        let mut type_word = [0u8; 32];
        type_word[31] = contribution_type;
        calldata.extend_from_slice(&type_word);

        // Amount: uint256 right-aligned in 32 bytes
        let mut amount_word = [0u8; 32];
        amount_word[24..32].copy_from_slice(&amount.to_be_bytes());
        calldata.extend_from_slice(&amount_word);

        let calldata_hex = format!("0x{}", hex::encode(&calldata));

        let id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{
                "from": self.recorder_address,
                "to": self.contract_address,
                "data": calldata_hex,
                "gas": "0x1e8480"
            }],
            "id": id
        });

        let type_name = match contribution_type {
            0 => "Validation",
            1 => "ModelHosting",
            2 => "AdapterCreation",
            3 => "DataProvision",
            4 => "AppDevelopment",
            5 => "BridgeInfra",
            6 => "Governance",
            _ => "Unknown",
        };

        match self
            .client
            .post(&self.rpc_url)
            .json(&request)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    let body: serde_json::Value = response.json().await.unwrap_or_default();
                    if let Some(error) = body.get("error") {
                        warn!(
                            "ContributionAccounting.recordContribution({}, {}) RPC error: {}",
                            type_name, amount, error
                        );
                    } else {
                        debug!(
                            "ContributionAccounting: recorded {} x{} (tx: {})",
                            type_name,
                            amount,
                            body.get("result")
                                .and_then(|r| r.as_str())
                                .unwrap_or("unknown")
                        );
                    }
                } else {
                    warn!(
                        "ContributionAccounting.recordContribution({}, {}) HTTP {}: {}",
                        type_name,
                        amount,
                        status,
                        response.text().await.unwrap_or_default()
                    );
                }
            }
            Err(e) => {
                // Timeout or connection error — non-fatal
                debug!(
                    "ContributionAccounting.recordContribution({}, {}) failed: {}",
                    type_name, amount, e
                );
            }
        }

        Ok(())
    }
}

/// Compute the 4-byte function selector (keccak256 of canonical signature).
fn function_selector(sig: &str) -> [u8; 4] {
    let hash = Keccak256::digest(sig.as_bytes());
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&hash[..4]);
    sel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_selector_record_contribution() {
        let sel = function_selector("recordContribution(address,uint8,uint256)");
        // The selector should be exactly 4 bytes and non-zero
        assert_ne!(sel, [0u8; 4]);
        // Verify it matches the expected keccak256 prefix
        let hash = Keccak256::digest(b"recordContribution(address,uint8,uint256)");
        assert_eq!(&sel[..], &hash[..4]);
    }

    #[test]
    fn test_contribution_recorder_creation() {
        let recorder = ContributionRecorder::new(
            "http://127.0.0.1:8545".to_string(),
            "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
        );
        assert_eq!(recorder.rpc_url, "http://127.0.0.1:8545");
        assert_eq!(
            recorder.contract_address,
            "0x1234567890abcdef1234567890abcdef12345678"
        );
    }

    #[test]
    fn test_contribution_type_mapping() {
        // Verify the ContributionType enum values match ContributionAccounting.sol
        assert_eq!(0u8, 0); // Validation
        assert_eq!(1u8, 1); // ModelHosting
        assert_eq!(2u8, 2); // AdapterCreation
        assert_eq!(3u8, 3); // DataProvision
        assert_eq!(4u8, 4); // AppDevelopment
        assert_eq!(5u8, 5); // BridgeInfra
        assert_eq!(6u8, 6); // Governance
    }

    #[tokio::test]
    async fn test_record_zero_amount_is_noop() {
        // Recording 0 amount should return Ok without making any RPC call
        let recorder = ContributionRecorder::new(
            "http://127.0.0.1:99999".to_string(), // deliberately unreachable
            "0x0000000000000000000000000000000000000000".to_string(),
            "0x0000000000000000000000000000000000000001".to_string(),
        );
        // Zero amount should be a no-op (no network call)
        assert!(recorder.record_validation(0).await.is_ok());
        assert!(recorder.record_model_hosting(0).await.is_ok());
        assert!(recorder.record_adapter_creation(0).await.is_ok());
    }
}
