//! Bridge configuration.
//!
//! Configurable parameters for the Citrate-side bridge relay,
//! including Ethereum RPC, oracle quorum, and bonding curve.

use serde::{Deserialize, Serialize};

/// Bridge relay configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Ethereum RPC endpoint (Sepolia).
    pub ethereum_rpc: String,

    /// Deployed CitrateBridgeNFT contract address on Sepolia (hex, 0x-prefixed).
    pub bridge_contract: String,

    /// Number of block confirmations before processing an event.
    pub confirmation_depth: u64,

    /// Oracle quorum: minimum attestations required (M in M-of-N).
    pub oracle_threshold: usize,

    /// Maximum time (seconds) to wait for oracle attestations.
    pub oracle_timeout_secs: u64,

    /// Maximum retry attempts for failed operations.
    pub max_retries: u32,

    /// Base delay (ms) for exponential backoff.
    pub retry_base_delay_ms: u64,

    /// Bonding curve configuration.
    pub bonding_curve: BondingCurveConfig,

    /// Bridge relay polling interval (ms).
    pub poll_interval_ms: u64,

    /// SECREM-01 BRG-3: Citrate chain id bound into every oracle
    /// attestation message, so attestations cannot replay across
    /// deployments that share oracle keys. Defaults to mainnet/testnet
    /// chain id 40204 for configs written before this field existed.
    #[serde(default = "default_attestation_chain_id")]
    pub chain_id: u64,
}

/// Serde default for [`BridgeConfig::chain_id`] (Citrate = 40204).
fn default_attestation_chain_id() -> u64 {
    40204
}

impl BridgeConfig {
    /// SECREM-01 BRG-3: the attestation signing domain for this deployment
    /// — `(chain_id, sha3("citrate-bridge-instance-v1" || lowercase
    /// contract address))`. Single source of truth shared by the relay's
    /// registry construction, oracle clients, and tests.
    pub fn attestation_domain(&self) -> (u64, [u8; 32]) {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"citrate-bridge-instance-v1");
        h.update(self.bridge_contract.trim().to_lowercase().as_bytes());
        let out = h.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&out);
        (self.chain_id, id)
    }
}

/// Bonding curve pricing configuration per Paper VI.
///
/// Price = base_multiplier + (slope * total_deposited / scale_factor)
/// Capped at max_multiplier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondingCurveConfig {
    /// Base price multiplier (1.0 = 1:1 ETH→SALT).
    pub base_multiplier: f64,

    /// Slope of the bonding curve.
    pub slope: f64,

    /// Scale factor for total deposited amount.
    pub scale_factor: f64,

    /// Maximum price multiplier cap.
    pub max_multiplier: f64,

    /// Base SALT per ETH (before curve adjustment).
    pub salt_per_eth: u64,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            ethereum_rpc: "https://sepolia.infura.io/v3/PLACEHOLDER".to_string(),
            bridge_contract: "0xB225F65B6a297dfe3A11BAD6e19E6f2f5D4AB247".to_string(),
            confirmation_depth: 12,
            oracle_threshold: 2,
            oracle_timeout_secs: 30,
            max_retries: 5,
            retry_base_delay_ms: 1000,
            bonding_curve: BondingCurveConfig::default(),
            poll_interval_ms: 5000,
            chain_id: default_attestation_chain_id(),
        }
    }
}

impl Default for BondingCurveConfig {
    fn default() -> Self {
        Self {
            base_multiplier: 1.0,
            slope: 0.001,
            scale_factor: 1000.0,
            max_multiplier: 3.0,
            salt_per_eth: 10_000,
        }
    }
}

impl BondingCurveConfig {
    /// Calculate SALT amount for a given ETH deposit and total already deposited.
    ///
    /// Returns the SALT amount (in base units, no decimals).
    pub fn calculate_salt_amount(&self, deposit_eth: f64, total_deposited_eth: f64) -> u64 {
        let multiplier =
            (self.base_multiplier + self.slope * total_deposited_eth / self.scale_factor)
                .min(self.max_multiplier);
        let salt = deposit_eth * self.salt_per_eth as f64 / multiplier;
        salt as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BridgeConfig::default();
        assert_eq!(config.confirmation_depth, 12);
        assert_eq!(config.oracle_threshold, 2);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_bonding_curve_base_rate() {
        let curve = BondingCurveConfig::default();
        // At 0 total deposited, multiplier = 1.0, so 1 ETH = 10,000 SALT
        let salt = curve.calculate_salt_amount(1.0, 0.0);
        assert_eq!(salt, 10_000);
    }

    #[test]
    fn test_bonding_curve_progressive_pricing() {
        let curve = BondingCurveConfig::default();
        // At 1000 ETH total deposited:
        // multiplier = 1.0 + 0.001 * 1000 / 1000 = 1.001
        let salt_early = curve.calculate_salt_amount(1.0, 0.0);
        let salt_later = curve.calculate_salt_amount(1.0, 1000.0);
        // Later deposits yield fewer SALT
        assert!(salt_later < salt_early);
    }

    #[test]
    fn test_bonding_curve_max_cap() {
        let curve = BondingCurveConfig::default();
        // At huge deposit total, multiplier caps at 3.0
        let salt = curve.calculate_salt_amount(1.0, 10_000_000.0);
        // 10000 / 3.0 = 3333
        assert_eq!(salt, 3333);
    }
}
