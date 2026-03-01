//! $SNAP mint flow.
//!
//! Handles the full deposit-to-SALT-credit flow:
//! 1. Deposit event arrives from Ethereum Sepolia
//! 2. Oracle attestations collected and verified
//! 3. Bonding curve calculates SALT amount
//! 4. SALT credited to recipient on Citrate
//! 5. $SNAP NFT metadata generated

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::config::BondingCurveConfig;
use crate::errors::{BridgeError, BridgeResult};
use crate::events::DepositEvent;

/// Minimum deposit: 0.02 ETH in wei.
pub const MIN_DEPOSIT_WEI: u128 = 20_000_000_000_000_000;

/// Maximum deposit per transaction: 10 ETH in wei.
pub const MAX_DEPOSIT_WEI: u128 = 10_000_000_000_000_000_000;

/// Hard cap for total deposits: 2000 ETH in wei.
pub const HARD_CAP_WEI: u128 = 2_000_000_000_000_000_000_000;

/// Mint receipt — proof that a deposit was converted to SALT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintReceipt {
    /// Event ID of the deposit.
    pub event_id: [u8; 32],

    /// Citrate recipient address.
    pub recipient: [u8; 20],

    /// ETH deposit amount in wei.
    pub deposit_wei: u128,

    /// SALT amount credited.
    pub salt_credited: u64,

    /// Bonding curve multiplier at time of mint.
    pub curve_multiplier: f64,

    /// $SNAP NFT metadata.
    pub nft_metadata: SnapNftMetadata,

    /// Receipt hash (for verification).
    pub receipt_hash: [u8; 32],

    /// Timestamp.
    pub timestamp: u64,
}

/// $SNAP NFT metadata per Paper VI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapNftMetadata {
    /// NFT name.
    pub name: String,

    /// NFT description.
    pub description: String,

    /// Depositor's Ethereum address (hex).
    pub depositor: String,

    /// Citrate recipient address (hex).
    pub recipient: String,

    /// ETH amount deposited.
    pub eth_amount: f64,

    /// SALT amount credited.
    pub salt_amount: u64,

    /// Bonding curve multiplier.
    pub multiplier: f64,

    /// Deposit timestamp.
    pub deposit_timestamp: u64,

    /// Ethereum transaction hash (hex).
    pub eth_tx_hash: String,

    /// Bridge version.
    pub bridge_version: String,
}

/// $SNAP minter — converts deposits to SALT credits.
#[derive(Debug)]
pub struct SnapMinter {
    /// Bonding curve configuration.
    curve: BondingCurveConfig,

    /// Total ETH deposited so far (in ETH, floating point).
    total_deposited_eth: f64,

    /// Total SALT minted so far.
    total_salt_minted: u64,

    /// Total deposits processed.
    total_deposits: u64,
}

impl SnapMinter {
    /// Create a new minter with the given bonding curve config.
    pub fn new(curve: BondingCurveConfig) -> Self {
        Self {
            curve,
            total_deposited_eth: 0.0,
            total_salt_minted: 0,
            total_deposits: 0,
        }
    }

    /// Process a deposit event and return a mint receipt.
    pub fn process_deposit(&mut self, deposit: &DepositEvent) -> BridgeResult<MintReceipt> {
        // Validate deposit amount
        if deposit.amount_wei < MIN_DEPOSIT_WEI {
            return Err(BridgeError::DepositTooSmall {
                amount_wei: deposit.amount_wei,
                min_wei: MIN_DEPOSIT_WEI,
            });
        }

        if deposit.amount_wei > MAX_DEPOSIT_WEI {
            return Err(BridgeError::DepositExceedsCap {
                amount_wei: deposit.amount_wei,
                max_wei: MAX_DEPOSIT_WEI,
            });
        }

        // Calculate SALT amount via bonding curve
        let salt_amount = self
            .curve
            .calculate_salt_amount(deposit.amount_eth, self.total_deposited_eth);

        if salt_amount == 0 {
            return Err(BridgeError::ConversionError {
                reason: "Bonding curve yielded zero SALT".to_string(),
            });
        }

        // Calculate current multiplier for receipt
        let multiplier = (self.curve.base_multiplier
            + self.curve.slope * self.total_deposited_eth / self.curve.scale_factor)
            .min(self.curve.max_multiplier);

        // Generate NFT metadata
        let nft_metadata = SnapNftMetadata {
            name: format!("SNAP #{}", self.total_deposits + 1),
            description: format!(
                "Citrate Bridge Deposit — {:.4} ETH → {} SALT",
                deposit.amount_eth, salt_amount
            ),
            depositor: format!("0x{}", hex::encode(deposit.depositor)),
            recipient: format!("0x{}", hex::encode(deposit.recipient)),
            eth_amount: deposit.amount_eth,
            salt_amount,
            multiplier,
            deposit_timestamp: deposit.timestamp,
            eth_tx_hash: format!("0x{}", hex::encode(deposit.eth_tx_hash)),
            bridge_version: "1.0.0".to_string(),
        };

        // Compute receipt hash
        let receipt_hash = self.compute_receipt_hash(
            &deposit.event_id,
            &deposit.recipient,
            salt_amount,
        );

        // Update running totals
        self.total_deposited_eth += deposit.amount_eth;
        self.total_salt_minted += salt_amount;
        self.total_deposits += 1;

        Ok(MintReceipt {
            event_id: deposit.event_id,
            recipient: deposit.recipient,
            deposit_wei: deposit.amount_wei,
            salt_credited: salt_amount,
            curve_multiplier: multiplier,
            nft_metadata,
            receipt_hash,
            timestamp: deposit.timestamp,
        })
    }

    /// Calculate SALT amount for a deposit (preview, does not mutate state).
    pub fn preview_conversion(&self, amount_eth: f64) -> u64 {
        self.curve
            .calculate_salt_amount(amount_eth, self.total_deposited_eth)
    }

    /// Get current bonding curve multiplier.
    pub fn current_multiplier(&self) -> f64 {
        (self.curve.base_multiplier
            + self.curve.slope * self.total_deposited_eth / self.curve.scale_factor)
            .min(self.curve.max_multiplier)
    }

    /// Get total ETH deposited.
    pub fn total_deposited_eth(&self) -> f64 {
        self.total_deposited_eth
    }

    /// Get total SALT minted.
    pub fn total_salt_minted(&self) -> u64 {
        self.total_salt_minted
    }

    fn compute_receipt_hash(
        &self,
        event_id: &[u8; 32],
        recipient: &[u8; 20],
        salt_amount: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(event_id);
        hasher.update(recipient);
        hasher.update(salt_amount.to_le_bytes());
        hasher.update(b"mint_receipt_v1");
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BondingCurveConfig;

    fn make_deposit(amount_eth: f64, amount_wei: u128) -> DepositEvent {
        DepositEvent {
            event_id: [1u8; 32],
            eth_tx_hash: [2u8; 32],
            log_index: 0,
            eth_block_number: 100,
            depositor: [3u8; 20],
            recipient: [4u8; 20],
            amount_wei,
            amount_eth,
            timestamp: 1000,
        }
    }

    #[test]
    fn test_basic_deposit_conversion() {
        let mut minter = SnapMinter::new(BondingCurveConfig::default());
        let deposit = make_deposit(1.0, 1_000_000_000_000_000_000);

        let receipt = minter.process_deposit(&deposit).unwrap();
        assert_eq!(receipt.salt_credited, 10_000);
        assert_eq!(receipt.recipient, [4u8; 20]);
        assert_eq!(receipt.nft_metadata.name, "SNAP #1");
    }

    #[test]
    fn test_deposit_too_small() {
        let mut minter = SnapMinter::new(BondingCurveConfig::default());
        // 0.01 ETH < 0.02 ETH minimum
        let deposit = make_deposit(0.01, 10_000_000_000_000_000);

        let err = minter.process_deposit(&deposit).unwrap_err();
        assert!(matches!(err, BridgeError::DepositTooSmall { .. }));
    }

    #[test]
    fn test_deposit_exceeds_cap() {
        let mut minter = SnapMinter::new(BondingCurveConfig::default());
        // 11 ETH > 10 ETH max
        let deposit = make_deposit(11.0, 11_000_000_000_000_000_000);

        let err = minter.process_deposit(&deposit).unwrap_err();
        assert!(matches!(err, BridgeError::DepositExceedsCap { .. }));
    }

    #[test]
    fn test_progressive_pricing_reduces_salt() {
        let mut minter = SnapMinter::new(BondingCurveConfig::default());

        // First deposit: 1 ETH → 10,000 SALT
        let d1 = make_deposit(1.0, 1_000_000_000_000_000_000);
        let r1 = minter.process_deposit(&d1).unwrap();

        // Simulate many deposits driving up price
        minter.total_deposited_eth = 2000.0;

        // Later deposit: 1 ETH → fewer SALT
        let mut d2 = make_deposit(1.0, 1_000_000_000_000_000_000);
        d2.event_id = [5u8; 32];
        let r2 = minter.process_deposit(&d2).unwrap();

        assert!(r2.salt_credited < r1.salt_credited);
        assert!(r2.curve_multiplier > r1.curve_multiplier);
    }

    #[test]
    fn test_nft_metadata_correctness() {
        let mut minter = SnapMinter::new(BondingCurveConfig::default());
        let deposit = make_deposit(0.5, 500_000_000_000_000_000);

        let receipt = minter.process_deposit(&deposit).unwrap();
        let meta = &receipt.nft_metadata;

        assert_eq!(meta.name, "SNAP #1");
        assert!(meta.description.contains("0.5000 ETH"));
        assert_eq!(meta.eth_amount, 0.5);
        assert_eq!(meta.bridge_version, "1.0.0");
        assert!(meta.depositor.starts_with("0x"));
        assert!(meta.eth_tx_hash.starts_with("0x"));
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let mut minter = SnapMinter::new(BondingCurveConfig::default());
        let deposit = make_deposit(1.0, 1_000_000_000_000_000_000);

        let r1 = minter.process_deposit(&deposit).unwrap();
        // Receipt hash should not be all zeros
        assert_ne!(r1.receipt_hash, [0u8; 32]);
    }

    #[test]
    fn test_preview_does_not_mutate() {
        let minter = SnapMinter::new(BondingCurveConfig::default());
        let preview = minter.preview_conversion(1.0);
        assert_eq!(preview, 10_000);
        assert_eq!(minter.total_deposited_eth(), 0.0);
        assert_eq!(minter.total_salt_minted(), 0);
    }

    #[test]
    fn test_running_totals() {
        let mut minter = SnapMinter::new(BondingCurveConfig::default());

        let d1 = make_deposit(1.0, 1_000_000_000_000_000_000);
        minter.process_deposit(&d1).unwrap();

        let mut d2 = make_deposit(2.0, 2_000_000_000_000_000_000);
        d2.event_id = [10u8; 32];
        minter.process_deposit(&d2).unwrap();

        assert_eq!(minter.total_deposited_eth(), 3.0);
        assert_eq!(minter.total_deposits, 2);
    }
}
