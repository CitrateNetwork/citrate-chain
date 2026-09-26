use crate::errors::WalletError;
use ed25519_dalek::SigningKey;
use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use citrate_execution::types::Address;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Signed transaction ready for broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub raw: Vec<u8>,
}

/// Transaction builder
pub struct TransactionBuilder {
    from: Option<PublicKey>,
    to: Option<Address>,
    value: U256,
    data: Vec<u8>,
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    chain_id: u64,
}

impl TransactionBuilder {
    /// Create new transaction builder
    pub fn new() -> Self {
        Self {
            from: None,
            to: None,
            value: U256::zero(),
            data: Vec::new(),
            nonce: 0,
            gas_price: 1_000_000_000, // 1 gwei default
            gas_limit: 21_000,        // Standard transfer
            chain_id: 40204,          // Citrate testnet
        }
    }

    /// Set sender
    pub fn from(mut self, from: PublicKey) -> Self {
        self.from = Some(from);
        self
    }

    /// Set recipient
    pub fn to(mut self, to: Option<Address>) -> Self {
        self.to = to;
        self
    }

    /// Set value in wei
    pub fn value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }

    /// Set data
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Set nonce
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Set gas price
    pub fn gas_price(mut self, gas_price: u64) -> Self {
        self.gas_price = gas_price;
        self
    }

    /// Set gas limit
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Set chain ID
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Build and sign with the V2 (chain-bound) native digest for the
    /// configured chain id: valid at every height on releases that verify V2,
    /// and required from the activation height. Used by the `citrate-wallet`
    /// binary and the node's `citrate wallet` subcommand, which run without
    /// an activation height. [`Self::build_and_sign_for_tip`] gives explicit
    /// control.
    pub fn build_and_sign(
        self,
        signing_key: &SigningKey,
    ) -> Result<SignedTransaction, WalletError> {
        self.build_and_sign_version(
            signing_key,
            citrate_consensus::native_sig::NativeSigVersion::V2,
        )
    }

    /// Build and sign with the native digest version the chain accepts for the
    /// next block (`citrate_consensus::native_sig::signer_version`): the
    /// chain-bound V2 digest once `tip_height + 1 >= activation`.
    pub fn build_and_sign_for_tip(
        self,
        signing_key: &SigningKey,
        activation: Option<u64>,
        tip_height: Option<u64>,
    ) -> Result<SignedTransaction, WalletError> {
        let version = citrate_consensus::native_sig::signer_version(activation, tip_height);
        self.build_and_sign_version(signing_key, version)
    }

    fn build_and_sign_version(
        self,
        signing_key: &SigningKey,
        version: citrate_consensus::native_sig::NativeSigVersion,
    ) -> Result<SignedTransaction, WalletError> {
        let from = self
            .from
            .ok_or_else(|| WalletError::Other("From address not set".to_string()))?;

        // Convert to address to PublicKey if set (for transaction format)
        let to_pubkey = self.to.map(|addr| {
            // Create a pseudo public key from address for compatibility
            // In production, this would be resolved from address book or chain state
            let mut pk_bytes = [0u8; 32];
            pk_bytes[..20].copy_from_slice(&addr.0);
            PublicKey::new(pk_bytes)
        });

        // Create unsigned transaction
        let mut tx = Transaction {
            hash: Hash::default(), // Will be calculated
            from,
            to: to_pubkey,
            value: value_to_u128(self.value),
            data: self.data,
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            signature: Signature::new([0; 64]), // Will be replaced
            tx_type: None,                      // Will be determined if needed
            // The chain requires it on every tx, and the V2 digest binds it.
            chain_id: Some(self.chain_id),
            ..Default::default()
        };

        // Calculate transaction hash (UI/display). Consensus verification uses canonical bytes.
        tx.hash = calculate_tx_hash(&tx, self.chain_id);

        // Sign canonical transaction bytes using consensus crypto so mempool verification passes
        citrate_consensus::native_sig::sign_native(&mut tx, signing_key, version)
            .map_err(|e| WalletError::Other(format!("Transaction signing failed: {}", e)))?;

        // Serialize for raw format
        let raw = bincode::serialize(&tx)?;

        Ok(SignedTransaction {
            transaction: tx,
            raw,
        })
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate transaction hash including chain ID (EIP-155 style)
fn calculate_tx_hash(tx: &Transaction, chain_id: u64) -> Hash {
    // Use Keccak-256 to align with Ethereum-style hashing across the stack
    let mut hasher = Keccak256::new();

    // Hash transaction fields
    hasher.update(tx.nonce.to_le_bytes());
    hasher.update(tx.gas_price.to_le_bytes());
    hasher.update(tx.gas_limit.to_le_bytes());

    if let Some(to) = &tx.to {
        hasher.update(to.as_bytes());
    }

    hasher.update(tx.value.to_le_bytes());
    hasher.update(&tx.data);

    // Include chain ID for replay protection
    hasher.update(chain_id.to_le_bytes());
    hasher.update([0u8; 8]); // r placeholder
    hasher.update([0u8; 8]); // s placeholder

    let hash_bytes = hasher.finalize();
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash_bytes);

    Hash::new(hash_array)
}

/// Convert U256 to u128 (with overflow check)
fn value_to_u128(value: U256) -> u128 {
    // Check if value fits in u128
    if value > U256::from(u128::MAX) {
        // Saturate at max
        u128::MAX
    } else {
        value.as_u128()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    fn test_signing_key() -> (SigningKey, PublicKey) {
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let public_key = PublicKey::new(signing_key.verifying_key().to_bytes());
        (signing_key, public_key)
    }

    #[test]
    fn test_transaction_builder() {
        let (signing_key, public_key) = test_signing_key();

        let tx = TransactionBuilder::new()
            .from(public_key)
            .to(Some(Address([0x11; 20])))
            .value(U256::from(1000))
            .nonce(0)
            .gas_price(1_000_000_000)
            .gas_limit(21_000)
            .chain_id(40204)
            .build_and_sign(&signing_key)
            .unwrap();

        assert_eq!(tx.transaction.from, public_key);
        assert_eq!(tx.transaction.value, 1000);
        assert_eq!(tx.transaction.nonce, 0);
    }

    #[test]
    fn test_builder_defaults() {
        let builder = TransactionBuilder::new();
        // Verify defaults match spec
        assert_eq!(builder.gas_price, 1_000_000_000);
        assert_eq!(builder.gas_limit, 21_000);
        assert_eq!(builder.chain_id, 40204);
        assert_eq!(builder.value, U256::zero());
        assert_eq!(builder.nonce, 0);
        assert!(builder.from.is_none());
        assert!(builder.to.is_none());
        assert!(builder.data.is_empty());
    }

    #[test]
    fn test_build_without_from_fails() {
        let (signing_key, _) = test_signing_key();
        let err = TransactionBuilder::new()
            .to(Some(Address([0x11; 20])))
            .value(U256::from(100))
            .build_and_sign(&signing_key)
            .unwrap_err();
        match err {
            WalletError::Other(msg) => assert!(msg.contains("From address not set")),
            _ => panic!("Expected Other error, got {:?}", err),
        }
    }

    #[test]
    fn test_signed_transaction_has_valid_signature() {
        let (signing_key, public_key) = test_signing_key();
        let tx = TransactionBuilder::new()
            .from(public_key)
            .to(Some(Address([0x22; 20])))
            .value(U256::from(500))
            .nonce(5)
            .build_and_sign(&signing_key)
            .unwrap();

        // Signature should not be all zeros (was replaced during signing)
        assert_ne!(tx.transaction.signature.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn test_transaction_hash_includes_chain_id() {
        let (signing_key, public_key) = test_signing_key();

        let tx1 = TransactionBuilder::new()
            .from(public_key)
            .to(Some(Address([0x33; 20])))
            .value(U256::from(100))
            .chain_id(40204)
            .build_and_sign(&signing_key)
            .unwrap();

        let tx2 = TransactionBuilder::new()
            .from(public_key)
            .to(Some(Address([0x33; 20])))
            .value(U256::from(100))
            .chain_id(1) // Different chain ID
            .build_and_sign(&signing_key)
            .unwrap();

        // Different chain IDs should produce different hashes
        assert_ne!(tx1.transaction.hash, tx2.transaction.hash);
    }

    #[test]
    fn test_transaction_hash_deterministic() {
        let secret = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let public_key = PublicKey::new(signing_key.verifying_key().to_bytes());

        // Build two identical transactions — hashes should be identical
        // (pre-signature hash, since signing uses randomness)
        let hash1 = calculate_tx_hash(
            &Transaction {
                hash: Hash::default(),
                from: public_key,
                to: None,
                value: 1000,
                data: vec![1, 2, 3],
                nonce: 7,
                gas_price: 1_000_000_000,
                gas_limit: 21_000,
                signature: Signature::new([0; 64]),
                tx_type: None,
                ..Default::default()
            },
            40204,
        );

        let hash2 = calculate_tx_hash(
            &Transaction {
                hash: Hash::default(),
                from: public_key,
                to: None,
                value: 1000,
                data: vec![1, 2, 3],
                nonce: 7,
                gas_price: 1_000_000_000,
                gas_limit: 21_000,
                signature: Signature::new([0; 64]),
                tx_type: None,
                ..Default::default()
            },
            40204,
        );

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_transaction_raw_serialization() {
        let (signing_key, public_key) = test_signing_key();
        let tx = TransactionBuilder::new()
            .from(public_key)
            .to(Some(Address([0x44; 20])))
            .value(U256::from(999))
            .build_and_sign(&signing_key)
            .unwrap();

        // Raw bytes should be non-empty bincode serialization
        assert!(!tx.raw.is_empty());
        // Should be deserializable back
        let deserialized: Transaction = bincode::deserialize(&tx.raw).unwrap();
        assert_eq!(deserialized.from, public_key);
        assert_eq!(deserialized.value, 999);
    }

    #[test]
    fn test_value_to_u128_normal() {
        assert_eq!(value_to_u128(U256::from(1000)), 1000);
        assert_eq!(value_to_u128(U256::zero()), 0);
    }

    #[test]
    fn test_value_to_u128_overflow_saturates() {
        let huge = U256::MAX;
        assert_eq!(value_to_u128(huge), u128::MAX);
    }

    #[test]
    fn test_value_to_u128_boundary() {
        let max_u128 = U256::from(u128::MAX);
        assert_eq!(value_to_u128(max_u128), u128::MAX);
    }

    #[test]
    fn test_builder_fluent_api_chains() {
        let (signing_key, public_key) = test_signing_key();
        // All builder methods should chain without issue
        let tx = TransactionBuilder::new()
            .from(public_key)
            .to(Some(Address([0x55; 20])))
            .value(U256::from(1))
            .data(vec![0xDE, 0xAD])
            .nonce(42)
            .gas_price(2_000_000_000)
            .gas_limit(50_000)
            .chain_id(40204)
            .build_and_sign(&signing_key)
            .unwrap();

        assert_eq!(tx.transaction.nonce, 42);
        assert_eq!(tx.transaction.gas_price, 2_000_000_000);
        assert_eq!(tx.transaction.gas_limit, 50_000);
        assert_eq!(tx.transaction.data, vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_contract_deploy_no_to_address() {
        let (signing_key, public_key) = test_signing_key();
        let bytecode = vec![0x60, 0x80, 0x60, 0x40]; // minimal EVM bytecode

        let tx = TransactionBuilder::new()
            .from(public_key)
            .to(None) // Contract deployment
            .data(bytecode.clone())
            .build_and_sign(&signing_key)
            .unwrap();

        assert!(tx.transaction.to.is_none());
        assert_eq!(tx.transaction.data, bytecode);
    }

    #[test]
    fn test_default_impl() {
        let builder = TransactionBuilder::default();
        assert_eq!(builder.chain_id, 40204);
    }

    /// `build_and_sign` (the `citrate-wallet` binary and the node's `citrate
    /// wallet` subcommand, which runs before the node sets any activation
    /// height) produces V2 for the configured chain.
    #[test]
    fn build_and_sign_produces_v2_without_an_activation_height() {
        use citrate_consensus::native_sig::{signed_version, NativeSigVersion};
        assert_eq!(citrate_consensus::hardening::pba_hardening_height(), None);
        let (signing_key, public_key) = test_signing_key();
        let tx = TransactionBuilder::new()
            .from(public_key)
            .to(Some(Address([0x11; 20])))
            .value(U256::from(1000))
            .chain_id(40204)
            .build_and_sign(&signing_key)
            .unwrap()
            .transaction;
        assert_eq!(tx.chain_id, Some(40204));
        assert_eq!(signed_version(&tx), Some(NativeSigVersion::V2));
    }

    /// The native digest version follows the activation height and tip, and
    /// the chain id the V2 digest binds is carried on the transaction.
    #[test]
    fn build_and_sign_for_tip_picks_the_digest_version() {
        use citrate_consensus::native_sig::{signed_version, NativeSigVersion};
        let (signing_key, public_key) = test_signing_key();
        let build = |activation, tip| {
            TransactionBuilder::new()
                .from(public_key)
                .to(Some(Address([0x11; 20])))
                .value(U256::from(1000))
                .chain_id(40204)
                .build_and_sign_for_tip(&signing_key, activation, tip)
                .unwrap()
                .transaction
        };
        let v1 = build(Some(100), Some(98));
        assert_eq!(v1.chain_id, Some(40204));
        assert_eq!(signed_version(&v1), Some(NativeSigVersion::V1));
        assert_eq!(
            signed_version(&build(Some(100), Some(99))),
            Some(NativeSigVersion::V2)
        );
        assert_eq!(
            signed_version(&build(None, Some(99))),
            Some(NativeSigVersion::V1)
        );
    }
}
