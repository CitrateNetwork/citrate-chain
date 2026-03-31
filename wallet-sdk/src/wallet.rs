//! High-level wallet API — the main entry point for SDK consumers.

use citrate_wallet_core::keys::KeyManager;
use citrate_wallet_core::chain::{TransactionBuilder, RpcClient};
use citrate_wallet_core::session::SessionManager;
use citrate_wallet_core::error::WalletError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// SDK wallet configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub keystore_path: String,
    pub session_timeout_secs: u64,
    pub max_failed_attempts: u32,
    pub lockout_duration_secs: u64,
}

impl Default for SdkConfig {
    fn default() -> Self {
        let core_config = citrate_wallet_core::WalletConfig::default();
        Self {
            rpc_url: core_config.rpc_url,
            chain_id: core_config.chain_id,
            keystore_path: core_config.keystore_path,
            session_timeout_secs: core_config.session_timeout_secs,
            max_failed_attempts: core_config.max_failed_attempts,
            lockout_duration_secs: core_config.lockout_duration_secs,
        }
    }
}

/// Account info returned by the SDK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkAccount {
    pub address: String,
    pub public_key: String,
    pub mnemonic: String,
    pub label: String,
}

/// Transaction result returned by the SDK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkTransaction {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub nonce: u64,
    pub chain_id: u64,
}

/// Account info for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkAccountInfo {
    pub address: String,
    pub label: String,
    pub key_type: String,
    pub is_default: bool,
}

/// The main wallet handle. Thread-safe, shareable.
pub struct Wallet {
    key_manager: Arc<KeyManager>,
    rpc_client: Arc<RpcClient>,
    session: Arc<RwLock<SessionManager>>,
    config: SdkConfig,
}

impl Wallet {
    /// Create a wallet with default configuration.
    pub fn new_default() -> Self {
        Self::new(SdkConfig::default())
    }

    /// Create a wallet with custom configuration.
    pub fn new(config: SdkConfig) -> Self {
        let keystore_path = PathBuf::from(&config.keystore_path);
        Self {
            key_manager: Arc::new(KeyManager::new(&keystore_path)),
            rpc_client: Arc::new(RpcClient::new(&config.rpc_url)),
            session: Arc::new(RwLock::new(SessionManager::new(
                config.max_failed_attempts,
                config.lockout_duration_secs,
                config.session_timeout_secs,
            ))),
            config,
        }
    }

    /// Load existing accounts from the keystore.
    pub async fn load(&self) -> Result<(), WalletError> {
        self.key_manager.load()
    }

    /// Check if this is the first time (no accounts exist).
    pub async fn is_first_run(&self) -> bool {
        self.key_manager.is_empty()
    }

    /// Create a new Ed25519 account with a BIP39 mnemonic.
    pub async fn create_account(
        &self,
        password: &str,
        label: &str,
    ) -> Result<SdkAccount, WalletError> {
        let result = self.key_manager.create_account(password, label)?;
        Ok(SdkAccount {
            address: result.address,
            public_key: result.public_key_hex,
            mnemonic: result.mnemonic,
            label: result.label,
        })
    }

    /// Create a new secp256k1 account (EVM-compatible).
    pub async fn create_evm_account(
        &self,
        password: &str,
        label: &str,
    ) -> Result<SdkAccount, WalletError> {
        let result = self.key_manager.create_secp256k1_account(password, label)?;
        Ok(SdkAccount {
            address: result.address,
            public_key: result.public_key_hex,
            mnemonic: result.mnemonic,
            label: result.label,
        })
    }

    /// Recover an account from a BIP39 mnemonic.
    pub async fn recover_account(
        &self,
        mnemonic: &str,
        password: &str,
        label: &str,
    ) -> Result<SdkAccount, WalletError> {
        let result = self.key_manager.recover_from_mnemonic(mnemonic, password, label)?;
        Ok(SdkAccount {
            address: result.address,
            public_key: result.public_key_hex,
            mnemonic: result.mnemonic,
            label: result.label,
        })
    }

    /// Import an account from a hex private key.
    pub async fn import_account(
        &self,
        private_key_hex: &str,
        password: &str,
        label: &str,
    ) -> Result<SdkAccount, WalletError> {
        let result = self.key_manager.import_account(private_key_hex, password, label)?;
        Ok(SdkAccount {
            address: result.address,
            public_key: result.public_key_hex,
            mnemonic: String::new(),
            label: result.label,
        })
    }

    /// List all accounts.
    pub async fn list_accounts(&self) -> Vec<SdkAccountInfo> {
        self.key_manager
            .list_accounts()
            .into_iter()
            .map(|a| SdkAccountInfo {
                address: a.address,
                label: a.label,
                key_type: format!("{:?}", a.key_type),
                is_default: a.is_default,
            })
            .collect()
    }

    /// Unlock the wallet with a password.
    pub async fn unlock(&self, password: &str) -> Result<usize, WalletError> {
        let primary = self.key_manager.primary_address()
            .unwrap_or_default();

        // Check rate limiting
        {
            let session = self.session.read().await;
            if session.is_locked_out(&primary) {
                return Err(WalletError::RateLimited("Account is locked out".into()));
            }
        }

        match self.key_manager.unlock(password) {
            Ok(count) => {
                let mut session = self.session.write().await;
                session.record_success(&primary);
                Ok(count)
            }
            Err(e) => {
                let mut session = self.session.write().await;
                let _ = session.record_failure(&primary);
                Err(e)
            }
        }
    }

    /// Lock the wallet — clears all decrypted keys from memory.
    pub async fn lock(&self) {
        let primary = self.key_manager.primary_address()
            .unwrap_or_default();
        self.key_manager.lock();
        self.session.write().await.end_session(&primary);
    }

    /// Check if the wallet is unlocked.
    pub async fn is_unlocked(&self) -> bool {
        self.key_manager.is_unlocked()
    }

    /// Get the balance of an address (in wei).
    pub async fn get_balance(&self, address: &str) -> Result<u128, WalletError> {
        self.rpc_client.get_balance(address).await
    }

    /// Get the nonce of an address.
    pub async fn get_nonce(&self, address: &str) -> Result<u64, WalletError> {
        self.rpc_client.get_nonce(address).await
    }

    /// Get the current block number.
    pub async fn get_block_number(&self) -> Result<u64, WalletError> {
        self.rpc_client.get_block_number().await
    }

    /// Get the chain ID.
    pub async fn get_chain_id(&self) -> Result<u64, WalletError> {
        self.rpc_client.get_chain_id().await
    }

    /// Send a transaction. Wallet must be unlocked.
    pub async fn send_transaction(
        &self,
        from: &str,
        to: &str,
        value_wei: u128,
        gas_limit: Option<u64>,
        gas_price: Option<u64>,
    ) -> Result<SdkTransaction, WalletError> {
        let unified_key = self.key_manager.get_signing_key(from)?;
        // P0 fix: nonce fetch failure is a real error, not silent zero
        let nonce = self.rpc_client.get_nonce(from).await
            .map_err(|e| WalletError::TransactionFailed(
                format!("Cannot fetch nonce: {}. Is the node running?", e)
            ))?;

        let signed = match &unified_key {
            citrate_wallet_core::keys::UnifiedKey::Ed25519(ed_key) => {
                TransactionBuilder::new()
                    .to(to)
                    .value(value_wei)
                    .gas_limit(gas_limit.unwrap_or(21_000))
                    .gas_price(gas_price.unwrap_or(1_000_000_000))
                    .chain_id(self.config.chain_id)
                    .sign(ed_key, nonce)?
            }
            citrate_wallet_core::keys::UnifiedKey::Secp256k1(secp_key) => {
                TransactionBuilder::new()
                    .to(to)
                    .value(value_wei)
                    .gas_limit(gas_limit.unwrap_or(21_000))
                    .gas_price(gas_price.unwrap_or(1_000_000_000))
                    .chain_id(self.config.chain_id)
                    .sign_secp256k1(secp_key, nonce)?
            }
        };

        // P0 fix: submission failure is a real error, not fake success
        let tx_hash = self.rpc_client
            .send_raw_transaction(&signed.raw)
            .await
            .map_err(|e| WalletError::TransactionFailed(
                format!("Transaction submission failed: {}. Signed but not accepted.", e)
            ))?;

        Ok(SdkTransaction {
            hash: tx_hash,
            from: from.to_string(),
            to: Some(to.to_string()),
            value: value_wei.to_string(),
            nonce,
            chain_id: self.config.chain_id,
        })
    }

    /// Sign arbitrary data with the key for the given address.
    pub async fn sign_message(
        &self,
        address: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, WalletError> {
        let key = self.key_manager.get_signing_key(address)?;
        Ok(key.sign(message))
    }

    /// Export the private key hex for an address (requires password).
    pub async fn export_private_key(
        &self,
        address: &str,
        password: &str,
    ) -> Result<String, WalletError> {
        self.key_manager.export_private_key(address, password)
    }

    /// Delete an account (requires password).
    pub async fn delete_account(
        &self,
        address: &str,
        password: &str,
    ) -> Result<(), WalletError> {
        self.key_manager.delete_account(address, password)
    }

    /// Get the primary (first) account address.
    pub async fn primary_address(&self) -> Option<String> {
        self.key_manager.primary_address()
    }

    /// Get the SDK configuration.
    pub fn config(&self) -> &SdkConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn test_wallet(_name: &str) -> Wallet {
        let path = temp_dir().join(format!("citrate_sdk_test_{}", uuid::Uuid::new_v4()));
        Wallet::new(SdkConfig {
            keystore_path: path.to_string_lossy().to_string(),
            rpc_url: "http://localhost:8545".to_string(),
            ..SdkConfig::default()
        })
    }

    #[tokio::test]
    async fn test_new_default() {
        let wallet = Wallet::new_default();
        assert!(wallet.is_first_run().await);
    }

    #[tokio::test]
    async fn test_create_account() {
        let wallet = test_wallet("create");
        let account = wallet.create_account("strongpassword1", "Primary").await.expect("create");
        assert!(account.address.starts_with("0x"));
        assert_eq!(account.address.len(), 42);
        assert_eq!(account.mnemonic.split_whitespace().count(), 24);
        assert!(!wallet.is_first_run().await);
    }

    #[tokio::test]
    async fn test_create_evm_account() {
        let wallet = test_wallet("evm");
        let account = wallet.create_evm_account("strongpassword1", "EVM").await.expect("create evm");
        assert!(account.address.starts_with("0x"));
        assert_eq!(account.address.len(), 42);
    }

    #[tokio::test]
    async fn test_unlock_lock() {
        let wallet = test_wallet("unlock");
        wallet.create_account("strongpassword1", "Primary").await.expect("create");

        let count = wallet.unlock("strongpassword1").await.expect("unlock");
        assert_eq!(count, 1);
        assert!(wallet.is_unlocked().await);

        wallet.lock().await;
        assert!(!wallet.is_unlocked().await);
    }

    #[tokio::test]
    async fn test_wrong_password() {
        let wallet = test_wallet("wrong_pwd");
        wallet.create_account("strongpassword1", "Primary").await.expect("create");
        let result = wallet.unlock("wrongpassword!").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_message() {
        let wallet = test_wallet("sign");
        let account = wallet.create_account("strongpassword1", "Primary").await.expect("create");
        wallet.unlock("strongpassword1").await.expect("unlock");

        let sig = wallet.sign_message(&account.address, b"hello world").await.expect("sign");
        assert_eq!(sig.len(), 64); // Ed25519 signature
    }

    #[tokio::test]
    async fn test_sign_requires_unlock() {
        let wallet = test_wallet("sign_locked");
        let account = wallet.create_account("strongpassword1", "Primary").await.expect("create");
        let result = wallet.sign_message(&account.address, b"test").await;
        assert!(result.is_err(), "Signing without unlock should fail");
    }

    #[tokio::test]
    async fn test_list_accounts() {
        let wallet = test_wallet("list");
        wallet.create_account("strongpassword1", "Account 1").await.expect("create 1");
        wallet.create_account("strongpassword1", "Account 2").await.expect("create 2");
        wallet.create_evm_account("strongpassword1", "EVM").await.expect("create evm");

        let accounts = wallet.list_accounts().await;
        assert_eq!(accounts.len(), 3);
        assert!(accounts[0].is_default);
    }

    #[tokio::test]
    async fn test_recover_from_mnemonic() {
        let wallet = test_wallet("recover");
        let original = wallet.create_account("strongpassword1", "Original").await.expect("create");
        let mnemonic = original.mnemonic.clone();

        wallet.delete_account(&original.address, "strongpassword1").await.expect("delete");
        assert!(wallet.is_first_run().await);

        let recovered = wallet.recover_account(&mnemonic, "newpassword12", "Recovered")
            .await.expect("recover");
        assert_eq!(original.address, recovered.address);
    }

    #[tokio::test]
    async fn test_import_account() {
        let wallet = test_wallet("import");
        let original = wallet.create_account("strongpassword1", "Original").await.expect("create");
        let privkey = wallet.export_private_key(&original.address, "strongpassword1").await.expect("export");

        let wallet2 = test_wallet("import2");
        let imported = wallet2.import_account(&privkey, "differentpwd1", "Imported").await.expect("import");
        // Same key, same address
        assert_eq!(original.address, imported.address);
    }

    #[tokio::test]
    async fn test_delete_account() {
        let wallet = test_wallet("delete");
        let account = wallet.create_account("strongpassword1", "Primary").await.expect("create");
        assert!(!wallet.is_first_run().await);

        wallet.delete_account(&account.address, "strongpassword1").await.expect("delete");
        assert!(wallet.is_first_run().await);
    }

    #[tokio::test]
    async fn test_delete_wrong_password() {
        let wallet = test_wallet("delete_wrong");
        let account = wallet.create_account("strongpassword1", "Primary").await.expect("create");
        let result = wallet.delete_account(&account.address, "wrongpassword!").await;
        assert!(result.is_err());
        assert!(!wallet.is_first_run().await);
    }

    #[tokio::test]
    async fn test_config_access() {
        let wallet = Wallet::new_default();
        assert_eq!(wallet.config().chain_id, 40204);
    }

    #[tokio::test]
    async fn test_primary_address() {
        let wallet = test_wallet("primary");
        assert!(wallet.primary_address().await.is_none());
        let account = wallet.create_account("strongpassword1", "Primary").await.expect("create");
        assert_eq!(wallet.primary_address().await, Some(account.address));
    }

    #[tokio::test]
    async fn test_sdk_account_serialization() {
        let account = SdkAccount {
            address: "0xabc".to_string(),
            public_key: "deadbeef".to_string(),
            mnemonic: "word1 word2".to_string(),
            label: "Test".to_string(),
        };
        let json = serde_json::to_string(&account).expect("serialize");
        let deser: SdkAccount = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.address, "0xabc");
    }

    #[tokio::test]
    async fn test_sdk_config_serialization() {
        let config = SdkConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let deser: SdkConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.chain_id, 40204);
    }

    #[tokio::test]
    async fn test_sign_deterministic() {
        let wallet = test_wallet("deterministic");
        let account = wallet.create_account("strongpassword1", "Primary").await.expect("create");
        wallet.unlock("strongpassword1").await.expect("unlock");

        let sig1 = wallet.sign_message(&account.address, b"determinism test").await.expect("sign 1");
        let sig2 = wallet.sign_message(&account.address, b"determinism test").await.expect("sign 2");
        assert_eq!(sig1, sig2);
    }

    #[tokio::test]
    async fn test_multiple_accounts_sign_differently() {
        let wallet = test_wallet("multi_sign");
        let a1 = wallet.create_account("strongpassword1", "A1").await.expect("create 1");
        let a2 = wallet.create_account("strongpassword1", "A2").await.expect("create 2");
        wallet.unlock("strongpassword1").await.expect("unlock");

        let sig1 = wallet.sign_message(&a1.address, b"test").await.expect("sign 1");
        let sig2 = wallet.sign_message(&a2.address, b"test").await.expect("sign 2");
        assert_ne!(sig1, sig2);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let wallet = test_wallet("rate_limit");
        wallet.create_account("strongpassword1", "Primary").await.expect("create");

        // 5 wrong attempts (default max_failed_attempts)
        for _ in 0..5 {
            let _ = wallet.unlock("wrongpassword!").await;
        }

        // Even correct password should be rate-limited now
        let result = wallet.unlock("strongpassword1").await;
        assert!(result.is_err(), "Should be rate-limited after 5 failures");
    }

    #[tokio::test]
    async fn test_empty_password_rejected() {
        let wallet = test_wallet("empty_pwd");
        let result = wallet.create_account("", "Test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_short_password_rejected() {
        let wallet = test_wallet("short_pwd");
        let result = wallet.create_account("1234567", "Test").await;
        assert!(result.is_err());
    }
}
