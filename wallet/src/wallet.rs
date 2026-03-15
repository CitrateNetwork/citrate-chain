use crate::errors::WalletError;
use crate::keystore::KeyStore;
use crate::rpc_client::RpcClient;
use citrate_consensus::types::{Hash, PublicKey};
use citrate_execution::types::Address;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub index: usize,
    pub address: Address,
    pub public_key: PublicKey,
    pub alias: Option<String>,
    pub balance: U256,
    pub nonce: u64,
}

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub keystore_path: PathBuf,
    pub rpc_url: String,
    pub chain_id: u64,
    pub default_gas_price: u64,
    pub default_gas_limit: u64,
}

impl Default for WalletConfig {
    fn default() -> Self {
        let mut keystore_path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        keystore_path.push(".citrate");
        keystore_path.push("keystore.json");

        Self {
            keystore_path,
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 40204,
            default_gas_price: 1_000_000_000, // 1 gwei
            default_gas_limit: 21_000,
        }
    }
}

/// Main wallet structure
pub struct Wallet {
    config: WalletConfig,
    keystore: KeyStore,
    rpc_client: RpcClient,
    accounts: Vec<Account>,
}

impl Wallet {
    /// Create new wallet with config
    pub fn new(config: WalletConfig) -> Result<Self, WalletError> {
        // Ensure parent directory exists
        if let Some(parent) = config.keystore_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let keystore = KeyStore::new(&config.keystore_path)?;
        let rpc_client = RpcClient::new(&config.rpc_url);

        Ok(Self {
            config,
            keystore,
            rpc_client,
            accounts: Vec::new(),
        })
    }

    /// Create new account
    pub fn create_account(
        &mut self,
        password: &str,
        alias: Option<String>,
    ) -> Result<Account, WalletError> {
        let verifying_key = self.keystore.generate_key(password, alias.clone())?;

        let public_key = PublicKey::new(verifying_key.to_bytes());
        let address = Address::from_public_key(&public_key);

        let index = self.accounts.len();
        let account = Account {
            index,
            address,
            public_key,
            alias,
            balance: U256::zero(),
            nonce: 0,
        };

        self.accounts.push(account.clone());

        Ok(account)
    }

    /// Import account from private key
    pub fn import_account(
        &mut self,
        private_key_hex: &str,
        password: &str,
        alias: Option<String>,
    ) -> Result<Account, WalletError> {
        let verifying_key = self
            .keystore
            .import_key(private_key_hex, password, alias.clone())?;

        let public_key = PublicKey::new(verifying_key.to_bytes());
        let address = Address::from_public_key(&public_key);

        let index = self.accounts.len();
        let account = Account {
            index,
            address,
            public_key,
            alias,
            balance: U256::zero(),
            nonce: 0,
        };

        self.accounts.push(account.clone());

        Ok(account)
    }

    /// Unlock wallet
    pub fn unlock(&mut self, password: &str) -> Result<(), WalletError> {
        self.keystore.unlock(password)?;
        self.refresh_accounts()?;
        Ok(())
    }

    /// Lock wallet
    pub fn lock(&mut self) {
        self.keystore.lock();
    }

    /// Refresh account list from keystore
    pub fn refresh_accounts(&mut self) -> Result<(), WalletError> {
        self.accounts.clear();

        for (index, public_key_bytes, alias) in self.keystore.list_accounts() {
            let mut pk_array = [0u8; 32];
            pk_array.copy_from_slice(&public_key_bytes[..32.min(public_key_bytes.len())]);
            let public_key = PublicKey::new(pk_array);
            let address = Address::from_public_key(&public_key);

            self.accounts.push(Account {
                index,
                address,
                public_key,
                alias,
                balance: U256::zero(),
                nonce: 0,
            });
        }

        Ok(())
    }

    /// Update account balances from chain
    pub async fn update_balances(&mut self) -> Result<(), WalletError> {
        for account in &mut self.accounts {
            let balance = self.rpc_client.get_balance(&account.address).await?;
            let nonce = self.rpc_client.get_nonce(&account.address).await?;

            account.balance = balance;
            account.nonce = nonce;
        }

        Ok(())
    }

    /// Get account by index
    pub fn get_account(&self, index: usize) -> Option<&Account> {
        self.accounts.get(index)
    }

    /// Get account by address
    pub fn get_account_by_address(&self, address: &Address) -> Option<&Account> {
        self.accounts.iter().find(|a| a.address == *address)
    }

    /// List all accounts
    pub fn list_accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Send transaction
    pub async fn send_transaction(
        &self,
        from_index: usize,
        to: Address,
        value: U256,
        data: Vec<u8>,
        gas_price: Option<u64>,
        gas_limit: Option<u64>,
    ) -> Result<Hash, WalletError> {
        // Get account
        let account = self
            .get_account(from_index)
            .ok_or_else(|| WalletError::AccountNotFound(format!("Index {}", from_index)))?;

        // Check balance
        let gas_price = gas_price.unwrap_or(self.config.default_gas_price);
        let gas_limit = gas_limit.unwrap_or(self.config.default_gas_limit);
        let gas_cost = U256::from(gas_price) * U256::from(gas_limit);
        let total_cost = value + gas_cost;

        if account.balance < total_cost {
            return Err(WalletError::InsufficientBalance {
                need: format_latt(total_cost),
                have: format_latt(account.balance),
            });
        }

        // Get signing key
        let signing_key = self.keystore.get_signing_key(from_index)?;

        // Build and sign transaction
        let tx = crate::transaction::TransactionBuilder::new()
            .from(account.public_key)
            .to(Some(to))
            .value(value)
            .data(data)
            .nonce(account.nonce)
            .gas_price(gas_price)
            .gas_limit(gas_limit)
            .chain_id(self.config.chain_id)
            .build_and_sign(signing_key)?;

        // Send transaction
        let tx_hash = self.rpc_client.send_transaction(tx).await?;

        Ok(tx_hash)
    }

    /// Transfer tokens
    pub async fn transfer(
        &self,
        from_index: usize,
        to: Address,
        amount: U256,
    ) -> Result<Hash, WalletError> {
        self.send_transaction(from_index, to, amount, Vec::new(), None, None)
            .await
    }

    /// Get transaction receipt
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &Hash,
    ) -> Result<Option<serde_json::Value>, WalletError> {
        self.rpc_client.get_transaction_receipt(tx_hash).await
    }

    /// Export private key
    pub fn export_private_key(&self, index: usize) -> Result<String, WalletError> {
        self.keystore.export_private_key(index)
    }

    /// Get config
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    /// Get RPC client
    pub fn rpc_client(&self) -> &RpcClient {
        &self.rpc_client
    }
}

/// Format U256 as SALT with decimals (public for testing)
pub(crate) fn format_latt(value: U256) -> String {
    let decimals = U256::from(10).pow(U256::from(18));
    let whole = value / decimals;
    let fraction = value % decimals;

    // Format with up to 6 decimal places
    let fraction_str = format!("{:018}", fraction);
    let end = fraction_str.len().min(6);
    let fraction_trimmed = fraction_str[..end].trim_end_matches('0');

    if fraction_trimmed.is_empty() {
        format!("{}", whole)
    } else {
        format!("{}.{}", whole, fraction_trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_wallet() -> (TempDir, Wallet) {
        let dir = TempDir::new().unwrap();
        let config = WalletConfig {
            keystore_path: dir.path().join("keystore.json"),
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 40204,
            default_gas_price: 1_000_000_000,
            default_gas_limit: 21_000,
        };
        let wallet = Wallet::new(config).unwrap();
        (dir, wallet)
    }

    // ── WalletConfig defaults ──

    #[test]
    fn test_wallet_config_defaults() {
        let config = WalletConfig::default();
        assert_eq!(config.chain_id, 40204);
        assert_eq!(config.rpc_url, "http://localhost:8545");
        assert_eq!(config.default_gas_price, 1_000_000_000);
        assert_eq!(config.default_gas_limit, 21_000);
    }

    // ── Account creation ──

    #[test]
    fn test_create_account_returns_valid_account() {
        let (_dir, mut wallet) = test_wallet();
        let account = wallet.create_account("pw", Some("alice".to_string())).unwrap();
        assert_eq!(account.index, 0);
        assert_eq!(account.alias, Some("alice".to_string()));
        assert_eq!(account.balance, U256::zero());
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn test_create_multiple_accounts_increments_index() {
        let (_dir, mut wallet) = test_wallet();
        let a0 = wallet.create_account("pw", None).unwrap();
        let a1 = wallet.create_account("pw", None).unwrap();
        let a2 = wallet.create_account("pw", None).unwrap();
        assert_eq!(a0.index, 0);
        assert_eq!(a1.index, 1);
        assert_eq!(a2.index, 2);
        assert_eq!(wallet.list_accounts().len(), 3);
    }

    #[test]
    fn test_create_account_derives_address_from_pubkey() {
        let (_dir, mut wallet) = test_wallet();
        let account = wallet.create_account("pw", None).unwrap();
        let expected_addr = Address::from_public_key(&account.public_key);
        assert_eq!(account.address, expected_addr);
    }

    // ── Account import ──

    #[test]
    fn test_import_account_from_known_key() {
        let (_dir, mut wallet) = test_wallet();
        let secret = [42u8; 32];
        let account = wallet
            .import_account(&hex::encode(secret), "pw", Some("imported".to_string()))
            .unwrap();
        assert_eq!(account.index, 0);
        assert_eq!(account.alias, Some("imported".to_string()));

        // Verify public key matches
        let expected_vk = ed25519_dalek::SigningKey::from_bytes(&secret).verifying_key();
        assert_eq!(account.public_key.as_bytes(), &expected_vk.to_bytes());
    }

    #[test]
    fn test_import_invalid_key_length_fails() {
        let (_dir, mut wallet) = test_wallet();
        // Valid hex but wrong length (only 3 bytes)
        let err = wallet.import_account("aabbcc", "pw", None).unwrap_err();
        match err {
            WalletError::Other(msg) => assert!(msg.contains("Invalid private key length")),
            _ => panic!("Expected Other error for wrong length, got {:?}", err),
        }
    }

    #[test]
    fn test_import_invalid_hex_fails() {
        let (_dir, mut wallet) = test_wallet();
        let err = wallet.import_account("not_valid_hex", "pw", None).unwrap_err();
        match err {
            WalletError::HexDecode(_) => {}
            _ => panic!("Expected HexDecode error, got {:?}", err),
        }
    }

    // ── Lock / Unlock ──

    #[test]
    fn test_unlock_and_lock_wallet() {
        let (_dir, mut wallet) = test_wallet();
        wallet.create_account("pw", None).unwrap();

        wallet.unlock("pw").unwrap();
        assert_eq!(wallet.list_accounts().len(), 1);

        wallet.lock();
        // After lock, export should fail
        let err = wallet.export_private_key(0).unwrap_err();
        match err {
            WalletError::WalletLocked => {}
            _ => panic!("Expected WalletLocked, got {:?}", err),
        }
    }

    #[test]
    fn test_unlock_wrong_password() {
        let (_dir, mut wallet) = test_wallet();
        wallet.create_account("correct", None).unwrap();
        let err = wallet.unlock("wrong").unwrap_err();
        match err {
            WalletError::InvalidPassword => {}
            _ => panic!("Expected InvalidPassword, got {:?}", err),
        }
    }

    // ── Account lookup ──

    #[test]
    fn test_get_account_by_index() {
        let (_dir, mut wallet) = test_wallet();
        wallet.create_account("pw", None).unwrap();
        assert!(wallet.get_account(0).is_some());
        assert!(wallet.get_account(1).is_none());
    }

    #[test]
    fn test_get_account_by_address() {
        let (_dir, mut wallet) = test_wallet();
        let account = wallet.create_account("pw", None).unwrap();
        assert!(wallet.get_account_by_address(&account.address).is_some());
        assert!(wallet.get_account_by_address(&Address([0xFF; 20])).is_none());
    }

    // ── Refresh accounts ──

    #[test]
    fn test_refresh_accounts_reloads_from_keystore() {
        let (_dir, mut wallet) = test_wallet();
        wallet.create_account("pw", Some("a1".to_string())).unwrap();
        wallet.create_account("pw", Some("a2".to_string())).unwrap();

        // Refresh should clear and rebuild
        wallet.refresh_accounts().unwrap();
        assert_eq!(wallet.list_accounts().len(), 2);
    }

    // ── Export ──

    #[test]
    fn test_export_private_key_roundtrip() {
        let (_dir, mut wallet) = test_wallet();
        let secret = [99u8; 32];
        wallet.import_account(&hex::encode(secret), "pw", None).unwrap();
        wallet.unlock("pw").unwrap();

        let exported = wallet.export_private_key(0).unwrap();
        assert_eq!(exported, hex::encode(secret));
    }

    // ── format_latt ──

    #[test]
    fn test_format_latt_whole_number() {
        let one_salt = U256::from(10).pow(U256::from(18));
        assert_eq!(format_latt(one_salt), "1");
    }

    #[test]
    fn test_format_latt_fractional() {
        let half_salt = U256::from(5) * U256::from(10).pow(U256::from(17));
        assert_eq!(format_latt(half_salt), "0.5");
    }

    #[test]
    fn test_format_latt_zero() {
        assert_eq!(format_latt(U256::zero()), "0");
    }

    #[test]
    fn test_format_latt_large() {
        let hundred_salt = U256::from(100) * U256::from(10).pow(U256::from(18));
        assert_eq!(format_latt(hundred_salt), "100");
    }
}
