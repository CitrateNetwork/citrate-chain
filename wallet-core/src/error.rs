//! Wallet error types — structured errors for all wallet operations.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Wallet is locked")]
    WalletLocked,

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Insufficient funds: have {have}, need {need}")]
    InsufficientFunds { have: String, need: String },

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Nonce error: {0}")]
    Nonce(String),

    #[error("Chain ID mismatch: expected {expected}, got {got}")]
    ChainIdMismatch { expected: u64, got: u64 },

    #[error("Credential error: {0}")]
    Credential(String),

    #[error("DID error: {0}")]
    Did(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Session expired")]
    SessionExpired,

    /// RM-I / WP-I1.1 (RA-WAL-01): the SDK requires fresh password
    /// verification before signing a high-value transaction. The
    /// caller (extension, CLI, GUI) must prompt the user for the
    /// password, verify it, and call
    /// `SessionManager::refresh_password_timestamp` before retrying.
    #[error("Re-authentication required: this operation requires a fresh password verification")]
    ReauthRequired,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<WalletError> = vec![
            WalletError::KeyGeneration("test".into()),
            WalletError::KeyNotFound("0xabc".into()),
            WalletError::InvalidPassword,
            WalletError::WalletLocked,
            WalletError::Encryption("aes failed".into()),
            WalletError::Decryption("bad key".into()),
            WalletError::InvalidMnemonic("wrong words".into()),
            WalletError::InvalidAddress("0xbad".into()),
            WalletError::InsufficientFunds { have: "1".into(), need: "10".into() },
            WalletError::TransactionFailed("nonce".into()),
            WalletError::Rpc("timeout".into()),
            WalletError::Nonce("too low".into()),
            WalletError::ChainIdMismatch { expected: 40204, got: 1 },
            WalletError::Credential("expired".into()),
            WalletError::Did("unresolvable".into()),
            WalletError::Storage("disk full".into()),
            WalletError::RateLimited("5 min".into()),
            WalletError::SessionExpired,
            WalletError::Serialization("bincode".into()),
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<WalletError>();
        assert_sync::<WalletError>();
    }
}
