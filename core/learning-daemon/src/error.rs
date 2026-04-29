//! Daemon error type. Per CORE_RULES Rule 5 + the WP-3.4 tripwire
//! `check_daemon_no_unwrap.py`, every fallible path returns
//! `Result<_, DaemonError>` rather than panicking via `.unwrap()`.

use thiserror::Error;

/// Top-level error type for the learning daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// RPC layer failure (connection, JSON-RPC error, malformed response).
    #[error("chain rpc: {0}")]
    Chain(String),

    /// Persistence layer failure (RocksDB Open, read, write, corruption).
    /// On `Corruption`, the daemon's startup contract is to refuse to
    /// continue and exit — automated recovery would mask deeper bugs.
    /// (See Gherkin scenario 6.)
    #[error("persistence: {0}")]
    Persistence(String),

    /// Aggregation layer failure (Belnap precompile rejected input,
    /// aggregator computed an invalid state vector, IPFS CID mismatch).
    #[error("aggregation: {0}")]
    Aggregation(String),

    /// Trainer layer failure (candle SGD diverged, Q16 quantization
    /// out-of-range, IPFS pin failed).
    #[error("training: {0}")]
    Training(String),

    /// Finalize-call layer failure (LearningCycleManager.finalizeCycle
    /// reverted, gas estimation failed, tx hash not found in receipts
    /// after timeout).
    #[error("finalize: {0}")]
    Finalize(String),

    /// Configuration error at startup (missing env var, malformed
    /// keystore, unreachable RPC URL).
    #[error("config: {0}")]
    Config(String),

    /// Internal invariant violation. Should never fire in practice;
    /// if it does, the daemon's state machine has drifted from
    /// `LearningDaemon.tla` and the operator should escalate.
    #[error("internal invariant violation: {0}")]
    Invariant(String),

    /// Generic I/O error (filesystem, OS-level).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Bincode (de)serialization error for state persistence.
    #[error("serde: {0}")]
    Serde(String),
}

impl From<bincode::Error> for DaemonError {
    fn from(e: bincode::Error) -> Self {
        DaemonError::Serde(e.to_string())
    }
}

impl From<rocksdb::Error> for DaemonError {
    fn from(e: rocksdb::Error) -> Self {
        DaemonError::Persistence(e.to_string())
    }
}

/// Result alias for daemon operations.
pub type DaemonResult<T> = Result<T, DaemonError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_displays_with_context() {
        let e = DaemonError::Chain("RPC timeout".to_string());
        assert_eq!(format!("{e}"), "chain rpc: RPC timeout");
    }

    #[test]
    fn error_categories_are_distinct() {
        let chain = DaemonError::Chain("x".into());
        let persist = DaemonError::Persistence("x".into());
        // Different variants — the operator can dispatch on category.
        assert!(format!("{chain}") != format!("{persist}"));
    }

    #[test]
    fn bincode_error_lifts_to_serde_variant() {
        // Force a bincode round-trip failure by deserializing
        // truncated bytes into a struct that won't fit.
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct Big {
            a: u64,
            b: u64,
        }
        let truncated = vec![0u8; 4]; // need 16 bytes for two u64s
        let result: Result<Big, _> = bincode::deserialize(&truncated);
        let err = result.expect_err("decode should fail");
        let lifted: DaemonError = err.into();
        assert!(matches!(lifted, DaemonError::Serde(_)));
    }
}
