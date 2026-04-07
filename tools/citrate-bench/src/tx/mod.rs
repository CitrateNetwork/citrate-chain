//! Transaction construction and signing.
//!
//! Phase 1: EIP-155 legacy transactions. The RLP encoding and the
//! EIP-155 signing hash are cross-checked against the canonical test
//! vector in EIP-155 itself (see `tests/legacy_tx_vectors.rs`).
//!
//! Later phases will add EIP-1559 typed transactions and the ABI
//! encoders for the workload classes.

pub mod legacy;

/// A signed transaction, ready to submit via `eth_sendRawTransaction`.
#[derive(Debug, Clone)]
pub struct SignedTx {
    pub raw: Vec<u8>,
    pub hash: [u8; 32],
    pub nonce: u64,
    pub sender: [u8; 20],
}

impl SignedTx {
    /// Hex-encoded `0x`-prefixed raw transaction — the form
    /// `eth_sendRawTransaction` expects.
    pub fn raw_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.raw))
    }

    /// Hex-encoded `0x`-prefixed transaction hash.
    pub fn hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.hash))
    }
}
