// citrate/core/execution/src/types.rs

// Types for representing addresses, models, and transactions
use citrate_consensus::types::{Hash, PublicKey};
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// Account address (20 bytes, similar to Ethereum)
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Derive an `Address` from a 32-byte `PublicKey`.
    ///
    /// The chain accepts two encodings inside the same 32-byte slot
    /// to support both ed25519 native callers and the EVM-style
    /// 20-byte addresses dApps already know:
    ///
    /// 1. **Embedded EVM address** — first 20 bytes carry the
    ///    address, last 12 bytes are all zero. Used directly. This
    ///    is the format `eth_sendRawTransaction` produces after
    ///    decoding an EIP-155 / EIP-1559 RLP and sender-recovery —
    ///    the sender's secp256k1 derived address is left-aligned in
    ///    the 32-byte field, padded with zeros. We recognise it by
    ///    "trailing 12 zeros AND leading 20 bytes not all zero" so
    ///    `PublicKey::default()` (which is all zeros) does not
    ///    collide with a legitimate embedded address.
    ///
    /// 2. **Full ed25519 public key** — every byte non-zero (or any
    ///    non-zero byte in the trailing 12). The address is the
    ///    last 20 bytes of `keccak256(pubkey)` — the same shape
    ///    Ethereum uses for secp256k1 keys, applied here to ed25519
    ///    so a single `Address` type spans both schemes.
    ///
    /// Collision-freeness between the two paths is asserted by
    /// `tests::test_dual_address_no_collision`: any 32-byte public
    /// key with at least one non-zero trailing byte yields a
    /// keccak-derived address that cannot equal the
    /// embedded-address result of any *other* key (because keccak
    /// over the full 32 bytes is preimage-resistant). C-02 in the
    /// 2026-04-24 audit covers the same property.
    pub fn from_public_key(pubkey: &PublicKey) -> Self {
        let is_evm_address =
            pubkey.0[20..].iter().all(|&b| b == 0) && !pubkey.0[..20].iter().all(|&b| b == 0);

        if is_evm_address {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&pubkey.0[..20]);
            Address(addr)
        } else {
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::default();
            hasher.update(pubkey.0);
            let hash = hasher.finalize();

            let mut addr = [0u8; 20];
            addr.copy_from_slice(&hash[12..32]);
            Address(addr)
        }
    }

    pub fn zero() -> Self {
        Address([0u8; 20])
    }

    /// Parse an address from a "0x..." hex string (Ethereum JSON-RPC format)
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
        if bytes.len() != 20 {
            return Err(format!("expected 20 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Address(arr))
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Get the underlying bytes (for compatibility with ethereum-types)
    pub fn as_fixed_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_public_key_embedded_evm() {
        // First 20 bytes non-zero, last 12 bytes zero → embedded address
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate().take(20) {
            *b = (i as u8) + 1;
        }
        // last 12 remain zero
        let pk = PublicKey::new(bytes);
        let addr = Address::from_public_key(&pk);
        assert_eq!(addr.0, bytes[0..20]);
    }

    #[test]
    fn test_address_from_public_key_hashed() {
        // Non-zero across 32 bytes → derive from Keccak256
        let bytes = [0x55u8; 32];
        let pk = PublicKey::new(bytes);
        let addr = Address::from_public_key(&pk);
        assert_ne!(addr.0, bytes[0..20]);
    }

    #[test]
    fn test_dual_address_no_collision() {
        // Test that embedded EVM addresses and hashed addresses from different
        // public keys never collide. This is a critical security property.
        use std::collections::HashSet;

        let mut addresses = HashSet::new();

        // Generate 100 embedded EVM addresses (first 20 bytes vary, last 12 are zero)
        for i in 0u8..100 {
            let mut bytes = [0u8; 32];
            // Set first 20 bytes to various patterns
            bytes[0] = i;
            bytes[1] = i.wrapping_mul(7);
            bytes[2] = i.wrapping_mul(13);
            for (j, byte) in bytes[3..20].iter_mut().enumerate() {
                *byte = ((i as usize + j + 3) % 256) as u8;
            }
            // Last 12 bytes are zero for embedded EVM address
            let pk = PublicKey::new(bytes);
            let addr = Address::from_public_key(&pk);
            assert!(
                addresses.insert(addr),
                "Collision detected for embedded EVM address with pattern {}",
                i
            );
        }

        // Generate 100 hashed addresses (full 32-byte public keys)
        for i in 0u8..100 {
            let mut bytes = [0u8; 32];
            // Fill all 32 bytes with varying patterns
            for (j, byte) in bytes.iter_mut().enumerate() {
                *byte = ((i as usize * 3 + j * 5) % 256) as u8;
            }
            // Ensure this is NOT an embedded EVM address by setting last 12 bytes non-zero
            bytes[31] = 1; // At least one non-zero byte in last 12
            let pk = PublicKey::new(bytes);
            let addr = Address::from_public_key(&pk);
            assert!(
                addresses.insert(addr),
                "Collision detected for hashed address with pattern {}",
                i
            );
        }

        // Total should be 200 unique addresses
        assert_eq!(addresses.len(), 200);
    }

    #[test]
    fn test_embedded_address_deterministic() {
        // Same embedded EVM bytes should always produce the same address
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes[..20].iter_mut().enumerate() {
            *byte = (i as u8) + 0xAB;
        }
        let pk1 = PublicKey::new(bytes);
        let pk2 = PublicKey::new(bytes);
        let addr1 = Address::from_public_key(&pk1);
        let addr2 = Address::from_public_key(&pk2);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_hashed_address_deterministic() {
        // Same full public key should always produce the same address
        let bytes = [0x42u8; 32];
        let pk1 = PublicKey::new(bytes);
        let pk2 = PublicKey::new(bytes);
        let addr1 = Address::from_public_key(&pk1);
        let addr2 = Address::from_public_key(&pk2);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_zero_detection_edge_cases() {
        // All zeros should be treated as embedded (though this is a degenerate case)
        let all_zero = [0u8; 32];
        let pk = PublicKey::new(all_zero);
        let addr = Address::from_public_key(&pk);
        // First 20 bytes are all zero, so it gets hashed (per the condition)
        // The condition is: first 20 NOT all zero AND last 12 all zero
        // With all zeros, first 20 ARE all zero, so it gets hashed
        assert_ne!(addr.0, [0u8; 20]); // Should not be zero address from hashing

        // First 20 bytes = 0 except one byte, last 12 = 0 → embedded
        let mut edge_case = [0u8; 32];
        edge_case[0] = 1;
        let pk2 = PublicKey::new(edge_case);
        let addr2 = Address::from_public_key(&pk2);
        assert_eq!(addr2.0[0], 1);
        assert_eq!(addr2.0[1..], [0u8; 19]);
    }

    // -----------------------------------------------------------------------
    // Property-based tests (proptest)
    // -----------------------------------------------------------------------
    use proptest::prelude::*;

    proptest! {
        /// Property: Address derivation is deterministic — same pubkey always yields the same address.
        #[test]
        fn prop_address_derivation_deterministic(pk_bytes in prop::collection::vec(any::<u8>(), 32)) {
            let arr: [u8; 32] = pk_bytes.as_slice().try_into().unwrap();
            let pk1 = PublicKey::new(arr);
            let pk2 = PublicKey::new(arr);
            let addr1 = Address::from_public_key(&pk1);
            let addr2 = Address::from_public_key(&pk2);
            prop_assert_eq!(addr1, addr2, "Same public key must produce same address");
        }

        /// Property: Address from_hex round-trip — Display then from_hex recovers the original address.
        #[test]
        fn prop_address_hex_roundtrip(addr_bytes in prop::collection::vec(any::<u8>(), 20)) {
            let arr: [u8; 20] = addr_bytes.as_slice().try_into().unwrap();
            let original = Address(arr);
            let hex_str = format!("{}", original);
            let recovered = Address::from_hex(&hex_str).expect("from_hex must succeed on Display output");
            prop_assert_eq!(original, recovered, "Hex round-trip must be identity");
        }

        /// Property: AccountState serialization round-trip — bincode serialize then deserialize is identity.
        #[test]
        fn prop_account_state_serialization_roundtrip(
            nonce in any::<u64>(),
            balance_lo in any::<u64>(),
        ) {
            let state = AccountState {
                nonce,
                balance: U256::from(balance_lo),
                storage_root: Hash::default(),
                code_hash: Hash::default(),
                model_permissions: Vec::new(),
            };
            let bytes = bincode::serialize(&state).expect("serialize must succeed");
            let recovered: AccountState = bincode::deserialize(&bytes).expect("deserialize must succeed");
            prop_assert_eq!(recovered.nonce, state.nonce);
            prop_assert_eq!(recovered.balance, state.balance);
        }
    }

    #[test]
    fn test_address_format_parity() {
        // Verify that addresses derived from embedded EVM format match the original bytes
        let mut evm_bytes = [0u8; 32];
        let expected_addr: [u8; 20] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34,
            0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
        ];
        evm_bytes[..20].copy_from_slice(&expected_addr);
        // Last 12 bytes are zero

        let pk = PublicKey::new(evm_bytes);
        let addr = Address::from_public_key(&pk);
        assert_eq!(addr.0, expected_addr, "Embedded EVM address should match original bytes exactly");
    }
}

/// Model identifier
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelId(pub Hash);

/// Training job identifier
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobId(pub Hash);

/// Account state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: Hash,
    pub code_hash: Hash,
    pub model_permissions: Vec<ModelId>,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::zero(),
            storage_root: Hash::default(),
            code_hash: Hash::default(),
            model_permissions: Vec::new(),
        }
    }
}

/// Model metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ModelMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub framework: String,
    pub input_shape: Vec<usize>,
    pub output_shape: Vec<usize>,
    pub size_bytes: u64,
    pub created_at: u64,
}

/// Access policy for models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessPolicy {
    Public,
    Private,
    Restricted(Vec<Address>),
    PayPerUse { fee: U256 },
}

/// Model state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelState {
    pub owner: Address,
    pub model_hash: Hash,
    pub version: u32,
    pub metadata: ModelMetadata,
    pub access_policy: AccessPolicy,
    pub usage_stats: UsageStats,
}

/// Usage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageStats {
    pub total_inferences: u64,
    pub total_gas_used: u64,
    pub total_fees_earned: U256,
    pub last_used: u64,
}

/// Training job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingJob {
    pub id: JobId,
    pub owner: Address,
    pub model_id: ModelId,
    pub dataset_hash: Hash,
    pub participants: Vec<Address>,
    pub gradients_submitted: u32,
    pub gradients_required: u32,
    pub reward_pool: U256,
    pub status: JobStatus,
    pub created_at: u64,
    pub completed_at: Option<u64>,
}

/// Job status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Active,
    Completed,
    Failed,
    Cancelled,
}

/// Transaction types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    /// Standard value transfer
    Transfer { to: Address, value: U256 },

    /// Deploy contract
    Deploy { code: Vec<u8>, init_data: Vec<u8> },

    /// Call contract
    Call {
        to: Address,
        data: Vec<u8>,
        value: U256,
    },

    /// Register a new model
    RegisterModel {
        model_hash: Hash,
        metadata: ModelMetadata,
        access_policy: AccessPolicy,
        artifact_cid: Option<String>,
    },

    /// Update model version
    UpdateModel {
        model_id: ModelId,
        metadata: ModelMetadata,
        artifact_cid: Option<String>,
    },

    /// Request inference
    InferenceRequest {
        model_id: ModelId,
        input_data: Vec<u8>,
        max_gas: u64,
    },

    /// Submit training gradient
    SubmitGradient {
        job_id: JobId,
        gradient_data: Vec<u8>,
        proof: Vec<u8>,
    },
}

/// Transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: Hash,
    pub block_hash: Hash,
    pub block_number: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub gas_used: u64,
    pub status: bool,
    pub logs: Vec<Log>,
    pub output: Vec<u8>,
    /// EIP-2718 transaction type (0=legacy, 1=EIP-2930, 2=EIP-1559)
    #[serde(default)]
    pub eth_tx_type: u8,
    /// Effective gas price actually paid (gas_price for legacy, computed for EIP-1559)
    #[serde(default)]
    pub effective_gas_price: u64,
    /// DPF-VM-1 WP-8 — when `status` is `false`, this carries the
    /// human-readable reason (REVM halt detail, executor error, or
    /// custom revert string). `None` on successful execution.
    ///
    /// Before this field existed, in-EVM halts were silently absorbed
    /// as `Ok(receipt{ status: false, output: vec![] })` and surfaced
    /// to `eth_call` as `"0x"` with no error visible to the caller —
    /// which is exactly how the CANCUN/MCOPY bug stayed undiagnosed
    /// for so long. Now `eth_call` reads this field and propagates
    /// the reason as a JSON-RPC error so the next silent-failure-bug
    /// is detectable from a single RPC call.
    ///
    /// The field is always serialised — `skip_serializing_if` would
    /// confuse bincode's positional encoding, leaving older receipt
    /// blobs unable to round-trip. JSON consumers still get `null`
    /// for unset values; the small overhead (1 byte per receipt in
    /// bincode) is the right price for forward-compat.
    #[serde(default)]
    pub revert_reason: Option<String>,
}

/// Event log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<Hash>,
    pub data: Vec<u8>,
}

/// Gas schedule
#[derive(Debug, Clone)]
pub struct GasSchedule {
    // Basic operations
    pub transfer: u64,
    pub sstore: u64,
    pub sload: u64,
    pub create: u64,
    pub call: u64,

    // AI operations
    pub model_register: u64,
    pub model_update: u64,
    pub inference_base: u64,
    pub inference_per_mb: u64,
    pub training_submit: u64,

    // AI opcodes
    pub tensor_op: u64,
    pub model_load: u64,
    pub model_exec: u64,
    pub zk_prove: u64,
    pub zk_verify: u64,

    // Arithmetic operations
    pub add: u64,
    pub mul: u64,
    pub sub: u64,
    pub div: u64,
    pub exp: u64,
    pub sha3: u64,

    // Stack operations
    pub push: u64,
    pub pop: u64,
    pub mload: u64,
    pub mstore: u64,

    // Control flow
    pub jump: u64,
    pub jumpi: u64,
}

impl Default for GasSchedule {
    fn default() -> Self {
        Self {
            // Basic operations
            transfer: 21_000,
            sstore: 20_000,
            sload: 800,
            create: 32_000,
            call: 700,

            // AI operations
            model_register: 100_000,
            model_update: 50_000,
            inference_base: 50_000,
            inference_per_mb: 10_000,
            training_submit: 200_000,

            // AI opcodes
            tensor_op: 10_000,
            model_load: 50_000,
            model_exec: 100_000,
            zk_prove: 200_000,
            zk_verify: 50_000,

            // Arithmetic operations
            add: 3,
            mul: 5,
            sub: 3,
            div: 5,
            exp: 10,
            sha3: 30,
            push: 3,
            pop: 2,
            mload: 3,
            mstore: 3,
            jump: 8,
            jumpi: 10,
        }
    }
}

/// Execution error
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("Insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: U256, have: U256 },

    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    #[error("Out of gas")]
    OutOfGas,

    #[error("Stack overflow")]
    StackOverflow,

    #[error("Invalid opcode: {0}")]
    InvalidOpcode(u8),

    #[error("Account not found: {0}")]
    AccountNotFound(Address),

    #[error("Model not found: {0:?}")]
    ModelNotFound(ModelId),

    #[error("Access denied")]
    AccessDenied,

    #[error("Invalid input data")]
    InvalidInput,

    #[error("Execution reverted: {0}")]
    Reverted(String),

    #[error("Stack underflow")]
    StackUnderflow,

    #[error("Invalid model")]
    InvalidModel,

    #[error("Invalid tensor")]
    InvalidTensor,

    #[error("Tensor shape mismatch")]
    TensorShapeMismatch,

    #[error("Invalid opcode")]
    InvalidOpcodeGeneric,

    #[error("Invalid jump destination")]
    InvalidJumpDestination,

    /// Execute-on-receive: re-executing a received block's transactions produced a
    /// state root different from the block's claimed `state_root`. The block is invalid
    /// and MUST be rejected; world state is left untouched (reverted).
    #[error("State root mismatch: block claims {expected}, re-execution produced {got}")]
    StateRootMismatch { expected: Hash, got: Hash },

    /// VALIDATOR-S1 §R': a block violated a priority-fee reward-settlement import
    /// rule and MUST be rejected — a committed `base_fee_per_gas` != the reroll
    /// constant, a `header.coinbase` that is not the proposer's registered
    /// `stakerAddress` at the epoch snapshot, a proposer absent from the snapshot,
    /// or an included transaction whose `gas_price < base_fee` (EIP-1559 invalid).
    /// Deterministic: every correctly-synced node reaches the identical verdict.
    #[error("Reward settlement rejected: {0}")]
    RewardSettlement(String),
}
