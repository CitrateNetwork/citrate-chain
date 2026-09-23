// SPDX-License-Identifier: MIT
// Blockchain-Anchored Key Commitment
//
// This module provides on-chain key lifecycle management:
// - Key commitments without revealing keys
// - Rotation proofs for audit trails
// - Time-bound key validity verification
//
// Innovation: Store key lifecycle events on-chain for verifiable
// cryptographic audit trails, enabling compliance and forensics.

use sha3::{Sha3_256, Sha3_512, Digest};
use serde::{Deserialize, Serialize};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

// Helper for serializing [u8; 64]
mod array64_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(arr: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        arr.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::custom("Expected 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

/// Key lifecycle event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyLifecycleEvent {
    /// Key was generated
    Generated,
    /// Key was activated for use
    Activated,
    /// Key was rotated (replaced by new key)
    Rotated,
    /// Key was revoked (emergency)
    Revoked,
    /// Key expired naturally
    Expired,
    /// Key was compromised (for audit)
    Compromised,
}

/// On-chain key commitment (stored on blockchain)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCommitment {
    /// Version of the commitment scheme
    pub version: u8,
    /// Key version number
    pub key_version: u32,
    /// Purpose identifier (domain separation)
    pub purpose: u8,
    /// Commitment hash (hiding the actual key)
    pub commitment: [u8; 32],
    /// Timestamp of commitment creation
    pub timestamp: u64,
    /// Node identifier
    pub node_id: [u8; 32],
    /// Signature from node operator (placeholder)
    pub signature: Vec<u8>,
}

impl KeyCommitment {
    /// Create a new key commitment
    pub fn new(
        key_bytes: &[u8; 32],
        key_version: u32,
        purpose: u8,
        node_id: &[u8; 32],
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create hiding commitment: H(key || salt || purpose || version)
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let commitment = Self::compute_commitment(key_bytes, &salt, purpose, key_version);

        Self {
            version: 1,
            key_version,
            purpose,
            commitment,
            timestamp,
            node_id: *node_id,
            signature: Vec::new(), // To be signed by node operator
        }
    }

    /// Compute the hiding commitment
    fn compute_commitment(key: &[u8], salt: &[u8], purpose: u8, version: u32) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSP-v1-key-commitment");
        hasher.update(key);
        hasher.update(salt);
        hasher.update([purpose]);
        hasher.update(version.to_be_bytes());
        hasher.finalize().into()
    }

    /// Serialize for on-chain storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);

        bytes.push(self.version);
        bytes.extend_from_slice(&self.key_version.to_be_bytes());
        bytes.push(self.purpose);
        bytes.extend_from_slice(&self.commitment);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.node_id);
        bytes.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.signature);

        bytes
    }

    /// Parse from on-chain data
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CommitmentError> {
        // CHAIN-B-B015: the fixed header is
        //   version(1) + key_version(4) + purpose(1) + commitment(32)
        //   + timestamp(8) + node_id(32) + sig_len(2) = 80 bytes.
        // The old guard checked `< 76` but the reader slices `bytes[46..78]`
        // (needs 78) and `bytes[78..80]` (needs 80), so inputs of length 76-79
        // passed the guard and then panicked on the slice — a node kill the
        // moment this parser is wired to on-chain data. Derive the bound from
        // the layout so it cannot drift again.
        const HEADER_LEN: usize = 1 + 4 + 1 + 32 + 8 + 32 + 2; // = 80
        if bytes.len() < HEADER_LEN {
            return Err(CommitmentError::InvalidFormat);
        }

        let version = bytes[0];
        let mut kv_buf = [0u8; 4];
        kv_buf.copy_from_slice(&bytes[1..5]);
        let key_version = u32::from_be_bytes(kv_buf);
        let purpose = bytes[5];

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&bytes[6..38]);

        let mut ts_buf = [0u8; 8];
        ts_buf.copy_from_slice(&bytes[38..46]);
        let timestamp = u64::from_be_bytes(ts_buf);

        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&bytes[46..78]);

        let mut sl_buf = [0u8; 2];
        sl_buf.copy_from_slice(&bytes[78..80]);
        let sig_len = u16::from_be_bytes(sl_buf) as usize;
        let signature = if bytes.len() >= 80 + sig_len {
            bytes[80..80 + sig_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            version,
            key_version,
            purpose,
            commitment,
            timestamp,
            node_id,
            signature,
        })
    }
}

/// Proof of key rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationProof {
    /// Previous key commitment
    pub previous_commitment: [u8; 32],
    /// New key commitment
    pub new_commitment: [u8; 32],
    /// Rotation timestamp
    pub rotated_at: u64,
    /// Reason for rotation
    pub reason: RotationReason,
    /// Proof that old key authorized this rotation
    #[serde(with = "array64_serde")]
    pub authorization_proof: [u8; 64],
    /// Block height where this is anchored
    pub anchor_block: Option<u64>,
    /// Transaction hash of anchor
    pub anchor_tx: Option<[u8; 32]>,
}

/// Reasons for key rotation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationReason {
    /// Scheduled rotation (best practice)
    Scheduled,
    /// Key approaching expiry
    Expiring,
    /// Security policy change
    PolicyChange,
    /// Suspected compromise
    SuspectedCompromise,
    /// Algorithm upgrade
    AlgorithmUpgrade,
    /// Personnel change
    PersonnelChange,
}

impl KeyRotationProof {
    /// Create a new rotation proof
    pub fn new(
        old_key: &[u8; 32],
        old_commitment: [u8; 32],
        new_commitment: [u8; 32],
        reason: RotationReason,
    ) -> Self {
        let rotated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create authorization proof (old key signs the rotation)
        let authorization_proof = Self::create_authorization(
            old_key,
            &old_commitment,
            &new_commitment,
            rotated_at,
        );

        Self {
            previous_commitment: old_commitment,
            new_commitment,
            rotated_at,
            reason,
            authorization_proof,
            anchor_block: None,
            anchor_tx: None,
        }
    }

    /// Create authorization proof using the old key
    fn create_authorization(
        old_key: &[u8; 32],
        old_commitment: &[u8; 32],
        new_commitment: &[u8; 32],
        timestamp: u64,
    ) -> [u8; 64] {
        // In production, this would be a proper signature
        // For now, we use HMAC-SHA3-512
        let mut hasher = Sha3_512::new();
        hasher.update(b"QSSP-v1-rotation-auth");
        hasher.update(old_key);
        hasher.update(old_commitment);
        hasher.update(new_commitment);
        hasher.update(timestamp.to_be_bytes());

        let digest = hasher.finalize();
        let mut proof = [0u8; 64];
        proof.copy_from_slice(&digest);
        proof
    }

    /// Verify authorization proof
    pub fn verify_authorization(&self, old_key: &[u8; 32]) -> bool {
        let expected = Self::create_authorization(
            old_key,
            &self.previous_commitment,
            &self.new_commitment,
            self.rotated_at,
        );
        expected == self.authorization_proof
    }

    /// Set blockchain anchor
    pub fn set_anchor(&mut self, block_height: u64, tx_hash: [u8; 32]) {
        self.anchor_block = Some(block_height);
        self.anchor_tx = Some(tx_hash);
    }

    /// Check if this proof is anchored on-chain
    pub fn is_anchored(&self) -> bool {
        self.anchor_block.is_some() && self.anchor_tx.is_some()
    }
}

/// On-chain key anchor for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainKeyAnchor {
    /// Block height
    pub block_height: u64,
    /// Block hash
    pub block_hash: [u8; 32],
    /// Transaction index in block
    pub tx_index: u32,
    /// Merkle proof to transaction
    pub merkle_proof: Vec<[u8; 32]>,
    /// The commitment that was anchored
    pub commitment: KeyCommitment,
}

impl OnChainKeyAnchor {
    /// Verify the merkle proof
    pub fn verify_merkle_proof(&self, tx_root: &[u8; 32]) -> bool {
        let mut current = self.compute_leaf_hash();

        for (i, sibling) in self.merkle_proof.iter().enumerate() {
            let bit = (self.tx_index >> i) & 1;
            if bit == 0 {
                current = Self::hash_pair(&current, sibling);
            } else {
                current = Self::hash_pair(sibling, &current);
            }
        }

        &current == tx_root
    }

    fn compute_leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSP-v1-leaf");
        hasher.update(self.commitment.to_bytes());
        hasher.finalize().into()
    }

    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

/// Key lifecycle manager for tracking key events
pub struct KeyLifecycleManager {
    /// Current key commitment
    current_commitment: Option<KeyCommitment>,
    /// Rotation history
    rotation_history: Vec<KeyRotationProof>,
    /// Node identifier
    node_id: [u8; 32],
}

impl KeyLifecycleManager {
    /// Create a new lifecycle manager
    pub fn new(node_id: [u8; 32]) -> Self {
        Self {
            current_commitment: None,
            rotation_history: Vec::new(),
            node_id,
        }
    }

    /// Register a new key
    pub fn register_key(
        &mut self,
        key_bytes: &[u8; 32],
        key_version: u32,
        purpose: u8,
    ) -> KeyCommitment {
        let commitment = KeyCommitment::new(key_bytes, key_version, purpose, &self.node_id);
        self.current_commitment = Some(commitment.clone());
        commitment
    }

    /// Rotate to a new key
    pub fn rotate_key(
        &mut self,
        old_key: &[u8; 32],
        new_key: &[u8; 32],
        key_version: u32,
        purpose: u8,
        reason: RotationReason,
    ) -> Result<(KeyCommitment, KeyRotationProof), CommitmentError> {
        let old_commitment = self.current_commitment
            .as_ref()
            .ok_or(CommitmentError::NoCurrentKey)?
            .commitment;

        // Create new commitment
        let new_commitment_obj = KeyCommitment::new(new_key, key_version, purpose, &self.node_id);
        let new_commitment = new_commitment_obj.commitment;

        // Create rotation proof
        let proof = KeyRotationProof::new(old_key, old_commitment, new_commitment, reason);

        // Update state
        self.rotation_history.push(proof.clone());
        self.current_commitment = Some(new_commitment_obj.clone());

        Ok((new_commitment_obj, proof))
    }

    /// Get full rotation history
    pub fn get_rotation_history(&self) -> &[KeyRotationProof] {
        &self.rotation_history
    }

    /// Verify the rotation chain
    pub fn verify_rotation_chain(&self) -> bool {
        if self.rotation_history.is_empty() {
            return true;
        }

        // Verify each rotation links properly
        for window in self.rotation_history.windows(2) {
            if window[0].new_commitment != window[1].previous_commitment {
                return false;
            }
        }

        // Verify last rotation matches current commitment
        if let (Some(last_rotation), Some(current)) = (
            self.rotation_history.last(),
            &self.current_commitment,
        ) {
            if last_rotation.new_commitment != current.commitment {
                return false;
            }
        }

        true
    }

    /// Export audit trail for compliance
    pub fn export_audit_trail(&self) -> KeyAuditTrail {
        KeyAuditTrail {
            node_id: self.node_id,
            current_commitment: self.current_commitment.clone(),
            rotations: self.rotation_history.clone(),
            exported_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Exportable audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAuditTrail {
    pub node_id: [u8; 32],
    pub current_commitment: Option<KeyCommitment>,
    pub rotations: Vec<KeyRotationProof>,
    pub exported_at: u64,
}

/// Commitment errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentError {
    InvalidFormat,
    VerificationFailed,
    NoCurrentKey,
    AnchorNotFound,
}

impl std::fmt::Display for CommitmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "Invalid commitment format"),
            Self::VerificationFailed => write!(f, "Commitment verification failed"),
            Self::NoCurrentKey => write!(f, "No current key registered"),
            Self::AnchorNotFound => write!(f, "On-chain anchor not found"),
        }
    }
}

impl std::error::Error for CommitmentError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_commitment() {
        let key = [1u8; 32];
        let node_id = [0u8; 32];

        let commitment = KeyCommitment::new(&key, 1, 0x01, &node_id);

        assert_eq!(commitment.version, 1);
        assert_eq!(commitment.key_version, 1);
        assert!(commitment.timestamp > 0);
    }

    /// CHAIN-B-B015 tripwire: inputs of length 76-79 passed the old `< 76`
    /// guard and then panicked slicing `bytes[46..78]` / `bytes[78..80]`.
    /// Post-fix they return `InvalidFormat` with no panic.
    #[test]
    fn from_bytes_rejects_short_header_without_panicking() {
        for len in 0..80usize {
            let bytes = vec![0u8; len];
            assert!(
                matches!(
                    KeyCommitment::from_bytes(&bytes),
                    Err(CommitmentError::InvalidFormat)
                ),
                "len {len} must be rejected, not panic"
            );
        }
        // The exact header length parses (with an empty signature).
        assert!(KeyCommitment::from_bytes(&[0u8; 80]).is_ok());
    }

    #[test]
    fn test_commitment_serialization() {
        let key = [42u8; 32];
        let node_id = [1u8; 32];

        let commitment = KeyCommitment::new(&key, 5, 0x02, &node_id);
        let bytes = commitment.to_bytes();
        let parsed = KeyCommitment::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.key_version, 5);
        assert_eq!(parsed.purpose, 0x02);
        assert_eq!(parsed.commitment, commitment.commitment);
    }

    #[test]
    fn test_rotation_proof() {
        let old_key = [1u8; 32];
        let new_key = [2u8; 32];

        let old_commitment = [10u8; 32];
        let new_commitment = [20u8; 32];

        let proof = KeyRotationProof::new(
            &old_key,
            old_commitment,
            new_commitment,
            RotationReason::Scheduled,
        );

        assert!(proof.verify_authorization(&old_key));
        assert!(!proof.verify_authorization(&new_key)); // Wrong key should fail
    }

    #[test]
    fn test_lifecycle_manager() {
        let node_id = [0u8; 32];
        let mut manager = KeyLifecycleManager::new(node_id);

        // Register first key
        let key1 = [1u8; 32];
        manager.register_key(&key1, 1, 0x01);

        // Rotate to second key
        let key2 = [2u8; 32];
        let (_, proof) = manager.rotate_key(&key1, &key2, 2, 0x01, RotationReason::Scheduled).unwrap();

        assert!(proof.verify_authorization(&key1));
        assert_eq!(manager.get_rotation_history().len(), 1);
        assert!(manager.verify_rotation_chain());
    }

    #[test]
    fn test_audit_trail() {
        let node_id = [0u8; 32];
        let mut manager = KeyLifecycleManager::new(node_id);

        let key1 = [1u8; 32];
        manager.register_key(&key1, 1, 0x01);

        let key2 = [2u8; 32];
        manager.rotate_key(&key1, &key2, 2, 0x01, RotationReason::PolicyChange).unwrap();

        let trail = manager.export_audit_trail();

        assert_eq!(trail.rotations.len(), 1);
        assert!(trail.current_commitment.is_some());
    }
}
