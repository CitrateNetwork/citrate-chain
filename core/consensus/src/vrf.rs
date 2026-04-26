// citrate/core/consensus/src/vrf.rs

use crate::types::{Hash, PublicKey, VrfProof};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Error, Debug)]
pub enum VrfError {
    #[error("Invalid VRF proof")]
    InvalidProof,

    #[error("Validator not found")]
    ValidatorNotFound,

    #[error("Threshold not met")]
    ThresholdNotMet,

    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

/// Validator information for VRF
#[derive(Debug, Clone)]
pub struct Validator {
    pub pubkey: PublicKey,
    pub stake: u128,
    pub is_active: bool,
}

/// Above this block height, the legacy 32-byte SHA3 VRF proof
/// format is rejected outright. Below it, both ECVRF (114 bytes)
/// and legacy SHA3 (32 bytes) are accepted — necessary for
/// replaying the genesis-era chain history that pre-dates ECVRF.
///
/// Audit finding **H-06** (HIGH, downgrade): the legacy SHA3 path
/// is unauthenticated — anyone can compute `proof.proof = anything`
/// and `output = SHA3(proof || alpha)` and the verifier accepts it.
/// Accepting it on new blocks lets attackers forge VRF proofs for
/// any validator. The cutoff bounds the damage to historical
/// blocks the chain has already finalized.
///
/// Cutoff = 100_000 — comfortably past testnet-beta's current
/// height (April 2026: ~12k) and well before mainnet launch
/// (target height < 100k at activation). Configurable via
/// [`VrfProposerSelector::with_legacy_cutoff_height`] for tests
/// and devnets.
pub const DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT: u64 = 100_000;

/// VRF-based proposer selection
pub struct VrfProposerSelector {
    validators: Arc<RwLock<HashMap<PublicKey, Validator>>>,
    total_stake: Arc<RwLock<u128>>,
    difficulty_adjustment: f64,
    /// Audit H-06: legacy 32-byte SHA3 proofs rejected at or above
    /// this height. See [`DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT`].
    legacy_vrf_cutoff_height: u64,
}

impl VrfProposerSelector {
    pub fn new() -> Self {
        Self {
            validators: Arc::new(RwLock::new(HashMap::new())),
            total_stake: Arc::new(RwLock::new(0)),
            difficulty_adjustment: 1.0,
            legacy_vrf_cutoff_height: DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT,
        }
    }

    /// Override the legacy-VRF cutoff height. Used by devnet and
    /// integration tests that exercise the legacy path explicitly.
    /// Production node startup keeps the default.
    pub fn with_legacy_cutoff_height(mut self, cutoff: u64) -> Self {
        self.legacy_vrf_cutoff_height = cutoff;
        self
    }

    /// Register a validator
    pub async fn register_validator(&self, validator: Validator) {
        let mut validators = self.validators.write().await;
        let mut total_stake = self.total_stake.write().await;

        if validator.is_active {
            *total_stake += validator.stake;
        }

        validators.insert(validator.pubkey, validator.clone());
        info!("Registered validator with stake {}", validator.stake);
    }

    /// Remove a validator
    pub async fn remove_validator(&self, pubkey: &PublicKey) -> Result<(), VrfError> {
        let mut validators = self.validators.write().await;
        let mut total_stake = self.total_stake.write().await;

        if let Some(validator) = validators.remove(pubkey) {
            if validator.is_active {
                *total_stake = total_stake.saturating_sub(validator.stake);
            }
            Ok(())
        } else {
            Err(VrfError::ValidatorNotFound)
        }
    }

    /// Generate VRF proof for proposer eligibility.
    ///
    /// WP-S.2: Uses ECVRF-P256-SHA256 (RFC 9381) for real verifiable randomness.
    /// The alpha string binds (proposer pubkey || previous VRF || slot) to prevent
    /// key substitution and replay attacks (WP-H.6).
    pub fn generate_vrf_proof(
        &self,
        secret_key: &[u8; 32],
        proposer_pubkey: &PublicKey,
        previous_vrf: &Hash,
        slot: u64,
    ) -> Result<VrfProof, VrfError> {
        // Build alpha string binding (proposer, previous_vrf, slot)
        let alpha = Self::build_alpha(proposer_pubkey, previous_vrf, slot);

        // WP-S.2: Use ECVRF-P256-SHA256
        let (ecvrf_proof, beta) = crate::ecvrf::prove(secret_key, &alpha)
            .map_err(|e| VrfError::CryptoError(format!("ECVRF prove: {}", e)))?;

        Ok(VrfProof {
            proof: ecvrf_proof.to_bytes(), // 81 bytes
            output: Hash::from_bytes(&beta),
        })
    }

    /// Verify VRF proof is bound to the claimed proposer.
    ///
    /// WP-S.2: Supports both ECVRF (114 bytes) and legacy SHA3
    /// (32 bytes) proofs. The `slot` parameter doubles as block
    /// height for the legacy-cutoff check.
    ///
    /// RM-B1 / WP-B2.3 (audit H-06): legacy 32-byte SHA3 proofs
    /// are accepted ONLY below `legacy_vrf_cutoff_height` (default
    /// `DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT = 100_000`). Above the
    /// cutoff, only the cryptographic ECVRF path is accepted —
    /// closing the downgrade vector where an attacker forges
    /// `proof.proof = anything; output = SHA3(proof || alpha)` and
    /// the verifier blindly accepts.
    ///
    /// **Math-only verifier — do not call from production admission paths.**
    ///
    /// The ECVRF math here attests "the holder of `proof.pk_p256`'s
    /// secret key produced a VRF over alpha" — it does NOT attest
    /// "the holder of the claimed proposer's ed25519 secret key
    /// produced it" (audit finding REM-N-01). The structural
    /// identity binding lives in [`Self::verify_vrf_with_block_signature`],
    /// which combines this math with an ed25519 signature check
    /// under the proposer's pubkey.
    ///
    /// Call sites that legitimately need just the math:
    /// - This module (called by `verify_vrf_with_block_signature`).
    /// - Tests and benches that exercise the math directly.
    ///
    /// Production admission MUST use `verify_vrf_with_block_signature`.
    /// See `core/consensus/src/dag_store.rs::verify_block_vrf_crypto`.
    pub fn verify_vrf_math_only(
        &self,
        pubkey: &PublicKey,
        proof: &VrfProof,
        previous_vrf: &Hash,
        slot: u64,
    ) -> Result<bool, VrfError> {
        if proof.proof.len() == 114 {
            // WP-S.2: ECVRF-P256-SHA256 proof (pk_p256=33 + Gamma=33 + c=16 + s=32)
            self.verify_ecvrf_proof(pubkey, proof, previous_vrf, slot)
        } else if proof.proof.len() == 32 {
            // Legacy SHA3 proof — accepted only below the cutoff
            // height. See `legacy_vrf_cutoff_height` doc + audit
            // finding H-06.
            if slot >= self.legacy_vrf_cutoff_height {
                tracing::warn!(
                    "H-06: rejecting legacy 32-byte VRF proof at slot {} (cutoff {})",
                    slot, self.legacy_vrf_cutoff_height
                );
                return Ok(false);
            }
            self.verify_legacy_proof(pubkey, proof, previous_vrf, slot)
        } else {
            Ok(false)
        }
    }

    /// RM-I-3 / WP-I1.5 (re-audit Stream 1 finding REM-N-01): the
    /// structurally-bound verifier. Combines the ECVRF math with an
    /// ed25519 signature check that binds `proof.pk_p256` to the
    /// claimed `pubkey` (ed25519 proposer identity) via the block's
    /// own signature.
    ///
    /// Cryptographic argument:
    /// - `proof` math is bound to `alpha = pubkey || previous_vrf || slot`.
    ///   The ECVRF math is consistent only under whatever P-256 secret
    ///   key signed the proof. An attacker can substitute a key they
    ///   own, but the math then attests "the holder of attacker_sk
    ///   produced a VRF output for alpha", NOT "the holder of pubkey's
    ///   ed25519 secret key produced it".
    /// - `block_signature` is an ed25519 signature over `signed_payload`
    ///   verified against `pubkey`. Only the holder of pubkey's ed25519
    ///   secret key can produce this signature.
    /// - The combination of the two checks attests: the holder of
    ///   pubkey's ed25519 secret key chose to associate this ECVRF
    ///   proof with this slot. The attacker who substitutes pk_p256
    ///   cannot also forge the ed25519 signature, so the combined
    ///   check rejects them.
    ///
    /// This method is the **production-callable** entry point. The
    /// raw `verify_vrf_math_only` is retained for internal benches and
    /// tests; production code paths SHOULD use this method.
    ///
    /// Returns `Ok(true)` only when BOTH checks pass.
    pub fn verify_vrf_with_block_signature(
        &self,
        pubkey: &PublicKey,
        proof: &VrfProof,
        previous_vrf: &Hash,
        slot: u64,
        signed_payload: &[u8],
        block_signature: &crate::types::Signature,
    ) -> Result<bool, VrfError> {
        // Step 1: ECVRF math (or legacy below cutoff).
        if !self.verify_vrf_math_only(pubkey, proof, previous_vrf, slot)? {
            return Ok(false);
        }

        // Step 2: ed25519 signature binding the ECVRF proof to pubkey
        // via the block's signed payload. The caller's responsibility
        // is to ensure `signed_payload` covers the proof bytes (e.g.,
        // it is or includes the block hash that commits to the proof).
        // Without this check the math attests only that *some* P-256
        // key signed alpha; with this check it attests that the
        // ed25519 proposer identity claimed the proof.
        use ed25519_dalek::Verifier;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(pubkey.as_bytes())
            .map_err(|_| VrfError::CryptoError("REM-N-01: invalid ed25519 pubkey".to_string()))?;
        let dalek_sig = ed25519_dalek::Signature::from_bytes(block_signature.as_bytes());
        match verifying_key.verify(signed_payload, &dalek_sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Build the alpha string that binds (proposer, previous_vrf, slot).
    fn build_alpha(proposer_pubkey: &PublicKey, previous_vrf: &Hash, slot: u64) -> Vec<u8> {
        let mut alpha = Vec::with_capacity(32 + 32 + 8);
        alpha.extend_from_slice(proposer_pubkey.as_bytes());
        alpha.extend_from_slice(previous_vrf.as_bytes());
        alpha.extend_from_slice(&slot.to_le_bytes());
        alpha
    }

    /// WP-S.2: Verify an ECVRF-P256-SHA256 proof.
    /// The P-256 public key is embedded in the proof bytes (self-contained verification).
    /// The alpha string binds the proof to the proposer's ed25519 identity, preventing
    /// an attacker from reusing another validator's ECVRF proof.
    fn verify_ecvrf_proof(
        &self,
        pubkey: &PublicKey,
        proof: &VrfProof,
        previous_vrf: &Hash,
        slot: u64,
    ) -> Result<bool, VrfError> {
        let ecvrf_proof = crate::ecvrf::EcvrfProof::from_bytes(&proof.proof)
            .map_err(|e| VrfError::CryptoError(format!("ECVRF decode: {}", e)))?;

        let alpha = Self::build_alpha(pubkey, previous_vrf, slot);

        match crate::ecvrf::verify(&alpha, &ecvrf_proof) {
            Ok(beta) => Ok(proof.output == Hash::from_bytes(&beta)),
            Err(_) => Ok(false),
        }
    }

    /// Legacy SHA3-based proof verification (backward compatibility).
    fn verify_legacy_proof(
        &self,
        pubkey: &PublicKey,
        proof: &VrfProof,
        previous_vrf: &Hash,
        slot: u64,
    ) -> Result<bool, VrfError> {
        // Reconstruct expected input with proposer identity bound
        let mut hasher = Sha3_256::new();
        hasher.update(pubkey.as_bytes());
        hasher.update(previous_vrf.as_bytes());
        hasher.update(slot.to_le_bytes());
        let input = hasher.finalize();

        // Verify output matches SHA3(proof || input)
        let mut output_hasher = Sha3_256::new();
        output_hasher.update(&proof.proof);
        output_hasher.update(input);
        let expected_output = Hash::from_bytes(&output_hasher.finalize());

        Ok(proof.output == expected_output)
    }

    /// Check if a validator is eligible to propose for a slot
    pub async fn is_eligible_proposer(
        &self,
        pubkey: &PublicKey,
        vrf_output: &Hash,
        slot: u64,
    ) -> Result<bool, VrfError> {
        let validators = self.validators.read().await;
        let total_stake = self.total_stake.read().await;

        let validator = validators.get(pubkey).ok_or(VrfError::ValidatorNotFound)?;

        if !validator.is_active {
            return Ok(false);
        }

        // Calculate threshold based on stake
        let stake_ratio = validator.stake as f64 / *total_stake as f64;
        let threshold = self.calculate_threshold(stake_ratio, slot);

        // Convert VRF output to a number between 0 and 1
        let vrf_value = self.vrf_output_to_float(vrf_output);

        Ok(vrf_value < threshold)
    }

    /// Calculate threshold for proposer eligibility
    fn calculate_threshold(&self, stake_ratio: f64, slot: u64) -> f64 {
        // Base threshold proportional to stake
        let base_threshold = stake_ratio * self.difficulty_adjustment;

        // Add time-based variation to prevent predictability
        let time_factor = ((slot % 100) as f64 / 100.0) * 0.1;

        (base_threshold + time_factor).min(1.0)
    }

    /// Convert VRF output to a float between 0 and 1
    fn vrf_output_to_float(&self, output: &Hash) -> f64 {
        let bytes = output.as_bytes();
        let mut value = 0u64;

        // Use first 8 bytes for the value
        for &b in bytes.iter().take(8) {
            value = (value << 8) | b as u64;
        }

        value as f64 / u64::MAX as f64
    }

    /// Select proposer for a slot
    pub async fn select_proposer(
        &self,
        slot: u64,
        previous_vrf: &Hash,
    ) -> Result<Option<PublicKey>, VrfError> {
        let validators = self.validators.read().await;

        let mut best_vrf_value = f64::MAX;
        let mut selected_proposer = None;

        // Each validator computes their VRF and the lowest wins
        for (pubkey, validator) in validators.iter() {
            if !validator.is_active {
                continue;
            }

            // Simulate VRF output for this validator
            let mut hasher = Sha3_256::new();
            hasher.update(pubkey.0);
            hasher.update(previous_vrf.as_bytes());
            hasher.update(slot.to_le_bytes());
            let vrf_output = Hash::from_bytes(&hasher.finalize());

            let vrf_value = self.vrf_output_to_float(&vrf_output);

            // Weight by stake
            let weighted_value = vrf_value / (validator.stake as f64).sqrt();

            if weighted_value < best_vrf_value {
                best_vrf_value = weighted_value;
                selected_proposer = Some(*pubkey);
            }
        }

        Ok(selected_proposer)
    }

    /// Update validator stake
    pub async fn update_stake(&self, pubkey: &PublicKey, new_stake: u128) -> Result<(), VrfError> {
        let mut validators = self.validators.write().await;
        let mut total_stake = self.total_stake.write().await;

        if let Some(validator) = validators.get_mut(pubkey) {
            if validator.is_active {
                *total_stake = total_stake.saturating_sub(validator.stake);
                *total_stake += new_stake;
            }
            validator.stake = new_stake;
            Ok(())
        } else {
            Err(VrfError::ValidatorNotFound)
        }
    }

    /// Get active validator count
    pub async fn active_validator_count(&self) -> usize {
        self.validators
            .read()
            .await
            .values()
            .filter(|v| v.is_active)
            .count()
    }

    /// Get total stake
    pub async fn total_stake(&self) -> u128 {
        *self.total_stake.read().await
    }
}

impl Default for VrfProposerSelector {
    fn default() -> Self {
        Self::new()
    }
}

/// Leader election using VRF
pub struct LeaderElection {
    vrf_selector: Arc<VrfProposerSelector>,
    _epoch_length: u64,
    slots_per_epoch: u64,
}

impl LeaderElection {
    pub fn new(vrf_selector: Arc<VrfProposerSelector>, epoch_length: u64) -> Self {
        Self {
            vrf_selector,
            _epoch_length: epoch_length,
            slots_per_epoch: epoch_length,
        }
    }

    /// Get current epoch from slot
    pub fn get_epoch(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    /// Get slot within epoch
    pub fn get_slot_in_epoch(&self, slot: u64) -> u64 {
        slot % self.slots_per_epoch
    }

    /// Elect leader for a slot
    pub async fn elect_leader(
        &self,
        slot: u64,
        previous_vrf: &Hash,
    ) -> Result<Option<PublicKey>, VrfError> {
        self.vrf_selector.select_proposer(slot, previous_vrf).await
    }

    /// Verify leader eligibility
    pub async fn verify_leader(
        &self,
        pubkey: &PublicKey,
        proof: &VrfProof,
        slot: u64,
        previous_vrf: &Hash,
    ) -> Result<bool, VrfError> {
        // Verify VRF proof
        if !self
            .vrf_selector
            .verify_vrf_math_only(pubkey, proof, previous_vrf, slot)?
        {
            return Ok(false);
        }

        // Check eligibility
        self.vrf_selector
            .is_eligible_proposer(pubkey, &proof.output, slot)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validator_registration() {
        let selector = VrfProposerSelector::new();

        let validator = Validator {
            pubkey: PublicKey::new([1; 32]),
            stake: 1000,
            is_active: true,
        };

        selector.register_validator(validator).await;

        assert_eq!(selector.active_validator_count().await, 1);
        assert_eq!(selector.total_stake().await, 1000);
    }

    #[tokio::test]
    async fn test_vrf_proof_generation() {
        let selector = VrfProposerSelector::new();
        let secret_key = [42; 32];
        let proposer = PublicKey::new([1; 32]);
        let previous_vrf = Hash::new([1; 32]);
        let slot = 100;

        let proof = selector
            .generate_vrf_proof(&secret_key, &proposer, &previous_vrf, slot)
            .unwrap();

        // WP-S.2: ECVRF proofs are 114 bytes (pk_p256=33 + Gamma=33 + c=16 + s=32)
        assert_eq!(proof.proof.len(), 114);
        assert_ne!(proof.output, Hash::default());

        // Verify the proof roundtrips
        let verified = selector
            .verify_vrf_math_only(&proposer, &proof, &previous_vrf, slot)
            .unwrap();
        assert!(verified, "ECVRF proof should verify against the proposer");
    }

    #[tokio::test]
    async fn test_proposer_selection() {
        let selector = Arc::new(VrfProposerSelector::new());

        // Register multiple validators
        for i in 0..5 {
            let validator = Validator {
                pubkey: PublicKey::new([i as u8; 32]),
                stake: 1000 * (i as u128 + 1),
                is_active: true,
            };
            selector.register_validator(validator).await;
        }

        let previous_vrf = Hash::new([0; 32]);
        let proposer = selector.select_proposer(1, &previous_vrf).await.unwrap();

        assert!(proposer.is_some());
    }

    #[tokio::test]
    async fn test_leader_election() {
        let vrf_selector = Arc::new(VrfProposerSelector::new());
        let leader_election = LeaderElection::new(vrf_selector.clone(), 100);

        // Register validators
        for i in 0..3 {
            let validator = Validator {
                pubkey: PublicKey::new([i as u8; 32]),
                stake: 1000,
                is_active: true,
            };
            vrf_selector.register_validator(validator).await;
        }

        let previous_vrf = Hash::new([0; 32]);
        let leader = leader_election
            .elect_leader(50, &previous_vrf)
            .await
            .unwrap();

        assert!(leader.is_some());
        assert_eq!(leader_election.get_epoch(50), 0);
        assert_eq!(leader_election.get_slot_in_epoch(50), 50);
    }

    // ────────────────────────────────────────────────────────────────
    // RM-I-3 / WP-I1.5 — REM-N-01 ECVRF identity binding tests.
    //
    // The structurally-bound verifier
    // `verify_vrf_with_block_signature` combines the ECVRF math
    // with an ed25519 signature check. The ECVRF math alone accepts
    // a forged proof under an attacker's pk_p256; combined with
    // the ed25519 check it does not, because only the holder of the
    // claimed proposer's ed25519 secret key can produce the
    // signature.
    // ────────────────────────────────────────────────────────────────

    fn ed25519_sign_payload(
        signing_key: &ed25519_dalek::SigningKey,
        payload: &[u8],
    ) -> crate::types::Signature {
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(payload);
        crate::types::Signature::new(sig.to_bytes())
    }

    #[tokio::test]
    async fn test_rem_n_01_combined_check_accepts_legitimate_proposer() {
        // Honest validator: derives ed25519 pubkey from a known
        // signing key, signs the block payload with it, and produces
        // an ECVRF proof from the same secret_key (treated as the
        // ECVRF seed).
        let secret = [0xAB; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();
        let proposer = PublicKey::new(pubkey_bytes);
        let prev = Hash::new([0; 32]);
        let slot = 100;

        let selector = VrfProposerSelector::new();
        let proof = selector
            .generate_vrf_proof(&secret, &proposer, &prev, slot)
            .expect("vrf");
        let block_payload = b"block-payload-bytes";
        let block_sig = ed25519_sign_payload(&signing_key, block_payload);

        let r = selector
            .verify_vrf_with_block_signature(
                &proposer,
                &proof,
                &prev,
                slot,
                block_payload,
                &block_sig,
            )
            .expect("verify");
        assert!(
            r,
            "REM-N-01: legitimate proposer + signature must verify"
        );
    }

    #[tokio::test]
    async fn test_rem_n_01_combined_check_rejects_substituted_pk_p256() {
        // Attacker scenario: the attacker has their own (sk, pk).
        // They produce an ECVRF proof signed under their sk over
        // alpha = (victim_ed25519 || prev || slot). The ECVRF math
        // accepts because proof.pk_p256 = attacker's pk and the
        // math is consistent. But the attacker cannot produce a
        // valid ed25519 signature under the victim's identity, so
        // the combined check rejects.
        let victim_secret = [0xAB; 32];
        let victim_signing_key = ed25519_dalek::SigningKey::from_bytes(&victim_secret);
        let victim_pubkey = PublicKey::new(victim_signing_key.verifying_key().to_bytes());

        let attacker_secret = [0xCD; 32];
        let attacker_signing_key = ed25519_dalek::SigningKey::from_bytes(&attacker_secret);

        let prev = Hash::new([0; 32]);
        let slot = 100;

        let selector = VrfProposerSelector::new();
        // Attacker produces an ECVRF proof under attacker's secret
        // but claims the victim's ed25519 pubkey is the proposer.
        // Note: generate_vrf_proof uses `pubkey.as_bytes()` to build
        // alpha, so the alpha will reference the victim's identity.
        let attacker_proof = selector
            .generate_vrf_proof(&attacker_secret, &victim_pubkey, &prev, slot)
            .expect("vrf");

        // Sanity: the raw verify accepts (the math is consistent).
        let raw = selector
            .verify_vrf_math_only(&victim_pubkey, &attacker_proof, &prev, slot)
            .expect("raw verify");
        assert!(
            raw,
            "REM-N-01: raw verify_vrf_math_only accepts the attacker's proof — \
             this is the bug shape"
        );

        // The structurally-bound verifier MUST reject because
        // the attacker cannot sign a block payload under the
        // victim's ed25519 identity.
        let block_payload = b"block-payload-bytes";
        let attacker_sig = ed25519_sign_payload(&attacker_signing_key, block_payload);
        let r = selector
            .verify_vrf_with_block_signature(
                &victim_pubkey,
                &attacker_proof,
                &prev,
                slot,
                block_payload,
                &attacker_sig,
            )
            .expect("verify");
        assert!(
            !r,
            "REM-N-01: attacker's pk_p256 substitution + attacker's ed25519 \
             signature MUST be rejected — the bound check requires the signature \
             to verify under the claimed proposer's pubkey"
        );
    }

    #[tokio::test]
    async fn test_rem_n_01_combined_check_rejects_missing_block_signature() {
        // A block whose signature is bytes of zeros (or any wrong
        // signature) cannot pass the ed25519 check, regardless of
        // ECVRF math validity.
        let secret = [0xAB; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let proposer = PublicKey::new(signing_key.verifying_key().to_bytes());
        let prev = Hash::new([0; 32]);
        let slot = 100;

        let selector = VrfProposerSelector::new();
        let proof = selector
            .generate_vrf_proof(&secret, &proposer, &prev, slot)
            .expect("vrf");
        let block_payload = b"block-payload-bytes";
        let bogus_sig = crate::types::Signature::new([0u8; 64]);

        let r = selector
            .verify_vrf_with_block_signature(
                &proposer,
                &proof,
                &prev,
                slot,
                block_payload,
                &bogus_sig,
            )
            .expect("verify");
        assert!(
            !r,
            "REM-N-01: a block payload not actually signed by the proposer \
             must fail the bound check"
        );
    }
}
