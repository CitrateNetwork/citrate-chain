//! AEAD wrapper around AES-256-GCM with mandatory AAD parameter.
//!
//! See crate-level docs (`lib.rs`) for design rationale.

use aes_gcm::aead::{Aead as AeadTrait, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use thiserror::Error;

/// Errors produced by the AEAD wrapper.
///
/// Tag verification failures and key-init failures are intentionally
/// flattened into a single `Failed` variant so a caller cannot
/// distinguish "wrong AAD" from "wrong key" from "tampered ciphertext"
/// from a timing observation. See `aes-gcm` documentation for why this
/// is the recommended API shape.
#[derive(Debug, Error)]
pub enum AeadError {
    /// Encrypt or decrypt failed. The underlying `aes-gcm` library does
    /// not surface a more specific reason on `decrypt` (intentionally,
    /// to avoid timing oracles); this wrapper preserves that posture.
    #[error("AEAD operation failed (wrong key, wrong AAD, or tampered ciphertext)")]
    Failed,

    /// Key length was wrong (must be exactly 32 bytes for AES-256-GCM).
    #[error("AEAD key length invalid: expected 32 bytes")]
    InvalidKeyLength,
}

/// AES-256-GCM AEAD handle with a mandatory-AAD seal/open API.
///
/// Constructed once from a 32-byte key; thread-safe via `Sync`.
/// Internally wraps `aes_gcm::Aes256Gcm`. The handle is intentionally
/// `Clone` (for callers that fan out to multiple workers) but does NOT
/// implement `Debug` to avoid accidentally printing key material in
/// log lines.
#[derive(Clone)]
pub struct Aead {
    inner: Aes256Gcm,
}

impl Aead {
    /// Construct an AEAD handle from a 32-byte key.
    ///
    /// The key is read by reference; callers are expected to hold it
    /// in `zeroize::Zeroizing<[u8; 32]>` (or equivalent) so the bytes
    /// erase when the local goes out of scope. The cipher copies the
    /// key into its own state, so the caller's buffer can drop
    /// immediately after this returns.
    pub fn new(key: &[u8; 32]) -> Result<Self, AeadError> {
        let inner = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength)?;
        Ok(Self { inner })
    }

    /// Seal a plaintext under AAD.
    ///
    /// Returns `ciphertext || tag` (the standard AES-GCM output shape;
    /// the tag is the last 16 bytes). The same `aad` MUST be supplied
    /// to [`Aead::open`] to recover the plaintext.
    pub fn seal(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = Nonce::from_slice(nonce);
        self.inner
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| AeadError::Failed)
    }

    /// Open a ciphertext sealed by [`Aead::seal`].
    ///
    /// Returns `Err(AeadError::Failed)` on any of:
    ///   - tampered ciphertext
    ///   - tampered nonce
    ///   - wrong key
    ///   - wrong AAD (substitution attacks fail here)
    ///
    /// The error variant intentionally does not distinguish among
    /// these to avoid timing-side-channel disclosure.
    pub fn open(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        let nonce = Nonce::from_slice(nonce);
        self.inner
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| AeadError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key_42() -> [u8; 32] {
        [0x42; 32]
    }

    fn nonce_11() -> [u8; 12] {
        [0x11; 12]
    }

    // =========================================================================
    // CORE: round-trip under matching AAD succeeds.
    // =========================================================================

    #[test]
    fn seal_open_roundtrip_succeeds() {
        let key = key_42();
        let aead = Aead::new(&key).expect("aead init");
        let nonce = nonce_11();
        let plaintext = b"Citrate sensitive data";
        let aad = b"context:test";

        let ciphertext = aead.seal(&nonce, plaintext, aad).expect("seal");
        let recovered = aead.open(&nonce, &ciphertext, aad).expect("open");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn seal_with_empty_aad_is_allowed() {
        let aead = Aead::new(&key_42()).expect("init");
        let nonce = nonce_11();
        let ct = aead.seal(&nonce, b"plain", b"").expect("empty AAD seal");
        let pt = aead.open(&nonce, &ct, b"").expect("empty AAD open");
        assert_eq!(pt, b"plain");
    }

    // =========================================================================
    // SUBSTITUTION: AAD mismatch on open MUST fail.
    // This is the property WAL-02 / GUI-L-01 was missing.
    // =========================================================================

    #[test]
    fn open_with_wrong_aad_fails() {
        let aead = Aead::new(&key_42()).expect("init");
        let nonce = nonce_11();
        let ciphertext = aead.seal(&nonce, b"data", b"context-a").expect("seal");
        let result = aead.open(&nonce, &ciphertext, b"context-b");
        assert!(matches!(result, Err(AeadError::Failed)));
    }

    #[test]
    fn open_with_empty_aad_against_nonempty_seal_fails() {
        let aead = Aead::new(&key_42()).expect("init");
        let nonce = nonce_11();
        let ciphertext = aead.seal(&nonce, b"data", b"context").expect("seal");
        let result = aead.open(&nonce, &ciphertext, b"");
        assert!(matches!(result, Err(AeadError::Failed)));
    }

    // =========================================================================
    // CIPHERTEXT TAMPER + NONCE TAMPER + KEY MISMATCH all fail.
    // =========================================================================

    #[test]
    fn open_with_tampered_ciphertext_fails() {
        let aead = Aead::new(&key_42()).expect("init");
        let nonce = nonce_11();
        let mut ct = aead.seal(&nonce, b"data", b"aad").expect("seal");
        ct[0] ^= 0x01;
        let result = aead.open(&nonce, &ct, b"aad");
        assert!(matches!(result, Err(AeadError::Failed)));
    }

    #[test]
    fn open_with_tampered_nonce_fails() {
        let aead = Aead::new(&key_42()).expect("init");
        let mut nonce = nonce_11();
        let ct = aead.seal(&nonce, b"data", b"aad").expect("seal");
        nonce[0] ^= 0x01;
        let result = aead.open(&nonce, &ct, b"aad");
        assert!(matches!(result, Err(AeadError::Failed)));
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let aead_a = Aead::new(&key_42()).expect("init a");
        let mut wrong_key = key_42();
        wrong_key[0] ^= 0xFF;
        let aead_b = Aead::new(&wrong_key).expect("init b");
        let nonce = nonce_11();
        let ct = aead_a.seal(&nonce, b"data", b"aad").expect("seal");
        let result = aead_b.open(&nonce, &ct, b"aad");
        assert!(matches!(result, Err(AeadError::Failed)));
    }

    // =========================================================================
    // PROPERTY: round-trip across arbitrary (plaintext, aad) pairs.
    // =========================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            ..ProptestConfig::default()
        })]

        #[test]
        fn prop_seal_open_round_trip(
            plaintext in proptest::collection::vec(any::<u8>(), 0..512),
            aad in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let aead = Aead::new(&key_42()).expect("init");
            let nonce = nonce_11();
            let ct = aead.seal(&nonce, &plaintext, &aad).expect("seal");
            let pt = aead.open(&nonce, &ct, &aad).expect("open");
            prop_assert_eq!(pt, plaintext);
        }

        /// Property: any single-byte AAD perturbation MUST fail open.
        /// This is the core substitution-attack defense.
        #[test]
        fn prop_aad_perturbation_fails_open(
            plaintext in proptest::collection::vec(any::<u8>(), 1..256),
            mut aad in proptest::collection::vec(any::<u8>(), 1..64),
            flip_idx in 0usize..64,
        ) {
            let aead = Aead::new(&key_42()).expect("init");
            let nonce = nonce_11();
            let ct = aead.seal(&nonce, &plaintext, &aad).expect("seal");

            // Perturb one byte of the AAD at a position within the slice.
            let i = flip_idx % aad.len();
            aad[i] ^= 0xFF;

            let result = aead.open(&nonce, &ct, &aad);
            prop_assert!(matches!(result, Err(AeadError::Failed)));
        }
    }

    // =========================================================================
    // KEY-LENGTH GUARD: the new() constructor accepts only 32-byte keys.
    // (Compile-time enforced by &[u8; 32] type, but the wrapper still
    //  returns Err if construction-via-slice fails internally.)
    // =========================================================================

    #[test]
    fn aead_clone_preserves_round_trip() {
        let aead = Aead::new(&key_42()).expect("init");
        let cloned = aead.clone();
        let nonce = nonce_11();
        let ct = aead.seal(&nonce, b"x", b"aad").expect("seal");
        let pt = cloned.open(&nonce, &ct, b"aad").expect("open via clone");
        assert_eq!(pt, b"x");
    }
}
