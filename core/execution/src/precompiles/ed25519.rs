// citrate/core/execution/src/precompiles/ed25519.rs
//
// Ed25519 Signature-Verification Precompile for EVM
// Address 0x0120 — first entry in the crypto sub-page (0x0120–0x012F).
//
// Verifies an Ed25519 (RFC 8032) signature over an arbitrary message.
// This complements the secp256k1 ECRECOVER path (0x0001) and the x402
// EIP-712 verifiers (0x0200) by giving contract code access to the
// signature scheme used by the consensus layer (block/tx signing in
// `core/consensus/src/crypto.rs`) and by most off-chain agent identities.
//
// Consensus-critical (@rule8): the verification result is folded into
// EVM state, so it MUST be byte-for-byte deterministic across every node
// build. `ed25519_dalek::verify_strict` (SUF-CMA: rejects non-canonical S
// and small-order R) plus an explicit `is_weak()` rejection of
// small-order / torsion public keys (C-3 fix) give the strict, single-
// valued acceptance predicate a precompile requires. Never panics on any
// input; malformed input returns the "false" word with `success: true`,
// mirroring ECRECOVER / the x402 verifiers.

use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, VerifyingKey};

use super::PrecompileResult;

/// 0x0120: Ed25519 Signature Verification.
///
/// Canonical WP-B0 address layout: byte 18 = 0x01 (Citrate family),
/// byte 19 = 0x20 (crypto sub-page selector). Reachable from Solidity as
/// `address(0x0120)`.
pub const ED25519_VERIFY: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x20];

/// Flat gas cost for an Ed25519 verification.
///
/// Charged unconditionally once the gas check passes (like ECRECOVER's
/// flat 3000). Ed25519 verification hashes the whole message (SHA-512,
/// O(len)); a flat charge is only safe if the message length is bounded,
/// so `execute` rejects messages longer than `MAX_MESSAGE_LEN` as invalid
/// before doing any hashing. 2000 conservatively covers the fixed
/// point-decompression / scalar-mult cost plus SHA-512 over a message up
/// to the cap, keeping the precompile deterministic and DoS-resistant.
pub const ED25519_VERIFY_GAS: u64 = 2_000;

/// Maximum message length accepted (bytes). Bounds the O(len) SHA-512
/// hashing cost so the flat `ED25519_VERIFY_GAS` charge can never be
/// undercharged. A longer message is treated as invalid input (returns
/// the "false" word) rather than erroring, so callers cannot use it to
/// force a revert. 8 KiB comfortably covers realistic signed payloads.
pub const MAX_MESSAGE_LEN: usize = 8 * 1024;

/// Minimum input length: pubkey(32) + sig(64), with a zero-length message.
const MIN_INPUT_LEN: usize = 96;

/// 32-byte big-endian word: all zero except the low byte, which is 1.
fn true_word() -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[31] = 1;
    out
}

/// 32-byte all-zero word (the "false" / invalid result).
fn false_word() -> Vec<u8> {
    vec![0u8; 32]
}

/// Precompile 0x0120: Ed25519 Signature Verification.
///
/// Input format:
///   pubkey (32 bytes) || signature (64 bytes) || message (remaining bytes)
///
/// Output (32 bytes, big-endian):
///   0x0…01 if the signature is valid under the given public key and
///   message, 0x0…00 otherwise.
///
/// Validity requires ALL of:
///   - input is at least 96 bytes (else invalid),
///   - message length ≤ `MAX_MESSAGE_LEN` (else invalid),
///   - pubkey decompresses to a valid Edwards point (`from_bytes` ok),
///   - pubkey is NOT small-order / torsion (`!is_weak()`, C-3 fix),
///   - `verify_strict(message, sig)` succeeds (canonical S, non-weak R).
///
/// Gas: flat `ED25519_VERIFY_GAS` (2,000). Returns `Err` ONLY when
/// `gas_limit` is below that cost (mirrors ECRECOVER / x402). Every other
/// path — including all malformed input — returns
/// `Ok(PrecompileResult { success: true, .. })` with the false word.
/// Never panics on any input.
pub fn execute(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    if gas_limit < ED25519_VERIFY_GAS {
        return Err(anyhow!("Insufficient gas for Ed25519 verify"));
    }

    let ok = verify(input);

    Ok(PrecompileResult {
        output: if ok { true_word() } else { false_word() },
        gas_used: ED25519_VERIFY_GAS,
        success: true,
    })
}

/// Pure verification predicate. Returns `true` iff the signature is valid;
/// `false` for any malformed input or failed check. Never panics.
fn verify(input: &[u8]) -> bool {
    if input.len() < MIN_INPUT_LEN {
        return false;
    }

    let message = &input[96..];
    // Bound the O(len) hashing cost covered by the flat gas charge.
    if message.len() > MAX_MESSAGE_LEN {
        return false;
    }

    // pubkey(32) — infallible slice, fixed length.
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&input[0..32]);

    // sig(64) — infallible slice, fixed length.
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&input[32..96]);

    // Parse the verifying key; reject non-decompressable encodings.
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // C-3 fix: reject small-order / low-order-component (torsion) public
    // keys. `verify_strict` already rejects small-order R, but a weak
    // public key can make a signature verify under keys the signer never
    // controlled; rejecting weak keys closes that class outright.
    if verifying_key.is_weak() {
        return false;
    }

    // Signature parsing is infallible in ed25519-dalek 2.x (structural
    // validation of S/R happens inside verify_strict).
    let signature = Signature::from_bytes(&sig_bytes);

    // Strict verification: rejects non-canonical S and small-order R;
    // gives the single-valued (SUF-CMA) acceptance predicate consensus
    // needs. No cofactored / batch shortcuts.
    verifying_key.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a well-formed precompile input from raw parts.
    fn build_input(pubkey: &[u8; 32], sig: &[u8; 64], message: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(96 + message.len());
        input.extend_from_slice(pubkey);
        input.extend_from_slice(sig);
        input.extend_from_slice(message);
        input
    }

    /// Deterministic keypair + signature over `message`.
    fn sign(seed: u8, message: &[u8]) -> ([u8; 32], [u8; 64]) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let signature = signing_key.sign(message);
        let verifying_key = signing_key.verifying_key();
        (verifying_key.to_bytes(), signature.to_bytes())
    }

    #[test]
    fn address_layout_is_canonical() {
        // Crypto sub-page: byte 18 = 0x01, byte 19 = 0x20; rest zero.
        assert!(ED25519_VERIFY[..18].iter().all(|&b| b == 0));
        assert_eq!(ED25519_VERIFY[18], 0x01);
        assert_eq!(ED25519_VERIFY[19], 0x20);
    }

    #[test]
    fn valid_signature_returns_true_word() {
        let message = b"citrate ed25519 precompile known-vector test";
        let (pubkey, sig) = sign(0x42, message);
        let input = build_input(&pubkey, &sig, message);

        let result = execute(&input, 10_000).expect("should not error");
        assert!(result.success);
        assert_eq!(result.gas_used, ED25519_VERIFY_GAS);
        assert_eq!(result.output, true_word());
        // The true word is exactly 0x0…01.
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 1);
        assert!(result.output[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn empty_message_valid_signature_returns_true_word() {
        // Boundary: exactly MIN_INPUT_LEN bytes (zero-length message).
        let message: &[u8] = b"";
        let (pubkey, sig) = sign(0x07, message);
        let input = build_input(&pubkey, &sig, message);
        assert_eq!(input.len(), MIN_INPUT_LEN);

        let result = execute(&input, 10_000).expect("should not error");
        assert!(result.success);
        assert_eq!(result.output, true_word());
    }

    #[test]
    fn tampered_signature_returns_false_word() {
        let message = b"the quick brown fox";
        let (pubkey, mut sig) = sign(0x11, message);
        // Flip a bit in S (last byte) — still parses, fails verify_strict.
        sig[63] ^= 0x01;
        let input = build_input(&pubkey, &sig, message);

        let result = execute(&input, 10_000).expect("should not error");
        assert!(result.success);
        assert_eq!(result.output, false_word());
    }

    #[test]
    fn tampered_message_returns_false_word() {
        let message = b"transfer 100 to alice";
        let (pubkey, sig) = sign(0x22, message);
        let mut tampered = message.to_vec();
        tampered[0] ^= 0xFF; // "Uransfer ..." — signature no longer matches
        let input = build_input(&pubkey, &sig, &tampered);

        let result = execute(&input, 10_000).expect("should not error");
        assert!(result.success);
        assert_eq!(result.output, false_word());
    }

    #[test]
    fn wrong_pubkey_returns_false_word() {
        let message = b"authorize withdrawal";
        let (_signer_pubkey, sig) = sign(0x33, message);
        // A different, valid, non-weak key that did not produce the sig.
        let other = SigningKey::from_bytes(&[0x99; 32]);
        let other_pubkey = other.verifying_key().to_bytes();
        let input = build_input(&other_pubkey, &sig, message);

        let result = execute(&input, 10_000).expect("should not error");
        assert!(result.success);
        assert_eq!(result.output, false_word());
    }

    #[test]
    fn short_input_returns_false_word_no_panic() {
        // Below the 96-byte minimum in various sizes — must not panic.
        for len in [0usize, 1, 31, 32, 63, 64, 95] {
            let input = vec![0u8; len];
            let result = execute(&input, 10_000).expect("should not error");
            assert!(result.success);
            assert_eq!(result.output, false_word(), "len {len}");
        }
    }

    #[test]
    fn wrong_length_pubkey_all_zero_returns_false_word() {
        // A 32-byte all-zero pubkey is small-order (weak) and must be
        // rejected even when the rest of the input is structurally sized.
        let input = vec![0u8; 96];
        let result = execute(&input, 10_000).expect("should not error");
        assert!(result.success);
        assert_eq!(result.output, false_word());
    }

    #[test]
    fn oversized_message_returns_false_word() {
        // Message just past the cap → invalid (bounds hashing cost),
        // but still success:true with the false word (never a revert).
        let (pubkey, sig) = sign(0x44, &vec![0u8; MAX_MESSAGE_LEN + 1]);
        let input = build_input(&pubkey, &sig, &vec![0u8; MAX_MESSAGE_LEN + 1]);
        let result = execute(&input, 10_000).expect("should not error");
        assert!(result.success);
        assert_eq!(result.output, false_word());
    }

    #[test]
    fn max_length_message_is_accepted() {
        // Exactly at the cap → still verified normally.
        let message = vec![0xABu8; MAX_MESSAGE_LEN];
        let (pubkey, sig) = sign(0x55, &message);
        let input = build_input(&pubkey, &sig, &message);
        let result = execute(&input, 10_000).expect("should not error");
        assert!(result.success);
        assert_eq!(result.output, true_word());
    }

    #[test]
    fn insufficient_gas_errors() {
        let (pubkey, sig) = sign(0x66, b"x");
        let input = build_input(&pubkey, &sig, b"x");
        // One below the flat cost must error (mirrors ECRECOVER / x402).
        assert!(execute(&input, ED25519_VERIFY_GAS - 1).is_err());
        assert!(execute(&input, ED25519_VERIFY_GAS).is_ok());
    }
}
