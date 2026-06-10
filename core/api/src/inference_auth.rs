//! SECREM-01 INFER-1: authenticated caller identity for inference RPCs.
//!
//! The pre-audit finding: `citrate_runInference` / `citrate_requestInference`
//! accepted a caller-supplied `"from"` address and the executor gated
//! Private / Restricted / PayPerUse model access purely on that claim — so
//! anyone could read the owner from public `citrate_getAIStatus` and spoof
//! `"from": "<owner>"` for free access to private model IP. A claim without
//! the signature that covers it is anonymous input.
//!
//! The rule after this module:
//! - **No signature → anonymous** (`Address([0;20])`): only Public models
//!   are reachable (the executor independently refuses anonymous callers
//!   for every non-Public policy — defense in depth).
//! - **Signature present → it must verify**: secp256k1 recovery over the
//!   domain-separated message below must yield exactly the claimed `from`,
//!   and the signed timestamp must be fresh. A present-but-invalid
//!   signature is an error, never a silent downgrade to anonymous.
//!
//! Signed message (all fields big-endian):
//! `keccak256("CITRATE_INFERENCE_AUTH_V1" || chain_id_u64 || model_id_32 ||
//! keccak256(input) || timestamp_u64)`
//!
//! Signature wire format: 65 hex bytes `r(32) || s(32) || v(1)`, low-s
//! enforced (EIP-2) by `recover_address`.

use citrate_execution::precompiles::recover_address;
use citrate_execution::types::Address;
use sha3::{Digest, Keccak256};

/// Domain separator — versioned so a future message-format change cannot
/// be replayed against old verifiers.
const DOMAIN: &[u8] = b"CITRATE_INFERENCE_AUTH_V1";

/// Maximum clock skew accepted between the signed timestamp and node time.
pub const MAX_TIMESTAMP_SKEW_SECS: u64 = 300;

#[derive(Debug, PartialEq, Eq)]
pub enum InferenceAuthError {
    /// `signature` present but not 65 hex bytes.
    MalformedSignature,
    /// `signature` present but `timestamp` missing/invalid.
    MissingTimestamp,
    /// Signed timestamp outside the freshness window.
    StaleTimestamp,
    /// Recovery failed or recovered address != claimed `from`.
    SignatureMismatch,
    /// `signature` present but `from` missing — nothing to bind it to.
    MissingFrom,
}

impl std::fmt::Display for InferenceAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedSignature => write!(f, "signature must be 65 hex bytes (r||s||v)"),
            Self::MissingTimestamp => write!(f, "signed requests require a 'timestamp' (unix seconds)"),
            Self::StaleTimestamp => write!(
                f,
                "timestamp outside the ±{MAX_TIMESTAMP_SKEW_SECS}s freshness window"
            ),
            Self::SignatureMismatch => write!(f, "signature does not verify for the claimed 'from'"),
            Self::MissingFrom => write!(f, "signed requests require 'from'"),
        }
    }
}

/// The message hash a caller signs to authenticate an inference request.
pub fn auth_message_hash(
    chain_id: u64,
    model_id: &[u8; 32],
    input: &[u8],
    timestamp: u64,
) -> [u8; 32] {
    let input_hash = Keccak256::digest(input);
    let mut h = Keccak256::new();
    h.update(DOMAIN);
    h.update(chain_id.to_be_bytes());
    h.update(model_id);
    h.update(input_hash);
    h.update(timestamp.to_be_bytes());
    h.finalize().into()
}

/// Resolve the authenticated identity for an inference request.
///
/// `claimed_from` / `signature_hex` / `timestamp` are the request fields
/// (each optional on the wire). `now_secs` is injected for testability.
///
/// Returns the authenticated address, or `Address([0;20])` (anonymous)
/// when no signature was supplied. Fail-closed: any supplied-but-invalid
/// credential is an error, never anonymous.
pub fn resolve_identity(
    chain_id: u64,
    model_id: &[u8; 32],
    input: &[u8],
    claimed_from: Option<Address>,
    signature_hex: Option<&str>,
    timestamp: Option<u64>,
    now_secs: u64,
) -> Result<Address, InferenceAuthError> {
    let Some(sig_hex) = signature_hex else {
        // Unsigned request: anonymous. The executor only serves Public
        // models to the zero address.
        return Ok(Address([0u8; 20]));
    };

    let from = claimed_from.ok_or(InferenceAuthError::MissingFrom)?;
    let ts = timestamp.ok_or(InferenceAuthError::MissingTimestamp)?;

    if now_secs.abs_diff(ts) > MAX_TIMESTAMP_SKEW_SECS {
        return Err(InferenceAuthError::StaleTimestamp);
    }

    let sig_bytes = hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|_| InferenceAuthError::MalformedSignature)?;
    if sig_bytes.len() != 65 {
        return Err(InferenceAuthError::MalformedSignature);
    }
    let r = &sig_bytes[0..32];
    let s = &sig_bytes[32..64];
    // Accept both raw recovery ids {0,1} and Ethereum-style {27,28}.
    let v = match sig_bytes[64] {
        v @ 0..=1 => v,
        v @ 27..=28 => v - 27,
        _ => return Err(InferenceAuthError::MalformedSignature),
    };

    let msg = auth_message_hash(chain_id, model_id, input, ts);
    let recovered =
        recover_address(&msg, r, s, v).ok_or(InferenceAuthError::SignatureMismatch)?;

    if recovered != from.0 {
        return Err(InferenceAuthError::SignatureMismatch);
    }
    Ok(from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{Signature, SigningKey};

    const CHAIN_ID: u64 = 40204;
    const NOW: u64 = 1_780_000_000;

    fn test_key() -> (SigningKey, Address) {
        let sk = SigningKey::from_bytes((&[7u8; 32]).into()).expect("key");
        let vk = sk.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let digest = Keccak256::digest(&pubkey.as_bytes()[1..65]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&digest[12..32]);
        (sk, Address(addr))
    }

    fn sign(sk: &SigningKey, msg: &[u8; 32]) -> String {
        let (sig, recid): (Signature, _) =
            sk.sign_prehash_recoverable(msg).expect("sign");
        // Normalize to low-s (recover_address rejects high-s per EIP-2).
        let (sig, recid) = if let Some(normalized) = sig.normalize_s() {
            // Flipping s flips the recovery id parity.
            let flipped = k256::ecdsa::RecoveryId::from_byte(recid.to_byte() ^ 1)
                .expect("recid");
            (normalized, flipped)
        } else {
            (sig, recid)
        };
        let mut out = sig.to_bytes().to_vec();
        out.push(recid.to_byte());
        hex::encode(out)
    }

    #[test]
    fn unsigned_request_is_anonymous() {
        let got = resolve_identity(CHAIN_ID, &[9u8; 32], b"in", None, None, None, NOW)
            .expect("anonymous ok");
        assert_eq!(got, Address([0u8; 20]));
        // Even a claimed `from` without a signature stays anonymous —
        // the INFER-1 spoof itself.
        let spoof = resolve_identity(
            CHAIN_ID,
            &[9u8; 32],
            b"in",
            Some(Address([0xAB; 20])),
            None,
            None,
            NOW,
        )
        .expect("ok");
        assert_eq!(
            spoof,
            Address([0u8; 20]),
            "INFER-1 regression: bare 'from' claim must NOT authenticate"
        );
    }

    #[test]
    fn valid_signature_authenticates_from() {
        let (sk, addr) = test_key();
        let model = [9u8; 32];
        let msg = auth_message_hash(CHAIN_ID, &model, b"input", NOW);
        let sig = sign(&sk, &msg);
        let got = resolve_identity(
            CHAIN_ID,
            &model,
            b"input",
            Some(addr),
            Some(&sig),
            Some(NOW),
            NOW,
        )
        .expect("verify");
        assert_eq!(got, addr);
    }

    #[test]
    fn signature_by_other_key_rejected() {
        let (sk, _addr) = test_key();
        let victim = Address([0xEE; 20]);
        let model = [9u8; 32];
        let msg = auth_message_hash(CHAIN_ID, &model, b"input", NOW);
        let sig = sign(&sk, &msg);
        let err = resolve_identity(
            CHAIN_ID,
            &model,
            b"input",
            Some(victim),
            Some(&sig),
            Some(NOW),
            NOW,
        )
        .expect_err("must reject");
        assert_eq!(err, InferenceAuthError::SignatureMismatch);
    }

    #[test]
    fn signature_binds_model_and_input_and_chain() {
        let (sk, addr) = test_key();
        let model = [9u8; 32];
        let msg = auth_message_hash(CHAIN_ID, &model, b"input", NOW);
        let sig = sign(&sk, &msg);

        // Different model.
        assert!(resolve_identity(
            CHAIN_ID, &[8u8; 32], b"input", Some(addr), Some(&sig), Some(NOW), NOW
        )
        .is_err());
        // Different input.
        assert!(resolve_identity(
            CHAIN_ID, &model, b"other", Some(addr), Some(&sig), Some(NOW), NOW
        )
        .is_err());
        // Different chain (cross-deployment replay).
        assert!(
            resolve_identity(1, &model, b"input", Some(addr), Some(&sig), Some(NOW), NOW)
                .is_err()
        );
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (sk, addr) = test_key();
        let model = [9u8; 32];
        let old = NOW - MAX_TIMESTAMP_SKEW_SECS - 1;
        let msg = auth_message_hash(CHAIN_ID, &model, b"input", old);
        let sig = sign(&sk, &msg);
        let err = resolve_identity(
            CHAIN_ID,
            &model,
            b"input",
            Some(addr),
            Some(&sig),
            Some(old),
            NOW,
        )
        .expect_err("stale");
        assert_eq!(err, InferenceAuthError::StaleTimestamp);
    }

    #[test]
    fn malformed_signature_is_error_not_anonymous() {
        // Fail closed: a bad credential must never silently downgrade.
        let err = resolve_identity(
            CHAIN_ID,
            &[9u8; 32],
            b"input",
            Some(Address([0xAB; 20])),
            Some("0xdeadbeef"),
            Some(NOW),
            NOW,
        )
        .expect_err("malformed");
        assert_eq!(err, InferenceAuthError::MalformedSignature);
    }
}
