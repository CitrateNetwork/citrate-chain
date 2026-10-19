//! Producer onboarding: the proposer-key half of a `ValidatorRegistry`
//! registration, built on the operator's own host.
//!
//! `registerValidator(bytes32 proposerPubkey, bytes ed25519Sig)` needs two
//! signatures from two different keys:
//!
//! 1. the node's ed25519 **proposer key** (`proposer.key` in the data dir)
//!    signs the EIP-712-style `Register` digest, proving control of the
//!    consensus identity being registered. That is what this module does.
//! 2. the operator's secp256k1 **staker key** signs the transaction itself
//!    (`msg.sender` = staker, `msg.value` = stake). This module never sees it:
//!    the operator signs the printed unsigned transaction with their own wallet.
//!
//! `citrate registration-proof` reads `proposer.key` **read-only**. It never
//! mints a key (a missing file is an error: the node mints its identity on its
//! first start with a coinbase set), never prints the seed, and refuses a key
//! file other users can read. Data source for the digest:
//! `citrate_consensus::crypto::registration_digest`, the same bytes the
//! contract rebuilds in `ValidatorRegistry.registerValidator` (cross-checked by
//! `contracts/test/ValidatorRegistryDigest.t.sol` and the `crypto.rs` tests).

use std::path::Path;

use anyhow::{anyhow, bail, Context};
use citrate_consensus::crypto::{registration_digest, sign_registration, Ed25519SigningKey};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// `registerValidator(bytes32,bytes)` — verified == 0x10f53ba1.
pub fn register_validator_selector() -> [u8; 4] {
    let h = Keccak256::digest(b"registerValidator(bytes32,bytes)");
    let mut out = [0u8; 4];
    for (dst, src) in out.iter_mut().zip(h.iter()) {
        *dst = *src;
    }
    out
}

/// Everything public an operator needs to submit a registration. The proposer
/// seed is not in here and is never printed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RegistrationProof {
    pub chain_id: u64,
    pub registry: String,
    pub staker: String,
    pub registration_nonce: u64,
    pub proposer_pubkey: String,
    pub register_digest: String,
    pub ed25519_signature: String,
    pub calldata: String,
}

/// Parse a 20-byte address written as hex, with or without `0x`.
pub fn parse_address(s: &str) -> anyhow::Result<[u8; 20]> {
    let t = s.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    let bytes = hex::decode(t).with_context(|| format!("address {s:?} is not hex"))?;
    let out: [u8; 20] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("address {s:?} is {} bytes, expected 20", bytes.len()))?;
    if out.iter().all(|b| *b == 0) {
        bail!("address {s:?} is the zero address");
    }
    Ok(out)
}

/// Load the node's ed25519 proposer key from `path` without modifying it.
///
/// Refuses (instead of repairing, unlike the node's own loader) when the file
/// is missing, is not exactly 32 bytes, or is readable by group or others.
pub fn read_proposer_key(path: &Path) -> anyhow::Result<Ed25519SigningKey> {
    if !path.exists() {
        bail!(
            "{} does not exist. The node mints its proposer identity on its first start with \
             [mining] coinbase set (mining may stay disabled). Start the node once on THIS host; \
             never copy a proposer.key from another host",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{} has mode {:o}; it must be 0600 (owner-only). Run `chmod 600` on it first",
                path.display(),
                mode
            );
        }
    }
    let seed_bytes =
        Zeroizing::new(std::fs::read(path).with_context(|| format!("read {}", path.display()))?);
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(seed_bytes.as_slice().try_into().map_err(|_| {
            anyhow!(
                "{} is {} bytes, expected a 32-byte ed25519 seed",
                path.display(),
                seed_bytes.len()
            )
        })?);
    Ok(citrate_consensus::crypto::block_signing_key_from_seed(
        &seed,
    ))
}

/// ABI-encode `registerValidator(bytes32 proposerPubkey, bytes ed25519Sig)`:
/// selector ‖ pubkey ‖ offset 0x40 ‖ length 64 ‖ sig (two whole words, no padding).
pub fn encode_register_validator(proposer_pubkey: &[u8; 32], sig: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 * 3 + 64);
    out.extend_from_slice(&register_validator_selector());
    out.extend_from_slice(proposer_pubkey);
    out.extend_from_slice(&word_u64(0x40));
    out.extend_from_slice(&word_u64(64));
    out.extend_from_slice(sig);
    out
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    for (dst, src) in w.iter_mut().skip(24).zip(v.to_be_bytes().iter()) {
        *dst = *src;
    }
    w
}

/// Sign the `Register` digest with `key` and build the calldata. The signature
/// is checked with `verify_strict` (what the 0x0120 precompile runs) before it
/// is returned, so a proof that the contract would reject is never printed.
pub fn build(
    chain_id: u64,
    registry: &[u8; 20],
    staker: &[u8; 20],
    registration_nonce: u64,
    key: &Ed25519SigningKey,
) -> anyhow::Result<RegistrationProof> {
    let pubkey: [u8; 32] = key.verifying_key().to_bytes();
    let digest = registration_digest(chain_id, registry, staker, &pubkey, registration_nonce);
    let sig = sign_registration(chain_id, registry, staker, &pubkey, registration_nonce, key);
    let dalek_sig = ed25519_dalek::Signature::from_bytes(sig.as_bytes());
    key.verifying_key()
        .verify_strict(&digest, &dalek_sig)
        .map_err(|e| anyhow!("self-check of the registration signature failed: {e}"))?;
    let calldata = encode_register_validator(&pubkey, sig.as_bytes());
    Ok(RegistrationProof {
        chain_id,
        registry: format!("0x{}", hex::encode(registry)),
        staker: format!("0x{}", hex::encode(staker)),
        registration_nonce,
        proposer_pubkey: format!("0x{}", hex::encode(pubkey)),
        register_digest: format!("0x{}", hex::encode(digest)),
        ed25519_signature: format!("0x{}", hex::encode(sig.as_bytes())),
        calldata: format!("0x{}", hex::encode(calldata)),
    })
}

/// The 32-byte proposer pubkey for `key`, as 0x-hex (what `ValidatorRegistry`
/// stores and what blocks carry as `proposerPubkey`).
pub fn pubkey_hex(key: &Ed25519SigningKey) -> String {
    format!("0x{}", hex::encode(key.verifying_key().to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_key(dir: &Path, bytes: &[u8], mode: u32) -> std::path::PathBuf {
        let p = dir.join("proposer.key");
        std::fs::write(&p, bytes).expect("write test key");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
        p
    }

    const REGISTRY: [u8; 20] = [0x11; 20];
    const STAKER: [u8; 20] = [0x22; 20];

    #[test]
    fn selector_is_register_validator() {
        assert_eq!(register_validator_selector(), [0x10, 0xf5, 0x3b, 0xa1]);
    }

    #[test]
    fn calldata_layout_matches_abi() {
        let pk = [0xAB; 32];
        let sig = [0xCD; 64];
        let data = encode_register_validator(&pk, &sig);
        assert_eq!(data.len(), 4 + 32 * 3 + 64);
        assert_eq!(data.get(..4), Some(&[0x10, 0xf5, 0x3b, 0xa1][..]));
        assert_eq!(data.get(4..36), Some(&pk[..]));
        assert_eq!(data.get(36..68), Some(&word_u64(0x40)[..]));
        assert_eq!(data.get(68..100), Some(&word_u64(64)[..]));
        assert_eq!(data.get(100..164), Some(&sig[..]));
    }

    #[test]
    fn proof_signature_verifies_against_registry_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_key(dir.path(), &[7u8; 32], 0o600);
        let key = read_proposer_key(&p).expect("load key");
        let proof = build(40204, &REGISTRY, &STAKER, 3, &key).expect("build");

        let pubkey = key.verifying_key().to_bytes();
        let digest = registration_digest(40204, &REGISTRY, &STAKER, &pubkey, 3);
        assert_eq!(proof.register_digest, format!("0x{}", hex::encode(digest)));
        assert_eq!(proof.proposer_pubkey, pubkey_hex(&key));

        let sig_bytes =
            hex::decode(proof.ed25519_signature.trim_start_matches("0x")).expect("sig hex");
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("64 bytes");
        key.verifying_key()
            .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&sig_arr))
            .expect("signature verifies under verify_strict");

        let expected = encode_register_validator(&pubkey, &sig_arr);
        assert_eq!(proof.calldata, format!("0x{}", hex::encode(expected)));
        assert_eq!(proof.staker, format!("0x{}", hex::encode(STAKER)));
        assert_eq!(proof.registration_nonce, 3);
    }

    #[test]
    fn nonce_and_chain_are_bound_into_the_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_key(dir.path(), &[9u8; 32], 0o600);
        let key = read_proposer_key(&p).expect("load key");
        let a = build(40204, &REGISTRY, &STAKER, 0, &key).expect("a");
        let b = build(40204, &REGISTRY, &STAKER, 1, &key).expect("b");
        let c = build(1337, &REGISTRY, &STAKER, 0, &key).expect("c");
        assert_ne!(a.ed25519_signature, b.ed25519_signature);
        assert_ne!(a.ed25519_signature, c.ed25519_signature);
        assert_eq!(a.proposer_pubkey, b.proposer_pubkey);
    }

    #[test]
    fn same_key_as_the_node_loader() {
        let seed = [5u8; 32];
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_key(dir.path(), &seed, 0o600);
        let key = read_proposer_key(&p).expect("load key");
        let node_key = citrate_consensus::crypto::block_signing_key_from_seed(&seed);
        assert_eq!(
            key.verifying_key().to_bytes(),
            node_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn missing_key_is_an_error_and_nothing_is_minted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("proposer.key");
        let err = read_proposer_key(&p).expect_err("missing key must fail");
        assert!(err.to_string().contains("does not exist"));
        assert!(!p.exists(), "registration-proof must never mint a key");
    }

    #[test]
    fn wrong_length_key_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_key(dir.path(), &[1u8; 31], 0o600);
        let err = read_proposer_key(&p).expect_err("31 bytes must fail");
        assert!(err.to_string().contains("expected a 32-byte"));
    }

    #[test]
    fn readable_by_others_is_refused_and_left_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_key(dir.path(), &[1u8; 32], 0o644);
        let err = read_proposer_key(&p).expect_err("0644 must fail");
        assert!(err.to_string().contains("0600"));
        let mode = std::fs::metadata(&p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the tool must not modify the key file");
    }

    #[test]
    fn proof_never_contains_the_seed() {
        let seed = [0x5Au8; 32];
        let dir = tempfile::tempdir().expect("tempdir");
        let p = write_key(dir.path(), &seed, 0o600);
        let key = read_proposer_key(&p).expect("load key");
        let proof = build(40204, &REGISTRY, &STAKER, 0, &key).expect("build");
        let json = serde_json::to_string(&proof).expect("json");
        assert!(!json.contains(&hex::encode(seed)));
    }

    #[test]
    fn address_parsing() {
        assert_eq!(
            parse_address("0x1111111111111111111111111111111111111111").expect("ok"),
            REGISTRY
        );
        assert_eq!(
            parse_address("2222222222222222222222222222222222222222").expect("ok"),
            STAKER
        );
        assert!(parse_address("0x00").is_err());
        assert!(parse_address("0x0000000000000000000000000000000000000000").is_err());
        assert!(parse_address("0xzz11111111111111111111111111111111111111").is_err());
    }
}
