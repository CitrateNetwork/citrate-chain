// citrate/core/consensus/src/crypto.rs

use crate::types::{Block, Hash, PublicKey, Signature, Transaction};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

// Re-export SigningKey so callers (e.g., node crate) don't need a direct ed25519-dalek dependency.
pub use ed25519_dalek::SigningKey as Ed25519SigningKey;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Determine if a transaction uses ECDSA (Ethereum) or ed25519 (native) signatures
fn is_ecdsa_transaction(tx: &Transaction) -> bool {
    let from_bytes = tx.from.as_bytes();

    // ECDSA transactions have a 20-byte Ethereum address embedded in the first 20 bytes
    // with the remaining 12 bytes as zeros
    let is_evm_address = from_bytes[20..].iter().all(|&b| b == 0)
        && !from_bytes[..20].iter().all(|&b| b == 0);

    is_evm_address
}

/// Verify a transaction's signature.
/// Supports both ECDSA (Ethereum) and ed25519 (native) signatures.
///
/// SECURITY: ECDSA transactions must have `ecdsa_verified == true`, which is
/// set only during successful cryptographic recovery in eth_tx_decoder.rs.
/// We never trust address shape alone — that was a bypass vulnerability (C-01).
pub fn verify_transaction(tx: &Transaction) -> Result<bool, CryptoError> {
    if is_ecdsa_transaction(tx) {
        // ECDSA-shaped address: require that the decoder already performed
        // cryptographic signature verification and set the flag.
        // This prevents forged transactions with embedded addresses from
        // bypassing signature checks (fixes audit finding C-01).
        if tx.ecdsa_verified {
            Ok(true)
        } else {
            Ok(false)
        }
    } else {
        // ed25519 native transaction verification (V2 or V1 preimage).
        verify_ed25519_transaction(tx, true)
    }
}

/// Verify an ed25519 native transaction signature.
///
/// Accepts the V2 preimage ([`canonical_tx_bytes_v2`], which binds
/// `chain_id` and every fee/type field under a domain tag) and, when
/// `accept_v1`, the V1 preimage ([`canonical_tx_bytes`]).
fn verify_ed25519_transaction(tx: &Transaction, accept_v1: bool) -> Result<bool, CryptoError> {
    // Convert our types to ed25519-dalek types
    let public_key =
        VerifyingKey::from_bytes(tx.from.as_bytes()).map_err(|_| CryptoError::InvalidPublicKey)?;

    let signature = DalekSignature::from_bytes(tx.signature.as_bytes());

    // Block rule from the activation height (`accept_v1 = false`): the V2
    // digest only, verified strictly, the same predicate as the 0x0120
    // precompile. `verify` is cofactorless and accepts small-order public
    // keys, so a signature for such a key can verify without its secret key;
    // `is_weak` refuses those keys and `verify_strict` also refuses a
    // small-order R. Honest signatures pass both.
    if !accept_v1 {
        return Ok(!public_key.is_weak()
            && public_key
                .verify_strict(&canonical_tx_bytes_v2(tx), &signature)
                .is_ok());
    }

    // Legacy rule (below the activation height): unchanged.
    if public_key
        .verify(&canonical_tx_bytes_v2(tx), &signature)
        .is_ok()
    {
        return Ok(true);
    }
    // Legacy V1 canonical bytes (no chain_id).
    let message = canonical_tx_bytes(tx)?;
    match public_key.verify(&message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// ed25519 verification of a native transaction over its canonical signing
/// bytes. Unlike [`verify_transaction`] it never consults `ecdsa_verified`.
/// Used by `tx_auth` (PBA-R2).
pub(crate) fn verify_ed25519_signature(tx: &Transaction) -> Result<bool, CryptoError> {
    // V2 or legacy V1 preimage, same policy as `verify_transaction`.
    verify_ed25519_transaction(tx, true)
}

/// The exact bytes a native ed25519 transaction signature covers.
pub fn canonical_signing_bytes(tx: &Transaction) -> Vec<u8> {
    // `canonical_tx_bytes` cannot fail (it only appends); keep one encoder.
    canonical_tx_bytes(tx).unwrap_or_default()
}

/// [`verify_transaction`] with an explicit native-signature policy:
/// `accept_v1 = false` accepts only V2 native signatures.
pub fn verify_transaction_with_policy(
    tx: &Transaction,
    accept_v1: bool,
) -> Result<bool, CryptoError> {
    if is_ecdsa_transaction(tx) {
        return verify_transaction(tx);
    }
    verify_ed25519_transaction(tx, accept_v1)
}

/// Sign with the V2 native preimage (binds `chain_id`, fee caps,
/// tx type and access list under a domain tag). `tx.chain_id` must be set.
pub fn sign_transaction_v2(
    tx: &mut Transaction,
    signing_key: &SigningKey,
) -> Result<(), CryptoError> {
    if tx.chain_id.is_none() {
        return Err(CryptoError::SerializationError(
            "V2 native signing requires chain_id".to_string(),
        ));
    }
    tx.from = PublicKey::new(signing_key.verifying_key().to_bytes());
    let signature: DalekSignature = signing_key.sign(&canonical_tx_bytes_v2(tx));
    tx.signature = Signature::new(signature.to_bytes());
    Ok(())
}

/// Domain tag for the V2 native transaction preimage.
pub const NATIVE_TX_V2_DOMAIN: &[u8] = b"CITRATE-NATIVE-TX-V2\0";

/// V2 canonical bytes for native (ed25519) transactions. The V2 preimage
/// binds `chain_id`, `eth_tx_type`, the fee caps and `access_list` in
/// addition to the V1 fields: every field except `hash`, `signature` and the
/// node-local `ecdsa_verified` / `tx_type` (derived from `data`), under a
/// domain tag, with length/presence prefixes so no two field layouts share
/// an encoding.
pub fn canonical_tx_bytes_v2(tx: &Transaction) -> Vec<u8> {
    fn opt_u64(out: &mut Vec<u8>, v: Option<u64>) {
        match v {
            Some(x) => {
                out.push(1);
                out.extend_from_slice(&x.to_le_bytes());
            }
            None => out.push(0),
        }
    }
    let mut data = Vec::with_capacity(160 + tx.data.len());
    data.extend_from_slice(NATIVE_TX_V2_DOMAIN);
    opt_u64(&mut data, tx.chain_id);
    data.extend_from_slice(&tx.nonce.to_le_bytes());
    data.extend_from_slice(tx.from.as_bytes());
    match &tx.to {
        Some(to) => {
            data.push(1);
            data.extend_from_slice(to.as_bytes());
        }
        None => data.push(0),
    }
    data.extend_from_slice(&tx.value.to_le_bytes());
    data.extend_from_slice(&tx.gas_limit.to_le_bytes());
    data.extend_from_slice(&tx.gas_price.to_le_bytes());
    opt_u64(&mut data, tx.max_fee_per_gas);
    opt_u64(&mut data, tx.max_priority_fee_per_gas);
    data.push(tx.eth_tx_type);
    match &tx.access_list {
        Some(list) => {
            data.push(1);
            data.extend_from_slice(&(list.len() as u64).to_le_bytes());
            for (addr, keys) in list {
                data.extend_from_slice(&(addr.len() as u64).to_le_bytes());
                data.extend_from_slice(addr);
                data.extend_from_slice(&(keys.len() as u64).to_le_bytes());
                for k in keys {
                    data.extend_from_slice(&(k.len() as u64).to_le_bytes());
                    data.extend_from_slice(k);
                }
            }
        }
        None => data.push(0),
    }
    data.extend_from_slice(&(tx.data.len() as u64).to_le_bytes());
    data.extend_from_slice(&tx.data);
    data
}

/// Sign a transaction (for testing and dev tools)
pub fn sign_transaction(tx: &mut Transaction, signing_key: &SigningKey) -> Result<(), CryptoError> {
    // Ensure `from` matches the signing key before computing canonical bytes
    tx.from = PublicKey::new(signing_key.verifying_key().to_bytes());

    // Get canonical bytes to sign (now includes correct `from`)
    let message = canonical_tx_bytes(tx)?;

    // Sign the message
    let signature: DalekSignature = signing_key.sign(&message);

    // Update signature in transaction
    tx.signature = Signature::new(signature.to_bytes());

    Ok(())
}

/// Get canonical bytes for transaction signing/verification
/// This excludes the signature field and uses a deterministic encoding
fn canonical_tx_bytes(tx: &Transaction) -> Result<Vec<u8>, CryptoError> {
    let mut data = Vec::new();

    // Fixed-size fields first (exclude tx.hash to avoid circular dependency)
    data.extend_from_slice(&tx.nonce.to_le_bytes());
    data.extend_from_slice(tx.from.as_bytes());

    // Optional to field
    if let Some(to) = &tx.to {
        data.push(1); // Present flag
        data.extend_from_slice(to.as_bytes());
    } else {
        data.push(0); // Absent flag
    }

    // Value and gas fields
    data.extend_from_slice(&tx.value.to_le_bytes());
    data.extend_from_slice(&tx.gas_limit.to_le_bytes());
    data.extend_from_slice(&tx.gas_price.to_le_bytes());

    // Variable-length data field
    data.extend_from_slice(&(tx.data.len() as u32).to_le_bytes());
    data.extend_from_slice(&tx.data);

    Ok(data)
}

/// Generate a new keypair for testing
pub fn generate_keypair() -> SigningKey {
    SigningKey::from_bytes(&rand::random())
}

/// Mint a fresh, random ed25519 block-signing (proposer) key.
///
/// # Why this replaced a derivation (WP-11 — CRITICAL)
///
/// Until 2026-07-27 this key was DERIVED as
/// `Sha3_256(b"citrate-block-signing-key-v1" ‖ coinbase32)`. Every input to that
/// was public — the domain was a compile-time constant, and the coinbase is
/// recoverable on-chain from `ValidatorRegistry.validatorInfo(pubkey).staker`
/// (consensus *enforces* `coinbase == staker`, so they are always equal).
///
/// That made every validator's block-signing PRIVATE key computable by anyone in
/// milliseconds. Verified against live chain 40204: hashing the public coinbase
/// `0x0ecbcd85…363b` reproduced the registered proposer pubkey
/// `0x25b78e08…8ad9` exactly.
///
/// The reachable exploit was `ValidatorRegistry.submitEquivocation`, which is
/// permissionless and only refuses `msg.sender == staker` (self-report). An
/// attacker could derive any validator's key, sign two `EquivocationVote`
/// digests at one height, and trigger a **Byzantine slash: 100% of bond +
/// escrow + rewards, a 10% bounty to themselves, and a permanent ban of both the
/// pubkey and the staker**. Across the set that destroys every validator and
/// halts the chain.
///
/// The original code comment described the derivation as "for devnet
/// reproducibility" and noted "production nodes should load a persistent key
/// from disk" — that devnet shortcut reached production.
///
/// The property the design actually wanted — *the member's wallet key never
/// touches the node* — is fully preserved, because the proposer key is now its
/// own independent secret rather than a function of the wallet address.
pub fn generate_block_signing_key() -> Ed25519SigningKey {
    use zeroize::Zeroize as _;
    let mut seed: [u8; 32] = rand::random();
    let key = Ed25519SigningKey::from_bytes(&seed);
    seed.zeroize();
    key
}

/// Reconstruct a block-signing key from its persisted 32-byte seed.
///
/// The caller owns the file handling (0600 permissions, zeroization); see
/// `node/src/main.rs::load_or_generate_proposer_key`.
pub fn block_signing_key_from_seed(seed: &[u8; 32]) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(seed)
}

/// Sign a block's canonical hash with an ed25519 signing key.
///
/// The block hash MUST already be computed via `Block::compute_hash()` before calling this.
/// The signature covers the hash, which in turn covers all consensus-critical fields.
pub fn sign_block(block_hash: &Hash, signing_key: &SigningKey) -> Signature {
    let sig: DalekSignature = signing_key.sign(block_hash.as_bytes());
    Signature::new(sig.to_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDATOR-S1 (v5) — ValidatorRegistry proof signing (companion §8).
//
// The on-chain ValidatorRegistry verifies ed25519 signatures over EIP-712-style
// digests using the 0x0120 precompile. For those checks to ever pass, the NODE
// must sign the SAME 32-byte digest the contract reconstructs. These helpers
// replicate `keccak256(abi.encode(TYPEHASH, ...))` byte-for-byte and sign it.
//
//   - Registration proof-of-key-control: registerValidator(pubkey, sig).
//   - Equivocation vote: submitEquivocation verifies each double-sign signature
//     over EquivocationVote(chainId, registry, height, blockHash). A raw block-hash
//     signature (see `sign_block`) CANNOT prove two blocks share a height, so the
//     block proposer must ALSO sign this height-binding vote for the permissionless
//     Byzantine-slash path to function.
//
// Cross-layer byte-equivalence is asserted against the Solidity contract in
// `contracts/test/ValidatorRegistryDigest.t.sol` (fixed vectors) and mirrored in the
// tests below.
// ─────────────────────────────────────────────────────────────────────────────

/// The exact EIP-712 type strings the contract hashes for its TYPEHASH constants.
pub const REGISTER_TYPE: &str =
    "Register(uint256 chainId,address registry,address staker,bytes32 proposerPubkey,uint256 nonce)";
pub const EQUIVOCATION_VOTE_TYPE: &str =
    "EquivocationVote(uint256 chainId,address registry,uint64 height,bytes32 blockHash)";

fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// abi.encode word for an unsigned integer (right-aligned, big-endian 32 bytes).
fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// abi.encode word for a 20-byte address (left-padded to 32 bytes).
fn word_addr(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// Digest for the registration proof: `keccak256(abi.encode(REGISTER_TYPEHASH,
/// chainId, registry, staker, proposerPubkey, nonce))`. `proposer_pubkey` is the
/// 32-byte ed25519 key (the contract's `bytes32 proposerPubkey`).
pub fn registration_digest(
    chain_id: u64,
    registry: &[u8; 20],
    staker: &[u8; 20],
    proposer_pubkey: &[u8; 32],
    nonce: u64,
) -> [u8; 32] {
    let mut enc = Vec::with_capacity(6 * 32);
    enc.extend_from_slice(&keccak256(REGISTER_TYPE.as_bytes()));
    enc.extend_from_slice(&word_u64(chain_id));
    enc.extend_from_slice(&word_addr(registry));
    enc.extend_from_slice(&word_addr(staker));
    enc.extend_from_slice(proposer_pubkey);
    enc.extend_from_slice(&word_u64(nonce));
    keccak256(&enc)
}

/// Sign the registration digest with the ed25519 proposer key. The contract's
/// `_ed25519Verify` message is `abi.encodePacked(digest)` — i.e. the 32-byte digest
/// itself — so we sign exactly those 32 bytes. The signature is canonical and passes
/// the precompile's `verify_strict`.
pub fn sign_registration(
    chain_id: u64,
    registry: &[u8; 20],
    staker: &[u8; 20],
    proposer_pubkey: &[u8; 32],
    nonce: u64,
    signing_key: &SigningKey,
) -> Signature {
    let digest = registration_digest(chain_id, registry, staker, proposer_pubkey, nonce);
    let sig: DalekSignature = signing_key.sign(&digest);
    Signature::new(sig.to_bytes())
}

/// Digest for an equivocation vote: `keccak256(abi.encode(EQUIVOCATION_TYPEHASH,
/// chainId, registry, height, blockHash))`.
pub fn equivocation_vote_digest(
    chain_id: u64,
    registry: &[u8; 20],
    height: u64,
    block_hash: &[u8; 32],
) -> [u8; 32] {
    let mut enc = Vec::with_capacity(5 * 32);
    enc.extend_from_slice(&keccak256(EQUIVOCATION_VOTE_TYPE.as_bytes()));
    enc.extend_from_slice(&word_u64(chain_id));
    enc.extend_from_slice(&word_addr(registry));
    enc.extend_from_slice(&word_u64(height));
    enc.extend_from_slice(block_hash);
    keccak256(&enc)
}

/// Sign the height-binding equivocation vote. The block proposer signs this ALONGSIDE
/// `sign_block` so a double-sign at one height yields two contract-verifiable votes
/// (submitEquivocation checks both). Signs the 32-byte digest; canonical → verify_strict.
pub fn sign_equivocation_vote(
    chain_id: u64,
    registry: &[u8; 20],
    height: u64,
    block_hash: &[u8; 32],
    signing_key: &SigningKey,
) -> Signature {
    let digest = equivocation_vote_digest(chain_id, registry, height, block_hash);
    let sig: DalekSignature = signing_key.sign(&digest);
    Signature::new(sig.to_bytes())
}

/// Verify a block's signature against its `proposer_pubkey`.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if the signature doesn't match.
/// Returns `Err` only for malformed keys.
///
/// VALIDATOR-S1 note: this uses the permissive `verify` (RFC-8032), consistent across
/// the fleet. The on-chain 0x0120 precompile uses `verify_strict`; a canonical dalek
/// signature (which the node always produces) satisfies both, so the registry proofs
/// signed above verify on-chain.
pub fn verify_block_signature(block: &Block) -> Result<bool, CryptoError> {
    let pubkey = VerifyingKey::from_bytes(block.header.proposer_pubkey.as_bytes())
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = DalekSignature::from_bytes(block.signature.as_bytes());
    match pubkey.verify(block.header.block_hash.as_bytes(), &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Hash;

    fn pba_native_tx() -> Transaction {
        Transaction {
            hash: Hash::new([1; 32]),
            nonce: 7,
            from: PublicKey::new([0; 32]),
            to: Some(PublicKey::new([2; 32])),
            value: 1_000,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            data: vec![1, 2, 3],
            chain_id: Some(40204),
            max_fee_per_gas: Some(3_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            eth_tx_type: 0,
            access_list: Some(vec![(vec![0xAA; 20], vec![vec![0xBB; 32]])]),
            ..Default::default()
        }
    }

    /// The V2 preimage binds every non-signature field: changing any of them
    /// invalidates the signature.
    #[test]
    fn pba_l4_002_v2_signature_binds_every_field() {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let mut tx = pba_native_tx();
        sign_transaction_v2(&mut tx, &key).expect("sign v2");
        assert!(verify_transaction(&tx).expect("verify"), "V2 signature verifies");
        assert!(verify_transaction_with_policy(&tx, false).expect("verify"), "V2 passes strict policy");

        type Mutation = fn(&mut Transaction);
        let mutations: [(&str, Mutation); 13] = [
            ("chain_id", |t| t.chain_id = Some(1337)),
            ("chain_id none", |t| t.chain_id = None),
            ("nonce", |t| t.nonce += 1),
            ("to", |t| t.to = Some(PublicKey::new([3; 32]))),
            ("to none", |t| t.to = None),
            ("value", |t| t.value += 1),
            ("gas_limit", |t| t.gas_limit += 1),
            ("gas_price", |t| t.gas_price += 1),
            ("max_fee", |t| t.max_fee_per_gas = Some(9)),
            ("max_prio", |t| t.max_priority_fee_per_gas = None),
            ("eth_tx_type", |t| t.eth_tx_type = 2),
            ("access_list", |t| t.access_list = None),
            ("data", |t| t.data.push(0)),
        ];
        for (name, m) in mutations {
            let mut changed = tx.clone();
            m(&mut changed);
            assert!(
                !verify_transaction(&changed).expect("verify"),
                "V2 signature must not survive rewriting `{name}`"
            );
        }
    }

    /// The signature policy switch: V1 signatures verify under the default
    /// policy and not under the V2-only policy.
    #[test]
    fn native_signature_policy_switch() {
        let key = SigningKey::from_bytes(&[0x43; 32]);
        let mut tx = pba_native_tx();
        tx.chain_id = Some(1337);
        sign_transaction(&mut tx, &key).expect("sign v1");
        assert!(
            verify_transaction_with_policy(&tx, true).expect("verify"),
            "default policy accepts V1"
        );
        assert!(
            !verify_transaction_with_policy(&tx, false).expect("verify"),
            "V2-only policy rejects V1"
        );
    }

    /// V2 signing requires a chain id.
    #[test]
    fn pba_l4_002_v2_requires_chain_id() {
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let mut tx = pba_native_tx();
        tx.chain_id = None;
        assert!(sign_transaction_v2(&mut tx, &key).is_err());
    }

    #[test]
    fn test_transaction_signing_and_verification() {
        // Generate a keypair
        let signing_key = generate_keypair();

        // Create a transaction
        let mut tx = Transaction {
            hash: Hash::new([1; 32]),
            nonce: 1,
            from: PublicKey::new([0; 32]), // Will be updated by sign
            to: Some(PublicKey::new([2; 32])),
            value: 1000,
            gas_limit: 21000,
            gas_price: 1_000_000_000,
            data: vec![1, 2, 3],
            signature: Signature::new([0; 64]), // Will be updated by sign
            tx_type: None,
            ..Default::default()
        };

        // Sign it
        sign_transaction(&mut tx, &signing_key).unwrap();

        // Verify it
        assert!(verify_transaction(&tx).unwrap());

        // Tamper with it
        tx.value = 2000;

        // Should fail verification
        assert!(!verify_transaction(&tx).unwrap());
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let tx = Transaction {
            hash: Hash::new([1; 32]),
            nonce: 42,
            from: PublicKey::new([3; 32]),
            to: Some(PublicKey::new([4; 32])),
            value: 1000,
            gas_limit: 21000,
            gas_price: 1_000_000_000,
            data: vec![5, 6, 7],
            signature: Signature::new([8; 64]),
            tx_type: None,
            ..Default::default()
        };

        // Should produce same bytes every time
        let bytes1 = canonical_tx_bytes(&tx).unwrap();
        let bytes2 = canonical_tx_bytes(&tx).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    /// C-01 regression: embedded 20-byte EVM address without ecdsa_verified must be rejected
    #[test]
    fn test_forged_embedded_address_rejected() {
        // Create a transaction with an embedded EVM address (20 bytes + 12 zeros)
        // but WITHOUT ecdsa_verified set — simulates a forged sender
        let mut from_bytes = [0u8; 32];
        from_bytes[..20].copy_from_slice(&[0xAA; 20]); // Fake EVM address

        let tx = Transaction {
            hash: Hash::new([1; 32]),
            nonce: 0,
            from: PublicKey::new(from_bytes),
            to: Some(PublicKey::new([2; 32])),
            value: 1000,
            gas_limit: 21000,
            gas_price: 1_000_000_000,
            data: vec![],
            signature: Signature::new([1; 64]), // Dummy signature
            tx_type: None,
            ecdsa_verified: false, // NOT cryptographically verified
            ..Default::default()
        };

        // Must be detected as ECDSA-shaped
        assert!(is_ecdsa_transaction(&tx));
        // Must FAIL verification — no cryptographic proof
        assert!(!verify_transaction(&tx).unwrap());
    }

    // ─────────────────────────────────────────────────────────────────────
    // VALIDATOR-S1 (v5) — registry digest cross-layer equivalence + strict-verify.
    //
    // The expected digests are produced by the Solidity contract for identical
    // fixed vectors in contracts/test/ValidatorRegistryDigest.t.sol. If either
    // side changes the abi.encode layout or a type string, these break — which is
    // exactly the cross-layer drift we want to catch.
    // ─────────────────────────────────────────────────────────────────────

    const V_CHAIN_ID: u64 = 40204;
    const V_REGISTRY: [u8; 20] = [0x11; 20];
    const V_STAKER: [u8; 20] = [0x22; 20];
    const V_NONCE: u64 = 7;
    const V_HEIGHT: u64 = 12345;

    fn vector_pubkey() -> [u8; 32] {
        // bytes32(uint256(0xABCDEF))
        let mut pk = [0u8; 32];
        pk[29] = 0xAB;
        pk[30] = 0xCD;
        pk[31] = 0xEF;
        pk
    }

    fn vector_block_hash() -> [u8; 32] {
        // bytes32(uint256(0x99))
        let mut bh = [0u8; 32];
        bh[31] = 0x99;
        bh
    }

    #[test]
    fn test_registration_digest_matches_solidity() {
        let d = registration_digest(V_CHAIN_ID, &V_REGISTRY, &V_STAKER, &vector_pubkey(), V_NONCE);
        assert_eq!(
            hex::encode(d),
            "43e3b0efc79703bd0e9327f6c6e6fcd080b6b69bf6096b2add28ed273afdd953",
            "registration digest must match the Solidity contract byte-for-byte"
        );
    }

    #[test]
    fn test_equivocation_digest_matches_solidity() {
        let d = equivocation_vote_digest(V_CHAIN_ID, &V_REGISTRY, V_HEIGHT, &vector_block_hash());
        assert_eq!(
            hex::encode(d),
            "4a9847b204a23b943979a06ced71cc9ba1d86895a0c7b1d81a6bd969b7285727",
            "equivocation vote digest must match the Solidity contract byte-for-byte"
        );
    }

    #[test]
    fn test_signed_vote_passes_verify_strict() {
        // The node's signature over the digest must satisfy the on-chain precompile,
        // which uses ed25519_dalek::verify_strict (canonical S + non-small-order R).
        let signing_key = generate_keypair();
        let vk = signing_key.verifying_key();
        let digest = equivocation_vote_digest(V_CHAIN_ID, &V_REGISTRY, V_HEIGHT, &vector_block_hash());
        let sig = sign_equivocation_vote(
            V_CHAIN_ID,
            &V_REGISTRY,
            V_HEIGHT,
            &vector_block_hash(),
            &signing_key,
        );
        let dalek_sig = DalekSignature::from_bytes(sig.as_bytes());
        // strict verify over the exact 32-byte digest (what the precompile receives as message)
        assert!(vk.verify_strict(&digest, &dalek_sig).is_ok());
        // wrong message must fail
        let mut other = digest;
        other[0] ^= 0x01;
        assert!(vk.verify_strict(&other, &dalek_sig).is_err());
    }

    #[test]
    fn test_registration_signature_roundtrip_strict() {
        let signing_key = generate_keypair();
        let vk = signing_key.verifying_key();
        let pk = vk.to_bytes();
        let digest = registration_digest(V_CHAIN_ID, &V_REGISTRY, &V_STAKER, &pk, V_NONCE);
        let sig = sign_registration(V_CHAIN_ID, &V_REGISTRY, &V_STAKER, &pk, V_NONCE, &signing_key);
        let dalek_sig = DalekSignature::from_bytes(sig.as_bytes());
        assert!(vk.verify_strict(&digest, &dalek_sig).is_ok());
    }

    /// Verify that ecdsa_verified=true allows ECDSA-shaped tx through
    #[test]
    fn test_verified_ecdsa_transaction_accepted() {
        let mut from_bytes = [0u8; 32];
        from_bytes[..20].copy_from_slice(&[0xBB; 20]);

        let tx = Transaction {
            hash: Hash::new([1; 32]),
            nonce: 0,
            from: PublicKey::new(from_bytes),
            to: Some(PublicKey::new([2; 32])),
            value: 1000,
            gas_limit: 21000,
            gas_price: 1_000_000_000,
            data: vec![],
            signature: Signature::new([1; 64]),
            tx_type: None,
            ecdsa_verified: true, // Decoder cryptographically verified this
            ..Default::default()
        };

        assert!(is_ecdsa_transaction(&tx));
        assert!(verify_transaction(&tx).unwrap());
    }
}
