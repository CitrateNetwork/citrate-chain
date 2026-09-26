// citrate/core/consensus/src/tx_auth.rs
//
// PBA-R2 — one place that answers "is this transaction really signed by its
// sender, and what is its id?", from the transaction's CONTENTS alone.
//
// Before this module the answer depended on where a transaction came from:
//
//   * RPC raw-RLP ingress recovered the ECDSA signer and set `ecdsa_verified`;
//     `crypto::verify_transaction` then trusted that flag.
//   * The mempool's P2P fallback (`verify_eth_ecdsa`) rebuilt only the legacy
//     EIP-155 payload, so typed (EIP-2930/1559) transactions never verified
//     (PBA-L1b-007), and it encoded value 0 as `0x00` instead of `0x80`.
//   * Block import verified nothing at all (PBA-L1b-001): `ecdsa_verified`
//     arrived as a deserialized wire field.
//   * `tx.hash` was whatever the sender (or a relaying peer) wrote, and both
//     mempool dedup and `tx_root` keyed on it (PBA-L1a-006 / PBA-L1b-002).
//
// [`authenticate`] rebuilds the exact signed payload from the transaction's
// fields, recovers / verifies the signature itself, checks that every field
// the executor acts on is covered by that signature, and returns the
// canonical transaction id. It never reads `ecdsa_verified` and never trusts
// `tx.hash`.
//
// [`tx_content_commitment`] and [`tx_root_v2`] bind a block body to its
// header by the transactions' full contents (PBA-L1b-002).

use crate::types::{Hash, Transaction, TransactionType};
use sha3::{Digest, Keccak256, Sha3_256};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TxAuthError {
    #[error("empty sender")]
    EmptySender,
    #[error("EVM transaction without a chain id (pre-EIP-155 is not accepted)")]
    MissingChainId,
    #[error("unsupported EIP-2718 transaction type {0}")]
    UnsupportedType(u8),
    #[error("field not covered by the signature is set or inconsistent: {0}")]
    UnsignedField(&'static str),
    #[error("EIP-2 violation: high-s signature")]
    HighS,
    #[error("signature does not verify for the claimed sender")]
    BadSignature,
    #[error("transaction hash {claimed} is not the canonical id {canonical} of its contents")]
    HashMismatch { claimed: Hash, canonical: Hash },
    #[error("transaction chain id {got:?} is not this chain's {expected}")]
    WrongChainId { expected: u64, got: Option<u64> },
}

/// An EVM-shaped sender: a 20-byte address embedded in the first 20 bytes of
/// the 32-byte key, the rest zero. Same predicate as `crypto` and the mempool.
pub fn is_evm_shaped(key: &[u8; 32]) -> bool {
    key[20..].iter().all(|&b| b == 0) && !key[..20].iter().all(|&b| b == 0)
}

/// Authenticate `tx` from its contents and return its canonical id.
///
/// * EVM-shaped sender: rebuild the legacy/EIP-2930/EIP-1559 signing payload,
///   enforce EIP-2 low-s, recover the signer and require it to equal
///   `from[0..20]`. The canonical id is `keccak256` of the canonical signed
///   encoding (identical to `keccak256(raw)` for any canonically-encoded raw
///   transaction, i.e. the hash every Ethereum client reports).
/// * Otherwise: ed25519 over `crypto::canonical_tx_bytes`. The canonical id
///   is a domain-separated `keccak256` over every consensus field.
///
/// The claimed `tx.hash` is NOT checked here; see [`authenticate_with_hash`].
pub fn authenticate(tx: &Transaction) -> Result<Hash, TxAuthError> {
    let from = tx.from.as_bytes();
    if from.iter().all(|&b| b == 0) {
        return Err(TxAuthError::EmptySender);
    }
    if is_evm_shaped(from) {
        authenticate_evm(tx)
    } else {
        authenticate_native(tx)
    }
}

/// [`authenticate`], then require `tx.hash` to be the canonical id.
/// This is the block-import rule (PBA-L1b-001 + PBA-L1a-006 import half).
pub fn authenticate_with_hash(tx: &Transaction) -> Result<Hash, TxAuthError> {
    let canonical = authenticate(tx)?;
    if canonical != tx.hash {
        return Err(TxAuthError::HashMismatch {
            claimed: tx.hash,
            canonical,
        });
    }
    Ok(canonical)
}

/// The block-import rule for one transaction (PBA-L1b-001), applied to every
/// transaction of every block at or above the PBA-R2 activation height:
/// authenticated from contents, canonical id as `hash` (PBA-L1a-006), and
/// bound to this chain (a tx signed for another chain id is not replayable
/// here, even though the mempool — which already enforced this — is not on
/// the import path).
pub fn verify_for_block(tx: &Transaction, chain_id: u64) -> Result<Hash, TxAuthError> {
    if tx.chain_id != Some(chain_id) {
        return Err(TxAuthError::WrongChainId {
            expected: chain_id,
            got: tx.chain_id,
        });
    }
    authenticate_with_hash(tx)
}

// ─────────────────────────────────────────────────────────────────────────────
// EVM (secp256k1)
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal big-endian bytes (RLP integer encoding: zero is the empty string).
fn be_trim(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

fn append_u128(s: &mut rlp::RlpStream, v: u128) {
    let be = v.to_be_bytes();
    s.append(&be_trim(&be));
}

fn append_to(s: &mut rlp::RlpStream, tx: &Transaction) -> Result<(), TxAuthError> {
    match &tx.to {
        Some(to) => {
            let b = to.as_bytes();
            // An EVM signature covers only the 20-byte address. Any non-zero
            // tail would be a recipient change the signer never authorized
            // (`address_utils::normalize_address` hashes a non-embedded key to
            // a different account), so it is rejected outright.
            if b[20..].iter().any(|&x| x != 0) {
                return Err(TxAuthError::UnsignedField("to[20..32]"));
            }
            s.append(&&b[..20]);
        }
        None => {
            s.append_empty_data();
        }
    }
    Ok(())
}

fn append_access_list(s: &mut rlp::RlpStream, tx: &Transaction) -> Result<(), TxAuthError> {
    let list: &[(Vec<u8>, Vec<Vec<u8>>)] = tx.access_list.as_deref().unwrap_or(&[]);
    s.begin_list(list.len());
    for (addr, keys) in list {
        if addr.len() != 20 {
            return Err(TxAuthError::UnsignedField("access_list address length"));
        }
        s.begin_list(2);
        s.append(&addr.as_slice());
        s.begin_list(keys.len());
        for k in keys {
            if k.len() != 32 {
                return Err(TxAuthError::UnsignedField("access_list storage key length"));
            }
            s.append(&k.as_slice());
        }
    }
    Ok(())
}

/// The fields an EVM signature does not cover must be consistent with the
/// ones it does, or a relayer could change them freely.
fn check_evm_unsigned_fields(tx: &Transaction) -> Result<(), TxAuthError> {
    if let Some(t) = tx.tx_type {
        if t != TransactionType::from_data(&tx.data) {
            return Err(TxAuthError::UnsignedField("tx_type"));
        }
    }
    match tx.eth_tx_type {
        0 | 1 => {
            if tx.max_fee_per_gas.is_some() || tx.max_priority_fee_per_gas.is_some() {
                return Err(TxAuthError::UnsignedField("EIP-1559 fees on a non-1559 tx"));
            }
            if tx.eth_tx_type == 0 && tx.access_list.is_some() {
                return Err(TxAuthError::UnsignedField("access_list on a legacy tx"));
            }
        }
        2 => {
            // The decoder charges `gas_price = maxFeePerGas`; a different
            // value would let a relayer change what the sender pays.
            if tx.max_fee_per_gas != Some(tx.gas_price) {
                return Err(TxAuthError::UnsignedField("gas_price != maxFeePerGas"));
            }
            if tx.max_priority_fee_per_gas.is_none() {
                return Err(TxAuthError::UnsignedField("missing maxPriorityFeePerGas"));
            }
        }
        other => return Err(TxAuthError::UnsupportedType(other)),
    }
    Ok(())
}

/// The unsigned payload (the RLP list without v/r/s) and the signed-encoding
/// prefix for this tx type. Returns (sighash, chain_id).
fn evm_sighash(tx: &Transaction) -> Result<([u8; 32], u64), TxAuthError> {
    let chain_id = tx.chain_id.ok_or(TxAuthError::MissingChainId)?;
    let mut s = rlp::RlpStream::new();
    match tx.eth_tx_type {
        0 => {
            s.begin_list(9);
            s.append(&tx.nonce);
            s.append(&tx.gas_price);
            s.append(&tx.gas_limit);
            append_to(&mut s, tx)?;
            append_u128(&mut s, tx.value);
            s.append(&tx.data.as_slice());
            s.append(&chain_id);
            s.append(&0u8);
            s.append(&0u8);
        }
        1 => {
            s.begin_list(8);
            s.append(&chain_id);
            s.append(&tx.nonce);
            s.append(&tx.gas_price);
            s.append(&tx.gas_limit);
            append_to(&mut s, tx)?;
            append_u128(&mut s, tx.value);
            s.append(&tx.data.as_slice());
            append_access_list(&mut s, tx)?;
        }
        2 => {
            let prio = tx
                .max_priority_fee_per_gas
                .ok_or(TxAuthError::UnsignedField("missing maxPriorityFeePerGas"))?;
            let max_fee = tx
                .max_fee_per_gas
                .ok_or(TxAuthError::UnsignedField("missing maxFeePerGas"))?;
            s.begin_list(9);
            s.append(&chain_id);
            s.append(&tx.nonce);
            s.append(&prio);
            s.append(&max_fee);
            s.append(&tx.gas_limit);
            append_to(&mut s, tx)?;
            append_u128(&mut s, tx.value);
            s.append(&tx.data.as_slice());
            append_access_list(&mut s, tx)?;
        }
        other => return Err(TxAuthError::UnsupportedType(other)),
    }
    let payload = s.out();
    let mut k = Keccak256::new();
    if tx.eth_tx_type != 0 {
        k.update([tx.eth_tx_type]);
    }
    k.update(&payload);
    Ok((k.finalize().into(), chain_id))
}

/// Canonical signed encoding hash, given the recovery id.
fn evm_signed_hash(tx: &Transaction, chain_id: u64, recid: u8) -> Result<Hash, TxAuthError> {
    let sig = tx.signature.as_bytes();
    let (r, s_val) = (be_trim(&sig[..32]), be_trim(&sig[32..]));
    let mut s = rlp::RlpStream::new();
    match tx.eth_tx_type {
        0 => {
            // EIP-155: v = chain_id * 2 + 35 + recid. chain_id is a u64, so
            // compute in u128 (a chain id near u64::MAX must not overflow).
            let v: u128 = (chain_id as u128) * 2 + 35 + recid as u128;
            s.begin_list(9);
            s.append(&tx.nonce);
            s.append(&tx.gas_price);
            s.append(&tx.gas_limit);
            append_to(&mut s, tx)?;
            append_u128(&mut s, tx.value);
            s.append(&tx.data.as_slice());
            append_u128(&mut s, v);
            s.append(&r);
            s.append(&s_val);
        }
        1 => {
            s.begin_list(11);
            s.append(&chain_id);
            s.append(&tx.nonce);
            s.append(&tx.gas_price);
            s.append(&tx.gas_limit);
            append_to(&mut s, tx)?;
            append_u128(&mut s, tx.value);
            s.append(&tx.data.as_slice());
            append_access_list(&mut s, tx)?;
            s.append(&recid);
            s.append(&r);
            s.append(&s_val);
        }
        2 => {
            let prio = tx
                .max_priority_fee_per_gas
                .ok_or(TxAuthError::UnsignedField("missing maxPriorityFeePerGas"))?;
            let max_fee = tx
                .max_fee_per_gas
                .ok_or(TxAuthError::UnsignedField("missing maxFeePerGas"))?;
            s.begin_list(12);
            s.append(&chain_id);
            s.append(&tx.nonce);
            s.append(&prio);
            s.append(&max_fee);
            s.append(&tx.gas_limit);
            append_to(&mut s, tx)?;
            append_u128(&mut s, tx.value);
            s.append(&tx.data.as_slice());
            append_access_list(&mut s, tx)?;
            s.append(&recid);
            s.append(&r);
            s.append(&s_val);
        }
        other => return Err(TxAuthError::UnsupportedType(other)),
    }
    let out = s.out();
    let mut k = Keccak256::new();
    if tx.eth_tx_type != 0 {
        k.update([tx.eth_tx_type]);
    }
    k.update(&out);
    Ok(Hash::new(k.finalize().into()))
}

/// secp256k1 n/2, big-endian (EIP-2).
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

fn authenticate_evm(tx: &Transaction) -> Result<Hash, TxAuthError> {
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
    use secp256k1::{Message, Secp256k1};

    check_evm_unsigned_fields(tx)?;
    let (sighash, chain_id) = evm_sighash(tx)?;

    let sig = tx.signature.as_bytes();
    if sig[32..] > HALF_N[..] {
        return Err(TxAuthError::HighS);
    }
    let msg = Message::from_slice(&sighash).map_err(|_| TxAuthError::BadSignature)?;
    let secp = Secp256k1::verification_only();
    let from20 = &tx.from.as_bytes()[..20];

    for recid in 0u8..=1 {
        let Ok(rid) = RecoveryId::from_i32(recid as i32) else {
            continue;
        };
        let Ok(rsig) = RecoverableSignature::from_compact(sig, rid) else {
            continue;
        };
        let Ok(pk) = secp.recover_ecdsa(&msg, &rsig) else {
            continue;
        };
        let uncompressed = pk.serialize_uncompressed();
        let addr = Keccak256::digest(&uncompressed[1..]);
        if &addr[12..] == from20 {
            return evm_signed_hash(tx, chain_id, recid);
        }
    }
    Err(TxAuthError::BadSignature)
}

// ─────────────────────────────────────────────────────────────────────────────
// Native (ed25519)
// ─────────────────────────────────────────────────────────────────────────────

const NATIVE_TX_ID_DOMAIN: &[u8] = b"citrate:native-tx-id:v1";

fn authenticate_native(tx: &Transaction) -> Result<Hash, TxAuthError> {
    // Native signatures cover `crypto::canonical_tx_bytes` only. The EVM
    // envelope fields must be absent, so a relayer cannot attach them.
    if tx.eth_tx_type != 0
        || tx.max_fee_per_gas.is_some()
        || tx.max_priority_fee_per_gas.is_some()
        || tx.access_list.is_some()
    {
        return Err(TxAuthError::UnsignedField(
            "EVM envelope fields on a native tx",
        ));
    }
    if let Some(t) = tx.tx_type {
        if t != TransactionType::from_data(&tx.data) {
            return Err(TxAuthError::UnsignedField("tx_type"));
        }
    }
    match crate::crypto::verify_ed25519_signature(tx) {
        Ok(true) => Ok(native_tx_id(tx)),
        _ => Err(TxAuthError::BadSignature),
    }
}

/// Canonical id of a native transaction: keccak256 over a domain tag, the
/// signed bytes, the signature and the chain id. Deterministic from contents;
/// a client-chosen `hash` is replaced by this at ingress.
pub fn native_tx_id(tx: &Transaction) -> Hash {
    let mut k = Keccak256::new();
    k.update(NATIVE_TX_ID_DOMAIN);
    let body = crate::crypto::canonical_signing_bytes(tx);
    k.update((body.len() as u64).to_le_bytes());
    k.update(&body);
    k.update(tx.signature.as_bytes());
    match tx.chain_id {
        Some(c) => {
            k.update([1u8]);
            k.update(c.to_le_bytes());
        }
        None => k.update([0u8]),
    }
    Hash::new(k.finalize().into())
}

// ─────────────────────────────────────────────────────────────────────────────
// Body commitment (PBA-L1b-002)
// ─────────────────────────────────────────────────────────────────────────────

const TX_COMMIT_DOMAIN: &[u8] = b"citrate:tx-commitment:v1";
const TX_ROOT_V2_DOMAIN: &[u8] = b"citrate:tx-root:v2";

fn put_bytes(h: &mut Sha3_256, b: &[u8]) {
    h.update((b.len() as u64).to_le_bytes());
    h.update(b);
}

fn put_opt_u64(h: &mut Sha3_256, v: Option<u64>) {
    match v {
        Some(x) => {
            h.update([1u8]);
            h.update(x.to_le_bytes());
        }
        None => h.update([0u8]),
    }
}

/// A commitment to EVERY consensus field of `tx` (everything except the
/// node-local `ecdsa_verified` flag), with an explicit, length-prefixed,
/// field-by-field encoding. Changing any byte of the body changes it.
///
/// Explicit rather than `bincode::serialize` so that adding a field to
/// `Transaction` cannot silently change (or fail to change) the commitment:
/// a new consensus field must be added here deliberately, and
/// `commitment_covers_every_field` fails until it is.
pub fn tx_content_commitment(tx: &Transaction) -> Hash {
    let Transaction {
        hash,
        nonce,
        from,
        to,
        value,
        gas_limit,
        gas_price,
        data,
        signature,
        tx_type,
        eth_tx_type,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        access_list,
        chain_id,
        // Node-local derived flag; never consensus, never trusted.
        ecdsa_verified: _,
    } = tx;

    let mut h = Sha3_256::new();
    h.update(TX_COMMIT_DOMAIN);
    h.update(hash.as_bytes());
    h.update(nonce.to_le_bytes());
    h.update(from.as_bytes());
    match to {
        Some(t) => {
            h.update([1u8]);
            h.update(t.as_bytes());
        }
        None => h.update([0u8]),
    }
    h.update(value.to_le_bytes());
    h.update(gas_limit.to_le_bytes());
    h.update(gas_price.to_le_bytes());
    put_bytes(&mut h, data);
    h.update(signature.as_bytes());
    match tx_type {
        Some(t) => h.update([1u8, *t as u8]),
        None => h.update([0u8]),
    }
    h.update([*eth_tx_type]);
    put_opt_u64(&mut h, *max_fee_per_gas);
    put_opt_u64(&mut h, *max_priority_fee_per_gas);
    match access_list {
        Some(list) => {
            h.update([1u8]);
            h.update((list.len() as u64).to_le_bytes());
            for (addr, keys) in list {
                put_bytes(&mut h, addr);
                h.update((keys.len() as u64).to_le_bytes());
                for k in keys {
                    put_bytes(&mut h, k);
                }
            }
        }
        None => h.update([0u8]),
    }
    put_opt_u64(&mut h, *chain_id);
    Hash::new(h.finalize().into())
}

/// Legacy (pre-activation) `tx_root`: Sha3-256 over the concatenated
/// `tx.hash` fields. Kept byte-identical for blocks below the activation
/// height. It commits to nothing but the peer-supplied ids (PBA-L1b-002).
pub fn tx_root_legacy(txs: &[Transaction]) -> Hash {
    let mut h = Sha3_256::new();
    for tx in txs {
        h.update(tx.hash.as_bytes());
    }
    Hash::new(h.finalize().into())
}

/// Post-activation `tx_root`: commits to every transaction's full contents
/// and to their order and count.
pub fn tx_root_v2(txs: &[Transaction]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(TX_ROOT_V2_DOMAIN);
    h.update((txs.len() as u64).to_le_bytes());
    for tx in txs {
        h.update(tx_content_commitment(tx).as_bytes());
    }
    Hash::new(h.finalize().into())
}

/// The `tx_root` a block at `height` must carry under `hardening`.
pub fn tx_root_for_height(
    hardening: crate::hardening::PbaHardening,
    height: u64,
    txs: &[Transaction],
) -> Hash {
    if hardening.active_at(height) {
        tx_root_v2(txs)
    } else {
        tx_root_legacy(txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PublicKey, Signature};

    /// A named field mutation applied to a transaction.
    type Mutation = (&'static str, Box<dyn Fn(&mut Transaction)>);

    fn native_signed(seed: u8, nonce: u64) -> Transaction {
        let sk = crate::crypto::Ed25519SigningKey::from_bytes(&[seed; 32]);
        let mut tx = Transaction {
            nonce,
            to: Some(PublicKey::new([9u8; 32])),
            value: 5,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            chain_id: Some(40204),
            ..Default::default()
        };
        crate::crypto::sign_transaction(&mut tx, &sk).unwrap();
        tx.hash = native_tx_id(&tx);
        tx
    }

    #[test]
    fn native_roundtrip_and_hash_rule() {
        let tx = native_signed(1, 0);
        assert_eq!(authenticate(&tx), Ok(tx.hash));
        assert_eq!(authenticate_with_hash(&tx), Ok(tx.hash));
        let mut squat = tx.clone();
        squat.hash = Hash::new([0x42; 32]);
        assert!(matches!(
            authenticate_with_hash(&squat),
            Err(TxAuthError::HashMismatch { .. })
        ));
    }

    #[test]
    fn native_forgeries_rejected() {
        let tx = native_signed(1, 0);
        let mut t = tx.clone();
        t.value = 6;
        assert_eq!(authenticate(&t), Err(TxAuthError::BadSignature));
        let mut t = tx.clone();
        t.signature = Signature::new([0u8; 64]);
        assert_eq!(authenticate(&t), Err(TxAuthError::BadSignature));
        let mut t = tx.clone();
        t.eth_tx_type = 2;
        assert!(matches!(
            authenticate(&t),
            Err(TxAuthError::UnsignedField(_))
        ));
        let mut t = tx.clone();
        t.tx_type = Some(TransactionType::ModelDeploy);
        assert!(matches!(
            authenticate(&t),
            Err(TxAuthError::UnsignedField(_))
        ));
        let mut t = tx;
        t.from = PublicKey::new([0u8; 32]);
        assert_eq!(authenticate(&t), Err(TxAuthError::EmptySender));
    }

    #[test]
    fn verify_for_block_binds_chain_and_hash() {
        let tx = native_signed(1, 0);
        assert_eq!(verify_for_block(&tx, 40204), Ok(tx.hash));
        assert_eq!(
            verify_for_block(&tx, 1),
            Err(TxAuthError::WrongChainId {
                expected: 1,
                got: Some(40204)
            })
        );
        let mut t = tx.clone();
        t.chain_id = None;
        assert!(matches!(
            verify_for_block(&t, 40204),
            Err(TxAuthError::WrongChainId { .. })
        ));
        let mut t = tx;
        t.hash = Hash::new([7; 32]);
        assert!(matches!(
            verify_for_block(&t, 40204),
            Err(TxAuthError::HashMismatch { .. })
        ));
    }

    #[test]
    fn evm_shaped_sender_with_forged_flag_is_rejected() {
        // The PBA-L1b-001 shape: an EVM-shaped `from`, a zero signature and
        // `ecdsa_verified = true` as it would arrive deserialized off the wire.
        let mut from = [0u8; 32];
        from[..20].copy_from_slice(&[0xAA; 20]);
        let tx = Transaction {
            from: PublicKey::new(from),
            to: Some(PublicKey::new([0u8; 32])),
            chain_id: Some(40204),
            ecdsa_verified: true,
            ..Default::default()
        };
        assert_eq!(authenticate(&tx), Err(TxAuthError::BadSignature));
    }

    // ── EVM vectors: sign with secp256k1 exactly per the EIPs, independently
    // of the code under test, and require authenticate == keccak(raw). ──

    fn trim(b: &[u8]) -> &[u8] {
        let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        &b[i..]
    }

    struct Evm {
        ty: u8,
        to: Option<[u8; 20]>,
        value: u128,
        data: Vec<u8>,
        access: Vec<([u8; 20], Vec<[u8; 32]>)>,
    }

    const GP: u64 = 2_000_000_000;
    const PRIO: u64 = 1_000_000_000;
    const GAS: u64 = 100_000;
    const NONCE: u64 = 3;
    const CH: u64 = 40204;

    fn fields(s: &mut rlp::RlpStream, e: &Evm) {
        match e.to {
            Some(t) => {
                s.append(&t.as_slice());
            }
            None => {
                s.append_empty_data();
            }
        }
        s.append(&trim(&e.value.to_be_bytes()));
        s.append(&e.data.as_slice());
    }

    fn access(s: &mut rlp::RlpStream, e: &Evm) {
        s.begin_list(e.access.len());
        for (a, keys) in &e.access {
            s.begin_list(2);
            s.append(&a.as_slice());
            s.begin_list(keys.len());
            for k in keys {
                s.append(&k.as_slice());
            }
        }
    }

    /// Returns (tx as the decoder would build it, keccak(raw)).
    fn evm_signed(seed: u8, e: &Evm) -> (Transaction, Hash) {
        use secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let addr = Keccak256::digest(&pk.serialize_uncompressed()[1..]);
        let mut u = rlp::RlpStream::new();
        match e.ty {
            0 => {
                u.begin_list(9);
                u.append(&NONCE);
                u.append(&GP);
                u.append(&GAS);
                fields(&mut u, e);
                u.append(&CH);
                u.append(&0u8);
                u.append(&0u8);
            }
            1 => {
                u.begin_list(8);
                u.append(&CH);
                u.append(&NONCE);
                u.append(&GP);
                u.append(&GAS);
                fields(&mut u, e);
                access(&mut u, e);
            }
            _ => {
                u.begin_list(9);
                u.append(&CH);
                u.append(&NONCE);
                u.append(&PRIO);
                u.append(&GP);
                u.append(&GAS);
                fields(&mut u, e);
                access(&mut u, e);
            }
        }
        let mut pre = Vec::new();
        if e.ty != 0 {
            pre.push(e.ty);
        }
        pre.extend_from_slice(&u.out());
        let msg = Message::from_slice(&Keccak256::digest(&pre)).unwrap();
        let (rid, sig) = secp.sign_ecdsa_recoverable(&msg, &sk).serialize_compact();
        let rid = rid.to_i32() as u64;
        let mut s = rlp::RlpStream::new();
        match e.ty {
            0 => {
                s.begin_list(9);
                s.append(&NONCE);
                s.append(&GP);
                s.append(&GAS);
                fields(&mut s, e);
                s.append(&(CH * 2 + 35 + rid));
            }
            1 => {
                s.begin_list(11);
                s.append(&CH);
                s.append(&NONCE);
                s.append(&GP);
                s.append(&GAS);
                fields(&mut s, e);
                access(&mut s, e);
                s.append(&rid);
            }
            _ => {
                s.begin_list(12);
                s.append(&CH);
                s.append(&NONCE);
                s.append(&PRIO);
                s.append(&GP);
                s.append(&GAS);
                fields(&mut s, e);
                access(&mut s, e);
                s.append(&rid);
            }
        }
        s.append(&trim(&sig[..32]));
        s.append(&trim(&sig[32..]));
        let mut raw = Vec::new();
        if e.ty != 0 {
            raw.push(e.ty);
        }
        raw.extend_from_slice(&s.out());
        let emb = |a: &[u8]| {
            let mut b = [0u8; 32];
            b[..20].copy_from_slice(a);
            PublicKey::new(b)
        };
        let al: Vec<(Vec<u8>, Vec<Vec<u8>>)> = e
            .access
            .iter()
            .map(|(a, ks)| (a.to_vec(), ks.iter().map(|k| k.to_vec()).collect()))
            .collect();
        let tx = Transaction {
            hash: Hash::new([0xEE; 32]),
            nonce: NONCE,
            from: emb(&addr[12..]),
            to: e.to.map(|t| emb(&t)),
            value: e.value,
            gas_limit: GAS,
            gas_price: GP,
            data: e.data.clone(),
            signature: Signature::new(sig),
            tx_type: Some(TransactionType::from_data(&e.data)),
            eth_tx_type: e.ty,
            max_fee_per_gas: if e.ty == 2 { Some(GP) } else { None },
            max_priority_fee_per_gas: if e.ty == 2 { Some(PRIO) } else { None },
            access_list: if al.is_empty() { None } else { Some(al) },
            chain_id: Some(CH),
            ecdsa_verified: false,
        };
        (tx, Hash::new(Keccak256::digest(&raw).into()))
    }

    fn evm_cases() -> Vec<Evm> {
        let al = vec![
            ([0x11; 20], vec![[0x22; 32], [0u8; 32]]),
            ([0x33; 20], vec![]),
        ];
        let mut v = Vec::new();
        for ty in [0u8, 1, 2] {
            v.push(Evm {
                ty,
                to: Some([0xB0; 20]),
                value: 10u128.pow(18),
                data: vec![],
                access: vec![],
            });
            v.push(Evm {
                ty,
                to: Some([0xB0; 20]),
                value: 0,
                data: vec![0xa9, 0x05, 0x9c, 0xbb],
                access: vec![],
            });
            v.push(Evm {
                ty,
                to: None,
                value: 0,
                data: vec![0x60, 0x80],
                access: vec![],
            });
            v.push(Evm {
                ty,
                to: Some([0x01; 20]),
                value: 0x7f,
                data: vec![1],
                access: vec![],
            });
            if ty != 0 {
                v.push(Evm {
                    ty,
                    to: Some([0x01; 20]),
                    value: 7,
                    data: vec![],
                    access: al.clone(),
                });
            }
        }
        v
    }

    #[test]
    fn evm_all_types_authenticate_to_keccak_of_raw() {
        for (i, e) in evm_cases().iter().enumerate() {
            for seed in [0x4c_u8, 0x07, 0x99] {
                let (tx, want) = evm_signed(seed, e);
                assert_eq!(
                    authenticate(&tx),
                    Ok(want),
                    "case {i} type {} seed {seed}",
                    e.ty
                );
                let mut t = tx.clone();
                t.hash = want;
                assert_eq!(authenticate_with_hash(&t), Ok(want));
                assert_eq!(verify_for_block(&t, CH), Ok(want));
            }
        }
    }

    #[test]
    fn evm_mutations_fail() {
        for e in evm_cases() {
            let (tx, want) = evm_signed(0x4c, &e);
            let muts: Vec<Mutation> = vec![
                ("value", Box::new(|t| t.value += 1)),
                ("nonce", Box::new(|t| t.nonce += 1)),
                ("gas", Box::new(|t| t.gas_limit += 1)),
                ("gas_price", Box::new(|t| t.gas_price += 1)),
                ("data", Box::new(|t| t.data.push(0))),
                ("chain", Box::new(|t| t.chain_id = Some(CH + 1))),
                ("no chain", Box::new(|t| t.chain_id = None)),
                ("to", Box::new(|t| t.to = Some(PublicKey::new([0xEE; 32])))),
                (
                    "to tail",
                    Box::new(|t| {
                        let mut b = [0u8; 32];
                        b[..20].copy_from_slice(&[0xB0; 20]);
                        b[31] = 1;
                        t.to = Some(PublicKey::new(b));
                    }),
                ),
                (
                    "type",
                    Box::new(|t| t.eth_tx_type = (t.eth_tx_type + 1) % 3),
                ),
                ("type 3", Box::new(|t| t.eth_tx_type = 3)),
                (
                    "sig r",
                    Box::new(|t| {
                        let mut b = *t.signature.as_bytes();
                        b[5] ^= 1;
                        t.signature = Signature::new(b);
                    }),
                ),
                (
                    "high s",
                    Box::new(|t| {
                        let mut b = *t.signature.as_bytes();
                        b[32] = 0xFF;
                        t.signature = Signature::new(b);
                    }),
                ),
                (
                    "tx_type",
                    Box::new(|t| t.tx_type = Some(TransactionType::ModelDeploy)),
                ),
                (
                    "prio",
                    Box::new(|t| {
                        t.max_priority_fee_per_gas =
                            Some(t.max_priority_fee_per_gas.unwrap_or(0) + 1)
                    }),
                ),
                (
                    "access",
                    Box::new(|t| t.access_list = Some(vec![(vec![0x44; 20], vec![])])),
                ),
                (
                    "access addr len",
                    Box::new(|t| t.access_list = Some(vec![(vec![0x44; 19], vec![])])),
                ),
                (
                    "access key len",
                    Box::new(|t| {
                        t.access_list = Some(vec![(vec![0x11; 20], vec![vec![0x22; 31]])])
                    }),
                ),
            ];
            for (name, m) in muts {
                let mut t = tx.clone();
                m(&mut t);
                let r = authenticate(&t);
                assert!(
                    r.is_err() && r != Ok(want),
                    "type {} mutation {name}: {r:?}",
                    e.ty
                );
            }
        }
    }

    /// Each EVM envelope field alone makes a native tx unauthenticated (the
    /// native signature does not cover any of them).
    #[test]
    fn native_rejects_each_envelope_field_alone() {
        let base = native_signed(4, 0);
        let muts: Vec<Mutation> = vec![
            ("eth_tx_type", Box::new(|t| t.eth_tx_type = 1)),
            ("max_fee", Box::new(|t| t.max_fee_per_gas = Some(1))),
            (
                "max_prio",
                Box::new(|t| t.max_priority_fee_per_gas = Some(1)),
            ),
            ("access_list", Box::new(|t| t.access_list = Some(vec![]))),
        ];
        for (name, m) in muts {
            let mut t = base.clone();
            m(&mut t);
            assert!(
                matches!(authenticate(&t), Err(TxAuthError::UnsignedField(_))),
                "{name} alone must be rejected"
            );
        }
    }

    /// EIP-2: the malleated twin (r, n - s) of a valid signature recovers the
    /// SAME signer with the other recovery id; it must still be rejected, or a
    /// relayer could mint a second id for one signed transaction.
    #[test]
    fn evm_malleated_high_s_twin_is_rejected() {
        const N: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];
        for e in evm_cases() {
            let (tx, want) = evm_signed(0x4c, &e);
            assert_eq!(authenticate(&tx), Ok(want));
            let sig = *tx.signature.as_bytes();
            // s' = n - s (big-endian, 256-bit).
            let mut s2 = [0u8; 32];
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let mut d = N[i] as i16 - sig[32 + i] as i16 - borrow;
                borrow = if d < 0 {
                    d += 256;
                    1
                } else {
                    0
                };
                s2[i] = d as u8;
            }
            let mut twin = sig;
            twin[32..].copy_from_slice(&s2);
            let mut t = tx.clone();
            t.signature = Signature::new(twin);
            assert_eq!(authenticate(&t), Err(TxAuthError::HighS), "type {}", e.ty);
        }
    }

    #[test]
    fn commitment_covers_every_field() {
        let base = native_signed(3, 7);
        let c0 = tx_content_commitment(&base);
        let mutations: Vec<Mutation> = vec![
            ("hash", Box::new(|t| t.hash = Hash::new([1; 32]))),
            ("nonce", Box::new(|t| t.nonce += 1)),
            ("from", Box::new(|t| t.from = PublicKey::new([2; 32]))),
            ("to", Box::new(|t| t.to = None)),
            ("value", Box::new(|t| t.value += 1)),
            ("gas_limit", Box::new(|t| t.gas_limit += 1)),
            ("gas_price", Box::new(|t| t.gas_price += 1)),
            ("data", Box::new(|t| t.data.push(0))),
            (
                "signature",
                Box::new(|t| t.signature = Signature::new([3; 64])),
            ),
            (
                "tx_type",
                Box::new(|t| t.tx_type = Some(TransactionType::Standard)),
            ),
            ("eth_tx_type", Box::new(|t| t.eth_tx_type = 1)),
            ("max_fee", Box::new(|t| t.max_fee_per_gas = Some(1))),
            (
                "max_prio",
                Box::new(|t| t.max_priority_fee_per_gas = Some(1)),
            ),
            ("access_list", Box::new(|t| t.access_list = Some(vec![]))),
            ("chain_id", Box::new(|t| t.chain_id = Some(1))),
        ];
        for (name, m) in mutations {
            let mut t = base.clone();
            m(&mut t);
            assert_ne!(tx_content_commitment(&t), c0, "{name} is not committed");
        }
        // The local flag is NOT part of the commitment.
        let mut t = base.clone();
        t.ecdsa_verified = !t.ecdsa_verified;
        assert_eq!(tx_content_commitment(&t), c0);
    }

    #[test]
    fn tx_root_v2_binds_body_order_and_count_legacy_does_not() {
        let a = native_signed(1, 0);
        let b = native_signed(2, 0);
        let mut tampered = a.clone();
        tampered.value = 999; // body rewritten, hash untouched
        let one = std::slice::from_ref(&a);
        assert_eq!(
            tx_root_legacy(one),
            tx_root_legacy(std::slice::from_ref(&tampered))
        );
        assert_ne!(tx_root_v2(one), tx_root_v2(std::slice::from_ref(&tampered)));
        assert_ne!(
            tx_root_v2(&[a.clone(), b.clone()]),
            tx_root_v2(&[b.clone(), a.clone()])
        );
        assert_ne!(tx_root_v2(&[]), tx_root_legacy(&[]));
        use crate::hardening::PbaHardening;
        assert_eq!(
            tx_root_for_height(PbaHardening::at(10), 9, one),
            tx_root_legacy(one)
        );
        assert_eq!(
            tx_root_for_height(PbaHardening::at(10), 10, one),
            tx_root_v2(one)
        );
    }

    /// EIP-2 boundary: `s <= floor(n/2)` is low-s and valid; `floor(n/2) + 1`
    /// is the first high-s value. n is odd, so there is no s with 2s == n.
    ///
    /// The vector is a legacy EIP-155 transfer whose ECDSA `s` equals
    /// floor(n/2) exactly. It was built by fixing the nonce k and s, then
    /// solving for the private key d = (s*k - z) / r mod n, and checked with an
    /// independent ECDSA verification. Without it, relaxing the check to
    /// `s >= floor(n/2)` passed every other test.
    #[test]
    fn low_s_boundary_is_inclusive_at_half_n() {
        fn hex32(s: &str) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
            }
            out
        }
        let s_half = hex32("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
        assert_eq!(s_half, HALF_N, "vector s is exactly floor(n/2)");
        let r = hex32("bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020d");
        let from20 = hex32("2f550c59d8200c040819f8ddf18880c8e9794e1b000000000000000000000000");
        let mut to = [0u8; 32];
        to[..20].copy_from_slice(&[0xBB; 20]);
        let mk = |s: [u8; 32]| {
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&r);
            sig[32..].copy_from_slice(&s);
            Transaction {
                nonce: 0,
                from: PublicKey::new(from20),
                to: Some(PublicKey::new(to)),
                value: 1,
                gas_limit: 21_000,
                gas_price: 1_000_000_000,
                signature: Signature::new(sig),
                chain_id: Some(40204),
                ..Default::default()
            }
        };

        // s == floor(n/2): accepted (EIP-2 low-s), and it recovers the sender.
        let at_half = mk(s_half);
        let id = authenticate(&at_half).expect("s == floor(n/2) is a valid low-s signature");
        assert_ne!(id, Hash::default());

        // s == floor(n/2) + 1: the first high-s value, rejected before recovery.
        let mut s_above = s_half;
        s_above[31] += 1;
        assert_eq!(authenticate(&mk(s_above)), Err(TxAuthError::HighS));
    }
}
