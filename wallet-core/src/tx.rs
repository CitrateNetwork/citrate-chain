//! Lean EIP-155 legacy secp256k1 transaction signing (B1.4.0).
//!
//! This module is compiled under the `crypto` feature — the LEAN key
//! path. It exposes a pure, recoverable EIP-155 legacy transaction signer
//! that produces `raw` RLP bytes ready for `eth_sendRawTransaction`, plus
//! the tx hash and v/r/s components.
//!
//! ## Why this lives here (and not in `chain`)
//!
//! The `chain` module carries an `RpcClient` (`reqwest`/`tokio`) and an
//! ed25519 signing path that imports `citrate_consensus::types`
//! (transitively ark-* / tracing-subscriber). Those force `chain` to be
//! `native`-only. The secp256k1 EIP-155 signing itself, however, needs
//! ONLY `sha3::Keccak256` + `k256` + `rlp` — all base (non-optional)
//! dependencies of this crate. citrate-core's lean `crypto` build
//! (B1.1-F-1) needs to sign real 40204 transactions without dragging the
//! native/zk/execution stack into the key path, so the pure signer is
//! extracted here and `chain::TransactionBuilder::sign_secp256k1`
//! delegates to it (identical bytes; the native builder is unchanged).
//!
//! ## Lean-tree discipline
//!
//! Deliberately U256-free. `LegacyTxFields::value` is a `u128` (>10^38
//! wei, far beyond any realistic SALT balance) so we do NOT pull
//! `primitive-types::U256` (a `native`-gated optional dep) into the lean
//! tree. `rlp` encodes a `u128` as a big-endian minimal-length byte
//! string exactly as the yellow-paper integer RLP requires, so the wire
//! bytes are identical to what a U256 would produce for any value that
//! fits in 128 bits.
//!
//! ## Reference conformance
//!
//! The canonical EIP-155 specification vector (Vitalik Buterin, EIP-155,
//! "Example": private key `0x4646…4646`, chainId 1, nonce 9, to
//! `0x3535…3535`, value 1e18, gasPrice 20e9, gasLimit 21000) reproduces
//! bit-for-bit through this signer — see `tests::eip155_spec_vector_*`.

use crate::error::WalletError;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

/// Fields of a legacy (type-0) EIP-155 transaction, prior to signing.
///
/// `value` is a `u128` (not a 256-bit integer) on purpose: this keeps the
/// lean `crypto` build free of `primitive-types`. RLP integer encoding is
/// big-endian minimal-length, so a `u128` value serializes to identical
/// wire bytes as a `U256` would for any amount that fits in 128 bits
/// (which covers every realistic wei balance).
#[derive(Debug, Clone)]
pub struct LegacyTxFields {
    /// Sender account nonce.
    pub nonce: u64,
    /// Gas price in wei.
    pub gas_price: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient 20-byte EVM address, or `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value to transfer, in wei.
    pub value: u128,
    /// Call data / init code.
    pub data: Vec<u8>,
}

/// A signed legacy EIP-155 transaction.
#[derive(Debug, Clone)]
pub struct SignedTx {
    /// RLP-encoded signed transaction, ready for `eth_sendRawTransaction`.
    pub raw: Vec<u8>,
    /// Keccak-256 hash of `raw` (the transaction hash).
    pub hash: [u8; 32],
    /// EIP-155 `v` value: `recovery_id + chain_id * 2 + 35`.
    pub v: u64,
    /// ECDSA signature `r` component (32 bytes, big-endian).
    pub r: [u8; 32],
    /// ECDSA signature `s` component (32 bytes, big-endian).
    pub s: [u8; 32],
}

/// RLP-encode the unsigned EIP-155 signing payload:
/// `[nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]`.
fn eip155_signing_payload(tx: &LegacyTxFields, chain_id: u64) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(9);
    stream.append(&tx.nonce);
    stream.append(&tx.gas_price);
    stream.append(&tx.gas_limit);
    append_to_address(&mut stream, &tx.to);
    stream.append(&tx.value);
    stream.append(&tx.data.as_slice());
    stream.append(&chain_id);
    stream.append(&0u8);
    stream.append(&0u8);
    stream.out().to_vec()
}

/// Keccak-256 the EIP-155 signing payload → the 32-byte signing hash.
fn eip155_signing_hash(tx: &LegacyTxFields, chain_id: u64) -> [u8; 32] {
    keccak256(&eip155_signing_payload(tx, chain_id))
}

/// RLP-append the `to` field: the 20-byte address, or the empty string
/// (RLP `0x80`) for contract creation.
fn append_to_address(stream: &mut rlp::RlpStream, to: &Option<[u8; 20]>) {
    match to {
        Some(addr) => stream.append(&addr.as_slice()),
        None => stream.append(&Vec::<u8>::new().as_slice()),
    };
}

/// Keccak-256 helper.
fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Sign a 32-byte prehash with secp256k1, returning `(r, s, recovery_id)`.
///
/// Recoverable ECDSA over the exact prehash (no additional hashing). The
/// `s` value is low-`s` normalized by `k256` (BIP-62 / EIP-2), matching
/// Ethereum's canonical-signature requirement, and `recovery_id` is the
/// 0/1 parity used to reconstruct the public key (`ecrecover`).
pub fn sign_recoverable(
    key: &SigningKey,
    prehash: &[u8; 32],
) -> Result<([u8; 32], [u8; 32], u8), WalletError> {
    let (signature, recovery_id) = key
        .sign_prehash_recoverable(prehash)
        .map_err(|e| WalletError::SigningFailed(format!("secp256k1 sign failed: {}", e)))?;

    let sig_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);
    Ok((r, s, recovery_id.to_byte()))
}

/// Sign a legacy EIP-155 transaction with a secp256k1 key.
///
/// Produces the RLP-encoded signed transaction (`raw`, ready for
/// `eth_sendRawTransaction`), its Keccak-256 hash, and the `v/r/s`
/// signature components where `v = recovery_id + chain_id * 2 + 35`
/// (EIP-155 replay protection).
///
/// This is the LEAN (crypto-feature) primitive citrate-core consumes to
/// sign real 40204 transactions. It touches only `sha3` + `k256` + `rlp`
/// — no RPC, no consensus, no U256.
///
/// WAL-04: the caller owns the key's lifetime; the `k256::SigningKey`
/// zeroizes on drop via the k256 crate. The intermediate signing-hash
/// buffer is explicitly zeroized before this function returns (it is a
/// pre-image commitment to the private-key signature, treated as
/// sensitive intermediate material).
pub fn sign_eip155_legacy_tx(
    key: &SigningKey,
    tx: &LegacyTxFields,
    chain_id: u64,
) -> Result<SignedTx, WalletError> {
    let mut signing_hash = eip155_signing_hash(tx, chain_id);

    let (r, s, recovery_id) = sign_recoverable(key, &signing_hash)?;

    // WAL-04: the signing hash is intermediate secret-adjacent material;
    // erase it now that the signature is produced.
    signing_hash.zeroize();

    // EIP-155: v = recovery_id + chain_id * 2 + 35.
    let v = recovery_id as u64 + chain_id * 2 + 35;

    let raw = serialize_rlp_signed(tx, v, &r, &s);
    let hash = keccak256(&raw);

    Ok(SignedTx { raw, hash, v, r, s })
}

/// RLP-encode a signed legacy EIP-155 transaction:
/// `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`.
///
/// `r`/`s` are appended as their minimal-length big-endian byte strings
/// (leading zero bytes stripped) — the yellow-paper canonical form. RLP's
/// `&[u8]` append does not strip leading zeros, so we trim here.
fn serialize_rlp_signed(tx: &LegacyTxFields, v: u64, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(9);
    stream.append(&tx.nonce);
    stream.append(&tx.gas_price);
    stream.append(&tx.gas_limit);
    append_to_address(&mut stream, &tx.to);
    stream.append(&tx.value);
    stream.append(&tx.data.as_slice());
    stream.append(&v);
    stream.append(&trim_leading_zeros(r));
    stream.append(&trim_leading_zeros(s));
    stream.out().to_vec()
}

/// Strip leading zero bytes for canonical RLP integer encoding. A
/// secp256k1 `r`/`s` is a positive scalar < curve order; RLP encodes
/// integers as minimal-length big-endian byte strings.
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a 0x-optional hex string into bytes (test helper).
    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("valid test hex")
    }

    fn addr20(s: &str) -> [u8; 20] {
        let v = unhex(s);
        let mut a = [0u8; 20];
        a.copy_from_slice(&v);
        a
    }

    /// Recover the signer's 20-byte EVM address from an EIP-155 signed tx,
    /// proving the signature is `ecrecover`-able back to the key. Mirrors
    /// what a node's tx-pool does on receipt.
    fn recover_evm_address(tx: &LegacyTxFields, chain_id: u64, signed: &SignedTx) -> [u8; 20] {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

        let signing_hash = eip155_signing_hash(tx, chain_id);
        // Reconstruct recovery_id from v: recovery_id = v - chain_id*2 - 35.
        let recid_byte = (signed.v - chain_id * 2 - 35) as u8;
        let recovery_id = RecoveryId::from_byte(recid_byte).expect("valid recovery id 0/1");

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signed.r);
        sig_bytes[32..].copy_from_slice(&signed.s);
        let signature = Signature::from_bytes((&sig_bytes).into()).expect("valid sig bytes");

        let recovered =
            VerifyingKey::recover_from_prehash(&signing_hash, &signature, recovery_id)
                .expect("ecrecover must succeed");

        // EVM address = Keccak256(uncompressed_pubkey[1..])[12..32].
        let point = recovered.to_encoded_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..32]);
        out
    }

    /// Derive the EVM address directly from the key (ground truth).
    fn evm_address_of_key(key: &SigningKey) -> [u8; 20] {
        let vk = key.verifying_key();
        let point = vk.to_encoded_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..32]);
        out
    }

    // ================================================================
    // RED-FIRST reference cross-check.
    //
    // SOURCE: EIP-155 specification, "Example" section (Vitalik Buterin,
    // https://eips.ethereum.org/EIPS/eip-155). The canonical published
    // test vector for legacy EIP-155 signing. This same vector is
    // reproduced by ethers.js / viem for identical inputs; the reference
    // raw bytes and hash below are taken directly from the EIP text.
    //
    //   private key : 0x4646464646464646464646464646464646464646464646464646464646464646
    //   nonce       : 9
    //   gasPrice    : 20_000_000_000
    //   gasLimit    : 21_000
    //   to          : 0x3535353535353535353535353535353535353535
    //   value       : 1_000_000_000_000_000_000 (1e18)
    //   data        : (empty)
    //   chainId     : 1
    //   expected v  : 37 (== 0 + 1*2 + 35)
    // ================================================================

    const EIP155_PRIV: &str =
        "4646464646464646464646464646464646464646464646464646464646464646";
    const EIP155_TO: &str = "3535353535353535353535353535353535353535";
    // Reference signing hash from the EIP-155 example text.
    const EIP155_SIGNING_HASH: &str =
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
    // Reference raw signed tx bytes from the EIP-155 example text.
    const EIP155_RAW: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

    fn eip155_example_tx() -> LegacyTxFields {
        LegacyTxFields {
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some(addr20(EIP155_TO)),
            value: 1_000_000_000_000_000_000,
            data: Vec::new(),
        }
    }

    #[test]
    fn eip155_spec_vector_signing_hash_matches() {
        let tx = eip155_example_tx();
        let hash = eip155_signing_hash(&tx, 1);
        assert_eq!(hex::encode(hash), EIP155_SIGNING_HASH);
    }

    #[test]
    fn eip155_spec_vector_raw_bytes_match_reference() {
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid EIP-155 example key");
        let tx = eip155_example_tx();

        let signed = sign_eip155_legacy_tx(&key, &tx, 1).expect("sign EIP-155 example");

        // Full raw RLP signed-tx bytes must equal the EIP-155 reference.
        assert_eq!(hex::encode(&signed.raw), EIP155_RAW);
        // v = recovery_id + chain_id*2 + 35 = 0 + 2 + 35 = 37.
        assert_eq!(signed.v, 37);
        // r/s from the reference (last 65 bytes of the raw tx encode
        // v(0x25)‖r‖s). Cross-check r/s independently.
        assert_eq!(
            hex::encode(signed.r),
            "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"
        );
        assert_eq!(
            hex::encode(signed.s),
            "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
    }

    #[test]
    fn eip155_spec_vector_hash_matches_reference() {
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid key");
        let tx = eip155_example_tx();
        let signed = sign_eip155_legacy_tx(&key, &tx, 1).expect("sign");
        // Keccak256 of the raw signed tx == the canonical tx hash.
        assert_eq!(
            hex::encode(signed.hash),
            "33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788"
        );
    }

    // ================================================================
    // ecrecover round-trip: recovered sender == key's EVM address, and
    // v = recovery_id + chain_id*2 + 35 (proved by successful recovery
    // using recovery_id reconstructed from v).
    // ================================================================

    #[test]
    fn ecrecover_roundtrip_recovers_signer_40204() {
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid key");
        let tx = LegacyTxFields {
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            to: Some(addr20("dead000000000000000000000000000000000000")),
            value: 1_000_000_000_000_000_000,
            data: Vec::new(),
        };
        let chain_id = 40204;

        let signed = sign_eip155_legacy_tx(&key, &tx, chain_id).expect("sign");

        // Prove v carries the EIP-155 chain binding.
        let recid = signed.v - chain_id * 2 - 35;
        assert!(recid == 0 || recid == 1, "recovery id must be 0 or 1");
        assert_eq!(signed.v, recid + chain_id * 2 + 35);

        // ecrecover → sender must equal the key's own EVM address.
        let recovered = recover_evm_address(&tx, chain_id, &signed);
        let expected = evm_address_of_key(&key);
        assert_eq!(recovered, expected, "ecrecover must return the signer");
    }

    #[test]
    fn ecrecover_roundtrip_spec_vector_chain_1() {
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid key");
        let tx = eip155_example_tx();
        let signed = sign_eip155_legacy_tx(&key, &tx, 1).expect("sign");
        let recovered = recover_evm_address(&tx, 1, &signed);
        let expected = evm_address_of_key(&key);
        assert_eq!(recovered, expected);
    }

    // ================================================================
    // Determinism, distinctness, contract-creation.
    // ================================================================

    #[test]
    fn signing_is_deterministic() {
        // secp256k1 via k256 uses RFC-6979 deterministic nonces, so the
        // same (key, tx, chain_id) yields byte-identical output.
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid key");
        let tx = eip155_example_tx();
        let a = sign_eip155_legacy_tx(&key, &tx, 40204).expect("sign a");
        let b = sign_eip155_legacy_tx(&key, &tx, 40204).expect("sign b");
        assert_eq!(a.raw, b.raw);
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.v, b.v);
        assert_eq!(a.r, b.r);
        assert_eq!(a.s, b.s);
    }

    #[test]
    fn distinct_tx_produces_distinct_bytes() {
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid key");
        let tx1 = eip155_example_tx();
        let mut tx2 = eip155_example_tx();
        tx2.nonce = 10; // one field differs

        let a = sign_eip155_legacy_tx(&key, &tx1, 40204).expect("sign 1");
        let b = sign_eip155_legacy_tx(&key, &tx2, 40204).expect("sign 2");
        assert_ne!(a.raw, b.raw);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn different_chain_id_produces_different_signature() {
        // Replay protection: chain_id enters the signing hash.
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid key");
        let tx = eip155_example_tx();
        let a = sign_eip155_legacy_tx(&key, &tx, 1).expect("chain 1");
        let b = sign_eip155_legacy_tx(&key, &tx, 40204).expect("chain 40204");
        assert_ne!(a.raw, b.raw);
        assert_ne!(a.v, b.v);
    }

    #[test]
    fn contract_creation_empty_to_is_handled() {
        // to == None → RLP-encodes the empty string (0x80), and ecrecover
        // still round-trips.
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid key");
        let tx = LegacyTxFields {
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 1_000_000,
            to: None,
            value: 0,
            data: vec![0x60, 0x80, 0x60, 0x40], // minimal init code
        };
        let signed = sign_eip155_legacy_tx(&key, &tx, 40204).expect("deploy sign");
        // Non-empty RLP list.
        assert!(signed.raw[0] >= 0xc0);
        let recovered = recover_evm_address(&tx, 40204, &signed);
        assert_eq!(recovered, evm_address_of_key(&key));
    }

    #[test]
    fn sign_recoverable_matches_full_signer() {
        // The low-level sign_recoverable over the signing hash yields the
        // same r/s the full signer embeds.
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid key");
        let tx = eip155_example_tx();
        let hash = eip155_signing_hash(&tx, 40204);
        let (r, s, recid) = sign_recoverable(&key, &hash).expect("recoverable");
        let signed = sign_eip155_legacy_tx(&key, &tx, 40204).expect("full");
        assert_eq!(r, signed.r);
        assert_eq!(s, signed.s);
        assert_eq!(recid as u64 + 40204 * 2 + 35, signed.v);
    }

    #[test]
    fn leading_zero_r_or_s_is_canonically_rlp_trimmed() {
        // B140-1 regression pin: ~1/256 of ECDSA signatures have r (or s)
        // with a leading 0x00 byte. RLP requires minimal big-endian, so that
        // zero must be stripped. The pre-fix encoder appended the full 32
        // bytes including the leading zero, producing a wire-invalid tx that
        // geth/ethers reject ("Unexpected type flag. Got 0."). This test finds
        // a real leading-zero case (deterministic RFC-6979) and asserts the
        // RLP-encoded r/s are trimmed — it FAILS against the un-trimmed encoder.
        let key = SigningKey::from_bytes((&unhex(EIP155_PRIV)[..]).into())
            .expect("valid key");
        let chain_id = 40204u64;
        let mut found = false;
        for nonce in 0u64..2000 {
            let tx = LegacyTxFields {
                nonce,
                gas_price: 20_000_000_000,
                gas_limit: 21_000,
                to: Some(addr20(EIP155_TO)),
                value: 1_000_000_000_000_000_000,
                data: vec![],
            };
            let signed = sign_eip155_legacy_tx(&key, &tx, chain_id).expect("sign");
            let r_lead0 = signed.r[0] == 0;
            let s_lead0 = signed.s[0] == 0;
            if !(r_lead0 || s_lead0) {
                continue;
            }
            found = true;
            // Sanity: the tx still ecrecovers to the signer.
            assert_eq!(
                recover_evm_address(&tx, chain_id, &signed),
                evm_address_of_key(&key)
            );
            // The RLP r/s fields (indices 7,8 of the 9-item legacy tx) must be
            // the trimmed big-endian, i.e. no leading zero survives on the wire.
            let rlp = rlp::Rlp::new(&signed.raw);
            let r_item: Vec<u8> = rlp.val_at(7).expect("rlp r");
            let s_item: Vec<u8> = rlp.val_at(8).expect("rlp s");
            assert_eq!(
                r_item.as_slice(),
                trim_leading_zeros(&signed.r),
                "r must be canonically trimmed in the RLP wire bytes"
            );
            assert_eq!(
                s_item.as_slice(),
                trim_leading_zeros(&signed.s),
                "s must be canonically trimmed in the RLP wire bytes"
            );
            if r_lead0 {
                assert!(r_item.len() < 32, "leading-zero r must encode to <32 bytes");
            }
            if s_lead0 {
                assert!(s_item.len() < 32, "leading-zero s must encode to <32 bytes");
            }
            break;
        }
        assert!(
            found,
            "expected a leading-zero r or s within 2000 nonces (~certain at p=1/256)"
        );
    }
}
