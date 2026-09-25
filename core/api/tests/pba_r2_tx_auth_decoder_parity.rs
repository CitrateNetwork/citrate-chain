// PBA-R2 — compatibility proof for the content-derived tx authentication
// (`citrate_consensus::tx_auth`) that block import enforces after activation
// (PBA-L1b-001) and the mempool/gossip use for canonical ids (PBA-L1a-006) and
// typed-tx P2P verification (PBA-L1b-007).
//
// For every transaction shape the RPC decoder accepts (legacy EIP-155,
// EIP-2930, EIP-1559; contract creation; value 0; access lists; calldata),
// sign a real raw transaction with secp256k1, decode it with the production
// decoder, and require:
//   * tx_auth::authenticate(tx) == keccak256(raw)  — the id every Ethereum
//     client reports, so re-verification on import never rejects an honest tx
//     and never changes its id;
//   * the result does not depend on the wire `ecdsa_verified` flag;
//   * any change to a signed field, or to a field the EVM signature does not
//     cover but the executor acts on, is rejected.

use citrate_api::eth_tx_decoder::decode_eth_transaction;
use citrate_consensus::tx_auth::{self, TxAuthError};
use citrate_consensus::types::PublicKey;
use rlp::RlpStream;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

const CHAIN: u64 = 40204;

/// A named field mutation applied to a decoded transaction.
type Mutation = (
    &'static str,
    Box<dyn Fn(&mut citrate_consensus::types::Transaction)>,
);

fn keccak(b: &[u8]) -> [u8; 32] {
    Keccak256::digest(b).into()
}

fn trim(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[i..]
}

struct Shape {
    ty: u8,
    nonce: u64,
    gas_price: u64,
    prio: u64,
    gas: u64,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
    access: Vec<([u8; 20], Vec<[u8; 32]>)>,
}

fn put_fields(s: &mut RlpStream, sh: &Shape) {
    match sh.to {
        Some(t) => {
            s.append(&t.as_slice());
        }
        None => {
            s.append_empty_data();
        }
    }
    s.append(&trim(&sh.value.to_be_bytes()));
    s.append(&sh.data.as_slice());
}

fn put_access(s: &mut RlpStream, sh: &Shape) {
    s.begin_list(sh.access.len());
    for (a, keys) in &sh.access {
        s.begin_list(2);
        s.append(&a.as_slice());
        s.begin_list(keys.len());
        for k in keys {
            s.append(&k.as_slice());
        }
    }
}

/// Build + sign a raw transaction exactly per the EIPs.
fn sign_raw(sk: &SecretKey, sh: &Shape) -> Vec<u8> {
    let secp = Secp256k1::new();
    let mut u = RlpStream::new();
    match sh.ty {
        0 => {
            u.begin_list(9);
            u.append(&sh.nonce);
            u.append(&sh.gas_price);
            u.append(&sh.gas);
            put_fields(&mut u, sh);
            u.append(&CHAIN);
            u.append(&0u8);
            u.append(&0u8);
        }
        1 => {
            u.begin_list(8);
            u.append(&CHAIN);
            u.append(&sh.nonce);
            u.append(&sh.gas_price);
            u.append(&sh.gas);
            put_fields(&mut u, sh);
            put_access(&mut u, sh);
        }
        _ => {
            u.begin_list(9);
            u.append(&CHAIN);
            u.append(&sh.nonce);
            u.append(&sh.prio);
            u.append(&sh.gas_price);
            u.append(&sh.gas);
            put_fields(&mut u, sh);
            put_access(&mut u, sh);
        }
    }
    let mut pre = Vec::new();
    if sh.ty != 0 {
        pre.push(sh.ty);
    }
    pre.extend_from_slice(&u.out());
    let msg = Message::from_slice(&keccak(&pre)).unwrap();
    let (recid, sig) = secp.sign_ecdsa_recoverable(&msg, sk).serialize_compact();
    let recid = recid.to_i32() as u64;

    let mut s = RlpStream::new();
    match sh.ty {
        0 => {
            s.begin_list(9);
            s.append(&sh.nonce);
            s.append(&sh.gas_price);
            s.append(&sh.gas);
            put_fields(&mut s, sh);
            s.append(&(CHAIN * 2 + 35 + recid));
        }
        1 => {
            s.begin_list(11);
            s.append(&CHAIN);
            s.append(&sh.nonce);
            s.append(&sh.gas_price);
            s.append(&sh.gas);
            put_fields(&mut s, sh);
            put_access(&mut s, sh);
            s.append(&recid);
        }
        _ => {
            s.begin_list(12);
            s.append(&CHAIN);
            s.append(&sh.nonce);
            s.append(&sh.prio);
            s.append(&sh.gas_price);
            s.append(&sh.gas);
            put_fields(&mut s, sh);
            put_access(&mut s, sh);
            s.append(&recid);
        }
    }
    s.append(&trim(&sig[..32]));
    s.append(&trim(&sig[32..]));
    let mut raw = Vec::new();
    if sh.ty != 0 {
        raw.push(sh.ty);
    }
    raw.extend_from_slice(&s.out());
    raw
}

fn shapes() -> Vec<Shape> {
    let al = vec![
        ([0x11; 20], vec![[0x22; 32], [0x00; 32]]),
        ([0x33; 20], vec![]),
    ];
    let mut v = Vec::new();
    for ty in [0u8, 1, 2] {
        for (to, value, data, access) in [
            (
                Some([0xB0; 20]),
                1_000_000_000_000_000_000u128,
                vec![],
                vec![],
            ),
            (
                Some([0xB0; 20]),
                0u128,
                vec![0xa9, 0x05, 0x9c, 0xbb, 0, 1, 2],
                vec![],
            ),
            (None, 0u128, vec![0x60, 0x80, 0x60, 0x40, 0x52], vec![]),
            (Some([0x01; 20]), 7u128, vec![1], al.clone()),
        ] {
            if ty == 0 && !access.is_empty() {
                continue;
            }
            v.push(Shape {
                ty,
                nonce: 3,
                gas_price: 2_000_000_000,
                prio: 1_000_000_000,
                gas: 100_000,
                to,
                value,
                data,
                access,
            });
        }
    }
    v
}

#[test]
fn every_decoder_shape_authenticates_to_keccak_of_raw() {
    let sk = SecretKey::from_slice(&[0x4c; 32]).unwrap();
    for (i, sh) in shapes().iter().enumerate() {
        let raw = sign_raw(&sk, sh);
        let tx = decode_eth_transaction(&raw).unwrap_or_else(|e| panic!("shape {i}: decode: {e}"));
        let expect = citrate_consensus::types::Hash::new(keccak(&raw));
        assert_eq!(tx.hash, expect, "shape {i} (type {}): RPC id", sh.ty);
        assert_eq!(
            tx_auth::authenticate(&tx),
            Ok(expect),
            "shape {i} (type {}): content-derived id must equal keccak(raw)",
            sh.ty
        );
        // The wire flag is irrelevant: import re-derives it.
        let mut stripped = tx.clone();
        stripped.ecdsa_verified = false;
        assert_eq!(tx_auth::authenticate_with_hash(&stripped), Ok(expect));
    }
}

#[test]
fn signed_and_executor_relevant_fields_cannot_be_changed() {
    let sk = SecretKey::from_slice(&[0x4c; 32]).unwrap();
    for sh in shapes() {
        let tx = decode_eth_transaction(&sign_raw(&sk, &sh)).unwrap();
        let mutations: Vec<Mutation> = vec![
            ("value", Box::new(|t| t.value += 1)),
            ("nonce", Box::new(|t| t.nonce += 1)),
            ("gas_limit", Box::new(|t| t.gas_limit += 1)),
            ("gas_price", Box::new(|t| t.gas_price += 1)),
            ("data", Box::new(|t| t.data.push(0))),
            ("chain_id", Box::new(|t| t.chain_id = Some(1))),
            ("to", Box::new(|t| t.to = Some(PublicKey::new([0xEE; 32])))),
            (
                "to tail",
                Box::new(|t| {
                    if let Some(to) = &mut t.to {
                        to.0[31] = 1
                    } else {
                        t.to = Some(PublicKey::new([1; 32]))
                    }
                }),
            ),
            (
                "eth_tx_type",
                Box::new(|t| t.eth_tx_type = (t.eth_tx_type + 1) % 3),
            ),
            (
                "signature",
                Box::new(|t| {
                    let mut b = *t.signature.as_bytes();
                    b[5] ^= 1;
                    t.signature = citrate_consensus::types::Signature::new(b);
                }),
            ),
        ];
        for (name, m) in mutations {
            let mut t = tx.clone();
            m(&mut t);
            let r = tx_auth::authenticate(&t);
            assert!(
                r.is_err(),
                "type {}: mutating {name} must fail authentication, got {r:?}",
                sh.ty
            );
        }
    }
}

#[test]
fn high_s_and_missing_chain_id_rejected() {
    let sk = SecretKey::from_slice(&[0x4c; 32]).unwrap();
    let sh = &shapes()[0];
    let tx = decode_eth_transaction(&sign_raw(&sk, sh)).unwrap();
    let mut no_chain = tx.clone();
    no_chain.chain_id = None;
    assert_eq!(
        tx_auth::authenticate(&no_chain),
        Err(TxAuthError::MissingChainId)
    );
    let mut high = tx.clone();
    let mut b = *high.signature.as_bytes();
    b[32] = 0xFF; // s > n/2
    high.signature = citrate_consensus::types::Signature::new(b);
    assert_eq!(tx_auth::authenticate(&high), Err(TxAuthError::HighS));
}

/// PBA-L1a-006 / PBA-L4-003 (issue #209 close condition): a wrong
/// client-supplied hash on the bincode (native) ingress path is REWRITTEN to
/// the canonical content id, so RPC returns — and the mempool stores — the id
/// that block import requires.
#[test]
fn bincode_native_tx_wrong_supplied_hash_is_rewritten() {
    use citrate_consensus::crypto::{sign_transaction, Ed25519SigningKey};
    use citrate_consensus::types::{Hash, Transaction};
    let sk = Ed25519SigningKey::from_bytes(&[0x21; 32]);
    let mut tx = Transaction {
        nonce: 0,
        to: Some(PublicKey::new([9; 32])),
        value: 1,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(CHAIN),
        ..Default::default()
    };
    sign_transaction(&mut tx, &sk).unwrap();
    tx.hash = Hash::new([0x42; 32]); // squatting someone else's id
    let raw = bincode::serialize(&tx).unwrap();
    let decoded = decode_eth_transaction(&raw).unwrap();
    let canonical = tx_auth::native_tx_id(&decoded);
    assert_ne!(
        decoded.hash,
        Hash::new([0x42; 32]),
        "supplied hash must not survive"
    );
    assert_eq!(decoded.hash, canonical);
    assert_eq!(tx_auth::authenticate_with_hash(&decoded), Ok(canonical));
}
