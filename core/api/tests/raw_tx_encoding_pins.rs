// One byte encoding per signed transaction, pinned at `decode_eth_transaction`
// (the decoder `eth_sendRawTransaction` uses).
//
// The existing tests cover an extra list item and a trailing byte on legacy and
// EIP-1559 transactions. These add the EIP-2930 envelope, and the case where
// the list header is one item short and the last signed field sits after it:
// the item count still comes out right, so only the "list ends where the input
// ends" check refuses it.
//
// In-process only: no server, no network, no files.

use citrate_api::eth_tx_decoder::decode_eth_transaction;
use rlp::RlpStream;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

const CHAIN_ID: u64 = 40204;
const TO: [u8; 20] = [0x22; 20];

fn be_trim(b: &[u8]) -> Vec<u8> {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[first..].to_vec()
}

/// Sign `sighash` with a fixed test key; returns (recovery id, r, s), with r
/// and s as canonical (trimmed) big-endian integers.
fn sign(sighash: &[u8], seed: u8) -> (u64, Vec<u8>, Vec<u8>) {
    let sig = Secp256k1::new().sign_ecdsa_recoverable(
        &Message::from_slice(sighash).expect("msg"),
        &SecretKey::from_slice(&[seed; 32]).expect("key"),
    );
    let (recid, rs) = sig.serialize_compact();
    (
        recid.to_i32() as u64,
        be_trim(&rs[..32]),
        be_trim(&rs[32..]),
    )
}

/// Assemble a signed list from `fields` (already-encoded RLP items). The list
/// header claims `fields.len() - moved_out` items; the last `moved_out` items
/// are appended after the list, outside it.
fn assemble(prefix: Option<u8>, fields: &[Vec<u8>], moved_out: usize) -> Vec<u8> {
    let inside = fields.len() - moved_out;
    let mut s = RlpStream::new_list(inside);
    for f in &fields[..inside] {
        s.append_raw(f, 1);
    }
    let mut out = Vec::new();
    if let Some(p) = prefix {
        out.push(p);
    }
    out.extend_from_slice(&s.out());
    for f in &fields[inside..] {
        out.extend_from_slice(f);
    }
    out
}

fn item<T: rlp::Encodable>(v: &T) -> Vec<u8> {
    rlp::encode(v).to_vec()
}

fn empty_list() -> Vec<u8> {
    let s = RlpStream::new_list(0);
    s.out().to_vec()
}

// --- legacy (EIP-155) ------------------------------------------------------

fn legacy_fields() -> Vec<Vec<u8>> {
    let mut unsigned = RlpStream::new_list(9);
    unsigned.append(&3u64);
    unsigned.append(&1_000_000_000u64);
    unsigned.append(&21_000u64);
    unsigned.append(&TO.as_slice());
    unsigned.append(&5u64);
    unsigned.append_empty_data();
    unsigned.append(&CHAIN_ID);
    unsigned.append(&0u8);
    unsigned.append(&0u8);
    let (recid, r, s) = sign(&Keccak256::digest(unsigned.out()), 7);
    vec![
        item(&3u64),
        item(&1_000_000_000u64),
        item(&21_000u64),
        item(&TO.to_vec()),
        item(&5u64),
        item(&Vec::<u8>::new()),
        item(&(CHAIN_ID * 2 + 35 + recid)),
        item(&r),
        item(&s),
    ]
}

#[test]
fn legacy_tx_with_a_signed_field_outside_the_list_header_is_rejected() {
    let fields = legacy_fields();
    decode_eth_transaction(&assemble(None, &fields, 0)).expect("canonical legacy tx decodes");
    assert!(
        decode_eth_transaction(&assemble(None, &fields, 1)).is_err(),
        "a legacy tx whose `s` sits after a short list header must be rejected"
    );
}

// --- EIP-1559 ---------------------------------------------------------------

fn eip1559_fields() -> Vec<Vec<u8>> {
    let body = vec![
        item(&CHAIN_ID),
        item(&1u64),
        item(&1_000_000_000u64),
        item(&2_000_000_000u64),
        item(&21_000u64),
        item(&TO.to_vec()),
        item(&0u64),
        item(&Vec::<u8>::new()),
        empty_list(),
    ];
    let mut pre = vec![0x02u8];
    pre.extend_from_slice(&assemble(None, &body, 0));
    let (y, r, s) = sign(&Keccak256::digest(&pre), 9);
    let mut f = body;
    f.extend([item(&y), item(&r), item(&s)]);
    f
}

#[test]
fn eip1559_tx_with_a_signed_field_outside_the_list_header_is_rejected() {
    let fields = eip1559_fields();
    decode_eth_transaction(&assemble(Some(0x02), &fields, 0))
        .expect("canonical EIP-1559 tx decodes");
    assert!(
        decode_eth_transaction(&assemble(Some(0x02), &fields, 1)).is_err(),
        "an EIP-1559 tx whose `s` sits after a short list header must be rejected"
    );
}

// --- EIP-2930 ---------------------------------------------------------------

fn eip2930_fields() -> Vec<Vec<u8>> {
    let body = vec![
        item(&CHAIN_ID),
        item(&2u64),
        item(&1_000_000_000u64),
        item(&21_000u64),
        item(&TO.to_vec()),
        item(&0u64),
        item(&Vec::<u8>::new()),
        empty_list(),
    ];
    let mut pre = vec![0x01u8];
    pre.extend_from_slice(&assemble(None, &body, 0));
    let (y, r, s) = sign(&Keccak256::digest(&pre), 11);
    let mut f = body;
    f.extend([item(&y), item(&r), item(&s)]);
    f
}

#[test]
fn eip2930_canonical_tx_decodes() {
    let tx = decode_eth_transaction(&assemble(Some(0x01), &eip2930_fields(), 0))
        .expect("canonical EIP-2930 tx decodes");
    assert_eq!(tx.nonce, 2);
}

#[test]
fn eip2930_tx_with_an_extra_list_item_is_rejected() {
    let mut fields = eip2930_fields();
    fields.push(item(&0xdeadu64));
    assert!(
        decode_eth_transaction(&assemble(Some(0x01), &fields, 0)).is_err(),
        "an EIP-2930 tx with a 12th list item must be rejected"
    );
}

#[test]
fn eip2930_tx_with_trailing_bytes_is_rejected() {
    let mut raw = assemble(Some(0x01), &eip2930_fields(), 0);
    raw.push(0x80);
    assert!(
        decode_eth_transaction(&raw).is_err(),
        "trailing bytes after an EIP-2930 list must be rejected"
    );
}

#[test]
fn eip2930_tx_with_a_signed_field_outside_the_list_header_is_rejected() {
    assert!(
        decode_eth_transaction(&assemble(Some(0x01), &eip2930_fields(), 1)).is_err(),
        "an EIP-2930 tx whose `s` sits after a short list header must be rejected"
    );
}
