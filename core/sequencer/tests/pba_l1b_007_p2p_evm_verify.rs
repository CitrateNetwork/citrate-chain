// PBA-L1b-007 (INFO) regression — CHAIN-B-A015 residual.
//
// Transactions arriving over P2P carry `ecdsa_verified = false` (stripped by
// `sanitize_inbound`), so the mempool re-verified EVM-shaped senders with
// `verify_eth_ecdsa`, which rebuilt ONLY the legacy EIP-155 payload and encoded
// value 0 as `0x00` instead of `0x80`. Every EIP-1559/2930 tx, and every
// zero-value legacy tx, failed and was dropped: typed transactions never
// propagated over P2P. The mempool now uses the shared content-derived
// verifier (`tx_auth::authenticate`).

use citrate_consensus::types::{PublicKey, Signature, Transaction, TransactionType};
use citrate_sequencer::mempool::{Mempool, MempoolConfig, TxClass};
use rlp::RlpStream;
use secp256k1::{Message, PublicKey as SecpPk, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

const CHAIN: u64 = 40204;

fn addr_of(sk: &SecretKey) -> [u8; 20] {
    let pk = SecpPk::from_secret_key(&Secp256k1::new(), sk);
    let h = Keccak256::digest(&pk.serialize_uncompressed()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

fn embedded(a: [u8; 20]) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&a);
    PublicKey::new(b)
}

fn trim(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[i..]
}

/// A tx as it arrives over P2P: fields only, `ecdsa_verified = false`.
fn p2p_tx(sk: &SecretKey, ty: u8, value: u128, nonce: u64) -> Transaction {
    let to = [0xB0u8; 20];
    let (gas_price, prio, gas) = (2_000_000_000u64, 1_000_000_000u64, 21_000u64);
    let mut s = RlpStream::new();
    match ty {
        0 => {
            s.begin_list(9);
            s.append(&nonce);
            s.append(&gas_price);
            s.append(&gas);
            s.append(&to.as_slice());
            s.append(&trim(&value.to_be_bytes()));
            s.append(&Vec::<u8>::new().as_slice());
            s.append(&CHAIN);
            s.append(&0u8);
            s.append(&0u8);
        }
        _ => {
            s.begin_list(9);
            s.append(&CHAIN);
            s.append(&nonce);
            s.append(&prio);
            s.append(&gas_price);
            s.append(&gas);
            s.append(&to.as_slice());
            s.append(&trim(&value.to_be_bytes()));
            s.append(&Vec::<u8>::new().as_slice());
            s.begin_list(0);
        }
    }
    let mut pre = Vec::new();
    if ty != 0 {
        pre.push(ty);
    }
    pre.extend_from_slice(&s.out());
    let msg = Message::from_slice(&Keccak256::digest(&pre)).unwrap();
    let (_rid, sig) = Secp256k1::new()
        .sign_ecdsa_recoverable(&msg, sk)
        .serialize_compact();
    let mut tx = Transaction {
        nonce,
        from: embedded(addr_of(sk)),
        to: Some(embedded(to)),
        value,
        gas_limit: gas,
        gas_price,
        signature: Signature::new(sig),
        tx_type: Some(TransactionType::Standard),
        eth_tx_type: ty,
        chain_id: Some(CHAIN),
        ecdsa_verified: false,
        ..Default::default()
    };
    if ty == 2 {
        tx.max_fee_per_gas = Some(gas_price);
        tx.max_priority_fee_per_gas = Some(prio);
    }
    tx
}

#[tokio::test]
async fn pba_l1b_007_typed_and_zero_value_evm_txs_verify_over_p2p() {
    let mp = Mempool::new(MempoolConfig::default());
    let sk = SecretKey::from_slice(&[0x31; 32]).unwrap();
    let r = mp.add_transaction(p2p_tx(&sk, 2, 5, 0), TxClass::Standard).await;
    assert!(r.is_ok(), "PBA-L1b-007: an EIP-1559 tx must verify on the P2P path, got {r:?}");
    let sk2 = SecretKey::from_slice(&[0x32; 32]).unwrap();
    let r = mp.add_transaction(p2p_tx(&sk2, 0, 0, 0), TxClass::Standard).await;
    assert!(r.is_ok(), "PBA-L1b-007: a zero-value legacy tx must verify, got {r:?}");
}

#[tokio::test]
async fn pba_l1b_007_forged_evm_sender_still_rejected() {
    let mp = Mempool::new(MempoolConfig::default());
    let sk = SecretKey::from_slice(&[0x31; 32]).unwrap();
    let mut t = p2p_tx(&sk, 2, 5, 0);
    t.from = embedded([0xAA; 20]); // not the signer
    assert!(mp.add_transaction(t, TxClass::Standard).await.is_err());
    let mut t = p2p_tx(&sk, 2, 5, 0);
    t.value = 6; // body changed after signing
    assert!(mp.add_transaction(t, TxClass::Standard).await.is_err());
}
