// PBA-R2 (lane CHAIN-EXEC) regression tests for wallet-core (audit lane L4).
#![cfg(feature = "native")]

use citrate_wallet_core::chain::TransactionBuilder;
use ed25519_dalek::SigningKey;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32]) // fixed throwaway test key
}

fn hex_of(len: usize) -> String {
    format!("0x{}", "11".repeat(len))
}

/// PBA-L4-004: a recipient must be exactly 20 or 32 bytes. Length table on the
/// native path.
#[test]
fn pba_l4_004_native_recipient_length_table() {
    for bad in [1usize, 19, 21, 31, 33, 64] {
        let r = TransactionBuilder::new()
            .to(&hex_of(bad))
            .value(1_000)
            .gas_limit(21_000)
            .gas_price(1)
            .sign(&key(), 0);
        assert!(
            r.is_err(),
            "{bad}-byte recipient must be rejected on the ed25519 path"
        );
    }
    for good in [20usize, 32] {
        let signed = TransactionBuilder::new()
            .to(&hex_of(good))
            .value(1_000)
            .gas_limit(21_000)
            .gas_price(1)
            .sign(&key(), 0)
            .expect("20/32-byte recipient signs");
        let tx: citrate_consensus::types::Transaction =
            bincode::deserialize(&signed.raw).expect("raw is bincode");
        let to = tx.to.expect("to");
        assert_eq!(&to.as_bytes()[..good], &vec![0x11u8; good][..]);
    }
}

/// PBA-L4-004: the secp256k1 path already rejected wrong lengths; keep both
/// paths aligned (the audit's "length table on both paths" tripwire).
#[test]
fn pba_l4_004_secp_recipient_length_table() {
    let sk = k256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).expect("key");
    for bad in [1usize, 19, 21, 32] {
        let r = TransactionBuilder::new()
            .to(&hex_of(bad))
            .value(1)
            .gas_limit(21_000)
            .gas_price(1)
            .sign_secp256k1(&sk, 0);
        assert!(
            r.is_err(),
            "{bad}-byte recipient must be rejected on the secp256k1 path"
        );
    }
}

/// `sign_v2` produces a signature the node verifies and that
/// binds chain_id (a relabelled copy fails).
#[test]
fn pba_l4_002_sign_v2_binds_chain_id() {
    let signed = TransactionBuilder::new()
        .to(&hex_of(20))
        .value(5)
        .gas_limit(21_000)
        .gas_price(1)
        .sign_v2(&key(), 3)
        .expect("v2 sign");
    let mut tx: citrate_consensus::types::Transaction =
        bincode::deserialize(&signed.raw).expect("raw is bincode");
    assert!(citrate_consensus::crypto::verify_transaction(&tx).expect("verify"));
    tx.chain_id = tx.chain_id.map(|c| c + 1);
    assert!(!citrate_consensus::crypto::verify_transaction(&tx).expect("verify"));
}

/// PBA-L4-011: `{:?}` of a freshly created account must not contain any
/// mnemonic word.
#[test]
fn pba_l4_011_create_account_debug_redacts_mnemonic() {
    let dir = std::env::temp_dir().join(format!("citrate_pba_l4_011_{}", uuid::Uuid::new_v4()));
    let km = citrate_wallet_core::keys::KeyManager::new(&dir);
    let r = km
        .create_account("strongpassword12345", "t")
        .expect("create");
    let dbg = format!("{r:?}");
    // Any two consecutive mnemonic words (a single short word can occur by
    // chance inside the address/public-key hex, e.g. "add").
    let words: Vec<&str> = r.mnemonic.split_whitespace().collect();
    assert!(words.len() >= 12);
    for pair in words.windows(2) {
        let phrase = format!("{} {}", pair[0], pair[1]);
        assert!(
            !dbg.contains(&phrase),
            "Debug output leaked mnemonic `{phrase}`: {dbg}"
        );
    }
    assert!(dbg.contains("<redacted>"));
    std::fs::remove_dir_all(&dir).ok();
}

/// PBA-L4-011: secret accessors hand out `Zeroizing` buffers.
#[test]
fn pba_l4_011_secret_bytes_is_zeroizing() {
    let k = citrate_wallet_core::keys::UnifiedKey::Ed25519(key());
    let s: zeroize::Zeroizing<[u8; 32]> = k.secret_bytes();
    assert_eq!(*s, key().to_bytes());
}
