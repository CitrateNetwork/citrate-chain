// citrate/wallet-core/tests/golden_secp256k1_vectors.rs
//
// Golden vectors for the secp256k1 key path (BIP39 -> BIP32/BIP44 -> k256):
// key derivation, public-key encoding, address derivation, RFC 6979
// deterministic signatures, and EIP-155 transaction bytes.
//
// The hex was captured on the k256 0.13 / bip32 0.5 line (2026-10-25) and is
// the reference for any curve-crate upgrade. Two rows are also independent of
// this code: the "abandon ... about" mnemonic at m/44'/60'/0'/0/{0,1} gives the
// widely published addresses 0x9858...da94 and 0x6fac...b9c0.
//
// The tests use only this crate's public API (the k256 `SigningKey` is taken
// out of `UnifiedKey` and passed back in, never built here), so the same file
// compiles on both sides of an upgrade. A changed byte means users' keys,
// addresses or signed transactions changed: that is never a dependency bump.

use citrate_wallet_core::{
    secp256k1_from_mnemonic, secp256k1_from_seed, sign_eip155_legacy_tx, sign_recoverable,
    LegacyTxFields, UnifiedKey,
};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon about";

/// (account index, secret key, uncompressed SEC1 public key, address)
const MNEMONIC_ACCOUNTS: [(u32, &str, &str, &str); 2] = [
    (
        0,
        "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
        "0437b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299a6179912b7451c09896c4098eca7ce6b2e58330672795e847c4d6af44e024230",
        "0x9858effd232b4033e47d90003d41ec34ecaeda94",
    ),
    (
        1,
        "9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6",
        "049fd0991d0222b4e1339c1a1a5b5f6d9f6a96672a3247b638ee6156d9ea877a2f1735e3a9260940e4c2225c344a8cea6c7b6a6057d0eb90a9a875f446c131031d",
        "0x6fac4d18c912343bf86fa7049364dd4e424ab9c0",
    ),
];

/// (prehash, r, s, recovery id) from `sign_recoverable` with mnemonic account 0.
/// The all-0xff prehash is above the curve order n, which exercises the
/// "reduce z mod n" step of RFC 6979.
const RECOVERABLE: [(&str, &str, &str, u8); 3] = [
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "9d379eda4fab00efc0884d0d909d0608fc22a4fcb7f7cf326fc0f1ee63ada7af",
        "5d6d481474337b3fb12e5a0cc7ffdfa3b2fe2c783beb08ed6bc3e639dc4b02f6",
        1,
    ),
    (
        "1111111111111111111111111111111111111111111111111111111111111111",
        "89da7ff582957446116d65bd9b6671705d4d8be533108cac124d6c57677b744b",
        "76361368022742e2025d83848dea47b480f21d9673b6c0ca36fb8aeca72503b1",
        1,
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "98d88c61484de4f8bedc1e95ecc3bdbbc2b27b554e2748e25dd05abb5feab234",
        "0f4160bd780608aabb2c27c4ba757f7ba44c47ebeda91da44f703043f758bcf2",
        0,
    ),
];

/// secp256k1 group order n / 2, big-endian: a canonical (low-S) s is <= this.
const HALF_N: &str = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";

fn account0() -> UnifiedKey {
    secp256k1_from_mnemonic(MNEMONIC, 0).expect("mnemonic derives")
}

fn with_secp<T>(key: &UnifiedKey, f: impl FnOnce(&k256::ecdsa::SigningKey) -> T) -> T {
    match key {
        UnifiedKey::Secp256k1(sk) => f(sk),
        UnifiedKey::Ed25519(_) => panic!("BIP44 EVM path must yield a secp256k1 key"),
    }
}

#[test]
fn golden_bip44_mnemonic_keys_pubkeys_and_addresses() {
    for (index, sk, pk, addr) in MNEMONIC_ACCOUNTS {
        let key = secp256k1_from_mnemonic(MNEMONIC, index).expect("derive");
        assert_eq!(hex::encode(*key.secret_bytes()), sk, "secret #{index}");
        assert_eq!(hex::encode(key.public_key_bytes()), pk, "pubkey #{index}");
        assert_eq!(key.derive_address(), addr, "address #{index}");
    }
}

#[test]
fn golden_bip44_from_bip32_test_vector_1_seed() {
    // BIP32 test vector 1 seed, at our EVM path m/44'/60'/0'/0/0.
    let seed: Vec<u8> = (0u8..16).collect();
    let key = secp256k1_from_seed(&seed, 0).expect("derive");
    assert_eq!(
        hex::encode(*key.secret_bytes()),
        "e22f5526ce620ec69441c3453d7a0acbc26c3fc7543023f338123fd45c7d44b3"
    );
    assert_eq!(
        key.derive_address(),
        "0x022b971dff0c43305e691ded7a14367af19d6407"
    );
}

#[test]
fn golden_rfc6979_message_signature() {
    // UnifiedKey::sign = ECDSA over SHA-256(message), RFC 6979 nonce, r || s.
    assert_eq!(
        hex::encode(account0().sign(b"citrate golden message")),
        "9e34a209b5114a8972761345343e9a46dc84827752da192088b1c79980e33e16\
         732c9973456059f97851e04296cf1b8e7a86b06f6e5ef21ddde6c6a418ffa4f5"
    );
}

#[test]
fn golden_rfc6979_recoverable_prehash_signatures() {
    let key = account0();
    for (h, r, s, v) in RECOVERABLE {
        let prehash: [u8; 32] = hex::decode(h).expect("hex").try_into().expect("32 bytes");
        let (got_r, got_s, got_v) =
            with_secp(&key, |sk| sign_recoverable(sk, &prehash)).expect("sign");
        assert_eq!(hex::encode(got_r), r, "r for prehash {h}");
        assert_eq!(hex::encode(got_s), s, "s for prehash {h}");
        assert_eq!(got_v, v, "recovery id for prehash {h}");
        // Canonical low-S (EIP-2): big-endian byte compare against n/2.
        assert!(hex::encode(got_s).as_str() <= HALF_N, "s must be low");
    }
}

#[test]
fn golden_eip155_transfer_bytes_on_chain_40204() {
    let tx = LegacyTxFields {
        nonce: 7,
        gas_price: 1_000_000_000,
        gas_limit: 21_000,
        to: Some([0x42u8; 20]),
        value: 1_000_000_000_000_000_000u128,
        data: vec![],
    };
    let signed = with_secp(&account0(), |sk| sign_eip155_legacy_tx(sk, &tx, 40204)).expect("sign");
    assert_eq!(
        hex::encode(&signed.raw),
        "f86e07843b9aca00825208944242424242424242424242424242424242424242880de0b6b3a7640000\
         8083013a3ca03668074256d14776772bbf1499960494678f1537384537a8ee8a39b02931bc64a014fe74\
         89a3d13f8b71625840807f577ee21e2598993359c3508d30507d5019e5"
    );
    assert_eq!(
        hex::encode(signed.hash),
        "1722000a04af3167c51fbc357d97ff79dad1448c78b764ead2513b349db32147"
    );
    assert_eq!(signed.v, 80444);
}

#[test]
fn golden_eip155_contract_creation_bytes_on_chain_40204() {
    let tx = LegacyTxFields {
        nonce: 0,
        gas_price: 0,
        gas_limit: 3_000_000,
        to: None,
        value: 0,
        data: vec![0x60, 0x80, 0x60, 0x40, 0x52],
    };
    let signed = with_secp(&account0(), |sk| sign_eip155_legacy_tx(sk, &tx, 40204)).expect("sign");
    assert_eq!(
        hex::encode(&signed.raw),
        "f8548080832dc6c0808085608060405283013a3ca0a4674326ae3e7052965d566728c757367d2d07bc\
         2161fff0635405f1a3d24a76a0661531086fc9447d0a64165fc898273b1971125ece80528004927417\
         ff3f6b6c"
    );
    assert_eq!(
        hex::encode(signed.hash),
        "1e53ee8774a7456723949964a36c1cfb19ea9b52b3a84af2d7adb8f4c8ee8dda"
    );
    assert_eq!(signed.v, 80444);
}
