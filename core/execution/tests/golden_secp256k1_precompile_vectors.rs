// citrate/core/execution/tests/golden_secp256k1_precompile_vectors.rs
//
// Golden vectors for the secp256k1 paths whose answers are consensus state:
//
//   * the EVM ECRECOVER precompile at 0x01, which is revm's implementation
//     (revm is built without its C `secp256k1` feature, so this is the k256
//     path);
//   * Citrate's `recover_address`, shared by `PrecompileExecutor` ECRECOVER and
//     the x402 signature precompiles;
//   * the ECIES/ECDH secp256k1 key agreement (`crypto::ecdh`).
//
// The signature is wallet-core's RFC 6979 vector for the "abandon ... about"
// account 0 (address 0x9858...da94), see
// wallet-core/tests/golden_secp256k1_vectors.rs. The hex was captured on the
// k256 0.13 line (2026-10-25). The tests use no k256 types, so the same file
// compiles on both sides of a curve-crate upgrade.
//
// The high-S rows matter most. k256 0.13's `recover_from_prehash` also verified
// the signature, which rejected high S. k256 0.14 / ecdsa 0.17 no longer
// verify there (RustCrypto/signatures#1381). Whatever the library does, the
// answers below must not change: revm's 0x01 normalizes and accepts high S
// (Ethereum semantics), Citrate's `recover_address` rejects it (EIP-2).

use citrate_execution::crypto::ecdh::{ECIESMessage, ECIES};
use citrate_execution::precompiles::{recover_address, standard, PrecompileExecutor};

const SIGNER: &str = "9858effd232b4033e47d90003d41ec34ecaeda94";
const HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const R: &str = "89da7ff582957446116d65bd9b6671705d4d8be533108cac124d6c57677b744b";
const S_LOW: &str = "76361368022742e2025d83848dea47b480f21d9673b6c0ca36fb8aeca72503b1";
/// n - S_LOW: the same signature with high S (recovery parity flips).
const S_HIGH: &str = "89c9ec97fdd8bd1dfda27c7b7215b84a39bcbf503b91df7188d6d3a029113d90";
const RECID_LOW: u8 = 1;
const RECID_HIGH: u8 = 0;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in vector")
}

/// hash || v word (27/28) || r || s, the 128-byte ECRECOVER input.
fn ecrecover_input(s: &str, recid: u8) -> Vec<u8> {
    let mut input = unhex(HASH);
    let mut v = [0u8; 32];
    v[31] = 27 + recid;
    input.extend_from_slice(&v);
    input.extend_from_slice(&unhex(R));
    input.extend_from_slice(&unhex(s));
    input
}

fn padded(addr: &str) -> String {
    format!("{}{addr}", "00".repeat(12))
}

fn revm_ecrecover(input: Vec<u8>) -> String {
    let out = revm::precompile::secp256k1::ec_recover_run(&input.into(), 3_000)
        .expect("ecrecover runs with enough gas");
    assert_eq!(out.gas_used, 3_000);
    hex::encode(out.bytes)
}

#[test]
fn golden_recover_address_low_s() {
    let got = recover_address(&unhex(HASH), &unhex(R), &unhex(S_LOW), RECID_LOW)
        .expect("canonical signature recovers");
    assert_eq!(hex::encode(got), SIGNER);
}

#[test]
fn golden_recover_address_wrong_parity_is_another_key() {
    let got = recover_address(&unhex(HASH), &unhex(R), &unhex(S_LOW), RECID_LOW ^ 1);
    assert_ne!(got.map(hex::encode).as_deref(), Some(SIGNER));
}

#[test]
fn golden_recover_address_rejects_high_s() {
    for recid in [RECID_HIGH, RECID_LOW] {
        assert_eq!(
            recover_address(&unhex(HASH), &unhex(R), &unhex(S_HIGH), recid),
            None,
            "high-S must be rejected (EIP-2), recid {recid}"
        );
    }
}

#[test]
fn golden_recover_address_rejects_zero_and_out_of_range_scalars() {
    let n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    let zero = "00".repeat(32);
    for (r, s) in [
        (zero.as_str(), S_LOW),
        (R, zero.as_str()),
        (n, S_LOW),
        (R, n),
    ] {
        assert_eq!(
            recover_address(&unhex(HASH), &unhex(r), &unhex(s), RECID_LOW),
            None,
            "r={r} s={s} must be rejected"
        );
    }
    assert_eq!(
        recover_address(&unhex(HASH), &unhex(R), &unhex(S_LOW), 4),
        None
    );
}

#[test]
fn golden_citrate_executor_ecrecover_low_and_high_s() {
    let mut exec = PrecompileExecutor::new();
    let low = exec
        .execute(
            &standard::ECRECOVER,
            &ecrecover_input(S_LOW, RECID_LOW),
            3_000,
        )
        .expect("runs");
    assert_eq!(hex::encode(&low.output), padded(SIGNER));
    let high = exec
        .execute(
            &standard::ECRECOVER,
            &ecrecover_input(S_HIGH, RECID_HIGH),
            3_000,
        )
        .expect("runs");
    assert_eq!(
        hex::encode(&high.output),
        "00".repeat(32),
        "high-S yields the zero word"
    );
}

#[test]
fn golden_evm_ecrecover_0x01_low_s() {
    assert_eq!(
        revm_ecrecover(ecrecover_input(S_LOW, RECID_LOW)),
        padded(SIGNER)
    );
}

#[test]
fn golden_evm_ecrecover_0x01_accepts_high_s_like_ethereum() {
    // Ethereum's ECRECOVER precompile does not enforce low S; revm normalizes
    // (s -> n - s, parity flip) and recovers the same signer.
    assert_eq!(
        revm_ecrecover(ecrecover_input(S_HIGH, RECID_HIGH)),
        padded(SIGNER)
    );
}

#[test]
fn golden_evm_ecrecover_0x01_bad_v_and_bad_scalars_return_empty() {
    let mut bad_v = ecrecover_input(S_LOW, RECID_LOW);
    bad_v[63] = 29;
    assert_eq!(revm_ecrecover(bad_v), "");
    let n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    assert_eq!(revm_ecrecover(ecrecover_input(n, RECID_LOW)), "");
    assert_eq!(
        revm_ecrecover(ecrecover_input(&"00".repeat(32), RECID_LOW)),
        ""
    );
}

const ECIES_SK_A: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];
const ECIES_SK_B: [u8; 32] = [0x5a; 32];

fn pinned_message() -> ECIESMessage {
    ECIESMessage {
        ephemeral_pubkey: unhex(
            "02fa82ba7fef15bcc826813d3b549e15dd5e5baf9269bf31da5068ce097dc0d947",
        )
        .try_into()
        .expect("33 bytes"),
        ciphertext: unhex("8bbf9782cfe52a17a211736151174e070e1ed4d591cd8cb635a91b2e87f7"),
        auth_tag: unhex("780051acf3129a3480cbc8f0531f4174")
            .try_into()
            .expect("16 bytes"),
        nonce: unhex("71f43e97243bb07940afd0d0")
            .try_into()
            .expect("12 bytes"),
    }
}

#[test]
fn golden_ecies_public_keys() {
    let a = ECIES::from_private_key(ECIES_SK_A).expect("valid key");
    let b = ECIES::from_private_key(ECIES_SK_B).expect("valid key");
    assert_eq!(
        hex::encode(a.public_key()),
        "0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0"
    );
    assert_eq!(
        hex::encode(b.public_key()),
        "029c5530e4385ebc41cdaf8257edf9a2baaf8506a4099103211e6ed7382103ed67"
    );
}

#[test]
fn golden_ecies_pinned_ciphertext_decrypts() {
    // Exercises secp256k1 ECDH + the HKDF key schedule + AES-GCM end to end: a
    // changed shared secret fails the GCM tag.
    let b = ECIES::from_private_key(ECIES_SK_B).expect("valid key");
    let plain = b
        .decrypt(&pinned_message())
        .expect("pinned message decrypts");
    assert_eq!(plain, b"citrate golden ecies plaintext");
}

#[test]
fn golden_ecies_wrong_recipient_and_bad_ephemeral_fail_closed() {
    let a = ECIES::from_private_key(ECIES_SK_A).expect("valid key");
    assert!(a.decrypt(&pinned_message()).is_err(), "wrong recipient");
    let b = ECIES::from_private_key(ECIES_SK_B).expect("valid key");
    let mut msg = pinned_message();
    msg.ephemeral_pubkey[0] = 0x05;
    assert!(b.decrypt(&msg).is_err(), "bad SEC1 tag");
    let mut msg = pinned_message();
    msg.ephemeral_pubkey[1..].fill(0xff);
    assert!(b.decrypt(&msg).is_err(), "x above the field modulus");
}
