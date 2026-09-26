// The native signer picks the digest version the chain accepts for the next
// block (`citrate_consensus::native_sig::signer_version`).
#![cfg(feature = "native")]

use citrate_consensus::native_sig::{signed_version, NativeSigVersion};
use citrate_consensus::tx_auth::{verify_for_block, TxAuthError};
use citrate_consensus::types::Transaction;
use citrate_wallet_core::chain::TransactionBuilder;
use ed25519_dalek::SigningKey;

const H: u64 = 100;

fn builder() -> TransactionBuilder {
    TransactionBuilder::new()
        .to(&format!("0x{}", "22".repeat(32)))
        .value(1_000)
        .gas_limit(21_000)
        .gas_price(1)
        .chain_id(40204)
}

fn decode(raw: &[u8]) -> Transaction {
    bincode::deserialize(raw).expect("raw is bincode")
}

#[test]
fn signer_switches_to_v2_from_tip_h_minus_1() {
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let cases = [
        (None, Some(10_000), NativeSigVersion::V1),
        (Some(H), Some(H - 2), NativeSigVersion::V1),
        (Some(H), Some(H - 1), NativeSigVersion::V2),
        (Some(H), Some(H + 7), NativeSigVersion::V2),
        (Some(H), None, NativeSigVersion::V2),
    ];
    for (activation, tip, want) in cases {
        let signed = builder()
            .sign_for_tip(&key, 0, activation, tip)
            .expect("signs");
        let tx = decode(&signed.raw);
        assert_eq!(signed_version(&tx), Some(want), "{activation:?} {tip:?}");
        assert_eq!(tx.chain_id, Some(40204));
    }
}

/// What the signer produces from tip H - 1 is valid in block H; what it
/// produced before is not.
#[test]
fn signer_output_matches_the_block_rule() {
    let key = SigningKey::from_bytes(&[6u8; 32]);
    let mut v2 = decode(
        &builder()
            .sign_for_tip(&key, 0, Some(H), Some(H - 1))
            .unwrap()
            .raw,
    );
    v2.hash = citrate_consensus::tx_auth::native_tx_id(&v2);
    assert_eq!(verify_for_block(&v2, 40204), Ok(v2.hash));
    let mut v1 = decode(
        &builder()
            .sign_for_tip(&key, 0, Some(H), Some(H - 2))
            .unwrap()
            .raw,
    );
    v1.hash = citrate_consensus::tx_auth::native_tx_id(&v1);
    assert_eq!(
        verify_for_block(&v1, 40204),
        Err(TxAuthError::LegacyNativeSignature)
    );
}

/// `sign` produces V2 for the builder's chain in a process that never set an
/// activation height (every client; this test binary never sets one). V2 is
/// valid at every height on releases that verify it, so it needs no
/// activation or tip. What it signs is valid in a block at H.
#[test]
fn sign_in_a_process_without_activation_produces_v2_for_40204() {
    assert_eq!(citrate_consensus::hardening::pba_hardening_height(), None);
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut tx = decode(&builder().sign(&key, 0).unwrap().raw);
    assert_eq!(tx.chain_id, Some(40204));
    assert_eq!(signed_version(&tx), Some(NativeSigVersion::V2));
    tx.hash = citrate_consensus::tx_auth::native_tx_id(&tx);
    assert_eq!(verify_for_block(&tx, 40204), Ok(tx.hash));
    // The default chain id is 40204 too.
    let tx = decode(
        &TransactionBuilder::new()
            .to(&format!("0x{}", "22".repeat(20)))
            .sign(&key, 0)
            .unwrap()
            .raw,
    );
    assert_eq!(tx.chain_id, Some(40204));
    assert_eq!(signed_version(&tx), Some(NativeSigVersion::V2));
}
