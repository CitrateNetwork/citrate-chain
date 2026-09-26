// citrate/core/consensus/src/native_sig.rs
//
// Native (ed25519) transaction signature versions, and when each is valid.
//
// Two signing digests exist for native transactions (see `crypto`):
//
//   * V1 (`crypto::canonical_signing_bytes`): nonce, from, to, value, gas and
//     data. It does not include the chain id.
//   * V2 (`crypto::canonical_tx_bytes_v2`): a domain tag, the chain id and every
//     other consensus field.
//
// V1 is retired at the same activation height as the rest of the block-validity
// hardening (`hardening::PbaHardening`), so there is one fork, not two:
//
//   * Block validity: a native transaction in a block at height `h` must carry
//     a V2 signature when `active_at(h)`. Below that, V1 and V2 are both valid,
//     exactly as before (legacy import does not re-verify signatures at all).
//   * Mempool: a transaction admitted while the tip is `t` can first be mined at
//     `t + 1`, so V1 is refused once `active_at(t + 1)`, that is from tip `H - 1`
//     onward. Pooled V1 transactions are evicted at the same point.
//   * Signers: produce V2 once the next block is at or above `H`
//     ([`signer_version`]). Before that they keep producing V1, so a client of
//     this release still interoperates with nodes that predate V2.
//
// EVM (secp256k1) transactions are unaffected: EIP-155 already binds the chain.

use crate::crypto::{self, CryptoError, Ed25519SigningKey};
use crate::hardening::PbaHardening;
use crate::types::{PublicKey, Transaction};
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};

/// Which digest a native signature covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSigVersion {
    /// Legacy digest, no chain id. Invalid from the activation height.
    V1,
    /// Chain-bound digest under a domain tag.
    V2,
}

/// Whether a V1 native signature is valid in a block at `height`.
pub fn v1_valid_in_block(hardening: PbaHardening, height: u64) -> bool {
    !hardening.active_at(height)
}

/// Whether the mempool may still admit (or keep) a V1 native transaction
/// while the applied tip is `tip_height`. The earliest block such a
/// transaction can land in is `tip_height + 1`.
pub fn v1_accepted_at_tip(hardening: PbaHardening, tip_height: u64) -> bool {
    v1_valid_in_block(hardening, tip_height.saturating_add(1))
}

/// The version a signer should produce.
///
/// * `activation`: the activation height the signer knows for its chain
///   (`None` = not scheduled).
/// * `tip_height`: the chain tip the signer last saw, if it knows it.
///
/// With no activation scheduled the answer is V1 (every node accepts it).
/// With one scheduled, V2 once the next block is at or above it. A signer that
/// knows the activation but not the tip produces V2: any node that knows the
/// activation height is a release that verifies V2.
pub fn signer_version(activation: Option<u64>, tip_height: Option<u64>) -> NativeSigVersion {
    match (activation, tip_height) {
        (None, _) => NativeSigVersion::V1,
        (Some(a), Some(tip)) => {
            if v1_accepted_at_tip(PbaHardening::at(a), tip) {
                NativeSigVersion::V1
            } else {
                NativeSigVersion::V2
            }
        }
        (Some(_), None) => NativeSigVersion::V2,
    }
}

/// Sign `tx` with `key` under `version`. V2 requires `tx.chain_id`.
pub fn sign_native(
    tx: &mut Transaction,
    key: &Ed25519SigningKey,
    version: NativeSigVersion,
) -> Result<(), CryptoError> {
    match version {
        NativeSigVersion::V1 => crypto::sign_transaction(tx, key),
        NativeSigVersion::V2 => crypto::sign_transaction_v2(tx, key),
    }
}

/// The version whose digest `tx.signature` verifies under `tx.from`, V2 first.
/// `None` when neither verifies (or `from` is not a valid ed25519 key).
///
/// For a native (non-EVM-shaped) sender only; an EVM sender is never a valid
/// ed25519 key in practice, and callers dispatch on the sender shape first.
pub fn signed_version(tx: &Transaction) -> Option<NativeSigVersion> {
    let key = VerifyingKey::from_bytes(tx.from.as_bytes()).ok()?;
    let sig = DalekSignature::from_bytes(tx.signature.as_bytes());
    if key.verify(&crypto::canonical_tx_bytes_v2(tx), &sig).is_ok() {
        return Some(NativeSigVersion::V2);
    }
    if key
        .verify(&crypto::canonical_signing_bytes(tx), &sig)
        .is_ok()
    {
        return Some(NativeSigVersion::V1);
    }
    None
}

/// A signature for a small-order public key that verifies without the secret key: `from` is the
/// order-2 point, `R` the identity and `s = 0`. Non-strict ed25519
/// verification accepts it for about half of all messages. Test fixture for
/// the strict-verification rule.
#[doc(hidden)]
pub fn small_order_key_signature(
    template: &Transaction,
    want: NativeSigVersion,
) -> Option<Transaction> {
    let mut key = [0xffu8; 32];
    key[0] = 0xec;
    key[31] = 0x7f;
    let mut sig = [0u8; 64];
    sig[0] = 1;
    for bump in 0..256u64 {
        let mut tx = template.clone();
        tx.from = PublicKey::new(key);
        tx.signature = crate::types::Signature::new(sig);
        tx.gas_price = template.gas_price.wrapping_add(bump);
        if signed_version(&tx) == Some(want) {
            tx.hash = crate::tx_auth::native_tx_id(&tx);
            return Some(tx);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PublicKey;
    use proptest::prelude::*;

    fn tx(chain: Option<u64>) -> Transaction {
        Transaction {
            nonce: 3,
            to: Some(PublicKey::new([0xB0; 32])),
            value: 1_000,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            data: vec![9, 8, 7],
            chain_id: chain,
            ..Default::default()
        }
    }

    #[test]
    fn block_and_mempool_windows() {
        let h = PbaHardening::at(100);
        assert!(v1_valid_in_block(h, 99));
        assert!(!v1_valid_in_block(h, 100));
        assert!(!v1_valid_in_block(h, 101));
        // Mempool: tip 98 -> next block 99 (V1 fine); tip 99 -> next block 100.
        assert!(v1_accepted_at_tip(h, 98));
        assert!(!v1_accepted_at_tip(h, 99));
        assert!(!v1_accepted_at_tip(h, 100));
        assert!(v1_accepted_at_tip(PbaHardening::off(), u64::MAX - 1));
        assert!(v1_accepted_at_tip(PbaHardening::off(), u64::MAX));
        // Genesis is never re-judged; with H = 0 the first block is height 1.
        assert!(v1_valid_in_block(PbaHardening::at(0), 0));
        assert!(!v1_accepted_at_tip(PbaHardening::at(0), 0));
    }

    #[test]
    fn signer_switches_at_h_minus_one() {
        assert_eq!(signer_version(None, Some(10)), NativeSigVersion::V1);
        assert_eq!(signer_version(None, None), NativeSigVersion::V1);
        assert_eq!(signer_version(Some(100), Some(98)), NativeSigVersion::V1);
        assert_eq!(signer_version(Some(100), Some(99)), NativeSigVersion::V2);
        assert_eq!(signer_version(Some(100), Some(500)), NativeSigVersion::V2);
        assert_eq!(signer_version(Some(100), None), NativeSigVersion::V2);
        assert_eq!(signer_version(Some(0), Some(0)), NativeSigVersion::V2);
    }

    #[test]
    fn signed_version_identifies_each_digest() {
        let sk = Ed25519SigningKey::from_bytes(&[7; 32]);
        let mut a = tx(Some(40204));
        sign_native(&mut a, &sk, NativeSigVersion::V1).unwrap();
        assert_eq!(signed_version(&a), Some(NativeSigVersion::V1));
        let mut b = tx(Some(40204));
        sign_native(&mut b, &sk, NativeSigVersion::V2).unwrap();
        assert_eq!(signed_version(&b), Some(NativeSigVersion::V2));
        // Changing the chain id breaks V2; V1 does not cover it.
        let mut a2 = a.clone();
        a2.chain_id = Some(1);
        assert_eq!(signed_version(&a2), Some(NativeSigVersion::V1));
        let mut b2 = b.clone();
        b2.chain_id = Some(1);
        assert_eq!(signed_version(&b2), None);
        // V2 needs a chain id to bind.
        let mut c = tx(None);
        assert!(sign_native(&mut c, &sk, NativeSigVersion::V2).is_err());
        // Garbage signature / non-key sender.
        let mut d = b.clone();
        d.signature = crate::types::Signature::new([1; 64]);
        assert_eq!(signed_version(&d), None);
    }

    /// Why a V1 digest can never be a V2 digest for a key anyone holds: a byte
    /// string that parses as both puts the sender key at offset 8 (V1) and
    /// right after the 21-byte tag, the chain id and the nonce (V2). The V1
    /// key's first 13 bytes are then the tail of the V2 domain tag, a fixed
    /// ASCII string. An ed25519 key with that prefix takes about 2^104 work
    /// to produce. This test pins the tag layout the argument relies on.
    #[test]
    fn v2_tag_layout_pins_the_disjointness_argument() {
        assert_eq!(crypto::NATIVE_TX_V2_DOMAIN.len(), 21);
        let t = tx(Some(40204));
        let v2 = crypto::canonical_tx_bytes_v2(&t);
        assert!(v2.starts_with(crypto::NATIVE_TX_V2_DOMAIN));
        // V2: tag(21) | chain flag(1) | chain(8) | nonce(8) | from(32)
        assert_eq!(&v2[38..70], t.from.as_bytes());
        let v1 = crypto::canonical_signing_bytes(&t);
        // V1: nonce(8) | from(32)
        assert_eq!(&v1[8..40], t.from.as_bytes());
    }

    proptest! {
        /// The V1 and V2 digests of any two transactions never coincide, so a
        /// signature over one can never be presented as the other.
        #[test]
        fn v1_and_v2_digests_never_collide(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
            nonce_a in any::<u64>(),
            nonce_b in any::<u64>(),
            chain_b in any::<u64>(),
            value in any::<u128>(),
            gas in any::<u64>(),
            data_a in proptest::collection::vec(any::<u8>(), 0..96),
            data_b in proptest::collection::vec(any::<u8>(), 0..96),
            to_a in proptest::option::of(any::<[u8; 32]>()),
            to_b in proptest::option::of(any::<[u8; 32]>()),
        ) {
            let ka = Ed25519SigningKey::from_bytes(&seed_a);
            let kb = Ed25519SigningKey::from_bytes(&seed_b);
            let a = Transaction {
                nonce: nonce_a,
                from: PublicKey::new(ka.verifying_key().to_bytes()),
                to: to_a.map(PublicKey::new),
                value,
                gas_limit: gas,
                gas_price: gas,
                data: data_a,
                chain_id: Some(chain_b ^ 1),
                ..Default::default()
            };
            let b = Transaction {
                nonce: nonce_b,
                from: PublicKey::new(kb.verifying_key().to_bytes()),
                to: to_b.map(PublicKey::new),
                value,
                gas_limit: gas,
                gas_price: gas,
                data: data_b,
                chain_id: Some(chain_b),
                ..Default::default()
            };
            prop_assert_ne!(crypto::canonical_signing_bytes(&a), crypto::canonical_tx_bytes_v2(&b));
            prop_assert_ne!(crypto::canonical_signing_bytes(&b), crypto::canonical_tx_bytes_v2(&a));
            // Same transaction, both digests.
            prop_assert_ne!(crypto::canonical_signing_bytes(&a), crypto::canonical_tx_bytes_v2(&a));
            // A V1 signature never verifies as V2 and vice versa.
            let mut s1 = a.clone();
            sign_native(&mut s1, &ka, NativeSigVersion::V1).unwrap();
            prop_assert_eq!(signed_version(&s1), Some(NativeSigVersion::V1));
            let mut s2 = a.clone();
            sign_native(&mut s2, &ka, NativeSigVersion::V2).unwrap();
            prop_assert_eq!(signed_version(&s2), Some(NativeSigVersion::V2));
        }
    }
}
