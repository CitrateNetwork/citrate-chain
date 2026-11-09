// Canonical ECVRF proof encoding, activation-gated.
//
// From `vrf_canonical_encoding_height` the two curve points carried in an
// ECVRF proof (the prover's P-256 key and Gamma) must be in canonical SEC1
// compressed form: tag 0x02/0x03 + x, the exact bytes the point re-encodes
// to. Below the height, the previous decoder applies unchanged.
//
// These tests drive the real entry points: `VrfProposerSelector` (what
// `DagStore::store_block` calls) and `DagStore::store_block` itself, with
// proofs made by the real prover. The compatibility suite replays thousands
// of honestly produced proofs through the strict path to show the rule never
// rejects what the shipped producer makes.

use std::sync::Arc;

use citrate_consensus::dag_store::{DagStore, DagStoreError};
use citrate_consensus::ecvrf::{self, EcvrfError, EcvrfProof};
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, VrfProof};
use citrate_consensus::vrf::{Validator, VrfProposerSelector};
use citrate_consensus::vrf_encoding;
use ed25519_dalek::{Signer, SigningKey};
use sha3::{Digest, Sha3_256};

/// Offsets inside the 114-byte proof: pk(33) || Gamma(33) || c(16) || s(32).
const PK_TAG: usize = 0;
const GAMMA_TAG: usize = 33;

/// SEC1 tag for the 33-byte "compact" form (x only).
const COMPACT_TAG: u8 = 0x05;

fn seed(i: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"vrf-canonical-encoding-test-seed");
    h.update(i.to_le_bytes());
    h.finalize().into()
}

fn proposer_of(secret: &[u8; 32]) -> PublicKey {
    PublicKey::new(SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

/// An honest proof (real prover) for `(secret, prev, slot)` whose Gamma,
/// re-tagged as the compact form, still decodes to the SAME point under the
/// previous decoder. About half of all proofs qualify; scan seeds until one
/// does.
fn honest_proof_with_compact_gamma_twin(
    sel: &VrfProposerSelector,
    prev: &Hash,
    slot: u64,
) -> ([u8; 32], VrfProof, VrfProof) {
    for i in 0..256u64 {
        let secret = seed(i);
        let proposer = proposer_of(&secret);
        let honest = sel
            .generate_vrf_proof(&secret, &proposer, prev, slot)
            .expect("prove");
        let mut twin = honest.clone();
        twin.proof[GAMMA_TAG] = COMPACT_TAG;
        let (Ok(a), Ok(b)) = (
            EcvrfProof::from_bytes(&honest.proof),
            EcvrfProof::from_bytes(&twin.proof),
        ) else {
            continue;
        };
        if a.gamma == b.gamma {
            return (secret, honest, twin);
        }
    }
    panic!("no seed in 0..256 gave a compact-form twin of Gamma");
}

fn accepted(r: Result<bool, citrate_consensus::vrf::VrfError>) -> bool {
    matches!(r, Ok(true))
}

// ---------------------------------------------------------------------------
// Selector entry point
// ---------------------------------------------------------------------------

/// The re-tagged Gamma is a second byte string for the same proof. Below the
/// activation height it verifies (unchanged behaviour); from the height on,
/// it is rejected, while the honest bytes verify on both sides.
#[test]
fn compact_gamma_is_rejected_from_the_activation_height_only() {
    const H: u64 = 1_000;
    let sel = VrfProposerSelector::production().with_canonical_encoding_height(Some(H));
    let prev = Hash::new([0x11; 32]);

    for slot in [H - 1, H, H + 1] {
        let (secret, honest, twin) = honest_proof_with_compact_gamma_twin(&sel, &prev, slot);
        let proposer = proposer_of(&secret);
        assert_ne!(honest.proof, twin.proof);
        assert_eq!(honest.output, twin.output, "same point, same VRF output");

        assert!(
            accepted(sel.verify_vrf_math_only(&proposer, &honest, &prev, slot)),
            "honest proof verifies at slot {slot}"
        );
        let twin_ok = accepted(sel.verify_vrf_math_only(&proposer, &twin, &prev, slot));
        if slot < H {
            assert!(
                twin_ok,
                "below the activation height the previous decoder applies unchanged"
            );
        } else {
            assert!(
                !twin_ok,
                "from the activation height a non-canonical Gamma must not verify (slot {slot})"
            );
        }
    }
}

/// With the rule not scheduled (the 40204 default) nothing changes at any
/// height: the selector judges proofs exactly as before.
#[test]
fn unscheduled_rule_changes_nothing_at_any_height() {
    let sel = VrfProposerSelector::production().with_canonical_encoding_height(None);
    let prev = Hash::new([0x22; 32]);
    for slot in [1u64, 1_000, u64::MAX / 2] {
        let (secret, honest, twin) = honest_proof_with_compact_gamma_twin(&sel, &prev, slot);
        let proposer = proposer_of(&secret);
        assert!(accepted(
            sel.verify_vrf_math_only(&proposer, &honest, &prev, slot)
        ));
        assert!(accepted(
            sel.verify_vrf_math_only(&proposer, &twin, &prev, slot)
        ));
    }
}

/// The selector's default comes from the process store, which is unset in a
/// fresh process (the 40204 default): no behaviour change without a height.
#[test]
fn selector_default_is_the_process_store() {
    assert_eq!(vrf_encoding::vrf_canonical_encoding_height(), None);
    assert_eq!(VrfProposerSelector::new().canonical_encoding_height(), None);
    assert_eq!(
        VrfProposerSelector::production().canonical_encoding_height(),
        None
    );
}

// ---------------------------------------------------------------------------
// Decoder: every tag, every malformed variant
// ---------------------------------------------------------------------------

/// Sweep every tag byte for Gamma and for the key. The canonical decoder
/// accepts only 0x02/0x03. The opposite parity tag is the canonical encoding
/// of a DIFFERENT point (the negation), so it decodes but the proof no longer
/// verifies; every other tag is refused at decode.
#[test]
fn canonical_decoder_accepts_only_compressed_tags() {
    let alpha = b"tag sweep";
    let (proof, _) = ecvrf::prove(&seed(7), alpha).expect("prove");
    let honest = proof.to_bytes();
    EcvrfProof::from_bytes_canonical(&honest).expect("honest bytes are canonical");

    for at in [PK_TAG, GAMMA_TAG] {
        let own = *honest.get(at).expect("tag");
        for tag in 0u8..=255 {
            if tag == own {
                continue;
            }
            let mut b = honest.clone();
            *b.get_mut(at).expect("tag") = tag;
            match EcvrfProof::from_bytes_canonical(&b) {
                Ok(d) => {
                    assert_eq!(tag, own ^ 0x01, "only the opposite parity tag decodes");
                    assert!(
                        ecvrf::verify(alpha, &d).is_err(),
                        "the negated point must not verify (offset {at})"
                    );
                }
                Err(_) => assert!(
                    tag != own ^ 0x01,
                    "opposite parity names a valid point; it must decode"
                ),
            }
        }
    }
}

/// x >= p (the field modulus) is never a valid coordinate: both decoders
/// reject it, so there is no second x for one point either.
#[test]
fn out_of_range_x_is_rejected_by_both_decoders() {
    let (proof, _) = ecvrf::prove(&seed(8), b"x range").expect("prove");
    let mut b = proof.to_bytes();
    for byte in b.get_mut(GAMMA_TAG + 1..GAMMA_TAG + 33).expect("gamma x") {
        *byte = 0xFF;
    }
    assert!(EcvrfProof::from_bytes(&b).is_err());
    assert!(EcvrfProof::from_bytes_canonical(&b).is_err());
}

/// The canonical decoder names the failure, so a rejected block logs why.
#[test]
fn canonical_decoder_reports_non_canonical_encoding() {
    let sel = VrfProposerSelector::production();
    let (_, _, twin) = honest_proof_with_compact_gamma_twin(&sel, &Hash::new([3; 32]), 5);
    assert!(matches!(
        EcvrfProof::from_bytes_canonical(&twin.proof),
        Err(EcvrfError::NonCanonicalEncoding)
    ));
    // The previous decoder accepts the same bytes (pinned: below the height).
    assert!(EcvrfProof::from_bytes(&twin.proof).is_ok());
}

// ---------------------------------------------------------------------------
// Compatibility: honestly produced proofs always pass the strict path
// ---------------------------------------------------------------------------

/// Replay 2,048 proofs from the real prover (the selector API and the raw
/// `ecvrf::prove` the node's producer calls), across many keys, parents and
/// heights, through the strict path. Every one must decode canonically,
/// re-encode to the same bytes, and verify at and above the height.
#[test]
fn every_honest_proof_passes_the_strict_path() {
    const H: u64 = 1;
    let strict = VrfProposerSelector::production().with_canonical_encoding_height(Some(H));
    let mut tags = [0usize; 2];
    for i in 0..1_024u64 {
        let secret = seed(10_000 + i);
        let proposer = proposer_of(&secret);
        let prev = Hash::new(seed(20_000 + i));
        let slot = H + i * 7_919;

        // Selector prover (same alpha + encoding as node/src/producer.rs).
        let p = strict
            .generate_vrf_proof(&secret, &proposer, &prev, slot)
            .expect("prove");
        assert_eq!(p.proof.len(), 114);
        assert!(
            accepted(strict.verify_vrf_math_only(&proposer, &p, &prev, slot)),
            "honest proof {i} must verify under the strict rule"
        );
        let d = EcvrfProof::from_bytes_canonical(&p.proof).expect("canonical");
        assert_eq!(
            d.to_bytes(),
            p.proof,
            "honest bytes are the canonical bytes"
        );

        // Raw prover, arbitrary alpha.
        let alpha = seed(30_000 + i);
        let (raw, beta) = ecvrf::prove(&secret, &alpha).expect("prove");
        let bytes = raw.to_bytes();
        let d = EcvrfProof::from_bytes_canonical(&bytes).expect("canonical");
        assert_eq!(ecvrf::verify(&alpha, &d).expect("verify"), beta);
        for at in [PK_TAG, GAMMA_TAG] {
            let tag = *bytes.get(at).expect("tag");
            assert!(tag == 0x02 || tag == 0x03, "honest tag {tag:#04x}");
            tags[usize::from(tag - 0x02)] += 1;
        }
    }
    // Both parities occur, so the sweep covered both canonical tags.
    assert!(tags[0] > 0 && tags[1] > 0, "{tags:?}");
}

// ---------------------------------------------------------------------------
// DagStore::store_block entry point
// ---------------------------------------------------------------------------

fn genesis() -> Block {
    BlockBuilder::new()
        .hash(Hash::new([0xFE; 32]))
        .height(0)
        .parent(Hash::default())
        .build_unhashed()
}

/// A child of `parent` at height 1 carrying `vrf`, signed by `secret` over
/// its canonical block hash (which commits to the proof bytes).
fn signed_child(parent: &Block, secret: &[u8; 32], vrf: VrfProof) -> Block {
    let key = SigningKey::from_bytes(secret);
    let mut b = BlockBuilder::new()
        .height(1)
        .parent(parent.hash())
        .proposer(proposer_of(secret))
        .vrf_reveal(vrf)
        .build();
    b.signature = Signature::new(key.sign(b.header.block_hash.as_bytes()).to_bytes());
    b
}

async fn store_with(selector: VrfProposerSelector, secret: &[u8; 32]) -> DagStore {
    let selector = Arc::new(selector.with_min_stake(1));
    selector
        .register_validator(Validator {
            pubkey: proposer_of(secret),
            stake: 1_000_000,
            is_active: true,
        })
        .await;
    let store = DagStore::with_strict_vrf(true).with_proposer_selector(selector);
    store.store_block(genesis()).await.expect("genesis");
    store
}

/// A block whose proof is re-encoded with a compact Gamma (signed by its own
/// producer, so it is otherwise valid) is admitted below the height and
/// refused from it. The honest block is admitted on both sides.
#[tokio::test]
async fn store_block_refuses_non_canonical_proof_from_the_height() {
    let prev = genesis().header.vrf_reveal.output;
    let probe = VrfProposerSelector::production();
    let (secret, honest, twin) = honest_proof_with_compact_gamma_twin(&probe, &prev, 1);

    // Activation at 1: the height-1 block is judged by the canonical rule.
    let strict = store_with(
        VrfProposerSelector::production().with_canonical_encoding_height(Some(1)),
        &secret,
    )
    .await;
    let r = strict
        .store_block(signed_child(&genesis(), &secret, twin.clone()))
        .await;
    assert!(
        matches!(r, Err(DagStoreError::InvalidVrf(_))),
        "non-canonical proof must be refused from the activation height, got {r:?}"
    );
    strict
        .store_block(signed_child(&genesis(), &secret, honest.clone()))
        .await
        .expect("honest block admitted under the strict rule");

    // Activation at 2: the same height-1 block replays exactly as before.
    let before = store_with(
        VrfProposerSelector::production().with_canonical_encoding_height(Some(2)),
        &secret,
    )
    .await;
    before
        .store_block(signed_child(&genesis(), &secret, twin))
        .await
        .expect("below the activation height the block is judged as before");
}
