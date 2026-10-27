// Canonical ECVRF proof encoding: selectors pick up the PUBLISHED height.
//
// Node start-up publishes the activation height once
// (`vrf_encoding::init_for_chain`, which calls
// `set_vrf_canonical_encoding_height`) and every selector built afterwards must
// enforce it without being told: the selector `start_node` attaches to the DAG
// store (`VrfProposerSelector::production()`), a plain `new()` selector, and
// the selector `DagStore` builds for itself when none is attached. The tests in
// `vrf_canonical_encoding.rs` inject the height with
// `with_canonical_encoding_height`, so they cannot see a selector that stopped
// reading the published value.
//
// The published height is process-global, so this file is its own test binary
// and every test publishes the SAME height.

use citrate_consensus::dag_store::{DagStore, DagStoreError};
use citrate_consensus::ecvrf::EcvrfProof;
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, VrfProof};
use citrate_consensus::vrf::VrfProposerSelector;
use citrate_consensus::vrf_encoding;
use ed25519_dalek::{Signer, SigningKey};
use sha3::{Digest, Sha3_256};

/// The published activation height. Block 1 (the first non-genesis block) is
/// judged by the canonical rule.
const H: u64 = 1;

/// Offset of Gamma's SEC1 tag inside the 114-byte proof.
const GAMMA_TAG: usize = 33;
/// SEC1 tag for the 33-byte "compact" form (x only).
const COMPACT_TAG: u8 = 0x05;

fn publish() {
    vrf_encoding::set_vrf_canonical_encoding_height(Some(H));
}

fn seed(i: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"vrf-canonical-encoding-published-height-seed");
    h.update(i.to_le_bytes());
    h.finalize().into()
}

fn proposer_of(secret: &[u8; 32]) -> PublicKey {
    PublicKey::new(SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

/// An honest proof for `(secret, prev, slot)` and its twin with Gamma
/// re-tagged in compact form, which the previous decoder reads as the same
/// point. The prover does not depend on the encoding height.
fn honest_and_compact_twin(prev: &Hash, slot: u64) -> ([u8; 32], VrfProof, VrfProof) {
    let prover = VrfProposerSelector::production().with_canonical_encoding_height(None);
    for i in 0..256u64 {
        let secret = seed(i);
        let honest = prover
            .generate_vrf_proof(&secret, &proposer_of(&secret), prev, slot)
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

fn verifies(sel: &VrfProposerSelector, secret: &[u8; 32], p: &VrfProof, prev: &Hash) -> bool {
    matches!(
        sel.verify_vrf_math_only(&proposer_of(secret), p, prev, H),
        Ok(true)
    )
}

/// `production()` and `new()` built after the height is published read it and
/// refuse the non-canonical twin at that height. Negative control: the same
/// twin verifies under a selector told the rule is unscheduled, so the refusal
/// comes from the published height and not from a broken proof.
#[test]
fn selectors_built_after_publication_enforce_the_published_height() {
    publish();
    let prev = Hash::new([0x44; 32]);
    let (secret, honest, twin) = honest_and_compact_twin(&prev, H);

    let lenient = VrfProposerSelector::production().with_canonical_encoding_height(None);
    assert!(
        verifies(&lenient, &secret, &twin, &prev),
        "control: the twin verifies when the rule is not scheduled"
    );

    for (what, sel) in [
        ("production()", VrfProposerSelector::production()),
        ("new()", VrfProposerSelector::new()),
    ] {
        assert_eq!(
            sel.canonical_encoding_height(),
            Some(H),
            "{what} carries the published height"
        );
        assert!(
            verifies(&sel, &secret, &honest, &prev),
            "{what}: the honest proof verifies at the published height"
        );
        assert!(
            !verifies(&sel, &secret, &twin, &prev),
            "{what}: a non-canonical proof must be refused at the published height"
        );
    }
}

fn genesis() -> Block {
    BlockBuilder::new()
        .hash(Hash::new([0xFE; 32]))
        .height(0)
        .parent(Hash::default())
        .build_unhashed()
}

fn signed_child(parent: &Block, secret: &[u8; 32], vrf: VrfProof) -> Block {
    let key = SigningKey::from_bytes(secret);
    let mut b = BlockBuilder::new()
        .height(H)
        .parent(parent.hash())
        .proposer(proposer_of(secret))
        .vrf_reveal(vrf)
        .build();
    b.signature = Signature::new(key.sign(b.header.block_hash.as_bytes()).to_bytes());
    b
}

/// A strict `DagStore` with NO selector attached builds its own fallback
/// selector per block; that selector must also read the published height. The
/// honest block is admitted, its non-canonical twin is refused.
#[tokio::test]
async fn dag_store_without_a_selector_enforces_the_published_height() {
    publish();
    let prev = genesis().header.vrf_reveal.output;
    let (secret, honest, twin) = honest_and_compact_twin(&prev, H);

    let store = DagStore::with_strict_vrf(true);
    store.store_block(genesis()).await.expect("genesis");
    let r = store
        .store_block(signed_child(&genesis(), &secret, twin))
        .await;
    assert!(
        matches!(r, Err(DagStoreError::InvalidVrf(_))),
        "the fallback selector must refuse a non-canonical proof at the published height, got {r:?}"
    );
    store
        .store_block(signed_child(&genesis(), &secret, honest))
        .await
        .expect("honest block admitted");
}
