// Audit findings H-01 + H-02 regression tests.
//
// H-01 (HIGH, liveness): pre-fix `submit_vote` inserted (height,
// voter) into the `voted` replay-protection set BEFORE verifying
// signature, committee membership, or block-hash match. An attacker
// could flood 100 invalid votes with victim pubkeys, locking honest
// voters out of every checkpoint and permanently breaking BFT
// finality.
//
// H-02 (HIGH, replay): pre-fix vote canonical message was just
// `height(8 LE) || block_hash(32) = 40 bytes`. No chain-id, no
// genesis hash, no domain tag. A vote signed for testnet checkpoint
// #50 was byte-identical to a vote on a fork or alternate chain
// with the same height + block hash → cross-chain replay.
//
// Sister TLA+ spec: `specs/tla/consensus/CheckpointVoteSafety.tla`
// (added in WP-B2.1 + WP-B2.2).

use citrate_consensus::checkpoint::{
    canonical_vote_message, CITRATE_VOTE_DOMAIN_SEPARATOR,
};
use citrate_consensus::{
    Block, BlockBuilder, CheckpointConfig, CheckpointManager, CheckpointVote, DagStore, Hash,
    PublicKey, Signature, VrfProof,
};
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;

fn test_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = 0x42;
    SigningKey::from_bytes(&bytes)
}

fn hash_for(n: u64) -> Hash {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&n.to_le_bytes());
    h[31] = 0xFF;
    Hash::new(h)
}

fn make_block(hash: Hash, parent: Hash, height: u64) -> Block {
    BlockBuilder::new()
        .hash(hash)
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height * 10)
        .blue_score(height + 1)
        .blue_work((height + 1) as u128 * 100)
        .proposer(PublicKey::new([0xAB; 32]))
        .vrf_reveal(VrfProof {
            proof: vec![0u8; 80],
            output: Hash::new([0xCD; 32]),
        })
        .build_unhashed()
}

fn signed_vote_for_chain(
    sk: &SigningKey,
    height: u64,
    block_hash: Hash,
    chain_id: u64,
) -> CheckpointVote {
    let pubkey_bytes = sk.verifying_key().to_bytes();
    let message = canonical_vote_message(chain_id, height, &block_hash);
    let sig = sk.sign(&message);
    CheckpointVote {
        height,
        block_hash,
        voter: PublicKey::new(pubkey_bytes),
        signature: Signature::new(sig.to_bytes()),
    }
}

/// H-01: a flood of invalid votes with victim pubkeys MUST NOT
/// pollute the `voted` set. Honest voters must still be able to
/// reach quorum after the flood.
#[tokio::test]
async fn h01_invalid_vote_flood_does_not_lock_out_honest_voters() {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let cfg = CheckpointConfig::for_testing();
    let chain_id = cfg.chain_id;
    let mgr = CheckpointManager::new(cfg, dag.clone());

    let block = make_block(hash_for(50), hash_for(49), 50);
    dag.store_block(block).await.expect("block admit");

    // 5 honest committee members; quorum = 4.
    let honest_keys: Vec<SigningKey> = (0..5).map(test_key).collect();
    let committee: Vec<PublicKey> = honest_keys
        .iter()
        .map(|k| PublicKey::new(k.verifying_key().to_bytes()))
        .collect();

    mgr.propose(50, hash_for(50), committee.clone())
        .await
        .expect("propose");

    // Attacker constructs garbage votes claiming to be each honest
    // member. Pre-fix, each `submit_vote` would mark (height, voter)
    // as voted before signature verification — locking the honest
    // voter out forever. Post-fix, signature verification fails and
    // the voted set is left untouched.
    for honest_pk in &committee {
        let bad = CheckpointVote {
            height: 50,
            block_hash: hash_for(50),
            voter: *honest_pk,
            signature: Signature::new([0xEE; 64]), // garbage
        };
        let res = mgr.submit_vote(bad).await;
        assert!(
            res.is_err(),
            "H-01: garbage-sig vote with victim's pubkey must be rejected"
        );
    }

    // Now honest voters cast their (real) votes. All 4 needed to
    // hit quorum MUST succeed.
    for (i, sk) in honest_keys.iter().enumerate().take(4) {
        let vote = signed_vote_for_chain(sk, 50, hash_for(50), chain_id);
        let reached = mgr
            .submit_vote(vote)
            .await
            .unwrap_or_else(|e| panic!(
                "H-01: honest voter #{i} rejected after attacker flood: {:?}",
                e
            ));
        if i < 3 {
            assert!(!reached);
        } else {
            assert!(reached, "H-01: honest quorum must be reachable post-flood");
        }
    }
}

/// H-02: a vote signed for chain A MUST be rejected on chain B
/// because chain_id is bound into the canonical message.
#[tokio::test]
async fn h02_cross_chain_vote_replay_rejected() {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let mut cfg = CheckpointConfig::for_testing();
    cfg.chain_id = 11_111; // chain "A"
    let mgr = CheckpointManager::new(cfg, dag.clone());

    let block = make_block(hash_for(50), hash_for(49), 50);
    dag.store_block(block).await.expect("block admit");

    let sk = test_key(7);
    let pk = PublicKey::new(sk.verifying_key().to_bytes());
    mgr.propose(50, hash_for(50), vec![pk])
        .await
        .expect("propose");

    // Vote signed for chain "B" (a different chain_id) — must be
    // rejected on this manager (which expects chain "A").
    let cross_chain_vote = signed_vote_for_chain(&sk, 50, hash_for(50), 22_222);
    let res = mgr.submit_vote(cross_chain_vote).await;
    assert!(
        res.is_err(),
        "H-02: cross-chain vote replay must be rejected"
    );

    // Same vote signed for chain "A" must be accepted.
    let in_chain_vote = signed_vote_for_chain(&sk, 50, hash_for(50), 11_111);
    mgr.submit_vote(in_chain_vote)
        .await
        .expect("H-02: in-chain vote must be accepted");
}

/// H-02 prefix sanity check: the canonical message format includes
/// the documented domain separator + chain_id + height + hash, in
/// that exact order. Pin the byte layout so a future refactor can't
/// silently change the prefix and divorce verifier from signer.
#[test]
fn h02_canonical_message_layout_pinned() {
    let chain_id = 0x0102030405060708u64;
    let height = 0xFEDCBA9876543210u64;
    let block_hash = Hash::new([0xAA; 32]);

    let msg = canonical_vote_message(chain_id, height, &block_hash);

    // Layout: separator (21) + chain_id (8) + height (8) + hash (32) = 69
    assert_eq!(msg.len(), CITRATE_VOTE_DOMAIN_SEPARATOR.len() + 8 + 8 + 32);
    assert_eq!(msg.len(), 69);

    // Domain separator at the start.
    assert_eq!(&msg[..CITRATE_VOTE_DOMAIN_SEPARATOR.len()], CITRATE_VOTE_DOMAIN_SEPARATOR);

    // chain_id immediately after separator, little-endian.
    let chain_start = CITRATE_VOTE_DOMAIN_SEPARATOR.len();
    assert_eq!(&msg[chain_start..chain_start + 8], &chain_id.to_le_bytes());

    // height after chain_id, little-endian.
    let height_start = chain_start + 8;
    assert_eq!(&msg[height_start..height_start + 8], &height.to_le_bytes());

    // block_hash at the tail.
    let hash_start = height_start + 8;
    assert_eq!(&msg[hash_start..], block_hash.as_bytes());
}

/// H-01 + H-02 combined: an attacker who knows the legacy 40-byte
/// canonical-message format constructs a vote signed over that old
/// format. The post-fix verifier (which uses the 69-byte canonical
/// message) MUST reject it AND must NOT mark the voter as having
/// voted (so the honest voter can still cast a valid vote).
#[tokio::test]
async fn h01_h02_legacy_signed_vote_rejected_voter_not_locked() {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let cfg = CheckpointConfig::for_testing();
    let chain_id = cfg.chain_id;
    let mgr = CheckpointManager::new(cfg, dag.clone());

    let block = make_block(hash_for(50), hash_for(49), 50);
    dag.store_block(block).await.expect("block admit");

    let sk = test_key(9);
    let pk = PublicKey::new(sk.verifying_key().to_bytes());
    mgr.propose(50, hash_for(50), vec![pk])
        .await
        .expect("propose");

    // Construct a vote signed over the LEGACY 40-byte canonical
    // (no domain separator, no chain_id) — what the attacker would
    // produce if they replayed a pre-fix vote.
    let mut legacy_msg = Vec::with_capacity(40);
    legacy_msg.extend_from_slice(&50u64.to_le_bytes());
    legacy_msg.extend_from_slice(hash_for(50).as_bytes());
    let legacy_sig = sk.sign(&legacy_msg);
    let legacy_vote = CheckpointVote {
        height: 50,
        block_hash: hash_for(50),
        voter: pk,
        signature: Signature::new(legacy_sig.to_bytes()),
    };

    let res = mgr.submit_vote(legacy_vote).await;
    assert!(res.is_err(), "H-02: legacy-canonical-format vote must be rejected");

    // The honest voter's NEW vote must still succeed.
    let honest_vote = signed_vote_for_chain(&sk, 50, hash_for(50), chain_id);
    mgr.submit_vote(honest_vote)
        .await
        .expect("H-01: honest vote must succeed after legacy attempt rejected");
}
