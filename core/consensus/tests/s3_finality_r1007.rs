//! S3-5 / ADR CV-8: checkpoint finality on r1007, and the G11 pruning point.
//! Spec: planset 2026-11-03-r1007-v060, `06_CONSENSUS_SPEC.md` §7 (finality)
//! and §2 G11 (pruning point), reviewer question R8 (quorum and committee).
//!
//! Every expectation here is written from the spec, not read back from the
//! implementation: the pruning-point heights are computed in the test from
//! `PRUNING_DEPTH = 10,000` and `CHECKPOINT_INTERVAL = 50` (§1.2), and the
//! vote message layout is the one §7 states.
//!
//! #185: the checkpoint quorum must count stake, and committee selection must
//! not invert stake weighting.

use citrate_consensus::checkpoint::{
    canonical_vote_message, checkpoint_accepted_root, empty_accepted_root, sign_checkpoint_vote,
    CheckpointConfig, CheckpointManager, CheckpointVote, Committee, CommitteeSelector, VoteBinding,
    CITRATE_VOTE_DOMAIN_SEPARATOR,
};
use citrate_consensus::checkpoint_gadget::{
    checkpoint_enforcement_on_for, checkpoint_enforcement_pinned, checkpoint_voting_active,
    FinalityGadget, CHECKPOINT_ENFORCEMENT_GENESES,
};
use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::dag_store::{DagStore, KvStore};
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::hardening::RELEASE_GENESIS;
use citrate_consensus::types::{
    blue_work_for_score, Block, BlockBuilder, GhostDagParams, Hash, PublicKey,
};
use citrate_consensus::vrf::VrfProposerSelector;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const CHAIN: u64 = 40204;

/// Spec §1.2. Written out here, not imported, so the test pins the spec value.
const SPEC_PRUNING_DEPTH: u64 = 10_000;
const SPEC_CHECKPOINT_INTERVAL: u64 = 50;

fn key(i: u8) -> Ed25519SigningKey {
    let mut seed = [0u8; 32];
    seed[0] = i;
    seed[1] = 0x85;
    Ed25519SigningKey::from_bytes(&seed)
}

fn pk(k: &Ed25519SigningKey) -> PublicKey {
    PublicKey::new(k.verifying_key().to_bytes())
}

fn genesis_hash() -> Hash {
    Hash::new([0x07; 32])
}

fn config() -> CheckpointConfig {
    CheckpointConfig {
        interval: 2,
        committee_size: 100,
        quorum_threshold: 67,
        chain_id: CHAIN,
        genesis_hash: genesis_hash(),
        vote_depth: 3,
    }
}

/// Linear chain 0..len, hash [i+1; 32], state root [0xE0 ^ i; 32] (distinct
/// per block, so a vote that binds the wrong block's root is detectable).
async fn dag_with(len: u8) -> Arc<DagStore> {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let mut parent = Hash::default();
    for i in 0..len {
        let b = BlockBuilder::new()
            .hash(Hash::new([i.saturating_add(1); 32]))
            .height(u64::from(i))
            .parent(parent)
            .state_root(Hash::new([0xE0 ^ i; 32]))
            .build_unhashed();
        parent = b.hash();
        dag.store_block(b).await.expect("store test block");
    }
    dag
}

fn block_hash(height: u8) -> Hash {
    Hash::new([height.saturating_add(1); 32])
}

fn state_root_at(height: u8) -> Hash {
    Hash::new([0xE0 ^ height; 32])
}

/// Schedule (EPOCH 1000, LAG 999): S(1) = 1 governs heights 2..=1000.
async fn selector(set: Vec<(PublicKey, u128)>) -> Arc<VrfProposerSelector> {
    let sel = VrfProposerSelector::new().with_snapshot_schedule(1000, 999);
    sel.sync_active_set_at(1, set, 1).await;
    Arc::new(sel)
}

#[derive(Default)]
struct MemKv {
    #[allow(clippy::type_complexity)]
    data: Mutex<HashMap<String, HashMap<Vec<u8>, Vec<u8>>>>,
}

impl KvStore for MemKv {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let d = self.data.lock().map_err(|e| e.to_string())?;
        Ok(d.get(cf).and_then(|m| m.get(key).cloned()))
    }
    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let mut d = self.data.lock().map_err(|e| e.to_string())?;
        d.entry(cf.to_string())
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
        let mut d = self.data.lock().map_err(|e| e.to_string())?;
        if let Some(m) = d.get_mut(cf) {
            m.remove(key);
        }
        Ok(())
    }
    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
        Ok(self.kv_get(cf, key)?.is_some())
    }
    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let d = self.data.lock().map_err(|e| e.to_string())?;
        Ok(d.get(cf)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// CV-8: voting is on from r1007 block 0, with no activation pin
// ---------------------------------------------------------------------------

/// r1007 runs finality voting from genesis (ADR CV-8, spec §7 "On from
/// block 0"). The production constructor is on for every chain id and
/// genesis this build runs: there is no activation height and no per-chain
/// pin. The first boundary with a committee is proposed and voted on.
#[tokio::test]
async fn finality_votes_from_genesis() {
    assert!(
        checkpoint_voting_active(),
        "r1007: voting has no pin, it is on for this build"
    );
    let ks: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let set = ks.iter().map(|k| (pk(k), 1_000u128)).collect();
    let kv: Arc<dyn KvStore> = Arc::new(MemKv::default());
    let mgr = Arc::new(CheckpointManager::with_persistence(
        config(),
        dag_with(12).await,
        kv,
    ));
    // The PRODUCTION constructor: no switch argument.
    let g = FinalityGadget::new(mgr, Some(selector(set).await));
    assert!(g.enabled(), "voting is active on r1007 from block 0");

    // Height 2 is the first checkpoint boundary (interval 2) and S(1) = 1
    // governs it: the gadget proposes and signs there, at the first chance.
    let out = g
        .on_buried_checkpoint(2, block_hash(2), &Hash::new([9; 32]), ks.first())
        .await;
    assert!(out.proposed, "the first boundary is proposed: {out:?}");
    assert!(out.signed_own_vote, "and voted on: {out:?}");
}

// ---------------------------------------------------------------------------
// §7 vote message v2
// ---------------------------------------------------------------------------

/// The vote message is `"CITRATE-CHECKPOINT-V2" ‖ chain_id ‖ genesis_hash ‖
/// epoch ‖ H ‖ block_hash ‖ state_root ‖ accepted_root`. Changing any one of
/// them breaks the signature, and the gadget's own vote binds the values of
/// the block it votes for: its state root, the governing epoch, and the
/// accepted-transactions root.
#[tokio::test]
async fn vote_binds_genesis_epoch_state_root_and_accepted_root() {
    assert_eq!(CITRATE_VOTE_DOMAIN_SEPARATOR, b"CITRATE-CHECKPOINT-V2");
    let binding = VoteBinding {
        epoch: 1,
        state_root: Hash::new([0x51; 32]),
        accepted_root: Hash::new([0xAC; 32]),
    };
    let g0 = genesis_hash();
    let h = Hash::new([0x42; 32]);
    let msg = canonical_vote_message(CHAIN, &g0, 12, &h, &binding);
    let mut expect = b"CITRATE-CHECKPOINT-V2".to_vec();
    expect.extend_from_slice(&CHAIN.to_le_bytes());
    expect.extend_from_slice(g0.as_bytes());
    expect.extend_from_slice(&1u64.to_le_bytes());
    expect.extend_from_slice(&12u64.to_le_bytes());
    expect.extend_from_slice(h.as_bytes());
    expect.extend_from_slice(binding.state_root.as_bytes());
    expect.extend_from_slice(binding.accepted_root.as_bytes());
    assert_eq!(msg, expect, "the §7 layout, byte for byte");

    // Each bound field changes the message.
    let other_genesis = Hash::new([0x08; 32]);
    let variants = [
        canonical_vote_message(CHAIN, &other_genesis, 12, &h, &binding),
        canonical_vote_message(
            CHAIN,
            &g0,
            12,
            &h,
            &VoteBinding {
                epoch: 2,
                ..binding
            },
        ),
        canonical_vote_message(
            CHAIN,
            &g0,
            12,
            &h,
            &VoteBinding {
                state_root: Hash::new([0x52; 32]),
                ..binding
            },
        ),
        canonical_vote_message(
            CHAIN,
            &g0,
            12,
            &h,
            &VoteBinding {
                accepted_root: Hash::new([0xAD; 32]),
                ..binding
            },
        ),
    ];
    for v in &variants {
        assert_ne!(*v, msg);
    }

    // The gadget's own vote at height 4 binds block 4's state root, the
    // epoch whose snapshot governs it (S(1) = 1), and the accepted root.
    let ks: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let set = ks.iter().map(|k| (pk(k), 1_000u128)).collect();
    let kv: Arc<dyn KvStore> = Arc::new(MemKv::default());
    let dag = dag_with(12).await;
    let block4 = dag.get_block(&block_hash(4)).await.expect("block 4");
    let mgr = Arc::new(CheckpointManager::with_persistence(config(), dag, kv));
    let g = FinalityGadget::new(mgr.clone(), Some(selector(set).await));
    let out = g
        .on_buried_checkpoint(4, block_hash(4), &Hash::new([9; 32]), ks.first())
        .await;
    let own = out.outbound.first().expect("own vote");
    assert_eq!(own.binding.state_root, state_root_at(4));
    assert_eq!(own.binding.epoch, 1, "S(1) governs height 4");
    assert_eq!(own.binding.accepted_root, checkpoint_accepted_root(&block4));
    // Until the mergeset lane's accepted_root lands (CV-4a), the accepted
    // root of every block is the root of the empty accepted set.
    assert_eq!(own.binding.accepted_root, empty_accepted_root());

    // A vote for the right block but a wrong state root is not counted.
    let k1 = ks.get(1).expect("k1");
    let wrong = sign_checkpoint_vote(
        CHAIN,
        &genesis_hash(),
        4,
        block_hash(4),
        &VoteBinding {
            state_root: Hash::new([0x99; 32]),
            ..own.binding
        },
        k1,
    );
    assert!(mgr.submit_vote(wrong).await.is_err(), "wrong state root");
    // A vote signed for another genesis does not verify.
    let foreign: CheckpointVote =
        sign_checkpoint_vote(CHAIN, &other_genesis, 4, block_hash(4), &own.binding, k1);
    assert!(mgr.submit_vote(foreign).await.is_err(), "other genesis");
    // The same vote for this genesis does.
    let ok = sign_checkpoint_vote(CHAIN, &genesis_hash(), 4, block_hash(4), &own.binding, k1);
    assert!(mgr.submit_vote(ok).await.is_ok());
}

// ---------------------------------------------------------------------------
// #185: stake, not head count
// ---------------------------------------------------------------------------

/// Committee {whale 100, a 1, b 1, c 1}. Three of four members is the old
/// count quorum (floor(2·4/3)+1 = 3), but they hold 3 of 103 stake, so they
/// must not finalize. The whale's stake alone is > 2/3 of the total.
#[tokio::test]
async fn quorum_is_stake_weighted() {
    let ks: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let stakes = [100u128, 1, 1, 1];
    let members: Vec<(PublicKey, u128)> = ks.iter().map(pk).zip(stakes).collect();
    let committee = Committee {
        epoch: 1,
        members: members.clone(),
    };
    assert_eq!(committee.total_stake(), 103);

    let dag = dag_with(12).await;
    let mgr = CheckpointManager::new(config(), dag);
    mgr.ensure_proposed(4, block_hash(4), committee.clone())
        .await
        .expect("propose");
    let binding = mgr.pending_binding(4).await.expect("binding");
    let vote = |k: &Ed25519SigningKey| {
        sign_checkpoint_vote(CHAIN, &genesis_hash(), 4, block_hash(4), &binding, k)
    };
    for k in &ks[1..] {
        let reached = mgr.submit_vote(vote(k)).await.expect("small vote");
        assert!(!reached, "3 of 103 stake is not a quorum");
    }
    assert!(mgr.finalize_checkpoint(4).await.is_err());
    assert!(mgr.submit_vote(vote(&ks[0])).await.expect("whale vote"));
    let cp = mgr.finalize_checkpoint(4).await.expect("finalizes");
    assert_eq!(cp.voted_stake(), 103);

    // A second checkpoint: the whale alone (100 > 2/3 · 103) is a quorum.
    mgr.ensure_proposed(6, block_hash(6), committee)
        .await
        .expect("propose 6");
    let b6 = mgr.pending_binding(6).await.expect("binding 6");
    let whale = sign_checkpoint_vote(CHAIN, &genesis_hash(), 6, block_hash(6), &b6, &ks[0]);
    assert!(mgr.submit_vote(whale).await.expect("whale"), "stake quorum");
}

/// Committee selection follows stake. Selecting one seat out of {1, 99}
/// over 1,000 seeds must pick the heavy validator about 99% of the time; a
/// selection that sorts ascending on a stake-scaled score picks it less, and
/// a stake-blind one about half the time.
#[test]
fn committee_selection_does_not_invert_stake() {
    let light = pk(&key(1));
    let heavy = pk(&key(2));
    let set = vec![(light, 1u128), (heavy, 99u128)];
    let mut heavy_picks = 0u32;
    for s in 0u32..1_000 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&s.to_le_bytes());
        let c = CommitteeSelector::select(&set, 50, &Hash::new(seed), 1);
        assert_eq!(c.len(), 1);
        if c[0] == heavy {
            heavy_picks += 1;
        }
    }
    assert!(
        heavy_picks >= 950,
        "the 99-stake validator took {heavy_picks}/1000 single seats"
    );

    // Five heavy (1,000) and five light (1) validators, five seats: the
    // committee is (almost always) the heavy five.
    let mut set = Vec::new();
    for i in 0..10u8 {
        set.push((pk(&key(10 + i)), if i < 5 { 1_000u128 } else { 1 }));
    }
    let heavy: Vec<PublicKey> = set.iter().take(5).map(|(p, _)| *p).collect();
    let mut heavy_seats = 0usize;
    for s in 0u32..200 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&s.to_le_bytes());
        for m in CommitteeSelector::select(&set, 50, &Hash::new(seed), 5) {
            if heavy.contains(&m) {
                heavy_seats += 1;
            }
        }
    }
    assert!(
        heavy_seats >= 950,
        "heavy validators took {heavy_seats}/1000 seats"
    );

    // The weighted form reports each member's stake, which the quorum counts.
    let w = CommitteeSelector::select_weighted(&set, 50, &Hash::new([3; 32]), 10);
    assert_eq!(w.len(), 10, "everyone fits: the whole set is the committee");
    let total: u128 = w.iter().map(|(_, s)| *s).sum();
    assert_eq!(total, 5 * 1_000 + 5);
}

// ---------------------------------------------------------------------------
// CV-8: enforcement off until governance flips it
// ---------------------------------------------------------------------------

/// Enforcement (refusing reorgs below the finalized checkpoint) is off for
/// every chain and genesis this build knows. It is keyed by (chain id,
/// genesis hash), not chain id alone, because r1006 and r1007 share 40204.
/// The flip is a governance decision after the soak (G5): a reviewed change
/// that lists the r1007 genesis in `CHECKPOINT_ENFORCEMENT_GENESES`.
#[test]
fn enforcement_off_by_default_until_governance_flip() {
    assert!(
        CHECKPOINT_ENFORCEMENT_GENESES.is_empty(),
        "no genesis is enforced before the governance flip"
    );
    for (chain, g) in RELEASE_GENESIS {
        assert!(!checkpoint_enforcement_pinned(*chain, &Hash::new(*g)));
    }
    assert!(!checkpoint_enforcement_pinned(CHAIN, &genesis_hash()));
    assert!(!checkpoint_enforcement_pinned(1337, &Hash::default()));

    // The flip mechanism: a listed (chain, genesis) pair, and only that pair.
    let flipped = [(CHAIN, [0x07u8; 32])];
    assert!(checkpoint_enforcement_on_for(
        &flipped,
        CHAIN,
        &genesis_hash()
    ));
    assert!(!checkpoint_enforcement_on_for(
        &flipped,
        CHAIN,
        &Hash::new([0x08; 32])
    ));
    assert!(!checkpoint_enforcement_on_for(
        &flipped,
        1337,
        &genesis_hash()
    ));
}

// ---------------------------------------------------------------------------
// G11: the committed pruning point
// ---------------------------------------------------------------------------

fn chain_id(h: u64) -> Hash {
    let mut id = [0u8; 32];
    id[0] = 0xC4;
    id[1..9].copy_from_slice(&h.to_be_bytes());
    Hash::new(id)
}

/// `pp_h(B)` from the spec, in the test's own words.
fn spec_pp_height(h: u64) -> u64 {
    h.saturating_sub(SPEC_PRUNING_DEPTH) / SPEC_CHECKPOINT_INTERVAL * SPEC_CHECKPOINT_INTERVAL
}

/// The committed value: genesis is encoded as the zero hash (no pruning point
/// yet, `pp_h = 0`); otherwise the chain block at `pp_h`.
fn spec_pp(h: u64) -> Hash {
    match spec_pp_height(h) {
        0 => Hash::default(),
        p => chain_id(p),
    }
}

/// Linear block at `h` with the given pruning point; linear GHOSTDAG values
/// (genesis 0, each step +1, G7).
fn linear(h: u64, pp: Hash) -> Block {
    BlockBuilder::new()
        .hash(chain_id(h))
        .parent(if h == 0 {
            Hash::default()
        } else {
            chain_id(h - 1)
        })
        .height(h)
        .blue_score(h)
        .blue_work(blue_work_for_score(h))
        .pruning_point(pp)
        .build_unhashed()
}

async fn admit(store: &DagStore, gd: &GhostDag, b: &Block) -> Result<(), String> {
    gd.validate_block_consistency(b)
        .await
        .map_err(|e| e.to_string())?;
    store
        .store_block(b.clone())
        .await
        .map_err(|e| e.to_string())?;
    gd.add_block(b).await.map_err(|e| e.to_string())
}

async fn build_linear(store: &DagStore, gd: &GhostDag, upto: u64) {
    for h in 0..=upto {
        let b = linear(h, spec_pp(h));
        if let Err(e) = admit(store, gd, &b).await {
            panic!("block {h} with the spec pruning point must be admitted: {e}");
        }
    }
}

/// G11: `header.pruning_point` MUST be `chain_ancestor(B, pp_h(B))`, which is
/// always a checkpoint height. It is in the hash preimage, a wrong value is
/// invalid at admission, and below `PRUNING_DEPTH` it is the genesis value.
#[tokio::test]
async fn pruning_point_committed_and_checkpoint_aligned() {
    // Committed: the field is in the block hash.
    let a = BlockBuilder::new()
        .height(5)
        .pruning_point(Hash::new([1; 32]))
        .build();
    let b = BlockBuilder::new()
        .height(5)
        .pruning_point(Hash::new([2; 32]))
        .build();
    assert_ne!(a.hash(), b.hash(), "pruning_point is in the hash preimage");

    let store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let gd = GhostDag::new(GhostDagParams::default(), store.clone());
    const TOP: u64 = SPEC_PRUNING_DEPTH + 2 * SPEC_CHECKPOINT_INTERVAL; // 10,100
                                                                        // Below the boundary: any non-genesis value is invalid.
    let early = linear(1, chain_id(0));
    build_linear(&store, &gd, 0).await;
    assert!(
        admit(&store, &gd, &early).await.is_err(),
        "a block below PRUNING_DEPTH must commit the genesis value"
    );
    let store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let gd = GhostDag::new(GhostDagParams::default(), store.clone());
    build_linear(&store, &gd, TOP - 1).await;

    // At TOP = 10,100 the pruning point is the chain block at 100.
    assert_eq!(spec_pp_height(TOP), 100);
    let off_by_one = linear(TOP, chain_id(99));
    let stale = linear(TOP, chain_id(50));
    let unaligned = linear(TOP, chain_id(101));
    let zero = linear(TOP, Hash::default());
    for (name, bad) in [
        ("off by one", &off_by_one),
        ("previous boundary", &stale),
        ("unaligned", &unaligned),
        ("zero", &zero),
    ] {
        assert!(
            admit(&store, &gd, bad).await.is_err(),
            "{name}: pruning point must be the chain ancestor at pp_h"
        );
    }
    let ok = linear(TOP, spec_pp(TOP));
    assert_eq!(admit(&store, &gd, &ok).await, Ok(()));
    // Between boundaries the value is the selected parent's.
    let next = linear(TOP + 1, spec_pp(TOP + 1));
    assert_eq!(spec_pp(TOP + 1), spec_pp(TOP));
    assert_eq!(admit(&store, &gd, &next).await, Ok(()));
    // The producer derives the same value it would be judged against.
    assert_eq!(
        gd.expected_pruning_point(&next.hash(), TOP + 2)
            .await
            .expect("expected pp"),
        spec_pp(TOP + 2)
    );
}

/// A pruned, restarted node keeps only blocks at or above the pruning point
/// of its tip and still validates a new boundary block's pruning point.
#[tokio::test]
async fn pruned_node_validates_pruning_point_commitment() {
    const TOP: u64 = SPEC_PRUNING_DEPTH + 120; // pp(TOP) = 100
    const BOUNDARY: u64 = SPEC_PRUNING_DEPTH + 150; // pp = 150
    let kv = Arc::new(MemKv::default());
    {
        let store = Arc::new(
            DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("persistent store"),
        );
        let gd = GhostDag::new(GhostDagParams::default(), store.clone());
        build_linear(&store, &gd, TOP).await;
        // The node prunes up to its tip's pruning point, never above it.
        store.update_pruning_point(spec_pp(TOP)).await.expect("pp");
        assert!(store.prune().await.expect("prune") > 0);
        assert!(!store.has_block(&chain_id(99)).await, "pruned below 100");
    }

    let store = Arc::new(DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("reopen"));
    let gd = GhostDag::new(GhostDagParams::default(), store.clone());
    for h in spec_pp_height(TOP)..=TOP {
        let b = linear(h, spec_pp(h));
        gd.register_existing_block(&b)
            .await
            .expect("a retained block registers");
    }
    gd.reconcile_tips_from_dag_store().await;

    for h in TOP + 1..BOUNDARY {
        let b = linear(h, spec_pp(h));
        assert_eq!(admit(&store, &gd, &b).await, Ok(()), "height {h}");
    }
    // The boundary block moves the pruning point to 150, which the pruned
    // node finds on its retained chain.
    let wrong = linear(BOUNDARY, spec_pp(BOUNDARY - 1));
    assert!(admit(&store, &gd, &wrong).await.is_err());
    let right = linear(BOUNDARY, spec_pp(BOUNDARY));
    assert_eq!(spec_pp(BOUNDARY), chain_id(150));
    assert_eq!(admit(&store, &gd, &right).await, Ok(()));
}

/// A sibling of the linear chain: same height and parent as `linear(h, pp)`,
/// a different hash (`chain_id` with a branch tag).
fn sibling(h: u64, parent: Hash, pp: Hash, tag: u8) -> Block {
    let mut id = [0u8; 32];
    id[0] = 0x5B;
    id[1] = tag;
    id[2..10].copy_from_slice(&h.to_be_bytes());
    BlockBuilder::new()
        .hash(Hash::new(id))
        .parent(parent)
        .height(h)
        .blue_score(h)
        .blue_work(blue_work_for_score(h))
        .pruning_point(pp)
        .build_unhashed()
}

/// The chain store a node keeps beside its DAG store (here: the linear
/// chain's headers, which the node stored when it admitted them).
struct ChainHeaders(HashMap<Hash, citrate_consensus::types::BlockHeader>);

impl citrate_consensus::ghostdag::AncestryHeaders for ChainHeaders {
    fn header(&self, hash: &Hash) -> Option<citrate_consensus::types::BlockHeader> {
        self.0.get(hash).cloned()
    }
}

/// G11 + CV-7a: a node whose DAG store is pruned at its tip's pruning point
/// must still admit a block it is required to admit: a late or side-branch
/// boundary block below its tip, inside the undo window. Such a block's
/// pruning point lies up to `PRUNING_DEPTH` below the block itself, so below
/// the node's DAG prune floor; the walk to it must read the selected-chain
/// headers the node keeps in its chain store, and a header found nowhere still
/// fails closed. An unpruned node admits the same block, so without this the
/// pruned node diverges from it.
#[tokio::test]
async fn pruned_node_validates_a_late_boundary_block_below_its_tip() {
    const TOP: u64 = SPEC_PRUNING_DEPTH + 520; // pp(TOP) = 500
    const LATE: u64 = SPEC_PRUNING_DEPTH + 450; // a boundary 70 below TOP: pp = 450
    assert_eq!(spec_pp_height(TOP), 500);
    assert_eq!(spec_pp_height(LATE), 450);

    // Every block of the linear chain, as the node's chain store holds them.
    let headers: HashMap<Hash, citrate_consensus::types::BlockHeader> = (0..=TOP)
        .map(|h| (chain_id(h), linear(h, spec_pp(h)).header))
        .collect();

    let store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let gd = GhostDag::new(GhostDagParams::default(), store.clone())
        .with_ancestry_headers(Arc::new(ChainHeaders(headers)));
    build_linear(&store, &gd, TOP).await;
    // The node prunes its DAG store at its tip's pruning point (G11 floor).
    store.update_pruning_point(spec_pp(TOP)).await.expect("pp");
    assert!(store.prune().await.expect("prune") > 0);
    assert!(
        !store.has_block(&chain_id(450)).await,
        "450 is below the floor"
    );

    // A sibling at LATE on the chain block LATE-1 (a late block, or the first
    // block of a branch forked 71 deep). Its pruning point is the chain block
    // at 450, which the DAG store dropped.
    let late = sibling(LATE, chain_id(LATE - 1), spec_pp(LATE), 1);
    assert_eq!(
        admit(&store, &gd, &late).await,
        Ok(()),
        "a pruned node admits a late boundary block inside the undo window"
    );
    // Still validated: the wrong value is refused.
    let wrong = sibling(LATE, chain_id(LATE - 1), chain_id(400), 2);
    assert!(admit(&store, &gd, &wrong).await.is_err());

    // Without the chain-store headers the walk cannot reach 450: it fails
    // closed rather than guessing.
    let bare_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let bare = GhostDag::new(GhostDagParams::default(), bare_store.clone());
    build_linear(&bare_store, &bare, TOP).await;
    bare_store
        .update_pruning_point(spec_pp(TOP))
        .await
        .expect("pp");
    assert!(bare_store.prune().await.expect("prune") > 0);
    let late = sibling(LATE, chain_id(LATE - 1), spec_pp(LATE), 3);
    assert!(
        admit(&bare_store, &bare, &late).await.is_err(),
        "no header source: fail closed"
    );
}

/// Characterisation (2026-11-09 verification; a decision for the lead, see the
/// S3-5 report): voting is ON from genesis in this build, but a checkpoint
/// needs a committee, and a committee comes from the epoch snapshot that
/// governs its height. Under the node's production schedule
/// (`node/src/registry_sync.rs` EPOCH = 1,000, SNAPSHOT_LAG = 200) the first
/// snapshot is S(1) = 800, which governs heights 801..=1,800. So the
/// checkpoints at 50..=800 have no committee and are never voted on, and the
/// first checkpoint that can finalize is 850. This pins that behaviour, so
/// that an epoch-0 (genesis) committee, if adopted with the r1007 genesis
/// validator set (S3-6), shows up as a deliberate change here.
#[tokio::test]
async fn production_schedule_first_votable_checkpoint_is_850() {
    const EPOCH: u64 = 1_000;
    const SNAPSHOT_LAG: u64 = 200;
    let ks: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let set: Vec<(PublicKey, u128)> = ks.iter().map(|k| (pk(k), 1_000u128)).collect();
    let sel = VrfProposerSelector::production().with_snapshot_schedule(EPOCH, SNAPSHOT_LAG);
    // registry_sync materializes S(1) = 800 when block 800 is applied.
    sel.sync_active_set_at(EPOCH - SNAPSHOT_LAG, set, 1).await;
    let kv: Arc<dyn KvStore> = Arc::new(MemKv::default());
    let mgr = Arc::new(CheckpointManager::with_persistence(
        config(),
        dag_with(12).await,
        kv,
    ));
    let g = FinalityGadget::new(mgr, Some(Arc::new(sel)));
    assert!(g.enabled());
    let seed = Hash::new([7; 32]);
    for h in (SPEC_CHECKPOINT_INTERVAL..=EPOCH - SNAPSHOT_LAG).step_by(50) {
        assert!(
            g.committee_for(h, &seed).await.is_none(),
            "checkpoint {h}: no snapshot governs it, so no committee"
        );
    }
    let first = g
        .committee_for(850, &seed)
        .await
        .expect("S(1) = 800 governs 850");
    assert_eq!(first.epoch, 800);
    assert_eq!(first.members.len(), 4);
}
