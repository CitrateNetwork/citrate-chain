//! WP-S.3 Stage 1a — multi-node in-process checkpoint finality.
//!
//! Four validators, each with its own DAG store, checkpoint manager (persistent
//! in-memory KV) and epoch-snapshot selector, run the producer path
//! (`FinalityGadget`) with the compiled switch FORCED ON for the test only
//! (`FinalityGadget::with_switch(.., true)`; every release pin is OFF). Votes are
//! carried by an in-process gossip queue standing in for
//! `NetworkMessage::CheckpointVote` broadcast. Asserts propose -> sign -> gossip
//! -> quorum -> `latest_finalized_height()` advances on EVERY node, including a
//! node that buries the block late and finalizes from its early-vote buffer.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use citrate_consensus::checkpoint::{
    sign_checkpoint_vote, CheckpointConfig, CheckpointManager, CheckpointVote,
    MAX_FINALIZED_IN_MEMORY,
};
use citrate_consensus::checkpoint_gadget::{
    FinalityGadget, InboundOutcome, SignRefusal, SkipReason,
};
use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::dag_store::{DagStore, KvStore};
use citrate_consensus::types::{BlockBuilder, Hash, PublicKey};
use citrate_consensus::vrf::VrfProposerSelector;

const CHAIN: u64 = 40204;

/// (column family, key)
type KvKey = (String, Vec<u8>);

struct MemKv {
    inner: Mutex<HashMap<KvKey, Vec<u8>>>,
}

impl MemKv {
    fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl KvStore for MemKv {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| e.to_string())?
            .get(&(cf.to_string(), key.to_vec()))
            .cloned())
    }
    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.inner
            .lock()
            .map_err(|e| e.to_string())?
            .insert((cf.to_string(), key.to_vec()), value.to_vec());
        Ok(())
    }
    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
        self.inner
            .lock()
            .map_err(|e| e.to_string())?
            .remove(&(cf.to_string(), key.to_vec()));
        Ok(())
    }
    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| e.to_string())?
            .contains_key(&(cf.to_string(), key.to_vec())))
    }
    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| e.to_string())?
            .iter()
            .filter(|((c, _), _)| c == cf)
            .map(|((_, k), v)| (k.clone(), v.clone()))
            .collect())
    }
}

fn key(id: u8) -> Ed25519SigningKey {
    let mut seed = [0u8; 32];
    seed[0] = id;
    seed[31] = 0x5E;
    Ed25519SigningKey::from_bytes(&seed)
}

fn pk(k: &Ed25519SigningKey) -> PublicKey {
    PublicKey::new(k.verifying_key().to_bytes())
}

fn hash_at(height: u64) -> Hash {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&height.to_le_bytes());
    b[31] = 0xAA;
    Hash::new(b)
}

fn seed_at(height: u64) -> Hash {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&height.to_be_bytes());
    b[31] = 0x77;
    Hash::new(b)
}

fn config(chain_id: u64) -> CheckpointConfig {
    CheckpointConfig {
        interval: 2,
        committee_size: 100,
        quorum_threshold: 67,
        chain_id,
        vote_depth: 3,
    }
}

async fn dag(len: u64) -> Arc<DagStore> {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let mut parent = Hash::default();
    for h in 0..len {
        let b = BlockBuilder::new()
            .hash(hash_at(h))
            .height(h)
            .parent(parent)
            .build_unhashed();
        parent = b.hash();
        dag.store_block(b).await.expect("store block");
    }
    dag
}

struct Node {
    gadget: FinalityGadget,
    key: Ed25519SigningKey,
}

/// `n` validators sharing one epoch snapshot (schedule EPOCH 1000 / LAG 999,
/// S(1) = 1 governs 2..=1000).
async fn network(n: u8, chain_id: u64, enabled: bool) -> Vec<Node> {
    let keys: Vec<Ed25519SigningKey> = (0..n).map(key).collect();
    let set: Vec<(PublicKey, u128)> = keys.iter().map(|k| (pk(k), 32_000u128)).collect();
    let mut nodes = Vec::new();
    for k in keys {
        let sel = VrfProposerSelector::new().with_snapshot_schedule(1000, 999);
        sel.sync_active_set_at(1, set.clone(), 1).await;
        let kv: Arc<dyn KvStore> = Arc::new(MemKv::new());
        let mgr = Arc::new(CheckpointManager::with_persistence(
            config(chain_id),
            dag(64).await,
            kv,
        ));
        nodes.push(Node {
            gadget: FinalityGadget::with_switch(mgr, Some(Arc::new(sel)), enabled),
            key: k,
        });
    }
    nodes
}

/// Deliver every queued vote to every node except its sender; re-gossip relays.
async fn gossip(nodes: &[Node], queue: &mut VecDeque<(usize, CheckpointVote)>) -> usize {
    let mut delivered = 0usize;
    while let Some((from, vote)) = queue.pop_front() {
        for (i, node) in nodes.iter().enumerate() {
            if i == from {
                continue;
            }
            delivered = delivered.saturating_add(1);
            let outcome = node.gadget.on_inbound_vote(vote.clone()).await;
            if let Some(relay) = outcome.relay() {
                queue.push_back((i, relay.clone()));
            }
        }
        assert!(delivered < 100_000, "gossip must terminate (relay dedupe)");
    }
    delivered
}

async fn bury(
    nodes: &[Node],
    idx: usize,
    height: u64,
    queue: &mut VecDeque<(usize, CheckpointVote)>,
) {
    let node = nodes.get(idx).expect("node index");
    let out = node
        .gadget
        .on_buried_checkpoint(height, hash_at(height), &seed_at(height), Some(&node.key))
        .await;
    for v in out.outbound {
        queue.push_back((idx, v));
    }
}

/// The headline: 4 validators propose -> vote -> quorum -> finalized on all 4,
/// with node 3 burying the block LAST (its votes arrive early and are buffered).
#[tokio::test]
async fn four_validators_reach_quorum_and_finalize_everywhere() {
    let nodes = network(4, CHAIN, true).await;
    let mut queue = VecDeque::new();
    let h = 10u64;
    for i in 0..3 {
        bury(&nodes, i, h, &mut queue).await;
    }
    gossip(&nodes, &mut queue).await;
    // Nodes 0..2 finalized from each other's votes (3 of 4 = derived quorum);
    // node 3 has not buried H yet and is holding the votes in its buffer.
    for (i, n) in nodes.iter().enumerate().take(3) {
        assert_eq!(
            n.gadget.manager().latest_finalized_height().await,
            h,
            "node {i}"
        );
    }
    let late = nodes.get(3).expect("node 3");
    assert_eq!(late.gadget.manager().latest_finalized_height().await, 0);
    assert_eq!(late.gadget.early_vote_count().await, 3);

    bury(&nodes, 3, h, &mut queue).await;
    gossip(&nodes, &mut queue).await;
    for (i, n) in nodes.iter().enumerate() {
        assert_eq!(
            n.gadget.manager().latest_finalized_height().await,
            h,
            "node {i}"
        );
        let cp = n
            .gadget
            .manager()
            .get_checkpoint(h)
            .await
            .expect("checkpoint");
        assert_eq!(cp.block_hash, hash_at(h));
        assert!(cp.votes.len() >= 3, "node {i} quorum certificate");
        assert_eq!(n.gadget.manager().pending_len().await, 0, "node {i} pruned");
        assert_eq!(n.gadget.manager().voted_len().await, 0, "node {i} pruned");
        assert_eq!(
            n.gadget.early_vote_keys().await,
            0,
            "node {i} buffer drained"
        );
    }
}

/// Successive checkpoints keep finalizing; finality is monotone.
#[tokio::test]
async fn successive_checkpoints_finalize_in_order() {
    let nodes = network(4, CHAIN, true).await;
    let mut queue = VecDeque::new();
    for h in (10u64..=30).step_by(2) {
        for i in 0..nodes.len() {
            bury(&nodes, i, h, &mut queue).await;
        }
        gossip(&nodes, &mut queue).await;
        for n in &nodes {
            assert_eq!(n.gadget.manager().latest_finalized_height().await, h);
        }
    }
}

/// L2 safe stall: with 2 of 4 online nothing finalizes; when a 3rd comes online
/// finality resumes. No conflicting finalization ever occurs.
#[tokio::test]
async fn stall_with_two_of_four_then_resume() {
    let nodes = network(4, CHAIN, true).await;
    let mut queue = VecDeque::new();
    let h = 12u64;
    bury(&nodes, 0, h, &mut queue).await;
    bury(&nodes, 1, h, &mut queue).await;
    // Only nodes 0 and 1 receive (2 and 3 offline): deliver among them only.
    let online = nodes.get(..2).expect("two nodes");
    gossip(online, &mut queue).await;
    for n in online {
        assert_eq!(
            n.gadget.manager().latest_finalized_height().await,
            0,
            "stalled"
        );
    }
    bury(&nodes, 2, h, &mut queue).await;
    gossip(&nodes, &mut queue).await;
    for (i, n) in nodes.iter().enumerate().take(2) {
        assert_eq!(
            n.gadget.manager().latest_finalized_height().await,
            h,
            "node {i}"
        );
    }
    // Node 2 was offline when 0's and 1's votes were gossiped; votes are relayed
    // once, never re-sent, so it does not finalize H on its own. Catching a
    // returning node up is late-joiner certificate sync (spec §11.10), which is
    // NOT part of Stage 1a — this assertion pins the current, honest behavior.
    let n2 = nodes.get(2).expect("node 2");
    assert_eq!(n2.gadget.manager().latest_finalized_height().await, 0);
    // Safety holds throughout: one hash only ever finalized at H.
    for n in nodes.iter().take(2) {
        let cp = n.gadget.manager().get_checkpoint(h).await.expect("cp");
        assert_eq!(cp.block_hash, hash_at(h));
    }
}

/// Switch OFF (the release default): the same network produces no proposals,
/// no votes and no finality.
#[tokio::test]
async fn switch_off_network_does_nothing() {
    let nodes = network(4, CHAIN, false).await;
    for (i, node) in nodes.iter().enumerate() {
        let out = node
            .gadget
            .on_buried_checkpoint(10, hash_at(10), &seed_at(10), Some(&node.key))
            .await;
        assert_eq!(out.skipped, Some(SkipReason::Disabled), "node {i}");
        assert!(out.outbound.is_empty());
        assert_eq!(node.gadget.manager().pending_hash(10).await, None);
    }
    let k = nodes.first().expect("node 0");
    let vote = sign_checkpoint_vote(CHAIN, 10, hash_at(10), &k.key);
    let other = nodes.get(1).expect("node 1");
    let res = other.gadget.on_inbound_vote(vote).await;
    assert!(matches!(res, InboundOutcome::Rejected(_)), "{res:?}");
    assert!(res.relay().is_none());
}

/// chain_id comes from the node's chain config: a devnet (1337) network signs
/// and verifies its own votes, and a 40204 vote is rejected there.
#[tokio::test]
async fn devnet_chain_id_is_bound_into_votes() {
    let nodes = network(4, 1337, true).await;
    let mut queue = VecDeque::new();
    for i in 0..nodes.len() {
        bury(&nodes, i, 10, &mut queue).await;
    }
    // The managers verify against their configured chain id (1337), so finality
    // below proves every vote was signed over chain 1337.
    gossip(&nodes, &mut queue).await;
    for n in &nodes {
        assert_eq!(n.gadget.manager().latest_finalized_height().await, 10);
    }
    // A foreign-chain vote for a pending checkpoint on the devnet is rejected.
    let foreign_net = network(4, 1337, true).await;
    let n0 = foreign_net.first().expect("node 0");
    let _ = n0
        .gadget
        .on_buried_checkpoint(12, hash_at(12), &seed_at(12), None)
        .await;
    let k1 = foreign_net.get(1).expect("node 1");
    let foreign = sign_checkpoint_vote(CHAIN, 12, hash_at(12), &k1.key);
    assert!(matches!(
        n0.gadget.on_inbound_vote(foreign).await,
        InboundOutcome::Rejected(_)
    ));
}

/// §11.9: the in-memory finalized map is bounded; trimmed checkpoints are still
/// served from the persistent store.
#[tokio::test]
async fn finalized_memory_is_bounded_and_trimmed_entries_stay_readable() {
    let keys: Vec<Ed25519SigningKey> = (0u8..4).map(key).collect();
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let kv: Arc<dyn KvStore> = Arc::new(MemKv::new());
    let total = u64::try_from(MAX_FINALIZED_IN_MEMORY)
        .expect("fits")
        .saturating_add(20);
    let top = total.saturating_mul(2);
    let mgr = CheckpointManager::with_persistence(
        config(CHAIN),
        dag(top.saturating_add(1)).await,
        kv.clone(),
    );
    for i in 1..=total {
        let h = i.saturating_mul(2);
        mgr.ensure_proposed(h, hash_at(h), committee.clone())
            .await
            .expect("propose");
        for k in keys.iter().take(3) {
            mgr.submit_vote(sign_checkpoint_vote(CHAIN, h, hash_at(h), k))
                .await
                .expect("vote");
        }
        mgr.finalize_checkpoint(h).await.expect("finalize");
    }
    assert_eq!(mgr.latest_finalized_height().await, top);
    assert_eq!(mgr.finalized_in_memory_len().await, MAX_FINALIZED_IN_MEMORY);
    assert_eq!(mgr.voted_len().await, 0);
    // Height 2 was trimmed from memory but is still readable (persistent store).
    let cp = mgr.get_checkpoint(2).await.expect("persisted checkpoint");
    assert_eq!(cp.block_hash, hash_at(2));
    assert!(mgr.is_finalized(2).await);
    // A reload keeps the bound too.
    let reloaded = CheckpointManager::with_persistence(config(CHAIN), dag(1).await, kv);
    assert_eq!(reloaded.latest_finalized_height().await, top);
    assert_eq!(
        reloaded.finalized_in_memory_len().await,
        MAX_FINALIZED_IN_MEMORY
    );
}

/// The competing branch's block at `height` (a sibling of `hash_at(height)`).
fn fork_hash_at(height: u64) -> Hash {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&height.to_le_bytes());
    b[31] = 0xBB;
    Hash::new(b)
}

/// DAG holding the main chain 0..len AND a competing block at `fork_height`
/// (child of the main chain's block below it): both branches' checkpoint
/// candidates exist in the store, as they do after a reorg.
async fn dag_with_fork(len: u64, fork_height: u64) -> Arc<DagStore> {
    let dag = dag(len).await;
    let b = BlockBuilder::new()
        .hash(fork_hash_at(fork_height))
        .height(fork_height)
        .parent(hash_at(fork_height.saturating_sub(1)))
        .build_unhashed();
    dag.store_block(b).await.expect("store fork block");
    dag
}

/// One validator's process over a persistent store; "restart" = build a fresh
/// manager + gadget over the SAME store.
async fn boot(kv: &Arc<MemKv>, keys: &[Ed25519SigningKey], fork_height: u64) -> FinalityGadget {
    let set: Vec<(PublicKey, u128)> = keys.iter().map(|k| (pk(k), 32_000u128)).collect();
    let sel = VrfProposerSelector::new().with_snapshot_schedule(1000, 999);
    sel.sync_active_set_at(1, set, 1).await;
    let store: Arc<dyn KvStore> = kv.clone();
    let mgr = Arc::new(CheckpointManager::with_persistence(
        config(CHAIN),
        dag_with_fork(64, fork_height).await,
        store,
    ));
    FinalityGadget::with_switch(mgr, Some(Arc::new(sel)), true)
}

/// PR #321 review (P2) regression: sign hash A at H -> reorg onto a SHORTER
/// winning branch whose tip is below H + D -> restart before that branch grows
/// -> the branch grows and buries a DIFFERENT hash B at H. The restarted node
/// must NOT sign B (equivocation); every vote it ever emits at H names A.
#[tokio::test]
async fn restart_after_shorter_branch_reorg_never_double_signs() {
    let keys: Vec<Ed25519SigningKey> = (0u8..4).map(key).collect();
    let me = keys.first().expect("validator 0");
    let h = 10u64;
    let kv = Arc::new(MemKv::new());
    let mut emitted: Vec<CheckpointVote> = Vec::new();

    // Process 1: tip reached H + D on branch A; A at H is buried -> signed.
    {
        let g = boot(&kv, &keys, h).await;
        g.observe_tip(h.saturating_add(3)).await;
        let out = g
            .on_buried_checkpoint(h, hash_at(h), &seed_at(h), Some(me))
            .await;
        assert!(out.signed_own_vote, "signed A at H");
        emitted.extend(out.outbound);
        assert_eq!(g.signed_vote_at(h), Some(hash_at(h)), "durable before emit");
        // Reorg onto the shorter branch B (tip < H + D): nothing buried at H on
        // B yet, so the gadget is not called. Then the process dies.
    }

    // Process 2 (restart): fresh manager + gadget, no in-memory memory of A.
    // Branch B grows and buries B at H.
    let g = boot(&kv, &keys, h).await;
    assert_eq!(g.manager().pending_hash(h).await, None, "fresh process");
    g.observe_tip(h.saturating_add(3)).await;
    let out = g
        .on_buried_checkpoint(h, fork_hash_at(h), &seed_at(h), Some(me))
        .await;
    assert!(out.proposed, "B is proposed for aggregation (not a vote)");
    assert!(!out.signed_own_vote, "MUST NOT sign B");
    assert_eq!(
        out.sign_refused,
        Some(SignRefusal::Conflicting { signed: hash_at(h) })
    );
    emitted.extend(out.outbound);

    // A third process re-buries A: idempotent, same hash only.
    drop(g);
    let g = boot(&kv, &keys, h).await;
    let out = g
        .on_buried_checkpoint(h, hash_at(h), &seed_at(h), Some(me))
        .await;
    assert!(out.signed_own_vote, "re-signing the same hash is allowed");
    emitted.extend(out.outbound);

    let mine: Vec<&CheckpointVote> = emitted
        .iter()
        .filter(|v| v.voter == pk(me) && v.height == h)
        .collect();
    assert_eq!(mine.len(), 2, "A, then A again");
    assert!(
        mine.iter().all(|v| v.block_hash == hash_at(h)),
        "no vote for B ever left the node: {mine:?}"
    );
}

/// Finality prunes every validator's durable signed-vote record at/below the
/// finalized height (bounded growth); a restart after that still refuses the
/// finalized height.
#[tokio::test]
async fn finality_prunes_durable_signed_records_on_every_node() {
    let nodes = network(4, CHAIN, true).await;
    let mut queue = VecDeque::new();
    for h in [10u64, 12] {
        for i in 0..nodes.len() {
            bury(&nodes, i, h, &mut queue).await;
        }
        gossip(&nodes, &mut queue).await;
    }
    for (i, n) in nodes.iter().enumerate() {
        assert_eq!(n.gadget.manager().latest_finalized_height().await, 12);
        assert_eq!(n.gadget.signed_vote_at(10), None, "node {i}");
        assert_eq!(n.gadget.signed_vote_at(12), None, "node {i}");
        let meta = n.gadget.signed_vote_meta().expect("meta");
        assert_eq!(meta.floor, 12, "node {i}");
        assert_eq!(meta.highest, 12, "node {i}");
    }
}
