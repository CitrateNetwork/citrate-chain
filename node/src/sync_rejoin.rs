// citrate/node/src/sync_rejoin.rs
//
// Rejoining the heavier chain from a side branch.
//
// THE FAILURE (r1006 testnet, 2026-10-28)
//
// A producer restarted with mining on and sealed its first block before any
// peer had connected, on top of the block it had applied (height 38) while
// the network was already a few heights further on. From then on it built
// every block on its own tip. Its peers stored those blocks as side blocks.
// Two hours later it was at height 3,353 on its own branch while the other six
// producers agreed at ~12,476.
//
// Its sync loop never stopped running and never brought it back:
//
// * Every `GetBlocks` was anchored at the APPLIED tip, i.e. the node's own
//   newest block. `serve_blocks` serves BY HEIGHT from the anchor's height, so
//   the answer was the node's own block plus the peers' blocks at the same and
//   following heights. Those peer blocks extend the heavier chain at heights
//   the node never had (everything between the fork point and its own tip), so
//   admission deferred every one of them as missing a parent. Nothing was
//   admitted; the next tick asked the same question one height higher.
// * Nothing ever asked for the blocks between the fork point and the node's
//   own tip. The gossip-side ancestry recovery (SYNC-S3) asks for one missing
//   parent and is deliberately limited to a short distance; the synced-block
//   path defers silently (debug level), so the journal showed only
//   "Validated and imported 32/32" and `SYNCSCORE ... new=0`.
//
// THE FIX
//
// The driver keeps anchoring on the applied tip while that makes progress. When
// answers to the tip anchor repeatedly admit nothing and carry blocks this node
// cannot connect (or come back empty because the peer does not hold the tip),
// the driver looks for the fork point: it anchors at heights below the tip on
// its own executed chain, doubling the distance until an answer is no longer
// unconnected, then bisecting between the deepest unconnected height and the
// shallowest height whose answer held only blocks it already had. As soon as an
// answer admits a new block, the driver follows those blocks upward by height
// (anchoring at the highest block it admitted) until a follow answer brings
// nothing new. By then fork choice has moved the applied tip to the heavier
// branch if it is heavier, and normal tip-anchored sync takes over.
//
// Only answers to the anchor this tracker asked for move it: an answer counts
// when it contains the anchor block (`serve_blocks` always includes it) or is an
// empty answer from the peer that was asked. Unsolicited `Blocks` messages are
// processed as before but never steer the search.
//
// NOTHING HERE DECIDES VALIDITY. The tracker only picks the anchor of the next
// `GetBlocks`. Every block still goes through `SyncManager::handle_blocks` and
// `BlockAdmission::admit`; fork choice still picks the head.

// PANIC-S1 G2: sync path; panic-free outside tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use citrate_consensus::types::Hash;
use citrate_storage::StorageManager;

/// Consecutive unconnected answers to the tip anchor, while behind, before the
/// driver starts looking for the fork point. Two, so a single answer that raced
/// a parent still on the wire does not start a search.
pub const PROBE_AFTER_STRIKES: u32 = 2;

/// What an answer to the tracker's anchor did, judged after admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// At least one block was newly admitted; the highest of them.
    Progress { highest: (Hash, u64) },
    /// Nothing new, and either some served block could not be connected (its
    /// parent is missing) or the answer was empty (the peer does not hold the
    /// anchor).
    Unconnected,
    /// Nothing new and nothing unconnected: every served block was already held.
    Known,
}

/// Classify an answer from what admission did with it.
///
/// `empty` is the answer as received (before validation); `deferred` counts the
/// blocks of THIS answer that admission left waiting for a parent.
pub fn classify(
    empty: bool,
    newly_admitted: usize,
    highest_admitted: Option<(Hash, u64)>,
    deferred: usize,
) -> Answer {
    match highest_admitted {
        Some(highest) if newly_admitted > 0 => Answer::Progress { highest },
        _ if empty || deferred > 0 => Answer::Unconnected,
        _ => Answer::Known,
    }
}

/// Where the next `GetBlocks` is anchored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Normal sync: anchor on the applied tip.
    Tip { strikes: u32 },
    /// Looking for the fork point below `top` (the applied height when the
    /// search started).
    Probe {
        top: u64,
        /// Deepest height whose answer was unconnected.
        unconnected: u64,
        /// Shallowest height whose answer held only known blocks, once seen.
        known: Option<u64>,
        /// Distance below `top` of the next expansion step.
        step: u64,
        /// Height anchored now.
        height: u64,
    },
    /// Following blocks admitted from the search upward by height.
    Follow { cursor: (Hash, u64) },
}

/// A change of mode worth one log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    StartedProbe { top: u64 },
    Following { cursor_height: u64 },
    Finished { from: &'static str },
    GaveUp { at: u64 },
}

/// The anchor policy described at the top of this file.
#[derive(Debug)]
pub struct RejoinTracker {
    mode: Mode,
    /// The anchor `(hash, height)` the last request was sent with, and to whom.
    asked: Option<(String, Hash, u64)>,
}

impl Default for RejoinTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RejoinTracker {
    pub fn new() -> Self {
        Self {
            mode: Mode::Tip { strikes: 0 },
            asked: None,
        }
    }

    #[cfg(test)]
    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    /// The anchor for the next `GetBlocks`. `applied` is the applied tip;
    /// `lookup(h)` names a block this node holds at height `h` on its executed
    /// chain (see [`anchor_at_height`]). A probe height that cannot be resolved
    /// ends the search and falls back to the applied tip.
    pub fn anchor(
        &mut self,
        applied: (Hash, u64),
        lookup: impl Fn(u64) -> Option<Hash>,
    ) -> (Hash, u64) {
        match &self.mode {
            Mode::Tip { .. } => applied,
            Mode::Probe { height, .. } => match lookup(*height) {
                Some(h) => (h, *height),
                None => {
                    self.mode = Mode::Tip { strikes: 0 };
                    applied
                }
            },
            Mode::Follow { cursor } => *cursor,
        }
    }

    /// Record that a `GetBlocks` anchored at `anchor` went to `peer`.
    pub fn note_asked(&mut self, peer: &str, anchor: (Hash, u64)) {
        self.asked = Some((peer.to_string(), anchor.0, anchor.1));
    }

    /// Whether a `Blocks` message from `peer` carrying `hashes` answers the
    /// outstanding request; if so, the anchor height it answers. Consumes the
    /// request, so one request moves the tracker at most once.
    pub fn take_answer(&mut self, peer: &str, hashes: &[Hash]) -> Option<u64> {
        let (asked_peer, anchor, height) = self.asked.as_ref()?;
        let answers = if hashes.is_empty() {
            asked_peer == peer
        } else {
            hashes.contains(anchor)
        };
        if !answers {
            return None;
        }
        let height = *height;
        self.asked = None;
        Some(height)
    }

    /// Fold in the verdict on an answer. `behind` is whether the node has
    /// evidence of a higher network head than its applied tip; `anchor_height`
    /// is the height the answered request was anchored at.
    pub fn on_answer(
        &mut self,
        answer: Answer,
        behind: bool,
        anchor_height: u64,
    ) -> Option<Transition> {
        if !behind {
            return self.reset("caught up");
        }
        match (self.mode.clone(), answer) {
            (Mode::Tip { .. }, Answer::Progress { .. }) | (Mode::Tip { .. }, Answer::Known) => {
                self.mode = Mode::Tip { strikes: 0 };
                None
            }
            (Mode::Tip { strikes }, Answer::Unconnected) => {
                let strikes = strikes.saturating_add(1);
                if strikes < PROBE_AFTER_STRIKES || anchor_height == 0 {
                    self.mode = Mode::Tip { strikes };
                    return None;
                }
                let top = anchor_height;
                self.mode = Mode::Probe {
                    top,
                    unconnected: top,
                    known: None,
                    step: 1,
                    height: top.saturating_sub(1),
                };
                Some(Transition::StartedProbe { top })
            }
            (Mode::Probe { .. }, Answer::Progress { highest })
            | (Mode::Follow { .. }, Answer::Progress { highest }) => {
                let cursor = match &self.mode {
                    Mode::Follow { cursor } if cursor.1 > highest.1 => *cursor,
                    _ => highest,
                };
                let was_following = matches!(self.mode, Mode::Follow { .. });
                self.mode = Mode::Follow { cursor };
                if was_following {
                    None
                } else {
                    Some(Transition::Following {
                        cursor_height: cursor.1,
                    })
                }
            }
            (Mode::Follow { .. }, _) => self.reset("follow"),
            (
                Mode::Probe {
                    top,
                    unconnected,
                    known,
                    step,
                    height,
                },
                verdict,
            ) => {
                // An answer for a height other than the one being probed is
                // stale (the probe moved since it was sent): ignore it.
                if anchor_height != height {
                    return None;
                }
                let (unconnected, known, step) = match verdict {
                    Answer::Unconnected => (height, known, step.saturating_mul(2)),
                    // Progress is handled above; this arm is Known.
                    _ => (unconnected, Some(height), step),
                };
                let next = match known {
                    // Still expanding: the next doubling below the top.
                    None => {
                        if height == 0 {
                            return self.give_up(0);
                        }
                        top.saturating_sub(step)
                    }
                    // Bisect between the known-good and unconnected heights.
                    Some(k) => {
                        let span = unconnected.saturating_sub(k);
                        if span <= 1 {
                            return self.give_up(k);
                        }
                        k.saturating_add(span / 2)
                    }
                };
                self.mode = Mode::Probe {
                    top,
                    unconnected,
                    known,
                    step,
                    height: next,
                };
                None
            }
        }
    }

    fn reset(&mut self, from: &'static str) -> Option<Transition> {
        let was = std::mem::replace(&mut self.mode, Mode::Tip { strikes: 0 });
        match was {
            Mode::Tip { .. } => None,
            _ => Some(Transition::Finished { from }),
        }
    }

    fn give_up(&mut self, at: u64) -> Option<Transition> {
        self.mode = Mode::Tip { strikes: 0 };
        Some(Transition::GaveUp { at })
    }
}

/// A block this node holds at `height` on its executed chain, for use as a
/// `GetBlocks` anchor. `serve_blocks` uses the anchor only for its height, so
/// any held block at that height works; the executed chain's block is the one
/// peers are most likely to hold. Falls back to the stored height index.
pub fn anchor_at_height(storage: &StorageManager, height: u64) -> Option<Hash> {
    storage
        .blocks
        .get_canonical_block_by_height(height)
        .ok()
        .flatten()
        .or_else(|| storage.blocks.get_block_by_height(height).ok().flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{bound_orphan_buffer, BlockAdmission};
    use crate::block_serve;
    use crate::canonical_apply::{canonical_reward_config, CanonicalApplicator};
    use citrate_consensus::crypto;
    use citrate_consensus::dag_store::DagStore;
    use citrate_consensus::ghostdag::GhostDag;
    use citrate_consensus::hardening::PbaHardening;
    use citrate_consensus::types::{
        blue_work_for_score, Block, BlockBuilder, GhostDagParams, PublicKey, VrfProof,
    };
    use citrate_economics::rewards::RewardCalculator;
    use citrate_execution::revm_adapter::BlockContext;
    use citrate_execution::types::Address;
    use citrate_execution::{Executor, StateDB};
    use citrate_network::sync::{SyncConfig, SyncManager};
    use citrate_network::PeerId;
    use citrate_storage::pruning::PruningConfig;
    use primitive_types::U256;
    use std::sync::Arc;

    // ---------------------------------------------------------------------
    // Fixture: a chain with real state roots, a node wired as `start_node`
    // wires one (storage-backed executor, applicator with GhostDAG fork
    // choice, admission, sync manager), and a peer store served by the real
    // `block_serve::serve_blocks`.
    // ---------------------------------------------------------------------

    const CB: [u8; 20] = [0x33; 20];
    const CHAIN_ID: u64 = 40204;
    const PEER: &str = "peer-main";

    fn h(b: &Block) -> Hash {
        b.header.block_hash
    }

    fn seal(key: &ed25519_dalek::SigningKey, height: u64, parent: Hash, root: Hash) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(CB)
            .timestamp(1_000 + height)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(vec![])
            .state_root(root)
            .blue_score(height)
            .blue_work(blue_work_for_score(height))
            .proposer(PublicKey::new(key.verifying_key().to_bytes()))
            .build_unhashed();
        b.tx_root = citrate_consensus::tx_auth::tx_root_for_height(
            PbaHardening::off(),
            height,
            &b.transactions,
        );
        b.header.block_hash = b.compute_hash();
        b.signature = crypto::sign_block(&b.header.block_hash, key);
        b
    }

    fn genesis() -> Block {
        let mut g = BlockBuilder::new()
            .version(2)
            .height(0)
            .parent(Hash::default())
            .coinbase(CB)
            .timestamp(1_000)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(vec![])
            // The empty genesis state's root, so the deep-fork rebuild (which
            // checks it) can replay from genesis.
            .state_root(Executor::new(Arc::new(StateDB::new())).calculate_state_root())
            .blue_score(0)
            .blue_work(blue_work_for_score(0))
            .build_unhashed();
        g.header.block_hash = g.compute_hash();
        g
    }

    /// State root after applying heights `1..=h`, for every `h <= n`. Blocks
    /// carry no transactions and pay the same coinbase, so the root at a
    /// height is the same on every branch.
    fn roots(n: u64, key: &ed25519_dalek::SigningKey) -> Vec<Hash> {
        let exec = Executor::new(Arc::new(StateDB::new()));
        let rewards = RewardCalculator::new(canonical_reward_config());
        let treasury = canonical_reward_config().treasury_address;
        let mut out = vec![Hash::default()];
        for height in 1..=n {
            exec.set_block_context(BlockContext {
                coinbase: CB,
                prevrandao: [0x5A; 32],
                block_hashes: std::collections::HashMap::new(),
            });
            let provisional = seal(key, height, Hash::default(), Hash::default());
            let r = rewards.calculate_reward(&provisional).expect("reward");
            for (addr, amt) in [
                (Address(CB), r.validator_reward),
                (treasury, r.treasury_reward),
            ] {
                if amt > U256::zero() {
                    let bal = exec.get_balance(&addr);
                    exec.set_balance(&addr, bal + amt);
                }
            }
            out.push(exec.calculate_state_root());
        }
        out
    }

    /// Blocks `from..=to` sealed by `key` on top of `parent`.
    fn extend(
        key: &ed25519_dalek::SigningKey,
        parent: Hash,
        from: u64,
        to: u64,
        roots: &[Hash],
    ) -> Vec<Block> {
        let mut parent = parent;
        let mut out = Vec::new();
        for height in from..=to {
            let b = seal(key, height, parent, roots[height as usize]);
            parent = h(&b);
            out.push(b);
        }
        out
    }

    /// The network: a common prefix `1..=fork`, the heavier main chain
    /// `fork+1..=main_tip` and the node's own side branch `fork+1..=side_tip`.
    struct Net {
        genesis: Block,
        prefix: Vec<Block>,
        main: Vec<Block>,
        side: Vec<Block>,
    }

    fn net(fork: u64, side_tip: u64, main_tip: u64) -> Net {
        let main_key = crypto::generate_keypair();
        let side_key = crypto::generate_keypair();
        let r = roots(main_tip.max(side_tip), &main_key);
        let g = genesis();
        let prefix = extend(&main_key, h(&g), 1, fork, &r);
        let fork_hash = prefix.last().map(h).unwrap_or_else(|| h(&g));
        let main = extend(&main_key, fork_hash, fork + 1, main_tip, &r);
        let side = extend(&side_key, fork_hash, fork + 1, side_tip, &r);
        Net {
            genesis: g,
            prefix,
            main,
            side,
        }
    }

    fn peer_store(net: &Net, with_side: bool, dir: &std::path::Path) -> Arc<StorageManager> {
        let s = Arc::new(StorageManager::new(dir, PruningConfig::default()).expect("storage"));
        s.blocks.put_block(&net.genesis).expect("genesis");
        for b in net.prefix.iter().chain(net.main.iter()) {
            s.blocks.put_block(b).expect("put");
        }
        if with_side {
            for b in &net.side {
                s.blocks.put_block(b).expect("put");
            }
        }
        s
    }

    struct Node {
        storage: Arc<StorageManager>,
        executor: Arc<Executor>,
        app: Arc<CanonicalApplicator>,
        admission: Arc<BlockAdmission>,
        sync: SyncManager,
    }

    /// A node that applied `own` (prefix and, optionally, its side branch).
    async fn node(net: &Net, own: &[Block], dir: &std::path::Path) -> Node {
        let storage =
            Arc::new(StorageManager::new(dir, PruningConfig::default()).expect("storage"));
        let g = &net.genesis;
        storage.blocks.put_block(g).expect("genesis");
        storage
            .blocks
            .put_applied_tip(&g.header.block_hash, 0)
            .expect("tip");
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        dag.set_configured_genesis(g.header.block_hash);
        dag.store_block(g.clone()).await.expect("genesis dag");
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        ghostdag.add_block(g).await.expect("genesis ghostdag");
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            CHAIN_ID,
        ));
        executor.set_pba_hardening(PbaHardening::off());
        let app = Arc::new(
            CanonicalApplicator::new(executor.clone(), storage.clone())
                .with_fork_choice(ghostdag.clone()),
        );
        // As start_node: genesis wired for the deep-fork rebuild, and the DAG
        // marked hydrated.
        app.set_genesis(
            Executor::new(Arc::new(StateDB::new())).state_snapshot(),
            g.header.block_hash,
        );
        ghostdag.reconcile_tips_from_dag_store().await;
        let admission = Arc::new(BlockAdmission::new(
            storage.clone(),
            dag,
            ghostdag,
            Some(app.clone()),
        ));
        let sync = SyncManager::new(SyncConfig::default())
            .with_local_height(app.applied_height_handle())
            .with_pba_hardening(PbaHardening::off());
        let n = Node {
            storage,
            executor,
            app,
            admission,
            sync,
        };
        let fx = n.admission.admit_to_fixpoint(own.to_vec(), |_, _| {}).await;
        assert_eq!(fx.newly_admitted, own.len(), "own blocks admit");
        assert_eq!(
            n.applied(),
            own.last().map(|b| (h(b), b.header.height)),
            "node starts on its own tip"
        );
        n
    }

    impl Node {
        fn applied(&self) -> Option<(Hash, u64)> {
            self.storage.blocks.get_applied_tip().expect("tip read")
        }
    }

    #[derive(Debug, Default)]
    struct Run {
        rounds: usize,
        /// Heights every request was anchored at, in order.
        anchors: Vec<u64>,
        modes: Vec<Mode>,
    }

    /// Drive the node's sync against one peer the way the 2 s tick and the
    /// `Blocks` handler do: anchor from the tracker, `serve_blocks` on the
    /// peer, `handle_blocks` + admission to a fixpoint (orphans buffered), the
    /// periodic drain, then the tracker judges the answer.
    async fn drive(
        node: &Node,
        tracker: &mut RejoinTracker,
        peer: &StorageManager,
        target: Hash,
        network_height: u64,
        max_rounds: usize,
    ) -> Run {
        let mut run = Run::default();
        let mut orphans: Vec<Block> = Vec::new();
        let pid = PeerId(PEER.to_string());
        while run.rounds < max_rounds {
            let applied = node.applied().expect("applied tip");
            if applied.0 == target {
                break;
            }
            run.rounds += 1;
            let anchor = tracker.anchor(applied, |ht| anchor_at_height(&node.storage, ht));
            tracker.note_asked(PEER, anchor);
            run.anchors.push(anchor.1);
            let answer = block_serve::serve_blocks(peer, &anchor.0, 32);
            let hashes: Vec<Hash> = answer.iter().map(h).collect();
            let answered = tracker.take_answer(PEER, &hashes);
            node.sync
                .handle_blocks(&pid, answer)
                .await
                .expect("validate");
            let mut pending = node.sync.drain_validated_blocks().await;
            let reprocessed = !pending.is_empty();
            if reprocessed {
                pending.append(&mut orphans);
                pending = bound_orphan_buffer(pending);
            }
            let fx = node.admission.admit_to_fixpoint(pending, |_, _| {}).await;
            let deferred = fx
                .deferred
                .iter()
                .filter(|b| hashes.contains(&h(b)))
                .count();
            if reprocessed {
                orphans = bound_orphan_buffer(fx.deferred);
            }
            node.app.drive_drain().await;
            let applied_now = node.applied().expect("applied tip").1;
            if let Some(ah) = answered {
                let verdict = classify(
                    hashes.is_empty(),
                    fx.newly_admitted,
                    fx.highest_admitted,
                    deferred,
                );
                tracker.on_answer(verdict, network_height > applied_now, ah);
            }
            run.modes.push(tracker.mode().clone());
        }
        run
    }

    /// The r1006 shape, scaled down: a node sealed its own blocks from height
    /// `fork + 1` while the network built a heavier chain from the same
    /// parent. Its peer holds both branches (it stored the node's blocks as
    /// side blocks). Tip-anchored sync is answered with the node's own block
    /// plus peer blocks at the same heights, none of which connect. The node
    /// must find the fork point, fetch the heavier branch, and switch to it.
    #[tokio::test]
    async fn node_on_a_short_side_branch_rejoins_the_heavier_chain() {
        let net = net(6, 14, 48);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, true, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive(&n, &mut tracker, &peer, h(main_tip), 48, 60).await;
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 48)),
            "the node stayed on its side branch: anchors {:?}, modes {:?}",
            run.anchors,
            run.modes
        );
        assert_eq!(
            n.executor.calculate_state_root(),
            main_tip.state_root,
            "executed state is the heavier chain's"
        );
        // The search is short: a few probes, then one request per batch.
        assert!(
            run.rounds <= 20,
            "took {} rounds: {:?}",
            run.rounds,
            run.anchors
        );
    }

    /// A side branch deeper than the in-memory reorg window (100 blocks): the
    /// switch goes through the applicator's rebuild from genesis, which the
    /// periodic drain triggers. The search itself is unchanged.
    #[tokio::test]
    async fn side_branch_deeper_than_the_reorg_window_rejoins() {
        let net = net(6, 150, 400);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, true, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive(&n, &mut tracker, &peer, h(main_tip), 400, 200).await;
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 400)),
            "the node stayed on its side branch after {} rounds: anchors {:?}",
            run.rounds,
            run.anchors
        );
        assert_eq!(n.executor.calculate_state_root(), main_tip.state_root);
        // ~log2(144) probes, then one request per 32-block batch up to 400.
        assert!(
            run.rounds <= 40,
            "took {} rounds: {:?}",
            run.rounds,
            run.anchors
        );
    }

    /// Same, but the peer never received the node's blocks (the node sealed its
    /// first block before any peer connected), so every tip-anchored request
    /// comes back empty.
    #[tokio::test]
    async fn side_branch_the_peer_never_saw_still_rejoins() {
        let net = net(6, 14, 48);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive(&n, &mut tracker, &peer, h(main_tip), 48, 60).await;
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 48)),
            "the node stayed on its side branch: anchors {:?}",
            run.anchors
        );
    }

    /// Negative control: a node on the heavier chain that is merely behind
    /// syncs on the tip anchor only. No request is ever anchored below its
    /// applied tip and the tracker never leaves `Tip`.
    #[tokio::test]
    async fn node_behind_on_the_same_chain_never_searches() {
        let net = net(6, 6, 200);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let n = node(&net, &net.prefix, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive(&n, &mut tracker, &peer, h(main_tip), 200, 200).await;
        assert_eq!(n.applied(), Some((h(main_tip), 200)));
        assert!(
            run.modes
                .iter()
                .all(|m| matches!(m, Mode::Tip { strikes: 0 })),
            "{:?}",
            run.modes
        );
        assert!(
            run.anchors.windows(2).all(|w| w[1] >= w[0]),
            "an anchor went below the previous one: {:?}",
            run.anchors
        );
    }

    // ---------------------------------------------------------------------
    // Wiring: the node's GetBlocks anchor comes from the tracker, and the
    // Blocks handler feeds it every answer it recognises.
    // ---------------------------------------------------------------------

    /// The problems with `src`'s wiring, if any.
    fn wiring_problems(src: &str) -> Vec<&'static str> {
        let mut out = Vec::new();
        let tick = src.find("let applied_tip = storage_for_sync");
        let anchor = src.find(".anchor(applied_tip,");
        let request = src.find(".request_blocks(&peer, block_from, block_height)");
        let asked = src.find(".note_asked(&pid.0, (block_from, block_height))");
        match (tick, anchor, request, asked) {
            (Some(t), Some(a), Some(r), Some(n)) if t < a && a < r && r < n => {}
            _ => out.push("sync tick: GetBlocks anchor must come from RejoinTracker::anchor"),
        }
        if src.contains(".request_blocks(&peer, start_from, start_height)") {
            out.push("sync tick: a GetBlocks still anchored on the applied tip directly");
        }
        let arm = src.find("NetworkMessage::Blocks { blocks } => {");
        let take = src.find(".take_answer(&pid.0, &answer_hashes)");
        let handle = arm.and_then(|a| src[a..].find(".handle_blocks(&pid, blocks)").map(|i| a + i));
        let judge = src.find(".on_answer(answer, gap > 0, anchor_height)");
        match (arm, take, handle, judge) {
            (Some(a), Some(t), Some(hb), Some(j)) if a < t && t < hb && hb < j => {}
            _ => out.push("Blocks handler: answers must reach RejoinTracker::on_answer"),
        }
        if !src.contains(".admit_to_fixpoint(pending,") {
            out.push("Blocks handler: admission must use BlockAdmission::admit_to_fixpoint");
        }
        out
    }

    #[test]
    fn start_node_wiring() {
        assert_eq!(wiring_problems(include_str!("main.rs")), Vec::<&str>::new());
    }

    /// Negative control: the pre-fix tick (anchored on the applied tip) and a
    /// handler that never judges answers are both caught.
    #[test]
    fn wiring_check_catches_the_old_tick() {
        let main = include_str!("main.rs");
        let old_tick = main.replace(
            ".request_blocks(&peer, block_from, block_height)",
            ".request_blocks(&peer, start_from, start_height)",
        );
        assert!(!wiring_problems(&old_tick).is_empty());
        let no_judge = main.replace(".on_answer(answer, gap > 0, anchor_height)", ".ignore()");
        assert!(!wiring_problems(&no_judge).is_empty());
    }

    // ---------------------------------------------------------------------
    // The state machine on its own.
    // ---------------------------------------------------------------------

    fn hx(n: u8) -> Hash {
        Hash::new([n; 32])
    }

    fn progress() -> Answer {
        Answer::Progress {
            highest: (hx(9), 0),
        }
    }

    /// Model of an honest peer holding the heavier chain: an answer anchored at
    /// `h` connects iff `h <= fork + 1`, and holds only known blocks iff it
    /// ends below the fork (`h + span < fork`).
    fn model(fork: u64, span: u64, h: u64) -> Answer {
        if h.saturating_add(span) < fork {
            Answer::Known
        } else if h <= fork + 1 {
            Answer::Progress {
                highest: (hx(7), h + span),
            }
        } else {
            Answer::Unconnected
        }
    }

    fn search(fork: u64, top: u64, span: u64) -> (usize, Mode) {
        let mut t = RejoinTracker::new();
        for _ in 0..PROBE_AFTER_STRIKES {
            t.on_answer(Answer::Unconnected, true, top);
        }
        let mut probes = 0usize;
        loop {
            let (_, at) = t.anchor((hx(1), top), |_| Some(hx(2)));
            if !matches!(t.mode(), Mode::Probe { .. }) {
                return (probes, t.mode().clone());
            }
            probes += 1;
            assert!(probes < 200, "search did not end");
            t.on_answer(model(fork, span, at), true, at);
        }
    }

    /// r1006 numbers: fork at 38, own tip at 3,353. The search ends in the
    /// follow mode within a logarithmic number of probes, from any depth.
    #[test]
    fn fork_point_search_is_logarithmic() {
        for (fork, top) in [
            (38u64, 3_353u64),
            (0, 1_000_000),
            (999_990, 1_000_000),
            (5, 7),
        ] {
            for span in [0u64, 1, 10, 31] {
                let (probes, mode) = search(fork, top, span);
                assert!(
                    matches!(mode, Mode::Follow { .. }),
                    "fork {fork} top {top} span {span}: ended in {mode:?}"
                );
                let bound = 2 * (64 - (top - fork).leading_zeros() as usize) + 2;
                assert!(
                    probes <= bound,
                    "fork {fork} top {top}: {probes} probes > {bound}"
                );
            }
        }
    }

    #[test]
    fn one_unconnected_answer_does_not_start_a_search() {
        let mut t = RejoinTracker::new();
        assert_eq!(t.on_answer(Answer::Unconnected, true, 50), None);
        assert_eq!(t.mode(), &Mode::Tip { strikes: 1 });
        t.on_answer(Answer::Known, true, 50);
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
        t.on_answer(Answer::Unconnected, true, 51);
        assert_eq!(
            t.on_answer(Answer::Unconnected, true, 52),
            Some(Transition::StartedProbe { top: 52 })
        );
    }

    #[test]
    fn not_behind_never_searches_and_ends_a_search() {
        let mut t = RejoinTracker::new();
        for _ in 0..10 {
            t.on_answer(Answer::Unconnected, false, 50);
        }
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
        t.on_answer(Answer::Unconnected, true, 50);
        t.on_answer(Answer::Unconnected, true, 50);
        assert!(matches!(t.mode(), Mode::Probe { .. }));
        assert_eq!(
            t.on_answer(Answer::Unconnected, false, 49),
            Some(Transition::Finished { from: "caught up" })
        );
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    /// Only the answer to the anchor we asked moves the tracker: a `Blocks`
    /// message without that block, or an empty one from another peer, does
    /// not count, and one request is consumed at most once.
    #[test]
    fn only_the_answer_to_our_anchor_counts() {
        let mut t = RejoinTracker::new();
        assert_eq!(t.take_answer(PEER, &[]), None, "nothing asked yet");
        t.note_asked(PEER, (hx(3), 40));
        assert_eq!(t.take_answer("other", &[]), None, "empty, other peer");
        assert_eq!(t.take_answer(PEER, &[hx(4), hx(5)]), None, "anchor absent");
        assert_eq!(t.take_answer("other", &[hx(4), hx(3)]), Some(40));
        assert_eq!(t.take_answer(PEER, &[hx(3)]), None, "consumed");
        t.note_asked(PEER, (hx(3), 41));
        assert_eq!(
            t.take_answer(PEER, &[]),
            Some(41),
            "empty from the asked peer"
        );
    }

    /// A probe answer for a height other than the one being probed (sent before
    /// the probe moved) is ignored.
    #[test]
    fn stale_probe_answers_are_ignored() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 100);
        t.on_answer(Answer::Unconnected, true, 100);
        let before = t.mode().clone();
        assert!(matches!(before, Mode::Probe { height: 99, .. }));
        assert_eq!(t.on_answer(Answer::Known, true, 100), None);
        assert_eq!(t.mode(), &before);
    }

    /// A peer that answers every probe empty (it holds nothing we hold, or
    /// lies) cannot keep the node searching: the search walks to genesis in
    /// log steps and gives up, back to the tip anchor.
    #[test]
    fn a_peer_that_never_connects_ends_the_search_at_genesis() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 1_000_000);
        t.on_answer(Answer::Unconnected, true, 1_000_000);
        let mut steps = 0;
        let last = loop {
            let (_, at) = t.anchor((hx(1), 1_000_000), |_| Some(hx(2)));
            steps += 1;
            assert!(steps < 64, "did not give up");
            if let Some(tr) = t.on_answer(Answer::Unconnected, true, at) {
                break tr;
            }
        };
        assert_eq!(last, Transition::GaveUp { at: 0 });
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    /// A probe height this node cannot name a block for ends the search.
    #[test]
    fn an_unresolvable_probe_height_falls_back_to_the_tip() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 10);
        t.on_answer(Answer::Unconnected, true, 10);
        assert_eq!(t.anchor((hx(1), 10), |_| None), (hx(1), 10));
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    /// Following ends when an answer brings nothing new; the cursor never
    /// moves down.
    #[test]
    fn follow_advances_and_ends_when_nothing_new() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 10);
        t.on_answer(Answer::Unconnected, true, 10);
        t.on_answer(
            Answer::Progress {
                highest: (hx(5), 20),
            },
            true,
            9,
        );
        assert_eq!(
            t.mode(),
            &Mode::Follow {
                cursor: (hx(5), 20)
            }
        );
        t.on_answer(
            Answer::Progress {
                highest: (hx(6), 18),
            },
            true,
            20,
        );
        assert_eq!(
            t.mode(),
            &Mode::Follow {
                cursor: (hx(5), 20)
            }
        );
        assert_eq!(t.anchor((hx(1), 10), |_| None), (hx(5), 20));
        assert_eq!(
            t.on_answer(Answer::Known, true, 20),
            Some(Transition::Finished { from: "follow" })
        );
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    #[test]
    fn classify_answers() {
        assert_eq!(classify(true, 0, None, 0), Answer::Unconnected);
        assert_eq!(classify(false, 0, None, 3), Answer::Unconnected);
        assert_eq!(classify(false, 0, None, 0), Answer::Known);
        assert_eq!(
            classify(false, 2, Some((hx(1), 9)), 5),
            Answer::Progress {
                highest: (hx(1), 9)
            }
        );
    }

    #[test]
    fn progress_on_the_tip_anchor_keeps_the_tip() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 10);
        assert_eq!(t.on_answer(progress(), true, 10), None);
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }
}
