// citrate/core/consensus/src/checkpoint_gadget.rs
//
// WP-S.3 Stage 1a — the producer/outbound half of checkpoint finality
// (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §4.1–4.4, §11.5, §11.6, §11.9).
//
// `checkpoint.rs` already validates, aggregates and finalizes votes. What was
// missing is everything that CREATES work for it: nothing proposed a checkpoint,
// selected a committee, signed a local vote or relayed one. This module is that
// missing half, kept in the consensus crate (no node/storage dependency) so it can
// be exercised by in-process multi-node tests. The node supplies only two inputs:
//
//   * the canonical block at a boundary height H once it is buried `vote_depth`
//     blocks deep, plus that block's VRF beacon (`header.vrf_reveal.output`) —
//     see `node/src/finality_driver.rs`;
//   * the node's consensus signing key (`proposer.key`, spec D-4).
//
// SWITCH. Everything here is gated by a compiled-in, per-chain pin
// ([`CHECKPOINT_VOTING_PINS`], the `hardening.rs` pattern — spec §6: rollout by
// compiled pin, never env). Every chain is OFF in this release. With the switch
// OFF the gadget proposes nothing, signs nothing, buffers nothing and relays
// nothing; inbound votes take exactly the pre-Stage-1a path (`submit_vote`, then
// `finalize_checkpoint` on quorum).
//
// NOT HERE (Stage 1c): floor ENFORCEMENT (§4.5). Finalizing a checkpoint advances
// `CheckpointManager::latest_finalized_height()` only; nothing in this module
// raises the reorg floor.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::checkpoint::{
    sign_checkpoint_vote, verify_vote_signature, CheckpointError, CheckpointManager,
    CheckpointVote, CommitteeSelector, ProposeOutcome,
};
use crate::crypto::Ed25519SigningKey;
use crate::types::{Hash, PublicKey};
use crate::vrf::VrfProposerSelector;

/// Compiled-in per-chain switch for the checkpoint-finality producer path
/// (propose / sign / broadcast / buffer / relay), following the
/// `hardening::PINNED_ACTIVATIONS` pattern: the rollout point is baked into the
/// binary, auditable, and not a runtime toggle (spec §6). A chain that is not
/// listed is OFF.
///
/// OWNER STEP (enable release): flip 40204 to `true` only after the validator
/// committee exists (spec §7: >= 4 staked, independent validators). Until then
/// quorum is unreachable and enabling it would only produce gossip.
pub const CHECKPOINT_VOTING_PINS: &[(u64, bool)] = &[(40204, false)];

/// Whether this release enables the checkpoint-finality producer path for
/// `chain_id`. Data source: the compiled table [`CHECKPOINT_VOTING_PINS`].
pub fn checkpoint_voting_pinned(chain_id: u64) -> bool {
    pinned_in(CHECKPOINT_VOTING_PINS, chain_id)
}

fn pinned_in(table: &[(u64, bool)], chain_id: u64) -> bool {
    table
        .iter()
        .find(|(id, _)| *id == chain_id)
        .is_some_and(|(_, on)| *on)
}

/// §11.5 early-vote buffer bound: distinct `(height, block_hash)` keys held at once.
pub const MAX_EARLY_VOTE_KEYS: usize = 32;
/// §11.5 early-vote buffer bound: distinct hashes buffered for ONE height. Honest
/// votes at a buried height name one hash; more than a few is an attacker or a
/// deep fork, and must not crowd out other heights.
pub const MAX_EARLY_HASHES_PER_HEIGHT: usize = 4;
/// §11.5 early-vote buffer bound: votes held per `(height, block_hash)` key.
/// >= the default committee cap (100), so one honest checkpoint fits whole.
pub const MAX_EARLY_VOTES_PER_KEY: usize = 256;
/// §11.5 early-vote buffer bound: a vote more than this many blocks above the
/// node's last observed canonical tip is not buffered (it cannot be for a block
/// this node is about to bury).
pub const EARLY_VOTE_HORIZON_BLOCKS: u64 = 256;
/// Bound on the per-height "this node already signed" record (equivocation guard).
pub const MAX_SIGNED_HEIGHTS: usize = 1024;

/// What happened to an inbound vote.
#[derive(Debug)]
pub enum InboundOutcome {
    /// Accepted into a pending checkpoint; quorum not reached yet.
    Accepted { relay: Option<CheckpointVote> },
    /// Accepted and the checkpoint finalized at `height` with `votes` votes.
    Finalized {
        height: u64,
        votes: usize,
        relay: Option<CheckpointVote>,
    },
    /// Accepted and quorum reached, but `finalize_checkpoint` refused.
    FinalizeFailed {
        height: u64,
        error: CheckpointError,
        relay: Option<CheckpointVote>,
    },
    /// Signature-valid vote for a checkpoint this node has not proposed yet;
    /// held in the bounded early-vote buffer (switch ON only).
    Buffered,
    /// Rejected (invalid, duplicate, stale, or the buffer refused it).
    Rejected(CheckpointError),
}

impl InboundOutcome {
    /// The vote to re-gossip, if any. Only a vote that THIS node accepted as
    /// valid, for the first time, is ever returned — a duplicate is rejected by
    /// `submit_vote` (`DuplicateVote`) and so is never relayed twice, which is
    /// what stops relay loops.
    pub fn relay(&self) -> Option<&CheckpointVote> {
        match self {
            Self::Accepted { relay } => relay.as_ref(),
            Self::Finalized { relay, .. } => relay.as_ref(),
            Self::FinalizeFailed { relay, .. } => relay.as_ref(),
            Self::Buffered | Self::Rejected(_) => None,
        }
    }
}

/// What happened when the node reported a buried canonical checkpoint block.
#[derive(Debug, Default)]
pub struct BuriedOutcome {
    /// The checkpoint `(height, hash)` was newly proposed by this call.
    pub proposed: bool,
    /// This node signed its own vote for it in this call.
    pub signed_own_vote: bool,
    /// The checkpoint finalized during this call.
    pub finalized: bool,
    /// Votes to broadcast: this node's own vote (if signed) followed by every
    /// buffered early vote that was accepted on replay (relayed exactly once).
    pub outbound: Vec<CheckpointVote>,
    /// Why nothing was proposed, when nothing was.
    pub skipped: Option<SkipReason>,
}

/// Why a buried checkpoint was not (newly) proposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The compiled switch is OFF for this chain.
    Disabled,
    /// No epoch validator-set snapshot is materialized for this height (no
    /// registry configured, or the governing S(E) has not been applied).
    NoCommittee,
    /// Already proposed for this exact hash (idempotent re-report).
    AlreadyPending,
    /// Already finalized, or at/below the latest finalized height.
    AlreadyFinalized,
    /// A DIFFERENT hash is already pending at this height (a reorg deeper than
    /// `vote_depth`). Never re-proposed and never re-signed: signing a second
    /// hash at one height is equivocation.
    Conflicting { pending: Hash },
    /// `CheckpointManager::ensure_proposed` refused (e.g. the block is not in
    /// this node's DAG store, or the height is not a boundary).
    ProposeFailed(String),
}

#[derive(Default)]
struct GadgetState {
    /// §11.5: signature-valid votes received before this node proposed the
    /// checkpoint they name, keyed by `(height, block_hash)`.
    early: BTreeMap<(u64, Hash), HashMap<PublicKey, CheckpointVote>>,
    /// Highest canonical tip the node has reported (bounds the buffer horizon).
    observed_tip: u64,
    /// Heights at which THIS node already signed, and the hash it signed. A
    /// second, different hash at the same height is never signed.
    signed: BTreeMap<u64, Hash>,
}

/// The producer/outbound half of checkpoint finality.
pub struct FinalityGadget {
    manager: Arc<CheckpointManager>,
    /// §4.1/§11.6 committee source: the shared proposer selector whose per-epoch
    /// history is filled by `registry_sync` from `ValidatorRegistry.activeSet()`
    /// read at each snapshot block S(E). `None` = no registry configured = no
    /// committee can be derived = nothing is proposed.
    committee_source: Option<Arc<VrfProposerSelector>>,
    enabled: bool,
    state: Mutex<GadgetState>,
}

impl FinalityGadget {
    /// Production constructor: the switch comes from the compiled pin for the
    /// manager's chain id ([`checkpoint_voting_pinned`]).
    pub fn new(
        manager: Arc<CheckpointManager>,
        committee_source: Option<Arc<VrfProposerSelector>>,
    ) -> Self {
        let enabled = checkpoint_voting_pinned(manager.config().chain_id);
        Self::with_switch(manager, committee_source, enabled)
    }

    /// Construct with an explicit switch value. The node never calls this — it
    /// uses [`Self::new`] (compiled pin). Exists so tests can exercise both sides
    /// of the switch without a release that pins it on.
    pub fn with_switch(
        manager: Arc<CheckpointManager>,
        committee_source: Option<Arc<VrfProposerSelector>>,
        enabled: bool,
    ) -> Self {
        Self {
            manager,
            committee_source,
            enabled,
            state: Mutex::new(GadgetState::default()),
        }
    }

    /// Whether the producer path is switched on.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The underlying checkpoint manager.
    pub fn manager(&self) -> &Arc<CheckpointManager> {
        &self.manager
    }

    /// §4.1 / §11.6: the committee for the checkpoint at `height` whose block
    /// carries VRF beacon `seed`.
    ///
    /// Validator set: the epoch snapshot that GOVERNS `height` (the greatest
    /// S(E) < height), from the selector's per-epoch history — never the live
    /// tip set — so two nodes on either side of an epoch boundary derive the
    /// identical committee. Seed: the ECVRF output committed in the header of the
    /// checkpoint block itself (the same beacon proposer election and
    /// `prevrandao` use), fixed by `(height, block_hash)`. `None` when no snapshot
    /// governs `height` on this node.
    pub async fn committee_for(&self, height: u64, seed: &Hash) -> Option<Vec<PublicKey>> {
        let source = self.committee_source.as_ref()?;
        let (_snapshot, set) = source.epoch_committee_set(height).await?;
        let committee =
            CommitteeSelector::select(&set, height, seed, self.manager.config().committee_size);
        if committee.is_empty() {
            None
        } else {
            Some(committee)
        }
    }

    /// §4.2–4.3: the canonical block at boundary `height` is now buried
    /// `vote_depth` deep on this node. Propose `(height, block_hash)` (idempotent),
    /// replay buffered early votes for it, and — if `signer` is in the committee
    /// and has not signed at this height — sign and submit this node's own vote.
    /// The caller broadcasts `outcome.outbound`.
    pub async fn on_buried_checkpoint(
        &self,
        height: u64,
        block_hash: Hash,
        seed: &Hash,
        signer: Option<&Ed25519SigningKey>,
    ) -> BuriedOutcome {
        let mut out = BuriedOutcome::default();
        if !self.enabled {
            out.skipped = Some(SkipReason::Disabled);
            return out;
        }
        let Some(committee) = self.committee_for(height, seed).await else {
            out.skipped = Some(SkipReason::NoCommittee);
            return out;
        };
        let signer_pk = signer.map(|k| PublicKey::new(k.verifying_key().to_bytes()));
        let in_committee = signer_pk.is_some_and(|pk| committee.contains(&pk));

        match self
            .manager
            .ensure_proposed(height, block_hash, committee)
            .await
        {
            Ok(ProposeOutcome::Proposed) => out.proposed = true,
            Ok(ProposeOutcome::AlreadyPending) => {
                out.skipped = Some(SkipReason::AlreadyPending);
                return out;
            }
            Ok(ProposeOutcome::AlreadyFinalized) => {
                out.skipped = Some(SkipReason::AlreadyFinalized);
                return out;
            }
            Ok(ProposeOutcome::ConflictingPending { pending }) => {
                warn!(
                    "checkpoint {}: canonical block {} differs from pending {} (reorg deeper \
                     than vote depth); not re-proposing, not re-signing",
                    height, block_hash, pending
                );
                out.skipped = Some(SkipReason::Conflicting { pending });
                return out;
            }
            Err(e) => {
                warn!(
                    "checkpoint {}: propose of {} failed: {}",
                    height, block_hash, e
                );
                out.skipped = Some(SkipReason::ProposeFailed(e.to_string()));
                return out;
            }
        }

        // Own vote first (it is the one peers are most likely missing).
        if let (Some(key), true) = (signer, in_committee) {
            let may_sign = {
                let mut st = self.state.lock().await;
                match st.signed.get(&height) {
                    Some(prev) => *prev == block_hash,
                    None => {
                        st.signed.insert(height, block_hash);
                        while st.signed.len() > MAX_SIGNED_HEIGHTS {
                            st.signed.pop_first();
                        }
                        true
                    }
                }
            };
            if may_sign {
                let vote =
                    sign_checkpoint_vote(self.manager.config().chain_id, height, block_hash, key);
                match self.manager.submit_vote(vote.clone()).await {
                    Ok(quorum) => {
                        out.signed_own_vote = true;
                        out.outbound.push(vote);
                        if quorum {
                            out.finalized |= self.finalize(height).await;
                        }
                    }
                    Err(e) => warn!("checkpoint {}: own vote not accepted: {}", height, e),
                }
            }
        }

        // §11.5 replay: votes that arrived before this proposal.
        let buffered = {
            let mut st = self.state.lock().await;
            let votes = st.early.remove(&(height, block_hash));
            // Votes for any OTHER hash at this height can never attach now.
            st.early.retain(|(h, _), _| *h != height);
            votes
        };
        if let Some(votes) = buffered {
            let mut votes: Vec<CheckpointVote> = votes.into_values().collect();
            // Deterministic replay order (by voter bytes).
            votes.sort_by(|a, b| a.voter.as_bytes().cmp(b.voter.as_bytes()));
            for vote in votes {
                match self.manager.submit_vote(vote.clone()).await {
                    Ok(quorum) => {
                        out.outbound.push(vote);
                        if quorum {
                            out.finalized |= self.finalize(height).await;
                        }
                    }
                    Err(e) => debug!("checkpoint {}: buffered vote dropped: {}", height, e),
                }
            }
        }

        self.prune().await;
        out
    }

    /// Record the latest canonical tip this node has applied (bounds the
    /// early-vote horizon).
    pub async fn observe_tip(&self, tip: u64) {
        let mut st = self.state.lock().await;
        if tip > st.observed_tip {
            st.observed_tip = tip;
        }
    }

    /// Handle a vote received from a peer.
    ///
    /// Switch OFF: exactly the pre-Stage-1a behavior — `submit_vote`, then
    /// `finalize_checkpoint` on quorum; nothing is buffered or relayed.
    ///
    /// Switch ON: as above when the checkpoint is pending; otherwise a
    /// signature-valid vote for a future boundary is buffered (§11.5). Every vote
    /// accepted for the first time is returned for a single re-gossip.
    pub async fn on_inbound_vote(&self, vote: CheckpointVote) -> InboundOutcome {
        let height = vote.height;
        if !self.enabled {
            return match self.manager.submit_vote(vote).await {
                Ok(true) => self.finalize_outcome(height, None).await,
                Ok(false) => InboundOutcome::Accepted { relay: None },
                Err(e) => InboundOutcome::Rejected(e),
            };
        }

        if self.manager.pending_hash(height).await.is_some() {
            return self.submit_pending(vote).await;
        }
        self.buffer_early(vote).await
    }

    /// Switch ON: submit to the pending checkpoint, finalize on quorum, and hand
    /// back the vote for a single relay when it was accepted.
    async fn submit_pending(&self, vote: CheckpointVote) -> InboundOutcome {
        let height = vote.height;
        match self.manager.submit_vote(vote.clone()).await {
            Ok(true) => {
                let outcome = self.finalize_outcome(height, Some(vote)).await;
                self.prune().await;
                outcome
            }
            Ok(false) => InboundOutcome::Accepted { relay: Some(vote) },
            Err(e) => InboundOutcome::Rejected(e),
        }
    }

    async fn finalize_outcome(&self, height: u64, relay: Option<CheckpointVote>) -> InboundOutcome {
        match self.manager.finalize_checkpoint(height).await {
            Ok(cp) => InboundOutcome::Finalized {
                height: cp.height,
                votes: cp.votes.len(),
                relay,
            },
            Err(error) => InboundOutcome::FinalizeFailed {
                height,
                error,
                relay,
            },
        }
    }

    async fn buffer_early(&self, vote: CheckpointVote) -> InboundOutcome {
        let cfg = self.manager.config();
        let height = vote.height;
        if !cfg.is_checkpoint_height(height) {
            return InboundOutcome::Rejected(CheckpointError::NotCheckpointBoundary);
        }
        if height <= self.manager.latest_finalized_height().await
            || self.manager.is_finalized(height).await
        {
            return InboundOutcome::Rejected(CheckpointError::AlreadyExists(height));
        }
        // Verify before holding: an unverifiable vote must not take buffer space.
        // Committee membership is checked on replay (the committee needs the
        // block at `height`, which this node does not have buried yet).
        if let Err(e) = verify_vote_signature(&vote, cfg.chain_id) {
            return InboundOutcome::Rejected(e);
        }
        let mut st = self.state.lock().await;
        // Re-check under the buffer lock: `on_buried_checkpoint` creates the
        // pending checkpoint BEFORE it takes this lock to drain the buffer, so if
        // the checkpoint appeared since the unlocked check above, submit directly —
        // otherwise the vote would land in a buffer that was already drained.
        // (Lock order buffer -> manager is only ever taken here; no path holds a
        // manager lock while waiting for the buffer lock.)
        if self.manager.pending_hash(height).await.is_some() {
            drop(st);
            return self.submit_pending(vote).await;
        }
        if st.observed_tip > 0 && height > st.observed_tip.saturating_add(EARLY_VOTE_HORIZON_BLOCKS)
        {
            return InboundOutcome::Rejected(CheckpointError::BlockNotFound(vote.block_hash));
        }
        let key = (height, vote.block_hash);
        if !st.early.contains_key(&key) {
            let hashes_at_height = st
                .early
                .range((height, Hash::new([0u8; 32]))..=(height, Hash::new([0xffu8; 32])))
                .count();
            if hashes_at_height >= MAX_EARLY_HASHES_PER_HEIGHT
                || st.early.len() >= MAX_EARLY_VOTE_KEYS
            {
                return InboundOutcome::Rejected(CheckpointError::StorageError(
                    "early-vote buffer full".to_string(),
                ));
            }
        }
        let slot = st.early.entry(key).or_default();
        if slot.contains_key(&vote.voter) {
            return InboundOutcome::Rejected(CheckpointError::DuplicateVote(vote.voter));
        }
        if slot.len() >= MAX_EARLY_VOTES_PER_KEY {
            return InboundOutcome::Rejected(CheckpointError::StorageError(
                "early-vote buffer full for checkpoint".to_string(),
            ));
        }
        slot.insert(vote.voter, vote);
        InboundOutcome::Buffered
    }

    async fn finalize(&self, height: u64) -> bool {
        match self.manager.finalize_checkpoint(height).await {
            Ok(cp) => {
                info!(
                    "checkpoint finalized at height {} ({} votes)",
                    cp.height,
                    cp.votes.len()
                );
                true
            }
            Err(e) => {
                warn!("checkpoint {}: finalize failed: {}", height, e);
                false
            }
        }
    }

    /// §11.9: drop everything at or below the latest finalized height — pending
    /// checkpoints, per-height voted markers (in the manager), buffered early
    /// votes and signed-height records (here).
    pub async fn prune(&self) {
        let floor = self.manager.latest_finalized_height().await;
        self.manager.prune_at_or_below(floor).await;
        let mut st = self.state.lock().await;
        st.early.retain(|(h, _), _| *h > floor);
        st.signed.retain(|h, _| *h > floor);
    }

    /// Number of `(height, hash)` keys in the early-vote buffer.
    pub async fn early_vote_keys(&self) -> usize {
        self.state.lock().await.early.len()
    }

    /// Total votes held in the early-vote buffer.
    pub async fn early_vote_count(&self) -> usize {
        self.state
            .lock()
            .await
            .early
            .values()
            .fold(0usize, |acc, m| acc.saturating_add(m.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{canonical_vote_message, CheckpointConfig, MAX_PENDING_CHECKPOINTS};
    use crate::dag_store::DagStore;
    use crate::types::{BlockBuilder, Signature};
    use ed25519_dalek::{Signer, SigningKey};

    const CHAIN: u64 = 40204;

    fn key(id: u8) -> SigningKey {
        let mut seed = [0u8; 32];
        seed[0] = id;
        seed[1] = 0xC7;
        SigningKey::from_bytes(&seed)
    }

    fn pk(k: &SigningKey) -> PublicKey {
        PublicKey::new(k.verifying_key().to_bytes())
    }

    fn config() -> CheckpointConfig {
        CheckpointConfig {
            interval: 2,
            committee_size: 100,
            quorum_threshold: 67,
            chain_id: CHAIN,
            vote_depth: 3,
        }
    }

    /// A selector on schedule (EPOCH 1000, LAG 999) — S(1) = 1 governs heights
    /// 2..=1000 — whose S(1) snapshot holds `keys` at stake 1000.
    async fn selector_with(keys: &[SigningKey]) -> Arc<VrfProposerSelector> {
        let sel = VrfProposerSelector::new().with_snapshot_schedule(1000, 999);
        let set: Vec<(PublicKey, u128)> = keys.iter().map(|k| (pk(k), 1000u128)).collect();
        sel.sync_active_set_at(1, set, 1).await;
        Arc::new(sel)
    }

    /// DAG with blocks at heights 0..=len-1, hashes [i+1; 32].
    async fn dag_with(len: u8) -> Arc<DagStore> {
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let mut parent = Hash::default();
        for i in 0..len {
            let b = BlockBuilder::new()
                .hash(Hash::new([i.saturating_add(1); 32]))
                .height(u64::from(i))
                .parent(parent)
                .build_unhashed();
            parent = b.hash();
            dag.store_block(b).await.expect("store test block");
        }
        dag
    }

    fn block_hash(height: u8) -> Hash {
        Hash::new([height.saturating_add(1); 32])
    }

    async fn gadget(keys: &[SigningKey], enabled: bool) -> FinalityGadget {
        let mgr = Arc::new(CheckpointManager::new(config(), dag_with(40).await));
        FinalityGadget::with_switch(mgr, Some(selector_with(keys).await), enabled)
    }

    fn keys(n: u8) -> Vec<SigningKey> {
        (0..n).map(key).collect()
    }

    #[test]
    fn compiled_pin_is_off_for_every_chain_in_this_release() {
        assert!(!checkpoint_voting_pinned(40204));
        assert!(!checkpoint_voting_pinned(1337));
        assert!(!checkpoint_voting_pinned(0));
        assert!(pinned_in(&[(7, true)], 7));
        assert!(!pinned_in(&[(7, true)], 8));
    }

    #[tokio::test]
    async fn production_constructor_follows_the_pin() {
        let mgr = Arc::new(CheckpointManager::new(config(), dag_with(4).await));
        let g = FinalityGadget::new(mgr, None);
        assert!(!g.enabled(), "40204 is pinned OFF in this release");
    }

    /// Switch OFF: no propose, no own vote, no buffering, no relay.
    #[tokio::test]
    async fn switch_off_is_a_no_op() {
        let ks = keys(4);
        let g = gadget(&ks, false).await;
        let out = g
            .on_buried_checkpoint(10, block_hash(10), &Hash::new([9; 32]), ks.first())
            .await;
        assert_eq!(out.skipped, Some(SkipReason::Disabled));
        assert!(!out.proposed && !out.signed_own_vote && out.outbound.is_empty());
        assert_eq!(g.manager().pending_hash(10).await, None);

        // Inbound vote for an unproposed checkpoint: rejected as before, not buffered.
        let k1 = ks.get(1).expect("key 1");
        let v = sign_checkpoint_vote(CHAIN, 10, block_hash(10), k1);
        let res = g.on_inbound_vote(v).await;
        assert!(matches!(res, InboundOutcome::Rejected(_)), "got {res:?}");
        assert!(res.relay().is_none());
        assert_eq!(g.early_vote_keys().await, 0);
    }

    /// §11.6 cross-epoch determinism: node A has already crossed into epoch 2
    /// (its LIVE set is epoch 2's) while node B is still in epoch 1. For a
    /// checkpoint governed by epoch 1 both derive the identical committee; for
    /// one governed by epoch 2, B derives NONE rather than a wrong committee.
    #[tokio::test]
    async fn committee_is_epoch_pinned_across_an_epoch_boundary() {
        let epoch1: Vec<SigningKey> = (0u8..12).map(key).collect();
        let epoch2: Vec<SigningKey> = (50u8..62).map(key).collect();
        let set = |ks: &[SigningKey]| -> Vec<(PublicKey, u128)> {
            ks.iter()
                .enumerate()
                .map(|(i, k)| (pk(k), 1000u128.saturating_add(i as u128)))
                .collect()
        };
        // Schedule EPOCH 10, LAG 2: S(1) = 8 governs 9..=18, S(2) = 18 governs 19..=28.
        let a = Arc::new(VrfProposerSelector::new().with_snapshot_schedule(10, 2));
        a.sync_active_set_at(8, set(&epoch1), 1).await;
        a.sync_active_set_at(18, set(&epoch2), 1).await;
        let b = Arc::new(VrfProposerSelector::new().with_snapshot_schedule(10, 2));
        b.sync_active_set_at(8, set(&epoch1), 1).await;

        let mut cfg = config();
        cfg.committee_size = 5;
        let ga = FinalityGadget::with_switch(
            Arc::new(CheckpointManager::new(cfg.clone(), dag_with(30).await)),
            Some(a.clone()),
            true,
        );
        let gb = FinalityGadget::with_switch(
            Arc::new(CheckpointManager::new(cfg, dag_with(30).await)),
            Some(b),
            true,
        );
        let seed = Hash::new([0x42; 32]);
        let ca = ga.committee_for(12, &seed).await.expect("A committee @12");
        let cb = gb.committee_for(12, &seed).await.expect("B committee @12");
        assert_eq!(
            ca, cb,
            "same epoch-1 committee on both sides of the boundary"
        );
        assert_eq!(ca.len(), 5);
        let epoch1_pks: Vec<PublicKey> = epoch1.iter().map(pk).collect();
        assert!(
            ca.iter().all(|m| epoch1_pks.contains(m)),
            "drawn from epoch 1"
        );
        // A's LIVE set is epoch 2's: a tip-set committee would have differed.
        let live = CommitteeSelector::select(&set(&epoch2), 12, &seed, 5);
        assert_ne!(ca, live, "must not use the live tip set");
        // Epoch-2 checkpoint: A can derive it, B (not yet materialized) cannot.
        assert!(ga.committee_for(20, &seed).await.is_some());
        assert!(gb.committee_for(20, &seed).await.is_none());
        // Same inputs => same committee (seed fixed by H's block).
        assert_eq!(ga.committee_for(12, &seed).await, Some(ca.clone()));
        assert_ne!(
            ga.committee_for(12, &Hash::new([0x43; 32])).await,
            Some(ca),
            "seed is an input"
        );
    }

    /// Below-min-stake members are not committee candidates.
    #[tokio::test]
    async fn committee_excludes_members_below_min_stake() {
        let ks = keys(5);
        let sel = VrfProposerSelector::new().with_snapshot_schedule(1000, 999);
        let entries: Vec<(PublicKey, u128)> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| (pk(k), if i == 0 { 10 } else { 1000 }))
            .collect();
        sel.sync_active_set_at(1, entries, 500).await;
        let mgr = Arc::new(CheckpointManager::new(config(), dag_with(4).await));
        let g = FinalityGadget::with_switch(mgr, Some(Arc::new(sel)), true);
        let c = g
            .committee_for(10, &Hash::new([1; 32]))
            .await
            .expect("committee");
        assert_eq!(c.len(), 4);
        let k0 = ks.first().expect("key 0");
        assert!(!c.contains(&pk(k0)));
    }

    /// Vote construction binds chain_id, height and block_hash.
    #[test]
    fn vote_construction_binds_chain_height_hash() {
        let k = key(3);
        let h = Hash::new([0x5a; 32]);
        let v = sign_checkpoint_vote(CHAIN, 12, h, &k);
        assert_eq!(v.height, 12);
        assert_eq!(v.block_hash, h);
        assert_eq!(v.voter, pk(&k));
        assert!(verify_vote_signature(&v, CHAIN).is_ok());
        assert!(verify_vote_signature(&v, 1337).is_err(), "other chain");
        let mut wrong_h = v.clone();
        wrong_h.height = 14;
        assert!(
            verify_vote_signature(&wrong_h, CHAIN).is_err(),
            "other height"
        );
        let mut wrong_hash = v.clone();
        wrong_hash.block_hash = Hash::new([0x5b; 32]);
        assert!(
            verify_vote_signature(&wrong_hash, CHAIN).is_err(),
            "other hash"
        );
        // Byte-identical to signing the canonical message directly.
        let direct = k.sign(&canonical_vote_message(CHAIN, 12, &h));
        assert_eq!(v.signature, Signature::new(direct.to_bytes()));
    }

    /// Quorum edge: committees of 1..=3 never finalize even with every vote; 4
    /// finalizes at 3 votes.
    #[tokio::test]
    async fn quorum_edges_for_set_sizes_one_to_four() {
        for n in 1u8..=4 {
            let ks = keys(n);
            let g = gadget(&ks, true).await;
            let seed = Hash::new([7; 32]);
            let committee = g.committee_for(10, &seed).await.expect("committee");
            assert_eq!(committee.len(), usize::from(n));
            let first = ks.first().expect("first key");
            let out = g
                .on_buried_checkpoint(10, block_hash(10), &seed, Some(first))
                .await;
            assert!(out.proposed && out.signed_own_vote);
            let mut finalized = out.finalized;
            for k in ks.iter().skip(1) {
                let res = g
                    .on_inbound_vote(sign_checkpoint_vote(CHAIN, 10, block_hash(10), k))
                    .await;
                if matches!(res, InboundOutcome::Finalized { .. }) {
                    finalized = true;
                }
            }
            let latest = g.manager().latest_finalized_height().await;
            if n < 4 {
                assert!(!finalized, "n={n} must never finalize");
                assert_eq!(latest, 0, "n={n}");
            } else {
                assert!(finalized, "n=4 finalizes");
                assert_eq!(latest, 10);
            }
        }
    }

    /// propose is idempotent per (H, hash) and never re-signs.
    #[tokio::test]
    async fn propose_is_idempotent_and_never_double_signs() {
        let ks = keys(5);
        let g = gadget(&ks, true).await;
        let seed = Hash::new([1; 32]);
        let k0 = ks.first().expect("key 0");
        let first = g
            .on_buried_checkpoint(10, block_hash(10), &seed, Some(k0))
            .await;
        assert!(first.proposed);
        let again = g
            .on_buried_checkpoint(10, block_hash(10), &seed, Some(k0))
            .await;
        assert_eq!(again.skipped, Some(SkipReason::AlreadyPending));
        assert!(again.outbound.is_empty());
        // A different hash at the same height (deep reorg): no re-propose, no vote.
        let other = g
            .on_buried_checkpoint(10, block_hash(11), &seed, Some(k0))
            .await;
        assert_eq!(
            other.skipped,
            Some(SkipReason::Conflicting {
                pending: block_hash(10)
            })
        );
        assert!(other.outbound.is_empty());
    }

    /// A node not in the committee proposes but does not sign.
    #[tokio::test]
    async fn non_member_proposes_but_does_not_vote() {
        let ks = keys(4);
        let g = gadget(&ks, true).await;
        let outsider = key(200);
        let out = g
            .on_buried_checkpoint(10, block_hash(10), &Hash::new([3; 32]), Some(&outsider))
            .await;
        assert!(out.proposed);
        assert!(!out.signed_own_vote);
        assert!(out.outbound.is_empty());
    }

    /// §11.5: votes that arrive before propose are buffered and replayed; the
    /// replayed votes are relayed exactly once.
    #[tokio::test]
    async fn early_votes_are_buffered_then_replayed_on_propose() {
        let ks = keys(4);
        let g = gadget(&ks, true).await;
        for k in ks.iter().skip(1) {
            let res = g
                .on_inbound_vote(sign_checkpoint_vote(CHAIN, 10, block_hash(10), k))
                .await;
            assert!(matches!(res, InboundOutcome::Buffered), "got {res:?}");
        }
        assert_eq!(g.early_vote_count().await, 3);
        // A re-delivery of a buffered vote is a duplicate, not a second entry.
        let k1 = ks.get(1).expect("key 1");
        let dup = g
            .on_inbound_vote(sign_checkpoint_vote(CHAIN, 10, block_hash(10), k1))
            .await;
        assert!(matches!(dup, InboundOutcome::Rejected(_)));
        assert_eq!(g.early_vote_count().await, 3);

        // Propose WITHOUT a signer: the three buffered votes alone reach quorum 3.
        let out = g
            .on_buried_checkpoint(10, block_hash(10), &Hash::new([4; 32]), None)
            .await;
        assert!(out.proposed);
        assert_eq!(out.outbound.len(), 3, "each replayed vote relayed once");
        assert!(out.finalized);
        assert_eq!(g.manager().latest_finalized_height().await, 10);
        assert_eq!(g.early_vote_keys().await, 0);
    }

    /// Relay dedupe: a vote is relayed the first time it is accepted, and a
    /// re-delivery (the echo of our own relay) is not relayed again.
    #[tokio::test]
    async fn relay_happens_once_per_vote() {
        let ks = keys(7);
        let g = gadget(&ks, true).await;
        let out = g
            .on_buried_checkpoint(10, block_hash(10), &Hash::new([5; 32]), None)
            .await;
        assert!(out.proposed);
        let k2 = ks.get(2).expect("key 2");
        let v = sign_checkpoint_vote(CHAIN, 10, block_hash(10), k2);
        let first = g.on_inbound_vote(v.clone()).await;
        assert!(first.relay().is_some(), "first acceptance relays");
        let echo = g.on_inbound_vote(v).await;
        assert!(echo.relay().is_none(), "echo is not relayed");
        assert!(matches!(
            echo,
            InboundOutcome::Rejected(CheckpointError::DuplicateVote(_))
        ));
    }

    /// Invalid early votes take no buffer space.
    #[tokio::test]
    async fn buffer_rejects_invalid_and_out_of_horizon_votes() {
        let ks = keys(4);
        let g = gadget(&ks, true).await;
        let k1 = ks.get(1).expect("key 1");
        // Not a boundary (interval 2).
        let odd = sign_checkpoint_vote(CHAIN, 11, block_hash(11), k1);
        assert!(matches!(
            g.on_inbound_vote(odd).await,
            InboundOutcome::Rejected(CheckpointError::NotCheckpointBoundary)
        ));
        // Wrong chain id.
        let foreign = sign_checkpoint_vote(1337, 10, block_hash(10), k1);
        assert!(matches!(
            g.on_inbound_vote(foreign).await,
            InboundOutcome::Rejected(CheckpointError::InvalidSignature(_))
        ));
        // Far beyond the observed tip.
        g.observe_tip(20).await;
        let far = 20u64
            .saturating_add(EARLY_VOTE_HORIZON_BLOCKS)
            .saturating_add(2);
        let far_vote = sign_checkpoint_vote(CHAIN, far, block_hash(10), k1);
        assert!(matches!(
            g.on_inbound_vote(far_vote).await,
            InboundOutcome::Rejected(_)
        ));
        assert_eq!(g.early_vote_keys().await, 0);
    }

    /// §11.5 bound: the buffer never exceeds its key/hash caps under a flood.
    #[tokio::test]
    async fn early_buffer_is_bounded_under_flood() {
        let ks = keys(4);
        let g = gadget(&ks, true).await;
        let k1 = ks.get(1).expect("key 1");
        // Many hashes at one height.
        for i in 0u8..20 {
            let v = sign_checkpoint_vote(CHAIN, 10, Hash::new([i.saturating_add(100); 32]), k1);
            let _ = g.on_inbound_vote(v).await;
        }
        assert!(g.early_vote_keys().await <= MAX_EARLY_HASHES_PER_HEIGHT);
        // Many heights.
        for h in 0u64..200 {
            let height = 12u64.saturating_add(h.saturating_mul(2));
            let v = sign_checkpoint_vote(CHAIN, height, Hash::new([1; 32]), k1);
            let _ = g.on_inbound_vote(v).await;
        }
        assert!(g.early_vote_keys().await <= MAX_EARLY_VOTE_KEYS);
    }

    /// §11.9: finalization prunes pending + voted + buffered state at/below it,
    /// and a quorum stall cannot grow pending past its cap.
    #[tokio::test]
    async fn pruning_bounds_memory_during_stall_and_after_finality() {
        // 3-member committee: never finalizes => a permanent quorum stall.
        let ks = keys(3);
        let mgr = Arc::new(CheckpointManager::new(config(), dag_with(250).await));
        let g = FinalityGadget::with_switch(mgr, Some(selector_with(&ks).await), true);
        let k0 = ks.first().expect("key 0");
        for h in (10u64..=240).step_by(2) {
            let hash = Hash::new([u8::try_from(h).expect("h < 256").saturating_add(1); 32]);
            let out = g
                .on_buried_checkpoint(h, hash, &Hash::new([2; 32]), Some(k0))
                .await;
            assert!(out.proposed, "h={h}");
        }
        assert!(g.manager().pending_len().await <= MAX_PENDING_CHECKPOINTS);
        assert!(g.manager().voted_len().await <= MAX_PENDING_CHECKPOINTS.saturating_mul(3));

        // Now a healthy committee finalizes height 30 => everything <= 30 pruned.
        let ks4 = keys(4);
        let g4 = gadget(&ks4, true).await;
        let seed = Hash::new([6; 32]);
        for h in [26u64, 28, 30] {
            let _ = g4
                .on_buried_checkpoint(h, block_hash(u8::try_from(h).expect("small")), &seed, None)
                .await;
        }
        let k1 = ks4.get(1).expect("key 1");
        let _ = g4
            .on_inbound_vote(sign_checkpoint_vote(CHAIN, 32, block_hash(32), k1))
            .await;
        for k in ks4.iter().take(3) {
            let _ = g4
                .on_inbound_vote(sign_checkpoint_vote(CHAIN, 30, block_hash(30), k))
                .await;
        }
        assert_eq!(g4.manager().latest_finalized_height().await, 30);
        assert_eq!(
            g4.manager().pending_len().await,
            0,
            "26/28 pruned, 30 finalized"
        );
        assert_eq!(g4.manager().voted_len().await, 0);
        assert_eq!(
            g4.early_vote_keys().await,
            1,
            "only the h=32 early vote survives"
        );
    }
}
