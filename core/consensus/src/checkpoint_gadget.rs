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
// SIGNING PROTECTION (PR #321 review, P2). Before this node's vote is signed,
// submitted locally or broadcast, the decision `(chain_id, height) -> block_hash`
// is written to the manager's persistent store with a synced (fsync'd) write.
// Every later sign attempt — including after a restart, on a fresh gadget over
// the same store — consults that record: same hash = idempotent re-sign (the
// ed25519 signature is deterministic, so the identical vote), different hash =
// refused and logged as a safety stop. If the write fails, or there is no
// persistent store, nothing is signed. See [`SignRefusal`].
//
// NOT HERE (Stage 1c): floor ENFORCEMENT (§4.5). Finalizing a checkpoint advances
// `CheckpointManager::latest_finalized_height()` only; nothing in this module
// raises the reorg floor.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::checkpoint::{
    sign_checkpoint_vote, verify_vote_signature, CheckpointError, CheckpointManager,
    CheckpointVote, CommitteeSelector, ProposeOutcome,
};
use crate::crypto::Ed25519SigningKey;
use crate::dag_store::{cf, KvOp, KvStore};
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
/// Bound on the durable signed-vote record, in checkpoint boundaries: records
/// are kept for at most this many boundaries below the highest height this node
/// has signed. Older records are deleted together with raising the durable
/// signed floor past them (see [`SignRefusal::BelowSignedFloor`]), so pruning
/// above the finalized floor never re-opens a height for signing.
pub const MAX_SIGNED_HEIGHTS: usize = 1024;

/// `DAG_METADATA` key prefix of the durable signed-vote record:
/// `checkpoint_signed:<chain_id>:<height>` -> the 32-byte block hash signed.
/// (Distinct from the manager's `checkpoint:` finalized-certificate prefix.)
pub const SIGNED_VOTE_KEY_PREFIX: &str = "checkpoint_signed:";
/// `DAG_METADATA` key prefix of the signed-vote watermarks:
/// `checkpoint_signed_meta:<chain_id>` -> 16 bytes, `floor || highest` (u64 BE).
pub const SIGNED_VOTE_META_PREFIX: &str = "checkpoint_signed_meta:";

/// Key of the durable record of this node's vote at `(chain_id, height)`.
pub fn signed_vote_key(chain_id: u64, height: u64) -> Vec<u8> {
    format!("{SIGNED_VOTE_KEY_PREFIX}{chain_id}:{height}").into_bytes()
}

/// Key of the durable signed-vote watermarks for `chain_id`.
pub fn signed_vote_meta_key(chain_id: u64) -> Vec<u8> {
    format!("{SIGNED_VOTE_META_PREFIX}{chain_id}").into_bytes()
}

/// Durable watermarks of the signed-vote record.
///
/// * `floor`: this node never signs at a height `<= floor`, and every record at
///   or below it has been deleted (in the same atomic, synced batch that raised
///   it). Raised to the finalized height on prune, and to
///   `highest - MAX_SIGNED_HEIGHTS * interval` when signing, so records only
///   ever exist in `(floor, highest]` and that span is bounded.
/// * `highest`: the highest height this node has signed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignedVoteMeta {
    pub floor: u64,
    pub highest: u64,
}

impl SignedVoteMeta {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&self.floor.to_be_bytes());
        out.extend_from_slice(&self.highest.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let raw: [u8; 16] = bytes.try_into().ok()?;
        let (f, h) = raw.split_at(8);
        Some(Self {
            floor: u64::from_be_bytes(f.try_into().ok()?),
            highest: u64::from_be_bytes(h.try_into().ok()?),
        })
    }
}

/// Why this node refused to sign its own vote at a height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignRefusal {
    /// The manager has no persistent store: a signing decision could not survive
    /// a restart, so none is made (fail closed).
    NoDurableStore,
    /// Reading or durably writing the signed-vote record failed.
    StoreUnavailable(String),
    /// This node already signed a DIFFERENT hash at this height (possibly before
    /// a restart). Signing again would be equivocation: a safety stop.
    Conflicting { signed: Hash },
    /// The height is at or below the durable signed floor.
    BelowSignedFloor { floor: u64 },
    /// A stored record or watermark did not decode (fail closed).
    CorruptRecord(String),
}

/// Boundary heights in `(after, upto]` for `interval`, ascending, at most
/// `MAX_SIGNED_HEIGHTS + 1` of them (the records only ever span that many).
fn boundaries_between(after: u64, upto: u64, interval: u64) -> Vec<u64> {
    let mut out = Vec::new();
    if interval == 0 || upto <= after {
        return out;
    }
    let Some(first) = after
        .checked_div(interval)
        .and_then(|q| q.checked_add(1))
        .and_then(|q| q.checked_mul(interval))
    else {
        return out;
    };
    let mut h = first;
    while h <= upto && out.len() <= MAX_SIGNED_HEIGHTS {
        out.push(h);
        match h.checked_add(interval) {
            Some(next) => h = next,
            None => break,
        }
    }
    out
}

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
    /// Why this node (a committee member with a signer) did NOT sign its own
    /// vote, when it did not. Nothing was submitted or broadcast for it.
    pub sign_refused: Option<SignRefusal>,
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
    /// Cached durable signed-vote watermarks, loaded from the store on first use
    /// (never at construction, so a switched-OFF gadget never touches the
    /// store) and updated only after a successful synced write.
    signed_meta: Option<SignedVoteMeta>,
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

        // Own vote first (it is the one peers are most likely missing). The
        // signing decision is made durable BEFORE the vote exists.
        if let (Some(key), true) = (signer, in_committee) {
            let authorized = {
                let mut st = self.state.lock().await;
                self.authorize_sign(&mut st, height, block_hash)
            };
            if let Err(refusal) = &authorized {
                match refusal {
                    SignRefusal::Conflicting { signed } => error!(
                        "checkpoint {}: SAFETY STOP — this node already signed {} at this \
                         height; refusing to sign {} (would be equivocation)",
                        height, signed, block_hash
                    ),
                    other => error!(
                        "checkpoint {}: not signing {}: {:?}",
                        height, block_hash, other
                    ),
                }
                out.sign_refused = Some(refusal.clone());
            }
            if authorized.is_ok() {
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

    /// The durable signed-vote watermarks, loading them on first use.
    fn signed_meta(
        &self,
        st: &mut GadgetState,
        kv: &Arc<dyn KvStore>,
    ) -> Result<SignedVoteMeta, SignRefusal> {
        if let Some(meta) = st.signed_meta {
            return Ok(meta);
        }
        let key = signed_vote_meta_key(self.manager.config().chain_id);
        let meta = match kv.kv_get(cf::DAG_METADATA, &key) {
            Ok(None) => SignedVoteMeta::default(),
            Ok(Some(bytes)) => SignedVoteMeta::decode(&bytes).ok_or_else(|| {
                SignRefusal::CorruptRecord(format!("signed-vote watermarks: {} bytes", bytes.len()))
            })?,
            Err(e) => return Err(SignRefusal::StoreUnavailable(e)),
        };
        st.signed_meta = Some(meta);
        Ok(meta)
    }

    /// Equivocation protection across restarts. Decide whether this node may
    /// sign `block_hash` at `height`, and — for a first signature at `height` —
    /// durably record the decision BEFORE returning `Ok`. Caller holds the state
    /// lock, which serializes every check-then-write.
    ///
    /// Data source: the manager's persistent store, `DAG_METADATA`
    /// `checkpoint_signed:<chain_id>:<height>` and `checkpoint_signed_meta:<chain_id>`,
    /// written with `KvStore::kv_write_batch` (atomic; `RocksDbKvStore` commits
    /// it with `write_batch_sync`, i.e. WAL fsync before returning).
    fn authorize_sign(
        &self,
        st: &mut GadgetState,
        height: u64,
        block_hash: Hash,
    ) -> Result<(), SignRefusal> {
        let kv = self
            .manager
            .persistent_store()
            .ok_or(SignRefusal::NoDurableStore)?;
        let meta = self.signed_meta(st, kv)?;
        if height <= meta.floor {
            return Err(SignRefusal::BelowSignedFloor { floor: meta.floor });
        }
        let chain_id = self.manager.config().chain_id;
        let record_key = signed_vote_key(chain_id, height);
        match kv.kv_get(cf::DAG_METADATA, &record_key) {
            Ok(Some(bytes)) => {
                let raw: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    SignRefusal::CorruptRecord(format!(
                        "signed-vote record at {height}: {} bytes",
                        bytes.len()
                    ))
                })?;
                let signed = Hash::new(raw);
                return if signed == block_hash {
                    Ok(()) // idempotent: the identical vote again
                } else {
                    Err(SignRefusal::Conflicting { signed })
                };
            }
            Ok(None) => {}
            Err(e) => return Err(SignRefusal::StoreUnavailable(e)),
        }

        // First signature at `height`: bound the record span, then write the
        // record + watermarks (+ deletions below the new floor) atomically.
        let interval = self.manager.config().interval.max(1);
        let horizon = interval.saturating_mul(MAX_SIGNED_HEIGHTS as u64);
        let highest = meta.highest.max(height);
        let floor = meta.floor.max(highest.saturating_sub(horizon));
        if height <= floor {
            return Err(SignRefusal::BelowSignedFloor { floor });
        }
        let next = SignedVoteMeta { floor, highest };
        let mut ops = vec![
            KvOp::Put {
                cf: cf::DAG_METADATA.to_string(),
                key: record_key,
                value: block_hash.as_bytes().to_vec(),
            },
            KvOp::Put {
                cf: cf::DAG_METADATA.to_string(),
                key: signed_vote_meta_key(chain_id),
                value: next.encode(),
            },
        ];
        for h in boundaries_between(meta.floor, floor.min(meta.highest), interval) {
            ops.push(KvOp::Delete {
                cf: cf::DAG_METADATA.to_string(),
                key: signed_vote_key(chain_id, h),
            });
        }
        kv.kv_write_batch(&ops)
            .map_err(SignRefusal::StoreUnavailable)?;
        st.signed_meta = Some(next);
        Ok(())
    }

    /// Raise the durable signed floor to `floor` and delete the records at or
    /// below it, in one atomic synced batch. Failure is safe: the records and
    /// the old floor remain, and are retried on the next prune.
    fn prune_signed_records(&self, st: &mut GadgetState, floor: u64) {
        let Some(kv) = self.manager.persistent_store() else {
            return;
        };
        let meta = match self.signed_meta(st, kv) {
            Ok(m) => m,
            Err(e) => {
                warn!("checkpoint: signed-vote record not pruned: {:?}", e);
                return;
            }
        };
        if floor <= meta.floor {
            return;
        }
        let chain_id = self.manager.config().chain_id;
        let interval = self.manager.config().interval.max(1);
        let next = SignedVoteMeta {
            floor,
            highest: meta.highest,
        };
        let mut ops = vec![KvOp::Put {
            cf: cf::DAG_METADATA.to_string(),
            key: signed_vote_meta_key(chain_id),
            value: next.encode(),
        }];
        for h in boundaries_between(meta.floor, floor.min(meta.highest), interval) {
            ops.push(KvOp::Delete {
                cf: cf::DAG_METADATA.to_string(),
                key: signed_vote_key(chain_id, h),
            });
        }
        match kv.kv_write_batch(&ops) {
            Ok(()) => st.signed_meta = Some(next),
            Err(e) => warn!(
                "checkpoint: signed-vote record prune to {} failed: {}",
                floor, e
            ),
        }
    }

    /// §11.9: drop everything at or below the latest finalized height — pending
    /// checkpoints, per-height voted markers (in the manager), buffered early
    /// votes and, switch ON only, the durable signed-vote records (here; the
    /// signed floor is raised in the same write, so a pruned height can never be
    /// signed again).
    pub async fn prune(&self) {
        let floor = self.manager.latest_finalized_height().await;
        self.manager.prune_at_or_below(floor).await;
        let mut st = self.state.lock().await;
        st.early.retain(|(h, _), _| *h > floor);
        if self.enabled && floor > 0 {
            self.prune_signed_records(&mut st, floor);
        }
    }

    /// The durable record of this node's own vote at `height`, if any
    /// (`checkpoint_signed:<chain_id>:<height>`). `None` also when there is no
    /// persistent store or the read fails.
    pub fn signed_vote_at(&self, height: u64) -> Option<Hash> {
        let kv = self.manager.persistent_store()?;
        let key = signed_vote_key(self.manager.config().chain_id, height);
        let bytes = kv.kv_get(cf::DAG_METADATA, &key).ok()??;
        let raw: [u8; 32] = bytes.as_slice().try_into().ok()?;
        Some(Hash::new(raw))
    }

    /// The durable signed-vote watermarks as stored (`None` = none written yet,
    /// no store, or unreadable).
    pub fn signed_vote_meta(&self) -> Option<SignedVoteMeta> {
        let kv = self.manager.persistent_store()?;
        let key = signed_vote_meta_key(self.manager.config().chain_id);
        let bytes = kv.kv_get(cf::DAG_METADATA, &key).ok()??;
        SignedVoteMeta::decode(&bytes)
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
    use std::sync::atomic::{AtomicBool, Ordering};

    const CHAIN: u64 = 40204;

    /// (column family, key) -> value.
    type MemMap = HashMap<(String, Vec<u8>), Vec<u8>>;

    /// In-memory persistent store. `fail_writes` makes every put / delete /
    /// batch fail (a full or broken disk); reads keep working.
    #[derive(Default)]
    struct MemKv {
        inner: std::sync::Mutex<MemMap>,
        fail_writes: AtomicBool,
        batches: std::sync::atomic::AtomicUsize,
    }

    impl MemKv {
        fn failing() -> Self {
            let kv = Self::default();
            kv.fail_writes.store(true, Ordering::SeqCst);
            kv
        }
        fn check_writable(&self) -> Result<(), String> {
            if self.fail_writes.load(Ordering::SeqCst) {
                Err("injected write failure".to_string())
            } else {
                Ok(())
            }
        }
        fn keys_with_prefix(&self, prefix: &str) -> usize {
            self.inner
                .lock()
                .expect("memkv lock")
                .keys()
                .filter(|(_, k)| k.starts_with(prefix.as_bytes()))
                .count()
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
            self.check_writable()?;
            self.inner
                .lock()
                .map_err(|e| e.to_string())?
                .insert((cf.to_string(), key.to_vec()), value.to_vec());
            Ok(())
        }
        fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
            self.check_writable()?;
            self.inner
                .lock()
                .map_err(|e| e.to_string())?
                .remove(&(cf.to_string(), key.to_vec()));
            Ok(())
        }
        fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
            Ok(self.kv_get(cf, key)?.is_some())
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
        /// Atomic: all ops or none.
        fn kv_write_batch(&self, ops: &[KvOp]) -> Result<(), String> {
            self.check_writable()?;
            self.batches.fetch_add(1, Ordering::SeqCst);
            let mut m = self.inner.lock().map_err(|e| e.to_string())?;
            for op in ops {
                match op {
                    KvOp::Put { cf, key, value } => {
                        m.insert((cf.clone(), key.clone()), value.clone());
                    }
                    KvOp::Delete { cf, key } => {
                        m.remove(&(cf.clone(), key.clone()));
                    }
                }
            }
            Ok(())
        }
    }

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

    async fn gadget_over(
        keys: &[SigningKey],
        enabled: bool,
        kv: Arc<MemKv>,
        dag_len: u8,
    ) -> FinalityGadget {
        let kv: Arc<dyn KvStore> = kv;
        let mgr = Arc::new(CheckpointManager::with_persistence(
            config(),
            dag_with(dag_len).await,
            kv,
        ));
        FinalityGadget::with_switch(mgr, Some(selector_with(keys).await), enabled)
    }

    async fn gadget(keys: &[SigningKey], enabled: bool) -> FinalityGadget {
        gadget_over(keys, enabled, Arc::new(MemKv::default()), 40).await
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
        let g = gadget_over(&ks, true, Arc::new(MemKv::default()), 250).await;
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

    /// Write-before-sign: a store that refuses writes yields NO signature — the
    /// vote is neither submitted locally nor returned for broadcast.
    #[tokio::test]
    async fn failed_durable_write_means_no_signature() {
        let ks = keys(4);
        let kv = Arc::new(MemKv::failing());
        let g = gadget_over(&ks, true, kv.clone(), 40).await;
        let k0 = ks.first().expect("key 0");
        let out = g
            .on_buried_checkpoint(10, block_hash(10), &Hash::new([1; 32]), Some(k0))
            .await;
        assert!(out.proposed, "aggregation still proceeds");
        assert!(!out.signed_own_vote);
        assert!(out.outbound.is_empty(), "nothing to broadcast");
        assert!(
            matches!(out.sign_refused, Some(SignRefusal::StoreUnavailable(_))),
            "{:?}",
            out.sign_refused
        );
        assert_eq!(g.manager().pending_vote_count(10).await, Some(0));
        assert_eq!(g.signed_vote_at(10), None);
    }

    /// No persistent store at all: fail closed (never sign).
    #[tokio::test]
    async fn no_durable_store_means_no_signature() {
        let ks = keys(4);
        let mgr = Arc::new(CheckpointManager::new(config(), dag_with(40).await));
        let g = FinalityGadget::with_switch(mgr, Some(selector_with(&ks).await), true);
        let out = g
            .on_buried_checkpoint(10, block_hash(10), &Hash::new([1; 32]), ks.first())
            .await;
        assert!(out.proposed && !out.signed_own_vote && out.outbound.is_empty());
        assert_eq!(out.sign_refused, Some(SignRefusal::NoDurableStore));
    }

    /// The record is durable before the vote is emitted, survives a restart
    /// (fresh manager + gadget over the same store), refuses a conflicting hash
    /// and re-signs the same hash idempotently (identical vote bytes).
    #[tokio::test]
    async fn durable_record_refuses_conflict_and_is_idempotent_across_restart() {
        let ks = keys(5);
        let kv = Arc::new(MemKv::default());
        let k0 = ks.first().expect("key 0");
        let seed = Hash::new([1; 32]);
        let first = {
            let g = gadget_over(&ks, true, kv.clone(), 40).await;
            let out = g
                .on_buried_checkpoint(10, block_hash(10), &seed, Some(k0))
                .await;
            assert!(out.signed_own_vote);
            assert_eq!(g.signed_vote_at(10), Some(block_hash(10)));
            assert_eq!(
                g.signed_vote_meta(),
                Some(SignedVoteMeta {
                    floor: 0,
                    highest: 10
                })
            );
            out.outbound.first().cloned().expect("own vote")
        };
        // "Restart" #1, canonical block at 10 is now a different hash.
        let g = gadget_over(&ks, true, kv.clone(), 40).await;
        let out = g
            .on_buried_checkpoint(10, block_hash(11), &seed, Some(k0))
            .await;
        assert!(out.proposed, "fresh manager proposes the new hash");
        assert!(!out.signed_own_vote && out.outbound.is_empty());
        assert_eq!(
            out.sign_refused,
            Some(SignRefusal::Conflicting {
                signed: block_hash(10)
            })
        );
        assert_eq!(g.signed_vote_at(10), Some(block_hash(10)), "unchanged");
        // "Restart" #2, back on the original hash: the identical vote again.
        let g = gadget_over(&ks, true, kv, 40).await;
        let out = g
            .on_buried_checkpoint(10, block_hash(10), &seed, Some(k0))
            .await;
        assert!(out.signed_own_vote);
        let again = out.outbound.first().expect("own vote again");
        assert_eq!(
            (again.height, again.block_hash, again.voter, again.signature),
            (first.height, first.block_hash, first.voter, first.signature),
            "same vote bytes"
        );
    }

    /// Records are bounded: past MAX_SIGNED_HEIGHTS boundaries the floor rises,
    /// old records are deleted and their heights are refused (not re-opened).
    #[tokio::test]
    async fn durable_record_is_bounded_by_the_signing_horizon() {
        let ks = keys(1);
        let kv = Arc::new(MemKv::default());
        let g = gadget_over(&ks, true, kv.clone(), 4).await;
        let mut st = g.state.lock().await;
        let n = u64::try_from(MAX_SIGNED_HEIGHTS)
            .expect("fits")
            .saturating_add(10);
        for i in 1..=n {
            let h = i.saturating_mul(2);
            g.authorize_sign(&mut st, h, Hash::new([7; 32]))
                .expect("authorize");
        }
        drop(st);
        let top = n.saturating_mul(2);
        let meta = g.signed_vote_meta().expect("meta");
        assert_eq!(meta.highest, top);
        assert_eq!(
            meta.floor,
            top.saturating_sub(2 * MAX_SIGNED_HEIGHTS as u64)
        );
        assert_eq!(
            kv.keys_with_prefix(SIGNED_VOTE_KEY_PREFIX),
            MAX_SIGNED_HEIGHTS
        );
        assert_eq!(g.signed_vote_at(2), None, "deleted below the floor");
        let mut st = g.state.lock().await;
        assert_eq!(
            g.authorize_sign(&mut st, 2, Hash::new([8; 32])),
            Err(SignRefusal::BelowSignedFloor { floor: meta.floor })
        );
        drop(st);
        // Never prunes above the floor: the lowest record above it survives.
        assert_eq!(
            g.signed_vote_at(meta.floor.saturating_add(2)),
            Some(Hash::new([7; 32]))
        );
    }

    /// Finality prunes the durable records at/below the finalized height and
    /// raises the signed floor with them; records above it survive.
    #[tokio::test]
    async fn finality_prunes_durable_records_at_or_below_the_floor() {
        let ks = keys(4);
        let kv = Arc::new(MemKv::default());
        let g = gadget_over(&ks, true, kv.clone(), 40).await;
        let seed = Hash::new([6; 32]);
        let k0 = ks.first().expect("key 0");
        for h in [10u64, 12, 14] {
            let out = g
                .on_buried_checkpoint(
                    h,
                    block_hash(u8::try_from(h).expect("small")),
                    &seed,
                    Some(k0),
                )
                .await;
            assert!(out.signed_own_vote, "h={h}");
        }
        for k in ks.iter().skip(1).take(2) {
            let _ = g
                .on_inbound_vote(sign_checkpoint_vote(CHAIN, 12, block_hash(12), k))
                .await;
        }
        assert_eq!(g.manager().latest_finalized_height().await, 12);
        assert_eq!(g.signed_vote_at(10), None);
        assert_eq!(g.signed_vote_at(12), None);
        assert_eq!(g.signed_vote_at(14), Some(block_hash(14)));
        assert_eq!(
            g.signed_vote_meta(),
            Some(SignedVoteMeta {
                floor: 12,
                highest: 14
            })
        );
    }

    /// Switch OFF: the store is never written (byte-identical to pre-Stage-1a).
    #[tokio::test]
    async fn switch_off_never_writes_the_store() {
        let ks = keys(4);
        let kv = Arc::new(MemKv::default());
        let g = gadget_over(&ks, false, kv.clone(), 40).await;
        let before = kv.batches.load(Ordering::SeqCst);
        let _ = g
            .on_buried_checkpoint(10, block_hash(10), &Hash::new([1; 32]), ks.first())
            .await;
        g.prune().await;
        assert_eq!(kv.batches.load(Ordering::SeqCst), before);
        assert_eq!(kv.keys_with_prefix(SIGNED_VOTE_KEY_PREFIX), 0);
        assert_eq!(kv.keys_with_prefix(SIGNED_VOTE_META_PREFIX), 0);
    }

    #[test]
    fn signed_vote_meta_round_trips_and_rejects_bad_lengths() {
        let m = SignedVoteMeta {
            floor: 7,
            highest: u64::MAX,
        };
        assert_eq!(SignedVoteMeta::decode(&m.encode()), Some(m));
        assert_eq!(SignedVoteMeta::decode(&[0u8; 15]), None);
        assert_eq!(boundaries_between(3, 11, 2), vec![4, 6, 8, 10]);
        assert_eq!(boundaries_between(4, 4, 2), Vec::<u64>::new());
        assert_eq!(boundaries_between(0, 10, 0), Vec::<u64>::new());
        assert_eq!(
            signed_vote_key(40204, 12),
            b"checkpoint_signed:40204:12".to_vec()
        );
        assert!(!signed_vote_key(1, 2).starts_with(b"checkpoint:"));
    }
}
