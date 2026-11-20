// node/src/finality_sync.rs
//
// WP-S.3 Stage 1b — late-joiner checkpoint certificate sync
// (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §11.10).
//
// A node that joins late, or restarts behind, has no finalized checkpoint of its
// own until it next takes part in a live quorum, so its floor would stay at 0.
// This module lets it fetch the latest finalized certificate from a peer:
//
//   requester  every CERT_SYNC_POLL_SECS, ask ONE peer (round robin over peers
//              that advertised protocol 1.2+) for its highest certificate with
//              `our finalized height < h <= our applied tip`
//              (`NetworkMessage::GetCheckpoint`). One request outstanding at a
//              time; it expires after CERT_REQUEST_TIMEOUT_SECS.
//   server     answer with that certificate (`NetworkMessage::CheckpointCertificate`),
//              at most once per peer per CERT_SERVE_MIN_INTERVAL_SECS, and only if
//              the encoded response fits MAX_CERTIFICATE_RESPONSE_BYTES (the same
//              60 KiB budget block serving uses, under the 64 KiB Noise message
//              limit). No certificate in range: no answer.
//
// TRUST. Nothing the peer sends is taken on trust. A response is used only if it
// answers the outstanding request, from the peer it was sent to, and then:
//
//   1. size: at most MAX_CERTIFICATE_SIGNATURES signatures and
//      MAX_CERTIFICATE_RESPONSE_BYTES encoded (checked before any other work);
//   2. stale: its height is above this node's latest finalized height;
//   3. (height, hash) binding: the certified block IS the block at that height
//      on this node's applied chain (`CanonicalApplicator::verify_certified_floor`,
//      read-only pre-check; re-checked under the advance lock in step 6). Above
//      the applied tip: not used yet. A SIBLING (another block at that height,
//      or a chain that steps over it): see CONFLICTING FINALITY below;
//   4. epoch-pinned committee: derived HERE, exactly as the producer path derives
//      it (`finality_floor::CertificateCommittees`, i.e.
//      `FinalityGadget::committee_for`): a function of the height's epoch
//      snapshot (or the genesis set), the same for every block at that height;
//      the binding comes from this node's own copy of the certified block. The
//      message carries no committee;
//   5. quorum + signatures: `CheckpointManager::verify_synced_certificate` —
//      boundary height, committee >= 4, floor(2n/3)+1 distinct members, every
//      ed25519 signature valid for this chain id over (height, hash);
//   6. install through the finalization path
//      (`CheckpointManager::install_synced_certificate`): serialized with local
//      finalizations, and in Enforced mode the manager's FinalizationGuard
//      (`FloorVerifier::on_finalize`) runs BEFORE the certificate is visible
//      (DAG mark, persisted record, latest finalized height). The guard
//      re-verifies it against the derived committee and, under the advance
//      lock, raises the reorg floor if the block is canonical here or engages
//      the safety stop if a reorg moved the node off it in the meantime —
//      exactly as for a certificate this node finalized itself. Enforced sync
//      never runs without that guard (`CertificateSync::new` returns `None`).
//      A floor verifier pass then reports the result (Observed: metric only).
//
// CONFLICTING FINALITY (owner Q1 on #332; same semantics as a stored-certificate
// mismatch in #323). A sibling certificate is checked further only if this
// node holds the sibling block (its binding — state root, accepted root — is
// read from this node's own copy):
//
//   * it VERIFIES against the committee derived here -> a quorum of this node's
//     own committee finalized a block this node is not on: in Enforced mode a
//     mismatch safety stop and alarm, in Observed mode a counted finality
//     conflict with voting continuing (`FloorVerifier::on_conflicting_certificate`).
//     Either way it is NOT installed and the floor is NOT raised;
//   * it does not verify, or its committee cannot be derived -> refused with a
//     log only. Unauthenticated peer input never halts finality.
//
// SWITCH. Same compiled pins as Stage 1a/1c. In Legacy mode (voting pin OFF,
// every chain in this release) `CertificateSync::new` returns `None`: nothing is
// requested, served or accepted, and inbound sync messages are ignored. The two
// message variants are sent only to peers that advertised
// `ProtocolVersion::CHECKPOINT_CERT_SYNC` (`Peer::send`), so older peers never
// see them.

// PANIC-S1 G2: runs on the live node; panic-free outside tests.
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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use citrate_consensus::checkpoint::{SyncedInstall, VerifiedCertificate, VoteBinding};
use citrate_consensus::checkpoint_gadget::FinalityGadget;
use citrate_consensus::types::{Hash, PublicKey, Signature};
use citrate_network::peer::PeerManager;
use citrate_network::{CheckpointSignature, NetworkMessage, PeerId};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::canonical_apply::{CanonicalApplicator, FloorCheck};
use crate::finality_floor::{CommitteeUnavailable, FloorMode, FloorTick, FloorVerifier};

/// Requester cadence.
pub const CERT_SYNC_POLL_SECS: u64 = 10;
/// Minimum spacing between two requests from this node.
pub const CERT_REQUEST_MIN_INTERVAL_SECS: u64 = 5;
/// An unanswered request is abandoned after this long (a peer with no
/// certificate in range does not answer).
pub const CERT_REQUEST_TIMEOUT_SECS: u64 = 10;
/// A peer is served at most once per this interval.
pub const CERT_SERVE_MIN_INTERVAL_SECS: u64 = 5;
/// Peers tracked for the serve rate limit. When full, entries older than the
/// serve interval are dropped; if it is still full, the request is not served.
pub const MAX_SERVE_RATE_ENTRIES: usize = 1024;
/// Signatures one certificate may carry, sent or received. 512 encoded
/// signatures (104 bytes each) plus the header stay under
/// [`MAX_CERTIFICATE_RESPONSE_BYTES`].
pub const MAX_CERTIFICATE_SIGNATURES: usize = 512;
/// Encoded size budget of a certificate response: block serving's 60 KiB
/// budget, under the 64 KiB Noise per-message limit (`block_serve`).
pub const MAX_CERTIFICATE_RESPONSE_BYTES: u64 = crate::block_serve::MAX_UNSPLIT_RESPONSE_BYTES;

/// What handling one certificate response concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Too many signatures or too many encoded bytes. Nothing else was checked.
    Oversize { signatures: usize, bytes: u64 },
    /// At or below this node's latest finalized height.
    Stale { height: u64, latest: u64 },
    /// The certified block is not the block at that height on this node's
    /// applied chain (`canonical`: what is there, `None` if the chain steps
    /// over the height), and the certificate did not verify against the
    /// committee derived here (or none could be derived: `reason`). Refused;
    /// finality is not halted.
    NotOnThisChain {
        height: u64,
        certified: Hash,
        canonical: Option<Hash>,
        reason: String,
    },
    /// Conflicting finality: a sibling of this node's block at `height` that
    /// VERIFIES against the committee derived here. Not installed; `floor` is
    /// the safety stop it engaged.
    ConflictingFinality {
        height: u64,
        certified: Hash,
        canonical: Option<Hash>,
        floor: FloorTick,
    },
    /// This node's applied tip is below the certified height.
    NotYetApplied { height: u64, applied_height: u64 },
    /// No validator snapshot governing the height is held here, so no
    /// committee can be derived.
    NoCommittee { height: u64 },
    /// Fails quorum / membership / signature / boundary verification.
    Invalid { height: u64, reason: String },
    /// A local check could not complete (retried on a later request).
    Unverifiable { height: u64, reason: String },
    /// Installed; `floor` is the floor verifier pass that followed.
    Installed { height: u64, floor: FloorTick },
}

#[derive(Default)]
struct SyncState {
    /// The request awaiting an answer: (peer, sent at).
    outstanding: Option<(String, Instant)>,
    /// A response is being verified (at most one at a time).
    verifying: bool,
    last_request: Option<Instant>,
    next_peer: usize,
    /// Serve rate limit: peer -> last served.
    served: HashMap<String, Instant>,
}

/// Late-joiner checkpoint certificate sync (see the module docs).
pub struct CertificateSync {
    mode: FloorMode,
    /// Committee derivation (`committee_for`) and the checkpoint manager.
    gadget: Arc<FinalityGadget>,
    /// Data source of this node's applied chain (binding check, applied tip).
    applicator: Arc<CanonicalApplicator>,
    /// The guard of every install (Enforced), the committee source
    /// (`FloorVerifier::committees`: epoch snapshot + this node's copy of the
    /// certified block's header), the conflicting-finality stop, and a pass
    /// after each install.
    floor: Arc<FloorVerifier>,
    state: Mutex<SyncState>,
}

fn elapsed_at_least(now: Instant, since: Instant, secs: u64) -> bool {
    now.saturating_duration_since(since) >= Duration::from_secs(secs)
}

impl CertificateSync {
    /// `None` in Legacy mode (voting pin OFF): certificate sync is compiled off
    /// with the rest of checkpoint finality. Also `None` in Enforced mode when
    /// `floor` is not installed as the checkpoint manager's finalization guard
    /// (`FloorVerifier::install_finalization_guard`): a synced certificate
    /// must never become visible before the floor rises or finality halts.
    pub fn new(
        gadget: Arc<FinalityGadget>,
        applicator: Arc<CanonicalApplicator>,
        floor: Arc<FloorVerifier>,
    ) -> Option<Self> {
        let mode = floor.mode();
        if mode == FloorMode::Legacy {
            return None;
        }
        if mode.raises_floor() && !gadget.manager().has_finalization_guard() {
            error!(
                "checkpoint finality: certificate sync NOT started — Enforced mode but the \
                 floor verifier is not the checkpoint manager's finalization guard"
            );
            return None;
        }
        Some(Self {
            mode,
            gadget,
            applicator,
            floor,
            state: Mutex::new(SyncState::default()),
        })
    }

    /// The next request to send, if one is due: `(peer, GetCheckpoint)`.
    /// `peers` are the candidates (protocol 1.2+), tried round robin.
    pub async fn request(&self, peers: &[String]) -> Option<(String, NetworkMessage)> {
        self.request_at(peers, Instant::now()).await
    }

    async fn request_at(&self, peers: &[String], now: Instant) -> Option<(String, NetworkMessage)> {
        let above = self.gadget.manager().latest_finalized_height().await;
        let at_or_below = self.applicator.applied_tip().await.height;
        if at_or_below <= above || peers.is_empty() {
            return None;
        }
        let mut st = self.state.lock().await;
        if st.verifying {
            return None;
        }
        if let Some((_, sent)) = &st.outstanding {
            if !elapsed_at_least(now, *sent, CERT_REQUEST_TIMEOUT_SECS) {
                return None;
            }
            st.outstanding = None;
        }
        if let Some(last) = st.last_request {
            if !elapsed_at_least(now, last, CERT_REQUEST_MIN_INTERVAL_SECS) {
                return None;
            }
        }
        let idx = st.next_peer.checked_rem(peers.len())?;
        let peer = peers.get(idx)?.clone();
        st.next_peer = st.next_peer.wrapping_add(1);
        st.outstanding = Some((peer.clone(), now));
        st.last_request = Some(now);
        Some((peer, NetworkMessage::GetCheckpoint { above, at_or_below }))
    }

    /// Answer a peer's `GetCheckpoint`, if allowed by the rate limit and a
    /// certificate is in range and fits the size budget.
    pub async fn serve(&self, peer: &str, above: u64, at_or_below: u64) -> Option<NetworkMessage> {
        self.serve_at(peer, above, at_or_below, Instant::now())
            .await
    }

    async fn serve_at(
        &self,
        peer: &str,
        above: u64,
        at_or_below: u64,
        now: Instant,
    ) -> Option<NetworkMessage> {
        {
            let mut st = self.state.lock().await;
            if let Some(last) = st.served.get(peer) {
                if !elapsed_at_least(now, *last, CERT_SERVE_MIN_INTERVAL_SECS) {
                    debug!("checkpoint sync: GetCheckpoint from {} rate-limited", peer);
                    return None;
                }
            }
            if st.served.len() >= MAX_SERVE_RATE_ENTRIES && !st.served.contains_key(peer) {
                st.served
                    .retain(|_, last| !elapsed_at_least(now, *last, CERT_SERVE_MIN_INTERVAL_SECS));
                if st.served.len() >= MAX_SERVE_RATE_ENTRIES {
                    debug!(
                        "checkpoint sync: serve rate table full; not serving {}",
                        peer
                    );
                    return None;
                }
            }
            st.served.insert(peer.to_string(), now);
        }
        let cp = self
            .gadget
            .manager()
            .latest_finalized_in_range(above, at_or_below)
            .await?;
        if cp.votes.len() > MAX_CERTIFICATE_SIGNATURES {
            warn!(
                "checkpoint sync: certificate {} carries {} signatures (max {}); not served",
                cp.height,
                cp.votes.len(),
                MAX_CERTIFICATE_SIGNATURES
            );
            return None;
        }
        let mut signatures: Vec<CheckpointSignature> = cp
            .votes
            .iter()
            .map(|(voter, signature)| CheckpointSignature {
                voter: *voter,
                signature: *signature,
            })
            .collect();
        signatures.sort_by(|a, b| a.voter.as_bytes().cmp(b.voter.as_bytes()));
        let msg = NetworkMessage::CheckpointCertificate {
            height: cp.height,
            block_hash: cp.block_hash,
            binding: cp.binding,
            signatures,
        };
        match bincode::serialized_size(&msg) {
            Ok(n) if n <= MAX_CERTIFICATE_RESPONSE_BYTES => Some(msg),
            Ok(n) => {
                warn!(
                    "checkpoint sync: certificate {} encodes to {} bytes (max {}); not served",
                    cp.height, n, MAX_CERTIFICATE_RESPONSE_BYTES
                );
                None
            }
            Err(e) => {
                warn!(
                    "checkpoint sync: certificate {} not encodable: {}",
                    cp.height, e
                );
                None
            }
        }
    }

    /// Whether a `CheckpointCertificate` from `peer` answers the outstanding
    /// request. `true` claims the single verification slot: the caller must
    /// then call [`Self::process`].
    pub async fn accept_response(&self, peer: &str) -> bool {
        self.accept_response_at(peer, Instant::now()).await
    }

    async fn accept_response_at(&self, peer: &str, now: Instant) -> bool {
        let mut st = self.state.lock().await;
        let answers = match &st.outstanding {
            Some((asked, sent)) => {
                asked == peer && !elapsed_at_least(now, *sent, CERT_REQUEST_TIMEOUT_SECS)
            }
            None => false,
        };
        if answers {
            st.outstanding = None;
            st.verifying = true;
        }
        answers
    }

    /// Verify and (if it passes) install a response accepted by
    /// [`Self::accept_response`]; releases the verification slot.
    pub async fn process(
        &self,
        peer: &str,
        height: u64,
        block_hash: Hash,
        binding: VoteBinding,
        signatures: Vec<CheckpointSignature>,
    ) -> SyncOutcome {
        let out = self
            .verify_and_install(height, block_hash, binding, &signatures)
            .await;
        self.state.lock().await.verifying = false;
        match &out {
            SyncOutcome::Installed { height, floor } => info!(
                "checkpoint sync: installed finalized certificate {} @ {} from {} ({:?} mode): {:?}",
                block_hash, height, peer, self.mode, floor
            ),
            SyncOutcome::ConflictingFinality { height, floor, .. } => error!(
                "checkpoint sync: peer {} presented certificate {} @ {} that VERIFIES against \
                 this node's committee but is not on this node's chain: {:?}",
                peer, block_hash, height, floor
            ),
            SyncOutcome::Stale { .. }
            | SyncOutcome::NotYetApplied { .. }
            | SyncOutcome::Unverifiable { .. }
            | SyncOutcome::NoCommittee { .. } => {
                debug!("checkpoint sync: certificate from {} not used: {:?}", peer, out)
            }
            SyncOutcome::Oversize { .. }
            | SyncOutcome::NotOnThisChain { .. }
            | SyncOutcome::Invalid { .. } => {
                warn!("checkpoint sync: certificate from {} refused: {:?}", peer, out)
            }
        }
        out
    }

    /// Test-only: forget the outstanding request and the request / serve
    /// spacing (in-process harnesses do not advance the clock).
    #[cfg(test)]
    pub(crate) async fn reset_rate_limits_for_tests(&self) {
        let mut st = self.state.lock().await;
        st.outstanding = None;
        st.last_request = None;
        st.served.clear();
    }

    /// Test convenience: accept (must be solicited) + process.
    #[cfg(test)]
    async fn on_certificate_at(
        &self,
        peer: &str,
        msg: NetworkMessage,
        now: Instant,
    ) -> SyncOutcome {
        let NetworkMessage::CheckpointCertificate {
            height,
            block_hash,
            binding,
            signatures,
        } = msg
        else {
            panic!("not a CheckpointCertificate: {msg:?}");
        };
        assert!(
            self.accept_response_at(peer, now).await,
            "response from {peer} not solicited"
        );
        self.process(peer, height, block_hash, binding, signatures)
            .await
    }

    async fn verify_and_install(
        &self,
        height: u64,
        block_hash: Hash,
        binding: VoteBinding,
        signatures: &[CheckpointSignature],
    ) -> SyncOutcome {
        // 1. size, before any other work.
        let count = signatures.len();
        let bytes = bincode::serialized_size(&(height, block_hash, signatures)).unwrap_or(u64::MAX);
        if count > MAX_CERTIFICATE_SIGNATURES || bytes > MAX_CERTIFICATE_RESPONSE_BYTES {
            return SyncOutcome::Oversize {
                signatures: count,
                bytes,
            };
        }
        // 2. stale.
        let manager = self.gadget.manager();
        let latest = manager.latest_finalized_height().await;
        if height <= latest {
            return SyncOutcome::Stale { height, latest };
        }
        if !manager.config().is_checkpoint_height(height) {
            return SyncOutcome::Invalid {
                height,
                reason: "not a checkpoint boundary".to_string(),
            };
        }
        // 3. (height, hash) binding to this node's applied chain (read-only
        // pre-check; the guard re-checks it under the advance lock at install).
        let sibling_of = match self
            .applicator
            .verify_certified_floor(height, block_hash, false)
            .await
        {
            FloorCheck::Match => None,
            FloorCheck::Mismatch { canonical } => Some(canonical),
            FloorCheck::NotYetApplied { applied_height } => {
                return SyncOutcome::NotYetApplied {
                    height,
                    applied_height,
                }
            }
            FloorCheck::Unverifiable(reason) => {
                return SyncOutcome::Unverifiable { height, reason }
            }
        };
        // 4. committee, derived here from the height's epoch; the binding from
        // this node's copy of the certified block.
        let (committee, expected) = match self.floor.committees().derive(height, block_hash).await {
            Ok(c) => c,
            Err(why) => {
                if let Some(canonical) = sibling_of {
                    return SyncOutcome::NotOnThisChain {
                        height,
                        certified: block_hash,
                        canonical,
                        reason: why.to_string(),
                    };
                }
                return match why {
                    CommitteeUnavailable::NoSnapshot => SyncOutcome::NoCommittee { height },
                    CommitteeUnavailable::Header(reason) => {
                        SyncOutcome::Unverifiable { height, reason }
                    }
                };
            }
        };
        // 5. quorum + signatures against that committee.
        let sigs: Vec<(PublicKey, Signature)> =
            signatures.iter().map(|s| (s.voter, s.signature)).collect();
        let verified = match manager
            .verify_synced_certificate(height, block_hash, binding, &sigs, &committee, &expected)
        {
            Ok(v) => v,
            Err(e) => {
                if let Some(canonical) = sibling_of {
                    return SyncOutcome::NotOnThisChain {
                        height,
                        certified: block_hash,
                        canonical,
                        reason: e.to_string(),
                    };
                }
                return SyncOutcome::Invalid {
                    height,
                    reason: e.to_string(),
                };
            }
        };
        if let Some(canonical) = sibling_of {
            return self.conflicting(&verified, canonical).await;
        }
        // 6. install through the finalization path: in Enforced mode the
        // manager's FinalizationGuard (this node's floor verifier) runs before
        // the certificate is visible.
        match manager.install_synced_certificate(verified).await {
            Ok(SyncedInstall::Installed { .. }) => {}
            Ok(SyncedInstall::Stale { height, latest }) => {
                return SyncOutcome::Stale { height, latest }
            }
            Err(e) => {
                return SyncOutcome::Unverifiable {
                    height,
                    reason: e.to_string(),
                }
            }
        }
        // Report (Observed: publishes the verified height; Enforced: the guard
        // already acted, this pass re-reads the same certificate).
        let floor = self.floor.tick().await;
        SyncOutcome::Installed { height, floor }
    }

    /// A verified sibling certificate: conflicting finality (module docs).
    async fn conflicting(
        &self,
        verified: &VerifiedCertificate,
        canonical: Option<Hash>,
    ) -> SyncOutcome {
        let cp = verified.checkpoint();
        let floor = self
            .floor
            .on_conflicting_certificate(verified, canonical)
            .await;
        SyncOutcome::ConflictingFinality {
            height: cp.height,
            certified: cp.block_hash,
            canonical,
            floor,
        }
    }
}

/// What a finalized certificate this node does NOT install says about this
/// node's chain (dead-branch evidence, `dead_branch.rs`). Judged by
/// [`judge_foreign_certificate`]; nothing here touches finality state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignCertificate {
    /// It verifies, and certifies a block above this node's applied tip: the
    /// committee finalized past a height this node has not reached.
    AboveTip { height: u64, hash: Hash },
    /// It verifies, and certifies a block at or below this node's applied tip
    /// that is NOT this node's block at that height (`ours`: what is there,
    /// `None` if the applied chain steps over the height).
    Conflicts {
        height: u64,
        hash: Hash,
        ours: Option<Hash>,
    },
    /// The certified block is on this node's applied chain: no evidence of a
    /// dead branch (the ordinary certificate sync installs such certificates).
    OnOurChain { height: u64 },
    /// Not used: why (size, boundary, no committee, quorum or signatures).
    Refused(String),
}

/// Judge a peer's finalized certificate as dead-branch evidence. Every check
/// the ordinary sync makes before trusting a certificate is made here, but
/// the certified block need not be held:
///
/// 1. size: at most [`MAX_CERTIFICATE_SIGNATURES`] signatures and
///    [`MAX_CERTIFICATE_RESPONSE_BYTES`] encoded, before any other work;
/// 2. a checkpoint boundary height;
/// 3. where it stands against this node's applied chain
///    (`CanonicalApplicator::verify_certified_floor`, read-only);
/// 4. the committee derived HERE (`FinalityGadget::committee_beyond_held_epochs`:
///    the governing epoch's snapshot, or, when this node has not reached that
///    epoch, its newest held validator set with that epoch's seed). Never the
///    peer's: the message carries none;
/// 5. `CheckpointManager::verify_synced_certificate` against that committee:
///    boundary, committee >= 4, distinct members holding more than two thirds
///    of its stake, the binding's epoch equal to the committee's, and every
///    ed25519 signature valid over the v2 vote message for this chain and
///    genesis. The binding is the certificate's own (this node holds no copy of
///    the block); every signature covers it.
///
/// The result is never installed and never raises a floor.
pub async fn judge_foreign_certificate(
    gadget: &FinalityGadget,
    applicator: &CanonicalApplicator,
    height: u64,
    block_hash: Hash,
    binding: VoteBinding,
    signatures: &[CheckpointSignature],
) -> ForeignCertificate {
    let count = signatures.len();
    let bytes = bincode::serialized_size(&(height, block_hash, signatures)).unwrap_or(u64::MAX);
    if count > MAX_CERTIFICATE_SIGNATURES || bytes > MAX_CERTIFICATE_RESPONSE_BYTES {
        return ForeignCertificate::Refused(format!("oversize: {count} signatures, {bytes} bytes"));
    }
    let manager = gadget.manager();
    if !manager.config().is_checkpoint_height(height) {
        return ForeignCertificate::Refused("not a checkpoint boundary".to_string());
    }
    let ours = match applicator
        .verify_certified_floor(height, block_hash, false)
        .await
    {
        FloorCheck::Match => return ForeignCertificate::OnOurChain { height },
        FloorCheck::Mismatch { canonical } => Some(canonical),
        FloorCheck::NotYetApplied { .. } => None,
        FloorCheck::Unverifiable(why) => {
            return ForeignCertificate::Refused(format!("chain check: {why}"))
        }
    };
    let Some(committee) = gadget.committee_beyond_held_epochs(height).await else {
        return ForeignCertificate::Refused(
            "no committee can be derived for the height here".to_string(),
        );
    };
    let sigs: Vec<(PublicKey, Signature)> =
        signatures.iter().map(|s| (s.voter, s.signature)).collect();
    if let Err(e) =
        manager.verify_synced_certificate(height, block_hash, binding, &sigs, &committee, &binding)
    {
        return ForeignCertificate::Refused(e.to_string());
    }
    match ours {
        Some(ours) => ForeignCertificate::Conflicts {
            height,
            hash: block_hash,
            ours,
        },
        None => ForeignCertificate::AboveTip {
            height,
            hash: block_hash,
        },
    }
}

/// Connected peers that advertised certificate sync support, by id.
async fn sync_capable_peers(peers: &PeerManager) -> Vec<String> {
    let mut out = Vec::new();
    for p in peers.get_all_peers() {
        if p.is_closed() {
            continue;
        }
        let info = p.info.read().await;
        if info
            .version
            .is_some_and(|v| v.understands_checkpoint_sync())
        {
            out.push(info.id.0.clone());
        }
    }
    out.sort();
    out
}

/// Spawn the requester loop (see the module docs).
pub fn spawn_requester(
    sync: Arc<CertificateSync>,
    peers: Arc<PeerManager>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            "checkpoint finality: certificate sync ON ({:?} mode, every {} s)",
            sync.mode, CERT_SYNC_POLL_SECS
        );
        let mut tick = crate::timing::cadence_interval(Duration::from_secs(CERT_SYNC_POLL_SECS));
        loop {
            tick.tick().await;
            let candidates = sync_capable_peers(&peers).await;
            let Some((peer_id, msg)) = sync.request(&candidates).await else {
                continue;
            };
            match peers.get_peer(&PeerId(peer_id.clone())) {
                Some(p) => {
                    if let Err(e) = p.send(msg).await {
                        debug!("checkpoint sync: request to {} not sent: {}", peer_id, e);
                    }
                }
                None => debug!("checkpoint sync: peer {} gone before request", peer_id),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_apply::tests::{fresh, setup_fork};
    use crate::finality_floor::{CertificateCommittees, HaltReason};
    use crate::persistent_dag::RocksDbKvStore;
    use citrate_api::finalized_tag::FinalizedAnchor;
    use citrate_consensus::checkpoint::{
        sign_checkpoint_vote, Checkpoint, CheckpointConfig, CheckpointManager, CheckpointStatus,
    };
    use citrate_consensus::checkpoint_gadget::SkipReason;
    use citrate_consensus::crypto::Ed25519SigningKey;
    use citrate_consensus::dag_store::{cf, DagStore, KvStore};
    use citrate_consensus::types::Block;
    use citrate_consensus::vrf::VrfProposerSelector;
    use citrate_storage::StorageManager;
    use std::sync::atomic::{AtomicU64, Ordering};

    const CHAIN: u64 = 40204;

    fn key(i: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[i.saturating_add(1); 32])
    }

    fn pk(k: &Ed25519SigningKey) -> PublicKey {
        PublicKey::new(k.verifying_key().to_bytes())
    }

    fn config() -> CheckpointConfig {
        CheckpointConfig {
            interval: 2,
            committee_size: 100,
            quorum_threshold: 67,
            chain_id: CHAIN,
            genesis_hash: Hash::default(),
            vote_depth: 3,
        }
    }

    /// The binding a vote for the test block at `height` carries: epoch S(1)
    /// = 1 (schedule EPOCH 1000 / LAG 999), the reward-only state root every
    /// test branch shares at that height, the empty accepted root.
    fn tb(height: u64) -> VoteBinding {
        VoteBinding {
            epoch: 1,
            state_root: {
                // Computed once: the reward-only chain's roots up to 512.
                static ROOTS: std::sync::OnceLock<Vec<Hash>> = std::sync::OnceLock::new();
                let roots = ROOTS.get_or_init(|| crate::canonical_apply::tests::roots(512));
                usize::try_from(height)
                    .ok()
                    .and_then(|h| h.checked_sub(1))
                    .and_then(|i| roots.get(i).copied())
                    .unwrap_or_default()
            },
            accepted_root: citrate_consensus::checkpoint::empty_accepted_root(),
        }
    }

    /// Signatures over (height, hash) on CHAIN by keys `ids`.
    fn signed(ids: &[u8], height: u64, hash: Hash) -> Vec<CheckpointSignature> {
        ids.iter()
            .map(|&i| {
                let v = sign_checkpoint_vote(
                    CHAIN,
                    &Hash::default(),
                    height,
                    hash,
                    &tb(height),
                    &key(i),
                );
                CheckpointSignature {
                    voter: v.voter,
                    signature: v.signature,
                }
            })
            .collect()
    }

    fn cert_msg(height: u64, hash: Hash, signatures: Vec<CheckpointSignature>) -> NetworkMessage {
        NetworkMessage::CheckpointCertificate {
            height,
            block_hash: hash,
            binding: tb(height),
            signatures,
        }
    }

    /// Through the real wire codec (bincode out, bounded `decode_inbound` in).
    fn over_the_wire(msg: &NetworkMessage) -> NetworkMessage {
        let bytes = bincode::serialize(msg).expect("encode");
        NetworkMessage::decode_inbound(&bytes).expect("decode_inbound")
    }

    /// Persist a finalized certificate where, and as, `finalize_checkpoint`
    /// does (the synced write).
    fn persist_certificate(storage: &StorageManager, cp: &Checkpoint) {
        let kv = RocksDbKvStore::new(storage.db.clone());
        let bytes = bincode::serialize(cp).expect("serialize certificate");
        kv.kv_put_durable(
            cf::DAG_METADATA,
            format!("checkpoint:{}", cp.height).as_bytes(),
            &bytes,
        )
        .expect("persist certificate");
    }

    struct Node {
        storage: Arc<StorageManager>,
        app: Arc<CanonicalApplicator>,
        gadget: Arc<FinalityGadget>,
        floor: Arc<FloorVerifier>,
        verified: Arc<AtomicU64>,
        sync: CertificateSync,
        _dir: tempfile::TempDir,
    }

    impl Node {
        fn floor_height(&self) -> u64 {
            self.app.finalized_height_handle().load(Ordering::SeqCst)
        }
        fn verified_height(&self) -> u64 {
            self.verified.load(Ordering::SeqCst)
        }
        async fn latest(&self) -> u64 {
            self.gadget.manager().latest_finalized_height().await
        }
        /// Issue a request to `peer` at `now` (must be due).
        async fn solicit(&self, peer: &str, now: Instant) -> NetworkMessage {
            let (to, msg) = self
                .sync
                .request_at(&[peer.to_string()], now)
                .await
                .expect("a request is due");
            assert_eq!(to, peer);
            msg
        }
    }

    /// The governing-snapshot schedule: (EPOCH 1000, LAG 999) puts S(1) = 1,
    /// which governs height 2.
    async fn selector(snapshot_at: u64, members: &[u8]) -> Arc<VrfProposerSelector> {
        let sel = VrfProposerSelector::new().with_snapshot_schedule(1000, 999);
        let set: Vec<(PublicKey, u128)> = members.iter().map(|&i| (pk(&key(i)), 1000)).collect();
        sel.record_snapshot(snapshot_at, &set, 1).await;
        Arc::new(sel)
    }

    /// A node over a fresh store. `blocks`: apply a1, a2 (tip a2 @ 2; b2, b3
    /// stored as an unapplied sibling branch). `persisted`: a certificate in
    /// the store before the manager loads it (a node that finalized it).
    async fn node_with(
        mode: FloorMode,
        sel: Arc<VrfProposerSelector>,
        blocks: bool,
        persisted: Option<Checkpoint>,
    ) -> (Node, Option<(Block, Block, Block, Block)>) {
        let (exec, storage, dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let fork = if blocks {
            Some(setup_fork(&app, &storage).await)
        } else {
            None
        };
        if let Some(cp) = &persisted {
            persist_certificate(&storage, cp);
        }
        let mgr = Arc::new(CheckpointManager::with_persistence(
            config(),
            Arc::new(DagStore::with_permissive_vrf_for_testing()),
            Arc::new(RocksDbKvStore::new(storage.db.clone())),
        ));
        let gadget = Arc::new(FinalityGadget::with_switch(
            mgr.clone(),
            Some(sel),
            mode != FloorMode::Legacy,
        ));
        let verified = Arc::new(AtomicU64::new(0));
        let floor = Arc::new(FloorVerifier::new(
            mode,
            mgr,
            app.clone(),
            gadget.safety_stop(),
            verified.clone(),
            CertificateCommittees::new(gadget.clone(), storage.clone()),
        ));
        // As main.rs: the guard is installed (Enforced only) before sync starts.
        assert_eq!(floor.install_finalization_guard(), mode.raises_floor());
        let sync =
            CertificateSync::new(gadget.clone(), app.clone(), floor.clone()).expect("not Legacy");
        (
            Node {
                storage,
                app,
                gadget,
                floor,
                verified,
                sync,
                _dir: dir,
            },
            fork,
        )
    }

    async fn node(mode: FloorMode) -> (Node, (Block, Block, Block, Block)) {
        let (n, fork) = node_with(mode, selector(1, &[0, 1, 2, 3]).await, true, None).await;
        (n, fork.expect("blocks applied"))
    }

    fn assert_untouched(n: &Node) {
        assert_eq!(n.floor_height(), 0, "floor not raised");
        assert_eq!(n.verified_height(), 0, "verified height not advanced");
        assert!(
            !n.gadget.halted(),
            "a peer's certificate never halts finality"
        );
    }

    /// Signatures by keys `ids` over (height, hash) with an explicit binding.
    fn signed_with(
        ids: &[u8],
        height: u64,
        hash: Hash,
        binding: &VoteBinding,
    ) -> Vec<CheckpointSignature> {
        ids.iter()
            .map(|&i| {
                let v =
                    sign_checkpoint_vote(CHAIN, &Hash::default(), height, hash, binding, &key(i));
                CheckpointSignature {
                    voter: v.voter,
                    signature: v.signature,
                }
            })
            .collect()
    }

    async fn judge(
        n: &Node,
        height: u64,
        hash: Hash,
        b: VoteBinding,
        sigs: &[CheckpointSignature],
    ) -> ForeignCertificate {
        judge_foreign_certificate(&n.gadget, &n.app, height, hash, b, sigs).await
    }

    /// Dead-branch evidence: a certificate for a block this node does not
    /// hold, above its applied tip, verifies against the committee derived
    /// here and is reported, not installed; one at the tip's height for a
    /// sibling is a conflict; one for our own block is no evidence.
    #[tokio::test]
    async fn a_foreign_certificate_is_judged_against_our_committee_and_never_installed() {
        let (n, (_a1, a2, b2, _b3)) = node(FloorMode::Observed).await;
        let above = Hash::new([0xF4; 32]);
        assert_eq!(
            judge(&n, 4, above, tb(4), &signed(&[0, 1, 2], 4, above)).await,
            ForeignCertificate::AboveTip {
                height: 4,
                hash: above
            }
        );
        let b2h = b2.header.block_hash;
        assert_eq!(
            judge(&n, 2, b2h, tb(2), &signed(&[0, 1, 2], 2, b2h)).await,
            ForeignCertificate::Conflicts {
                height: 2,
                hash: b2h,
                ours: Some(a2.header.block_hash)
            }
        );
        let a2h = a2.header.block_hash;
        assert_eq!(
            judge(&n, 2, a2h, tb(2), &signed(&[0, 1, 2], 2, a2h)).await,
            ForeignCertificate::OnOurChain { height: 2 }
        );
        assert_eq!(n.latest().await, 0, "nothing was installed");
        assert_untouched(&n);
    }

    /// The mutations: keys outside our committee, too few of its members, a
    /// changed block, binding or chain, an off-boundary height, a voter listed
    /// twice, or an oversize message: never evidence.
    #[tokio::test]
    async fn a_forged_foreign_certificate_is_refused() {
        let (n, _) = node(FloorMode::Observed).await;
        let h = Hash::new([0xF4; 32]);
        let refused = |c: &ForeignCertificate| matches!(c, ForeignCertificate::Refused(_));
        // Keys this node never materialized.
        let c = judge(&n, 4, h, tb(4), &signed(&[20, 21, 22, 23], 4, h)).await;
        assert!(
            refused(&c),
            "forged certificate accepted: keys this node never materialized"
        );
        // Two of four members: not more than two thirds.
        let c = judge(&n, 4, h, tb(4), &signed(&[0, 1], 4, h)).await;
        assert!(
            refused(&c),
            "forged certificate accepted: two of four members"
        );
        // Three members plus a stranger: a non-member voter.
        let mut sigs = signed(&[0, 1, 2], 4, h);
        sigs.extend(signed(&[20], 4, h));
        let c = judge(&n, 4, h, tb(4), &sigs).await;
        assert!(
            refused(&c),
            "forged certificate accepted: a non-member voter"
        );
        // Signatures over another block.
        let c = judge(&n, 4, h, tb(4), &signed(&[0, 1, 2], 4, Hash::new([1; 32]))).await;
        assert!(
            refused(&c),
            "forged certificate accepted: signatures over another block"
        );
        // A binding the signatures do not cover, and a binding of another epoch.
        let mut other = tb(4);
        other.state_root = Hash::new([9; 32]);
        let c = judge(&n, 4, h, other, &signed(&[0, 1, 2], 4, h)).await;
        assert!(
            refused(&c),
            "forged certificate accepted: a binding the signatures do not cover"
        );
        let mut epoch = tb(4);
        epoch.epoch = 7;
        let c = judge(&n, 4, h, epoch, &signed_with(&[0, 1, 2], 4, h, &epoch)).await;
        assert!(
            refused(&c),
            "forged certificate accepted: a binding of another epoch"
        );
        // Off the boundary (interval 2).
        let c = judge(&n, 5, h, tb(5), &signed(&[0, 1, 2], 5, h)).await;
        assert!(
            refused(&c),
            "forged certificate accepted: off the checkpoint boundary"
        );
        // A voter twice.
        let mut twice = signed(&[0, 1], 4, h);
        twice.extend(signed(&[1], 4, h));
        let c = judge(&n, 4, h, tb(4), &twice).await;
        assert!(
            refused(&c),
            "forged certificate accepted: a voter listed twice"
        );
        // Oversize.
        let many: Vec<CheckpointSignature> = (0..=MAX_CERTIFICATE_SIGNATURES)
            .map(|_| signed(&[0], 4, h).remove(0))
            .collect();
        let c = judge(&n, 4, h, tb(4), &many).await;
        assert!(refused(&c), "forged certificate accepted: oversize");
        assert_untouched(&n);
    }

    /// The r1007 member is behind the epoch boundary of the certificate it is
    /// shown (snapshot S(2) = 1001 governs 1002; it holds only S(1) = 1): the
    /// committee is drawn from its newest held set with epoch 1001's seed, and
    /// the certificate must bind epoch 1001.
    #[tokio::test]
    async fn a_certificate_beyond_our_held_epochs_verifies_against_our_newest_set() {
        let (n, _) = node(FloorMode::Observed).await;
        let h = Hash::new([0xF5; 32]);
        let binding = VoteBinding {
            epoch: 1001,
            ..tb(4)
        };
        assert_eq!(
            judge(
                &n,
                1002,
                h,
                binding,
                &signed_with(&[0, 1, 2], 1002, h, &binding)
            )
            .await,
            ForeignCertificate::AboveTip {
                height: 1002,
                hash: h
            }
        );
        // The held epoch's binding is not the governing epoch's.
        let stale = tb(4);
        let c = judge(
            &n,
            1002,
            h,
            stale,
            &signed_with(&[0, 1, 2], 1002, h, &stale),
        )
        .await;
        assert!(
            matches!(c, ForeignCertificate::Refused(_)),
            "forged certificate accepted: the held epoch's binding"
        );
        // Validators this node does not hold in its newest set.
        let c = judge(
            &n,
            1002,
            h,
            binding,
            &signed_with(&[30, 31, 32], 1002, h, &binding),
        )
        .await;
        assert!(
            matches!(c, ForeignCertificate::Refused(_)),
            "forged certificate accepted: validators not in our newest set"
        );
        assert_untouched(&n);
    }

    #[tokio::test]
    async fn legacy_mode_has_no_certificate_sync() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let mgr = Arc::new(CheckpointManager::new(
            config(),
            Arc::new(DagStore::with_permissive_vrf_for_testing()),
        ));
        let gadget = Arc::new(FinalityGadget::new(mgr.clone(), None));
        let floor = Arc::new(FloorVerifier::new(
            FloorMode::Legacy,
            mgr,
            app.clone(),
            gadget.safety_stop(),
            Arc::new(AtomicU64::new(0)),
            CertificateCommittees::new(gadget.clone(), storage),
        ));
        // (r1007 runs Observed: voting on from genesis, enforcement off. This
        // test pins that Legacy, the voting-off mode, still has no sync.)
        assert_eq!(
            FloorMode::for_genesis(CHAIN, &Hash::default()),
            FloorMode::Observed
        );
        assert!(CertificateSync::new(gadget, app, floor).is_none());
    }

    #[tokio::test]
    async fn valid_certificate_is_installed_and_raises_the_enforced_floor() {
        let (n, (_a1, a2, _b2, _b3)) = node(FloorMode::Enforced).await;
        let now = Instant::now();
        let req = n.solicit("peer-a", now).await;
        assert!(matches!(
            req,
            NetworkMessage::GetCheckpoint {
                above: 0,
                at_or_below: 2
            }
        ));
        let h = a2.header.block_hash;
        let out = n
            .sync
            .on_certificate_at("peer-a", cert_msg(2, h, signed(&[0, 1, 2], 2, h)), now)
            .await;
        assert_eq!(
            out,
            SyncOutcome::Installed {
                height: 2,
                floor: FloorTick::Verified {
                    height: 2,
                    floor_raised: true,
                    recovered: false
                }
            }
        );
        assert_eq!(n.latest().await, 2);
        assert_eq!(n.floor_height(), 2);
        assert_eq!(n.verified_height(), 2);
        assert_eq!(
            n.floor.rpc_finalized_handle().resolve(&n.storage),
            FinalizedAnchor {
                height: 2,
                hash: Some(h)
            }
        );
        assert!(!n.gadget.halted());
    }

    #[tokio::test]
    async fn forged_signature_is_rejected() {
        let (n, (_a1, a2, _b2, _b3)) = node(FloorMode::Enforced).await;
        let now = Instant::now();
        n.solicit("peer-a", now).await;
        let h = a2.header.block_hash;
        let mut sigs = signed(&[0, 1, 2], 2, h);
        // Member 2's slot carries member 3's (valid) signature.
        if let (Some(slot), Some(other)) = (sigs.get_mut(2), signed(&[3], 2, h).first()) {
            slot.signature = other.signature;
        }
        let out = n
            .sync
            .on_certificate_at("peer-a", cert_msg(2, h, sigs), now)
            .await;
        assert!(
            matches!(&out, SyncOutcome::Invalid { height: 2, reason } if reason.contains("does not verify")),
            "got {out:?}"
        );
        assert_eq!(n.latest().await, 0, "nothing installed");
        assert_untouched(&n);
    }

    /// Valid signatures over the right (height, hash), but by validators that
    /// are not this height's epoch committee — and a node that does not hold
    /// the governing snapshot at all derives no committee.
    #[tokio::test]
    async fn wrong_epoch_committee_is_rejected() {
        let (n, (_a1, a2, _b2, _b3)) = node(FloorMode::Enforced).await;
        let now = Instant::now();
        let h = a2.header.block_hash;
        n.solicit("peer-a", now).await;
        let out = n
            .sync
            .on_certificate_at(
                "peer-a",
                cert_msg(2, h, signed(&[10, 11, 12, 13], 2, h)),
                now,
            )
            .await;
        assert!(
            matches!(&out, SyncOutcome::Invalid { height: 2, reason } if reason.contains("not in the committee")),
            "got {out:?}"
        );
        assert_untouched(&n);

        // Holds only the snapshot of a later epoch (S(2) = 1001), not the one
        // governing height 2: no committee, nothing installed — never a
        // fallback to another epoch's set.
        let (m, _) = node_with(
            FloorMode::Enforced,
            selector(1001, &[0, 1, 2, 3]).await,
            true,
            None,
        )
        .await;
        m.solicit("peer-a", now).await;
        let out = m
            .sync
            .on_certificate_at("peer-a", cert_msg(2, h, signed(&[0, 1, 2], 2, h)), now)
            .await;
        assert_eq!(out, SyncOutcome::NoCommittee { height: 2 });
        assert_eq!(m.latest().await, 0);
        assert_untouched(&m);
    }

    /// Owner Q1 on #332: a certificate for the SIBLING b2 at height 2 (its
    /// header is stored here) while this node's chain holds a2, signed by a
    /// quorum of the committee this node derives for b2: conflicting
    /// finality. Mismatch safety stop + alarm; nothing installed, floor and
    /// verified height untouched. The stop clears once fork choice moves this
    /// node onto b2 (normal poll recovery).
    ///
    /// Enforced mode only since lead decision 3 (2026-11-09); Observed mode is
    /// `observed_verified_sibling_certificate_is_a_conflict_not_a_halt`.
    #[tokio::test]
    async fn verified_sibling_certificate_halts_and_is_not_installed() {
        for mode in [FloorMode::Enforced] {
            let (n, (_a1, a2, b2, b3)) = node(mode).await;
            let now = Instant::now();
            n.solicit("peer-a", now).await;
            let sib = b2.header.block_hash;
            let out = n
                .sync
                .on_certificate_at("peer-a", cert_msg(2, sib, signed(&[0, 1, 2], 2, sib)), now)
                .await;
            let stop = HaltReason::Mismatch {
                height: 2,
                certified: sib,
                canonical: Some(a2.header.block_hash),
            };
            assert_eq!(
                out,
                SyncOutcome::ConflictingFinality {
                    height: 2,
                    certified: sib,
                    canonical: Some(a2.header.block_hash),
                    floor: FloorTick::Halted(stop.clone()),
                },
                "{mode:?}"
            );
            assert!(n.gadget.halted(), "{mode:?}: safety stop engaged");
            assert_eq!(n.latest().await, 0, "{mode:?}: not installed");
            assert_eq!(n.floor_height(), 0, "{mode:?}: floor not raised");
            assert_eq!(n.verified_height(), 0, "{mode:?}");
            assert_eq!(n.floor.halt_reason().await, Some(stop.clone()));
            // The poll keeps it while a2 is canonical here.
            assert_eq!(n.floor.tick().await, FloorTick::Halted(stop), "{mode:?}");
            // Fork choice moves the node onto b2 -> b3: the stop clears.
            let lock = n.app.advance_lock();
            {
                let mut st = lock.lock().await;
                let _ = n.app.reorg_to(&mut st, b3.header.block_hash).await;
            }
            assert!(
                matches!(n.floor.tick().await, FloorTick::NoCertificate),
                "{mode:?}: recovered (nothing installed, so no certificate)"
            );
            assert!(!n.gadget.halted(), "{mode:?}: cleared");
            // Recovery is the poll's: b2 (a verified quorum certificate) is
            // now canonical, so Enforced raises the floor to it; sync then
            // fetches and installs the certificate. Nothing is PUBLISHED yet:
            // the peer's certificate was never persisted here (#335,
            // publication after persistence).
            let raised = if mode.raises_floor() { 2 } else { 0 };
            assert_eq!(n.floor_height(), raised, "{mode:?}");
            assert_eq!(n.verified_height(), 0, "{mode:?}: not persisted here");
            let later = now + Duration::from_secs(CERT_REQUEST_TIMEOUT_SECS);
            n.solicit("peer-a", later).await;
            let out = n
                .sync
                .on_certificate_at(
                    "peer-a",
                    cert_msg(2, sib, signed(&[0, 1, 2], 2, sib)),
                    later,
                )
                .await;
            assert!(
                matches!(out, SyncOutcome::Installed { height: 2, .. }),
                "{mode:?}: {out:?}"
            );
            assert_eq!(n.latest().await, 2, "{mode:?}");
            // Installed AND persisted: published now (Enforced from the
            // post-finalization hook, Observed from the pass sync runs after
            // the install).
            assert_eq!(n.verified_height(), 2, "{mode:?}: published once persisted");
        }
    }

    /// Observed mode (lead decision 3, 2026-11-09; the soak's mode): the same
    /// verified sibling certificate is a FINALITY CONFLICT, logged and counted,
    /// not a safety stop. Nothing is installed, the floor and the verified
    /// height do not move, and the gadget keeps voting on this node's own
    /// selected chain (a later checkpoint is not refused as halted). The poll
    /// does not turn it into a stop either.
    #[tokio::test]
    async fn observed_verified_sibling_certificate_is_a_conflict_not_a_halt() {
        let (n, (_a1, a2, b2, _b3)) = node(FloorMode::Observed).await;
        let now = Instant::now();
        n.solicit("peer-a", now).await;
        let sib = b2.header.block_hash;
        let out = n
            .sync
            .on_certificate_at("peer-a", cert_msg(2, sib, signed(&[0, 1, 2], 2, sib)), now)
            .await;
        match &out {
            SyncOutcome::ConflictingFinality {
                height: 2,
                certified,
                canonical,
                floor,
            } => {
                assert_eq!(*certified, sib);
                assert_eq!(*canonical, Some(a2.header.block_hash));
                assert_eq!(
                    *floor,
                    FloorTick::Conflict {
                        height: 2,
                        certified: sib,
                        canonical: Some(a2.header.block_hash),
                    }
                );
            }
            other => panic!("expected a conflicting-finality outcome, got {other:?}"),
        }
        assert!(!n.gadget.halted(), "observed: no safety stop");
        assert_eq!(n.floor.halt_reason().await, None);
        assert_eq!(n.latest().await, 0, "not installed");
        assert_eq!(n.floor_height(), 0, "floor not raised");
        assert_eq!(n.verified_height(), 0);
        assert!(!matches!(n.floor.tick().await, FloorTick::Halted(_)));
        assert!(!n.gadget.halted(), "the poll does not halt either");
        assert_eq!(n.floor.finality_conflicts(), 1, "counted once");
        let later = n
            .gadget
            .on_buried_checkpoint(4, Hash::new([4; 32]), None)
            .await;
        assert_ne!(later.skipped, Some(SkipReason::Halted), "{later:?}");
    }

    /// Owner Q1, the other half: a sibling certificate that does NOT verify
    /// against the committee derived here (outsider signers, below quorum, a
    /// forged signature), or whose committee cannot be derived (the sibling's
    /// header is not held here), is refused with a log only — unauthenticated
    /// peer input never halts finality.
    #[tokio::test]
    async fn unverified_sibling_certificate_is_refused_without_halting() {
        let (n, (_a1, a2, b2, _b3)) = node(FloorMode::Enforced).await;
        let sib = b2.header.block_hash;
        let mut forged = signed(&[0, 1, 2], 2, sib);
        if let (Some(slot), Some(other)) = (forged.get_mut(2), signed(&[3], 2, sib).first()) {
            slot.signature = other.signature;
        }
        let unknown = Hash::new([0x77; 32]);
        let cases: Vec<(&str, Hash, Vec<CheckpointSignature>, &str)> = vec![
            (
                "outsiders",
                sib,
                signed(&[10, 11, 12, 13], 2, sib),
                "not in the committee",
            ),
            ("below quorum", sib, signed(&[0, 1], 2, sib), "quorum"),
            ("forged signature", sib, forged, "does not verify"),
            (
                "header not held",
                unknown,
                signed(&[0, 1, 2], 2, unknown),
                "not stored",
            ),
        ];
        let mut now = Instant::now();
        for (what, hash, sigs, why) in cases {
            n.solicit("peer-a", now).await;
            let out = n
                .sync
                .on_certificate_at("peer-a", cert_msg(2, hash, sigs), now)
                .await;
            match &out {
                SyncOutcome::NotOnThisChain {
                    height: 2,
                    certified,
                    canonical,
                    reason,
                } => {
                    assert_eq!(*certified, hash, "{what}");
                    assert_eq!(*canonical, Some(a2.header.block_hash), "{what}");
                    assert!(reason.contains(why), "{what}: {reason}");
                }
                other => panic!("{what}: {other:?}"),
            }
            assert_eq!(n.latest().await, 0, "{what}");
            assert_untouched(&n);
            now += Duration::from_secs(CERT_REQUEST_MIN_INTERVAL_SECS);
        }
    }

    /// Enforced certificate sync never runs without the finalization guard: a
    /// synced certificate must not become visible before the floor rises or
    /// finality halts (review of #332 @ 354908b).
    #[tokio::test]
    async fn enforced_sync_requires_the_finalization_guard() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let mgr = Arc::new(CheckpointManager::new(
            config(),
            Arc::new(DagStore::with_permissive_vrf_for_testing()),
        ));
        let gadget = Arc::new(FinalityGadget::with_switch(
            mgr.clone(),
            Some(selector(1, &[0, 1, 2, 3]).await),
            true,
        ));
        let floor = Arc::new(FloorVerifier::new(
            FloorMode::Enforced,
            mgr.clone(),
            app.clone(),
            gadget.safety_stop(),
            Arc::new(AtomicU64::new(0)),
            CertificateCommittees::new(gadget.clone(), storage),
        ));
        assert!(CertificateSync::new(gadget.clone(), app.clone(), floor.clone()).is_none());
        assert!(floor.install_finalization_guard());
        assert!(mgr.has_finalization_guard());
        assert!(CertificateSync::new(gadget, app, floor).is_some());
    }

    /// The synced install runs the floor verifier as the finalization guard:
    /// by the time the certificate is visible (latest finalized height moved)
    /// the floor already covers it — no poll is involved. Checked from inside
    /// the install: the guard records the floor and latest height it ran with.
    #[tokio::test]
    async fn synced_install_raises_the_floor_before_the_certificate_is_visible() {
        let (n, (_a1, a2, _b2, _b3)) = node(FloorMode::Enforced).await;
        let h = a2.header.block_hash;
        let mgr = n.gadget.manager();
        let (committee, expected) = n.floor.committees().derive(2, h).await.expect("committee");
        let sigs: Vec<(PublicKey, Signature)> = signed(&[0, 1, 2], 2, h)
            .into_iter()
            .map(|s| (s.voter, s.signature))
            .collect();
        let cert = mgr
            .verify_synced_certificate(2, h, tb(2), &sigs, &committee, &expected)
            .expect("verifies");
        // Watch the latest finalized height and the floor while installing.
        let floor_handle = n.app.finalized_height_handle();
        let watcher_mgr = mgr.clone();
        let watcher = tokio::spawn(async move {
            let mut violations = 0u32;
            for _ in 0..2_000 {
                let latest = watcher_mgr.latest_finalized_height().await;
                let floor = floor_handle.load(Ordering::SeqCst);
                if latest >= 2 && floor < 2 {
                    violations = violations.saturating_add(1);
                }
                if latest >= 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            violations
        });
        assert_eq!(
            mgr.install_synced_certificate(cert).await.expect("install"),
            SyncedInstall::Installed {
                height: 2,
                guarded: true
            }
        );
        assert_eq!(watcher.await.expect("watcher"), 0);
        assert_eq!(n.floor_height(), 2, "raised by the guard, no tick");
        // Published by `after_finalize`, once the certificate is persisted
        // (#335): no tick needed.
        assert_eq!(n.verified_height(), 2, "published after persistence");
    }

    #[tokio::test]
    async fn oversize_response_is_rejected_before_any_check() {
        let (n, (_a1, a2, _b2, _b3)) = node(FloorMode::Enforced).await;
        let now = Instant::now();
        n.solicit("peer-a", now).await;
        let h = a2.header.block_hash;
        let filler = CheckpointSignature {
            voter: PublicKey::new([9; 32]),
            signature: Signature::new([9; 64]),
        };
        let sigs = vec![filler; MAX_CERTIFICATE_SIGNATURES.saturating_add(1)];
        let out = n
            .sync
            .on_certificate_at("peer-a", cert_msg(2, h, sigs), now)
            .await;
        assert!(
            matches!(out, SyncOutcome::Oversize { signatures, .. } if signatures == MAX_CERTIFICATE_SIGNATURES + 1),
            "got {out:?}"
        );
        assert_untouched(&n);
    }

    /// The largest certificate this node sends or accepts fits one Noise
    /// message (64 KiB minus the 16-byte tag), with the response budget.
    #[test]
    fn largest_allowed_certificate_fits_the_noise_message_limit() {
        let sigs = vec![
            CheckpointSignature {
                voter: PublicKey::new([1; 32]),
                signature: Signature::new([2; 64]),
            };
            MAX_CERTIFICATE_SIGNATURES
        ];
        let msg = cert_msg(u64::MAX, Hash::new([3; 32]), sigs);
        let n = bincode::serialized_size(&msg).expect("size");
        assert!(n <= MAX_CERTIFICATE_RESPONSE_BYTES, "{n} bytes");
        assert!(n < 65_535 - 16, "{n} bytes");
    }

    /// A response for a height this node has already finalized changes nothing.
    #[tokio::test]
    async fn stale_certificate_changes_nothing() {
        let (n, (_a1, a2, _b2, _b3)) = node(FloorMode::Enforced).await;
        let now = Instant::now();
        let h = a2.header.block_hash;
        n.solicit("peer-a", now).await;
        // Meanwhile this node finalizes height 2 itself (here: an install).
        let mgr = n.gadget.manager();
        let committee = n.gadget.committee_for(2).await.expect("committee");
        let sigs: Vec<(PublicKey, Signature)> = signed(&[0, 1, 2], 2, h)
            .into_iter()
            .map(|s| (s.voter, s.signature))
            .collect();
        let local = mgr
            .verify_synced_certificate(2, h, tb(2), &sigs, &committee, &tb(2))
            .expect("verifies");
        mgr.install_synced_certificate(local)
            .await
            .expect("install");
        let out = n
            .sync
            .on_certificate_at("peer-a", cert_msg(2, h, signed(&[1, 2, 3], 2, h)), now)
            .await;
        assert_eq!(
            out,
            SyncOutcome::Stale {
                height: 2,
                latest: 2
            }
        );
        // The stored certificate is still the local one.
        let stored = mgr.latest_finalized_certificate().await.expect("stored");
        assert!(stored.votes.contains_key(&pk(&key(0))));
    }

    #[tokio::test]
    async fn certificate_above_the_applied_tip_waits() {
        let (n, _) = node(FloorMode::Enforced).await;
        let now = Instant::now();
        n.solicit("peer-a", now).await;
        let h = Hash::new([4; 32]);
        let out = n
            .sync
            .on_certificate_at("peer-a", cert_msg(4, h, signed(&[0, 1, 2], 4, h)), now)
            .await;
        assert_eq!(
            out,
            SyncOutcome::NotYetApplied {
                height: 4,
                applied_height: 2
            }
        );
        assert_untouched(&n);
    }

    /// Responses are used only as the answer to the outstanding request, from
    /// the peer asked, before it expires.
    #[tokio::test]
    async fn unsolicited_responses_are_ignored() {
        let (n, _) = node(FloorMode::Enforced).await;
        let t0 = Instant::now();
        // Never requested.
        assert!(!n.sync.accept_response_at("peer-a", t0).await);
        // Requested from peer-a; peer-b answers.
        n.solicit("peer-a", t0).await;
        assert!(!n.sync.accept_response_at("peer-b", t0).await);
        // peer-a answers after the request expired.
        let late = t0 + Duration::from_secs(CERT_REQUEST_TIMEOUT_SECS);
        assert!(!n.sync.accept_response_at("peer-a", late).await);
        // Nothing was claimed: the slot is free and nothing was checked.
        assert!(!n.sync.state.lock().await.verifying);
        assert_eq!(n.latest().await, 0);
        assert_untouched(&n);
    }

    #[tokio::test]
    async fn requests_are_rate_limited_and_rotate_peers() {
        let (n, _) = node(FloorMode::Enforced).await;
        let peers = vec!["peer-a".to_string(), "peer-b".to_string()];
        let t0 = Instant::now();
        let (first, _) = n.sync.request_at(&peers, t0).await.expect("due");
        // Outstanding: nothing new until it expires.
        assert!(n
            .sync
            .request_at(&peers, t0 + Duration::from_secs(1))
            .await
            .is_none());
        let t1 = t0 + Duration::from_secs(CERT_REQUEST_TIMEOUT_SECS);
        let (second, _) = n
            .sync
            .request_at(&peers, t1)
            .await
            .expect("due after expiry");
        assert_ne!(first, second, "round robin");
        // Answered at once -> the next request still waits the minimum interval.
        assert!(n.sync.accept_response_at(&second, t1).await);
        n.sync.state.lock().await.verifying = false;
        assert!(n
            .sync
            .request_at(&peers, t1 + Duration::from_secs(1))
            .await
            .is_none());
        let t2 = t1 + Duration::from_secs(CERT_REQUEST_MIN_INTERVAL_SECS);
        assert!(n.sync.request_at(&peers, t2).await.is_some());
        // No candidates: nothing.
        let t3 = t2 + Duration::from_secs(CERT_REQUEST_TIMEOUT_SECS);
        assert!(n.sync.request_at(&[], t3).await.is_none());
    }

    #[tokio::test]
    async fn nothing_is_requested_until_the_node_has_blocks_beyond_its_floor() {
        let (n, _) = node_with(
            FloorMode::Enforced,
            selector(1, &[0, 1, 2, 3]).await,
            false,
            None,
        )
        .await;
        assert!(
            n.sync
                .request_at(&["peer-a".to_string()], Instant::now())
                .await
                .is_none(),
            "applied tip 0 = finalized 0: nothing to ask for"
        );
    }

    #[tokio::test]
    async fn serving_is_rate_limited_per_peer_and_bounded_to_the_range() {
        let (seed, (_a1, a2, _b2, _b3)) = node(FloorMode::Enforced).await;
        let h = a2.header.block_hash;
        let committee: Vec<PublicKey> = (0..4u8).map(|i| pk(&key(i))).collect();
        let cp = Checkpoint {
            height: 2,
            block_hash: h,
            binding: tb(2),
            stakes: vec![1000; committee.len()],
            committee,
            votes: signed(&[0, 1, 2], 2, h)
                .into_iter()
                .map(|s| (s.voter, s.signature))
                .collect(),
            status: CheckpointStatus::Finalized,
        };
        let (n, _) = node_with(
            FloorMode::Observed,
            selector(1, &[0, 1, 2, 3]).await,
            true,
            Some(cp),
        )
        .await;
        drop(seed);
        let t0 = Instant::now();
        let first = n.sync.serve_at("peer-x", 0, 10, t0).await.expect("served");
        assert!(matches!(
            first,
            NetworkMessage::CheckpointCertificate { height: 2, .. }
        ));
        assert!(
            n.sync
                .serve_at("peer-x", 0, 10, t0 + Duration::from_secs(1))
                .await
                .is_none(),
            "same peer within the interval"
        );
        assert!(
            n.sync.serve_at("peer-y", 0, 10, t0).await.is_some(),
            "another peer"
        );
        let t1 = t0 + Duration::from_secs(CERT_SERVE_MIN_INTERVAL_SECS);
        assert!(
            n.sync.serve_at("peer-x", 0, 10, t1).await.is_some(),
            "after the interval"
        );
        // Out of range: nothing.
        let t2 = t1 + Duration::from_secs(CERT_SERVE_MIN_INTERVAL_SECS);
        assert!(
            n.sync.serve_at("peer-x", 2, 10, t2).await.is_none(),
            "not above 2"
        );
        let t3 = t2 + Duration::from_secs(CERT_SERVE_MIN_INTERVAL_SECS);
        assert!(
            n.sync.serve_at("peer-x", 0, 1, t3).await.is_none(),
            "not at or below 1"
        );
    }

    #[tokio::test]
    async fn serve_rate_table_is_bounded() {
        let (n, _) = node(FloorMode::Enforced).await;
        let t0 = Instant::now();
        for i in 0..MAX_SERVE_RATE_ENTRIES {
            let _ = n.sync.serve_at(&format!("p{i}"), 0, 10, t0).await;
        }
        assert_eq!(
            n.sync.state.lock().await.served.len(),
            MAX_SERVE_RATE_ENTRIES
        );
        // Full of fresh entries: a new peer is not served and not added.
        let _ = n.sync.serve_at("late", 0, 10, t0).await;
        assert_eq!(
            n.sync.state.lock().await.served.len(),
            MAX_SERVE_RATE_ENTRIES
        );
        assert!(!n.sync.state.lock().await.served.contains_key("late"));
        // Once the entries age past the interval they are dropped for a new peer.
        let t1 = t0 + Duration::from_secs(CERT_SERVE_MIN_INTERVAL_SECS);
        let _ = n.sync.serve_at("late", 0, 10, t1).await;
        let st = n.sync.state.lock().await;
        assert_eq!(st.served.len(), 1);
        assert!(st.served.contains_key("late"));
    }

    /// Integration: node A finalized checkpoint 2 (its certificate is in its
    /// store). Node B starts empty, catches up by applying the same blocks,
    /// fetches A's certificate over the real wire codec, verifies it against
    /// its OWN epoch committee and ends with the same finality floor — and
    /// keeps it across a restart.
    #[tokio::test]
    async fn fresh_node_catches_up_to_the_floor_via_a_peer_certificate() {
        // A: a node with a finalized checkpoint at 2 (signed by 3 of 4).
        let (probe, (_a1, a2, _b2, _b3)) = node(FloorMode::Enforced).await;
        let h = a2.header.block_hash;
        let committee = probe.gadget.committee_for(2).await.expect("committee");
        drop(probe);
        let a_cert = Checkpoint {
            height: 2,
            block_hash: h,
            binding: tb(2),
            stakes: committee.stakes(),
            committee: committee.pubkeys(),
            votes: signed(&[0, 1, 2], 2, h)
                .into_iter()
                .map(|s| (s.voter, s.signature))
                .collect(),
            status: CheckpointStatus::Finalized,
        };
        let (a, _) = node_with(
            FloorMode::Enforced,
            selector(1, &[0, 1, 2, 3]).await,
            true,
            Some(a_cert),
        )
        .await;
        assert!(matches!(
            a.floor.boot_check().await,
            FloorTick::Verified { height: 2, .. }
        ));
        assert_eq!(a.floor_height(), 2);

        // B: fresh — no blocks, no certificate, floor 0.
        let (exec, storage, dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let mgr = Arc::new(CheckpointManager::with_persistence(
            config(),
            Arc::new(DagStore::with_permissive_vrf_for_testing()),
            Arc::new(RocksDbKvStore::new(storage.db.clone())),
        ));
        let gadget = Arc::new(FinalityGadget::with_switch(
            mgr.clone(),
            Some(selector(1, &[0, 1, 2, 3]).await),
            true,
        ));
        let verified = Arc::new(AtomicU64::new(0));
        let floor = Arc::new(FloorVerifier::new(
            FloorMode::Enforced,
            mgr.clone(),
            app.clone(),
            gadget.safety_stop(),
            verified.clone(),
            CertificateCommittees::new(gadget.clone(), storage.clone()),
        ));
        assert!(floor.install_finalization_guard());
        let b = Node {
            sync: CertificateSync::new(gadget.clone(), app.clone(), floor.clone())
                .expect("not Legacy"),
            storage,
            app,
            gadget,
            floor,
            verified,
            _dir: dir,
        };
        assert_eq!(b.floor.boot_check().await, FloorTick::NoCertificate);
        let t0 = Instant::now();
        assert!(
            b.sync.request_at(&["A".to_string()], t0).await.is_none(),
            "nothing applied yet: nothing to ask for"
        );

        // B catches up on blocks (the sync path applies them).
        let _ = setup_fork(&b.app, &b.storage).await;
        assert_eq!(b.app.applied_tip().await.height, 2);
        assert_eq!(b.floor_height(), 0, "blocks alone do not raise the floor");

        // B -> A: GetCheckpoint; A -> B: CheckpointCertificate.
        let req = over_the_wire(&b.solicit("A", t0).await);
        let NetworkMessage::GetCheckpoint { above, at_or_below } = req else {
            panic!("expected GetCheckpoint, got {req:?}");
        };
        let resp = a
            .sync
            .serve_at("B", above, at_or_below, t0)
            .await
            .expect("A serves its certificate");
        let resp = over_the_wire(&resp);
        let out = b.sync.on_certificate_at("A", resp, t0).await;
        assert_eq!(
            out,
            SyncOutcome::Installed {
                height: 2,
                floor: FloorTick::Verified {
                    height: 2,
                    floor_raised: true,
                    recovered: false
                }
            }
        );
        assert_eq!(b.floor_height(), a.floor_height(), "B's floor caught up");
        assert_eq!(
            b.floor.rpc_finalized_handle().resolve(&b.storage),
            FinalizedAnchor {
                height: 2,
                hash: Some(h)
            }
        );
        // Nothing more to ask for.
        let later = t0 + Duration::from_secs(CERT_REQUEST_TIMEOUT_SECS);
        assert!(b.sync.request_at(&["A".to_string()], later).await.is_none());

        // Restart B over the same store: the synced certificate was persisted
        // and passes the boot check like a locally finalized one.
        let mgr2 = Arc::new(CheckpointManager::with_persistence(
            config(),
            Arc::new(DagStore::with_permissive_vrf_for_testing()),
            Arc::new(RocksDbKvStore::new(b.storage.db.clone())),
        ));
        assert_eq!(mgr2.latest_finalized_height().await, 2);
        let gadget2 = Arc::new(FinalityGadget::with_switch(
            mgr2.clone(),
            Some(selector(1, &[0, 1, 2, 3]).await),
            true,
        ));
        let (exec2, _unused_storage, _unused_dir) = fresh();
        let app2 = Arc::new(CanonicalApplicator::new(exec2, b.storage.clone()));
        let floor2 = FloorVerifier::new(
            FloorMode::Enforced,
            mgr2,
            app2.clone(),
            gadget2.safety_stop(),
            Arc::new(AtomicU64::new(0)),
            CertificateCommittees::new(gadget2.clone(), b.storage.clone()),
        );
        assert_eq!(
            floor2.boot_check().await,
            FloorTick::Verified {
                height: 2,
                floor_raised: true,
                recovered: false
            }
        );
        assert_eq!(app2.finalized_height_handle().load(Ordering::SeqCst), 2);
    }

    /// Observed mode: a synced certificate is verified and reported, but the
    /// floor and RPC tags do not move (same rule as a local certificate).
    #[tokio::test]
    async fn observed_mode_installs_but_does_not_raise_the_floor() {
        let (n, (_a1, a2, _b2, _b3)) = node(FloorMode::Observed).await;
        let now = Instant::now();
        n.solicit("peer-a", now).await;
        let h = a2.header.block_hash;
        let out = n
            .sync
            .on_certificate_at("peer-a", cert_msg(2, h, signed(&[0, 1, 2], 2, h)), now)
            .await;
        assert_eq!(
            out,
            SyncOutcome::Installed {
                height: 2,
                floor: FloorTick::Verified {
                    height: 2,
                    floor_raised: false,
                    recovered: false
                }
            }
        );
        assert_eq!(n.floor_height(), 0);
        assert_eq!(n.verified_height(), 2);
        assert_eq!(
            n.floor.rpc_finalized_handle().resolve(&n.storage),
            FinalizedAnchor::GENESIS
        );
    }
}
