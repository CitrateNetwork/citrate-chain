// node/src/finality_floor.rs
//
// WP-S.3 Stage 1c — checkpoint-finality floor verification and enforcement
// (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §4.5, §6).
//
// A finalized checkpoint certifies a (height, block_hash) PAIR. Raising the reorg
// floor on the height alone can lock a node onto the wrong branch, so before a
// certificate is used for anything this module:
//
//   1. re-verifies the stored certificate (`Checkpoint::verify_certificate`:
//      finalized, committee >= 4, quorum reached, every voter a member, every
//      signature valid for this chain);
//   2. checks its block hash is the block at that height on THIS node's applied
//      chain (`CanonicalApplicator::verify_certified_floor`, which re-confirms the
//      answer under the advance lock and raises the floor before releasing it).
//
// Three modes, from two COMPILED pins (never env/config; spec §6):
//
//   * Legacy   — voting pin OFF (every chain in this release). Nothing new can
//                finalize: a pending checkpoint is only ever created by the
//                gadget's producer path, which is off, so `submit_vote` has
//                nothing to attach to. The pre-Stage-1c poll therefore never
//                moved the floor on a node that never ran voting, and Legacy
//                keeps exactly that: the floor and the finalized/safe RPC tags
//                stay where they are. Improvement over the old poll: a
//                certificate persisted by an earlier voting-ON run is NEVER used
//                to raise the floor by its raw height (it is not hash-checked) —
//                it is logged and ignored.
//   * Observed — voting ON, enforcement OFF. Certificates are verified as above
//                and the verified height is published ONLY as the
//                `citrate_finality_verified_height` metric. The reorg floor is
//                NOT raised, and the finalized/safe RPC tags do NOT advance (they
//                keep reading the applicator's floor, i.e. genesis): nothing
//                enforces the floor in this mode, so a reorg below the verified
//                height still proceeds, and labelling such a block "finalized"
//                would claim a guarantee the node does not give.
//   * Enforced — both ON. A verified certificate also raises the reorg floor
//                (AT FINALIZATION — see below — with this poll as a backstop),
//                and the finalized/safe RPC tags follow the verified
//                (height, hash) PAIR: the RPC resolves them by the certified
//                block's hash, never through the height index (where the last
//                block written at a height — possibly an uncertified sibling —
//                wins). If that block is not stored locally the previous
//                verified pair is served, else genesis.
//
// SAFETY STOP. A certificate that does not match this node's chain (a different
// block at that height, or a chain that steps over it), or does not verify, is
// never used: the floor is not raised, the RPC tags do not advance, the finality
// gadget is HALTED (proposes / signs nothing) and an `error!` "CHECKPOINT
// FINALITY SAFETY STOP" with operator guidance is logged, plus the
// `citrate_finality_*` metrics. A mismatch stop clears only when that
// certificate's block becomes canonical on this node through NORMAL fork choice
// (re-checked every poll). An invalid certificate never clears automatically.
// There is deliberately no forced reorg onto the certified branch: no safe path
// exists for it here, so the node halts finality and alarms instead.
//
// FLOOR AT FINALIZATION (Enforced; spec §5 S2). The poll alone left a window:
// `CheckpointManager::finalize_checkpoint` advanced the finalized height, but the
// floor only followed at the next poll (up to FLOOR_POLL_SECS later), so a reorg
// in between could revert the just-finalized block. In Enforced mode the
// verifier is installed as the manager's `FinalizationGuard`
// ([`FloorVerifier::install_finalization_guard`]), which runs once the
// certificate is durably written (synced; #362) and BEFORE the finalization
// becomes visible (DAG mark, latest finalized height), and does the same check
// as the poll under the same locks ([`FloorVerifier::on_finalize`]). A failed
// certificate write finalizes nothing and never reaches the guard, so the
// floor is never raised for a certificate a restart would not find:
//
//   * certified block canonical here -> the floor is raised in the advance-lock
//     critical section that confirmed it (no reorg can slip between);
//   * a different block at that height -> mismatch safety stop, as the poll;
//   * not confirmable now (the applied tip is below it, or the check could not
//     complete) -> `HaltReason::Unconfirmed` safety stop, which clears like a
//     mismatch once the certified block is confirmed canonical.
//
// So when finalization becomes visible, either the floor covers the certified
// block or the gadget is halted (proposes / signs nothing).
//
// PUBLICATION AFTER PERSISTENCE (review of #335 @ db243a1). The guard raises
// the floor but never PUBLISHES: the finalization is not visible yet when it
// runs. The finalized/safe RPC pair (and the verified-height metric) advance
// only in [`FloorVerifier::after_finalize`] — once the finalization is
// visible, with the same (height, hash) re-confirmed under the advance lock and
// no safety stop in force — or from the poll; and every publication path first
// requires the exact certificate to be in the persistent store
// (`CheckpointManager::is_certificate_persisted`), so an unpersisted
// certificate is never published, whoever calls the hooks. In both non-matching
// cases the pair is also registered with the applicator
// (`CanonicalApplicator::register_certified`): every later reorg re-checks it
// under the advance lock and raises the floor first if the certified block has
// become canonical, so recovery onto the certified branch is protected at once,
// not at the next poll. The poll stays as the backstop (boot, restarts, missed
// hooks). Legacy and Observed install no guard: behaviour there is unchanged.
//
// RESTART (Enforced). The floor and the registered certificates are in memory
// only. When the boot check's latest certificate does not raise the floor, the
// floor is restored from the certificate STORE before any block is admitted
// ([`FloorVerifier::restore_certified_floor`]): every stored certificate,
// highest first, is verified and registered until the highest one whose block
// is on this node's chain is found; the floor is raised to it. Nothing above
// it is dropped, whatever the number of stored certificates.

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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use std::sync::Weak;

use citrate_api::finalized_tag::{FinalizedTagSource, VerifiedFinalized};
use citrate_consensus::checkpoint::{Checkpoint, CheckpointManager, FinalizationGuard};
use citrate_consensus::checkpoint_gadget::{
    checkpoint_enforcement_pinned, checkpoint_voting_pinned, SafetyStop,
};
use citrate_consensus::types::Hash;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::canonical_apply::{CanonicalApplicator, FloorCheck};

/// Floor verification cadence (the pre-Stage-1c floor poll's 5 s).
pub const FLOOR_POLL_SECS: u64 = 5;

/// How finalized checkpoints are used on this node (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorMode {
    /// Voting OFF: certificates are never used; floor + RPC tags unchanged.
    Legacy,
    /// Voting ON, enforcement OFF: verified certificates are reported (metric)
    /// only; neither the floor nor the RPC tags move.
    Observed,
    /// Voting ON, enforcement ON: verified certificates raise the floor and
    /// advance the RPC tags.
    Enforced,
}

impl FloorMode {
    /// Mode for the two switches. Enforcement without voting is Legacy: with
    /// voting off nothing can finalize, so there is nothing to enforce.
    pub fn from_switches(voting: bool, enforcement: bool) -> Self {
        match (voting, enforcement) {
            (false, _) => Self::Legacy,
            (true, false) => Self::Observed,
            (true, true) => Self::Enforced,
        }
    }

    /// Mode for `chain_id` from the compiled pins
    /// (`checkpoint_gadget::CHECKPOINT_VOTING_PINS` /
    /// `CHECKPOINT_ENFORCEMENT_PINS`).
    pub fn for_chain(chain_id: u64) -> Self {
        Self::from_switches(
            checkpoint_voting_pinned(chain_id),
            checkpoint_enforcement_pinned(chain_id),
        )
    }

    /// Whether a verified certificate raises the reorg floor in this mode.
    pub fn raises_floor(self) -> bool {
        self == Self::Enforced
    }
}

/// Why finality is in a safety stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltReason {
    /// The certificate verifies, but this node's applied chain holds
    /// `canonical` at `height` (or no block there: `None`), not `certified`.
    /// Clears when `certified` becomes canonical here via normal fork choice.
    Mismatch {
        height: u64,
        certified: Hash,
        canonical: Option<Hash>,
    },
    /// The stored certificate does not verify. Never clears automatically.
    InvalidCertificate {
        height: u64,
        certified: Hash,
        reason: String,
    },
    /// At finalization the certified block could not be confirmed on this
    /// node's applied chain (its tip was below `height`, or the check could not
    /// complete): finality is paused rather than run unprotected. Clears like a
    /// mismatch once `certified` is confirmed canonical here; becomes a
    /// `Mismatch` if another block is found at `height`.
    Unconfirmed {
        height: u64,
        certified: Hash,
        reason: String,
    },
}

impl HaltReason {
    /// The certified pair a stop waits for, if it can clear (mismatch /
    /// unconfirmed); `None` for an invalid certificate.
    fn awaited(&self) -> Option<(u64, Hash)> {
        match self {
            Self::Mismatch {
                height, certified, ..
            }
            | Self::Unconfirmed {
                height, certified, ..
            } => Some((*height, *certified)),
            Self::InvalidCertificate { .. } => None,
        }
    }
}

/// What one verification pass concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorTick {
    /// Legacy mode: nothing is done.
    Legacy,
    /// Nothing has finalized.
    NoCertificate,
    /// The latest certificate verified and matches this node's chain.
    /// `recovered` = a mismatch stop was cleared during this pass.
    Verified {
        height: u64,
        floor_raised: bool,
        recovered: bool,
    },
    /// This node's applied tip is still below the certified height.
    Waiting { height: u64, applied_height: u64 },
    /// The chain check could not complete this pass (retried next pass).
    Unverifiable(String),
    /// In a safety stop.
    Halted(HaltReason),
}

#[derive(Default)]
struct VerifierState {
    halt: Option<HaltReason>,
}

/// Verifies finalized checkpoint certificates against this node's applied chain
/// and (Enforced) raises the reorg floor. See the module docs.
pub struct FloorVerifier {
    mode: FloorMode,
    chain_id: u64,
    /// Data source of certificates: `CheckpointManager::latest_finalized_certificate`
    /// (memory, else `DAG_METADATA` `checkpoint:{height}`).
    manager: Arc<CheckpointManager>,
    /// Data source of this node's chain + owner of the reorg floor.
    applicator: Arc<CanonicalApplicator>,
    /// The finality gadget's safety stop (`FinalityGadget::safety_stop`).
    /// Engaged / cleared only through its signing gate, so a halt is
    /// serialized against the gadget's signing path. Lock order: this
    /// verifier's `state` -> the stop's gate (the gadget never awaits the
    /// verifier state).
    gadget_halt: Arc<SafetyStop>,
    /// Verified finalized height (Observed / Enforced): the
    /// `citrate_finality_verified_height` metric; backs the RPC tags in
    /// Enforced mode only.
    verified_height: Arc<AtomicU64>,
    /// Verified `(height, hash)` pairs (Observed / Enforced): what the RPC
    /// `finalized`/`safe` tags resolve BY HASH in Enforced mode only.
    verified_pairs: Arc<VerifiedFinalized>,
    state: Mutex<VerifierState>,
}

impl FloorVerifier {
    /// `verified_height` only ever advances to a verified, matching height; the
    /// RPC `finalized`/`safe` tags read it in Enforced mode only
    /// ([`Self::rpc_finalized_handle`]).
    pub fn new(
        mode: FloorMode,
        manager: Arc<CheckpointManager>,
        applicator: Arc<CanonicalApplicator>,
        gadget_halt: Arc<SafetyStop>,
        verified_height: Arc<AtomicU64>,
    ) -> Self {
        let chain_id = manager.config().chain_id;
        Self {
            mode,
            chain_id,
            manager,
            applicator,
            gadget_halt,
            verified_height,
            verified_pairs: Arc::new(VerifiedFinalized::new()),
            state: Mutex::new(VerifierState::default()),
        }
    }

    /// The source the RPC `finalized`/`safe` tags must read in this mode:
    /// Legacy and Observed keep today's source (the applicator's floor handle,
    /// which neither mode raises, so the tags stay at genesis); only Enforced,
    /// where the floor is actually enforced, reads the verified
    /// `(height, hash)` pairs — resolved by hash, so an uncertified sibling at
    /// the finalized height is never served.
    pub fn rpc_finalized_handle(&self) -> FinalizedTagSource {
        match self.mode {
            FloorMode::Legacy | FloorMode::Observed => {
                FinalizedTagSource::Height(self.applicator.finalized_height_handle())
            }
            FloorMode::Enforced => FinalizedTagSource::Verified(self.verified_pairs.clone()),
        }
    }

    /// The finalized height the RPC tags currently name in this mode (for the
    /// alarm text).
    fn rpc_finalized_height(&self) -> u64 {
        match self.mode {
            FloorMode::Legacy | FloorMode::Observed => self
                .applicator
                .finalized_height_handle()
                .load(Ordering::SeqCst),
            FloorMode::Enforced => self.verified_pairs.latest().map_or(0, |(h, _)| h),
        }
    }

    /// Publish a verified, matching `(height, hash)` — only if its certificate
    /// is in the persistent store, so a restart reloads it (and restores the
    /// floor from it) before any reorg. Returns whether it was published.
    fn record_verified(&self, height: u64, hash: Hash) -> bool {
        if !self.manager.is_certificate_persisted(height, &hash) {
            warn!(
                "checkpoint finality: finalized block {} @ {} is not published (finalized/safe \
                 RPC tags unchanged): its certificate is not in the persistent store",
                hash, height
            );
            return false;
        }
        self.verified_height.fetch_max(height, Ordering::SeqCst);
        self.verified_pairs.record(height, hash);
        true
    }

    /// The current safety stop, if any.
    #[cfg(test)]
    pub async fn halt_reason(&self) -> Option<HaltReason> {
        self.state.lock().await.halt.clone()
    }

    /// Boot-time pass. MUST run before any block admission, drain or recovery so
    /// a node restarting with a certificate for a branch it is not on halts
    /// finality before it does anything else. Legacy: logs (and ignores) any
    /// certificate a previous voting-ON run persisted; changes nothing.
    pub async fn boot_check(&self) -> FloorTick {
        if self.mode == FloorMode::Legacy {
            let persisted = self.manager.latest_finalized_height().await;
            if persisted > 0 {
                warn!(
                    "checkpoint finality: this database holds finalized checkpoint certificates up \
                     to height {} from an earlier run with voting ON. Voting is OFF in this \
                     release, so they are IGNORED: the reorg floor and the finalized/safe RPC \
                     tags are not raised from them.",
                    persisted
                );
            }
            self.publish(false);
            return FloorTick::Legacy;
        }
        let out = self.tick().await;
        if self.mode.raises_floor() && !matches!(out, FloorTick::Verified { .. }) {
            self.restore_certified_floor().await;
        }
        info!(
            "checkpoint finality: boot certificate check ({:?} mode): {:?}",
            self.mode, out
        );
        out
    }

    /// Enforced, at boot, when the latest certificate did not raise the floor
    /// (mismatch / waiting / unverifiable). The floor is an in-memory value
    /// lost on restart, so restore it from the certificate STORE before any
    /// block admission, drain or recovery (review of #335 @ 5236d2b): walk
    /// every stored finalized certificate, highest first — the persisted
    /// records, not only the in-memory window — verify each, and register it
    /// with the applicator, until one is found whose block is on this node's
    /// applied chain; raise the floor to that one (under the advance lock,
    /// `verify_certified_floor`) and stop.
    ///
    /// Why stopping there is safe: the floor protects by HEIGHT (a reorg's
    /// fork point must be >= the floor), so once it is at the highest stored
    /// certificate that is canonical here, every lower certified block that is
    /// canonical here is protected too; a lower one that is NOT canonical here
    /// can never become canonical without a reorg below the floor, which is
    /// refused. Every certificate ABOVE it is registered, none dropped, so the
    /// first reorg after any of them becomes canonical raises the floor to it
    /// (`CanonicalApplicator::effective_floor`). If the chain cannot be read,
    /// or the floor could not be raised, nothing is skipped: the remaining
    /// certificates are all registered and the applicator settles the floor
    /// from them under its lock. A stored certificate that does not verify is
    /// logged and not used.
    async fn restore_certified_floor(&self) {
        let heights = self.manager.finalized_certificate_heights().await;
        let tip = self.applicator.applied_tip().await;
        let mut walk = self.applicator.walk_applied(tip);
        // `false` once the walk cannot be trusted: register everything left.
        let mut early_stop = true;
        let mut registered = 0usize;
        let mut restored: Option<(u64, Hash)> = None;
        let floor_handle = self.applicator.finalized_height_handle();
        for height in heights {
            if height <= floor_handle.load(Ordering::SeqCst) {
                break;
            }
            let Some(cert) = self.manager.get_checkpoint(height).await else {
                warn!(
                    "checkpoint finality: stored certificate at height {} could not be read; \
                     not registered",
                    height
                );
                continue;
            };
            if let Err(e) = cert.verify_certificate(self.chain_id) {
                warn!(
                    "checkpoint finality: stored certificate {} @ {} does not verify; not \
                     registered: {}",
                    cert.block_hash, cert.height, e
                );
                continue;
            }
            self.applicator
                .register_certified(cert.height, cert.block_hash);
            registered = registered.saturating_add(1);
            if !early_stop {
                continue;
            }
            match walk.hash_at(cert.height) {
                Ok(Some(here)) if here == cert.block_hash => {
                    match self
                        .applicator
                        .verify_certified_floor(cert.height, cert.block_hash, true)
                        .await
                    {
                        FloorCheck::Match => {
                            restored = Some((cert.height, cert.block_hash));
                            break;
                        }
                        other => {
                            warn!(
                                "checkpoint finality: stored certificate {} @ {} could not \
                                 raise the floor at boot ({:?}); registering every older \
                                 certificate instead",
                                cert.block_hash, cert.height, other
                            );
                            early_stop = false;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        "checkpoint finality: applied chain unreadable while restoring the \
                         floor at boot ({}); registering every older certificate instead",
                        e
                    );
                    early_stop = false;
                }
            }
        }
        // Same check the next reorg would make, under the advance lock (also
        // settles the case where the walk could not be used).
        let floor = self.applicator.settle_registered_floor().await;
        match restored {
            Some((height, hash)) => info!(
                "checkpoint finality: reorg floor restored at boot to finalized block {} @ {} \
                 (the highest stored certificate on this node's chain); {} certificate(s) \
                 above it registered",
                hash,
                height,
                registered.saturating_sub(1)
            ),
            None => info!(
                "checkpoint finality: no stored certificate confirmed on this node's chain at \
                 boot; {} certificate(s) registered, reorg floor {}",
                registered, floor
            ),
        }
    }

    /// One verification pass (see the module docs).
    pub async fn tick(&self) -> FloorTick {
        if self.mode == FloorMode::Legacy {
            return FloorTick::Legacy;
        }
        let mut st = self.state.lock().await;
        let raise = self.mode.raises_floor();

        // An invalid certificate never clears.
        if let Some(reason @ HaltReason::InvalidCertificate { .. }) = &st.halt {
            let reason = reason.clone();
            self.gadget_halt.engage().await;
            self.publish(true);
            return FloorTick::Halted(reason);
        }

        // A mismatch / unconfirmed stop clears only once the certified block is
        // canonical here.
        let mut recovered = false;
        if let Some((height, certified)) = st.halt.as_ref().and_then(HaltReason::awaited) {
            if raise {
                self.applicator.register_certified(height, certified);
            }
            match self
                .applicator
                .verify_certified_floor(height, certified, raise)
                .await
            {
                FloorCheck::Match => {
                    info!(
                        "checkpoint finality: RECOVERED — finalized block {} @ {} is canonical on \
                         this node (normal fork choice); safety stop cleared, finality resumes",
                        certified, height
                    );
                    st.halt = None;
                    recovered = true;
                    let _ = self.record_verified(height, certified);
                    self.gadget_halt.clear().await;
                }
                FloorCheck::Mismatch { canonical } => {
                    let reason = HaltReason::Mismatch {
                        height,
                        certified,
                        canonical,
                    };
                    if matches!(st.halt, Some(HaltReason::Unconfirmed { .. })) {
                        // Now known to be a mismatch: raise the alarm.
                        return self.enter_halt(&mut st, reason).await;
                    }
                    st.halt = Some(reason);
                    return self.still_halted(&st).await;
                }
                FloorCheck::NotYetApplied { .. } | FloorCheck::Unverifiable(_) => {
                    return self.still_halted(&st).await;
                }
            }
        }

        let Some(cert) = self.manager.latest_finalized_certificate().await else {
            self.publish(false);
            return FloorTick::NoCertificate;
        };
        // Re-verified on every pass (at most `committee_size` ed25519 checks per
        // 5 s): no cache keyed on (height, hash) that a rewritten record could slip
        // past.
        if let Err(e) = cert.verify_certificate(self.chain_id) {
            let reason = HaltReason::InvalidCertificate {
                height: cert.height,
                certified: cert.block_hash,
                reason: e.to_string(),
            };
            return self.enter_halt(&mut st, reason).await;
        }

        if raise {
            // Settled at once on a match; otherwise every later reorg re-checks it.
            self.applicator
                .register_certified(cert.height, cert.block_hash);
        }
        match self
            .applicator
            .verify_certified_floor(cert.height, cert.block_hash, raise)
            .await
        {
            FloorCheck::Match => {
                let _ = self.record_verified(cert.height, cert.block_hash);
                self.publish(false);
                FloorTick::Verified {
                    height: cert.height,
                    floor_raised: raise,
                    recovered,
                }
            }
            FloorCheck::Mismatch { canonical } => {
                let reason = HaltReason::Mismatch {
                    height: cert.height,
                    certified: cert.block_hash,
                    canonical,
                };
                self.enter_halt(&mut st, reason).await
            }
            FloorCheck::NotYetApplied { applied_height } => {
                self.publish(false);
                FloorTick::Waiting {
                    height: cert.height,
                    applied_height,
                }
            }
            FloorCheck::Unverifiable(why) => {
                warn!(
                    "checkpoint finality: certificate {} @ {} not checked this pass: {}",
                    cert.block_hash, cert.height, why
                );
                self.publish(false);
                FloorTick::Unverifiable(why)
            }
        }
    }

    /// Enforced mode: install this verifier as `manager`'s
    /// [`FinalizationGuard`], so the floor is raised (or finality halted) BEFORE
    /// a finalization becomes visible ([`Self::on_finalize`]). Legacy and
    /// Observed install nothing (returns `false`): they keep the poll-only
    /// behaviour. Also `false` if the manager already has a guard. The manager
    /// holds only a weak reference, so this creates no reference cycle.
    pub fn install_finalization_guard(self: &Arc<Self>) -> bool {
        if !self.mode.raises_floor() {
            return false;
        }
        self.manager
            .install_finalization_guard(Arc::new(FinalizeHook(Arc::downgrade(self))))
    }

    /// The finalization-time check (Enforced; module docs, "FLOOR AT
    /// FINALIZATION"). Runs from `CheckpointManager::finalize_checkpoint` once
    /// the certificate is durably written and before the latest finalized
    /// height moves (never for a certificate whose write failed). Same
    /// verification as [`Self::tick`]'s main path, under the same verifier
    /// state lock and advance lock, but it raises the floor WITHOUT publishing:
    /// the RPC tags advance only once the finalization is visible
    /// ([`Self::after_finalize`]).
    /// Returns `None` outside Enforced mode.
    pub async fn on_finalize(&self, cert: &Checkpoint) -> Option<FloorTick> {
        if !self.mode.raises_floor() {
            return None;
        }
        let mut st = self.state.lock().await;
        if let Err(e) = cert.verify_certificate(self.chain_id) {
            let reason = HaltReason::InvalidCertificate {
                height: cert.height,
                certified: cert.block_hash,
                reason: e.to_string(),
            };
            return Some(self.enter_halt(&mut st, reason).await);
        }
        // Registered first: whatever the check below concludes, no later reorg
        // can revert this block once it is canonical here.
        self.applicator
            .register_certified(cert.height, cert.block_hash);
        let reason = match self
            .applicator
            .verify_certified_floor(cert.height, cert.block_hash, true)
            .await
        {
            FloorCheck::Match => {
                if st.halt.is_some() {
                    // The floor now protects this canonical certified block, but
                    // an existing stop keeps the RPC tags / verified height frozen
                    // until the poll clears it.
                    return Some(self.still_halted(&st).await);
                }
                // Not published here: the finalization is not visible yet.
                self.publish(false);
                info!(
                    "checkpoint finality: finalized block {} @ {} is canonical on this node; \
                     reorg floor raised at finalization",
                    cert.block_hash, cert.height
                );
                return Some(FloorTick::Verified {
                    height: cert.height,
                    floor_raised: true,
                    recovered: false,
                });
            }
            FloorCheck::Mismatch { canonical } => HaltReason::Mismatch {
                height: cert.height,
                certified: cert.block_hash,
                canonical,
            },
            FloorCheck::NotYetApplied { applied_height } => HaltReason::Unconfirmed {
                height: cert.height,
                certified: cert.block_hash,
                reason: format!("this node's applied tip is at height {applied_height}"),
            },
            FloorCheck::Unverifiable(why) => HaltReason::Unconfirmed {
                height: cert.height,
                certified: cert.block_hash,
                reason: why,
            },
        };
        if st.halt.is_some() {
            // Already stopped: that stop's own certificate decides when it
            // clears (re-checked every poll).
            return Some(self.still_halted(&st).await);
        }
        Some(self.enter_halt(&mut st, reason).await)
    }

    /// Publication after finalization (Enforced; module docs, "PUBLICATION
    /// AFTER PERSISTENCE"). Runs from `CheckpointManager::finalize_checkpoint`
    /// once the certificate is durably written and the finalization is
    /// visible. Publishes `cert`'s exact (height, hash) only if no safety stop
    /// is in force, the certificate still verifies, the pair is confirmed
    /// canonical with the floor at or above it under the advance lock (the
    /// guard raised it), and the certificate is persisted. Otherwise publishes
    /// nothing and leaves it to the poll. Returns `None` outside Enforced mode.
    pub async fn after_finalize(&self, cert: &Checkpoint) -> Option<FloorTick> {
        if !self.mode.raises_floor() {
            return None;
        }
        let st = self.state.lock().await;
        if st.halt.is_some() {
            return Some(self.still_halted(&st).await);
        }
        if let Err(e) = cert.verify_certificate(self.chain_id) {
            // Left to the poll, which halts on it.
            return Some(FloorTick::Unverifiable(e.to_string()));
        }
        match self
            .applicator
            .verify_certified_floor(cert.height, cert.block_hash, true)
            .await
        {
            FloorCheck::Match => {
                let published = self.record_verified(cert.height, cert.block_hash);
                self.publish(false);
                if published {
                    info!(
                        "checkpoint finality: finalized block {} @ {} persisted; finalized/safe \
                         RPC tags advanced",
                        cert.block_hash, cert.height
                    );
                }
                Some(FloorTick::Verified {
                    height: cert.height,
                    floor_raised: true,
                    recovered: false,
                })
            }
            other => Some(FloorTick::Unverifiable(format!(
                "finalized block {} @ {} not confirmed after finalization: {:?}",
                cert.block_hash, cert.height, other
            ))),
        }
    }

    /// Spawn the periodic pass (every [`FLOOR_POLL_SECS`]). `None` in Legacy
    /// mode: there is nothing to verify or enforce.
    pub fn spawn(self: Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        if self.mode == FloorMode::Legacy {
            return None;
        }
        Some(tokio::spawn(async move {
            // #310: Skip — no burst of passes after a stall.
            let mut tick = crate::timing::cadence_interval(Duration::from_secs(FLOOR_POLL_SECS));
            loop {
                tick.tick().await;
                let _ = self.tick().await;
            }
        }))
    }

    async fn still_halted(&self, st: &VerifierState) -> FloorTick {
        self.gadget_halt.engage().await;
        self.publish(true);
        match &st.halt {
            Some(reason) => FloorTick::Halted(reason.clone()),
            None => FloorTick::Unverifiable("halt state lost".to_string()),
        }
    }

    async fn enter_halt(&self, st: &mut VerifierState, reason: HaltReason) -> FloorTick {
        // Waits for any in-flight signing decision; once engaged, the gadget
        // creates no new signature until the stop is cleared.
        self.gadget_halt.engage().await;
        if st.halt.as_ref() != Some(&reason) {
            crate::metrics::record_finality_certificate_mismatch();
            self.alarm(&reason);
        }
        st.halt = Some(reason.clone());
        self.publish(true);
        FloorTick::Halted(reason)
    }

    fn alarm(&self, reason: &HaltReason) {
        // What the finalized/safe RPC tags currently answer in this mode.
        let frozen = self.rpc_finalized_height();
        match reason {
            HaltReason::Mismatch {
                height,
                certified,
                canonical,
            } => {
                let here = match canonical {
                    Some(h) => format!("block {h}"),
                    None => "no block at that height (its chain steps over it)".to_string(),
                };
                error!(
                    "CHECKPOINT FINALITY SAFETY STOP: the finalized checkpoint at height {height} \
                     certifies block {certified}, but this node's applied chain has {here}. This \
                     node is on a branch the validator committee did not finalize. Finality is \
                     HALTED here: no checkpoint is proposed or signed, the reorg floor is not \
                     raised, and the finalized/safe RPC tags stay at {frozen}. Block import and \
                     production continue. The stop clears by itself if normal fork choice moves \
                     this node onto block {certified}. If it does not: keep the node running, \
                     compare the block at height {height} with independent peers and escalate to \
                     the chain operators. Do not force a reorg, and do not delete this node's \
                     database if it is a voting validator (it holds the signed-vote record that \
                     prevents equivocation)."
                );
            }
            HaltReason::Unconfirmed {
                height,
                certified,
                reason,
            } => {
                error!(
                    "CHECKPOINT FINALITY SAFETY STOP: the checkpoint at height {height} finalized \
                     block {certified}, but that block could not be confirmed on this node's \
                     applied chain when it finalized ({reason}). Finality is PAUSED here: no \
                     checkpoint is proposed or signed, and the finalized/safe RPC tags stay at \
                     {frozen}. Block import and production continue, and any reorg is re-checked \
                     against this certificate. The stop clears by itself once block {certified} \
                     is confirmed canonical at height {height} on this node; if another block \
                     is found there it becomes a mismatch stop."
                );
            }
            HaltReason::InvalidCertificate {
                height,
                certified,
                reason,
            } => {
                error!(
                    "CHECKPOINT FINALITY SAFETY STOP: the stored finalized checkpoint certificate \
                     at height {height} (block {certified}) does not verify on chain {}: {reason}. \
                     Finality is HALTED: no checkpoint is proposed or signed, the reorg floor is \
                     not raised, and the finalized/safe RPC tags stay at {frozen}. This stop \
                     NEVER clears automatically. The record (dag_metadata key \
                     checkpoint:{height}) was not produced by a valid quorum for this chain, or \
                     the database is damaged. Stop and escalate; preserve a copy of the database \
                     for analysis before changing anything.",
                    self.chain_id
                );
            }
        }
    }

    fn publish(&self, halted: bool) {
        crate::metrics::record_finality_floor(
            halted,
            self.verified_height.load(Ordering::SeqCst),
            self.applicator
                .finalized_height_handle()
                .load(Ordering::SeqCst),
        );
    }
}

/// The manager-side handle of an installed verifier (weak: the verifier owns
/// the manager, not the other way round).
struct FinalizeHook(Weak<FloorVerifier>);

#[async_trait::async_trait]
impl FinalizationGuard for FinalizeHook {
    async fn before_finalize(&self, certificate: &Checkpoint) {
        if let Some(verifier) = self.0.upgrade() {
            let _ = verifier.on_finalize(certificate).await;
        }
    }

    async fn after_finalize(&self, certificate: &Checkpoint) {
        if let Some(verifier) = self.0.upgrade() {
            let _ = verifier.after_finalize(certificate).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_apply::tests::{fresh, setup_fork};
    use crate::canonical_apply::ReorgOutcome;
    use crate::persistent_dag::RocksDbKvStore;
    use citrate_api::finalized_tag::FinalizedAnchor;
    use citrate_consensus::checkpoint::{
        sign_checkpoint_vote, Checkpoint, CheckpointConfig, CheckpointStatus,
    };
    use citrate_consensus::checkpoint_gadget::{FinalityGadget, SkipReason};
    use citrate_consensus::crypto::Ed25519SigningKey;
    use citrate_consensus::dag_store::{cf, DagStore, KvStore};
    use citrate_consensus::types::PublicKey;
    use citrate_storage::StorageManager;
    use std::collections::HashMap;

    const CHAIN: u64 = 40204;

    fn signer(i: u8) -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[i.saturating_add(1); 32])
    }

    /// A finalized certificate for `(height, hash)` on `CHAIN`: committee of 4,
    /// signed by the first `votes` members (quorum for 4 is 3).
    fn certificate(height: u64, hash: Hash, votes: u8) -> Checkpoint {
        let keys: Vec<Ed25519SigningKey> = (0..4u8).map(signer).collect();
        let committee: Vec<PublicKey> = keys
            .iter()
            .map(|k| PublicKey::new(k.verifying_key().to_bytes()))
            .collect();
        let mut sigs = HashMap::new();
        for k in keys.iter().take(usize::from(votes)) {
            let v = sign_checkpoint_vote(CHAIN, height, hash, k);
            sigs.insert(v.voter, v.signature);
        }
        Checkpoint {
            height,
            block_hash: hash,
            committee,
            votes: sigs,
            status: CheckpointStatus::Finalized,
        }
    }

    /// Persist `cert` exactly where `CheckpointManager::finalize_checkpoint`
    /// does (`DAG_METADATA` `checkpoint:{height}`, bincode).
    fn persist_certificate(storage: &StorageManager, cert: &Checkpoint) {
        let kv = RocksDbKvStore::new(storage.db.clone());
        let bytes = bincode::serialize(cert).expect("serialize certificate");
        kv.kv_put(
            cf::DAG_METADATA,
            format!("checkpoint:{}", cert.height).as_bytes(),
            &bytes,
        )
        .expect("persist certificate");
    }

    /// A checkpoint manager over the node's store, as at boot (it loads every
    /// persisted certificate).
    fn manager_over(storage: &StorageManager) -> Arc<CheckpointManager> {
        let cfg = CheckpointConfig {
            interval: 2,
            committee_size: 100,
            quorum_threshold: 67,
            chain_id: CHAIN,
            vote_depth: 3,
        };
        Arc::new(CheckpointManager::with_persistence(
            cfg,
            Arc::new(DagStore::with_permissive_vrf_for_testing()),
            Arc::new(RocksDbKvStore::new(storage.db.clone())),
        ))
    }

    struct Rig {
        verifier: FloorVerifier,
        gadget: FinalityGadget,
        verified: Arc<AtomicU64>,
        floor: Arc<AtomicU64>,
    }

    fn rig(mode: FloorMode, mgr: Arc<CheckpointManager>, app: Arc<CanonicalApplicator>) -> Rig {
        let gadget = FinalityGadget::with_switch(mgr.clone(), None, mode != FloorMode::Legacy);
        let verified = Arc::new(AtomicU64::new(0));
        let floor = app.finalized_height_handle();
        let verifier = FloorVerifier::new(mode, mgr, app, gadget.safety_stop(), verified.clone());
        Rig {
            verifier,
            gadget,
            verified,
            floor,
        }
    }

    fn load(a: &AtomicU64) -> u64 {
        a.load(Ordering::SeqCst)
    }

    /// The RPC tag source reads the applicator's (unraised) floor handle.
    fn reads_floor_handle(src: &FinalizedTagSource, app: &CanonicalApplicator) -> bool {
        matches!(src, FinalizedTagSource::Height(h) if Arc::ptr_eq(h, &app.finalized_height_handle()))
    }

    #[test]
    fn both_pins_off_is_legacy_and_modes_follow_the_switches() {
        assert_eq!(FloorMode::for_chain(40204), FloorMode::Legacy);
        assert_eq!(FloorMode::for_chain(1337), FloorMode::Legacy);
        assert_eq!(FloorMode::from_switches(false, false), FloorMode::Legacy);
        assert_eq!(
            FloorMode::from_switches(false, true),
            FloorMode::Legacy,
            "enforcement without voting has nothing to enforce"
        );
        assert_eq!(FloorMode::from_switches(true, false), FloorMode::Observed);
        assert_eq!(FloorMode::from_switches(true, true), FloorMode::Enforced);
        assert!(FloorMode::Enforced.raises_floor());
        assert!(!FloorMode::Observed.raises_floor());
        assert!(!FloorMode::Legacy.raises_floor());
    }

    /// The finalization-time check exists only in Enforced mode: Legacy and
    /// Observed install no guard and `on_finalize` does nothing there, so their
    /// behaviour is the poll's, unchanged.
    #[tokio::test]
    async fn finalization_guard_is_enforced_only() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (_a1, a2, _b2, _b3) = setup_fork(&app, &storage).await;
        let cert = certificate(2, a2.header.block_hash, 3);
        for mode in [FloorMode::Legacy, FloorMode::Observed] {
            let mgr = manager_over(&storage);
            let v = Arc::new(rig(mode, mgr.clone(), app.clone()).verifier);
            assert!(!v.install_finalization_guard(), "{mode:?}");
            assert!(!mgr.has_finalization_guard(), "{mode:?}");
            assert_eq!(v.on_finalize(&cert).await, None, "{mode:?}");
            assert_eq!(v.after_finalize(&cert).await, None, "{mode:?}");
            assert_eq!(load(&app.finalized_height_handle()), 0, "{mode:?}");
            assert!(app.certified_pending().is_empty(), "{mode:?}");
        }
        let mgr = manager_over(&storage);
        let r = rig(FloorMode::Enforced, mgr.clone(), app.clone());
        let v = Arc::new(r.verifier);
        assert!(v.install_finalization_guard());
        assert!(mgr.has_finalization_guard());
        assert!(!v.install_finalization_guard(), "first install wins");
        assert_eq!(
            v.on_finalize(&cert).await,
            Some(FloorTick::Verified {
                height: 2,
                floor_raised: true,
                recovered: false
            })
        );
        assert_eq!(load(&r.floor), 2);
        assert_eq!(load(&r.verified), 0, "not published before persistence");
        assert!(app.certified_pending().is_empty(), "settled on a match");
        // Published only by the post-finalization hook, and only once the
        // certificate is persisted.
        assert_eq!(
            v.after_finalize(&cert).await,
            Some(FloorTick::Verified {
                height: 2,
                floor_raised: true,
                recovered: false
            })
        );
        assert_eq!(load(&r.verified), 0, "certificate not persisted");
        persist_certificate(&storage, &cert);
        let _ = v.after_finalize(&cert).await;
        assert_eq!(load(&r.verified), 2);
        assert_eq!(
            v.rpc_finalized_handle().resolve(&storage),
            FinalizedAnchor {
                height: 2,
                hash: Some(a2.header.block_hash)
            }
        );
    }

    /// Enforced: a certificate that does not verify, handed to the
    /// finalization-time check, halts permanently (never raises the floor).
    #[tokio::test]
    async fn on_finalize_invalid_certificate_halts() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (_a1, a2, _b2, _b3) = setup_fork(&app, &storage).await;
        let r = rig(FloorMode::Enforced, manager_over(&storage), app.clone());
        let out = r
            .verifier
            .on_finalize(&certificate(2, a2.header.block_hash, 2))
            .await;
        assert!(
            matches!(
                out,
                Some(FloorTick::Halted(HaltReason::InvalidCertificate {
                    height: 2,
                    ..
                }))
            ),
            "{out:?}"
        );
        assert!(r.gadget.halted());
        assert_eq!(load(&r.floor), 0);
        assert!(app.certified_pending().is_empty());
    }

    /// Improvement over the pre-Stage-1c poll: with voting OFF a certificate
    /// persisted by an earlier voting-ON run is never used — not even a valid one
    /// for this node's own block. Floor and RPC tags stay at today's value (0),
    /// the RPC reads today's handle, and no loop is spawned.
    #[tokio::test]
    async fn legacy_never_raises_from_a_persisted_certificate() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (_a1, a2, _b2, _b3) = setup_fork(&app, &storage).await;
        persist_certificate(&storage, &certificate(2, a2.header.block_hash, 3));
        let mgr = manager_over(&storage);
        assert_eq!(mgr.latest_finalized_height().await, 2, "certificate loaded");
        let r = rig(FloorMode::Legacy, mgr, app.clone());
        assert_eq!(r.verifier.boot_check().await, FloorTick::Legacy);
        assert_eq!(r.verifier.tick().await, FloorTick::Legacy);
        assert_eq!(load(&r.floor), 0, "floor never raised in Legacy");
        let rpc = r.verifier.rpc_finalized_handle();
        assert!(reads_floor_handle(&rpc, &app), "RPC reads today's handle");
        assert_eq!(rpc.resolve(&storage), FinalizedAnchor::GENESIS);
        assert!(!r.gadget.halted());
        assert!(Arc::new(r.verifier).spawn().is_none(), "no Legacy loop");
    }

    #[tokio::test]
    async fn enforced_raises_the_floor_from_a_verified_matching_certificate() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (_a1, a2, b2, _b3) = setup_fork(&app, &storage).await;
        let mgr = manager_over(&storage);
        let r = rig(FloorMode::Enforced, mgr, app);
        assert_eq!(r.verifier.boot_check().await, FloorTick::NoCertificate);
        assert_eq!(load(&r.floor), 0);

        persist_certificate(&storage, &certificate(2, a2.header.block_hash, 3));
        let r = rig(
            FloorMode::Enforced,
            manager_over(&storage),
            r.verifier.applicator.clone(),
        );
        assert_eq!(
            r.verifier.boot_check().await,
            FloorTick::Verified {
                height: 2,
                floor_raised: true,
                recovered: false
            }
        );
        assert_eq!(load(&r.floor), 2, "floor raised to the certified height");
        assert_eq!(load(&r.verified), 2, "verified height reported");
        assert_eq!(
            r.verifier.rpc_finalized_handle().resolve(&storage),
            FinalizedAnchor {
                height: 2,
                hash: Some(a2.header.block_hash)
            },
            "RPC tags advanced to the verified (height, hash) pair"
        );
        // R1: the height index names the uncertified sibling b2 (written last at
        // height 2); the tags resolve by the certified hash, not through it.
        assert_eq!(
            storage.blocks.get_block_by_height(2).expect("height index"),
            Some(b2.header.block_hash),
            "precondition: last-written sibling wins the height index"
        );
        assert!(!r.gadget.halted());
        assert_eq!(r.verifier.halt_reason().await, None);
    }

    /// The range reads behind `eth_getLogs` / `eth_feeHistory` / log filters,
    /// fed by this verifier's RPC handle: after boot from a persisted
    /// certificate, and again after a restart that reloads it, heights at or
    /// below the certified height follow the certified chain (a1, a2) even
    /// though the height index names the later-written sibling b2; a reorg onto
    /// b3 across the raised floor is refused and changes nothing.
    #[tokio::test]
    async fn enforced_range_reads_follow_the_certified_chain_across_restart() {
        use citrate_api::finalized_tag::range_block_hashes;
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (a1, a2, b2, b3) = setup_fork(&app, &storage).await;
        persist_certificate(&storage, &certificate(2, a2.header.block_hash, 3));
        assert_eq!(
            storage.blocks.get_block_by_height(2).expect("height index"),
            Some(b2.header.block_hash),
            "precondition: last-written sibling wins the height index"
        );
        let certified = vec![(1, a1.header.block_hash), (2, a2.header.block_hash)];
        let expected = {
            let mut v = certified.clone();
            v.push((3, b3.header.block_hash)); // above the floor: height index
            v
        };

        let r = rig(FloorMode::Enforced, manager_over(&storage), app.clone());
        assert!(matches!(
            r.verifier.boot_check().await,
            FloorTick::Verified { height: 2, .. }
        ));
        let anchor = r.verifier.rpc_finalized_handle().resolve(&storage);
        assert_eq!(
            range_block_hashes(&storage, Some(anchor), 1, 2).expect("range"),
            certified
        );
        assert_eq!(
            range_block_hashes(&storage, Some(anchor), 1, 3).expect("straddling range"),
            expected
        );

        {
            let lock = app.advance_lock();
            let mut state = lock.lock().await;
            match app.reorg_to(&mut state, b3.header.block_hash).await {
                ReorgOutcome::Rejected(_) => {}
                other => panic!("reorg across the floor must be refused, got {other:?}"),
            }
        }

        // Restart: a fresh manager reloads the certificate from disk and a fresh
        // verifier re-publishes it at boot.
        drop(r);
        let r = rig(FloorMode::Enforced, manager_over(&storage), app.clone());
        assert_eq!(
            r.verifier.rpc_finalized_handle().resolve(&storage),
            FinalizedAnchor::GENESIS,
            "nothing published before the boot check"
        );
        assert!(matches!(
            r.verifier.boot_check().await,
            FloorTick::Verified { height: 2, .. }
        ));
        let anchor = r.verifier.rpc_finalized_handle().resolve(&storage);
        assert_eq!(
            anchor,
            FinalizedAnchor {
                height: 2,
                hash: Some(a2.header.block_hash)
            }
        );
        assert_eq!(
            range_block_hashes(&storage, Some(anchor), 0, 2).expect("range"),
            certified,
            "after restart"
        );
    }

    /// Enforcement OFF: the certificate is verified and reported (metric), but
    /// neither the floor nor the RPC tags move, so a reorg below it PROCEEDS —
    /// and the node then reports that it left the finalized block (safety
    /// stop). The tags never claimed it final.
    #[tokio::test]
    async fn observed_does_not_raise_the_floor_and_reorg_proceeds() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (_a1, a2, b2, b3) = setup_fork(&app, &storage).await;
        persist_certificate(&storage, &certificate(2, a2.header.block_hash, 3));
        let r = rig(FloorMode::Observed, manager_over(&storage), app.clone());
        assert_eq!(
            r.verifier.boot_check().await,
            FloorTick::Verified {
                height: 2,
                floor_raised: false,
                recovered: false
            }
        );
        assert_eq!(load(&r.floor), 0, "observed: floor untouched");
        assert_eq!(load(&r.verified), 2, "observed: verified height reported");
        let rpc = r.verifier.rpc_finalized_handle();
        assert!(
            reads_floor_handle(&rpc, &app),
            "observed: RPC tags read the (unraised) floor, not the verified height"
        );
        assert_eq!(
            rpc.resolve(&storage),
            FinalizedAnchor::GENESIS,
            "observed: finalized/safe stay at genesis"
        );

        {
            let lock = app.advance_lock();
            let mut state = lock.lock().await;
            match app.reorg_to(&mut state, b3.header.block_hash).await {
                ReorgOutcome::Reorged { .. } => {}
                other => panic!("expected the reorg to proceed, got {other:?}"),
            }
        }
        assert_eq!(
            r.verifier.tick().await,
            FloorTick::Halted(HaltReason::Mismatch {
                height: 2,
                certified: a2.header.block_hash,
                canonical: Some(b2.header.block_hash),
            })
        );
        assert!(r.gadget.halted());
        assert_eq!(load(&r.floor), 0);
        assert_eq!(load(&r.verified), 2, "verified height frozen");
        assert_eq!(
            rpc.resolve(&storage),
            FinalizedAnchor::GENESIS,
            "RPC tags never advanced"
        );
    }

    /// Boot with a persisted certificate for ANOTHER branch: finality halts
    /// before anything else runs (gadget proposes/signs nothing, floor and RPC
    /// tags not raised), and recovers once normal fork choice reorgs this node
    /// onto the certified block.
    #[tokio::test]
    async fn boot_on_another_branch_halts_then_recovers_after_reorg() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (_a1, a2, b2, b3) = setup_fork(&app, &storage).await; // tip a2
        persist_certificate(&storage, &certificate(2, b2.header.block_hash, 3));
        let r = rig(FloorMode::Enforced, manager_over(&storage), app.clone());
        let halted = HaltReason::Mismatch {
            height: 2,
            certified: b2.header.block_hash,
            canonical: Some(a2.header.block_hash),
        };
        assert_eq!(
            r.verifier.boot_check().await,
            FloorTick::Halted(halted.clone())
        );
        assert!(r.gadget.halted());
        let out = r
            .gadget
            .on_buried_checkpoint(4, Hash::new([4; 32]), &Hash::new([1; 32]), None)
            .await;
        assert_eq!(out.skipped, Some(SkipReason::Halted));
        assert_eq!(load(&r.floor), 0, "mismatch: floor not raised");
        assert_eq!(
            load(&r.verified),
            0,
            "mismatch: verified height not advanced"
        );
        assert_eq!(
            r.verifier.rpc_finalized_handle().resolve(&storage),
            FinalizedAnchor::GENESIS,
            "mismatch: RPC tags not advanced"
        );
        // Still halted on the next pass (nothing changed).
        assert_eq!(r.verifier.tick().await, FloorTick::Halted(halted));

        // Normal fork choice moves the node onto the certified branch (the
        // floor was never raised, so the reorg is allowed).
        {
            let lock = app.advance_lock();
            let mut state = lock.lock().await;
            match app.reorg_to(&mut state, b3.header.block_hash).await {
                ReorgOutcome::Reorged { .. } => {}
                other => panic!("expected Reorged onto the certified branch, got {other:?}"),
            }
        }
        assert_eq!(
            r.verifier.tick().await,
            FloorTick::Verified {
                height: 2,
                floor_raised: true,
                recovered: true
            }
        );
        assert!(!r.gadget.halted(), "halt cleared");
        assert_eq!(r.verifier.halt_reason().await, None);
        assert_eq!(load(&r.floor), 2);
        assert_eq!(load(&r.verified), 2);
        assert_eq!(
            r.verifier.rpc_finalized_handle().resolve(&storage),
            FinalizedAnchor {
                height: 2,
                hash: Some(b2.header.block_hash)
            },
            "recovered: RPC tags name the certified block"
        );
    }

    /// Boot restores the floor from ANY number of stored certificates (review
    /// of #335 @ 5236d2b): the certificate for this node's block a2 is stored
    /// below 300 certificates for heights this node has not applied yet — more
    /// than the 64 the boot check used to register and more than the 256 the
    /// manager keeps in memory. The boot check finds a2 in the persisted store,
    /// raises the floor to 2, keeps all 300 registered, and a reorg forking
    /// below a2 is refused.
    #[tokio::test]
    async fn boot_restores_the_floor_from_any_number_of_stored_certificates() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (_a1, a2, _b2, b3) = setup_fork(&app, &storage).await; // tip a2
        persist_certificate(&storage, &certificate(2, a2.header.block_hash, 3));
        let above: u64 = 300;
        for h in 3..3 + above {
            let mut x = [0xEE; 32];
            x[..8].copy_from_slice(&h.to_be_bytes());
            persist_certificate(&storage, &certificate(h, Hash::new(x), 3));
        }
        let r = rig(FloorMode::Enforced, manager_over(&storage), app.clone());
        assert_eq!(
            r.verifier.boot_check().await,
            FloorTick::Waiting {
                height: 2 + above,
                applied_height: 2
            }
        );
        assert_eq!(load(&r.floor), 2, "restored from the persisted store");
        assert_eq!(
            app.certified_pending().len(),
            usize::try_from(above).expect("fits"),
            "nothing above the floor is dropped"
        );
        let lock = app.advance_lock();
        let mut state = lock.lock().await;
        match app.reorg_to(&mut state, b3.header.block_hash).await {
            ReorgOutcome::Rejected(why) => {
                assert!(why.contains("below finalized height 2"), "{why}")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    /// A persisted certificate that does not verify (below quorum) halts finality
    /// permanently — even though its block IS this node's block — and the halt
    /// is re-asserted on every pass.
    #[tokio::test]
    async fn invalid_persisted_certificate_halts_permanently() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (_a1, a2, _b2, _b3) = setup_fork(&app, &storage).await;
        persist_certificate(&storage, &certificate(2, a2.header.block_hash, 2));
        let r = rig(FloorMode::Enforced, manager_over(&storage), app);
        let first = r.verifier.boot_check().await;
        assert!(
            matches!(
                first,
                FloorTick::Halted(HaltReason::InvalidCertificate { height: 2, .. })
            ),
            "got {first:?}"
        );
        assert!(r.gadget.halted());
        assert_eq!(load(&r.floor), 0);
        assert_eq!(load(&r.verified), 0);
        // Even if something cleared the gadget flag, the next pass re-halts.
        r.gadget.safety_stop().clear().await;
        assert_eq!(r.verifier.tick().await, first);
        assert!(
            r.gadget.halted(),
            "an invalid certificate never auto-clears"
        );
        assert_eq!(load(&r.floor), 0);
    }

    /// A certificate above the applied tip is neither a match nor a mismatch yet.
    #[tokio::test]
    async fn certificate_above_the_applied_tip_waits() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let _ = setup_fork(&app, &storage).await; // tip @ 2
        persist_certificate(&storage, &certificate(4, Hash::new([4; 32]), 3));
        let r = rig(FloorMode::Enforced, manager_over(&storage), app);
        assert_eq!(
            r.verifier.boot_check().await,
            FloorTick::Waiting {
                height: 4,
                applied_height: 2
            }
        );
        assert!(!r.gadget.halted());
        assert_eq!(load(&r.floor), 0);
        assert_eq!(load(&r.verified), 0);
    }
}
