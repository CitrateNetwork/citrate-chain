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
//   * Enforced — both ON. A verified certificate also raises the reorg floor,
//                and the finalized/safe RPC tags follow the verified height.
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

use citrate_consensus::checkpoint::CheckpointManager;
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
            state: Mutex::new(VerifierState::default()),
        }
    }

    /// The handle the RPC `finalized`/`safe` tags must read in this mode:
    /// Legacy and Observed keep today's source (the applicator's floor handle,
    /// which neither mode raises, so the tags stay at genesis); only Enforced,
    /// where the floor is actually enforced, reads the verified height.
    pub fn rpc_finalized_handle(&self) -> Arc<AtomicU64> {
        match self.mode {
            FloorMode::Legacy | FloorMode::Observed => self.applicator.finalized_height_handle(),
            FloorMode::Enforced => self.verified_height.clone(),
        }
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
        info!(
            "checkpoint finality: boot certificate check ({:?} mode): {:?}",
            self.mode, out
        );
        out
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

        // A mismatch clears only once the certified block is canonical here.
        let mut recovered = false;
        if let Some(HaltReason::Mismatch {
            height, certified, ..
        }) = st.halt.clone()
        {
            match self
                .applicator
                .verify_certified_floor(height, certified, raise)
                .await
            {
                FloorCheck::Match => {
                    info!(
                        "checkpoint finality: RECOVERED — finalized block {} @ {} is canonical on \
                         this node again (normal fork choice); safety stop cleared, finality \
                         resumes",
                        certified, height
                    );
                    st.halt = None;
                    recovered = true;
                    self.verified_height.fetch_max(height, Ordering::SeqCst);
                    self.gadget_halt.clear().await;
                }
                FloorCheck::Mismatch { canonical } => {
                    st.halt = Some(HaltReason::Mismatch {
                        height,
                        certified,
                        canonical,
                    });
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

        match self
            .applicator
            .verify_certified_floor(cert.height, cert.block_hash, raise)
            .await
        {
            FloorCheck::Match => {
                self.verified_height
                    .fetch_max(cert.height, Ordering::SeqCst);
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
        let frozen = self.rpc_finalized_handle().load(Ordering::SeqCst);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_apply::tests::{fresh, setup_fork};
    use crate::canonical_apply::ReorgOutcome;
    use crate::persistent_dag::RocksDbKvStore;
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
        assert!(
            Arc::ptr_eq(&rpc, &app.finalized_height_handle()),
            "RPC reads today's handle"
        );
        assert_eq!(load(&rpc), 0);
        assert!(!r.gadget.halted());
        assert!(Arc::new(r.verifier).spawn().is_none(), "no Legacy loop");
    }

    #[tokio::test]
    async fn enforced_raises_the_floor_from_a_verified_matching_certificate() {
        let (exec, storage, _dir) = fresh();
        let app = Arc::new(CanonicalApplicator::new(exec, storage.clone()));
        let (_a1, a2, _b2, _b3) = setup_fork(&app, &storage).await;
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
        assert_eq!(load(&r.verified), 2, "RPC tags advanced");
        assert!(Arc::ptr_eq(&r.verifier.rpc_finalized_handle(), &r.verified));
        assert!(!r.gadget.halted());
        assert_eq!(r.verifier.halt_reason().await, None);
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
            Arc::ptr_eq(&rpc, &app.finalized_height_handle()),
            "observed: RPC tags read the (unraised) floor, not the verified height"
        );
        assert_eq!(load(&rpc), 0, "observed: finalized/safe stay at genesis");

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
        assert_eq!(load(&rpc), 0, "RPC tags never advanced");
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
        assert_eq!(load(&r.verified), 0, "mismatch: RPC tags not advanced");
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
