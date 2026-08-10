// citrate/node/src/admission.rs
//
// SYNC-S1 / D2 — the single, idempotent, crash-safe block admission path.
//
// Planset: citrate-federation/.agentile/planset/
//          2026-07-24-sync-s1-crash-atomic-admission-and-blueset-memory.md
//
// WHY THIS MODULE EXISTS
//
// A block becoming part of this node is not one write, it is several:
//
//   1. DagStore::store_block   — durable (RocksDB cf::DAG_*) + in-memory DAG
//   2. GhostDag::add_block     — in-memory relations + tips (fork choice)
//   3. BlockStore::put_block   — durable chain store (block bytes, height
//                                index, parent->children index)
//   4. CanonicalApplicator     — execute + state-root-verify + advance tip
//
// Before this module those steps were open-coded in two places (the sync
// `NetworkMessage::Blocks` handler and the gossip `NewBlock` handler) as a
// nested match ladder, each step gated on the previous one's success. Three
// separate consequences, all observed in production:
//
//   * A crash between (1) and (3) left the block in the DAG store and absent
//     from the chain store, permanently. `citrate-boot-3` was OOM-killed at
//     exactly that point on 2026-07-24 (height 10944) and never recovered.
//     Re-delivery could not repair it: `store_block` then returns
//     `BlockExists`, which the handler discarded as a no-op (`=> {}`), so
//     `put_block` was never reached. The applied tip froze at 10943 while the
//     stored height climbed to 10974 — a 31-block range re-imported every 2s
//     forever, because `drain_forward` walks the CHAIN store's children index
//     and cannot cross a chain-store hole.
//   * The mirror hole: both handlers skipped a block already in the chain
//     store WITHOUT consulting the DAG store, so a crash in the opposite
//     order was equally permanent.
//   * PIL-42 was a third instance of the same class: genesis was written to
//     the chain store (`genesis.rs:165`) and never the DAG store, orphaning
//     block 1.
//
// THE INVARIANT THIS MODULE ENFORCES
//
//   A block is either fully admitted (present in BOTH stores) or the node
//   will drive it there on the next delivery or the next restart.
//
// Which decomposes into three rules, each of which the pre-D2 code broke:
//
//   R1 — NEVER gate on one store alone. Presence is computed independently
//        for each store and each missing half is completed on its own.
//   R2 — `BlockExists` means CONTINUE, never STOP. It reports that step (1)
//        already happened, which is precisely when steps (2)-(3) still need
//        to run.
//   R3 — a persistence Result is NEVER discarded. (`main.rs:2156` used
//        `let _ = ...put_block(&block);`, so a transient write failure
//        produced the same permanent hole with no crash and no log line.)
//
// CRASH SAFETY WITHOUT ATOMICITY
//
// The DAG store and the chain store are backed by the SAME `Arc<RocksDB>`
// (`main.rs`: `RocksDbKvStore::new(storage.db.clone())`), so admission COULD
// be collapsed into one `WriteBatch`. That is the stronger guarantee and is
// tracked as planset D2.2. It is deliberately not done here: idempotence (R1
// -R3) plus the startup reconciler already reduces a partial admission from
// PERMANENT to TRANSIENT, which is the property that was missing, and it does
// so without a cross-crate refactor of the write path on a T1 consensus
// surface. With D2.2 a partial admission becomes impossible; with D2.3 alone
// it becomes self-healing. Self-healing first, impossible second.

use std::sync::Arc;

use citrate_consensus::dag_store::{DagStore, DagStoreError};
use citrate_consensus::ghostdag::{GhostDag, GhostDagError};
use citrate_consensus::types::{Block, Hash};
use citrate_storage::StorageManager;
use tracing::{debug, info, warn};

use crate::canonical_apply::{ApplyOutcome, CanonicalApplicator};

/// Result of an admission attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// The block is now fully admitted. `completed_partial` is true when this
    /// call REPAIRED a pre-existing partial admission rather than admitting a
    /// block for the first time — i.e. the crash-recovery path fired. Surfaced
    /// so the caller can log/meter it: in a healthy node it is always false.
    Admitted { completed_partial: bool },
    /// Already present in both stores; nothing to do. (Applying it, if it is
    /// stored-but-unapplied, is the periodic drain's job.)
    AlreadyAdmitted,
    /// A parent is not admitted yet, so consistency cannot be established.
    /// The caller buffers the block and retries on a later batch. Carries the
    /// missing parent hash for diagnosis — the pre-D2 code discarded it, which
    /// is why the live wedge could not be read off the logs.
    Deferred { missing_parent: Hash },
    /// The block is inconsistent with this node's view and was not written.
    Rejected(String),
}

/// What a reconcile pass repaired.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Heights whose block was in the DAG store but missing from the chain
    /// store — the `citrate-boot-3` wedge — and has now been written.
    pub chain_writes_completed: Vec<u64>,
    /// Blocks present in the chain store but missing from the DAG store,
    /// now admitted to the DAG.
    pub dag_writes_completed: Vec<u64>,
    /// Heights still unresolvable after the pass (block in neither store —
    /// an ordinary sync gap, not a partial admission).
    pub gaps: Vec<u64>,
}

impl ReconcileReport {
    pub fn repaired_anything(&self) -> bool {
        !self.chain_writes_completed.is_empty() || !self.dag_writes_completed.is_empty()
    }
}

/// The single path by which a block enters this node.
///
/// Every ingest source — sync (`NetworkMessage::Blocks`), gossip
/// (`NetworkMessage::NewBlock`), and the startup reconciler — routes through
/// [`BlockAdmission::admit`]. Nothing else may call `DagStore::store_block` or
/// `BlockStore::put_block`; a Semgrep tripwire enforces that (planset §3.3),
/// mirroring how Rule 3 keeps signing inside the `SignatureCeremony`.
pub struct BlockAdmission {
    storage: Arc<StorageManager>,
    dag_store: Arc<DagStore>,
    ghostdag: Arc<GhostDag>,
    /// Execute-on-receive driver. `None` under v1 headers (pre-reroll), where
    /// received blocks are stored but never executed.
    applicator: Option<Arc<CanonicalApplicator>>,
}

impl BlockAdmission {
    pub fn new(
        storage: Arc<StorageManager>,
        dag_store: Arc<DagStore>,
        ghostdag: Arc<GhostDag>,
        applicator: Option<Arc<CanonicalApplicator>>,
    ) -> Self {
        Self {
            storage,
            dag_store,
            ghostdag,
            applicator,
        }
    }

    /// Whether `hash` is present in BOTH stores.
    ///
    /// The gossip handler uses this to suppress relay/validation work for a
    /// block it already holds. It replaces a bare chain-store `has_block`,
    /// which is what let a half-admitted block masquerade as complete (R1).
    /// A partially-admitted block reports `false` here, so gossip hands it to
    /// [`Self::admit`] and the missing half gets written.
    pub async fn is_fully_admitted(&self, hash: &Hash) -> bool {
        self.storage.blocks.has_block(hash).unwrap_or(false) && self.dag_store.has_block(hash).await
    }

    /// Admit `block`, completing whichever steps are outstanding.
    ///
    /// Idempotent: calling this repeatedly on the same block drives it to
    /// fully-admitted and then reports [`AdmitOutcome::AlreadyAdmitted`],
    /// regardless of which subset of the underlying writes had already landed
    /// when a previous attempt was interrupted.
    pub async fn admit(&self, block: &Block) -> AdmitOutcome {
        let hash = block.header.block_hash;

        // R1: presence in each store is established INDEPENDENTLY. A single
        // `has_block` on either store is exactly the bug this module exists
        // to remove, so the two reads are never collapsed into one check.
        let in_chain = match self.storage.blocks.has_block(&hash) {
            Ok(v) => v,
            Err(e) => {
                // A failed existence read must not be silently coerced to
                // `false` — that would re-run the writes on a healthy block.
                return AdmitOutcome::Rejected(format!("chain-store has_block failed: {e}"));
            }
        };
        let in_dag = self.dag_store.has_block(&hash).await;

        if in_chain && in_dag {
            return AdmitOutcome::AlreadyAdmitted;
        }

        // A partial admission is a crash artefact, not a normal event. Say so
        // loudly and name which half is missing — this is the log line whose
        // absence made the live wedge unreadable for several sessions.
        let completed_partial = in_chain != in_dag;
        if completed_partial {
            warn!(
                "admission: REPAIRING partial admission of {} @ {} (chain_store={}, dag_store={}) \
                 — a previous attempt was interrupted between the two writes",
                hash, block.header.height, in_chain, in_dag
            );
        }

        // The consistency gate runs before ANY write, on every path. Sync is
        // an equally untrusted ingest as gossip (SECREM-01 CONS-1/2/3).
        if let Err(e) = self.ghostdag.validate_block_consistency(block).await {
            return match e {
                GhostDagError::MissingParent(missing_parent) => {
                    AdmitOutcome::Deferred { missing_parent }
                }
                other => AdmitOutcome::Rejected(format!("consistency: {other}")),
            };
        }

        // ---- DAG side ----
        if !in_dag {
            match self.dag_store.store_block(block.clone()).await {
                Ok(()) => {}
                // R2: BlockExists is not a failure and not a stop. It means
                // step 1 is already done, which is exactly the state a crash
                // between the writes leaves behind. Fall through.
                Err(DagStoreError::BlockExists(_)) => {
                    debug!("admission: {} already in DAG store, continuing", hash);
                }
                Err(e) => return AdmitOutcome::Rejected(format!("dag store_block: {e}")),
            }

            if let Err(e) = self.ghostdag.add_block(block).await {
                // Deliberate divergence from the pre-D2 handlers, which nested
                // `put_block` inside `add_block`'s Ok arm and therefore turned
                // any add_block error into a permanent chain-store hole.
                //
                // `add_block` re-runs the consistency gate we just passed, so
                // a failure here is an internal blue-set error, not a verdict
                // on the block. `relations` feeds fork choice only; leaving
                // the two STORES divergent is strictly worse than leaving
                // `relations` incomplete, and the next delivery retries it.
                warn!(
                    "admission: ghostdag.add_block({}) failed after the consistency gate \
                     passed: {} — continuing to the chain write to keep the stores \
                     consistent; fork choice will re-register on a later delivery",
                    hash, e
                );
            }
        }

        // ---- chain side ----
        if !in_chain {
            // R3: never `let _ =`. A discarded error here is indistinguishable
            // from a crash and produces the identical permanent hole.
            if let Err(e) = self.storage.blocks.put_block(block) {
                return AdmitOutcome::Rejected(format!("chain put_block: {e}"));
            }
        }

        // ---- execute-on-receive ----
        // Only for a genuinely new admission. A repaired partial admission is
        // handed to the periodic drain instead: the repair may have filled a
        // hole well BELOW the stored head, in which case the whole contiguous
        // suffix above it should drain in one pass, which is precisely what
        // `drive_drain` does and what a single `apply_received` would not.
        if !completed_partial {
            if let Some(app) = &self.applicator {
                match app.apply_received(block).await {
                    ApplyOutcome::Applied { root, height } => {
                        debug!(
                            "admission: execute-on-receive applied {} @ {} (root {})",
                            hash, height, root
                        );
                    }
                    ApplyOutcome::Rejected(why) => {
                        warn!(
                            "admission: execute-on-receive REJECTED {} @ {}: {}",
                            hash, block.header.height, why
                        );
                    }
                    // Deferred / AlreadyApplied: gap, fork, or echo. No-op.
                    _ => {}
                }
            }
        }

        AdmitOutcome::Admitted { completed_partial }
    }

    /// PIL-42: make genesis the DAG's height-0 root if it is only in the chain
    /// store.
    ///
    /// `genesis.rs` writes genesis to the chain store directly, before any
    /// handler exists, and originally never wrote it to the DAG store — so on a
    /// fresh chain the producer sealed block 1 against a zero selected-parent
    /// and orphaned genesis, which halted testnet-beta at height 231788. That
    /// was the FIRST instance of the chain/DAG divergence class this module
    /// exists to eliminate; it lives here now so all four instances (PIL-42,
    /// PIL-13's sibling, the boot-3 wedge, and its mirror) are handled by one
    /// piece of code with one set of rules.
    ///
    /// Idempotent: a no-op once the DAG has any tip. Genesis sits at height 0,
    /// i.e. below every possible applied tip, so [`Self::reconcile`]'s bounded
    /// range cannot reach it — it needs its own call.
    pub async fn seed_genesis(&self) {
        if !self.dag_store.get_tips().await.is_empty() {
            return;
        }
        let genesis = match self.storage.blocks.get_block_by_height(0) {
            Ok(Some(hash)) => match self.storage.blocks.get_block(&hash) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    warn!("seed_genesis: genesis hash indexed but block missing; DAG not seeded");
                    return;
                }
                Err(e) => {
                    warn!("seed_genesis: failed to read the genesis block: {e}");
                    return;
                }
            },
            // Pre-genesis boot — nothing to seed yet.
            Ok(None) => return,
            Err(e) => {
                warn!("seed_genesis: failed to query the genesis height: {e}");
                return;
            }
        };
        match self.dag_store.store_block(genesis).await {
            Ok(()) => info!(
                "seed_genesis: seeded genesis as the DAG height-0 root (block 1 will link to it)"
            ),
            // R2: already present is success, not a reason to stop.
            Err(DagStoreError::BlockExists(_)) => {
                debug!("seed_genesis: genesis already in the DAG store")
            }
            Err(e) => warn!("seed_genesis: failed to seed genesis into the DAG store: {e}"),
        }
    }

    /// Repair partial admissions already on disk, then let the caller drain.
    ///
    /// D2.3 makes a partial admission self-healing *for blocks that are
    /// re-delivered*. This closes the remaining case: a node that already
    /// holds a hole from a pre-D2 binary (every node in the current fleet),
    /// where nothing guarantees the missing block is offered again.
    ///
    /// Scope is `(applied_tip, latest_height]` — the only range where a hole
    /// can block progress. A hole strictly below the applied tip cannot stall
    /// the drain (that block was already executed), so a full-history scan
    /// would cost O(chain) at every boot to fix nothing.
    pub async fn reconcile(&self) -> ReconcileReport {
        let mut report = ReconcileReport::default();

        let applied_height = self
            .storage
            .blocks
            .get_applied_tip()
            .ok()
            .flatten()
            .map(|(_, h)| h)
            .unwrap_or(0);
        let latest = self.storage.blocks.get_latest_height().unwrap_or(0);
        if latest <= applied_height {
            return report;
        }

        for height in (applied_height + 1)..=latest {
            let in_chain = self
                .storage
                .blocks
                .get_block_by_height(height)
                .ok()
                .flatten()
                .is_some();
            if in_chain {
                continue;
            }

            // Chain store has no block at this height. If the DAG store does,
            // this is a crash-interrupted admission — finish the chain write.
            let candidates = self.dag_store.get_blocks_at_height(height).await;
            match candidates.len() {
                0 => report.gaps.push(height),
                _ => {
                    // With >1 the height is contested; admit them all and let
                    // fork choice pick. Each is individually consistent or it
                    // would not be in the DAG store.
                    let mut wrote = false;
                    for block in candidates {
                        match self.storage.blocks.put_block(&block) {
                            Ok(()) => {
                                info!(
                                    "reconcile: completed the interrupted chain write for {} @ {}",
                                    block.header.block_hash, height
                                );
                                wrote = true;
                            }
                            Err(e) => warn!(
                                "reconcile: failed to complete chain write for {} @ {}: {}",
                                block.header.block_hash, height, e
                            ),
                        }
                    }
                    if wrote {
                        report.chain_writes_completed.push(height);
                    } else {
                        report.gaps.push(height);
                    }
                }
            }
        }

        // Mirror direction: present in the chain store, absent from the DAG.
        // Left inadmissible, every descendant fails the consistency gate.
        for height in (applied_height + 1)..=latest {
            let Some(hash) = self
                .storage
                .blocks
                .get_block_by_height(height)
                .ok()
                .flatten()
            else {
                continue;
            };
            if self.dag_store.has_block(&hash).await {
                continue;
            }
            let Some(block) = self.storage.blocks.get_block(&hash).ok().flatten() else {
                continue;
            };
            match self.dag_store.store_block(block.clone()).await {
                Ok(()) | Err(DagStoreError::BlockExists(_)) => {
                    if let Err(e) = self.ghostdag.add_block(&block).await {
                        debug!("reconcile: add_block({hash}) @ {height}: {e}");
                    }
                    info!("reconcile: admitted chain-only block {hash} @ {height} into the DAG");
                    report.dag_writes_completed.push(height);
                }
                Err(e) => warn!("reconcile: could not admit {hash} @ {height} into the DAG: {e}"),
            }
        }

        if report.repaired_anything() {
            warn!(
                "reconcile: repaired {} interrupted chain write(s) and {} missing DAG \
                 admission(s) above applied height {} (latest {}) — this node was \
                 previously wedged; the periodic drain will now advance",
                report.chain_writes_completed.len(),
                report.dag_writes_completed.len(),
                applied_height,
                latest
            );
        } else {
            debug!(
                "reconcile: no partial admissions above applied height {} (latest {})",
                applied_height, latest
            );
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{BlockBuilder, GhostDagParams, VrfProof};
    use citrate_storage::pruning::PruningConfig;

    const CB: [u8; 20] = [0x33; 20];

    /// A v2 block with an explicit blue score (and the canonical derived work),
    /// so it satisfies `validate_block_consistency`'s score/work band.
    fn mk(height: u64, parent: Hash, blue_score: u64, vrf: [u8; 32]) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(CB)
            .timestamp(1000)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new(vrf),
            })
            .transactions(vec![])
            .state_root(Hash::default())
            .blue_score(blue_score)
            .blue_work(citrate_consensus::types::blue_work_for_score(blue_score))
            .build_unhashed();
        b.header.block_hash = b.compute_hash();
        b
    }

    /// Admission with no applicator (v1 / storage-only), which is all these
    /// tests need — the applier is exercised in `canonical_apply`.
    fn harness() -> (
        BlockAdmission,
        Arc<StorageManager>,
        Arc<DagStore>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        let adm = BlockAdmission::new(storage.clone(), dag.clone(), ghostdag, None);
        (adm, storage, dag, dir)
    }

    /// Root of the test chain: parent == default and no merge parents, so
    /// `is_genesis()` holds and it is admitted unconditionally.
    fn root() -> Block {
        mk(1, Hash::default(), 0, [0x5A; 32])
    }

    fn fully_admitted(storage: &StorageManager, dag_has: bool, b: &Block) -> bool {
        storage.blocks.has_block(&b.header.block_hash).unwrap() && dag_has
    }

    #[tokio::test]
    async fn admits_a_fresh_block_into_both_stores() {
        let (adm, storage, dag, _d) = harness();
        let g = root();
        assert_eq!(
            adm.admit(&g).await,
            AdmitOutcome::Admitted {
                completed_partial: false
            }
        );
        assert!(fully_admitted(
            &storage,
            dag.has_block(&g.header.block_hash).await,
            &g
        ));
        // Idempotent: a second delivery is a no-op, not a second write.
        assert_eq!(adm.admit(&g).await, AdmitOutcome::AlreadyAdmitted);
    }

    /// THE LIVE WEDGE (planset §1.2/§1.3, quadrant Q3). `citrate-boot-3` was
    /// OOM-killed between the DAG write and the chain write at height 10944.
    ///
    /// Pre-D2 this was permanent: re-delivery hit `store_block` ->
    /// `Err(BlockExists)` -> `=> {}`, so `put_block` never ran. Admission must
    /// instead recognise the partial state and complete the chain write.
    #[tokio::test]
    async fn admit_completes_a_chain_write_interrupted_after_the_dag_write() {
        let (adm, storage, dag, _d) = harness();
        let g = root();
        adm.admit(&g).await;
        let b2 = mk(2, g.header.block_hash, 1, [0x5A; 32]);

        // Manufacture the exact post-crash state: DAG write committed, process
        // killed before the chain write.
        dag.store_block(b2.clone()).await.expect("dag write");
        assert!(dag.has_block(&b2.header.block_hash).await);
        assert!(
            !storage.blocks.has_block(&b2.header.block_hash).unwrap(),
            "chain store must have the hole"
        );

        // The trap that made this permanent: the DAG write is not retryable.
        assert!(
            matches!(
                dag.store_block(b2.clone()).await,
                Err(DagStoreError::BlockExists(_))
            ),
            "re-storing reports BlockExists — treating that as a no-op strands the chain write"
        );

        // Admission repairs it and says so.
        assert_eq!(
            adm.admit(&b2).await,
            AdmitOutcome::Admitted {
                completed_partial: true
            }
        );
        assert!(storage.blocks.has_block(&b2.header.block_hash).unwrap());

        // And the repair is what unblocks the drain: `drain_forward` walks the
        // CHAIN store's parent->children index, so the link must now exist.
        assert!(
            storage
                .blocks
                .get_children(&g.header.block_hash)
                .unwrap()
                .contains(&b2.header.block_hash),
            "the chain-store child link is what lets the applied tip advance"
        );
    }

    /// Mirror direction (quadrant Q1): the chain write landed and the process
    /// died before the DAG write. Equally permanent pre-D2, because both
    /// handlers skipped on a chain-store hit without consulting the DAG.
    #[tokio::test]
    async fn admit_completes_a_dag_write_interrupted_after_the_chain_write() {
        let (adm, storage, dag, _d) = harness();
        let g = root();
        adm.admit(&g).await;
        let b2 = mk(2, g.header.block_hash, 1, [0x5A; 32]);

        storage.blocks.put_block(&b2).expect("chain write");
        assert!(!dag.has_block(&b2.header.block_hash).await);

        assert_eq!(
            adm.admit(&b2).await,
            AdmitOutcome::Admitted {
                completed_partial: true
            }
        );
        assert!(dag.has_block(&b2.header.block_hash).await);

        // Which is what makes descendants admissible again.
        let b3 = mk(3, b2.header.block_hash, 2, [0x5A; 32]);
        assert_eq!(
            adm.admit(&b3).await,
            AdmitOutcome::Admitted {
                completed_partial: false
            }
        );
    }

    /// MUTATION / FAULT-POINT ENUMERATION (planset §3.2). The live bug is
    /// "crash at step k of admission", so every step boundary is enumerated —
    /// not sampled — and each must converge to fully-admitted.
    #[tokio::test]
    async fn every_admission_crash_point_converges() {
        #[derive(Debug, Clone, Copy)]
        enum FaultPoint {
            BeforeAnyWrite,
            AfterDagWrite,
            AfterChainWrite,
            AfterBothWrites,
        }

        for fp in [
            FaultPoint::BeforeAnyWrite,
            FaultPoint::AfterDagWrite,
            FaultPoint::AfterChainWrite,
            FaultPoint::AfterBothWrites,
        ] {
            let (adm, storage, dag, _d) = harness();
            let g = root();
            adm.admit(&g).await;
            let b2 = mk(2, g.header.block_hash, 1, [0x5A; 32]);
            let h = b2.header.block_hash;

            // Replay the writes that had landed before the kill.
            match fp {
                FaultPoint::BeforeAnyWrite => {}
                FaultPoint::AfterDagWrite => {
                    dag.store_block(b2.clone()).await.expect("dag");
                }
                FaultPoint::AfterChainWrite => {
                    storage.blocks.put_block(&b2).expect("chain");
                }
                FaultPoint::AfterBothWrites => {
                    dag.store_block(b2.clone()).await.expect("dag");
                    storage.blocks.put_block(&b2).expect("chain");
                }
            }

            // One delivery after restart must converge from ANY fault point.
            let out = adm.admit(&b2).await;
            assert!(
                matches!(
                    out,
                    AdmitOutcome::Admitted { .. } | AdmitOutcome::AlreadyAdmitted
                ),
                "fault point {fp:?}: unexpected {out:?}"
            );
            assert!(
                storage.blocks.has_block(&h).unwrap() && dag.has_block(&h).await,
                "fault point {fp:?}: did not converge to fully admitted"
            );
            // Convergence must also be stable, not oscillating.
            assert_eq!(
                adm.admit(&b2).await,
                AdmitOutcome::AlreadyAdmitted,
                "fault point {fp:?}: not stable on re-delivery"
            );
            // And the child link must be intact exactly once, so the drain
            // sees a unique linear extension.
            let children = storage.blocks.get_children(&g.header.block_hash).unwrap();
            assert_eq!(
                children.iter().filter(|c| **c == h).count(),
                1,
                "fault point {fp:?}: duplicate child link"
            );
        }
    }

    #[tokio::test]
    async fn defers_and_names_the_missing_parent() {
        let (adm, storage, dag, _d) = harness();
        let g = root();
        // b3's parent b2 is never admitted.
        let b2 = mk(2, g.header.block_hash, 1, [0x5A; 32]);
        let b3 = mk(3, b2.header.block_hash, 2, [0x5A; 32]);
        adm.admit(&g).await;

        assert_eq!(
            adm.admit(&b3).await,
            AdmitOutcome::Deferred {
                missing_parent: b2.header.block_hash
            },
            "the missing parent must be NAMED — the pre-D2 handler discarded it"
        );
        // Nothing was written on the deferred path.
        assert!(!storage.blocks.has_block(&b3.header.block_hash).unwrap());
        assert!(!dag.has_block(&b3.header.block_hash).await);
    }

    /// The startup reconciler (D2.4): a node carrying a pre-D2 hole has no
    /// guarantee the missing block is ever offered again, so boot must repair
    /// it. This models `citrate-boot-3` exactly: applied tip at the block
    /// below the hole, chain store missing one height, DAG store holding it,
    /// and higher blocks stored above the hole.
    #[tokio::test]
    async fn reconcile_repairs_the_boot3_hole_and_reports_it() {
        let (adm, storage, dag, _d) = harness();
        let g = root();
        adm.admit(&g).await;

        let b2 = mk(2, g.header.block_hash, 1, [0x5A; 32]);
        let b3 = mk(3, b2.header.block_hash, 2, [0x5A; 32]);

        // The hole: b2 in the DAG only (the interrupted admission).
        dag.store_block(b2.clone()).await.expect("dag");
        // b3 admitted normally, so it sits ABOVE the hole (stored height
        // climbs past a frozen applied tip — the live signature).
        adm.admit(&b3).await;
        storage
            .blocks
            .put_applied_tip(&g.header.block_hash, 1)
            .expect("applied tip");

        assert!(!storage.blocks.has_block(&b2.header.block_hash).unwrap());

        let report = adm.reconcile().await;
        assert!(report.repaired_anything());
        assert_eq!(
            report.chain_writes_completed,
            vec![2],
            "height 2 was the hole"
        );
        assert!(storage.blocks.has_block(&b2.header.block_hash).unwrap());
        // The chain is now contiguous, so a drain can cross the old hole.
        assert!(storage
            .blocks
            .get_children(&g.header.block_hash)
            .unwrap()
            .contains(&b2.header.block_hash));
        assert!(storage
            .blocks
            .get_children(&b2.header.block_hash)
            .unwrap()
            .contains(&b3.header.block_hash));
    }

    #[tokio::test]
    async fn reconcile_is_a_noop_on_a_healthy_node() {
        let (adm, storage, _dag, _d) = harness();
        let g = root();
        adm.admit(&g).await;
        let b2 = mk(2, g.header.block_hash, 1, [0x5A; 32]);
        adm.admit(&b2).await;
        storage
            .blocks
            .put_applied_tip(&b2.header.block_hash, 2)
            .expect("applied tip");

        let report = adm.reconcile().await;
        assert!(!report.repaired_anything());
        assert!(report.gaps.is_empty());
    }

    /// A chain-only block above the applied tip makes every descendant
    /// inadmissible; reconcile must admit it into the DAG (mirror direction).
    #[tokio::test]
    async fn reconcile_admits_chain_only_blocks_into_the_dag() {
        let (adm, storage, dag, _d) = harness();
        let g = root();
        adm.admit(&g).await;
        let b2 = mk(2, g.header.block_hash, 1, [0x5A; 32]);

        storage.blocks.put_block(&b2).expect("chain only");
        storage
            .blocks
            .put_applied_tip(&g.header.block_hash, 1)
            .expect("applied tip");
        assert!(!dag.has_block(&b2.header.block_hash).await);

        let report = adm.reconcile().await;
        assert_eq!(report.dag_writes_completed, vec![2]);
        assert!(dag.has_block(&b2.header.block_hash).await);
    }
}
