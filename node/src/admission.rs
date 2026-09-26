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

/// PBA-R2: verify a block's body against its header under the hardened
/// validity rules. A no-op below the activation height (legacy validity is
/// never re-judged). Every path that stores a block calls this first.
pub(crate) fn verify_block_body(
    hardening: citrate_consensus::hardening::PbaHardening,
    block: &Block,
) -> Result<(), String> {
    let height = block.header.height;
    if !hardening.active_at(height) {
        return Ok(());
    }
    if !block.verify_hash_for(hardening) {
        return Err(format!("body: block hash mismatch @ {height}"));
    }
    // PBA-L1b-002: the root must commit to the transactions' full contents.
    let expected = citrate_consensus::tx_auth::tx_root_for_height(
        hardening,
        height,
        &block.transactions,
    );
    if block.tx_root != expected {
        return Err(format!(
            "body: tx_root {} does not commit to the block's transactions (expected {}) \
             — rewritten body (PBA-L1b-002)",
            block.tx_root, expected
        ));
    }
    // PBA-L1b-001: every transaction authenticated from its contents (never
    // the wire `ecdsa_verified` flag) and carrying its canonical id, so a
    // forged-sender body is never stored. (Chain-id binding is enforced by
    // the executor on apply, which knows the chain id.) Native signatures must
    // use the chain-bound (v2) digest here.
    for (i, tx) in block.transactions.iter().enumerate() {
        if let Err(e) = citrate_consensus::tx_auth::authenticate_for_block(tx) {
            return Err(format!("body: tx #{i} ({}): {e} (PBA-L1b-001)", tx.hash));
        }
    }
    Ok(())
}

/// The sidecar rule for a received block (see `admit`). `Ok(None)` = store it
/// as received; `Ok(Some(b))` = store `b`, the block with its uncommitted
/// sidecar fields reset.
pub(crate) fn sidecar_ingest(
    hardening: citrate_consensus::hardening::PbaHardening,
    block: &Block,
) -> Result<Option<Block>, String> {
    let height = block.header.height;
    if height == 0 {
        return Ok(None);
    }
    if !block.verify_hash_for(hardening) {
        return Err(format!("block hash does not recompute @ {height}"));
    }
    if hardening.active_at(height) || citrate_consensus::block_sidecars::is_canonical_empty(block) {
        return Ok(None);
    }
    let mut b = block.clone();
    citrate_consensus::block_sidecars::strip(&mut b);
    Ok(Some(b))
}

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

        // PBA-R2 body gate, before ANY write. From the activation height a
        // block's body must verify against its header here, on every ingest
        // path, so a relayed block with a rewritten body is never persisted
        // under the honest hash (PBA-L1b-002: that persisted copy used to wedge
        // the follower, because the honest copy was then `AlreadyAdmitted`).
        if let Err(why) = verify_block_body(self.ghostdag.pba_hardening(), block) {
            return AdmitOutcome::Rejected(why);
        }

        // Sidecar fields (`block_sidecars`), at every height. The stored copy
        // must be the one the hash commits to: a block whose hash does not
        // recompute is never written, and below the activation height, where
        // the hash does not cover the sidecars, they are reset before storage
        // so every copy of a block is stored identically.
        // Genesis (height 0) is built locally and never re-judged.
        let stripped;
        let block: &Block = match sidecar_ingest(self.ghostdag.pba_hardening(), block) {
            Ok(None) => block,
            Ok(Some(b)) => {
                stripped = b;
                &stripped
            }
            Err(why) => return AdmitOutcome::Rejected(why),
        };

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

/// CHAIN-B-A005: hard cap on the count of buffered orphan (deferred) blocks.
pub const MAX_ORPHAN_BLOCKS: usize = 20_000;

/// CHAIN-B-A005: hard cap on the SERIALIZED bytes of the orphan buffer. The
/// pre-fix code bounded only by count (20_000 × up to ~1 MiB ≈ 20 GB of heap).
pub const MAX_ORPHAN_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// CHAIN-B-A005: de-duplicate and bound the orphan (deferred-block) buffer.
///
/// Pre-fix the buffer was de-duplicated with `sort_by_key(height)` +
/// `dedup_by_key(hash)`, which only collapses *adjacent* equal hashes — an
/// attacker defeats it by interleaving two copies of a block around a sibling
/// at the same height, so both survive. And it was bounded only by COUNT, so
/// 20_000 near-1-MiB blocks could retain ~20 GB.
///
/// This helper de-duplicates by a `HashSet<Hash>` (interleaving-proof) and
/// bounds by BOTH count and serialized bytes, keeping the lowest-height blocks
/// first (those are the ones whose parents are most likely to arrive next and
/// unblock them).
pub fn bound_orphan_buffer(blocks: Vec<Block>) -> Vec<Block> {
    use std::collections::HashSet;

    let mut seen: HashSet<Hash> = HashSet::with_capacity(blocks.len());
    let mut deduped: Vec<Block> = Vec::with_capacity(blocks.len());
    for b in blocks {
        if seen.insert(b.header.block_hash) {
            deduped.push(b);
        }
    }

    // Lowest-height first.
    deduped.sort_by_key(|b| b.header.height);

    let mut total_bytes: usize = 0;
    let mut out: Vec<Block> = Vec::with_capacity(deduped.len().min(MAX_ORPHAN_BLOCKS));
    for b in deduped {
        if out.len() >= MAX_ORPHAN_BLOCKS {
            break;
        }
        let sz = bincode::serialized_size(&b).unwrap_or(u64::MAX) as usize;
        if total_bytes.saturating_add(sz) > MAX_ORPHAN_BYTES {
            break;
        }
        total_bytes += sz;
        out.push(b);
    }
    out
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

    /// Root of the test chain: the height-0 genesis (parentless, no merge
    /// parents), so `is_configured_genesis()` holds and it is admitted. (SECREM-A001
    /// RC-8: was height 1 — a shape-only pseudo-genesis — before genesis became an
    /// identity bound to height 0.)
    fn root() -> Block {
        mk(0, Hash::default(), 0, [0x5A; 32])
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
        let b2 = mk(1, g.header.block_hash, 1, [0x5A; 32]);

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
        let b2 = mk(1, g.header.block_hash, 1, [0x5A; 32]);

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
        let b3 = mk(2, b2.header.block_hash, 2, [0x5A; 32]);
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
            let b2 = mk(1, g.header.block_hash, 1, [0x5A; 32]);
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
        let b2 = mk(1, g.header.block_hash, 1, [0x5A; 32]);
        let b3 = mk(2, b2.header.block_hash, 2, [0x5A; 32]);
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

        let b2 = mk(1, g.header.block_hash, 1, [0x5A; 32]);
        let b3 = mk(2, b2.header.block_hash, 2, [0x5A; 32]);

        // The hole: b2 in the DAG only (the interrupted admission).
        dag.store_block(b2.clone()).await.expect("dag");
        // b3 admitted normally, so it sits ABOVE the hole (stored height
        // climbs past a frozen applied tip — the live signature).
        adm.admit(&b3).await;
        storage
            .blocks
            .put_applied_tip(&g.header.block_hash, 0)
            .expect("applied tip");

        assert!(!storage.blocks.has_block(&b2.header.block_hash).unwrap());

        let report = adm.reconcile().await;
        assert!(report.repaired_anything());
        assert_eq!(
            report.chain_writes_completed,
            vec![1],
            "height 1 was the hole"
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
        let b2 = mk(1, g.header.block_hash, 1, [0x5A; 32]);
        adm.admit(&b2).await;
        storage
            .blocks
            .put_applied_tip(&b2.header.block_hash, 1)
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
        let b2 = mk(1, g.header.block_hash, 1, [0x5A; 32]);

        storage.blocks.put_block(&b2).expect("chain only");
        storage
            .blocks
            .put_applied_tip(&g.header.block_hash, 0)
            .expect("applied tip");
        assert!(!dag.has_block(&b2.header.block_hash).await);

        let report = adm.reconcile().await;
        assert_eq!(report.dag_writes_completed, vec![1]);
        assert!(dag.has_block(&b2.header.block_hash).await);
    }

    /// CHAIN-B-A005 tripwire: the orphan buffer must de-duplicate by HASH even
    /// when duplicate copies are interleaved around a same-height sibling. The
    /// pre-fix `sort_by_key(height) + dedup_by_key(hash)` only collapses
    /// *adjacent* equal hashes, so two copies of a block separated by a sibling
    /// at the same height both survived — an attacker defeats the dedup by
    /// interleaving. RED with the adjacency dedup; GREEN with the HashSet dedup.
    #[test]
    fn orphan_buffer_dedups_by_hash_despite_interleaving() {
        let a = mk(5, Hash::new([1; 32]), 5, [0xA1; 32]);
        let b = mk(5, Hash::new([2; 32]), 5, [0xB2; 32]); // same height, different hash
        assert_ne!(a.header.block_hash, b.header.block_hash);

        // Interleave: A, B, A  — all height 5. A height sort leaves them in
        // stable order [A, B, A], so adjacency dedup keeps both A's.
        let input = vec![a.clone(), b.clone(), a.clone()];
        let out = bound_orphan_buffer(input);

        assert_eq!(out.len(), 2, "interleaved duplicate must be collapsed");
        let mut hashes: Vec<_> = out.iter().map(|x| x.header.block_hash).collect();
        hashes.sort();
        let mut want = vec![a.header.block_hash, b.header.block_hash];
        want.sort();
        assert_eq!(hashes, want);
    }

    /// CHAIN-B-A005 tripwire: the orphan buffer is bounded by COUNT (and by
    /// bytes — asserted via the count cap being ≤ MAX_ORPHAN_BLOCKS). Pre-fix
    /// only a by-count truncate existed and the byte size was unbounded.
    #[test]
    fn orphan_buffer_is_count_bounded() {
        // A handful over the cap; lowest-height-first retention.
        let over = 8usize;
        let mut input = Vec::with_capacity(MAX_ORPHAN_BLOCKS + over);
        for i in 0..(MAX_ORPHAN_BLOCKS + over) as u64 {
            let mut vrf = [0u8; 32];
            vrf[..8].copy_from_slice(&i.to_le_bytes());
            // distinct parent per block → distinct hash
            let mut parent = [0u8; 32];
            parent[..8].copy_from_slice(&i.to_le_bytes());
            input.push(mk(i + 1, Hash::new(parent), i, vrf));
        }
        let out = bound_orphan_buffer(input);
        assert!(
            out.len() <= MAX_ORPHAN_BLOCKS,
            "orphan buffer must be count-bounded; got {}",
            out.len()
        );
        // Serialized footprint must be within the byte cap.
        let bytes: usize = out
            .iter()
            .map(|b| bincode::serialized_size(b).unwrap_or(u64::MAX) as usize)
            .sum();
        assert!(
            bytes <= MAX_ORPHAN_BYTES,
            "orphan buffer must be byte-bounded; got {} bytes",
            bytes
        );
    }
}

/// PBA-L1b-002 / PBA-L1b-001 at the node's single admission entry point.
///
/// The audit's node PoC (`pba_l1b_002_node_wedge_test.rs`) showed the wedge:
/// a relayed block with a rewritten body was PERSISTED under the honest hash,
/// failed on state root, and the honest copy was then short-circuited as
/// `AlreadyAdmitted`. After activation admission verifies the body (hash,
/// content-bound tx_root, every tx's signature + canonical id) BEFORE any
/// write, so a bad body is never stored and the honest copy is admitted.
#[cfg(test)]
mod pba_r2_admission {
    use super::*;
    use citrate_consensus::crypto;
    use citrate_consensus::hardening::PbaHardening;
    use citrate_consensus::tx_auth::{native_tx_id, tx_root_for_height};
    use citrate_consensus::types::{BlockBuilder, GhostDagParams, PublicKey, Transaction, VrfProof};
    use citrate_storage::pruning::PruningConfig;

    fn harness(
        hardening: PbaHardening,
    ) -> (BlockAdmission, Arc<StorageManager>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(
            GhostDag::new(GhostDagParams::default(), dag.clone()).with_pba_hardening(hardening),
        );
        (BlockAdmission::new(storage.clone(), dag, ghostdag, None), storage, dir)
    }

    fn signed_native(seed: u8, nonce: u64, value: u128) -> Transaction {
        let sk = crypto::Ed25519SigningKey::from_bytes(&[seed; 32]);
        let mut tx = Transaction {
            nonce,
            to: Some(PublicKey::new([0xB0; 32])),
            value,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            chain_id: Some(40204),
            ..Default::default()
        };
        crypto::sign_transaction_v2(&mut tx, &sk).unwrap();
        tx.hash = native_tx_id(&tx);
        tx
    }

    fn block(
        hardening: PbaHardening,
        height: u64,
        parent: Hash,
        txs: Vec<Transaction>,
    ) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase([0x33; 20])
            .timestamp(1000)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(txs)
            .state_root(Hash::default())
            .blue_score(height)
            .blue_work(citrate_consensus::types::blue_work_for_score(height))
            .build_unhashed();
        b.tx_root = tx_root_for_height(hardening, height, &b.transactions);
        b.header.block_hash = b.compute_hash();
        b
    }

    #[tokio::test]
    async fn pba_l1b_002_rewritten_body_never_stored_honest_copy_admitted() {
        let pba = PbaHardening::at(0);
        let (adm, storage, _d) = harness(pba);
        let g = block(pba, 0, Hash::default(), vec![]);
        assert!(matches!(adm.admit(&g).await, AdmitOutcome::Admitted { .. }));

        let honest = block(pba, 1, g.header.block_hash, vec![signed_native(1, 0, 1_000)]);
        let mut forged = honest.clone();
        forged.transactions[0].value = 2_000; // body rewritten, tx.hash untouched
        assert_eq!(forged.header.block_hash, honest.header.block_hash);

        let r = adm.admit(&forged).await;
        assert!(
            matches!(r, AdmitOutcome::Rejected(_)),
            "PBA-L1b-002: a rewritten body must be rejected, got {r:?}"
        );
        assert!(
            !storage.blocks.has_block(&honest.header.block_hash).unwrap(),
            "PBA-L1b-002: nothing may be persisted under the honest hash"
        );
        assert!(
            matches!(adm.admit(&honest).await, AdmitOutcome::Admitted { .. }),
            "the honest copy is admitted after the tampered one was seen"
        );
        let stored = storage.blocks.get_block(&honest.header.block_hash).unwrap().unwrap();
        assert_eq!(stored.transactions[0].value, 1_000, "the honest body is what is stored");
    }

    /// PBA-L1b-001: a forged-sender tx (EVM-shaped victim, no signature, the
    /// wire `ecdsa_verified` flag set) makes the block inadmissible — it is
    /// never stored.
    #[tokio::test]
    async fn pba_l1b_001_forged_sender_block_never_stored() {
        let pba = PbaHardening::at(0);
        let (adm, storage, _d) = harness(pba);
        let g = block(pba, 0, Hash::default(), vec![]);
        adm.admit(&g).await;
        let mut victim = [0u8; 32];
        victim[..20].copy_from_slice(&[0xAA; 20]);
        let forged = Transaction {
            hash: Hash::new([0x42; 32]),
            from: PublicKey::new(victim),
            to: Some(PublicKey::new([0xBB; 32])),
            value: 1_000,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            chain_id: Some(40204),
            ecdsa_verified: true,
            ..Default::default()
        };
        let b = block(pba, 1, g.header.block_hash, vec![forged]);
        let r = adm.admit(&b).await;
        assert!(matches!(r, AdmitOutcome::Rejected(ref why) if why.contains("PBA-L1b-001")), "{r:?}");
        assert!(!storage.blocks.has_block(&b.header.block_hash).unwrap());
    }

    /// Tripwire: the body gate runs before either store is written.
    #[test]
    fn pba_r2_tripwire_body_gate_precedes_every_write() {
        let src = include_str!("admission.rs");
        let admit = src.find("pub async fn admit(&self, block: &Block)").expect("admit");
        let body = &src[admit..];
        let gate = body.find("verify_block_body(self.ghostdag.pba_hardening(), block)").expect(
            "PBA-R2: admit must run verify_block_body",
        );
        assert!(gate < body.find("self.dag_store.store_block(").expect("dag write"));
        assert!(gate < body.find("self.storage.blocks.put_block(").expect("chain write"));
    }

    #[tokio::test]
    async fn pba_l1b_002_before_activation_admission_is_unchanged() {
        let pba = PbaHardening::off();
        let (adm, _storage, _d) = harness(pba);
        let g = block(pba, 0, Hash::default(), vec![]);
        adm.admit(&g).await;
        let honest = block(pba, 1, g.header.block_hash, vec![signed_native(1, 0, 1_000)]);
        let mut forged = honest.clone();
        forged.transactions[0].value = 2_000;
        // Legacy validity (documented residual until activation).
        assert!(matches!(adm.admit(&forged).await, AdmitOutcome::Admitted { .. }));
    }
}

/// Native signature digest and block sidecar fields at the activation height.
#[cfg(test)]
mod fold_activation {
    use super::*;
    use citrate_consensus::crypto;
    use citrate_consensus::hardening::PbaHardening;
    use citrate_consensus::native_sig::{sign_native, NativeSigVersion};
    use citrate_consensus::tx_auth::{native_tx_id, tx_root_for_height};
    use citrate_consensus::types::{
        BlockBuilder, EmbeddedModel, GhostDagParams, ModelId, ModelMetadata, ModelType, PublicKey,
        RequiredModel, Transaction, VrfProof,
    };
    use citrate_storage::pruning::PruningConfig;

    const H: u64 = 2;

    fn harness(
        hardening: PbaHardening,
    ) -> (BlockAdmission, Arc<StorageManager>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(
            GhostDag::new(GhostDagParams::default(), dag.clone()).with_pba_hardening(hardening),
        );
        (
            BlockAdmission::new(storage.clone(), dag, ghostdag, None),
            storage,
            dir,
        )
    }

    /// A native tx signed with `version` for `signed_chain`, then labelled
    /// `label_chain`.
    fn native_tx(
        seed: u8,
        nonce: u64,
        version: NativeSigVersion,
        signed_chain: u64,
        label_chain: u64,
    ) -> Transaction {
        let sk = crypto::Ed25519SigningKey::from_bytes(&[seed; 32]);
        let mut tx = Transaction {
            nonce,
            to: Some(PublicKey::new([0xB0; 32])),
            value: 1_000,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            chain_id: Some(signed_chain),
            ..Default::default()
        };
        sign_native(&mut tx, &sk, version).unwrap();
        tx.chain_id = Some(label_chain);
        tx.hash = native_tx_id(&tx);
        tx
    }

    fn block(pba: PbaHardening, height: u64, parent: Hash, txs: Vec<Transaction>) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase([0x33; 20])
            .timestamp(1000 + height)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(txs)
            .state_root(Hash::default())
            .blue_score(height)
            .blue_work(citrate_consensus::types::blue_work_for_score(height))
            .build_unhashed();
        b.tx_root = tx_root_for_height(pba, height, &b.transactions);
        b.header.block_hash = b.compute_hash_for(pba);
        b
    }

    /// Chain of empty blocks 0..=to under `pba`, all admitted. Returns the tip.
    async fn chain_to(adm: &BlockAdmission, pba: PbaHardening, to: u64) -> Block {
        let mut prev = block(pba, 0, Hash::default(), vec![]);
        assert!(matches!(
            adm.admit(&prev).await,
            AdmitOutcome::Admitted { .. }
        ));
        for h in 1..=to {
            let b = block(pba, h, prev.header.block_hash, vec![]);
            let r = adm.admit(&b).await;
            assert!(
                matches!(r, AdmitOutcome::Admitted { .. }),
                "height {h}: {r:?}"
            );
            prev = b;
        }
        prev
    }

    fn fill_body_fields(b: &mut Block) {
        b.learning_embedding = Some(vec![1.0f32; 100_000]);
        b.learning_confidence = Some(vec![0.5f32; 64]);
        b.ghostdag_params.k = 99;
        b.gradient_commitment = Some([7; 32]);
        b.learning_root = Hash::new([9; 32]);
        b.embedded_models = vec![EmbeddedModel {
            model_id: ModelId("m".into()),
            model_type: ModelType::TinyLLM,
            weights_sha256: Hash::new([1; 32]),
            metadata: ModelMetadata {
                name: "m".into(),
                version: "1".into(),
                context_length: 1,
                // `Some`: the chain store's bincode round-trip needs both
                // `skip_serializing_if` fields present.
                embedding_dim: Some(8),
                license: "x".into(),
                framework: Some("f".into()),
            },
        }];
        b.required_pins = vec![RequiredModel {
            model_id: ModelId("m".into()),
            ipfs_cid: "bafy".into(),
            sha256_hash: Hash::new([2; 32]),
            size_bytes: 1,
            must_pin: true,
            slash_penalty: 1,
            grace_period_hours: 1,
        }];
    }

    fn assert_no_sidecars(b: &Block) {
        assert!(
            citrate_consensus::block_sidecars::is_canonical_empty(b),
            "stored copy carries sidecars"
        );
    }

    // ---- native signature digest -----------------------------------------

    /// A V1 native tx signed for another chain and labelled with this one is
    /// admitted below H (legacy validity is never re-judged) and rejected at
    /// and above H.
    #[tokio::test]
    async fn native_tx_signed_for_another_chain_accepted_below_h_rejected_from_h() {
        let pba = PbaHardening::at(H);
        let (adm, storage, _d) = harness(pba);
        let tip = chain_to(&adm, pba, H - 2).await;

        let below = block(
            pba,
            H - 1,
            tip.header.block_hash,
            vec![native_tx(1, 0, NativeSigVersion::V1, 1337, 40204)],
        );
        let r = adm.admit(&below).await;
        assert!(matches!(r, AdmitOutcome::Admitted { .. }), "below H: {r:?}");

        let at = block(
            pba,
            H,
            below.header.block_hash,
            vec![native_tx(1, 1, NativeSigVersion::V1, 1337, 40204)],
        );
        let r = adm.admit(&at).await;
        assert!(
            matches!(r, AdmitOutcome::Rejected(ref why) if why.contains("legacy digest")),
            "at H: {r:?}"
        );
        assert!(!storage.blocks.has_block(&at.header.block_hash).unwrap());

        // Also a V1 tx that was genuinely signed for this chain.
        let at_own = block(
            pba,
            H,
            below.header.block_hash,
            vec![native_tx(2, 0, NativeSigVersion::V1, 40204, 40204)],
        );
        assert!(matches!(
            adm.admit(&at_own).await,
            AdmitOutcome::Rejected(_)
        ));
    }

    /// V2 native txs are admitted at and above H, and V2 is also valid below.
    #[tokio::test]
    async fn v2_native_tx_accepted_at_and_above_h() {
        let pba = PbaHardening::at(H);
        let (adm, _s, _d) = harness(pba);
        let tip = chain_to(&adm, pba, H - 2).await;
        let below = block(
            pba,
            H - 1,
            tip.header.block_hash,
            vec![native_tx(3, 0, NativeSigVersion::V2, 40204, 40204)],
        );
        assert!(matches!(
            adm.admit(&below).await,
            AdmitOutcome::Admitted { .. }
        ));
        let at = block(
            pba,
            H,
            below.header.block_hash,
            vec![native_tx(3, 1, NativeSigVersion::V2, 40204, 40204)],
        );
        let r = adm.admit(&at).await;
        assert!(matches!(r, AdmitOutcome::Admitted { .. }), "{r:?}");
        let above = block(
            pba,
            H + 1,
            at.header.block_hash,
            vec![native_tx(3, 2, NativeSigVersion::V2, 40204, 40204)],
        );
        assert!(matches!(
            adm.admit(&above).await,
            AdmitOutcome::Admitted { .. }
        ));
    }

    /// A V2 tx carries its chain in the signature: changing its label breaks the
    /// signature, and one left on its own chain id is refused by the chain
    /// binding.
    #[test]
    fn v2_with_another_chain_id_rejected() {
        use citrate_consensus::tx_auth::{verify_for_block, TxAuthError};
        let other_label = native_tx(4, 0, NativeSigVersion::V2, 1337, 40204);
        assert_eq!(
            verify_for_block(&other_label, 40204),
            Err(TxAuthError::BadSignature)
        );
        let other_chain = native_tx(4, 0, NativeSigVersion::V2, 1337, 1337);
        assert!(matches!(
            verify_for_block(&other_chain, 40204),
            Err(TxAuthError::WrongChainId {
                expected: 40204,
                got: Some(1337)
            })
        ));
        let ok = native_tx(4, 0, NativeSigVersion::V2, 40204, 40204);
        assert_eq!(verify_for_block(&ok, 40204), Ok(ok.hash));
        let v1 = native_tx(4, 0, NativeSigVersion::V1, 40204, 40204);
        assert_eq!(
            verify_for_block(&v1, 40204),
            Err(TxAuthError::LegacyNativeSignature)
        );
    }

    // ---- block sidecars ----------------------------------------------------

    /// At and above H the hash commits to the sidecars: a filled copy is
    /// rejected (never stored) and the honest copy is admitted afterwards.
    #[tokio::test]
    async fn copy_with_other_body_fields_rejected_from_h_honest_admitted_after() {
        for pba in [
            PbaHardening::at(0),
            PbaHardening::at(1),
            PbaHardening::at(H),
        ] {
            let (adm, storage, _d) = harness(pba);
            let tip = chain_to(&adm, pba, H - 1).await;
            let honest = block(pba, H, tip.header.block_hash, vec![]);
            let mut filled = honest.clone();
            fill_body_fields(&mut filled);
            assert_eq!(filled.header.block_hash, honest.header.block_hash);
            let r = adm.admit(&filled).await;
            assert!(matches!(r, AdmitOutcome::Rejected(_)), "{pba:?}: {r:?}");
            assert!(!storage.blocks.has_block(&honest.header.block_hash).unwrap());
            let r = adm.admit(&honest).await;
            assert!(matches!(r, AdmitOutcome::Admitted { .. }), "{pba:?}: {r:?}");
            let stored = storage
                .blocks
                .get_block(&honest.header.block_hash)
                .unwrap()
                .unwrap();
            assert_no_sidecars(&stored);
        }
    }

    /// Each sidecar field on its own changes the hash at H.
    #[test]
    fn every_sidecar_field_is_committed_from_h() {
        let pba = PbaHardening::at(H);
        let honest = block(pba, H, Hash::new([1; 32]), vec![]);
        type Mutation = fn(&mut Block);
        let muts: [(&str, Mutation); 8] = [
            ("learning_embedding", |b| {
                b.learning_embedding = Some(vec![])
            }),
            ("learning_confidence", |b| {
                b.learning_confidence = Some(vec![0.0])
            }),
            ("ghostdag_params", |b| b.ghostdag_params.finality_depth += 1),
            ("embedded_models", |b| {
                let mut p = b.clone();
                fill_body_fields(&mut p);
                b.embedded_models = p.embedded_models;
            }),
            ("required_pins", |b| {
                let mut p = b.clone();
                fill_body_fields(&mut p);
                b.required_pins = p.required_pins;
            }),
            ("gradient_commitment", |b| {
                b.gradient_commitment = Some([0; 32])
            }),
            ("learning_root", |b| b.learning_root = Hash::new([3; 32])),
            ("ghostdag_params.k", |b| b.ghostdag_params.k = 0),
        ];
        for (name, m) in muts {
            let mut b = honest.clone();
            m(&mut b);
            assert!(!b.verify_hash_for(pba), "{name} must be committed at H");
            // Below H: the legacy hash ignores it.
            let below = PbaHardening::at(H + 1);
            let mut lb = block(below, H, Hash::new([1; 32]), vec![]);
            m(&mut lb);
            assert!(
                lb.verify_hash_for(below),
                "{name} must not change the legacy hash"
            );
        }
    }

    /// Below H (or with no activation), the filled copy keeps the honest hash
    /// but is stored stripped, so the honest content is what the node holds.
    #[tokio::test]
    async fn copy_with_body_fields_below_h_is_stored_reset() {
        for pba in [PbaHardening::off(), PbaHardening::at(H + 1)] {
            let (adm, storage, _d) = harness(pba);
            let tip = chain_to(&adm, pba, H - 1).await;
            let honest = block(pba, H, tip.header.block_hash, vec![]);
            let mut filled = honest.clone();
            fill_body_fields(&mut filled);
            assert!(
                filled.verify_hash_for(pba),
                "legacy hash does not cover sidecars"
            );
            let r = adm.admit(&filled).await;
            assert!(matches!(r, AdmitOutcome::Admitted { .. }), "{pba:?}: {r:?}");
            let stored = storage
                .blocks
                .get_block(&honest.header.block_hash)
                .unwrap()
                .unwrap();
            assert_no_sidecars(&stored);
            assert_eq!(adm.admit(&honest).await, AdmitOutcome::AlreadyAdmitted);
        }
    }

    /// A block whose hash does not recompute is never stored, below H too.
    #[tokio::test]
    async fn hash_mismatch_never_stored_at_any_height() {
        for pba in [
            PbaHardening::off(),
            PbaHardening::at(H + 1),
            PbaHardening::at(0),
        ] {
            let (adm, storage, _d) = harness(pba);
            let tip = chain_to(&adm, pba, H - 1).await;
            let mut b = block(pba, H, tip.header.block_hash, vec![]);
            b.state_root = Hash::new([0xEE; 32]);
            let r = adm.admit(&b).await;
            assert!(matches!(r, AdmitOutcome::Rejected(_)), "{pba:?}: {r:?}");
            assert!(!storage.blocks.has_block(&b.header.block_hash).unwrap());
        }
    }

    /// Parity below H: the hash of every block is the legacy one, with or
    /// without sidecars. At and above H an honest block (canonical-empty
    /// sidecars) also keeps its legacy hash.
    #[test]
    fn hash_parity_below_h_and_for_honest_blocks() {
        let mut b = block(PbaHardening::off(), H, Hash::new([4; 32]), vec![]);
        let legacy = b.compute_hash_for(PbaHardening::off());
        assert_eq!(b.compute_hash_for(PbaHardening::at(H + 1)), legacy);
        assert_eq!(
            b.compute_hash_for(PbaHardening::at(H)),
            legacy,
            "honest block at H"
        );
        fill_body_fields(&mut b);
        let legacy_filled = b.compute_hash_for(PbaHardening::off());
        assert_eq!(legacy_filled, legacy, "legacy hash ignores sidecars");
        assert_eq!(b.compute_hash_for(PbaHardening::at(H + 1)), legacy);
        assert_ne!(b.compute_hash_for(PbaHardening::at(H)), legacy);
        // Genesis is never re-judged.
        let mut g = block(PbaHardening::off(), 0, Hash::default(), vec![]);
        fill_body_fields(&mut g);
        assert_eq!(
            g.compute_hash_for(PbaHardening::at(0)),
            g.compute_hash_for(PbaHardening::off())
        );
    }

    /// Genesis carries its model sidecars and is admitted and stored as is.
    #[tokio::test]
    async fn genesis_sidecars_never_stripped() {
        let pba = PbaHardening::off();
        let (adm, storage, _d) = harness(pba);
        let mut g = block(pba, 0, Hash::default(), vec![]);
        fill_body_fields(&mut g);
        g.header.block_hash = g.compute_hash_for(pba);
        assert!(matches!(adm.admit(&g).await, AdmitOutcome::Admitted { .. }));
        let stored = storage
            .blocks
            .get_block(&g.header.block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(stored.required_pins.len(), 1);
        assert_eq!(stored.embedded_models.len(), 1);
    }

    // ---- rejoin ------------------------------------------------------------

    /// A node that upgrades late holds post-H blocks it admitted under the old
    /// rules. The start-up rejoin check re-runs `verify_block_body` on every
    /// stored block at or above H (and `verify_for_block` per tx); both new
    /// rules must make such blocks fail it, so they are purged and resynced.
    #[tokio::test]
    async fn late_upgrade_stored_post_h_blocks_fail_the_body_rules() {
        let old = PbaHardening::off();
        let (adm, storage, _d) = harness(old);
        let tip = chain_to(&adm, old, H - 1).await;
        // (a) A V1 native tx at H, admitted by the old release.
        let mut v1_block = block(
            old,
            H,
            tip.header.block_hash,
            vec![native_tx(5, 0, NativeSigVersion::V1, 40204, 40204)],
        );
        // An old-release producer's tx_root at H is the legacy one; model the
        // block as the new rules see it with a v2 root so only the signature
        // rule decides.
        let new = PbaHardening::at(H);
        v1_block.tx_root = tx_root_for_height(new, H, &v1_block.transactions);
        v1_block.header.block_hash = v1_block.compute_hash_for(new);
        let r = verify_block_body(new, &v1_block);
        assert!(
            matches!(r, Err(ref why) if why.contains("legacy digest")),
            "{r:?}"
        );
        assert!(
            citrate_consensus::tx_auth::verify_for_block(&v1_block.transactions[0], 40204).is_err()
        );

        // (b) An old-release checkpoint block at H carrying a learning root,
        // hashed without it.
        let mut cp = block(old, H, tip.header.block_hash, vec![]);
        cp.learning_root = Hash::new([0xC0; 32]);
        cp.tx_root = tx_root_for_height(new, H, &cp.transactions);
        cp.header.block_hash = cp.compute_hash_for(old);
        assert!(matches!(
            adm.admit(&cp).await,
            AdmitOutcome::Admitted { .. }
        ));
        let r = verify_block_body(new, &cp);
        assert!(
            matches!(r, Err(ref why) if why.contains("hash mismatch")),
            "{r:?}"
        );
        // The same block from an upgraded producer is valid.
        let mut good = cp.clone();
        good.header.block_hash = good.compute_hash_for(new);
        assert!(verify_block_body(new, &good).is_ok());
        drop(storage);
    }

    /// Tripwire: the sidecar rule runs before either store is written.
    #[test]
    fn tripwire_sidecar_rule_precedes_every_write() {
        let src = include_str!("admission.rs");
        let admit = src
            .find("pub async fn admit(&self, block: &Block)")
            .expect("admit");
        let body = &src[admit..];
        let gate = body
            .find("sidecar_ingest(self.ghostdag.pba_hardening(), block)")
            .expect("admit must run sidecar_ingest");
        assert!(gate < body.find("self.dag_store.store_block(").expect("dag write"));
        assert!(
            gate < body
                .find("self.storage.blocks.put_block(")
                .expect("chain write")
        );
    }

    fn model(id: &str, dim: Option<u32>, framework: Option<&str>) -> EmbeddedModel {
        EmbeddedModel {
            model_id: ModelId(id.into()),
            model_type: ModelType::TinyLLM,
            weights_sha256: Hash::new([1; 32]),
            metadata: ModelMetadata {
                name: "n".into(),
                version: "1".into(),
                context_length: 8,
                embedding_dim: dim,
                license: "l".into(),
                framework: framework.map(Into::into),
            },
        }
    }

    /// An honest block at H with non-empty sidecars (a checkpoint
    /// `learning_root`, models, an embedding) is admitted and stored as is;
    /// every changed copy under the same hash is refused first.
    #[tokio::test]
    async fn honest_nonempty_sidecars_at_h_every_changed_copy_refused() {
        let pba = PbaHardening::at(H);
        let (adm, storage, _d) = harness(pba);
        let tip = chain_to(&adm, pba, H - 1).await;
        let mut honest = block(pba, H, tip.header.block_hash, vec![]);
        honest.learning_root = Hash::new([0xC0; 32]);
        honest.embedded_models = vec![
            model("a", Some(4), Some("f")),
            model("b", Some(4), Some("f")),
        ];
        honest.learning_embedding = Some(vec![0.25, 0.5]);
        honest.header.block_hash = honest.compute_hash_for(pba);
        assert_ne!(
            honest.header.block_hash,
            honest.compute_hash_for(PbaHardening::off())
        );

        type M = fn(&mut Block);
        let changes: &[(&str, M)] = &[
            ("strip all", |b| citrate_consensus::block_sidecars::strip(b)),
            ("reorder models", |b| b.embedded_models.reverse()),
            ("drop a model", |b| {
                b.embedded_models.pop();
            }),
            ("learning_root", |b| b.learning_root = Hash::default()),
            ("embedding value", |b| {
                b.learning_embedding = Some(vec![0.25, 0.75])
            }),
            ("embedding none", |b| b.learning_embedding = None),
            ("nested license", |b| {
                b.embedded_models[1].metadata.license = "m".into()
            }),
            ("nested dim", |b| {
                b.embedded_models[0].metadata.embedding_dim = Some(5)
            }),
            ("add pin", |b| {
                b.required_pins = vec![RequiredModel {
                    model_id: ModelId("p".into()),
                    ipfs_cid: "c".into(),
                    sha256_hash: Hash::new([2; 32]),
                    size_bytes: 1,
                    must_pin: true,
                    slash_penalty: 1,
                    grace_period_hours: 1,
                }]
            }),
            ("ghostdag k", |b| b.ghostdag_params.k = 17),
            ("gradient", |b| b.gradient_commitment = Some([1; 32])),
            ("confidence", |b| b.learning_confidence = Some(vec![1.0])),
        ];
        for (name, t) in changes {
            let mut x = honest.clone();
            t(&mut x);
            let r = adm.admit(&x).await;
            assert!(matches!(r, AdmitOutcome::Rejected(_)), "{name}: {r:?}");
            assert!(
                !storage.blocks.has_block(&honest.header.block_hash).unwrap(),
                "{name} stored"
            );
        }
        let r = adm.admit(&honest).await;
        assert!(matches!(r, AdmitOutcome::Admitted { .. }), "{r:?}");
        let stored = storage
            .blocks
            .get_block(&honest.header.block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(stored.embedded_models.len(), 2);
        assert_eq!(stored.learning_root, Hash::new([0xC0; 32]));
        assert_eq!(
            bincode::serialize(&stored).unwrap(),
            bincode::serialize(&honest).unwrap()
        );
    }

    /// Model metadata with the optional fields unset survives the store's
    /// bincode round trip (post-H blocks keep their sidecars).
    #[tokio::test]
    async fn post_h_model_metadata_without_optional_fields_round_trips() {
        let pba = PbaHardening::at(H);
        let (adm, storage, _d) = harness(pba);
        let tip = chain_to(&adm, pba, H - 1).await;
        let mut b = block(pba, H, tip.header.block_hash, vec![]);
        b.embedded_models = vec![model("a", None, None), model("b", Some(4), None)];
        b.header.block_hash = b.compute_hash_for(pba);
        assert!(matches!(adm.admit(&b).await, AdmitOutcome::Admitted { .. }));
        let stored = storage
            .blocks
            .get_block(&b.header.block_hash)
            .expect("decodes")
            .expect("stored");
        assert_eq!(stored.embedded_models[0].metadata.embedding_dim, None);
        assert_eq!(stored.embedded_models[1].metadata.framework, None);
        assert!(stored.verify_hash_for(pba));
    }
}
