// citrate/node/src/cold_resync.rs
//
// The guarded automatic cold resync (ADR-2026-11-03 CV-7c, root cause H6).
//
// A pruned node (DAG retain window) forked more than the reorg window below its
// applied tip cannot switch to the heavier branch: the undo records cover
// `MAX_REORG_DEPTH` heights (10,000 = the prune retention since S3-4, CV-7a;
// 100 before) and the rebuild from genesis is refused on a pruned
// store (`RebuildDecision::RefusePruned`). The applicator then records the
// dead-branch marker (`citrate_storage::chain::wedge`, CV-7b). Before this
// module the only way out was an operator moving the chain data aside by hand.
//
// What this module does, in order:
//
// 1. `decide` (every minute, from `spawn_monitor`): the node has been wedged
//    for `[recovery] cold_resync_after_secs`, automatic resync is enabled, and
//    the last one was more than `cold_resync_min_interval_hours` ago.
//    a checkpoint-voting validator resyncs too, carrying its
//    signed-vote record (below). It used to be excluded, and so did every
//    node with finality on (the flag passed was "finality on", not "this node
//    signs"), so on r1007 four producers and a bootnode stayed wedged for
//    hours until an operator reseeded them by hand (2026-11-14).
// 2. `request`: write `cold-resync.request.json` into the data dir (fsync'd),
//    log at ERROR, and exit non-zero so the supervisor restarts the node (the
//    same contract as the P2P stall watchdog in main.rs). The chain database
//    cannot be swapped under the running process: every component holds it.
// 3. `apply_pending` (start-up, before the chain database is opened): move the
//    RocksDB files into `chain-aside/<unix-seconds>/` inside the data dir.
//    Nothing is deleted. The node identity (`noise.key`, `proposer.key`,
//    `peer.id`) and every other file stay where they are. The node then starts
//    on an empty chain database and syncs from genesis via its peers.
//
// The rate limit is kept in `cold-resync.state.json`, outside the chain
// database, so it survives the move. `[recovery] cold_resync = false` turns the
// whole path off; a wedged node then stays wedged (not serving, advertising or
// sealing the dead branch, and reporting `syncState: wedged`).

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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use citrate_consensus::checkpoint_gadget::FinalityGadget;
use citrate_consensus::types::Hash;
use citrate_storage::chain::wedge::WedgeRecord;
use citrate_storage::crypto::at_rest::EncryptionAtRestConfig;
use citrate_storage::signed_votes::{self, Binding};
use citrate_storage::StorageManager;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::canonical_apply::CanonicalApplicator;
use crate::config::RecoveryConfig;

/// The resync request the running node leaves for its next start.
pub const REQUEST_FILE: &str = "cold-resync.request.json";
/// Rate-limit state (outside the chain database, so it survives the move).
pub const STATE_FILE: &str = "cold-resync.state.json";
/// Where moved chain databases are kept, inside the data dir.
pub const ASIDE_DIR: &str = "chain-aside";
/// The signed-vote record carried across a resync.
pub const VOTES_FILE: &str = "cold-resync.signed-votes";
/// An in-progress resync ([`Journal`]).
pub const JOURNAL_FILE: &str = "cold-resync.journal.json";

/// How often the running node evaluates the wedge.
const MONITOR_EVERY: Duration = Duration::from_secs(60);

/// The head this node advertises in its handshake: the applied tip, or, while
/// the applied tip is held on a dead branch (CV-7b), the dead branch's fork
/// point, so peers never pick this node as a source for that branch. Sources:
/// `BlockStore::get_applied_tip`, `citrate_storage::chain::wedge::read`.
pub fn advertised_head(storage: &StorageManager) -> Option<(Hash, u64)> {
    if let Ok(Some(w)) = citrate_storage::chain::wedge::read(&storage.db) {
        return Some((w.fork_point, w.fork_height));
    }
    storage.blocks.get_applied_tip().ok().flatten()
}

/// The `[recovery]` settings in the units the decision uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub enabled: bool,
    pub min_interval_secs: u64,
    pub after_secs: u64,
}

impl From<&RecoveryConfig> for Policy {
    fn from(c: &RecoveryConfig) -> Self {
        Self {
            enabled: c.cold_resync,
            min_interval_secs: c.cold_resync_min_interval_hours.saturating_mul(3600),
            after_secs: c.cold_resync_after_secs,
        }
    }
}

/// Rate-limit state, `STATE_FILE`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResyncState {
    /// Unix seconds of the last move-aside (0: never).
    pub last_resync_unix: u64,
    /// Move-asides done on this data dir.
    pub resyncs: u64,
    /// Where the last chain database was moved.
    pub last_aside: Option<String>,
}

/// What the running node leaves for its next start, `REQUEST_FILE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResyncRequest {
    pub requested_unix: u64,
    pub dead_tip: String,
    pub dead_tip_height: u64,
    pub fork_height: u64,
    pub fork_depth: u64,
    pub head: String,
    pub head_height: u64,
    pub reason: String,
    /// This node signs checkpoint votes: its signed-vote record must be
    /// carried into the new database .
    #[serde(default)]
    pub carry_signed_votes: bool,
}

/// The verdict of one evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    NotWedged,
    /// `[recovery] cold_resync = false`.
    Disabled,
    /// Wedged for less than `after_secs`.
    Waiting {
        remaining_secs: u64,
    },
    /// The last resync was less than `min_interval_secs` ago.
    RateLimited {
        next_unix: u64,
    },
    Resync(ResyncRequest),
}

/// Whether to resync now. Pure: every input is passed in. `finality_voting`
/// is whether THIS node signs checkpoint votes ([`signs_checkpoint_votes`]);
/// such a node resyncs with its signed-vote record carried.
pub fn decide(
    policy: Policy,
    wedge: Option<&WedgeRecord>,
    state: &ResyncState,
    finality_voting: bool,
    now_unix: u64,
) -> Decision {
    let Some(w) = wedge else {
        return Decision::NotWedged;
    };
    if !policy.enabled {
        return Decision::Disabled;
    }
    let wedged_for = now_unix.saturating_sub(w.since_unix);
    if wedged_for < policy.after_secs {
        return Decision::Waiting {
            remaining_secs: policy.after_secs.saturating_sub(wedged_for),
        };
    }
    if let Some(next_unix) = rate_limited(policy, state, now_unix) {
        return Decision::RateLimited { next_unix };
    }
    Decision::Resync(ResyncRequest {
        requested_unix: now_unix,
        dead_tip: w.dead_tip.to_string(),
        dead_tip_height: w.dead_tip_height,
        fork_height: w.fork_height,
        fork_depth: w.fork_depth(),
        head: w.head.to_string(),
        head_height: w.head_height,
        reason: w.reason.clone(),
        carry_signed_votes: finality_voting,
    })
}

/// Whether this node signs checkpoint votes: finality voting is on for the
/// chain AND the node has a consensus identity (a non-zero coinbase, which is
/// what makes `start_node` load `proposer.key` as the vote signer). A node
/// without one proposes and aggregates but never signs, so it holds no
/// signed-vote record to protect.
pub fn signs_checkpoint_votes(finality_on: bool, coinbase: &str) -> bool {
    let c = coinbase.trim_start_matches("0x");
    finality_on
        && !c.is_empty()
        && hex::decode(c)
            .map(|b| b.iter().any(|&x| x != 0))
            .unwrap_or(false)
}

/// What a cold resync needs to read and bind the signed-vote record: the
/// storage key of an encrypted chain database (`None`: plaintext) and the
/// chain, genesis and validator the carry file is bound to.
// No Debug: it holds the storage key.
#[derive(Clone, Default)]
pub struct Carry {
    pub encryption: Option<EncryptionAtRestConfig>,
    pub binding: Binding,
}

/// In-progress resync, `JOURNAL_FILE`: written before
/// the first file moves, so a crash at any point resumes at the next start
/// and a carry that did not complete stops the start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub aside: String,
    pub phase: Phase,
    /// What the carry file must hold once imported (set when carried).
    #[serde(default)]
    pub expected: Option<Expected>,
}

/// Where a resync stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// The chain database is being moved aside.
    Moving,
    /// Moved; the signed-vote record is not carried yet.
    Moved,
    /// The record is in `VOTES_FILE`; the next open imports it.
    Carried,
}

/// The carried record, as counted when it was written: the import must find at least this much, or the start stops.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expected {
    pub votes: usize,
    pub highest_vote: Option<u64>,
    pub meta_highest: Option<u64>,
}

impl Expected {
    fn of(s: &signed_votes::Summary) -> Self {
        Self {
            votes: s.votes,
            highest_vote: s.vote_heights.map(|(_, hi)| hi),
            meta_highest: s.meta.iter().map(|(_, m)| m.highest).max(),
        }
    }

    fn met_by(&self, s: &signed_votes::Summary) -> bool {
        let got = Self::of(s);
        got.votes >= self.votes
            && got.highest_vote >= self.highest_vote
            && got.meta_highest >= self.meta_highest
    }
}

fn read_journal(data_dir: &Path) -> anyhow::Result<Option<Journal>> {
    match std::fs::read(data_dir.join(JOURNAL_FILE)) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_journal(data_dir: &Path, j: &Journal) -> anyhow::Result<()> {
    write_durable(&data_dir.join(JOURNAL_FILE), &serde_json::to_vec_pretty(j)?)
}

/// Export the running node's signed-vote record to `VOTES_FILE` (merged with
/// one already there, bound to `binding`), before it asks for a resync.
pub fn export_signed_votes(
    storage: &StorageManager,
    data_dir: &Path,
    binding: &Binding,
) -> anyhow::Result<()> {
    let path = data_dir.join(VOTES_FILE);
    let live = signed_votes::export(&storage.db)?;
    let merged = match path.exists() {
        true => signed_votes::merge(&signed_votes::read_file_bound(&path, binding)?, &live)?,
        false => live,
    };
    signed_votes::write_file_bound(&path, &merged, binding)?;
    info!(
        "COLD RESYNC: signed-vote record exported for the resync ({})",
        signed_votes::summarize(&merged)?
    );
    Ok(())
}

/// [`import_carried_votes_bound`] with nothing bound (tests; start_node
/// always binds).
#[cfg(test)]
pub fn import_carried_votes(storage: &StorageManager, data_dir: &Path) -> anyhow::Result<bool> {
    import_carried_votes_bound(storage, data_dir, &Binding::default())
}

/// Right after the (new) chain database opens and before anything can sign:
/// write a carried signed-vote record back. Stops the start (an error) when a
/// resync is unfinished, when its carry file is missing or does not verify,
/// or when the import holds less than was carried. The file is kept, renamed,
/// as an audit copy; the journal is removed last.
pub fn import_carried_votes_bound(
    storage: &StorageManager,
    data_dir: &Path,
    binding: &Binding,
) -> anyhow::Result<bool> {
    let path = data_dir.join(VOTES_FILE);
    let journal = read_journal(data_dir)?;
    if let Some(j) = &journal {
        if j.phase != Phase::Carried {
            anyhow::bail!(
                "COLD RESYNC: an interrupted resync ({:?}, chain data at {}) has not carried this node's signed-vote record; refusing to start. {}",
                j.phase,
                j.aside,
                citrate_storage::VOTING_VALIDATOR_WIPE_NOTE
            );
        }
        if !path.exists() {
            // Second a crash after the carry file was imported
            // (and renamed) but before the journal was removed. The record is
            // already in this database if it holds at least what was carried:
            // finish the resync rather than refuse every start.
            let held = signed_votes::summarize(&signed_votes::export(&storage.db)?)?;
            if j.expected.as_ref().is_some_and(|e| e.met_by(&held)) {
                std::fs::remove_file(data_dir.join(JOURNAL_FILE))?;
                warn!(
                    "COLD RESYNC: finished a resync interrupted after its import: the chain \
                     database already holds the carried signed-vote record ({held})"
                );
                return Ok(false);
            }
            anyhow::bail!(
                "COLD RESYNC: the signed-vote record carried from {} ({:?}) is missing ({}); refusing to start, since this node could sign again at heights it has signed. Restore the file, or re-export it from the moved database with signed_vote_carry. {}",
                j.aside,
                j.expected,
                path.display(),
                citrate_storage::VOTING_VALIDATOR_WIPE_NOTE
            );
        }
    } else if !path.exists() {
        return Ok(false);
    }
    let recs = signed_votes::read_file_bound(&path, binding)?;
    let after = signed_votes::import(&storage.db, &recs)?;
    let summary = signed_votes::summarize(&after)?;
    if let Some(expected) = journal.as_ref().and_then(|j| j.expected.as_ref()) {
        if !expected.met_by(&summary) {
            anyhow::bail!(
                "COLD RESYNC: the imported signed-vote record ({summary}) holds less than was carried ({expected:?}); refusing to start"
            );
        }
    }
    // The journal goes first: a crash before the rename leaves the file and
    // no journal, and the next start imports it again (idempotent).
    if journal.is_some() {
        std::fs::remove_file(data_dir.join(JOURNAL_FILE))?;
    }
    let done = data_dir.join(format!("{VOTES_FILE}.imported-{}", now_unix()));
    std::fs::rename(&path, &done)?;
    info!(
        "COLD RESYNC: signed-vote record carried into the new chain database ({summary}); \
         audit copy at {}",
        done.display()
    );
    Ok(true)
}

/// `Some(next allowed unix second)` while the last resync is too recent.
fn rate_limited(policy: Policy, state: &ResyncState, now_unix: u64) -> Option<u64> {
    if state.resyncs == 0 {
        return None;
    }
    let next = state
        .last_resync_unix
        .saturating_add(policy.min_interval_secs);
    (now_unix < next).then_some(next)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read `STATE_FILE`; absent is the default state. A file that does not parse
/// is an error: it never reads as "never resynced".
pub fn read_state(data_dir: &Path) -> anyhow::Result<ResyncState> {
    match std::fs::read(data_dir.join(STATE_FILE)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ResyncState::default()),
        Err(e) => Err(e.into()),
    }
}

/// Write `bytes` to `path` durably (temp file, fsync, rename).
fn write_durable(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Leave the resync request for the next start.
pub fn request(data_dir: &Path, req: &ResyncRequest) -> anyhow::Result<()> {
    write_durable(
        &data_dir.join(REQUEST_FILE),
        &serde_json::to_vec_pretty(req)?,
    )
}

/// A file or directory of the chain database (RocksDB) in the data dir. Only
/// these move; anything else (the identity keys, the resync state, operator
/// files) stays.
fn is_chain_db_entry(name: &str) -> bool {
    matches!(
        name,
        "CURRENT" | "IDENTITY" | "LOCK" | "LOG" | "encryption.meta"
    ) || name.starts_with("LOG.old")
        || name.starts_with("MANIFEST-")
        || name.starts_with("OPTIONS-")
        || name.ends_with(".sst")
        || name.ends_with(".log")
        || name.ends_with(".blob")
}

/// At start-up, before the chain database is opened: carry out a resync the
/// previous process requested, or finish one a crash interrupted. Returns where
/// the chain database was moved, or `None` when nothing was requested or the
/// request was declined (disabled, rate-limited, or its signed-vote record
/// could not be carried; the request is then dropped with a warning and the
/// node starts on its chain data as it is).
pub fn apply_pending(
    data_dir: &Path,
    policy: Policy,
    carry: &Carry,
) -> anyhow::Result<Option<PathBuf>> {
    apply_pending_with(data_dir, policy, carry, now_unix())
}

/// [`apply_pending_with`] for a plaintext store, nothing bound (tests).
#[cfg(test)]
pub(crate) fn apply_pending_at(
    data_dir: &Path,
    policy: Policy,
    now: u64,
) -> anyhow::Result<Option<PathBuf>> {
    apply_pending_with(data_dir, policy, &Carry::default(), now)
}

pub(crate) fn apply_pending_with(
    data_dir: &Path,
    policy: Policy,
    carry: &Carry,
    now: u64,
) -> anyhow::Result<Option<PathBuf>> {
    if let Some(j) = read_journal(data_dir)? {
        warn!(
            "COLD RESYNC: resuming an interrupted resync ({:?}, chain data at {})",
            j.phase, j.aside
        );
        return finish(data_dir, j, carry, now);
    }
    let req_path = data_dir.join(REQUEST_FILE);
    let req: ResyncRequest = match std::fs::read(&req_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let state = read_state(data_dir)?;
    if !policy.enabled {
        warn!(
            "COLD RESYNC: a resync was requested ({req:?}) but [recovery] cold_resync is off; \
             not moving the chain data. The node stays on its dead branch until an operator \
             resyncs it."
        );
        std::fs::remove_file(&req_path)?;
        return Ok(None);
    }
    if let Some(next) = rate_limited(policy, &state, now) {
        warn!(
            "COLD RESYNC: a resync was requested but the last one was at {} (next allowed at {}); \
             not moving the chain data",
            state.last_resync_unix, next
        );
        std::fs::remove_file(&req_path)?;
        return Ok(None);
    }
    let aside = data_dir.join(ASIDE_DIR).join(now.to_string());
    std::fs::create_dir_all(&aside)?;
    let j = Journal {
        aside: aside.display().to_string(),
        phase: Phase::Moving,
        expected: None,
    };
    write_journal(data_dir, &j)?;
    finish(data_dir, j, carry, now)
}

/// Move the chain database entries left in `data_dir` into `aside`.
fn move_chain_db(from: &Path, to: &Path) -> anyhow::Result<usize> {
    let mut moved = 0usize;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_chain_db_entry(name) {
            continue;
        }
        std::fs::rename(entry.path(), to.join(name))?;
        moved = moved.saturating_add(1);
    }
    Ok(moved)
}

/// Drive a journaled resync to `Carried` (or put everything back), then
/// record it. Each phase is written before the next begins, so any crash
/// resumes here.
fn finish(
    data_dir: &Path,
    mut j: Journal,
    carry: &Carry,
    now: u64,
) -> anyhow::Result<Option<PathBuf>> {
    let aside = PathBuf::from(&j.aside);
    if j.phase == Phase::Moving {
        std::fs::create_dir_all(&aside)?;
        move_chain_db(data_dir, &aside)?;
        j.phase = Phase::Moved;
        write_journal(data_dir, &j)?;
    }
    if j.phase == Phase::Moved {
        // always carried, whatever the config says;
        // the record (if any) is in the data, not in the coinbase setting.
        match carry_from_aside(data_dir, &aside, carry) {
            Ok(summary) => {
                j.expected = Some(Expected::of(&summary));
                j.phase = Phase::Carried;
                write_journal(data_dir, &j)?;
            }
            Err(e) => {
                // Fail closed: put the database back and keep the node wedged
                // rather than start without its signed-vote record.
                move_back(data_dir, &aside)?;
                let _ = std::fs::remove_file(data_dir.join(VOTES_FILE));
                std::fs::remove_file(data_dir.join(JOURNAL_FILE))?;
                let _ = std::fs::remove_file(data_dir.join(REQUEST_FILE));
                error!(
                    "COLD RESYNC: NOT resyncing: this node's signed-vote record could not be \
                     carried ({e}). The chain database was put back. {}",
                    citrate_storage::VOTING_VALIDATOR_WIPE_NOTE
                );
                return Ok(None);
            }
        }
    }
    let req_path = data_dir.join(REQUEST_FILE);
    if req_path.exists() {
        let req: Option<ResyncRequest> = std::fs::read(&req_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        let mut state = read_state(data_dir)?;
        state.last_resync_unix = now;
        state.resyncs = state.resyncs.saturating_add(1);
        state.last_aside = Some(j.aside.clone());
        write_durable(
            &data_dir.join(STATE_FILE),
            &serde_json::to_vec_pretty(&state)?,
        )?;
        std::fs::remove_file(&req_path)?;
        error!(
            "COLD RESYNC: moved the chain database aside to {} — NOT deleted; reclaim it once \
             this node has resynced. Request: {req:?}. It now resyncs from genesis via its \
             peers with the same node identity (noise.key, proposer.key kept) and its \
             signed-vote record carried ({:?}). Resync #{} on this data dir.",
            j.aside, j.expected, state.resyncs
        );
    }
    Ok(Some(aside))
}

/// Undo a move: everything in `aside` back into `data_dir`.
fn move_back(data_dir: &Path, aside: &Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(aside)? {
        let entry = entry?;
        std::fs::rename(entry.path(), data_dir.join(entry.file_name()))?;
    }
    std::fs::remove_dir(aside)?;
    Ok(())
}

/// The signed-vote record of the moved database, read directly (decrypted
/// with the node's storage key when it is encrypted, )
/// and merged with the running node's export, into `VOTES_FILE`.
fn carry_from_aside(
    data_dir: &Path,
    aside: &Path,
    carry: &Carry,
) -> anyhow::Result<signed_votes::Summary> {
    let path = data_dir.join(VOTES_FILE);
    let exported = match path.exists() {
        true => Some(signed_votes::read_file_bound(&path, &carry.binding)?),
        false => None,
    };
    let encryption = if aside.join("encryption.meta").exists() {
        Some(carry.encryption.as_ref().ok_or_else(|| {
            anyhow::anyhow!("the moved chain database is encrypted and no storage key was given")
        })?)
    } else {
        None
    };
    let db = citrate_storage::db::RocksDB::open_read_only_with(aside, encryption)?;
    let moved = signed_votes::export(&db)?;
    drop(db);
    let merged = match exported {
        Some(e) => signed_votes::merge(&e, &moved)?,
        None => moved,
    };
    signed_votes::write_file_bound(&path, &merged, &carry.binding)?;
    let summary = signed_votes::summarize(&merged)?;
    info!("COLD RESYNC: signed-vote record to carry: {summary}");
    Ok(summary)
}

/// One evaluation of the running node: on `Decision::Resync`, stop checkpoint
/// signing (no vote can be signed after the export),
/// export the signed-vote record, leave the request and return it (the
/// caller exits the process). The stop is not lifted: the process exits.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn evaluate(
    app: &CanonicalApplicator,
    storage: &StorageManager,
    gadget: Option<&FinalityGadget>,
    data_dir: &Path,
    policy: Policy,
    finality_voting: bool,
    binding: &Binding,
    now: u64,
) -> anyhow::Result<Decision> {
    let mut wedge = app.wedge()?;
    // A marker the dead-branch evidence recorded (`dead_branch.rs`) holds only
    // while the applied tip is the dead tip it was judged against: re-checked
    // HERE, at decision time, so a tip that moved since the evidence tick (or
    // an evidence tick that stopped running) never fires a resync. The
    // applicator's own marker (`RefusePruned`) keeps its CV-7b rule.
    if let Some(w) = &wedge {
        if w.reason.starts_with(crate::dead_branch::REASON_PREFIX)
            && app.applied_tip().await.hash != w.dead_tip
        {
            let _ = app
                .clear_evidence_dead_branch(crate::dead_branch::REASON_PREFIX)
                .await;
            wedge = None;
        }
    }
    let state = read_state(data_dir)?;
    let decision = decide(policy, wedge.as_ref(), &state, finality_voting, now);
    if let Decision::Resync(req) = &decision {
        if let Some(g) = gadget {
            // A latch the floor verifier's recovery (`clear`) cannot lift,
            // held until the process exits.
            g.safety_stop().latch_until_exit().await;
        }
        // Before the request: no request without the record.
        export_signed_votes(storage, data_dir, binding)?;
        request(data_dir, req)?;
    }
    Ok(decision)
}

/// Run the evaluation every [`MONITOR_EVERY`]; on a resync verdict, log at
/// ERROR and exit non-zero so the supervisor restarts the node into
/// [`apply_pending`].
pub(crate) fn spawn_monitor(
    app: Arc<CanonicalApplicator>,
    storage: Arc<StorageManager>,
    gadget: Option<Arc<FinalityGadget>>,
    data_dir: PathBuf,
    policy: Policy,
    finality_voting: bool,
    binding: Binding,
) {
    tokio::spawn(async move {
        let mut last: Option<Decision> = None;
        let mut tick = tokio::time::interval(MONITOR_EVERY);
        loop {
            tick.tick().await;
            match evaluate(
                &app,
                &storage,
                gadget.as_deref(),
                &data_dir,
                policy,
                finality_voting,
                &binding,
                now_unix(),
            )
            .await
            {
                Ok(Decision::Resync(req)) => {
                    error!(
                        "COLD RESYNC: this node has been held on a dead branch {} block(s) deep \
                         (dead tip {} @ {}, network head {} @ {}) for at least {} s and cannot \
                         switch on its own. Requested a cold resync; exiting so the supervisor \
                         restarts it. The chain data is moved aside (not deleted) at start-up. \
                         Disable with [recovery] cold_resync = false.",
                        req.fork_depth,
                        req.dead_tip,
                        req.dead_tip_height,
                        req.head,
                        req.head_height,
                        policy.after_secs
                    );
                    std::process::exit(1);
                }
                Ok(d) => {
                    let changed = last.as_ref().map(std::mem::discriminant)
                        != Some(std::mem::discriminant(&d));
                    if changed {
                        match &d {
                            Decision::NotWedged | Decision::Waiting { .. } => {}
                            Decision::Disabled => warn!(
                                "COLD RESYNC: wedged on a dead branch, automatic resync is off \
                                 ([recovery] cold_resync = false); resync this node by hand"
                            ),
                            Decision::RateLimited { next_unix } => warn!(
                                "COLD RESYNC: wedged on a dead branch again; the last automatic \
                                 resync was too recent, next allowed at {next_unix}"
                            ),
                            Decision::Resync(_) => {}
                        }
                        if matches!(d, Decision::NotWedged) && last.is_some() {
                            info!("COLD RESYNC: no longer wedged");
                        }
                    }
                    last = Some(d);
                }
                Err(e) => warn!("COLD RESYNC: evaluation failed: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_storage::pruning::PruningConfig;
    use tempfile::TempDir;

    fn wedge(since: u64) -> WedgeRecord {
        WedgeRecord {
            dead_tip: Hash::new([1; 32]),
            dead_tip_height: 5_100,
            fork_point: Hash::new([2; 32]),
            fork_height: 100,
            head: Hash::new([3; 32]),
            head_height: 5_200,
            reason: "refused".into(),
            since_unix: since,
        }
    }

    fn policy() -> Policy {
        Policy::from(&RecoveryConfig::default())
    }

    #[test]
    fn cold_resync_decision_is_guarded() {
        let w = wedge(1_000);
        let fresh = ResyncState::default();
        assert_eq!(
            decide(policy(), None, &fresh, false, 5_000),
            Decision::NotWedged
        );
        assert_eq!(
            decide(policy(), Some(&w), &fresh, false, 1_100),
            Decision::Waiting {
                remaining_secs: 800
            },
            "wedged for less than the grace period"
        );
        let off = Policy {
            enabled: false,
            ..policy()
        };
        assert_eq!(
            decide(off, Some(&w), &fresh, false, 9_000),
            Decision::Disabled
        );
        // a checkpoint-voting validator is not left wedged; it
        // resyncs and carries its signed-vote record (see
        // `a_voting_validator_resync_carries_its_signed_vote_record`).
        assert!(
            matches!(
                decide(policy(), Some(&w), &fresh, true, 9_000),
                Decision::Resync(_)
            ),
            "a wedged voting validator must resync, not stay wedged"
        );
        let Decision::Resync(req) = decide(policy(), Some(&w), &fresh, false, 9_000) else {
            panic!("a wedge past the grace period resyncs");
        };
        assert_eq!(req.fork_depth, 5_000);
        let recent = ResyncState {
            last_resync_unix: 8_000,
            resyncs: 1,
            last_aside: None,
        };
        assert_eq!(
            decide(policy(), Some(&w), &recent, false, 9_000),
            Decision::RateLimited {
                next_unix: 8_000 + 6 * 3600
            }
        );
        assert!(matches!(
            decide(policy(), Some(&w), &recent, false, 8_000 + 6 * 3600),
            Decision::Resync(_)
        ));
    }

    #[test]
    fn cold_resync_moves_only_the_chain_database_aside_and_keeps_the_identity() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        {
            let s = StorageManager::new(data, PruningConfig::default()).expect("storage");
            s.db.put_cf("metadata", b"probe", b"old chain")
                .expect("write");
            s.db.flush().expect("flush");
        }
        for f in ["noise.key", "proposer.key", "peer.id", "operator-notes.txt"] {
            std::fs::write(data.join(f), f.as_bytes()).expect("write");
        }
        let w = wedge(0);
        let Decision::Resync(req) =
            decide(policy(), Some(&w), &ResyncState::default(), false, 10_000)
        else {
            panic!("resync");
        };
        request(data, &req).expect("request");
        let aside = apply_pending_at(data, policy(), 10_000)
            .expect("apply")
            .expect("moved aside");
        assert_eq!(aside, data.join(ASIDE_DIR).join("10000"));
        // Identity and operator files stay; the request is consumed.
        for f in ["noise.key", "proposer.key", "peer.id", "operator-notes.txt"] {
            assert_eq!(std::fs::read(data.join(f)).expect("kept"), f.as_bytes());
        }
        assert!(!data.join(REQUEST_FILE).exists());
        assert!(
            aside.join("CURRENT").exists(),
            "the database moved, not deleted"
        );
        // The moved database still opens and holds the old chain.
        {
            let old = StorageManager::new(&aside, PruningConfig::default()).expect("aside opens");
            assert_eq!(
                old.db.get_cf("metadata", b"probe").expect("read"),
                Some(b"old chain".to_vec())
            );
        }
        // The data dir opens as an empty chain database; start_node then
        // imports the carried record (nothing signed here) and the resync is
        // complete.
        {
            let fresh = StorageManager::new(data, PruningConfig::default()).expect("fresh");
            assert_eq!(fresh.db.get_cf("metadata", b"probe").expect("read"), None);
            assert!(import_carried_votes(&fresh, data).expect("import"));
            assert!(!data.join(JOURNAL_FILE).exists(), "resync complete");
        }
        let state = read_state(data).expect("state");
        assert_eq!(state.resyncs, 1);
        assert_eq!(state.last_resync_unix, 10_000);
        // A second request inside the interval is declined and nothing moves.
        request(data, &req).expect("request");
        assert_eq!(
            apply_pending_at(data, policy(), 10_060).expect("apply"),
            None
        );
        assert!(!data.join(REQUEST_FILE).exists());
        assert!(!data.join(ASIDE_DIR).join("10060").exists());
        // Disabled: declined too.
        request(data, &req).expect("request");
        let off = Policy {
            enabled: false,
            ..policy()
        };
        assert_eq!(apply_pending_at(data, off, 100_000).expect("apply"), None);
        assert!(
            data.join("CURRENT").exists(),
            "nothing moved while disabled"
        );
    }

    fn vote(h: u64, b: u8) -> citrate_storage::signed_votes::Record {
        (
            citrate_consensus::checkpoint_gadget::signed_vote_key(40204, h),
            vec![b; 32],
        )
    }

    fn votes_in(storage: &StorageManager) -> Vec<u64> {
        let s = signed_votes::summarize(&signed_votes::export(&storage.db).expect("export"))
            .expect("summary");
        match s.vote_heights {
            Some((lo, hi)) => vec![s.votes as u64, lo, hi],
            None => vec![0],
        }
    }

    /// a wedged voting validator resyncs and its new chain
    /// database holds its whole signed-vote record before anything can sign,
    /// including a vote signed after the running node exported it.
    #[test]
    fn a_voting_validator_resync_carries_its_signed_vote_record() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        let w = wedge(0);
        let Decision::Resync(req) =
            decide(policy(), Some(&w), &ResyncState::default(), true, 10_000)
        else {
            panic!("a wedged voting validator resyncs");
        };
        assert!(req.carry_signed_votes);
        {
            let s = StorageManager::new(data, PruningConfig::default()).expect("storage");
            signed_votes::import(
                &s.db,
                &[
                    vote(93_050, 1),
                    vote(95_350, 2),
                    (
                        citrate_consensus::checkpoint_gadget::signed_vote_meta_key(40204),
                        citrate_consensus::checkpoint_gadget::SignedVoteMeta {
                            floor: 93_000,
                            highest: 95_350,
                        }
                        .encode(),
                    ),
                ],
            )
            .expect("seed votes");
            // `evaluate`: the record is exported before the request is left.
            export_signed_votes(&s, data, &Binding::default()).expect("export");
            request(data, &req).expect("request");
            // A vote signed between the export and the exit.
            signed_votes::import(&s.db, &[vote(95_400, 3)]).expect("late vote");
            s.db.flush().expect("flush");
        }
        std::fs::write(data.join("proposer.key"), b"key").expect("key");
        apply_pending_at(data, policy(), 10_000)
            .expect("apply")
            .expect("moved aside");
        let fresh = StorageManager::new(data, PruningConfig::default()).expect("fresh");
        assert_eq!(votes_in(&fresh), vec![0], "nothing before the import");
        assert!(import_carried_votes(&fresh, data).expect("import"));
        assert_eq!(
            votes_in(&fresh),
            vec![3, 93_050, 95_400],
            "every vote, the late one too"
        );
        assert!(!data.join(VOTES_FILE).exists(), "consumed");
        assert!(!import_carried_votes(&fresh, data).expect("again"));
        assert_eq!(
            std::fs::read(data.join("proposer.key")).expect("kept"),
            b"key"
        );
    }

    fn enc() -> citrate_storage::crypto::at_rest::EncryptionAtRestConfig {
        citrate_storage::crypto::at_rest::EncryptionAtRestConfig::with_raw_key([9u8; 32])
    }

    fn enc_storage(data: &Path) -> StorageManager {
        StorageManager::with_config(
            data,
            citrate_storage::StorageConfig::default().with_encryption(enc()),
        )
        .expect("encrypted storage")
    }

    /// on an ENCRYPTED chain database (every Core
    /// desktop node) a vote signed between the running node's export and its
    /// exit must still be carried.
    #[test]
    fn a_late_vote_on_an_encrypted_database_is_carried() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        let Decision::Resync(req) = decide(
            policy(),
            Some(&wedge(0)),
            &ResyncState::default(),
            true,
            10_000,
        ) else {
            panic!("resync");
        };
        {
            let s = enc_storage(data);
            signed_votes::import(&s.db, &[vote(93_050, 1)]).expect("seed");
            export_signed_votes(&s, data, &Binding::default()).expect("export");
            request(data, &req).expect("request");
            signed_votes::import(&s.db, &[vote(95_400, 3)]).expect("late vote");
            s.db.flush().expect("flush");
        }
        std::fs::write(data.join("proposer.key"), b"key").expect("key");
        let carry = Carry {
            encryption: Some(enc()),
            binding: Binding::default(),
        };
        apply_pending_with(data, policy(), &carry, 10_000)
            .expect("apply")
            .expect("moved aside");
        let fresh = enc_storage(data);
        assert!(import_carried_votes(&fresh, data).expect("import"));
        assert_eq!(
            votes_in(&fresh),
            vec![2, 93_050, 95_400],
            "the late vote was lost"
        );
    }

    /// the carried record disappearing between the move
    /// and the next start must stop the start, never let the validator run
    /// without its protection.
    #[test]
    fn a_missing_carry_file_after_the_move_stops_the_start() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        let Decision::Resync(req) = decide(
            policy(),
            Some(&wedge(0)),
            &ResyncState::default(),
            true,
            10_000,
        ) else {
            panic!("resync");
        };
        {
            let s = StorageManager::new(data, PruningConfig::default()).expect("storage");
            signed_votes::import(&s.db, &[vote(93_050, 1)]).expect("seed");
            export_signed_votes(&s, data, &Binding::default()).expect("export");
            request(data, &req).expect("request");
            s.db.flush().expect("flush");
        }
        apply_pending_at(data, policy(), 10_000)
            .expect("apply")
            .expect("moved aside");
        std::fs::remove_file(data.join(VOTES_FILE)).expect("the carry file is lost");
        let fresh = StorageManager::new(data, PruningConfig::default()).expect("fresh");
        assert!(
            import_carried_votes(&fresh, data).is_err(),
            "a node whose carried record vanished must not start"
        );
    }

    /// decide on the data, not the config. A node whose
    /// chain database holds signed votes (or that has a proposer.key) carries
    /// them even if its config says it does not sign (a coinbase removed, a
    /// finality switch off).
    #[test]
    fn signed_votes_are_carried_whatever_the_config_says() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        let Decision::Resync(req) = decide(
            policy(),
            Some(&wedge(0)),
            &ResyncState::default(),
            false,
            10_000,
        ) else {
            panic!("resync");
        };
        std::fs::write(data.join("proposer.key"), b"key").expect("key");
        {
            let s = StorageManager::new(data, PruningConfig::default()).expect("storage");
            signed_votes::import(&s.db, &[vote(93_050, 1)]).expect("seed");
            request(data, &req).expect("request");
            s.db.flush().expect("flush");
        }
        apply_pending_at(data, policy(), 10_000)
            .expect("apply")
            .expect("moved aside");
        let fresh = StorageManager::new(data, PruningConfig::default()).expect("fresh");
        let _ = import_carried_votes(&fresh, data).expect("import");
        assert_eq!(
            votes_in(&fresh),
            vec![1, 93_050, 93_050],
            "the votes were dropped"
        );
    }

    /// a crash in the middle of the move (some files
    /// moved, the journal at `Moving`) resumes at the next start and still
    /// carries the whole record; until the record is imported the start is
    /// refused.
    #[test]
    fn a_resync_interrupted_mid_move_resumes_and_carries() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        {
            let s = StorageManager::new(data, PruningConfig::default()).expect("storage");
            signed_votes::import(&s.db, &[vote(93_050, 1), vote(95_350, 2)]).expect("seed");
            s.db.flush().expect("flush");
        }
        let Decision::Resync(req) = decide(
            policy(),
            Some(&wedge(0)),
            &ResyncState::default(),
            true,
            10_000,
        ) else {
            panic!("resync");
        };
        request(data, &req).expect("request");
        // The crash: journal written, one file moved, then nothing.
        let aside = data.join(ASIDE_DIR).join("10000");
        std::fs::create_dir_all(&aside).expect("aside");
        write_journal(
            data,
            &Journal {
                aside: aside.display().to_string(),
                phase: Phase::Moving,
                expected: None,
            },
        )
        .expect("journal");
        std::fs::rename(data.join("CURRENT"), aside.join("CURRENT")).expect("one file");
        // An open before the resume would be refused by the import.
        assert_eq!(
            apply_pending_at(data, policy(), 10_005)
                .expect("resume")
                .expect("aside"),
            aside
        );
        let j = read_journal(data).expect("read").expect("journal kept");
        assert_eq!(j.phase, Phase::Carried);
        assert_eq!(
            j.expected,
            Some(Expected {
                votes: 2,
                highest_vote: Some(95_350),
                meta_highest: None
            })
        );
        assert!(!data.join(REQUEST_FILE).exists());
        let fresh = StorageManager::new(data, PruningConfig::default()).expect("fresh");
        assert!(import_carried_votes(&fresh, data).expect("import"));
        assert_eq!(votes_in(&fresh), vec![2, 93_050, 95_350]);
        assert!(!data.join(JOURNAL_FILE).exists());
    }

    /// An unfinished journal (crash before the carry) stops the start if the
    /// resume did not run.
    #[test]
    fn an_unfinished_resync_refuses_to_start() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        write_journal(
            data,
            &Journal {
                aside: "x".into(),
                phase: Phase::Moved,
                expected: None,
            },
        )
        .expect("journal");
        let fresh = StorageManager::new(data, PruningConfig::default()).expect("fresh");
        assert!(import_carried_votes(&fresh, data).is_err());
    }

    /// a carry file bound to another validator is not
    /// imported.
    #[test]
    fn a_carry_file_for_another_validator_is_not_imported() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        let theirs = Binding {
            chain_id: Some(40204),
            genesis: None,
            validator: Binding::normalize("fc0305a20a46c791ea40e72bbf80582fdd5fe0ab"),
        };
        signed_votes::write_file_bound(&data.join(VOTES_FILE), &[vote(95_350, 2)], &theirs)
            .expect("write");
        let mine = Binding {
            validator: Binding::normalize("96b82a070ca2615eef29d8c67b86c21fd0ba474b"),
            ..theirs.clone()
        };
        let fresh = StorageManager::new(data, PruningConfig::default()).expect("fresh");
        assert!(import_carried_votes_bound(&fresh, data, &mine).is_err());
        assert_eq!(votes_in(&fresh), vec![0]);
        assert!(import_carried_votes_bound(&fresh, data, &theirs).expect("theirs"));
    }

    /// once `evaluate` decides to resync it engages the
    /// gadget's safety stop before the export, so nothing is signed after it.
    #[test]
    fn evaluate_stops_signing_before_it_exports() {
        let src = include_str!("cold_resync.rs");
        let body = &src[src.find("pub(crate) async fn evaluate(").expect("evaluate")..];
        let stop = body
            .find("safety_stop().latch_until_exit().await")
            .expect("stops signing");
        let export = body.find("export_signed_votes(storage").expect("exports");
        assert!(stop < export, "the stop must come before the export");
    }

    /// the floor verifier's recovery path clears
    /// the ordinary safety stop. Between the export and the exit nothing may
    /// lift the hold, so `evaluate` takes the exit latch, which `clear` does
    /// not touch.
    #[test]
    fn evaluate_holds_an_exit_latch_the_verifier_cannot_clear() {
        let src = include_str!("cold_resync.rs");
        let body = &src[src.find("pub(crate) async fn evaluate(").expect("evaluate")..];
        let latch = body
            .find("safety_stop().latch_until_exit().await")
            .expect("evaluate takes the exit latch");
        let export = body.find("export_signed_votes(storage").expect("exports");
        assert!(latch < export, "the latch must come before the export");
    }

    /// a crash after the carry file was renamed
    /// (imported) but before the journal was removed. The votes are already in
    /// the new database, so the next start finishes the resync instead of
    /// refusing for ever.
    #[test]
    fn a_crash_after_the_import_before_the_journal_is_removed_finishes() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        {
            let s = StorageManager::new(data, PruningConfig::default()).expect("storage");
            signed_votes::import(&s.db, &[vote(93_050, 1), vote(95_350, 2)]).expect("seed");
            s.db.flush().expect("flush");
        }
        let Decision::Resync(req) = decide(
            policy(),
            Some(&wedge(0)),
            &ResyncState::default(),
            true,
            10_000,
        ) else {
            panic!("resync");
        };
        request(data, &req).expect("request");
        apply_pending_at(data, policy(), 10_000)
            .expect("apply")
            .expect("moved aside");
        let carried = read_journal(data).expect("read").expect("journal");
        let fresh = StorageManager::new(data, PruningConfig::default()).expect("fresh");
        assert!(import_carried_votes(&fresh, data).expect("import"));
        // The crash: the journal is still there, the carry file is renamed.
        write_journal(data, &carried).expect("journal back");
        assert!(!data.join(VOTES_FILE).exists());
        assert!(
            !import_carried_votes(&fresh, data).expect("the next start finishes the resync"),
            "nothing left to import"
        );
        assert!(!data.join(JOURNAL_FILE).exists(), "journal removed");
        assert_eq!(votes_in(&fresh), vec![2, 93_050, 95_350]);
    }

    /// Fail closed: an encrypted database whose running node left no export
    /// is not moved, so the validator never starts without its record.
    #[test]
    fn an_encrypted_voting_validator_without_an_export_is_not_moved() {
        let dir = TempDir::new().expect("tempdir");
        let data = dir.path();
        {
            let s = StorageManager::new(data, PruningConfig::default()).expect("storage");
            s.db.flush().expect("flush");
        }
        // Stand-in for an encrypted store's marker: the carry cannot read it.
        std::fs::write(data.join("encryption.meta"), b"{}").expect("marker");
        let Decision::Resync(req) = decide(
            policy(),
            Some(&wedge(0)),
            &ResyncState::default(),
            true,
            10_000,
        ) else {
            panic!("resync");
        };
        request(data, &req).expect("request");
        assert_eq!(
            apply_pending_at(data, policy(), 10_000).expect("apply"),
            None
        );
        assert!(data.join("CURRENT").exists(), "put back");
        assert!(data.join("encryption.meta").exists(), "put back");
        assert!(!data.join(ASIDE_DIR).join("10000").exists());
        assert!(!data.join(REQUEST_FILE).exists());
        assert_eq!(read_state(data).expect("state").resyncs, 0);
    }

    /// A bootnode (finality on, no coinbase) holds no signed-vote record: it
    /// is not a voting validator. On r1007 the flag passed was "finality on",
    /// so boot-2 counted as one and never resynced.
    #[test]
    fn only_a_node_with_a_consensus_identity_signs_checkpoint_votes() {
        assert!(!signs_checkpoint_votes(
            true,
            "0000000000000000000000000000000000000000"
        ));
        assert!(!signs_checkpoint_votes(true, ""));
        assert!(!signs_checkpoint_votes(
            false,
            "96b82a070ca2615eef29d8c67b86c21fd0ba474b"
        ));
        assert!(signs_checkpoint_votes(
            true,
            "0x96b82a070ca2615eef29d8c67b86c21fd0ba474b"
        ));
    }

    /// Tripwire: start_node carries out a pending resync before it opens the
    /// chain database, runs the monitor, and advertises through
    /// `advertised_head`.
    #[test]
    fn start_node_wires_the_cold_resync() {
        let main = include_str!("main.rs");
        let apply = main
            .find("cold_resync::apply_pending(\n        &config.storage.data_dir,\n        recovery_policy,")
            .expect("start_node carries out a pending resync");
        // with the storage key, so an encrypted moved
        // database is read directly.
        assert!(main.contains("encryption: storage_encryption.clone(),"));
        let open = main
            .find("let storage = Arc::new(StorageManager::with_config(")
            .expect("chain database open");
        assert!(
            apply < open,
            "the resync must run before the chain database opens"
        );
        assert!(main.contains("cold_resync::spawn_monitor("));
        // the carried record is imported right after the open,
        // before the finality gadget (the only signer) is built, and the
        // monitor is told whether THIS node signs.
        let import = main
            .find("cold_resync::import_carried_votes_bound(&storage, &config.storage.data_dir, &resync_binding)?")
            .expect("start_node imports a carried signed-vote record");
        let gadget = main
            .find("let finality_voting_on = finality_gadget.enabled();")
            .expect("finality gadget");
        assert!(open < import && import < gadget);
        assert!(main.contains(
            "cold_resync::signs_checkpoint_votes(finality_voting_on, &config.mining.coinbase)"
        ));
        // the monitor holds the gadget, to stop signing
        // before it exports.
        assert!(main.contains("Some(finality_gadget.clone()),"));
        assert!(main.contains("cold_resync::advertised_head(&storage_head)"));
        assert!(main.contains("cold_resync::advertised_head(&storage)"));
    }
}
