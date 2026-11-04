// citrate/node/src/cold_resync.rs
//
// The guarded automatic cold resync (ADR-2026-11-03 CV-7c, root cause H6).
//
// A pruned node (DAG retain window) forked more than the reorg window below its
// applied tip cannot switch to the heavier branch: the undo records cover
// `MAX_REORG_DEPTH` heights and the rebuild from genesis is refused on a pruned
// store (`RebuildDecision::RefusePruned`). The applicator then records the
// dead-branch marker (`citrate_storage::chain::wedge`, CV-7b). Before this
// module the only way out was an operator moving the chain data aside by hand.
//
// What this module does, in order:
//
// 1. `decide` (every minute, from `spawn_monitor`): the node has been wedged
//    for `[recovery] cold_resync_after_secs`, automatic resync is enabled, the
//    last one was more than `cold_resync_min_interval_hours` ago, and the node
//    is not a checkpoint-voting validator (its signed-vote record lives in the
//    chain database; resyncing would discard it, see VOTING_VALIDATOR_WIPE_NOTE).
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

use citrate_consensus::types::Hash;
use citrate_storage::chain::wedge::WedgeRecord;
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
    /// A checkpoint-voting validator never resyncs automatically.
    VotingValidator,
    Resync(ResyncRequest),
}

/// Whether to resync now. Pure: every input is passed in.
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
    if finality_voting {
        return Decision::VotingValidator;
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
    })
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
/// previous process requested. Returns where the chain database was moved, or
/// `None` when nothing was requested or the request was declined (disabled or
/// rate-limited; the request is then dropped with a warning and the node
/// starts on its chain data as it is).
pub fn apply_pending(data_dir: &Path, policy: Policy) -> anyhow::Result<Option<PathBuf>> {
    apply_pending_at(data_dir, policy, now_unix())
}

pub(crate) fn apply_pending_at(
    data_dir: &Path,
    policy: Policy,
    now: u64,
) -> anyhow::Result<Option<PathBuf>> {
    let req_path = data_dir.join(REQUEST_FILE);
    let req: ResyncRequest = match std::fs::read(&req_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut state = read_state(data_dir)?;
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
    let mut moved = 0usize;
    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_chain_db_entry(name) {
            continue;
        }
        std::fs::rename(entry.path(), aside.join(name))?;
        moved = moved.saturating_add(1);
    }
    state.last_resync_unix = now;
    state.resyncs = state.resyncs.saturating_add(1);
    state.last_aside = Some(aside.display().to_string());
    write_durable(
        &data_dir.join(STATE_FILE),
        &serde_json::to_vec_pretty(&state)?,
    )?;
    std::fs::remove_file(&req_path)?;
    error!(
        "COLD RESYNC: moved the chain database ({moved} file(s)) aside to {} — NOT deleted; \
         reclaim it once this node has resynced. This node was held on a dead branch {} \
         block(s) deep (dead tip {} @ {}, fork point @ {}, network head {} @ {}): {}. It now \
         resyncs from genesis via its peers with the same node identity (noise.key, \
         proposer.key kept). Resync #{} on this data dir.",
        aside.display(),
        req.fork_depth,
        req.dead_tip,
        req.dead_tip_height,
        req.fork_height,
        req.head,
        req.head_height,
        req.reason,
        state.resyncs
    );
    Ok(Some(aside))
}

/// One evaluation of the running node: on `Decision::Resync`, leave the
/// request and return it (the caller exits the process). Logs every other
/// verdict that keeps a wedged node wedged, once per change of verdict.
pub(crate) fn evaluate(
    app: &CanonicalApplicator,
    data_dir: &Path,
    policy: Policy,
    finality_voting: bool,
    now: u64,
) -> anyhow::Result<Decision> {
    let wedge = app.wedge()?;
    let state = read_state(data_dir)?;
    let decision = decide(policy, wedge.as_ref(), &state, finality_voting, now);
    if let Decision::Resync(req) = &decision {
        request(data_dir, req)?;
    }
    Ok(decision)
}

/// Run the evaluation every [`MONITOR_EVERY`]; on a resync verdict, log at
/// ERROR and exit non-zero so the supervisor restarts the node into
/// [`apply_pending`].
pub(crate) fn spawn_monitor(
    app: Arc<CanonicalApplicator>,
    data_dir: PathBuf,
    policy: Policy,
    finality_voting: bool,
) {
    tokio::spawn(async move {
        let mut last: Option<Decision> = None;
        let mut tick = tokio::time::interval(MONITOR_EVERY);
        loop {
            tick.tick().await;
            match evaluate(&app, &data_dir, policy, finality_voting, now_unix()) {
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
                            Decision::VotingValidator => warn!(
                                "COLD RESYNC: wedged on a dead branch, but this node votes on \
                                 checkpoints: no automatic resync (it would discard the signed-vote \
                                 record). {}",
                                citrate_storage::VOTING_VALIDATOR_WIPE_NOTE
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
        assert_eq!(
            decide(policy(), Some(&w), &fresh, true, 9_000),
            Decision::VotingValidator
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
        // The data dir opens as an empty chain database.
        {
            let fresh = StorageManager::new(data, PruningConfig::default()).expect("fresh");
            assert_eq!(fresh.db.get_cf("metadata", b"probe").expect("read"), None);
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

    /// Tripwire: start_node carries out a pending resync before it opens the
    /// chain database, runs the monitor, and advertises through
    /// `advertised_head`.
    #[test]
    fn start_node_wires_the_cold_resync() {
        let main = include_str!("main.rs");
        let apply = main
            .find("cold_resync::apply_pending(&config.storage.data_dir, recovery_policy)?")
            .expect("start_node carries out a pending resync");
        let open = main
            .find("let storage = Arc::new(StorageManager::with_config(")
            .expect("chain database open");
        assert!(
            apply < open,
            "the resync must run before the chain database opens"
        );
        assert!(main.contains("cold_resync::spawn_monitor("));
        assert!(main.contains("cold_resync::advertised_head(&storage_head)"));
        assert!(main.contains("cold_resync::advertised_head(&storage)"));
    }
}
