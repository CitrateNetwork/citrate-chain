// citrate/core/storage/src/fd_limit.rs
//
// The process's open-file limit (RLIMIT_NOFILE) and the RocksDB table-file
// budget derived from it.
//
// macOS starts GUI apps with a soft limit of 256 (`launchctl limit maxfiles`),
// and a node launched by Citrate Core inherits it. RocksDB's default
// `max_open_files = -1` opens every SST at DB::Open and keeps it open, so a
// chain database past ~250 SST files failed every start with
// "IO error: While open a file for random read: …/NNNNNN.sst: Too many open
// files". Two fixes live here:
//
// 1. `raise_nofile_limit`: the node's `main` raises the soft limit toward
//    `TARGET_NOFILE` (never above the hard limit, and on macOS never above
//    `kern.maxfilesperproc`, with an `OPEN_MAX` fallback), before anything
//    opens a file. It never fails start-up.
// 2. `rocksdb_max_open_files`: every RocksDB open bounds its table cache from
//    the limit in effect, so the database opens and runs even when the raise
//    was refused and the limit is still 256.

use std::sync::OnceLock;
use tracing::{info, warn};

/// Soft limit the node asks for at start-up (clamped to what the OS allows).
pub const TARGET_NOFILE: u64 = 65_536;

/// macOS `OPEN_MAX` (<sys/syslimits.h>): the fallback when a raise to
/// `kern.maxfilesperproc` is refused.
pub const DARWIN_OPEN_MAX: u64 = 10_240;

/// RocksDB instances the node process can hold open at the same time, each
/// with its own table cache: the chain database (the DAG store shares its
/// handle through `RocksDbKvStore`) and the canonical-recovery scratch
/// genesis store. The cold-resync read of the moved-aside database is closed
/// before the chain database opens.
pub const ROCKSDB_INSTANCES: u64 = 2;

/// Env var: explicit RocksDB `max_open_files` per database (positive integer;
/// raised to `MIN_MAX_OPEN_FILES`). Unset or unparsable uses the computed value.
pub const MAX_OPEN_FILES_ENV: &str = "CITRATE_ROCKSDB_MAX_OPEN_FILES";

/// Smallest per-database table-file budget. RocksDB itself clamps
/// `max_open_files` below 20 up to 20; 64 keeps the LRU table cache useful.
pub const MIN_MAX_OPEN_FILES: i32 = 64;

/// Largest per-database table-file budget (past this the table cache stops
/// paying for the descriptors it holds).
pub const MAX_MAX_OPEN_FILES: i32 = 8_192;

/// Descriptors always left for everything that is not a table file: sockets
/// (P2P, RPC, WebSocket), logs, sidecar pipes, WAL/MANIFEST/LOCK files and
/// compaction outputs. A quarter of the limit, at least this many.
const MIN_RESERVE: u64 = 128;

/// Soft limit assumed when `getrlimit` fails (the macOS GUI default).
const FALLBACK_SOFT: u64 = 256;

/// One reading of RLIMIT_NOFILE. `hard` is `u64::MAX` for RLIM_INFINITY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NofileLimit {
    pub soft: u64,
    pub hard: u64,
}

/// What `raise_nofile_limit` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaiseReport {
    /// The limit inherited from the parent process (None: getrlimit failed).
    pub before: Option<NofileLimit>,
    /// The limit after the raise (equal to `before` when nothing changed).
    pub after: Option<NofileLimit>,
    /// The per-process cap the raise was clamped to (macOS
    /// `kern.maxfilesperproc`), when one applies.
    pub per_process_cap: Option<u64>,
    /// Refused attempts, in order: (soft value asked for, OS error).
    pub refused: Vec<(u64, String)>,
}

impl RaiseReport {
    /// Log the before and after values (info), and every refused attempt and
    /// a limit left below the target (warn).
    pub fn log(&self) {
        match (self.before, self.after) {
            (Some(b), Some(a)) => info!(
                "open-file limit (RLIMIT_NOFILE): soft {} -> {} (hard {}, per-process cap {}, target {})",
                b.soft,
                a.soft,
                render(a.hard),
                self.per_process_cap.map(render).unwrap_or_else(|| "none".into()),
                TARGET_NOFILE
            ),
            _ => warn!("open-file limit (RLIMIT_NOFILE): getrlimit failed, limit left unchanged"),
        }
        for (asked, err) in &self.refused {
            warn!(
                "open-file limit: setrlimit to soft {} refused: {}",
                asked, err
            );
        }
        if let Some(a) = self.after {
            if a.soft < TARGET_NOFILE.min(a.hard) {
                warn!(
                    "open-file limit stays at {}; RocksDB keeps at most {} table files open per database",
                    a.soft,
                    max_open_files_for(a.soft, ROCKSDB_INSTANCES)
                );
            }
        }
    }
}

fn render(v: u64) -> String {
    if v == u64::MAX {
        "unlimited".into()
    } else {
        v.to_string()
    }
}

/// The soft values to try, best first: the target clamped to the hard limit
/// and the per-process cap, then (macOS) the same clamped to `OPEN_MAX`.
/// Only values above the current soft limit are listed: the limit is never
/// lowered. Pure, so the macOS clamping is tested with injected values.
pub fn raise_plan(
    current: NofileLimit,
    target: u64,
    per_process_cap: Option<u64>,
    open_max: Option<u64>,
) -> Vec<u64> {
    let mut want = target.min(current.hard);
    if let Some(cap) = per_process_cap {
        want = want.min(cap);
    }
    let mut plan = Vec::new();
    if want > current.soft {
        plan.push(want);
    }
    if let Some(om) = open_max {
        let fallback = want.min(om);
        if fallback > current.soft && fallback < want {
            plan.push(fallback);
        }
    }
    plan
}

/// Run `plan` against `set`, stopping at the first accepted value. Returns the
/// accepted value and the refused attempts. `set` is injected so the fallback
/// path is tested without an OS that refuses.
pub fn apply_plan(
    plan: &[u64],
    mut set: impl FnMut(u64) -> Result<(), String>,
) -> (Option<u64>, Vec<(u64, String)>) {
    let mut refused = Vec::new();
    for &v in plan {
        match set(v) {
            Ok(()) => return (Some(v), refused),
            Err(e) => refused.push((v, e)),
        }
    }
    (None, refused)
}

/// Per-database RocksDB `max_open_files` for a soft fd limit shared by
/// `instances` databases: a quarter of the limit (at least 128) is reserved for
/// everything else, the rest is split between the databases, then clamped to
/// [`MIN_MAX_OPEN_FILES`, `MAX_MAX_OPEN_FILES`].
pub fn max_open_files_for(soft: u64, instances: u64) -> i32 {
    let reserve = (soft / 4).max(MIN_RESERVE);
    let per_db = soft
        .saturating_sub(reserve)
        .checked_div(instances.max(1))
        .unwrap_or(0);
    let clamped = per_db.clamp(MIN_MAX_OPEN_FILES as u64, MAX_MAX_OPEN_FILES as u64);
    i32::try_from(clamped).unwrap_or(MAX_MAX_OPEN_FILES)
}

/// `max_open_files` from an env override (positive integer, raised to the
/// floor; anything else ignored) or else from the soft limit.
pub fn max_open_files_from(env: Option<&str>, soft: u64) -> i32 {
    match env.and_then(|raw| raw.trim().parse::<i32>().ok()) {
        Some(v) if v > 0 => v.max(MIN_MAX_OPEN_FILES),
        _ => max_open_files_for(soft, ROCKSDB_INSTANCES),
    }
}

/// The `max_open_files` every RocksDB open in this process uses: the
/// `CITRATE_ROCKSDB_MAX_OPEN_FILES` override, else derived from the soft limit
/// in effect now (after `raise_nofile_limit` in the node).
pub fn rocksdb_max_open_files() -> i32 {
    let soft = current().map(|l| l.soft).unwrap_or(FALLBACK_SOFT);
    max_open_files_from(std::env::var(MAX_OPEN_FILES_ENV).ok().as_deref(), soft)
}

// rlim_t is u64 on every target the node ships for; the conversion keeps a
// 32-bit build compiling.
#[allow(clippy::useless_conversion)]
fn from_rlim(v: libc::rlim_t) -> u64 {
    if v == libc::RLIM_INFINITY {
        u64::MAX
    } else {
        u64::from(v)
    }
}

/// The current RLIMIT_NOFILE, None when getrlimit fails.
pub fn current() -> Option<NofileLimit> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `rl` is a valid, writable rlimit for the duration of the call.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    (rc == 0).then(|| NofileLimit {
        soft: from_rlim(rl.rlim_cur),
        hard: from_rlim(rl.rlim_max),
    })
}

/// Set the soft RLIMIT_NOFILE to `soft`, keeping the hard limit.
#[allow(clippy::unnecessary_fallible_conversions, clippy::useless_conversion)]
pub fn set_soft(soft: u64) -> Result<(), String> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `rl` is a valid, writable rlimit for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    rl.rlim_cur = libc::rlim_t::try_from(soft).map_err(|e| e.to_string())?;
    // SAFETY: `rl` is a valid rlimit; setrlimit only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

/// macOS `kern.maxfilesperproc`: setrlimit refuses a soft limit above it
/// (and refuses RLIM_INFINITY).
#[cfg(target_os = "macos")]
fn per_process_cap() -> Option<u64> {
    let mut val: libc::c_int = 0;
    let mut len: libc::size_t = std::mem::size_of::<libc::c_int>();
    let name = b"kern.maxfilesperproc\0";
    // SAFETY: `name` is NUL-terminated; `val`/`len` are valid and `len` is
    // the size of `val`; no new value is written.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast::<libc::c_char>(),
            (&mut val as *mut libc::c_int).cast::<libc::c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    match (rc, u64::try_from(val)) {
        (0, Ok(v)) if v > 0 => Some(v),
        _ => None,
    }
}

#[cfg(not(target_os = "macos"))]
fn per_process_cap() -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
const OPEN_MAX_FALLBACK: Option<u64> = Some(DARWIN_OPEN_MAX);
#[cfg(not(target_os = "macos"))]
const OPEN_MAX_FALLBACK: Option<u64> = None;

static RAISED: OnceLock<RaiseReport> = OnceLock::new();

/// Raise the soft RLIMIT_NOFILE toward [`TARGET_NOFILE`], once per process
/// (later calls return the first report). Never fails: a refused raise is
/// recorded in the report and the limit stays as it was. Call it first in
/// `main`, then [`RaiseReport::log`] once logging is up.
pub fn raise_nofile_limit() -> &'static RaiseReport {
    RAISED.get_or_init(|| {
        let cap = per_process_cap();
        let Some(before) = current() else {
            return RaiseReport {
                before: None,
                after: None,
                per_process_cap: cap,
                refused: Vec::new(),
            };
        };
        let plan = raise_plan(before, TARGET_NOFILE, cap, OPEN_MAX_FALLBACK);
        let (_, refused) = apply_plan(&plan, set_soft);
        RaiseReport {
            before: Some(before),
            after: current().or(Some(before)),
            per_process_cap: cap,
            refused,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim(soft: u64, hard: u64) -> NofileLimit {
        NofileLimit { soft, hard }
    }

    #[test]
    fn linux_raises_to_the_target_within_the_hard_limit() {
        assert_eq!(
            raise_plan(lim(1024, 1_048_576), TARGET_NOFILE, None, None),
            vec![65_536]
        );
        // Hard below the target: up to the hard limit.
        assert_eq!(
            raise_plan(lim(1024, 4096), TARGET_NOFILE, None, None),
            vec![4096]
        );
        // Unlimited hard: the target, never RLIM_INFINITY.
        assert_eq!(
            raise_plan(lim(256, u64::MAX), TARGET_NOFILE, None, None),
            vec![65_536]
        );
    }

    #[test]
    fn never_lowers_the_soft_limit() {
        assert!(raise_plan(lim(100_000, u64::MAX), TARGET_NOFILE, None, None).is_empty());
        assert!(raise_plan(lim(65_536, 65_536), TARGET_NOFILE, None, None).is_empty());
        assert!(raise_plan(lim(256, 256), TARGET_NOFILE, Some(10_240), Some(10_240)).is_empty());
    }

    /// macOS: GUI soft 256, hard unlimited, kern.maxfilesperproc caps the ask;
    /// OPEN_MAX is the fallback after a refusal.
    #[test]
    fn macos_clamps_to_maxfilesperproc_then_open_max() {
        // maxfilesperproc 24576 (a common Apple-silicon value): ask 24576, then 10240.
        assert_eq!(
            raise_plan(
                lim(256, u64::MAX),
                TARGET_NOFILE,
                Some(24_576),
                Some(DARWIN_OPEN_MAX)
            ),
            vec![24_576, 10_240]
        );
        // maxfilesperproc below OPEN_MAX: one ask, no fallback above it.
        assert_eq!(
            raise_plan(
                lim(256, u64::MAX),
                TARGET_NOFILE,
                Some(4096),
                Some(DARWIN_OPEN_MAX)
            ),
            vec![4096]
        );
        // Hard limit below everything else wins.
        assert_eq!(
            raise_plan(
                lim(256, 2048),
                TARGET_NOFILE,
                Some(24_576),
                Some(DARWIN_OPEN_MAX)
            ),
            vec![2048]
        );
        // No sysctl reading: target, then OPEN_MAX.
        assert_eq!(
            raise_plan(
                lim(256, u64::MAX),
                TARGET_NOFILE,
                None,
                Some(DARWIN_OPEN_MAX)
            ),
            vec![65_536, 10_240]
        );
    }

    #[test]
    fn a_refused_raise_falls_back_and_never_errors() {
        let plan = raise_plan(
            lim(256, u64::MAX),
            TARGET_NOFILE,
            Some(24_576),
            Some(10_240),
        );
        // The first ask is refused (EINVAL, as macOS does above its cap).
        let mut asked = Vec::new();
        let (ok, refused) = apply_plan(&plan, |v| {
            asked.push(v);
            if v > 10_240 {
                Err("Invalid argument (os error 22)".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(ok, Some(10_240));
        assert_eq!(asked, vec![24_576, 10_240]);
        assert_eq!(refused.len(), 1);
        // Everything refused: no value, every refusal recorded, no panic.
        let (ok, refused) = apply_plan(&plan, |_| Err("refused".into()));
        assert_eq!(ok, None);
        assert_eq!(refused.len(), 2);
    }

    #[test]
    fn max_open_files_leaves_a_reserve_and_is_bounded() {
        // macOS GUI default: 128 reserved, 64 per database.
        assert_eq!(max_open_files_for(256, 2), 64);
        // Tiny or failed limits still give the floor.
        assert_eq!(max_open_files_for(0, 2), MIN_MAX_OPEN_FILES);
        assert_eq!(max_open_files_for(100, 2), MIN_MAX_OPEN_FILES);
        // OPEN_MAX: a quarter reserved, the rest split.
        assert_eq!(max_open_files_for(10_240, 2), 3840);
        assert_eq!(max_open_files_for(1024, 2), 384);
        // Large limits hit the cap.
        assert_eq!(max_open_files_for(65_536, 2), MAX_MAX_OPEN_FILES);
        assert_eq!(max_open_files_for(u64::MAX, 2), MAX_MAX_OPEN_FILES);
        // Zero instances is treated as one.
        assert_eq!(max_open_files_for(1024, 0), 768);
        // Every database's budget plus the reserve fits in the limit once
        // the limit is above the floor.
        for soft in [512u64, 1024, 4096, 10_240, 24_576] {
            let per = max_open_files_for(soft, ROCKSDB_INSTANCES) as u64;
            assert!(per * ROCKSDB_INSTANCES + MIN_RESERVE <= soft, "soft {soft}");
        }
    }

    #[test]
    fn max_open_files_env_override() {
        assert_eq!(max_open_files_from(None, 256), 64);
        assert_eq!(max_open_files_from(Some(" 500 "), 256), 500);
        assert_eq!(max_open_files_from(Some("10"), 256), MIN_MAX_OPEN_FILES);
        // -1 (RocksDB's keep-everything-open) and junk are ignored.
        assert_eq!(max_open_files_from(Some("-1"), 256), 64);
        assert_eq!(max_open_files_from(Some("0"), 256), 64);
        assert_eq!(max_open_files_from(Some("lots"), 10_240), 3840);
    }

    const RAISE_CHILD: &str = "CITRATE_FD_LIMIT_RAISE_CHILD";

    /// The real raise, in a child process started at the macOS GUI soft limit
    /// of 256: the soft limit goes up (within the hard limit), the report
    /// carries before/after, and a second call returns the same report.
    #[test]
    fn raise_lifts_a_256_soft_limit() {
        if std::env::var(RAISE_CHILD).is_ok() {
            set_soft(256).expect("lower soft limit to 256");
            let report = raise_nofile_limit();
            let before = report.before.expect("getrlimit");
            let after = report.after.expect("getrlimit");
            assert_eq!(before.soft, 256);
            let expect = TARGET_NOFILE.min(after.hard);
            if expect > 256 {
                assert!(after.soft > 256, "soft limit not raised: {report:?}");
                assert!(after.soft <= expect);
            }
            assert_eq!(current().map(|l| l.soft), Some(after.soft));
            assert!(std::ptr::eq(report, raise_nofile_limit()));
            report.log();
            return;
        }
        let exe = std::env::current_exe().expect("test binary");
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "fd_limit::tests::raise_lifts_a_256_soft_limit",
                "--nocapture",
            ])
            .env(RAISE_CHILD, "1")
            .output()
            .expect("run child");
        assert!(
            out.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "the child ran the test"
        );
    }
}
