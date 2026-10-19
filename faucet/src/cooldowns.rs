//! Per-address + per-IP cooldown tracker with on-disk persistence.
//!
//! RM-B1 / WP-E6.3 (audit FAU-04): pre-fix the faucet kept
//! `address_cooldown` in a `DashMap` that vanished on every
//! restart. An attacker that crashed the faucet (or just waited
//! for a deploy) could keep dripping forever. Post-fix the state
//! is loaded from disk on startup and re-persisted after every
//! successful drip; restart no longer launders the cooldown.
//!
//! Storage format: a single JSON file on disk with two maps.
//! Per-address keyed by the lowercase hex address (no 0x prefix);
//! per-IP keyed by the canonical string form of the address. Each
//! value is the Unix-seconds timestamp of the last successful drip.
//! On Unix the file is written with mode 0600.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

/// Persisted cooldown record. Time is wall-clock (Unix seconds) so
/// it survives across process restarts where `Instant` would not.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CooldownState {
    pub address_last: HashMap<String, u64>,
    pub ip_last: HashMap<String, u64>,
}

/// Per-deployment cooldown policy. Defaults match the user-facing
/// `/` page: 24h per address, 1h per IP.
#[derive(Debug, Clone)]
pub struct CooldownPolicy {
    pub address_cooldown_secs: u64,
    pub ip_cooldown_secs: u64,
}

impl Default for CooldownPolicy {
    fn default() -> Self {
        Self {
            address_cooldown_secs: 24 * 3600,
            ip_cooldown_secs: 3600,
        }
    }
}

/// Shortest cooldown accepted from the environment (a typo guard, not a policy).
pub const MIN_COOLDOWN_SECS: u64 = 60;
/// Longest cooldown accepted from the environment: 30 days (a typo guard, not a policy).
pub const MAX_COOLDOWN_SECS: u64 = 30 * 24 * 3600;

/// Parse one cooldown variable. Unset or blank: `Ok(default)`. Anything that is not a whole
/// number of seconds from [`MIN_COOLDOWN_SECS`] to [`MAX_COOLDOWN_SECS`] is a startup error, never
/// silently replaced by the default.
fn parse_cooldown(name: &str, raw: Option<&str>, default: u64) -> Result<u64, String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(default);
    };
    let secs: u64 = s
        .parse()
        .map_err(|_| format!("{name} must be a whole number of seconds, got {s:?}"))?;
    if !(MIN_COOLDOWN_SECS..=MAX_COOLDOWN_SECS).contains(&secs) {
        return Err(format!(
            "{name} must be {MIN_COOLDOWN_SECS} to {MAX_COOLDOWN_SECS} seconds, got {secs}"
        ));
    }
    Ok(secs)
}

impl CooldownPolicy {
    /// G4 (genesis faucet policy): the per-address and per-IP windows from
    /// `FAUCET_ADDRESS_COOLDOWN_SECS` and `FAUCET_IP_COOLDOWN_SECS`. Each one unset keeps its
    /// default (24 h per address, 1 h per IP), so an operator who sets neither gets exactly the
    /// behaviour before this change. One drip per address per window is the per-address cap.
    pub fn from_env(address_raw: Option<&str>, ip_raw: Option<&str>) -> Result<Self, String> {
        let d = CooldownPolicy::default();
        Ok(CooldownPolicy {
            address_cooldown_secs: parse_cooldown(
                "FAUCET_ADDRESS_COOLDOWN_SECS",
                address_raw,
                d.address_cooldown_secs,
            )?,
            ip_cooldown_secs: parse_cooldown(
                "FAUCET_IP_COOLDOWN_SECS",
                ip_raw,
                d.ip_cooldown_secs,
            )?,
        })
    }
}

/// Reasons a drip can be denied by the cooldown layer.
#[derive(Debug, Clone)]
pub enum CooldownDenial {
    AddressCooldown {
        remaining_secs: u64,
    },
    IpCooldown {
        remaining_secs: u64,
    },
    /// Required-gates mode only: the cooldown file cannot be written, so no window can be kept.
    PersistenceUnavailable,
}

/// File-backed cooldown tracker. Thread-safe via interior `RwLock`.
pub struct Cooldowns {
    state: RwLock<CooldownState>,
    file: Option<PathBuf>,
    policy: CooldownPolicy,
    /// G4 required-gates mode: persistence is part of the policy, so a failed write stops new
    /// reservations until a write succeeds again (fail closed).
    persistence_required: bool,
    /// False after a failed write while `persistence_required` is on.
    persistence_ok: AtomicBool,
    /// Serialises every disk write (success path and recovery path). The snapshot is taken
    /// while this is held, so writes land in snapshot order and a later write never publishes
    /// an older state than an earlier one.
    persist_lock: Mutex<()>,
}

impl Cooldowns {
    /// In-memory tracker (used by tests and dev mode without
    /// `FAUCET_COOLDOWN_FILE` set).
    pub fn in_memory(policy: CooldownPolicy) -> Self {
        Self {
            state: RwLock::new(CooldownState::default()),
            file: None,
            policy,
            persistence_required: false,
            persistence_ok: AtomicBool::new(true),
            persist_lock: Mutex::new(()),
        }
    }

    /// File-backed tracker. Loads any existing state at construct
    /// time; writes to disk on every successful drip via
    /// `record_success`.
    pub fn with_file(path: PathBuf, policy: CooldownPolicy) -> Self {
        let initial = load_from_disk(&path);
        Self {
            state: RwLock::new(initial),
            file: Some(path),
            policy,
            persistence_required: false,
            persistence_ok: AtomicBool::new(true),
            persist_lock: Mutex::new(()),
        }
    }

    /// G4 required-gates mode: a file-backed tracker whose persistence is verified before the
    /// faucet serves anything. A missing file starts empty; any other read error, a path that is
    /// not a regular file, or content that does not parse is a startup error (never "start
    /// empty"). The loaded state is then written back once, so an unwritable location also fails
    /// at startup. After startup, a failed write makes [`Self::try_reserve`] refuse with
    /// [`CooldownDenial::PersistenceUnavailable`] until a later write succeeds.
    pub fn with_file_required(path: PathBuf, policy: CooldownPolicy) -> Result<Self, String> {
        let initial = load_from_disk_strict(&path)?;
        persist_to_disk(&path, &initial).map_err(|e| {
            format!(
                "FAUCET_COOLDOWN_FILE {} is not writable: {e}",
                path.display()
            )
        })?;
        Ok(Self {
            state: RwLock::new(initial),
            file: Some(path),
            policy,
            persistence_required: true,
            persistence_ok: AtomicBool::new(true),
            persist_lock: Mutex::new(()),
        })
    }

    /// False only in required-gates mode after a persistence write failed and no later write has
    /// succeeded.
    pub fn persistence_ok(&self) -> bool {
        self.persistence_ok.load(Ordering::SeqCst)
    }

    /// In required-gates mode with persistence down, try one write of the current state; on
    /// success the tracker is healthy again.
    fn recover_persistence(&self) -> bool {
        if self.persistence_ok() {
            return true;
        }
        let Some(path) = self.file.as_ref() else {
            return true;
        };
        let _writer = self
            .persist_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.persistence_ok() {
            // Another writer restored persistence while this one waited.
            return true;
        }
        let snapshot = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match persist_to_disk(path, &snapshot) {
            Ok(()) => {
                self.persistence_ok.store(true, Ordering::SeqCst);
                tracing::info!("faucet cooldown: persistence restored");
                true
            }
            Err(_) => false,
        }
    }

    /// Check whether a drip is allowed for `(address, ip)` right
    /// now. Returns `Ok(())` or the specific cooldown denial.
    ///
    /// SECREM-01 FAUCET-1: read-only — does NOT claim the slot. The
    /// drip path must use [`Self::try_reserve`] instead; check-then-
    /// send-then-record leaves an RPC round-trip between the check
    /// and the record, during which N concurrent requests for the
    /// same address all pass. Retained as a read-only probe (used by
    /// tests); `#[allow(dead_code)]` because the bin's production path
    /// now goes through `try_reserve`.
    #[allow(dead_code)]
    pub fn check(&self, address: &str, ip: &str) -> Result<(), CooldownDenial> {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        check_in_state(&state, &self.policy, address, ip, unix_seconds())
    }

    /// SECREM-01 FAUCET-1: atomically check AND claim the cooldown
    /// slot under one write lock — concurrent requests for the same
    /// address/IP see the reservation immediately, so exactly one
    /// in-flight drip can hold it. On send failure the caller MUST
    /// call [`Self::release`] to return the slot; on success,
    /// [`Self::record_success`] re-stamps and persists it.
    ///
    /// The reservation is in-memory only (not persisted): a crash
    /// between reserve and outcome forgets the reservation, which
    /// matches the pre-fix exposure and only risks one extra drip.
    pub fn try_reserve(&self, address: &str, ip: &str) -> Result<(), CooldownDenial> {
        if self.persistence_required && !self.recover_persistence() {
            return Err(CooldownDenial::PersistenceUnavailable);
        }
        let now = unix_seconds();
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        check_in_state(&state, &self.policy, address, ip, now)?;
        state.address_last.insert(address_key(address), now);
        state.ip_last.insert(ip.to_string(), now);
        Ok(())
    }

    /// SECREM-01 FAUCET-1: return a reserved slot after a failed
    /// send so the user can retry. Removes the in-memory entries for
    /// this (address, ip); safe because while the reservation is
    /// held no other request can have claimed the same keys.
    pub fn release(&self, address: &str, ip: &str) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.address_last.remove(&address_key(address));
        state.ip_last.remove(ip);
    }

    /// Record a successful drip and persist. Caller must have
    /// already passed `check`.
    pub fn record_success(&self, address: &str, ip: &str) {
        let now = unix_seconds();
        {
            let mut state = self
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.address_last.insert(address_key(address), now);
            state.ip_last.insert(ip.to_string(), now);
        }
        let Some(path) = self.file.as_ref() else {
            return;
        };
        // One writer at a time; the snapshot is taken under the writer lock so it contains every
        // record completed before this write started (including ones whose own write is queued
        // behind this one).
        let _writer = self
            .persist_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snapshot = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match persist_to_disk(path, &snapshot) {
            Ok(()) => {}
            Err(e) if self.persistence_required => {
                self.persistence_ok.store(false, Ordering::SeqCst);
                tracing::error!(
                    "faucet cooldown: persist failed, refusing new drips until it succeeds: {}",
                    e
                );
            }
            Err(e) => warn!("faucet cooldown: persist failed: {}", e),
        }
    }

    /// Public for tests + future ops endpoints; the bin doesn't currently
    /// reach into the policy after construction.
    #[allow(dead_code)]
    pub fn policy(&self) -> &CooldownPolicy {
        &self.policy
    }
}

/// Shared cooldown evaluation used by both the read-only `check` and
/// the atomic `try_reserve` (single source of truth for the policy).
fn check_in_state(
    state: &CooldownState,
    policy: &CooldownPolicy,
    address: &str,
    ip: &str,
    now: u64,
) -> Result<(), CooldownDenial> {
    if let Some(&last) = state.address_last.get(&address_key(address)) {
        let elapsed = now.saturating_sub(last);
        if elapsed < policy.address_cooldown_secs {
            return Err(CooldownDenial::AddressCooldown {
                remaining_secs: policy.address_cooldown_secs.saturating_sub(elapsed),
            });
        }
    }
    if let Some(&last) = state.ip_last.get(ip) {
        let elapsed = now.saturating_sub(last);
        if elapsed < policy.ip_cooldown_secs {
            return Err(CooldownDenial::IpCooldown {
                remaining_secs: policy.ip_cooldown_secs.saturating_sub(elapsed),
            });
        }
    }
    Ok(())
}

fn address_key(addr: &str) -> String {
    addr.to_lowercase().trim_start_matches("0x").to_string()
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_from_disk(path: &PathBuf) -> CooldownState {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return CooldownState::default();
        }
        Err(e) => {
            warn!(
                "faucet cooldown: couldn't read {}, starting empty: {}",
                path.display(),
                e
            );
            return CooldownState::default();
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "faucet cooldown: file {} is corrupt, starting empty: {}",
                path.display(),
                e
            );
            CooldownState::default()
        }
    }
}

/// Strict load for required-gates mode: only a missing file means "start empty".
fn load_from_disk_strict(path: &PathBuf) -> Result<CooldownState, String> {
    match std::fs::metadata(path) {
        Ok(m) if !m.is_file() => {
            return Err(format!(
                "FAUCET_COOLDOWN_FILE {} is not a regular file",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CooldownState::default());
        }
        Err(e) => {
            return Err(format!(
                "FAUCET_COOLDOWN_FILE {} cannot be read: {e}",
                path.display()
            ));
        }
    }
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "FAUCET_COOLDOWN_FILE {} cannot be read: {e}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "FAUCET_COOLDOWN_FILE {} is not valid cooldown state ({e}); fix or move it before \
             starting with FAUCET_REQUIRE_GATES on",
            path.display()
        )
    })
}

/// Distinguishes temporary files of writes within one process.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write the state to a fresh, exclusively created sibling temporary file (mode 0600 on Unix),
/// fsync it, rename it over `path`, then fsync the directory, so a crash mid-write never leaves a
/// truncated file behind and no two writes ever share a temporary inode. Callers inside
/// [`Cooldowns`] additionally serialise writes through `persist_lock`.
fn persist_to_disk(path: &PathBuf, state: &CooldownState) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    if path.is_dir() {
        return Err(std::io::Error::other(format!(
            "{} is a directory",
            path.display()
        )));
    }
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = PathBuf::from(tmp_name);
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        // create_new: never open (and truncate) a file another writer may still hold.
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            let dir = if parent.as_os_str().is_empty() {
                std::path::Path::new(".")
            } else {
                parent
            };
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    };
    let result = write();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

// Manual `Debug` impl for `CooldownDenial` — derived would suffice
// but spelling it out makes panic messages stable.
impl std::fmt::Display for CooldownDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressCooldown { remaining_secs } => write!(
                f,
                "address cooldown: {}h {}m remaining",
                remaining_secs / 3600,
                (remaining_secs % 3600) / 60
            ),
            Self::IpCooldown { remaining_secs } => write!(
                f,
                "ip cooldown: {}h {}m remaining",
                remaining_secs / 3600,
                (remaining_secs % 3600) / 60
            ),
            Self::PersistenceUnavailable => write!(f, "cooldown persistence unavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn g4_policy_from_env_defaults_when_unset() {
        let p = CooldownPolicy::from_env(None, Some("  ")).expect("ok");
        assert_eq!(p.address_cooldown_secs, 24 * 3600);
        assert_eq!(p.ip_cooldown_secs, 3600);
    }

    #[test]
    fn g4_policy_from_env_reads_both_windows() {
        let p = CooldownPolicy::from_env(Some(" 172800 "), Some("600")).expect("ok");
        assert_eq!(p.address_cooldown_secs, 172_800);
        assert_eq!(p.ip_cooldown_secs, 600);
    }

    #[test]
    fn g4_policy_from_env_rejects_bad_values() {
        for bad in ["0", "59", "-1", "1h", "1.5", "2592001"] {
            let e = CooldownPolicy::from_env(Some(bad), None).expect_err(bad);
            assert!(e.contains("FAUCET_ADDRESS_COOLDOWN_SECS"), "{e}");
            let e = CooldownPolicy::from_env(None, Some(bad)).expect_err(bad);
            assert!(e.contains("FAUCET_IP_COOLDOWN_SECS"), "{e}");
        }
        // The bounds themselves are accepted.
        CooldownPolicy::from_env(Some("60"), Some("2592000")).expect("bounds");
    }

    #[test]
    fn g4_configured_address_window_is_enforced() {
        let policy = CooldownPolicy::from_env(Some("7200"), Some("60")).expect("ok");
        let cd = Cooldowns::in_memory(policy);
        cd.try_reserve("0xabc", "1.1.1.1").expect("first");
        match cd.try_reserve("0xabc", "2.2.2.2") {
            Err(CooldownDenial::AddressCooldown { remaining_secs }) => {
                assert!(
                    remaining_secs > 7000 && remaining_secs <= 7200,
                    "{remaining_secs}"
                );
            }
            other => panic!("expected address cooldown, got {other:?}"),
        }
    }

    #[test]
    fn test_first_request_passes() {
        let cd = Cooldowns::in_memory(CooldownPolicy::default());
        cd.check("0xabc", "1.2.3.4").expect("first request OK");
    }

    #[test]
    fn test_address_cooldown_blocks_second() {
        let cd = Cooldowns::in_memory(CooldownPolicy::default());
        cd.record_success("0xabc", "1.2.3.4");
        match cd.check("0xabc", "5.6.7.8").expect_err("second blocked") {
            CooldownDenial::AddressCooldown { remaining_secs } => {
                assert!(remaining_secs <= 24 * 3600);
                assert!(remaining_secs > 0);
            }
            other => panic!("expected AddressCooldown, got {:?}", other),
        }
    }

    #[test]
    fn test_ip_cooldown_blocks_when_only_ip_matches() {
        let cd = Cooldowns::in_memory(CooldownPolicy::default());
        cd.record_success("0xabc", "1.2.3.4");
        match cd.check("0xdef", "1.2.3.4").expect_err("ip blocked") {
            CooldownDenial::IpCooldown { remaining_secs } => {
                assert!(remaining_secs <= 3600);
                assert!(remaining_secs > 0);
            }
            other => panic!("expected IpCooldown, got {:?}", other),
        }
    }

    #[test]
    fn test_disjoint_address_and_ip_pass() {
        let cd = Cooldowns::in_memory(CooldownPolicy::default());
        cd.record_success("0xabc", "1.2.3.4");
        cd.check("0xdef", "5.6.7.8").expect("disjoint OK");
    }

    #[test]
    fn test_address_match_is_case_insensitive_and_prefix_tolerant() {
        let cd = Cooldowns::in_memory(CooldownPolicy::default());
        cd.record_success("0xABCDEF", "1.2.3.4");
        // Same address, different casing + missing 0x prefix.
        cd.check("abcdef", "5.6.7.8")
            .expect_err("same address rejects");
    }

    /// FAU-04 core: persistence survives "process restart".
    #[test]
    fn test_persistence_round_trip() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("cooldowns.json");

        let cd1 = Cooldowns::with_file(path.clone(), CooldownPolicy::default());
        cd1.record_success("0xabc", "1.2.3.4");
        // Fresh tracker pointing at the same file.
        let cd2 = Cooldowns::with_file(path.clone(), CooldownPolicy::default());
        match cd2
            .check("0xabc", "5.6.7.8")
            .expect_err("blocked after restart")
        {
            CooldownDenial::AddressCooldown { .. } => {}
            other => panic!("expected AddressCooldown, got {:?}", other),
        }
    }

    #[test]
    fn test_persistence_corrupt_file_starts_empty() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("cooldowns.json");
        std::fs::write(&path, b"not-json").expect("write garbage");
        let cd = Cooldowns::with_file(path, CooldownPolicy::default());
        cd.check("0xabc", "1.2.3.4")
            .expect("starts empty after corruption");
    }

    /// G4 required gates: a directory is not a cooldown file.
    #[test]
    fn g4_required_rejects_directory_path() {
        let tmp = TempDir::new().expect("tempdir");
        let err =
            Cooldowns::with_file_required(tmp.path().to_path_buf(), CooldownPolicy::default())
                .err()
                .expect("directory must be rejected");
        assert!(err.contains("not a regular file"), "{err}");
    }

    /// G4 required gates: corrupt state stops startup instead of resetting every window.
    #[test]
    fn g4_required_rejects_corrupt_state() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("cooldowns.json");
        std::fs::write(&path, b"not-json").expect("write garbage");
        let err = Cooldowns::with_file_required(path.clone(), CooldownPolicy::default())
            .err()
            .expect("corrupt state must be rejected");
        assert!(err.contains("not valid cooldown state"), "{err}");
        // The corrupt file is left for the operator, not overwritten.
        assert_eq!(std::fs::read(&path).expect("still there"), b"not-json");
    }

    /// G4 required gates: a missing file is fine (first start) and is created at startup.
    #[test]
    fn g4_required_missing_file_starts_empty_and_is_created() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("sub").join("cooldowns.json");
        let cd = Cooldowns::with_file_required(path.clone(), CooldownPolicy::default())
            .expect("missing file is a fresh start");
        assert!(path.is_file(), "startup write probe created the file");
        cd.check("0xabc", "1.2.3.4").expect("empty");
        cd.record_success("0xabc", "1.2.3.4");
        let cd2 = Cooldowns::with_file_required(path, CooldownPolicy::default())
            .expect("reload persisted state");
        cd2.check("0xabc", "9.9.9.9")
            .expect_err("window survives restart");
    }

    /// G4 required gates: an unwritable location fails at startup.
    #[test]
    fn g4_required_rejects_unwritable_location() {
        let tmp = TempDir::new().expect("tempdir");
        // The parent "directory" is a regular file, so nothing can be created beneath it.
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"x").expect("write blocker");
        let err = Cooldowns::with_file_required(
            blocker.join("cooldowns.json"),
            CooldownPolicy::default(),
        )
        .err()
        .expect("unwritable path must be rejected");
        assert!(
            err.contains("not writable") || err.contains("cannot be read"),
            "{err}"
        );
    }

    /// G4 required gates: a write failure after startup closes the faucet until a write works.
    #[test]
    fn g4_required_write_failure_fails_closed_then_recovers() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("cooldowns.json");
        let cd =
            Cooldowns::with_file_required(path.clone(), CooldownPolicy::default()).expect("start");
        assert!(cd.persistence_ok());
        // Make the next write fail: replace the file with a directory.
        std::fs::remove_file(&path).expect("rm");
        std::fs::create_dir(&path).expect("mkdir in its place");
        cd.try_reserve("0xabc", "1.2.3.4")
            .expect("reserve while healthy");
        cd.record_success("0xabc", "1.2.3.4");
        assert!(!cd.persistence_ok(), "failed write is noticed");
        match cd.try_reserve("0xdef", "5.6.7.8") {
            Err(CooldownDenial::PersistenceUnavailable) => {}
            other => panic!("expected PersistenceUnavailable, got {:?}", other),
        }
        // Repair the path: the next reservation writes successfully and proceeds.
        std::fs::remove_dir(&path).expect("rmdir");
        cd.try_reserve("0xdef", "5.6.7.8")
            .expect("recovered after the path is writable again");
        assert!(cd.persistence_ok());
    }

    /// The non-required tracker keeps its old behaviour: write failures never block drips.
    #[test]
    fn g4_optional_write_failure_does_not_block() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("cooldowns.json");
        std::fs::create_dir(&path).expect("dir in place of file");
        let cd = Cooldowns::with_file(path, CooldownPolicy::default());
        cd.record_success("0xabc", "1.2.3.4");
        cd.try_reserve("0xdef", "5.6.7.8")
            .expect("not fail-closed when optional");
    }

    #[cfg(unix)]
    #[test]
    fn test_persisted_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("cooldowns.json");
        let cd = Cooldowns::with_file(path.clone(), CooldownPolicy::default());
        cd.record_success("0xabc", "1.2.3.4");
        let mode = std::fs::metadata(&path)
            .expect("file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// SECREM-01 FAUCET-1 red test: pre-fix, N concurrent requests for
    /// one address all passed `check` before any `record_success` (the
    /// RPC round-trip sat between them). With `try_reserve`, exactly
    /// one of N concurrent reservations can win.
    #[test]
    fn test_faucet1_concurrent_reservations_only_one_wins() {
        use std::sync::Arc;
        let cd = Arc::new(Cooldowns::in_memory(CooldownPolicy::default()));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let cd = cd.clone();
            handles.push(std::thread::spawn(move || {
                cd.try_reserve("0xabc", "1.2.3.4").is_ok()
            }));
        }
        let wins = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(
            wins, 1,
            "FAUCET-1 regression: {wins} concurrent requests passed the cooldown gate"
        );
    }

    /// Concurrent successful drips persist without corrupting the file: every write goes through
    /// one writer with its own temporary file, the final file is valid JSON holding every
    /// completed cooldown, and no temporary file is left behind.
    #[test]
    fn g4_concurrent_persistence_keeps_every_cooldown() {
        use std::sync::Arc;
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("cooldowns.json");
        let cd = Arc::new(
            Cooldowns::with_file_required(path.clone(), CooldownPolicy::default()).expect("start"),
        );
        const THREADS: usize = 16;
        const PER_THREAD: usize = 8;
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let cd = cd.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for i in 0..PER_THREAD {
                        let addr = format!("0x{t:02x}{i:02x}");
                        let ip = format!("10.0.{t}.{i}");
                        cd.try_reserve(&addr, &ip).expect("distinct keys reserve");
                        cd.record_success(&addr, &ip);
                        // Exercise the recovery writer concurrently too.
                        assert!(cd.recover_persistence());
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread");
        }
        assert!(cd.persistence_ok(), "no write failed");
        let on_disk = load_from_disk_strict(&path).expect("valid JSON on disk");
        assert_eq!(on_disk.address_last.len(), THREADS * PER_THREAD);
        assert_eq!(on_disk.ip_last.len(), THREADS * PER_THREAD);
        for t in 0..THREADS {
            for i in 0..PER_THREAD {
                assert!(on_disk
                    .address_last
                    .contains_key(&address_key(&format!("0x{t:02x}{i:02x}"))));
                assert!(on_disk.ip_last.contains_key(&format!("10.0.{t}.{i}")));
            }
        }
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .filter(|n| n != "cooldowns.json")
            .collect();
        assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");
        // A restart sees every cooldown.
        let reloaded =
            Cooldowns::with_file_required(path, CooldownPolicy::default()).expect("restart");
        assert!(matches!(
            reloaded.check("0x0000", "192.0.2.1"),
            Err(CooldownDenial::AddressCooldown { .. })
        ));
    }

    /// Two independent writers (e.g. two trackers on one path) never share a temporary file:
    /// each publishes a complete document.
    #[test]
    fn g4_persist_uses_a_unique_temporary_file_per_write() {
        use std::sync::Arc;
        let tmp = TempDir::new().expect("tempdir");
        let path = Arc::new(tmp.path().join("cooldowns.json"));
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let mut st = CooldownState::default();
                    for i in 0..200 {
                        st.address_last.insert(format!("{t:02x}{i:04x}"), i);
                    }
                    for _ in 0..20 {
                        persist_to_disk(&path, &st).expect("write");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread");
        }
        let on_disk = load_from_disk_strict(&path).expect("valid JSON");
        assert_eq!(
            on_disk.address_last.len(),
            200,
            "one writer's complete document"
        );
    }

    /// SECREM-01 FAUCET-1: a failed send releases the slot so the user
    /// can retry; a successful send keeps it claimed.
    #[test]
    fn test_faucet1_release_returns_slot_success_keeps_it() {
        let cd = Cooldowns::in_memory(CooldownPolicy::default());
        cd.try_reserve("0xabc", "1.2.3.4").expect("first reserve");
        cd.check("0xabc", "1.2.3.4")
            .expect_err("slot held while reserved");
        cd.release("0xabc", "1.2.3.4");
        cd.try_reserve("0xabc", "1.2.3.4")
            .expect("reserve again after release");
        cd.record_success("0xabc", "1.2.3.4");
        cd.check("0xabc", "5.6.7.8")
            .expect_err("claimed after success");
    }

    /// Tight policy: zero cooldown means every request passes.
    /// Tests that the policy is honored, not hard-coded.
    #[test]
    fn test_zero_policy_passes_everything() {
        let cd = Cooldowns::in_memory(CooldownPolicy {
            address_cooldown_secs: 0,
            ip_cooldown_secs: 0,
        });
        cd.record_success("0xabc", "1.2.3.4");
        cd.check("0xabc", "1.2.3.4")
            .expect("zero policy = no cooldown");
    }
}
