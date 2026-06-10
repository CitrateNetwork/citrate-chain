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
use std::sync::RwLock;
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

/// Reasons a drip can be denied by the cooldown layer.
#[derive(Debug, Clone)]
pub enum CooldownDenial {
    AddressCooldown { remaining_secs: u64 },
    IpCooldown { remaining_secs: u64 },
}

/// File-backed cooldown tracker. Thread-safe via interior `RwLock`.
pub struct Cooldowns {
    state: RwLock<CooldownState>,
    file: Option<PathBuf>,
    policy: CooldownPolicy,
}

impl Cooldowns {
    /// In-memory tracker (used by tests and dev mode without
    /// `FAUCET_COOLDOWN_FILE` set).
    pub fn in_memory(policy: CooldownPolicy) -> Self {
        Self {
            state: RwLock::new(CooldownState::default()),
            file: None,
            policy,
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
        }
    }

    /// Check whether a drip is allowed for `(address, ip)` right
    /// now. Returns `Ok(())` or the specific cooldown denial.
    ///
    /// SECREM-01 FAUCET-1: read-only — does NOT claim the slot. The
    /// drip path must use [`Self::try_reserve`] instead; check-then-
    /// send-then-record leaves an RPC round-trip between the check
    /// and the record, during which N concurrent requests for the
    /// same address all pass.
    pub fn check(&self, address: &str, ip: &str) -> Result<(), CooldownDenial> {
        let state = self.state.read().expect("cooldown lock poisoned");
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
        let now = unix_seconds();
        let mut state = self.state.write().expect("cooldown lock poisoned");
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
        let mut state = self.state.write().expect("cooldown lock poisoned");
        state.address_last.remove(&address_key(address));
        state.ip_last.remove(ip);
    }

    /// Record a successful drip and persist. Caller must have
    /// already passed `check`.
    pub fn record_success(&self, address: &str, ip: &str) {
        let now = unix_seconds();
        let snapshot = {
            let mut state = self.state.write().expect("cooldown lock poisoned");
            state.address_last.insert(address_key(address), now);
            state.ip_last.insert(ip.to_string(), now);
            state.clone()
        };
        if let Some(path) = self.file.as_ref() {
            if let Err(e) = persist_to_disk(path, &snapshot) {
                warn!("faucet cooldown: persist failed: {}", e);
            }
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
                remaining_secs: policy.address_cooldown_secs - elapsed,
            });
        }
    }
    if let Some(&last) = state.ip_last.get(ip) {
        let elapsed = now.saturating_sub(last);
        if elapsed < policy.ip_cooldown_secs {
            return Err(CooldownDenial::IpCooldown {
                remaining_secs: policy.ip_cooldown_secs - elapsed,
            });
        }
    }
    Ok(())
}

fn address_key(addr: &str) -> String {
    addr.to_lowercase()
        .trim_start_matches("0x")
        .to_string()
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

fn persist_to_disk(path: &PathBuf, state: &CooldownState) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
        cd.check("abcdef", "5.6.7.8").expect_err("same address rejects");
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
        match cd2.check("0xabc", "5.6.7.8").expect_err("blocked after restart") {
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
        cd.check("0xabc", "1.2.3.4").expect("starts empty after corruption");
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

    /// SECREM-01 FAUCET-1: a failed send releases the slot so the user
    /// can retry; a successful send keeps it claimed.
    #[test]
    fn test_faucet1_release_returns_slot_success_keeps_it() {
        let cd = Cooldowns::in_memory(CooldownPolicy::default());
        cd.try_reserve("0xabc", "1.2.3.4").expect("first reserve");
        cd.check("0xabc", "1.2.3.4").expect_err("slot held while reserved");
        cd.release("0xabc", "1.2.3.4");
        cd.try_reserve("0xabc", "1.2.3.4").expect("reserve again after release");
        cd.record_success("0xabc", "1.2.3.4");
        cd.check("0xabc", "5.6.7.8").expect_err("claimed after success");
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
        cd.check("0xabc", "1.2.3.4").expect("zero policy = no cooldown");
    }
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
        }
    }
}
