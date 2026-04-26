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
    pub fn check(&self, address: &str, ip: &str) -> Result<(), CooldownDenial> {
        let now = unix_seconds();
        let state = self.state.read().expect("cooldown lock poisoned");

        if let Some(&last) = state.address_last.get(&address_key(address)) {
            let elapsed = now.saturating_sub(last);
            if elapsed < self.policy.address_cooldown_secs {
                return Err(CooldownDenial::AddressCooldown {
                    remaining_secs: self.policy.address_cooldown_secs - elapsed,
                });
            }
        }
        if let Some(&last) = state.ip_last.get(ip) {
            let elapsed = now.saturating_sub(last);
            if elapsed < self.policy.ip_cooldown_secs {
                return Err(CooldownDenial::IpCooldown {
                    remaining_secs: self.policy.ip_cooldown_secs - elapsed,
                });
            }
        }
        Ok(())
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
