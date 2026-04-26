//! Session management — unlock timeout, rate limiting, lockout.
//!
//! Enforces security policies:
//! - Session auto-lock after configurable timeout
//! - Rate limiting on password attempts
//! - Lockout after max failed attempts

use crate::address::canonicalize as canonicalize_address;
use crate::error::WalletError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// RM-K / WP-K1.5: canonicalize an address input before using it as a
/// HashMap key. If the input does not look like an EVM address (e.g.,
/// the public CLI/test fixtures that pass arbitrary strings as
/// "account labels"), fall back to the trimmed input — but the
/// canonical form takes precedence whenever the input parses as a
/// valid address. This way `0xABC...`, `0xabc...`, `abc...`, and the
/// EIP-55 form all collide to the same map key for the same on-chain
/// account, while non-address opaque labels keep their stable string
/// identity.
fn session_key(address: &str) -> String {
    match canonicalize_address(address) {
        Ok(canonical) => canonical,
        Err(_) => address.trim().to_string(),
    }
}

/// Session manager — tracks unlock state and enforces rate limits.
pub struct SessionManager {
    sessions: HashMap<String, SessionState>,
    failed_attempts: HashMap<String, (u32, Option<Instant>)>,
    max_failed_attempts: u32,
    lockout_duration: Duration,
    session_timeout: Duration,
}

struct SessionState {
    /// Last successful password verification (re-auth or initial unlock).
    /// Renamed from `_unlocked_at` in RM-I / WP-I1.1 because it's now
    /// load-bearing for the SDK-level re-auth check (RA-WAL-01).
    /// `record_password_freshness` updates this on a fresh password
    /// verification (e.g., the GUI prompts the user; the SDK consumer
    /// passes the fresh timestamp through `record_success`).
    unlocked_at: Instant,
    last_activity: Instant,
}

/// Public session status for UI display.
#[derive(Debug, Clone)]
pub struct SessionStatus {
    pub is_active: bool,
    pub remaining_secs: Option<u64>,
    pub is_locked_out: bool,
    pub lockout_remaining_secs: Option<u64>,
}

/// Persistence record for failed-attempt state.
///
/// RM-B1 / WP-E2.3 (audit WAL-05): pre-fix `failed_attempts` lived
/// only in memory. Process restart wiped the counter, letting an
/// attacker keep brute-forcing indefinitely so long as they crashed
/// the GUI between attempts. Post-fix this record can be persisted
/// to disk by the caller; lockout times survive restarts.
///
/// Times are captured as Unix seconds for portability across runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedFailure {
    pub address: String,
    pub count: u32,
    /// Unix seconds at which the lockout started, or `None` if the
    /// failure threshold has not yet been hit.
    pub lockout_started_unix: Option<u64>,
}

impl SessionManager {
    pub fn new(
        max_failed_attempts: u32,
        lockout_duration_secs: u64,
        session_timeout_secs: u64,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            failed_attempts: HashMap::new(),
            max_failed_attempts,
            lockout_duration: Duration::from_secs(lockout_duration_secs),
            session_timeout: Duration::from_secs(session_timeout_secs),
        }
    }

    /// Check if an address is currently locked out from password attempts.
    pub fn is_locked_out(&self, address: &str) -> bool {
        let key = session_key(address);
        if let Some((count, lockout_start)) = self.failed_attempts.get(&key) {
            if *count >= self.max_failed_attempts {
                if let Some(start) = lockout_start {
                    return start.elapsed() < self.lockout_duration;
                }
            }
        }
        false
    }

    /// Record a failed password attempt. Returns error if now locked out.
    pub fn record_failure(&mut self, address: &str) -> Result<(), WalletError> {
        let key = session_key(address);
        let entry = self.failed_attempts
            .entry(key)
            .or_insert((0, None));

        // Check if existing lockout has expired
        if let Some(start) = entry.1 {
            if start.elapsed() >= self.lockout_duration {
                *entry = (0, None);
            }
        }

        entry.0 += 1;
        if entry.0 >= self.max_failed_attempts {
            entry.1 = Some(Instant::now());
            return Err(WalletError::RateLimited(format!(
                "Too many failed attempts. Locked out for {} seconds.",
                self.lockout_duration.as_secs()
            )));
        }
        Ok(())
    }

    /// Record a successful unlock. Resets failed attempts.
    pub fn record_success(&mut self, address: &str) {
        let key = session_key(address);
        self.failed_attempts.remove(&key);
        self.sessions.insert(key, SessionState {
            unlocked_at: Instant::now(),
            last_activity: Instant::now(),
        });
    }

    /// Refresh the password-verification timestamp without resetting
    /// the session. Called after a successful re-auth prompt: the
    /// session was already active (so we don't tear it down) but the
    /// caller has just verified the password again.
    ///
    /// RM-I / WP-I1.1 (RA-WAL-01): the SDK-level re-auth check uses
    /// `password_freshness_secs` to decide whether a high-value
    /// transaction (>= RE_AUTH_THRESHOLD_WEI / 10 SALT) requires a
    /// new password prompt. After the prompt verifies, the caller
    /// invokes this method so the SDK sees the fresh timestamp.
    pub fn refresh_password_timestamp(&mut self, address: &str) {
        let key = session_key(address);
        if let Some(session) = self.sessions.get_mut(&key) {
            session.unlocked_at = Instant::now();
            session.last_activity = Instant::now();
        }
    }

    /// Seconds since the most recent password verification for this
    /// address. Returns `None` if the session is inactive.
    ///
    /// RM-I / WP-I1.1 (RA-WAL-01): used by `wallet-sdk::Wallet::sign_transaction`
    /// to enforce re-auth on high-value transactions at the SDK boundary.
    /// Pre-fix the GUI was the only enforcement layer; non-GUI SDK
    /// consumers (extension, CLI scripts) bypassed the gate entirely.
    pub fn password_freshness_secs(&self, address: &str) -> Option<u64> {
        let key = session_key(address);
        self.sessions
            .get(&key)
            .map(|s| s.unlocked_at.elapsed().as_secs())
    }

    /// Check if a session is active (not timed out).
    pub fn is_session_active(&self, address: &str) -> bool {
        let key = session_key(address);
        if let Some(session) = self.sessions.get(&key) {
            session.last_activity.elapsed() < self.session_timeout
        } else {
            false
        }
    }

    /// Touch the session (reset activity timer).
    pub fn touch_session(&mut self, address: &str) {
        let key = session_key(address);
        if let Some(session) = self.sessions.get_mut(&key) {
            session.last_activity = Instant::now();
        }
    }

    /// End a session.
    pub fn end_session(&mut self, address: &str) {
        let key = session_key(address);
        self.sessions.remove(&key);
    }

    /// End all sessions.
    pub fn end_all_sessions(&mut self) {
        self.sessions.clear();
    }

    /// Get the session status for an address.
    pub fn get_status(&self, address: &str) -> SessionStatus {
        let key = session_key(address);
        let is_active = self.is_session_active(&key);
        let remaining_secs = if is_active {
            self.sessions.get(&key).map(|s| {
                let elapsed = s.last_activity.elapsed();
                self.session_timeout.as_secs().saturating_sub(elapsed.as_secs())
            })
        } else {
            None
        };

        let is_locked_out = self.is_locked_out(&key);
        let lockout_remaining_secs = if is_locked_out {
            self.failed_attempts.get(&key).and_then(|(_, start)| {
                start.map(|s| {
                    self.lockout_duration.as_secs().saturating_sub(s.elapsed().as_secs())
                })
            })
        } else {
            None
        };

        SessionStatus {
            is_active,
            remaining_secs,
            is_locked_out,
            lockout_remaining_secs,
        }
    }

    /// Snapshot the failed-attempt state in a serializable form.
    /// RM-B1 / WP-E2.3 (audit WAL-05).
    pub fn export_failures(&self) -> Vec<PersistedFailure> {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.failed_attempts
            .iter()
            .map(|(addr, (count, started))| {
                let lockout_started_unix = started.map(|inst| {
                    // How many seconds ago was the lockout started?
                    let elapsed = now.saturating_duration_since(inst);
                    now_unix.saturating_sub(elapsed.as_secs())
                });
                PersistedFailure {
                    address: addr.clone(),
                    count: *count,
                    lockout_started_unix,
                }
            })
            .collect()
    }

    /// Restore failed-attempt state from a previously-exported list.
    /// Lockouts whose duration has already elapsed at the wall-clock
    /// level are dropped on the way in.
    /// RM-B1 / WP-E2.3 (audit WAL-05).
    pub fn import_failures(&mut self, items: Vec<PersistedFailure>) {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for item in items {
            // Translate Unix start → Instant. If the lockout window
            // has already fully elapsed we DROP the record so the
            // user isn't perma-locked.
            let started_inst = match item.lockout_started_unix {
                Some(start_unix) => {
                    let elapsed_secs = now_unix.saturating_sub(start_unix);
                    if elapsed_secs >= self.lockout_duration.as_secs() {
                        // Lockout expired during the gap — reset counter.
                        continue;
                    }
                    Some(now - Duration::from_secs(elapsed_secs))
                }
                None => None,
            };
            // K1.5: canonicalize on import too so persisted failures
            // match runtime lookups regardless of which case form the
            // exporter produced.
            let key = session_key(&item.address);
            self.failed_attempts
                .insert(key, (item.count, started_inst));
        }
    }

    /// Expire timed-out sessions. Returns list of expired addresses.
    pub fn expire_sessions(&mut self) -> Vec<String> {
        let expired: Vec<String> = self.sessions
            .iter()
            .filter(|(_, s)| s.last_activity.elapsed() >= self.session_timeout)
            .map(|(addr, _)| addr.clone())
            .collect();

        for addr in &expired {
            self.sessions.remove(addr);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> SessionManager {
        SessionManager::new(3, 5, 10) // 3 attempts, 5s lockout, 10s timeout
    }

    #[test]
    fn test_initial_state_not_locked() {
        let mgr = test_manager();
        assert!(!mgr.is_locked_out("0xabc"));
        assert!(!mgr.is_session_active("0xabc"));
    }

    #[test]
    fn test_record_success_creates_session() {
        let mut mgr = test_manager();
        mgr.record_success("0xabc");
        assert!(mgr.is_session_active("0xabc"));
    }

    #[test]
    fn test_end_session() {
        let mut mgr = test_manager();
        mgr.record_success("0xabc");
        assert!(mgr.is_session_active("0xabc"));
        mgr.end_session("0xabc");
        assert!(!mgr.is_session_active("0xabc"));
    }

    #[test]
    fn test_end_all_sessions() {
        let mut mgr = test_manager();
        mgr.record_success("0xabc");
        mgr.record_success("0xdef");
        mgr.end_all_sessions();
        assert!(!mgr.is_session_active("0xabc"));
        assert!(!mgr.is_session_active("0xdef"));
    }

    #[test]
    fn test_failed_attempts_lockout() {
        let mut mgr = test_manager();
        mgr.record_failure("0xabc").expect("attempt 1");
        mgr.record_failure("0xabc").expect("attempt 2");
        let result = mgr.record_failure("0xabc"); // attempt 3 = lockout
        assert!(result.is_err());
        assert!(mgr.is_locked_out("0xabc"));
    }

    #[test]
    fn test_success_resets_failures() {
        let mut mgr = test_manager();
        mgr.record_failure("0xabc").expect("attempt 1");
        mgr.record_failure("0xabc").expect("attempt 2");
        mgr.record_success("0xabc"); // success resets counter
        mgr.record_failure("0xabc").expect("attempt 1 again");
        assert!(!mgr.is_locked_out("0xabc"));
    }

    #[test]
    fn test_session_status_active() {
        let mut mgr = test_manager();
        mgr.record_success("0xabc");
        let status = mgr.get_status("0xabc");
        assert!(status.is_active);
        assert!(status.remaining_secs.is_some());
        assert!(!status.is_locked_out);
    }

    #[test]
    fn test_session_status_inactive() {
        let mgr = test_manager();
        let status = mgr.get_status("0xabc");
        assert!(!status.is_active);
        assert!(status.remaining_secs.is_none());
    }

    #[test]
    fn test_session_status_locked_out() {
        let mut mgr = test_manager();
        let _ = mgr.record_failure("0xabc");
        let _ = mgr.record_failure("0xabc");
        let _ = mgr.record_failure("0xabc");
        let status = mgr.get_status("0xabc");
        assert!(status.is_locked_out);
        assert!(status.lockout_remaining_secs.is_some());
    }

    #[test]
    fn test_touch_session() {
        let mut mgr = test_manager();
        mgr.record_success("0xabc");
        mgr.touch_session("0xabc");
        assert!(mgr.is_session_active("0xabc"));
    }

    #[test]
    fn test_independent_addresses() {
        let mut mgr = test_manager();
        mgr.record_success("0xabc");
        assert!(mgr.is_session_active("0xabc"));
        assert!(!mgr.is_session_active("0xdef"));

        let _ = mgr.record_failure("0xdef");
        let _ = mgr.record_failure("0xdef");
        let _ = mgr.record_failure("0xdef");
        assert!(mgr.is_locked_out("0xdef"));
        assert!(!mgr.is_locked_out("0xabc"));
    }

    #[test]
    fn test_expire_sessions_returns_expired() {
        let mut mgr = SessionManager::new(3, 5, 0); // 0 second timeout = immediate
        mgr.record_success("0xabc");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let expired = mgr.expire_sessions();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "0xabc");
        assert!(!mgr.is_session_active("0xabc"));
    }

    /// RM-B1 / WP-E2.3 (audit WAL-05): export/import round-trips
    /// preserve failure counts across simulated process restart.
    #[test]
    fn test_export_import_round_trip_preserves_count() {
        let mut mgr = test_manager();
        mgr.record_failure("0xabc").expect("attempt 1");
        mgr.record_failure("0xabc").expect("attempt 2");
        let snapshot = mgr.export_failures();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].count, 2);

        // Fresh manager, same persisted state.
        let mut restored = test_manager();
        restored.import_failures(snapshot);
        // Third attempt (continuing from the persisted 2) triggers lockout.
        let res = restored.record_failure("0xabc");
        assert!(res.is_err(), "lockout fires at the persisted threshold");
        assert!(restored.is_locked_out("0xabc"));
    }

    /// Lockouts whose duration has fully elapsed during the restart
    /// gap are dropped so the user isn't perma-locked.
    #[test]
    fn test_import_drops_expired_lockouts() {
        let snapshot = vec![PersistedFailure {
            address: "0xabc".to_string(),
            count: 3,
            // Lockout started "1 hour ago" — way past our 5s lockout.
            lockout_started_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs().saturating_sub(3600)),
        }];
        let mut mgr = test_manager();
        mgr.import_failures(snapshot);
        assert!(!mgr.is_locked_out("0xabc"), "expired lockout dropped");
    }

    #[test]
    fn test_multiple_failures_then_lockout_message() {
        let mut mgr = test_manager();
        let _ = mgr.record_failure("0xabc");
        let _ = mgr.record_failure("0xabc");
        let err = mgr.record_failure("0xabc").expect_err("should be locked out");
        match err {
            WalletError::RateLimited(msg) => {
                assert!(msg.contains("Locked out"));
            }
            _ => panic!("Expected RateLimited error"),
        }
    }

    // ── RM-K / WP-K1.5 — address normalization tests ─────────────
    //
    // Every public method that accepts an address string MUST treat
    // the four canonical-equivalent shapes (lowercase, uppercase,
    // no-prefix, EIP-55 mixed case) as the same key. Without this,
    // a session lock for one form does not protect the others, and
    // a phishing UI can present a visually-similar address to the
    // user that hits a different lockout bucket.

    /// EIP-55 reference vector (mixed case).
    const VALID_EIP55: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

    #[test]
    fn test_k1_5_session_lockout_is_case_insensitive() {
        let mut mgr = test_manager();
        // Trip the lockout under one case form …
        let _ = mgr.record_failure("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        let _ = mgr.record_failure("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        let _ = mgr.record_failure("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        // … and check from another.
        assert!(
            mgr.is_locked_out("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED"),
            "K1.5: uppercase form must see the lockout set under lowercase"
        );
        assert!(
            mgr.is_locked_out(VALID_EIP55),
            "K1.5: EIP-55 form must see the lockout set under lowercase"
        );
        assert!(
            mgr.is_locked_out("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
            "K1.5: no-prefix form must see the lockout set under lowercase"
        );
    }

    #[test]
    fn test_k1_5_session_active_is_case_insensitive() {
        let mut mgr = test_manager();
        mgr.record_success(VALID_EIP55);
        assert!(
            mgr.is_session_active("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
            "K1.5: lowercase query must see the session opened under EIP-55"
        );
        assert!(
            mgr.is_session_active("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED"),
            "K1.5: uppercase query must see the session opened under EIP-55"
        );
    }

    #[test]
    fn test_k1_5_password_freshness_is_case_insensitive() {
        let mut mgr = test_manager();
        mgr.record_success("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assert!(
            mgr.password_freshness_secs(VALID_EIP55).is_some(),
            "K1.5: freshness must be visible across case forms (the SDK \
             re-auth gate at RA-WAL-01 depends on this)"
        );
    }

    #[test]
    fn test_k1_5_end_session_is_case_insensitive() {
        let mut mgr = test_manager();
        mgr.record_success(VALID_EIP55);
        // End under lowercase form …
        mgr.end_session("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        // … session must be gone under EIP-55 form too.
        assert!(
            !mgr.is_session_active(VALID_EIP55),
            "K1.5: end_session under lowercase must end the EIP-55 session"
        );
    }

    #[test]
    fn test_k1_5_get_status_is_case_insensitive() {
        let mut mgr = test_manager();
        mgr.record_success("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        let status = mgr.get_status(VALID_EIP55);
        assert!(
            status.is_active,
            "K1.5: get_status must see the session across case forms"
        );
    }

    #[test]
    fn test_k1_5_non_address_labels_keep_stable_identity() {
        // Non-address strings (used by some test fixtures and CLI
        // tooling as opaque labels) must still hash to themselves —
        // canonicalization rejects them, so the fallback is the
        // trimmed input. Two distinct labels must remain distinct.
        let mut mgr = test_manager();
        mgr.record_success("alice@local");
        assert!(mgr.is_session_active("alice@local"));
        assert!(!mgr.is_session_active("bob@local"));
    }

    #[test]
    fn test_k1_5_invalid_eip55_does_not_collide_with_valid() {
        // A flipped-case mixed string fails canonicalization and falls
        // back to its trimmed self. It must NOT collide with the
        // correctly-checksummed form.
        let bad = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let mut mgr = test_manager();
        mgr.record_success(bad);
        // The bad form opened a session keyed at its own bucket.
        assert!(mgr.is_session_active(bad));
        // The correctly-checksummed form is a DIFFERENT key.
        assert!(
            !mgr.is_session_active(VALID_EIP55),
            "K1.5: invalid-checksum mixed-case input must NOT canonicalize \
             to the valid form (otherwise an attacker could exploit \
             ambiguity to steal a session)"
        );
    }
}
