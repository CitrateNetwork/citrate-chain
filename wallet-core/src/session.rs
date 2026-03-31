//! Session management — unlock timeout, rate limiting, lockout.
//!
//! Enforces security policies:
//! - Session auto-lock after configurable timeout
//! - Rate limiting on password attempts
//! - Lockout after max failed attempts

use crate::error::WalletError;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Session manager — tracks unlock state and enforces rate limits.
pub struct SessionManager {
    sessions: HashMap<String, SessionState>,
    failed_attempts: HashMap<String, (u32, Option<Instant>)>,
    max_failed_attempts: u32,
    lockout_duration: Duration,
    session_timeout: Duration,
}

struct SessionState {
    _unlocked_at: Instant,
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
        if let Some((count, lockout_start)) = self.failed_attempts.get(address) {
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
        let entry = self.failed_attempts
            .entry(address.to_string())
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
        self.failed_attempts.remove(address);
        self.sessions.insert(address.to_string(), SessionState {
            _unlocked_at: Instant::now(),
            last_activity: Instant::now(),
        });
    }

    /// Check if a session is active (not timed out).
    pub fn is_session_active(&self, address: &str) -> bool {
        if let Some(session) = self.sessions.get(address) {
            session.last_activity.elapsed() < self.session_timeout
        } else {
            false
        }
    }

    /// Touch the session (reset activity timer).
    pub fn touch_session(&mut self, address: &str) {
        if let Some(session) = self.sessions.get_mut(address) {
            session.last_activity = Instant::now();
        }
    }

    /// End a session.
    pub fn end_session(&mut self, address: &str) {
        self.sessions.remove(address);
    }

    /// End all sessions.
    pub fn end_all_sessions(&mut self) {
        self.sessions.clear();
    }

    /// Get the session status for an address.
    pub fn get_status(&self, address: &str) -> SessionStatus {
        let is_active = self.is_session_active(address);
        let remaining_secs = if is_active {
            self.sessions.get(address).map(|s| {
                let elapsed = s.last_activity.elapsed();
                self.session_timeout.as_secs().saturating_sub(elapsed.as_secs())
            })
        } else {
            None
        };

        let is_locked_out = self.is_locked_out(address);
        let lockout_remaining_secs = if is_locked_out {
            self.failed_attempts.get(address).and_then(|(_, start)| {
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
}
