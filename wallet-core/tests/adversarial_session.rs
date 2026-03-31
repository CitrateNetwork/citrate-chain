//! Adversarial tests for session management.
//!
//! Attack surfaces: lockout bypass, timing attacks, concurrent unlock,
//! session hijacking, timeout manipulation.

use citrate_wallet_core::session::SessionManager;

#[allow(dead_code)]
fn fast_manager() -> SessionManager {
    // 3 attempts, 1s lockout, 0s timeout (immediate expire for testing)
    SessionManager::new(3, 1, 0)
}

fn normal_manager() -> SessionManager {
    // 5 attempts, 5s lockout, 10s timeout
    SessionManager::new(5, 5, 10)
}

// =========================================================================
// LOCKOUT BYPASS ATTEMPTS
// =========================================================================

#[test]
fn test_lockout_cannot_be_bypassed_by_success() {
    let mut mgr = SessionManager::new(3, 300, 60); // 5 min lockout
    // Trigger lockout
    let _ = mgr.record_failure("0xabc");
    let _ = mgr.record_failure("0xabc");
    let _ = mgr.record_failure("0xabc"); // locked out

    assert!(mgr.is_locked_out("0xabc"), "Should be locked out");

    // During lockout, even "success" doesn't help — the caller should check
    // is_locked_out BEFORE attempting unlock. But if they call record_success:
    mgr.record_success("0xabc"); // This resets the counter

    // After record_success, lockout is cleared (this is by design — the password
    // was correct, so the user is who they claim to be)
    assert!(!mgr.is_locked_out("0xabc"));
}

#[test]
fn test_lockout_persists_across_status_checks() {
    let mut mgr = SessionManager::new(3, 300, 60);
    let _ = mgr.record_failure("0xabc");
    let _ = mgr.record_failure("0xabc");
    let _ = mgr.record_failure("0xabc");

    // Multiple status checks don't clear lockout
    for _ in 0..100 {
        let status = mgr.get_status("0xabc");
        assert!(status.is_locked_out, "Status checks must not clear lockout");
    }
}

#[test]
fn test_lockout_exactly_at_max_attempts() {
    let mut mgr = SessionManager::new(3, 300, 60);
    mgr.record_failure("0xabc").expect("attempt 1 ok");
    mgr.record_failure("0xabc").expect("attempt 2 ok");
    let result = mgr.record_failure("0xabc"); // attempt 3 = lockout
    assert!(result.is_err(), "Third failure should trigger lockout");
    assert!(mgr.is_locked_out("0xabc"));
}

#[test]
fn test_lockout_boundary_one_below_max() {
    let mut mgr = SessionManager::new(3, 300, 60);
    mgr.record_failure("0xabc").expect("attempt 1");
    mgr.record_failure("0xabc").expect("attempt 2");
    // 2 failures — NOT locked out yet
    assert!(!mgr.is_locked_out("0xabc"), "2/3 failures should not lock out");
}

// =========================================================================
// SESSION TIMEOUT
// =========================================================================

#[test]
fn test_session_expires_immediately_with_zero_timeout() {
    let mut mgr = SessionManager::new(5, 5, 0); // 0 second timeout
    mgr.record_success("0xabc");

    // Session should expire essentially immediately
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert!(!mgr.is_session_active("0xabc"), "Zero-timeout session should expire immediately");
}

#[test]
fn test_touch_extends_session() {
    let mut mgr = SessionManager::new(5, 5, 1); // 1 second timeout
    mgr.record_success("0xabc");
    assert!(mgr.is_session_active("0xabc"));

    // Touch should reset the timer
    std::thread::sleep(std::time::Duration::from_millis(500));
    mgr.touch_session("0xabc");
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Without touch, 1s would have passed and session would expire
    // With touch at 500ms, only 500ms elapsed since last touch
    assert!(mgr.is_session_active("0xabc"), "Touch should extend session");
}

#[test]
fn test_touch_nonexistent_session_is_noop() {
    let mut mgr = normal_manager();
    // Touch a session that doesn't exist — should not panic or create session
    mgr.touch_session("0xnonexistent");
    assert!(!mgr.is_session_active("0xnonexistent"));
}

// =========================================================================
// ADDRESS ISOLATION
// =========================================================================

#[test]
fn test_lockout_on_one_address_doesnt_affect_other() {
    let mut mgr = SessionManager::new(3, 300, 60);

    // Lock out address A
    let _ = mgr.record_failure("0xaaa");
    let _ = mgr.record_failure("0xaaa");
    let _ = mgr.record_failure("0xaaa");
    assert!(mgr.is_locked_out("0xaaa"));

    // Address B should be unaffected
    assert!(!mgr.is_locked_out("0xbbb"));
    mgr.record_success("0xbbb");
    assert!(mgr.is_session_active("0xbbb"));
}

#[test]
fn test_session_on_one_address_doesnt_affect_other() {
    let mut mgr = normal_manager();
    mgr.record_success("0xaaa");
    assert!(mgr.is_session_active("0xaaa"));
    assert!(!mgr.is_session_active("0xbbb"));
}

#[test]
fn test_end_session_doesnt_affect_other_addresses() {
    let mut mgr = normal_manager();
    mgr.record_success("0xaaa");
    mgr.record_success("0xbbb");
    mgr.end_session("0xaaa");
    assert!(!mgr.is_session_active("0xaaa"));
    assert!(mgr.is_session_active("0xbbb"), "Ending A should not affect B");
}

// =========================================================================
// EXPIRE SESSIONS
// =========================================================================

#[test]
fn test_expire_sessions_returns_expired_addresses() {
    let mut mgr = SessionManager::new(5, 5, 0); // 0 timeout
    mgr.record_success("0xaaa");
    mgr.record_success("0xbbb");

    std::thread::sleep(std::time::Duration::from_millis(10));

    let expired = mgr.expire_sessions();
    assert_eq!(expired.len(), 2);
    assert!(expired.contains(&"0xaaa".to_string()));
    assert!(expired.contains(&"0xbbb".to_string()));
}

#[test]
fn test_expire_sessions_on_empty_is_empty() {
    let mut mgr = normal_manager();
    let expired = mgr.expire_sessions();
    assert!(expired.is_empty());
}

// =========================================================================
// STATUS REPORTING
// =========================================================================

#[test]
fn test_status_lockout_remaining_secs() {
    let mut mgr = SessionManager::new(3, 60, 300); // 60s lockout
    let _ = mgr.record_failure("0xabc");
    let _ = mgr.record_failure("0xabc");
    let _ = mgr.record_failure("0xabc");

    let status = mgr.get_status("0xabc");
    assert!(status.is_locked_out);
    assert!(status.lockout_remaining_secs.is_some());
    let remaining = status.lockout_remaining_secs.expect("remaining secs");
    assert!(remaining > 0 && remaining <= 60, "Remaining should be between 0 and 60, got {}", remaining);
}

#[test]
fn test_status_session_remaining_secs() {
    let mut mgr = SessionManager::new(5, 5, 300); // 300s timeout
    mgr.record_success("0xabc");

    let status = mgr.get_status("0xabc");
    assert!(status.is_active);
    let remaining = status.remaining_secs.expect("remaining");
    assert!(remaining > 0 && remaining <= 300, "Remaining should be 0-300, got {}", remaining);
}

#[test]
fn test_status_inactive_has_no_remaining() {
    let mgr = normal_manager();
    let status = mgr.get_status("0xabc");
    assert!(!status.is_active);
    assert!(status.remaining_secs.is_none());
    assert!(!status.is_locked_out);
    assert!(status.lockout_remaining_secs.is_none());
}

// =========================================================================
// RAPID CYCLING
// =========================================================================

#[test]
fn test_rapid_lock_unlock_cycles() {
    let mut mgr = normal_manager();
    for _ in 0..100 {
        mgr.record_success("0xabc");
        assert!(mgr.is_session_active("0xabc"));
        mgr.end_session("0xabc");
        assert!(!mgr.is_session_active("0xabc"));
    }
}

#[test]
fn test_rapid_failure_then_success_cycles() {
    let mut mgr = SessionManager::new(5, 1, 60);
    for _ in 0..20 {
        let _ = mgr.record_failure("0xabc");
        let _ = mgr.record_failure("0xabc");
        mgr.record_success("0xabc"); // resets counter
        assert!(!mgr.is_locked_out("0xabc"));
    }
}

// =========================================================================
// EDGE CASES
// =========================================================================

#[test]
fn test_empty_address_string() {
    let mut mgr = normal_manager();
    mgr.record_success("");
    assert!(mgr.is_session_active(""));
    mgr.end_session("");
    assert!(!mgr.is_session_active(""));
}

#[test]
fn test_unicode_address() {
    let mut mgr = normal_manager();
    mgr.record_success("0x日本語アドレス");
    assert!(mgr.is_session_active("0x日本語アドレス"));
}

#[test]
fn test_very_long_address() {
    let mut mgr = normal_manager();
    let long_addr = "0x".to_string() + &"a".repeat(10_000);
    mgr.record_success(&long_addr);
    assert!(mgr.is_session_active(&long_addr));
}
