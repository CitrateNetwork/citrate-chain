// WAL-01 — fixture for tools/semgrep/rules/wal-01-argon2-default.yaml
//
// Run via: `semgrep --config wal-01-argon2-default.yaml wal-01-argon2-default.rs`
// Both `ruleid:` markers must produce findings; both `ok:` markers must not.
//
// This file is NOT compiled — it is fixture data only. The `path` exclusions
// in the rule (`**/tests/**`) prevent the linter from running here in CI;
// for local manual runs we exercise the rule directly.

#![cfg(any())] // never compiled

use argon2::{Algorithm, Argon2, Params, Version};

// ============================================================================
// POSITIVES — these patterns must be flagged
// ============================================================================

fn bad_direct_default_in_encrypt() {
    // ruleid: wal-01-argon2-default
    let _argon2 = Argon2::default();
}

fn bad_default_inside_block() {
    // ruleid: wal-01-argon2-default
    let argon2 = Argon2::default();
    let _ = argon2;
}

// ============================================================================
// NEGATIVES — these patterns must NOT be flagged
// ============================================================================

// ok: wal-01-argon2-default
// The dispatcher's legacy branch is the documented exception per
// docs/security/KDF_POLICY.md and the rule's pattern-not-inside.
fn argon2_for_version(version: u32) -> Option<Argon2<'static>> {
    match version {
        1 => Some(Argon2::default()),
        2 => {
            let params = Params::new(65536, 3, 4, Some(32)).ok()?;
            Some(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
        }
        _ => None,
    }
}

// ok: wal-01-argon2-default
fn good_explicit_v2_params() {
    let params = Params::new(65536, 3, 4, Some(32)).expect("v2 params are statically valid");
    let _argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
}

// ok: wal-01-argon2-default
fn good_via_dispatcher() {
    let _argon2 = argon2_for_version(2);
}
