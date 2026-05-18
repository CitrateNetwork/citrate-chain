//! RM-K / WP-K1.9 — WASM zeroize / JS lifetime policy tripwires.
//!
//! ADR-RM-K-1-9 (`/.agentile/docs/adr/ADR-RM-K-1-9-wasm-zeroize-and-js-lifetime.md`)
//! lays out the policy for WASM-derived secret buffers crossing
//! into JavaScript: Rust cannot zeroize the JS-heap copy, so JS
//! consumers MUST `.fill(0)` derived buffers in `finally` blocks
//! and prefer non-extractable `CryptoKey` objects. This test file
//! is the static-grep tripwire that catches a future PR which
//! reverts the policy.
//!
//! These are not runtime tests — there is no programmatic way to
//! verify "the Uint8Array was zeroed before GC" in a JS runtime.
//! Static-grep is the structurally reliable defense.

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    // Tests run from `wallet-sdk/`, so go up one level.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p
}

fn read_text(rel: &str) -> String {
    let mut p = workspace_root();
    p.push(rel);
    fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("K1.9: cannot read {}: {e}", p.display()))
}

#[test]
fn test_k1_9_wasm_argon2_docstring_documents_lifetime_contract() {
    let src = read_text("wallet-sdk/src/wasm.rs");
    // Find the argon2_v2_derive_key function and verify its
    // docstring mentions both the ADR id and the word "lifetime"
    // so a future PR that strips the lifetime contract from the
    // docstring also has to silence this assertion.
    let needle = "pub fn argon2_v2_derive_key";
    let fn_idx = src
        .find(needle)
        .expect("K1.9: argon2_v2_derive_key must exist in wallet-sdk/src/wasm.rs");

    // Docstring must appear before the function definition.
    let preamble = &src[..fn_idx];

    // Search the most recent /// docstring block (between the last
    // `#[cfg(feature = "wasm")]` and the function).
    assert!(
        preamble.contains("ADR-RM-K-1-9"),
        "K1.9: the argon2_v2_derive_key docstring must reference \
         ADR-RM-K-1-9 so future contributors know where the lifetime \
         policy lives. The reference moved or was deleted."
    );
    assert!(
        preamble.contains("Lifetime contract"),
        "K1.9: the argon2_v2_derive_key docstring must contain the \
         phrase 'Lifetime contract' — a regression PR that strips the \
         policy language must also explain why."
    );
    assert!(
        preamble.contains(".fill(0)"),
        "K1.9: docstring must instruct JS callers to call .fill(0) \
         on the returned Uint8Array."
    );
    assert!(
        preamble.contains("extractable"),
        "K1.9: docstring must instruct JS callers to prefer \
         non-extractable CryptoKey."
    );
}
