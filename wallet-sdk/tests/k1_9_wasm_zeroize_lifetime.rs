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

#[test]
#[ignore = "moved to citrate-wallet-extension repo post 2026-05-18 split; tripwire belongs there now"]
fn test_k1_9_extension_consumer_zeroes_derived_buffer() {
    let src = read_text("wallet-extension/js/crypto.js");

    // Locate the deriveEncryptionKeyV2 function body. It's the only
    // consumer of argon2_v2_derive_key in the extension.
    let header = "async function deriveEncryptionKeyV2";
    let header_idx = src
        .find(header)
        .expect("K1.9: deriveEncryptionKeyV2 must exist in wallet-extension/js/crypto.js");

    // Take a generous slice forward — the function is only ~30 lines.
    let body_end = header_idx + 4096;
    let slice_end = body_end.min(src.len());
    let body = &src[header_idx..slice_end];

    // Invariant 1: the keyBytes return value MUST be inside a try
    // block whose finally clause zeros it.
    assert!(
        body.contains("try {"),
        "K1.9: deriveEncryptionKeyV2 must wrap the importKey call in \
         try/finally so the derived bytes get zeroed even on error."
    );
    assert!(
        body.contains("finally {"),
        "K1.9: deriveEncryptionKeyV2 must have a finally block."
    );
    assert!(
        body.contains("keyBytes.fill(0)"),
        "K1.9: deriveEncryptionKeyV2 must call keyBytes.fill(0) to \
         zero the JS-heap copy of the derived AES key. ADR-RM-K-1-9 \
         is the policy reference."
    );
    assert!(
        body.contains("keyBytes = null"),
        "K1.9: deriveEncryptionKeyV2 must rebind keyBytes to null \
         after fill(0) so the GC has no live reference to the cleared \
         buffer."
    );

    // Invariant 2: imported CryptoKey is non-extractable.
    // The boolean position varies; require either an `extractable: false`
    // shape or a positional `false` flag.
    let nonextractable_signal =
        body.contains("/* extractable */ false") || body.contains("false,\n      ['encrypt'");
    assert!(
        nonextractable_signal,
        "K1.9: deriveEncryptionKeyV2 must import the AES-GCM key with \
         extractable=false so the actual key bytes live in opaque \
         browser crypto memory rather than scriptable JS heap."
    );
}

#[test]
#[ignore = "ADR moved to citrate-agentile-archive repo post 2026-05-18 split; tripwire belongs there now"]
fn test_k1_9_adr_exists_and_is_active() {
    let adr = read_text(
        "../.agentile/docs/adr/ADR-RM-K-1-9-wasm-zeroize-and-js-lifetime.md",
    );
    assert!(
        adr.contains("status: active"),
        "K1.9: ADR-RM-K-1-9 must declare `status: active` in its frontmatter."
    );
    assert!(
        adr.contains("Layer 1"),
        "K1.9: ADR-RM-K-1-9 must enumerate the three layers of the \
         zeroize policy (Rust-only, WASM-to-JS, JS-only)."
    );
    assert!(
        adr.contains("Layer 2"),
        "K1.9: ADR-RM-K-1-9 must enumerate Layer 2 (WASM-to-JS handoff)."
    );
    assert!(
        adr.contains("Layer 3"),
        "K1.9: ADR-RM-K-1-9 must enumerate Layer 3 (JS-only)."
    );
}

#[test]
#[ignore = "moved to citrate-wallet-extension repo post 2026-05-18 split; tripwire belongs there now"]
fn test_k1_9_password_bytes_also_zeroed() {
    // The TextEncoder().encode(password) buffer is also a JS-heap
    // copy of secret material. After the WASM call returns, the
    // password bytes are no longer needed and should be zeroed
    // alongside the derived key.
    let src = read_text("wallet-extension/js/crypto.js");
    let header_idx = src
        .find("async function deriveEncryptionKeyV2")
        .expect("K1.9: deriveEncryptionKeyV2 must exist");
    let slice_end = (header_idx + 4096).min(src.len());
    let body = &src[header_idx..slice_end];
    assert!(
        body.contains("passwordBytes.fill(0)"),
        "K1.9: deriveEncryptionKeyV2 must zero passwordBytes too — \
         the TextEncoder output is a JS-heap copy of the user's \
         password and lingers after the WASM call returns."
    );
}
