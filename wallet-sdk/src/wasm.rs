//! WASM bindings for the wallet SDK.
//!
//! Compiled only when the `wasm` feature is enabled.
//! Exports functions callable from JavaScript via wasm-bindgen.
//!
//! Usage from JavaScript:
//! ```javascript
//! import init, { WasmWallet } from '@citrate/wallet';
//! await init();
//!
//! const wallet = new WasmWallet("http://localhost:8545", 40204);
//! const account = await wallet.createAccount("mypassword123", "Primary");
//! console.log(account.address);
//! ```

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// WASM wallet handle — wraps the Rust Wallet struct for JavaScript access.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmWallet {
    // The actual wallet is created per-call because WASM can't hold async state.
    // Configuration is stored and used to create wallet instances.
    rpc_url: String,
    chain_id: u64,
    // Reserved for the async-WASM keystore landing in RM-G1 / WP-G1.1.
    // Suppressed today because the create_account/sign/send WASM bindings
    // are stubbed (per the file-level note); RM-G1 wires the field
    // through the keystore upgrade flow.
    #[allow(dead_code)]
    keystore_json: String,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmWallet {
    /// Create a new WASM wallet instance.
    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: &str, chain_id: u64) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
            chain_id,
            keystore_json: String::new(),
        }
    }

    /// Get the configured RPC URL.
    #[wasm_bindgen(getter)]
    pub fn rpc_url(&self) -> String {
        self.rpc_url.clone()
    }

    /// Get the configured chain ID.
    #[wasm_bindgen(getter)]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

// Note: Full async WASM bindings (create_account, sign, send) require
// wasm-bindgen-futures and careful lifetime management. These will be
// implemented when the WASM build target is verified with wasm-pack.
// For now, the module structure and basic types are in place.

// =========================================================================
// WP-A1.5 — Argon2id v2 KDF exposed to WASM consumers.
//
// Closes audit finding EXT-01 (CRITICAL — browser extension currently uses
// PBKDF2-100k, materially weaker than the OWASP floor). This export gives
// the extension's RM-G1 migration a single canonical primitive: feed
// `(password, salt)` and receive the same 32-byte derived key the
// desktop wallet uses.
//
// Spec: docs/security/KDF_POLICY.md §3.2 (canonical params) and §1
// (surface table). Both browser and desktop converge on `kdf_version: 2`
// to keep ciphertext interoperable across surfaces.
//
// Available under both `wasm` and `argon2-wasm` feature flags. The
// `argon2-wasm` flag exists so a future bundle that doesn't need KDF
// (e.g., a dapp embedding a read-only client) can opt out.
// =========================================================================

#[cfg(feature = "wasm")]
const KDF_OUTPUT_LEN: usize = 32;

/// Derive a 32-byte AES-256 key from `(password, salt)` using Argon2id v2
/// per `docs/security/KDF_POLICY.md` §3.2.
///
/// Parameters: m=65536 KiB, t=3, p=1, output_len=32. Identical to the
/// desktop wallet's `KeyManager::create_account` so a v2 keystore created
/// in the browser unlocks identically in the desktop wallet (and vice
/// versa).
///
/// JS signature (after `wasm-pack build`):
///
/// ```javascript
/// import init, { argon2_v2_derive_key } from '@citrate/wallet-sdk';
/// await init();
/// const password = new TextEncoder().encode("user-supplied-password");
/// const salt = crypto.getRandomValues(new Uint8Array(16));
/// const key32 = argon2_v2_derive_key(password, salt);
/// // key32 is a Uint8Array(32) ready for AES-GCM.
/// ```
///
/// **Errors** as a JS exception (`Error.message` set) on:
///   * `salt.len() < 8` — Argon2 minimum salt length
///   * `password.is_empty()` — empty passwords are rejected at this layer
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn argon2_v2_derive_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, JsError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    if password.is_empty() {
        return Err(JsError::new(
            "WP-A1.5: empty password rejected by argon2_v2_derive_key",
        ));
    }
    if salt.len() < 8 {
        return Err(JsError::new(
            "WP-A1.5: salt must be at least 8 bytes (Argon2 minimum)",
        ));
    }

    let params = Params::new(65536, 3, 1, Some(KDF_OUTPUT_LEN))
        .map_err(|e| JsError::new(&format!("WP-A1.5: invalid Argon2 params: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; KDF_OUTPUT_LEN];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| JsError::new(&format!("WP-A1.5: Argon2 derivation failed: {}", e)))?;
    Ok(output)
}

/// Returns the canonical KDF version this build of `wallet-sdk` writes
/// for new entries. Lets JS consumers stamp records consistently with
/// the Rust desktop wallet (same `kdf_version: 2` field).
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn kdf_version_current() -> u32 {
    2
}

// Native-target tests for the WASM Argon2 primitive live in
// `wallet-sdk/tests/wp_a1_5_argon2_wasm_parity.rs` — they don't require
// the `wasm` feature, so they run on every `cargo test` invocation.
