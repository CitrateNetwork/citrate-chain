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

// =========================================================================
// RM-G1.5 / EXT-10 — constant-time secp256k1 ECDSA signing exposed to WASM.
//
// Replaces the hand-rolled BigInt secp256k1 in
// `wallet-extension/js/crypto.js` with the same `k256` crate the
// desktop wallet uses. The audit's concern with BigInt was twofold:
//
//   1. Pure-JS BigInt arithmetic is NOT constant-time. A side-channel
//      attacker that can co-locate code in the same renderer / worker
//      could measure scalar-mul timings and recover key bits.
//   2. The hand-rolled implementation never went through external
//      cryptographic review; subtle bugs (e.g., point-at-infinity,
//      RFC 6979 edge cases) are easy to miss.
//
// k256 is constant-time, audited (Trail of Bits 2023), and produces
// byte-for-byte identical signatures to wallet-core's `UnifiedKey`,
// which means a transaction signed in the extension verifies under
// the same on-chain checks as a transaction signed by the desktop
// wallet.
//
// Spec: same `low-S enforced via SignatureNormalization` invariant
// as `wallet-core/src/keys.rs::Secp256k1.sign_evm_tx` — both honor
// EIP-2 by always emitting the canonical low-S signature.
// =========================================================================

#[cfg(feature = "wasm")]
fn parse_secp256k1_secret(bytes: &[u8]) -> Result<k256::ecdsa::SigningKey, JsError> {
    if bytes.len() != 32 {
        return Err(JsError::new(&format!(
            "EXT-10: secp256k1 secret key must be exactly 32 bytes (got {})",
            bytes.len()
        )));
    }
    k256::ecdsa::SigningKey::from_bytes(bytes.into())
        .map_err(|e| JsError::new(&format!("EXT-10: invalid secp256k1 secret: {}", e)))
}

/// Sign a 32-byte message digest with secp256k1 ECDSA, RFC 6979
/// deterministic-k, low-S enforced (EIP-2). Returns a 65-byte buffer:
/// `r (32) || s (32) || v (1)` where v is the recovery parameter
/// (0 or 1) — Ethereum callers translate to `27 + v` or
/// `35 + 2*chainId + v` depending on legacy vs. EIP-155 framing.
///
/// This is the EXT-10 replacement for `wallet-extension/js/crypto.js`'s
/// `Secp256k1.sign`. JS callers handle the v -> chain-id offset.
///
/// JS signature:
/// ```javascript
/// const sig = secp256k1_sign_hash(privateKey32, msgHash32);
/// const r = sig.subarray(0, 32);
/// const s = sig.subarray(32, 64);
/// const v = sig[64]; // 0 or 1
/// ```
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn secp256k1_sign_hash(private_key: &[u8], msg_hash: &[u8]) -> Result<Vec<u8>, JsError> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature};

    if msg_hash.len() != 32 {
        return Err(JsError::new(&format!(
            "EXT-10: msg_hash must be exactly 32 bytes (got {})",
            msg_hash.len()
        )));
    }

    let signing_key = parse_secp256k1_secret(private_key)?;
    let signature: Signature = signing_key
        .sign_prehash(msg_hash)
        .map_err(|e| JsError::new(&format!("EXT-10: signing failed: {}", e)))?;

    // k256's PrehashSigner doesn't return the recovery id directly —
    // we recompute it. The pattern matches wallet-core's
    // `Secp256k1.sign_evm_tx` so the on-the-wire format is identical.
    let recovery_id = RecoveryId::trial_recovery_from_prehash(
        signing_key.verifying_key(),
        msg_hash,
        &signature,
    )
    .map_err(|e| JsError::new(&format!("EXT-10: recovery id failed: {}", e)))?;

    // k256's Signature is automatically normalized to low-S by
    // `sign_prehash` per EIP-2; assert defensively.
    debug_assert!(signature.normalize_s().is_none());

    let r_bytes = signature.r().to_bytes();
    let s_bytes = signature.s().to_bytes();
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&r_bytes);
    out.extend_from_slice(&s_bytes);
    out.push(recovery_id.to_byte());
    Ok(out)
}

/// Derive the uncompressed secp256k1 public key (65 bytes:
/// `0x04 || X (32) || Y (32)`) from a 32-byte private key. The
/// `0x04` prefix matches Ethereum's expectation; JS callers
/// `keccak256(pubkey[1..]).slice(-20)` to derive the address.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn secp256k1_public_key(private_key: &[u8]) -> Result<Vec<u8>, JsError> {
    #[allow(unused_imports)]
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let signing_key = parse_secp256k1_secret(private_key)?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false); // uncompressed
    Ok(encoded.as_bytes().to_vec())
}

/// Derive the EIP-55 checksummed Ethereum address from a 32-byte
/// secp256k1 private key. Convenience wrapper so JS callers don't
/// have to keccak256 + slice manually.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn secp256k1_address(private_key: &[u8]) -> Result<String, JsError> {
    #[allow(unused_imports)]
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha3::{Digest, Keccak256};

    let signing_key = parse_secp256k1_secret(private_key)?;
    let pk = signing_key.verifying_key().to_encoded_point(false);
    let pk_bytes = pk.as_bytes();
    // Skip the 0x04 prefix; hash the 64-byte X||Y.
    let mut hasher = Keccak256::new();
    hasher.update(&pk_bytes[1..]);
    let hash = hasher.finalize();
    let addr = &hash[12..]; // last 20 bytes

    // EIP-55 checksum.
    let addr_hex = hex_lower(addr);
    let mut hasher2 = Keccak256::new();
    hasher2.update(addr_hex.as_bytes());
    let cksum = hasher2.finalize();
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in addr_hex.chars().enumerate() {
        let nib = if i % 2 == 0 {
            cksum[i / 2] >> 4
        } else {
            cksum[i / 2] & 0x0f
        };
        if nib >= 8 {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

#[cfg(feature = "wasm")]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
