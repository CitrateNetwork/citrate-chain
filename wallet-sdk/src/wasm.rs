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
    keystore_json: String, // In WASM, keystore is in-memory JSON (no filesystem)
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
