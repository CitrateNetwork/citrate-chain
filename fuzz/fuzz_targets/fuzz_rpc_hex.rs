#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz hex parsing paths used by RPC handlers.
    // Simulates the pattern: strip "0x" prefix, hex::decode, length check.
    if let Ok(s) = std::str::from_utf8(data) {
        let trimmed = s.trim();
        let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);

        // Address parsing (20 bytes)
        if let Ok(bytes) = hex::decode(stripped) {
            if bytes.len() == 20 {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&bytes);
            }
            // Hash parsing (32 bytes)
            if bytes.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
            }
            // Transaction data (arbitrary length — feed to decoder)
            if !bytes.is_empty() {
                let _ = citrate_api::eth_tx_decoder::decode_eth_transaction(&bytes);
            }
        }

        // U256 parsing (used for value, gas price)
        let _ = u128::from_str_radix(stripped, 16);
    }
});
