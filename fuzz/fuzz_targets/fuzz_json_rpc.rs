#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz JSON-RPC request parsing with malformed JSON, oversized payloads,
    // and boundary inputs. Exercises serde_json deserialization of RPC requests.
    if let Ok(s) = std::str::from_utf8(data) {
        // Try parsing as a JSON-RPC 2.0 request object
        let _: Result<serde_json::Value, _> = serde_json::from_str(s);

        // Try parsing as a JSON-RPC batch (array of requests)
        let _: Result<Vec<serde_json::Value>, _> = serde_json::from_str(s);

        // Simulate the RPC method extraction pattern used in eth_rpc.rs:
        // parse JSON, extract "method" string, extract "params" array
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(s) {
            if let Some(method) = val.get("method").and_then(|m| m.as_str()) {
                // Exercise method matching patterns
                let _ = method.starts_with("eth_");
                let _ = method.starts_with("citrate_");
                let _ = method.starts_with("net_");
                let _ = method.starts_with("web3_");
            }
            // Exercise params extraction
            if let Some(params) = val.get("params") {
                if let Some(arr) = params.as_array() {
                    for param in arr {
                        // Simulate hex parsing of RPC params
                        if let Some(s) = param.as_str() {
                            let stripped = s.strip_prefix("0x").unwrap_or(s);
                            let _ = hex::decode(stripped);
                            let _ = u64::from_str_radix(stripped, 16);
                        }
                    }
                }
            }
        }
    }
});
