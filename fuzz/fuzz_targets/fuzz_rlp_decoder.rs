#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the RLP transaction decoder with arbitrary bytes.
    // This exercises: EIP-1559 (type 0x02), EIP-2930 (type 0x01),
    // legacy RLP, and the unified decoder dispatch logic.
    // The decoder must never panic — all malformed input should return Err.

    // Main decode path (handles type byte dispatch)
    let _ = citrate_api::eth_tx_decoder::decode_eth_transaction(data);

    // Also test with explicit type prefixes to maximize coverage
    // of each decoder branch:

    // EIP-2930 prefix (type 0x01)
    if !data.is_empty() {
        let mut eip2930 = vec![0x01u8];
        eip2930.extend_from_slice(data);
        let _ = citrate_api::eth_tx_decoder::decode_eth_transaction(&eip2930);
    }

    // EIP-1559 prefix (type 0x02)
    if !data.is_empty() {
        let mut eip1559 = vec![0x02u8];
        eip1559.extend_from_slice(data);
        let _ = citrate_api::eth_tx_decoder::decode_eth_transaction(&eip1559);
    }
});
