#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the main transaction decoder with arbitrary bytes.
    // This exercises: RLP legacy, EIP-1559, EIP-2930, and bincode paths.
    // The decoder must never panic — all malformed input should return Err.
    let _ = citrate_api::eth_tx_decoder::decode_eth_transaction(data);
});
