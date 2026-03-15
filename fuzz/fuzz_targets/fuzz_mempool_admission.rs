#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_consensus::types::Transaction;

fuzz_target!(|data: &[u8]| {
    // Fuzz mempool transaction admission by deserializing random Transaction structs.
    // The mempool's add_transaction is async and requires state, so we focus on the
    // deserialization boundary: can arbitrary bytes produce a valid Transaction
    // without panicking?

    // Bincode deserialization (primary internal format)
    let _: Result<Transaction, _> = bincode::deserialize(data);

    // JSON deserialization (used in RPC submission paths)
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<Transaction, _> = serde_json::from_str(s);
    }

    // Also exercise the eth_tx_decoder which feeds the mempool
    let _ = citrate_api::eth_tx_decoder::decode_eth_transaction(data);
});
