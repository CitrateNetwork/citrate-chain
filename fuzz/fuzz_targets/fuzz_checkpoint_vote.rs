#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_consensus::CheckpointVote;

fuzz_target!(|data: &[u8]| {
    // Fuzz checkpoint vote deserialization via bincode.
    // CheckpointVote contains: height (u64), block_hash (Hash), voter (PublicKey),
    // signature (Signature). The deserializer must never panic on malformed input.
    let _: Result<CheckpointVote, _> = bincode::deserialize(data);

    // Also try JSON deserialization (used in RPC/API paths)
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<CheckpointVote, _> = serde_json::from_str(s);
    }
});
