#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_consensus::types::Block;

fuzz_target!(|data: &[u8]| {
    // Fuzz block deserialization via bincode.
    // The deserializer must never panic on malformed input.
    let _: Result<Block, _> = bincode::deserialize(data);
});
