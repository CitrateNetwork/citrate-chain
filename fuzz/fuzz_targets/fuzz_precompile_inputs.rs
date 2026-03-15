#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_execution::precompiles::PrecompileExecutor;
use citrate_execution::types::Address;

fuzz_target!(|data: &[u8]| {
    // Fuzz EVM precompile execution with arbitrary input bytes.
    // Exercises ECRECOVER (0x01), SHA256 (0x02), RIPEMD160 (0x03),
    // IDENTITY (0x04), MODEXP (0x05), ECADD (0x06), ECMUL (0x07),
    // ECPAIRING (0x08), BLAKE2F (0x09).
    // Each precompile must handle malformed/truncated input without panicking.

    let mut executor = PrecompileExecutor::new();
    let gas_limit: u64 = 1_000_000;

    // Test all 9 standard Ethereum precompile addresses
    for i in 1u8..=9 {
        let mut addr_bytes = [0u8; 20];
        addr_bytes[19] = i;
        let addr = Address(addr_bytes);
        // Precompile execution may return Err, but must never panic
        let _ = executor.execute(&addr, data, gas_limit);
    }
});
