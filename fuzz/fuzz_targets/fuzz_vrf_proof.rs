#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_consensus::EcvrfProof;

fuzz_target!(|data: &[u8]| {
    // Fuzz ECVRF proof parsing with arbitrary bytes.
    // EcvrfProof::from_bytes expects exactly 114 bytes:
    //   pk_p256 (33) + Gamma (33) + c (16) + s (32)
    // Must gracefully reject invalid lengths and malformed curve points.
    let _ = EcvrfProof::from_bytes(data);

    // Also fuzz the full verify path if we can parse a proof.
    // verify(alpha, proof) — the public key is embedded in the proof struct.
    if data.len() >= 114 {
        let proof_bytes = &data[..114];
        let alpha = &data[114..];

        if let Ok(proof) = EcvrfProof::from_bytes(proof_bytes) {
            // verify() should return Err for invalid proofs, never panic
            let _ = citrate_consensus::ecvrf::verify(alpha, &proof);
        }
    }
});
