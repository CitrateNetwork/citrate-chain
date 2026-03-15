#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_consensus::types::{Hash, PublicKey, Signature};

/// Simulated bridge attestation structure matching the on-wire format.
/// There is no dedicated bridge.rs module yet, so we fuzz the deserialization
/// of the attestation payload that a bridge verifier would receive.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct BridgeAttestation {
    /// Source chain identifier
    source_chain_id: u64,
    /// Destination chain identifier
    dest_chain_id: u64,
    /// Block height on source chain
    source_height: u64,
    /// State root of the source chain at source_height
    state_root: Hash,
    /// Transaction hash being attested
    tx_hash: Hash,
    /// Attester public key
    attester: PublicKey,
    /// Signature over the attestation payload
    signature: Signature,
    /// Nonce to prevent replay
    nonce: u64,
}

fuzz_target!(|data: &[u8]| {
    // Fuzz bridge attestation deserialization via bincode.
    // This exercises the nested Hash/PublicKey/Signature deserializers
    // with arbitrary bytes, checking for panics in fixed-size array parsing.
    let _: Result<BridgeAttestation, _> = bincode::deserialize(data);

    // Also exercise JSON path
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<BridgeAttestation, _> = serde_json::from_str(s);
    }
});
