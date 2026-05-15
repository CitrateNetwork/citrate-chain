// CIT-AGENT-9c-4 — verify-provenance-chain capsule.
//
// Single eth_call to PartProvenanceRegistry.verifyChain(bytes32).
// Return is a mixed (bool, bytes32[]) tuple:
//   chunk 0 (0..32):  bool (last byte 0/1)
//   chunk 1 (32..64): offset to bytes32[] (typically 0x40)
//   at offset: array length (uint256), then N × 32-byte entries

#[allow(warnings)]
mod bindings;

use bindings::citrate::chain::eth_call;
use bindings::exports::citrate::verify_provenance_chain::query::{Guest, VerifyResult};
use sha3::{Digest, Keccak256};

const REGISTRY_ADDR: [u8; 20] = [
    0x1a, 0xfe, 0x98, 0x76, 0x22, 0xab, 0x5a, 0xdd, 0x27, 0x5d,
    0x2f, 0xd2, 0x12, 0x48, 0xf7, 0x7f, 0x5e, 0x00, 0x66, 0x7f,
];

fn keccak4(data: &[u8]) -> [u8; 4] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut s = [0u8; 4];
    s.copy_from_slice(&out[..4]);
    s
}

fn parse_bytes32(s: &str) -> Result<[u8; 32], String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 64 {
        return Err(format!("expected 32-byte hex (64 chars), got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("bad hex at byte {i}"))?;
    }
    Ok(out)
}

/// Decode `(bool, bytes32[])` return.
fn decode_verify_result(ret: &[u8]) -> Result<VerifyResult, String> {
    if ret.len() < 64 {
        return Err(format!(
            "verifyChain response too short: got {}, need ≥ 64",
            ret.len()
        ));
    }
    let ok = ret[31] != 0;
    let mut off_b = [0u8; 32];
    off_b.copy_from_slice(&ret[32..64]);
    if off_b[0..24] != [0u8; 24] {
        return Err("bytes32[] offset has unexpected high bits".to_string());
    }
    let mut off_arr = [0u8; 8];
    off_arr.copy_from_slice(&off_b[24..32]);
    let off = u64::from_be_bytes(off_arr) as usize;
    if ret.len() < off + 32 {
        return Err(format!(
            "verifyChain response truncated at chain offset {off}: got {}",
            ret.len()
        ));
    }
    let mut len_b = [0u8; 32];
    len_b.copy_from_slice(&ret[off..off + 32]);
    if len_b[0..24] != [0u8; 24] {
        return Err("bytes32[] length has unexpected high bits".to_string());
    }
    let mut len_arr = [0u8; 8];
    len_arr.copy_from_slice(&len_b[24..32]);
    let len = u64::from_be_bytes(len_arr) as usize;
    let expected = off + 32 + len * 32;
    if ret.len() < expected {
        return Err(format!(
            "verifyChain chain entries truncated: need {expected}, got {}",
            ret.len()
        ));
    }
    let mut chain = Vec::with_capacity(len);
    for i in 0..len {
        let start = off + 32 + i * 32;
        chain.push(ret[start..start + 32].to_vec());
    }
    Ok(VerifyResult { ok, chain })
}

struct Component;

impl Guest for Component {
    fn query(part_hash: String) -> Result<VerifyResult, String> {
        let part_b = parse_bytes32(&part_hash)?;
        let selector = keccak4(b"verifyChain(bytes32)");
        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&part_b);
        let response = eth_call::call(&REGISTRY_ADDR, &calldata)?;
        decode_verify_result(&response)
    }
}

bindings::export!(Component with_types_in bindings);
