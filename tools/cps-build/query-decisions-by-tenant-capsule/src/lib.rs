// CIT-AGENT-9c-2 — query-decisions-by-tenant capsule.
//
// Two-call capsule. First call: latestByTenant(bytes32, uint256) →
// returns bytes32[] of decision IDs. Then per-ID: getDecision(bytes32)
// → returns a dynamic struct that we decode into 6-field summaries.
//
// All ABI work + N-cap enforcement happens inside the WASM sandbox.

#[allow(warnings)]
mod bindings;

use bindings::citrate::chain::eth_call;
use bindings::exports::citrate::query_decisions_by_tenant::query::{DecisionSummary, Guest};
use sha3::{Digest, Keccak256};

/// AgentDecisionRegistryV2 deployed address (Stage-9 deployment,
/// chain 40204). Hardcoded — manifest allow-list cross-checks
/// this at the host fn boundary.
const REGISTRY_ADDR: [u8; 20] = [
    0x4a, 0x86, 0x65, 0x9b, 0xda, 0xb2, 0x4d, 0xc4, 0x44, 0xc7,
    0x2f, 0xbb, 0xad, 0x4c, 0xd8, 0x34, 0x91, 0x82, 0x0e, 0x40,
];

/// Max decision IDs to fetch per invocation. Mirrors the DPF-INT-12
/// chat-tool contract.
const MAX_N: u32 = 50;

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

/// Encode uint256 as a 32-byte big-endian chunk. We only ever pass
/// small u64 values, so the high 24 bytes are zero.
fn encode_u256_from_u64(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

/// Decode the bytes32[] return from latestByTenant. Layout:
///   [0..32)   outer offset (always 32 — points at byte 32)
///   [32..64)  array length N
///   [64..)    N * 32 bytes of entries
fn decode_bytes32_array(ret: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if ret.len() < 64 {
        return Err(format!(
            "bytes32[] response too short: got {}, need ≥ 64",
            ret.len()
        ));
    }
    // Verify outer offset is 32. (Solidity-ABI always emits 0x20 here
    // for a single dynamic-return type.)
    let mut off_bytes = [0u8; 32];
    off_bytes.copy_from_slice(&ret[0..32]);
    if off_bytes[0..24] != [0u8; 24] {
        return Err("bytes32[] outer offset has unexpected high bits".to_string());
    }
    let mut len_bytes = [0u8; 32];
    len_bytes.copy_from_slice(&ret[32..64]);
    if len_bytes[0..24] != [0u8; 24] {
        return Err("bytes32[] length has unexpected high bits".to_string());
    }
    let mut len_arr = [0u8; 8];
    len_arr.copy_from_slice(&len_bytes[24..32]);
    let len = u64::from_be_bytes(len_arr) as usize;
    let expected_total = 64 + len * 32;
    if ret.len() < expected_total {
        return Err(format!(
            "bytes32[] truncated: got {}, expected {}",
            ret.len(),
            expected_total
        ));
    }
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let start = 64 + i * 32;
        let mut chunk = [0u8; 32];
        chunk.copy_from_slice(&ret[start..start + 32]);
        out.push(chunk);
    }
    Ok(out)
}

/// Decode the getDecision dynamic-struct response into a 6-field
/// summary. Layout per LiveAssistantBindings::get_decision:
///   [0..32)        outer offset → s
///   s+0..s+32      decision_id (bytes32)
///   s+32..s+64     user (bytes32)
///   s+64..s+96     tenant (bytes32)
///   s+96..s+128    corr_id (bytes32)
///   s+128..s+160   class (uint8, last byte)
///   s+160..s+288   skipped fields (description/auth_mode/
///                  artifact_root/status offsets)
///   s+288..s+320   ts (uint64 — low 8 bytes BE)
fn decode_decision(ret: &[u8]) -> Result<DecisionSummary, String> {
    if ret.len() < 32 {
        return Err("decision response missing outer offset".to_string());
    }
    let mut off_b = [0u8; 32];
    off_b.copy_from_slice(&ret[0..32]);
    if off_b[0..24] != [0u8; 24] {
        return Err("decision outer offset has unexpected high bits".to_string());
    }
    let mut off_arr = [0u8; 8];
    off_arr.copy_from_slice(&off_b[24..32]);
    let s = u64::from_be_bytes(off_arr) as usize;
    if ret.len() < s + 320 {
        return Err(format!(
            "decision struct truncated: got {}, need {}",
            ret.len(),
            s + 320
        ));
    }
    let chunk = |offset: usize| -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&ret[offset..offset + 32]);
        a
    };
    let decision_id = chunk(s);
    let user = chunk(s + 32);
    let tenant = chunk(s + 64);
    let corr_id = chunk(s + 96);
    let class_chunk = chunk(s + 128);
    let ts_chunk = chunk(s + 288);
    let class = class_chunk[31];
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&ts_chunk[24..32]);
    let recorded_at_block = u64::from_be_bytes(tail);
    Ok(DecisionSummary {
        decision_id: decision_id.to_vec(),
        user: user.to_vec(),
        tenant: tenant.to_vec(),
        corr_id: corr_id.to_vec(),
        class,
        recorded_at_block,
    })
}

struct Component;

impl Guest for Component {
    fn query(tenant: String, n: u32) -> Result<Vec<DecisionSummary>, String> {
        let tenant_b = parse_bytes32(&tenant)?;
        let n_capped = n.min(MAX_N);

        // Step 1: latestByTenant(bytes32, uint256) → bytes32[]
        let selector_latest = keccak4(b"latestByTenant(bytes32,uint256)");
        let mut calldata = Vec::with_capacity(68);
        calldata.extend_from_slice(&selector_latest);
        calldata.extend_from_slice(&tenant_b);
        calldata.extend_from_slice(&encode_u256_from_u64(n_capped as u64));
        let ids_resp = eth_call::call(&REGISTRY_ADDR, &calldata)?;
        let ids = decode_bytes32_array(&ids_resp)?;

        // Step 2: per-ID getDecision(bytes32) → Decision (dynamic struct)
        let selector_get = keccak4(b"getDecision(bytes32)");
        let mut out = Vec::with_capacity(ids.len());
        for id in ids.iter() {
            let mut cd = Vec::with_capacity(36);
            cd.extend_from_slice(&selector_get);
            cd.extend_from_slice(id);
            let dec_resp = eth_call::call(&REGISTRY_ADDR, &cd)?;
            out.push(decode_decision(&dec_resp)?);
        }
        Ok(out)
    }
}

bindings::export!(Component with_types_in bindings);
