// CIT-AGENT-9c-1 — list-compliance-posture capsule.
//
// Encodes ABI calldata for `framework(bytes32, bytes32)` against
// BoeingComplianceRegistry, calls eth-call via the host fn, and
// decodes the 288-byte Row response into a structured posture-row.
//
// All ABI work happens INSIDE the WASM sandbox — the harness's
// host fn just enforces the allow-list and routes the call. If
// the contract layout changes, only this capsule needs an update.

#[allow(warnings)]
mod bindings;

use bindings::citrate::chain::eth_call;
use bindings::exports::citrate::list_compliance_posture::query::{Guest, PostureRow};
use sha3::{Digest, Keccak256};

/// BoeingComplianceRegistry deployed address (Stage-9 deployment,
/// chain 40204). Hardcoded into the capsule so the harness can't
/// silently redirect to a different contract.
const REGISTRY_ADDR: [u8; 20] = [
    0x8d, 0xbb, 0xbc, 0x46, 0xd8, 0x40, 0xf4, 0x02, 0x05, 0xb4,
    0x8d, 0x76, 0xaa, 0x9f, 0xc5, 0x06, 0x3b, 0x7d, 0x55, 0xd8,
];

/// `keccak256("framework(bytes32,bytes32)")[..4]`. Computed at
/// the integration test site against the canonical selector to
/// ensure the capsule's calldata matches the existing
/// `LiveComplianceBindings::framework_row` calldata one-for-one.
fn function_selector() -> [u8; 4] {
    let mut hasher = Keccak256::new();
    hasher.update(b"framework(bytes32,bytes32)");
    let out = hasher.finalize();
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&out[..4]);
    sel
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Parse `0x`-prefixed (or not) 64-hex string into a `[u8; 32]`.
/// Returns `Err(reason)` on malformed input.
fn parse_bytes32(s: &str) -> Result<[u8; 32], String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 64 {
        return Err(format!("expected 32-byte hex (64 chars), got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte_hex = &hex[i * 2..i * 2 + 2];
        out[i] = u8::from_str_radix(byte_hex, 16)
            .map_err(|_| format!("bad hex at byte {i}: {byte_hex}"))?;
    }
    Ok(out)
}

/// Decode 9 32-byte chunks (288 bytes) into a `PostureRow`. Layout
/// mirrors `LiveComplianceBindings::decode_row` exactly:
///   0   row_id (bytes32)
///   32  framework (bytes32)
///   64  scope (bytes32)
///   96  evidence_cid (bytes32)
///   128 attestor (bytes32)
///   160 posture (uint8 right-padded to 32 bytes)
///   192 expired (bool right-padded to 32 bytes)
///   224 attested_at_block (uint256 — we take the low 64 bits)
///   256 expires_at_block (uint256 — we take the low 64 bits)
fn decode_row(ret: &[u8]) -> Result<PostureRow, String> {
    if ret.len() < 288 {
        return Err(format!(
            "row response truncated: got {} bytes, expected ≥ 288",
            ret.len()
        ));
    }
    let chunk = |offset: usize| -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&ret[offset..offset + 32]);
        a
    };
    let row_id = chunk(0);
    let framework = chunk(32);
    let scope = chunk(64);
    let evidence_cid = chunk(96);
    let attestor = chunk(128);
    let posture_chunk = chunk(160);
    let expired_chunk = chunk(192);
    let attested_chunk = chunk(224);
    let expires_chunk = chunk(256);

    // For a uint8, all but the last byte is zero (ABI right-pads).
    let posture = posture_chunk[31];
    // For bool, the last byte is 0 or 1.
    let expired = expired_chunk[31] != 0;
    // uint256 → u64: read the low 8 bytes (big-endian).
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&attested_chunk[24..32]);
    let attested_at_block = u64::from_be_bytes(tail);
    tail.copy_from_slice(&expires_chunk[24..32]);
    let expires_at_block = u64::from_be_bytes(tail);

    Ok(PostureRow {
        row_id: row_id.to_vec(),
        framework: framework.to_vec(),
        scope: scope.to_vec(),
        evidence_cid: evidence_cid.to_vec(),
        attestor: attestor.to_vec(),
        posture,
        expired,
        attested_at_block,
        expires_at_block,
    })
}

struct Component;

impl Guest for Component {
    fn query(framework: String, scope: String) -> Result<PostureRow, String> {
        let framework_hash = keccak256(framework.as_bytes());
        let scope_bytes = parse_bytes32(&scope)?;
        let selector = function_selector();
        let mut calldata = Vec::with_capacity(4 + 32 + 32);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&framework_hash);
        calldata.extend_from_slice(&scope_bytes);
        let response = eth_call::call(&REGISTRY_ADDR, &calldata)?;
        decode_row(&response)
    }
}

bindings::export!(Component with_types_in bindings);
