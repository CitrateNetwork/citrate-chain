// CIT-AGENT-9c-3 — query-supplier-status capsule.
//
// Single-call read of SupplierRegistry.get(bytes32). The return
// is a static 6-chunk struct — no outer offset, simplest decode
// path in the cit-agent capsule lineup.

#[allow(warnings)]
mod bindings;

use bindings::citrate::chain::eth_call;
use bindings::exports::citrate::query_supplier_status::query::{Guest, SupplierView};
use sha3::{Digest, Keccak256};

/// SupplierRegistry deployed address (chain 40204).
const REGISTRY_ADDR: [u8; 20] = [
    0x42, 0x50, 0x64, 0x44, 0x3c, 0x3c, 0x33, 0x92, 0xc4, 0x7d,
    0xcb, 0xe1, 0x0d, 0x45, 0x58, 0x31, 0x54, 0x5e, 0xfd, 0x9b,
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

/// Decode 6-chunk static Supplier struct. Layout:
///   [0..32)   supplier_id (bytes32)
///   [32..64)  scope (bytes32)
///   [64..96)  state (uint8, last byte)
///   [96..128) registered_at (uint64, low 8 bytes BE)
///   [128..160) qualification_period_days (uint64, low 8 bytes BE)
///   [160..192) exists (bool, skipped — call reverts on !exists)
fn decode_supplier(ret: &[u8]) -> Result<SupplierView, String> {
    if ret.len() < 192 {
        return Err(format!(
            "supplier response truncated: got {}, expected ≥ 192",
            ret.len()
        ));
    }
    let chunk = |off: usize| -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&ret[off..off + 32]);
        a
    };
    let supplier_id = chunk(0);
    let scope = chunk(32);
    let state_chunk = chunk(64);
    let registered_chunk = chunk(96);
    let period_chunk = chunk(128);
    let state = state_chunk[31];
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&registered_chunk[24..32]);
    let registered_at = u64::from_be_bytes(tail);
    tail.copy_from_slice(&period_chunk[24..32]);
    let qualification_period_days = u64::from_be_bytes(tail);
    Ok(SupplierView {
        supplier_id: supplier_id.to_vec(),
        scope: scope.to_vec(),
        state,
        registered_at,
        qualification_period_days,
    })
}

struct Component;

impl Guest for Component {
    fn query(supplier_id: String) -> Result<SupplierView, String> {
        let id = parse_bytes32(&supplier_id)?;
        let selector = keccak4(b"get(bytes32)");
        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&id);
        let response = eth_call::call(&REGISTRY_ADDR, &calldata)?;
        decode_supplier(&response)
    }
}

bindings::export!(Component with_types_in bindings);
