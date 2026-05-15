// CIT-AGENT-9c-6 — revoke-role capsule.
//
// Encodes `revoke(bytes32 user, bytes32 tenant, bytes32 reason,
// bytes32 corr_id)` against RoleEscalation. Pure-static 4-slot
// calldata.

#[allow(warnings)]
mod bindings;

use bindings::citrate::chain::eth_send;
use bindings::exports::citrate::revoke_role::action::Guest;
use sha3::{Digest, Keccak256};

/// RoleEscalation deployed address (chain 40204).
const REGISTRY_ADDR: [u8; 20] = [
    0xa6, 0xa4, 0x12, 0x21, 0x26, 0xa7, 0x56, 0x11, 0xea, 0x06,
    0x24, 0x1e, 0x40, 0x43, 0x27, 0xad, 0xdf, 0xe8, 0xeb, 0x5e,
];

fn keccak4(data: &[u8]) -> [u8; 4] {
    let mut h = Keccak256::new();
    h.update(data);
    let out = h.finalize();
    let mut s = [0u8; 4];
    s.copy_from_slice(&out[..4]);
    s
}

fn keccak32(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
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

/// Hex-encode 32 bytes (lower-case, no `0x` prefix).
fn hex32(b: &[u8; 32]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in b {
        out.push(HEX[(*byte >> 4) as usize] as char);
        out.push(HEX[(*byte & 0x0f) as usize] as char);
    }
    out
}

struct Component;

impl Guest for Component {
    fn revoke(
        user: String,
        tenant: String,
        reason: String,
    ) -> Result<Vec<u8>, String> {
        let user_b = parse_bytes32(&user)?;
        let tenant_b = parse_bytes32(&tenant)?;
        // reason: free-form string keccak256'd to bytes32, matching
        // the Boeing chat tool's `keccak_short(reason)` shape.
        let reason_b = keccak32(reason.as_bytes());
        // Deterministic corr_id: keccak256("revoke_role|0x<user>|0x<tenant>|<reason>")
        let corr_seed = format!(
            "revoke_role|0x{}|0x{}|{reason}",
            hex32(&user_b),
            hex32(&tenant_b)
        );
        let corr_id = keccak32(corr_seed.as_bytes());

        // ABI: selector + 4 × 32 bytes.
        let selector = keccak4(b"revoke(bytes32,bytes32,bytes32,bytes32)");
        let mut calldata = Vec::with_capacity(4 + 4 * 32);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&user_b);
        calldata.extend_from_slice(&tenant_b);
        calldata.extend_from_slice(&reason_b);
        calldata.extend_from_slice(&corr_id);

        eth_send::send(&REGISTRY_ADDR, &calldata)
    }
}

bindings::export!(Component with_types_in bindings);
