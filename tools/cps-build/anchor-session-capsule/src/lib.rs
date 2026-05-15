// CIT-AGENT-9c-7 — anchor-session capsule.
//
// Encodes `anchor(uint8, bytes32, bytes32, bytes32, bytes32,
// bytes32, uint256)` against AuditBundleRegistry. Static 7-slot
// calldata. bundle_id derived inside the capsule as
// keccak256(session_id || merkle_root) for retry idempotency.

#[allow(warnings)]
mod bindings;

use bindings::citrate::chain::eth_send;
use bindings::exports::citrate::anchor_session::action::Guest;
use sha3::{Digest, Keccak256};

const REGISTRY_ADDR: [u8; 20] = [
    0x9a, 0x58, 0xe4, 0x4f, 0x8d, 0xd6, 0xfd, 0x6a, 0x75, 0x63,
    0x7a, 0x32, 0xe6, 0xe5, 0x1c, 0x16, 0x44, 0x09, 0x96, 0xf8,
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

fn u256_from_u64(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

struct Component;

impl Guest for Component {
    fn anchor(
        kind: u8,
        session_id: String,
        scope: String,
        merkle_root: String,
        ipfs_cid: String,
        entry_count: u64,
    ) -> Result<Vec<u8>, String> {
        if kind > 2 {
            return Err(format!("kind must be 0..2, got {kind}"));
        }
        let session_b = parse_bytes32(&session_id)?;
        let scope_b = parse_bytes32(&scope)?;
        let merkle_b = parse_bytes32(&merkle_root)?;
        // Empty / "0x" ipfs_cid → zero bytes32; non-empty must be
        // 32-byte hex.
        let ipfs_b = if ipfs_cid.is_empty() || ipfs_cid == "0x" {
            [0u8; 32]
        } else {
            parse_bytes32(&ipfs_cid)?
        };

        // bundle_id = keccak256(session_id || merkle_root)
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&session_b);
        seed.extend_from_slice(&merkle_b);
        let bundle_id = keccak32(&seed);

        // ABI: selector + 7 × 32-byte slots
        let selector =
            keccak4(b"anchor(uint8,bytes32,bytes32,bytes32,bytes32,bytes32,uint256)");
        let mut calldata = Vec::with_capacity(4 + 7 * 32);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&u256_from_u64(kind as u64));
        calldata.extend_from_slice(&bundle_id);
        calldata.extend_from_slice(&session_b);
        calldata.extend_from_slice(&scope_b);
        calldata.extend_from_slice(&merkle_b);
        calldata.extend_from_slice(&ipfs_b);
        calldata.extend_from_slice(&u256_from_u64(entry_count));

        eth_send::send(&REGISTRY_ADDR, &calldata)
    }
}

bindings::export!(Component with_types_in bindings);
