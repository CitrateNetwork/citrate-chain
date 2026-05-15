// CIT-AGENT-9c-5 — provision-user capsule.
//
// Encodes `requestElevation(bytes32 user, bytes32 tenant,
// bytes32 role, uint32 duration_sec, bytes32 corr_id, bytes
// reauth_proof, string reauth_proof_kind)` against RoleEscalation.
// 7-slot head + 2 dynamic tails (bytes + string).

#[allow(warnings)]
mod bindings;

use bindings::citrate::chain::eth_send;
use bindings::exports::citrate::provision_user::action::Guest;
use sha3::{Digest, Keccak256};

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

fn hex32(b: &[u8; 32]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in b {
        out.push(HEX[(*byte >> 4) as usize] as char);
        out.push(HEX[(*byte & 0x0f) as usize] as char);
    }
    out
}

fn u256_from_u64(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

/// 32-byte-aligned padding length: ceil(len / 32) * 32.
fn padded_len(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        ((len + 31) / 32) * 32
    }
}

/// Push a Solidity `bytes` (length-prefixed, right-padded to 32).
fn push_bytes_dynamic(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&u256_from_u64(data.len() as u64));
    out.extend_from_slice(data);
    let pad = padded_len(data.len()) - data.len();
    for _ in 0..pad {
        out.push(0u8);
    }
}

struct Component;

impl Guest for Component {
    fn provision(
        user: String,
        tenant: String,
        role: String,
        duration_sec: u32,
        reauth_kind: String,
    ) -> Result<Vec<u8>, String> {
        let user_b = parse_bytes32(&user)?;
        let tenant_b = parse_bytes32(&tenant)?;
        let role_b = parse_bytes32(&role)?;

        // Deterministic corr_id — matches Boeing chat tool:
        //   keccak256("provision_user|0x<user>|0x<tenant>")
        let seed = format!(
            "provision_user|0x{}|0x{}",
            hex32(&user_b),
            hex32(&tenant_b)
        );
        let corr_id = keccak32(seed.as_bytes());

        // Placeholder reauth_proof (single byte). Real PIV/CAC
        // attestation flows in CIT-AGENT-10.
        let reauth_proof: Vec<u8> = vec![0x01];
        let kind_bytes = reauth_kind.as_bytes();

        // ABI layout:
        //   selector (4)
        //   user, tenant, role        — 3 × 32
        //   duration_sec (u256)       — 32
        //   corr_id                   — 32
        //   reauth_proof offset       — 32  → 7 * 32 = 224
        //   reauth_kind offset        — 32  → 224 + 32 + padded(proof)
        //   reauth_proof tail (len + bytes + pad)
        //   reauth_kind tail (len + bytes + pad)
        let head_len = 7 * 32;
        let proof_offset = head_len;
        let kind_offset = proof_offset + 32 + padded_len(reauth_proof.len());

        let selector = keccak4(
            b"requestElevation(bytes32,bytes32,bytes32,uint32,bytes32,bytes,string)",
        );
        let mut calldata =
            Vec::with_capacity(4 + head_len + 32 + 32 + reauth_proof.len() + kind_bytes.len());
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(&user_b);
        calldata.extend_from_slice(&tenant_b);
        calldata.extend_from_slice(&role_b);
        calldata.extend_from_slice(&u256_from_u64(duration_sec as u64));
        calldata.extend_from_slice(&corr_id);
        calldata.extend_from_slice(&u256_from_u64(proof_offset as u64));
        calldata.extend_from_slice(&u256_from_u64(kind_offset as u64));
        push_bytes_dynamic(&mut calldata, &reauth_proof);
        push_bytes_dynamic(&mut calldata, kind_bytes);

        eth_send::send(&REGISTRY_ADDR, &calldata)
    }
}

bindings::export!(Component with_types_in bindings);
