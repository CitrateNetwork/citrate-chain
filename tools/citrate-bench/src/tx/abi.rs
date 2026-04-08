//! Minimal ABI encoding helpers for benchmark workload classes.
//!
//! These are the hand-rolled subset of Ethereum ABI encoding that the
//! Phase-4 workloads need: 4-byte keccak selectors, static `uint256`
//! from native integers, left-padded `address`, `bytes32` passthrough,
//! and one composite encoder for the `Forwarder.execute` calldata —
//! the only non-trivial case, because it contains a dynamic `bytes`
//! inside a dynamic tuple.
//!
//! The intent is **not** to reimplement a general-purpose ABI encoder.
//! The surface is deliberately narrow so that the hand-computed test
//! vectors in this module are easy to read and audit.

use sha3::{Digest, Keccak256};

/// Compute the 4-byte function selector: `keccak256(signature)[..4]`.
///
/// `signature` is the canonical Solidity form with no spaces and
/// parameter types only, e.g., `"transfer(address,uint256)"`.
pub fn selector(signature: &str) -> [u8; 4] {
    let hash = Keccak256::digest(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

/// Encode a 20-byte address into a 32-byte ABI word (left-padded with
/// zeros, address bytes in the low 20).
pub fn encode_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr);
    out
}

/// Encode a `u128` as a 32-byte big-endian `uint256` word.
pub fn encode_uint256_u128(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

/// Encode a `u64` as a 32-byte big-endian `uint256` word.
pub fn encode_uint256_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// Encode a `bytes32` word. Identity — this helper exists for type
/// clarity at call sites only.
pub fn encode_bytes32(v: &[u8; 32]) -> [u8; 32] {
    *v
}

/// Round a byte length up to the next 32-byte boundary.
pub(crate) fn padded_len(n: usize) -> usize {
    n.div_ceil(32) * 32
}

/// Arguments for `Forwarder.execute((bytes32,uint256,uint256,uint256,bytes32,address,bytes),bytes)`.
///
/// See `contracts/src/edu/interfaces/IForwarder.sol` for the source of
/// truth on field order and types.
#[derive(Debug, Clone)]
pub struct ForwardRequestArgs<'a> {
    pub org_principal_id: [u8; 32],
    pub classroom_id: u64,
    pub nonce: u64,
    pub session_expiry: u64,
    pub device_cert_hash: [u8; 32],
    pub target: [u8; 20],
    pub data: &'a [u8],
}

/// Build the full `execute(...)` calldata including the 4-byte selector.
///
/// The `ForwardRequest` tuple contains a dynamic `bytes` field, so the
/// tuple itself is dynamic at the outer level. The outer
/// `bytes relayerSignature` argument is likewise dynamic. Both are
/// therefore encoded as an offset in the head section and a length-
/// prefixed tail after the static region.
///
/// Layout (bytes, inclusive/exclusive):
///
/// ```text
///   [0..4)     selector
///   [4..36)    offset_to_request_tail  = 64
///   [36..68)   offset_to_sig_tail      = 64 + request_total_len
///   [68..100)  request_tuple[0]  orgPrincipalId        (bytes32)
///   [100..132) request_tuple[1]  classroomId           (uint256)
///   [132..164) request_tuple[2]  nonce                 (uint256)
///   [164..196) request_tuple[3]  sessionExpiry         (uint256)
///   [196..228) request_tuple[4]  deviceCertHash        (bytes32)
///   [228..260) request_tuple[5]  target                (address)
///   [260..292) request_tuple[6]  offset_to_data_tail   = 7 * 32 = 224
///   [292..324) data length
///   [324..324+pad(data.len)) data bytes + right-pad to 32
///   ... sig length ...
///   ... sig bytes + right-pad to 32 ...
/// ```
pub fn encode_forwarder_execute(req: &ForwardRequestArgs<'_>, relayer_sig: &[u8]) -> Vec<u8> {
    // Canonical signature per IForwarder.sol.
    let sel = selector("execute((bytes32,uint256,uint256,uint256,bytes32,address,bytes),bytes)");

    let data_padded = padded_len(req.data.len());
    let sig_padded = padded_len(relayer_sig.len());

    // Tuple tail: length word (32) + padded data.
    let request_tail_len = 32 + data_padded;
    // Tuple total: head (7 words) + tail.
    let request_total_len = 7 * 32 + request_tail_len;
    // Outer heads: two offsets (2 * 32).
    let offset_to_request: u64 = 64;
    let offset_to_sig: u64 = 64 + request_total_len as u64;
    // Sig tail: length word + padded sig.
    let sig_tail_len = 32 + sig_padded;

    let total_len = 4 + 64 + request_total_len + sig_tail_len;
    let mut out = Vec::with_capacity(total_len);

    out.extend_from_slice(&sel);
    out.extend_from_slice(&encode_uint256_u64(offset_to_request));
    out.extend_from_slice(&encode_uint256_u64(offset_to_sig));

    // Request head (7 words) within the tuple encoding.
    out.extend_from_slice(&encode_bytes32(&req.org_principal_id));
    out.extend_from_slice(&encode_uint256_u64(req.classroom_id));
    out.extend_from_slice(&encode_uint256_u64(req.nonce));
    out.extend_from_slice(&encode_uint256_u64(req.session_expiry));
    out.extend_from_slice(&encode_bytes32(&req.device_cert_hash));
    out.extend_from_slice(&encode_address(&req.target));
    // Offset to the dynamic `data` tail within the tuple encoding:
    // after 7 head words = 224 bytes.
    out.extend_from_slice(&encode_uint256_u64(7 * 32));

    // Request dynamic tail: len + padded data.
    out.extend_from_slice(&encode_uint256_u64(req.data.len() as u64));
    out.extend_from_slice(req.data);
    out.resize(out.len() + (data_padded - req.data.len()), 0);

    // Relayer signature tail: len + padded bytes.
    out.extend_from_slice(&encode_uint256_u64(relayer_sig.len() as u64));
    out.extend_from_slice(relayer_sig);
    out.resize(out.len() + (sig_padded - relayer_sig.len()), 0);

    debug_assert_eq!(out.len(), total_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical ERC-20 `transfer(address,uint256)` selector is `0xa9059cbb`.
    #[test]
    fn selector_matches_erc20_transfer() {
        let s = selector("transfer(address,uint256)");
        assert_eq!(s, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    /// Canonical ERC-20 `balanceOf(address)` selector is `0x70a08231`.
    #[test]
    fn selector_matches_erc20_balance_of() {
        let s = selector("balanceOf(address)");
        assert_eq!(s, [0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn encode_address_left_pads() {
        let addr = [0xaa; 20];
        let word = encode_address(&addr);
        // First 12 bytes should be zero.
        assert_eq!(&word[..12], &[0u8; 12]);
        // Last 20 bytes are the address.
        assert_eq!(&word[12..], &addr);
    }

    #[test]
    fn encode_uint256_u128_is_big_endian_right_aligned() {
        let v = 0x1122_3344_5566_7788u128;
        let word = encode_uint256_u128(v);
        // Upper 24 bytes must be zero (v fits in u64).
        for b in &word[..24] {
            assert_eq!(*b, 0);
        }
        assert_eq!(&word[24..], &v.to_be_bytes()[8..]);
    }

    #[test]
    fn encode_uint256_u64_is_big_endian_right_aligned() {
        let v = 42u64;
        let word = encode_uint256_u64(v);
        for b in &word[..24] {
            assert_eq!(*b, 0);
        }
        assert_eq!(&word[24..], &v.to_be_bytes());
    }

    #[test]
    fn padded_len_rounds_up_to_32() {
        assert_eq!(padded_len(0), 0);
        assert_eq!(padded_len(1), 32);
        assert_eq!(padded_len(31), 32);
        assert_eq!(padded_len(32), 32);
        assert_eq!(padded_len(33), 64);
        assert_eq!(padded_len(64), 64);
        assert_eq!(padded_len(65), 96);
    }

    #[test]
    fn forwarder_execute_empty_data_and_sig_has_expected_length() {
        let req = ForwardRequestArgs {
            org_principal_id: [0u8; 32],
            classroom_id: 0,
            nonce: 0,
            session_expiry: 0,
            device_cert_hash: [0u8; 32],
            target: [0u8; 20],
            data: &[],
        };
        let sig = &[] as &[u8];
        let call = encode_forwarder_execute(&req, sig);
        // 4 selector + 64 top-level head + (7*32 + 32) request tuple + 32 sig tail
        //   = 4 + 64 + (224 + 32) + 32 = 356 bytes
        assert_eq!(call.len(), 4 + 64 + 256 + 32);
    }

    #[test]
    fn forwarder_execute_selector_is_first_four_bytes() {
        let req = ForwardRequestArgs {
            org_principal_id: [0u8; 32],
            classroom_id: 0,
            nonce: 0,
            session_expiry: 0,
            device_cert_hash: [0u8; 32],
            target: [0u8; 20],
            data: &[],
        };
        let call = encode_forwarder_execute(&req, &[]);
        let sel = selector("execute((bytes32,uint256,uint256,uint256,bytes32,address,bytes),bytes)");
        assert_eq!(&call[..4], &sel);
    }

    #[test]
    fn forwarder_execute_top_level_offsets_are_correct() {
        // With data=[] and sig=[]:
        //   offset_to_request = 64
        //   request_total_len = 7*32 + 32 = 256
        //   offset_to_sig     = 64 + 256 = 320
        let req = ForwardRequestArgs {
            org_principal_id: [0u8; 32],
            classroom_id: 0,
            nonce: 0,
            session_expiry: 0,
            device_cert_hash: [0u8; 32],
            target: [0u8; 20],
            data: &[],
        };
        let call = encode_forwarder_execute(&req, &[]);
        let off_req = u64::from_be_bytes(call[4 + 24..4 + 32].try_into().unwrap());
        let off_sig = u64::from_be_bytes(call[4 + 32 + 24..4 + 64].try_into().unwrap());
        assert_eq!(off_req, 64);
        assert_eq!(off_sig, 320);
    }

    #[test]
    fn forwarder_execute_encodes_fields_in_order() {
        let org = [0x11u8; 32];
        let dev = [0x22u8; 32];
        let mut target = [0u8; 20];
        target[19] = 0xab;
        let req = ForwardRequestArgs {
            org_principal_id: org,
            classroom_id: 7,
            nonce: 11,
            session_expiry: 99,
            device_cert_hash: dev,
            target,
            data: &[],
        };
        let call = encode_forwarder_execute(&req, &[]);
        // Head starts at offset 4 + 64 = 68.
        let head_start = 68;
        assert_eq!(&call[head_start..head_start + 32], &org);
        assert_eq!(
            &call[head_start + 32..head_start + 64],
            &encode_uint256_u64(7)
        );
        assert_eq!(
            &call[head_start + 64..head_start + 96],
            &encode_uint256_u64(11)
        );
        assert_eq!(
            &call[head_start + 96..head_start + 128],
            &encode_uint256_u64(99)
        );
        assert_eq!(&call[head_start + 128..head_start + 160], &dev);
        assert_eq!(
            &call[head_start + 160..head_start + 192],
            &encode_address(&target)
        );
        // Data offset (relative to tuple start) = 7 * 32 = 224
        assert_eq!(
            &call[head_start + 192..head_start + 224],
            &encode_uint256_u64(224)
        );
    }

    #[test]
    fn forwarder_execute_non_empty_data_is_padded() {
        let req = ForwardRequestArgs {
            org_principal_id: [0u8; 32],
            classroom_id: 0,
            nonce: 0,
            session_expiry: 0,
            device_cert_hash: [0u8; 32],
            target: [0u8; 20],
            data: &[0xde, 0xad, 0xbe, 0xef],
        };
        let call = encode_forwarder_execute(&req, &[]);
        // request total = 7*32 + 32 + padded(4) = 224 + 32 + 32 = 288
        // total = 4 + 64 + 288 + 32 = 388
        assert_eq!(call.len(), 4 + 64 + 288 + 32);
        // Data length word then 4 bytes of data + 28 pad zeros.
        let data_len_pos = 4 + 64 + 7 * 32;
        let data_len = u64::from_be_bytes(
            call[data_len_pos + 24..data_len_pos + 32]
                .try_into()
                .unwrap(),
        );
        assert_eq!(data_len, 4);
        assert_eq!(
            &call[data_len_pos + 32..data_len_pos + 36],
            &[0xde, 0xad, 0xbe, 0xef]
        );
        // Padding after the 4 bytes is all zero.
        assert!(call[data_len_pos + 36..data_len_pos + 64]
            .iter()
            .all(|&b| b == 0));
    }
}
