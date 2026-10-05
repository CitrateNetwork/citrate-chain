// citrate/core/execution/src/precompiles/agent_ops.rs
//
// HUP-S7.2 / federation F-3: 0x0122 AGENT_OPS (agent precompile fork,
// `crate::agent_fork`). Spec: `docs/precompiles/AGENT_PRECOMPILES.md`.
//
// Agent identity operations a contract cannot do cheaply or without drift. The
// first byte of the input selects the operation:
//
//   0x01 DEVICE_LINK_VERIFY        a member's three-signature DeviceLink (D-31)
//   0x02 DEVICE_REVOCATION_VERIFY  a member's signed DeviceRevocation
//
// A DeviceLink binds one device key (the device's libp2p / mesh identity) to a
// member: the member's roster key, the device key itself and the member's
// custody wallet each sign the same human-readable text with EIP-191
// `personal_sign`. The exact text is defined in citrate-cluster
// (`cluster_core::device::DeviceLink::signing_message`) and pinned by a golden
// vector shared with citrate-core; this precompile builds the same bytes, so a
// contract (an on-chain device roster, an AgentSBT device binding) accepts
// exactly the links the mesh accepts. Building that text in Solidity means
// lowercase hex and decimal formatting plus three `ecrecover`s per link: easy to
// get subtly different, which is the drift this operation removes.
//
// Rules, identical to cluster-core / cluster-daemon:
//   * signatures are 65 bytes `r || s || v`, v in {0, 1, 27, 28};
//   * high-s signatures are refused (the malleable twin of a valid signature);
//   * the device key must differ from the member key and the wallet;
//   * index <= 1023;
//   * label: 1..=48 bytes of ASCII letters, digits, space, `.`, `_`, `-`, `'`, with
//     no leading or trailing space.
//
// Output: a 32-byte big-endian word, 1 when every check passes and 0 otherwise.
// Malformed input (unknown op, wrong length) is an error, which fails the frame.
// The precompile verifies only; it holds no key and signs nothing.

use anyhow::{anyhow, Result};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

use super::PrecompileResult;

/// 0x0122 AGENT_OPS.
pub const AGENT_OPS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x22,
];

/// Operation selectors (first input byte).
pub const OP_DEVICE_LINK_VERIFY: u8 = 0x01;
pub const OP_DEVICE_REVOCATION_VERIFY: u8 = 0x02;

/// DeviceLink message version (cluster-core `DEVICE_LINK_VERSION`).
pub const DEVICE_LINK_VERSION: u32 = 1;
/// Longest label (cluster-core `MAX_LABEL_LEN`).
pub const MAX_LABEL_LEN: usize = 48;
/// Highest device index (cluster-core `MAX_DEVICE_INDEX`).
pub const MAX_DEVICE_INDEX: u32 = 1023;

/// Gas schedule. Conservative placeholder values, pending owner sign-off:
/// `ecrecover`'s 3000 per signature, keccak's 6 per message word, plus a base.
pub mod gas_costs {
    pub const BASE: u64 = 1_000;
    pub const PER_SIGNATURE: u64 = 3_000;
    pub const PER_MESSAGE_WORD: u64 = 6;
}

const SIG_LEN: usize = 65;
/// The three signatures (member, device, wallet) of a DEVICE_LINK_VERIFY body.
const LINK_SIGS_LEN: usize = 3 * SIG_LEN;

/// The exact DeviceLink text (cluster-core `DeviceLink::signing_message`).
pub fn device_link_message(
    member: &[u8; 20],
    device: &[u8; 20],
    wallet: &[u8; 20],
    index: u32,
    label: &str,
    issued_at: u64,
) -> String {
    format!(
        "Citrate DeviceLink v{DEVICE_LINK_VERSION}\n\
         Link this device to my Citrate member identity.\n\
         member: 0x{}\n\
         device: 0x{}\n\
         wallet: 0x{}\n\
         index: {}\n\
         label: {}\n\
         issued_at: {}",
        hex::encode(member),
        hex::encode(device),
        hex::encode(wallet),
        index,
        label,
        issued_at
    )
}

/// The exact DeviceRevocation text (cluster-core `DeviceRevocation::signing_message`).
pub fn device_revocation_message(member: &[u8; 20], device: &[u8; 20], revoked_at: u64) -> String {
    format!(
        "Citrate DeviceRevocation v{DEVICE_LINK_VERSION}\n\
         Remove this device from my Citrate member identity.\n\
         member: 0x{}\n\
         device: 0x{}\n\
         revoked_at: {}",
        hex::encode(member),
        hex::encode(device),
        revoked_at
    )
}

/// cluster-core `label_is_valid`.
pub fn label_is_valid(label: &[u8]) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && label.first() != Some(&b' ')
        && label.last() != Some(&b' ')
        && label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-' | b'\''))
}

/// EIP-191 `personal_sign` digest.
pub fn eip191_digest(message: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
    h.update(message);
    h.finalize().into()
}

/// The address that signed `digest`, or `None` (malformed, high-s, bad v, no
/// recovery).
fn recover(digest: &[u8; 32], sig: &[u8]) -> Option<[u8; 20]> {
    let (rs, v) = match sig {
        [rs @ .., v] if sig.len() == SIG_LEN => (rs, *v),
        _ => return None,
    };
    let signature = Signature::from_slice(rs).ok()?;
    if signature.normalize_s().is_some() {
        return None;
    }
    let v = match v {
        0 | 27 => 0u8,
        1 | 28 => 1u8,
        _ => return None,
    };
    let recid = RecoveryId::from_byte(v)?;
    let key = VerifyingKey::recover_from_prehash(digest, &signature, recid).ok()?;
    let point = key.to_encoded_point(false);
    let hash: [u8; 32] = Keccak256::digest(point.as_bytes().get(1..)?).into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, out @ ..] = hash;
    Some(out)
}

fn word(ok: bool) -> Vec<u8> {
    let mut w = [0u8; 32];
    if let Some(last) = w.last_mut() {
        *last = u8::from(ok);
    }
    w.to_vec()
}

/// `len` bytes of `body` from `start`, or an error naming the field.
fn field<'a>(body: &'a [u8], start: usize, len: usize, name: &'static str) -> Result<&'a [u8]> {
    start
        .checked_add(len)
        .and_then(|end| body.get(start..end))
        .ok_or_else(|| anyhow!("{name} field"))
}

fn be_u32(b: &[u8], name: &'static str) -> Result<u32> {
    Ok(u32::from_be_bytes(
        b.try_into().map_err(|_| anyhow!("{name}"))?,
    ))
}

fn be_u64(b: &[u8], name: &'static str) -> Result<u64> {
    Ok(u64::from_be_bytes(
        b.try_into().map_err(|_| anyhow!("{name}"))?,
    ))
}

fn addr(b: &[u8]) -> Result<[u8; 20]> {
    b.try_into().map_err(|_| anyhow!("address field"))
}

fn message_gas(signatures: u64, message_len: usize) -> u64 {
    // Saturating: the inputs are bounded (at most 3 signatures, a message under
    // 1 KiB), so this equals the plain sum; saturation only refuses absurd gas.
    let words = (message_len as u64).div_ceil(32);
    gas_costs::BASE
        .saturating_add(gas_costs::PER_SIGNATURE.saturating_mul(signatures))
        .saturating_add(gas_costs::PER_MESSAGE_WORD.saturating_mul(words))
}

fn check_gas(needed: u64, have: u64, op: &'static str) -> Result<()> {
    if have < needed {
        return Err(anyhow!(
            "Insufficient gas for {op}: need {needed}, have {have}"
        ));
    }
    Ok(())
}

/// Fixed part of a DEVICE_LINK_VERIFY body: member, device, wallet (20 each),
/// index (4), issued_at (8), label_len (1).
const LINK_FIXED: usize = 20 * 3 + 4 + 8 + 1;

fn device_link_verify(body: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let Some((fixed, rest)) = body.split_at_checked(LINK_FIXED) else {
        return Err(anyhow!("DEVICE_LINK_VERIFY: body too short"));
    };
    let label_len = usize::from(fixed.last().copied().unwrap_or_default());
    // label_len <= 255, so neither sum can overflow.
    let expected = LINK_FIXED
        .saturating_add(label_len)
        .saturating_add(LINK_SIGS_LEN);
    let (label, sigs) = match rest.split_at_checked(label_len) {
        Some((label, sigs)) if sigs.len() == LINK_SIGS_LEN => (label, sigs),
        _ => return Err(anyhow!(
            "DEVICE_LINK_VERIFY: body {} bytes, label length {label_len} needs exactly {expected}",
            body.len()
        )),
    };
    let member = addr(field(fixed, 0, 20, "member")?)?;
    let device = addr(field(fixed, 20, 20, "device")?)?;
    let wallet = addr(field(fixed, 40, 20, "wallet")?)?;
    let index = be_u32(field(fixed, 60, 4, "index")?, "index")?;
    let issued_at = be_u64(field(fixed, 64, 8, "issued_at")?, "issued_at")?;

    // The label alphabet is ASCII, so a valid label is valid UTF-8; an invalid
    // one fails below without building a message.
    let fields_ok =
        device != member && device != wallet && index <= MAX_DEVICE_INDEX && label_is_valid(label);
    let label_str = std::str::from_utf8(label).unwrap_or("");
    let message = device_link_message(&member, &device, &wallet, index, label_str, issued_at);
    let gas_used = message_gas(3, message.len());
    check_gas(gas_used, gas_limit, "DEVICE_LINK_VERIFY")?;
    if !fields_ok {
        return Ok(PrecompileResult {
            output: word(false),
            gas_used,
            success: true,
        });
    }
    let digest = eip191_digest(message.as_bytes());
    let mut chunks = sigs.chunks_exact(SIG_LEN);
    let ok = [member, device, wallet]
        .iter()
        .all(|signer| chunks.next().and_then(|sig| recover(&digest, sig)) == Some(*signer));
    Ok(PrecompileResult {
        output: word(ok),
        gas_used,
        success: true,
    })
}

/// DEVICE_REVOCATION_VERIFY body: member (20), device (20), revoked_at (8), member_sig (65).
const REVOCATION_LEN: usize = 20 + 20 + 8 + SIG_LEN;

fn device_revocation_verify(body: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    if body.len() != REVOCATION_LEN {
        return Err(anyhow!(
            "DEVICE_REVOCATION_VERIFY: body {} bytes, need exactly {REVOCATION_LEN}",
            body.len()
        ));
    }
    let member = addr(field(body, 0, 20, "member")?)?;
    let device = addr(field(body, 20, 20, "device")?)?;
    let revoked_at = be_u64(field(body, 40, 8, "revoked_at")?, "revoked_at")?;
    let message = device_revocation_message(&member, &device, revoked_at);
    let gas_used = message_gas(1, message.len());
    check_gas(gas_used, gas_limit, "DEVICE_REVOCATION_VERIFY")?;
    let member_sig = body.get(48..).unwrap_or_default();
    let ok = recover(&eip191_digest(message.as_bytes()), member_sig) == Some(member);
    Ok(PrecompileResult {
        output: word(ok),
        gas_used,
        success: true,
    })
}

/// 0x0122 AGENT_OPS dispatch.
pub fn execute(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let (op, body) = input
        .split_first()
        .ok_or_else(|| anyhow!("AGENT_OPS: empty input"))?;
    match *op {
        OP_DEVICE_LINK_VERIFY => device_link_verify(body, gas_limit),
        OP_DEVICE_REVOCATION_VERIFY => device_revocation_verify(body, gas_limit),
        other => Err(anyhow!("AGENT_OPS: unknown operation 0x{other:02x}")),
    }
}

/// Encode a DEVICE_LINK_VERIFY input (tests, tooling, spec examples).
#[allow(clippy::too_many_arguments)]
pub fn encode_device_link(
    member: &[u8; 20],
    device: &[u8; 20],
    wallet: &[u8; 20],
    index: u32,
    label: &[u8],
    issued_at: u64,
    member_sig: &[u8; 65],
    device_sig: &[u8; 65],
    wallet_sig: &[u8; 65],
) -> Result<Vec<u8>> {
    let label_len = u8::try_from(label.len()).map_err(|_| anyhow!("label longer than 255"))?;
    let mut out = vec![OP_DEVICE_LINK_VERIFY];
    out.extend_from_slice(member);
    out.extend_from_slice(device);
    out.extend_from_slice(wallet);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.push(label_len);
    out.extend_from_slice(label);
    out.extend_from_slice(member_sig);
    out.extend_from_slice(device_sig);
    out.extend_from_slice(wallet_sig);
    Ok(out)
}

/// Encode a DEVICE_REVOCATION_VERIFY input.
pub fn encode_device_revocation(
    member: &[u8; 20],
    device: &[u8; 20],
    revoked_at: u64,
    member_sig: &[u8; 65],
) -> Vec<u8> {
    let mut out = vec![OP_DEVICE_REVOCATION_VERIFY];
    out.extend_from_slice(member);
    out.extend_from_slice(device);
    out.extend_from_slice(&revoked_at.to_be_bytes());
    out.extend_from_slice(member_sig);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    /// Test keys built at run time from a small integer (never a literal key).
    fn key(n: u8) -> SigningKey {
        let mut scalar = [0u8; 32];
        scalar[31] = n;
        scalar[0] = 0x11;
        SigningKey::from_bytes((&scalar).into()).expect("valid scalar")
    }

    fn address(k: &SigningKey) -> [u8; 20] {
        let point = k.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        out
    }

    fn sign(k: &SigningKey, message: &str) -> [u8; 65] {
        let digest = eip191_digest(message.as_bytes());
        let (sig, recid) = k.sign_prehash_recoverable(&digest).expect("sign");
        // k256 signs low-s already; normalize defensively for the test vector.
        let (sig, recid) = match sig.normalize_s() {
            Some(n) => (
                n,
                RecoveryId::from_byte(recid.to_byte() ^ 1).expect("recid"),
            ),
            None => (sig, recid),
        };
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + recid.to_byte();
        out
    }

    struct Fixture {
        m: [u8; 20],
        d: [u8; 20],
        w: [u8; 20],
        ms: [u8; 65],
        ds: [u8; 65],
        ws: [u8; 65],
    }

    fn fixture(label: &str) -> Fixture {
        let (mk, dk, wk) = (key(1), key(2), key(3));
        let (m, d, w) = (address(&mk), address(&dk), address(&wk));
        let msg = device_link_message(&m, &d, &w, 0, label, 1_790_000_000);
        Fixture {
            m,
            d,
            w,
            ms: sign(&mk, &msg),
            ds: sign(&dk, &msg),
            ws: sign(&wk, &msg),
        }
    }

    fn run(input: &[u8]) -> Vec<u8> {
        execute(input, 1_000_000).expect("execute").output
    }

    #[test]
    fn golden_messages_match_citrate_cluster() {
        // citrate-cluster `cluster-core/src/device_tests.rs` pins these exact strings.
        let mut a1 = [0u8; 20];
        a1[19] = 0xa1;
        let mut d1 = [0u8; 20];
        d1[19] = 0xd1;
        let mut b1 = [0u8; 20];
        b1[19] = 0xb1;
        assert_eq!(
            device_link_message(&a1, &d1, &b1, 0, "Studio Mac", 1_790_000_000),
            "Citrate DeviceLink v1\n\
             Link this device to my Citrate member identity.\n\
             member: 0x00000000000000000000000000000000000000a1\n\
             device: 0x00000000000000000000000000000000000000d1\n\
             wallet: 0x00000000000000000000000000000000000000b1\n\
             index: 0\n\
             label: Studio Mac\n\
             issued_at: 1790000000"
        );
        assert_eq!(
            device_revocation_message(&a1, &d1, 1_790_000_100),
            "Citrate DeviceRevocation v1\n\
             Remove this device from my Citrate member identity.\n\
             member: 0x00000000000000000000000000000000000000a1\n\
             device: 0x00000000000000000000000000000000000000d1\n\
             revoked_at: 1790000100"
        );
    }

    #[test]
    fn valid_device_link_verifies() {
        let f = fixture("Studio Mac");
        let input = encode_device_link(
            &f.m,
            &f.d,
            &f.w,
            0,
            b"Studio Mac",
            1_790_000_000,
            &f.ms,
            &f.ds,
            &f.ws,
        )
        .expect("encode");
        assert_eq!(run(&input), word(true));
    }

    #[test]
    fn any_wrong_signer_or_field_fails() {
        let f = fixture("Studio Mac");
        let enc = |m: &[u8; 20],
                   d: &[u8; 20],
                   w: &[u8; 20],
                   idx: u32,
                   label: &[u8],
                   ts: u64,
                   s: [&[u8; 65]; 3]| {
            encode_device_link(m, d, w, idx, label, ts, s[0], s[1], s[2]).expect("encode")
        };
        // Each of the three signatures is required: a wrong key in any one slot fails.
        let other = key(9);
        let msg = device_link_message(&f.m, &f.d, &f.w, 0, "Studio Mac", 1_790_000_000);
        let forged = sign(&other, &msg);
        assert_eq!(
            run(&enc(
                &f.m,
                &f.d,
                &f.w,
                0,
                b"Studio Mac",
                1_790_000_000,
                [&forged, &f.ds, &f.ws]
            )),
            word(false)
        );
        assert_eq!(
            run(&enc(
                &f.m,
                &f.d,
                &f.w,
                0,
                b"Studio Mac",
                1_790_000_000,
                [&f.ms, &forged, &f.ws]
            )),
            word(false)
        );
        assert_eq!(
            run(&enc(
                &f.m,
                &f.d,
                &f.w,
                0,
                b"Studio Mac",
                1_790_000_000,
                [&f.ms, &f.ds, &forged]
            )),
            word(false)
        );
        // Signatures in the wrong slots.
        assert_eq!(
            run(&enc(
                &f.m,
                &f.d,
                &f.w,
                0,
                b"Studio Mac",
                1_790_000_000,
                [&f.ds, &f.ms, &f.ws]
            )),
            word(false)
        );
        // Any changed field breaks every signature.
        assert_eq!(
            run(&enc(
                &f.m,
                &f.d,
                &f.w,
                1,
                b"Studio Mac",
                1_790_000_000,
                [&f.ms, &f.ds, &f.ws]
            )),
            word(false)
        );
        assert_eq!(
            run(&enc(
                &f.m,
                &f.d,
                &f.w,
                0,
                b"Studio mac",
                1_790_000_000,
                [&f.ms, &f.ds, &f.ws]
            )),
            word(false)
        );
        assert_eq!(
            run(&enc(
                &f.m,
                &f.d,
                &f.w,
                0,
                b"Studio Mac",
                1_790_000_001,
                [&f.ms, &f.ds, &f.ws]
            )),
            word(false)
        );
        // The device key may not be the member key.
        assert_eq!(
            run(&enc(
                &f.m,
                &f.m,
                &f.w,
                0,
                b"Studio Mac",
                1_790_000_000,
                [&f.ms, &f.ms, &f.ws]
            )),
            word(false)
        );
        // Nor the wallet: a link where device == wallet is refused even when both
        // of those signatures are genuinely the wallet's.
        let (mk, wk) = (key(1), key(3));
        let (m, w) = (address(&mk), address(&wk));
        let msg = device_link_message(&m, &w, &w, 0, "Studio Mac", 1_790_000_000);
        let (ms, ws) = (sign(&mk, &msg), sign(&wk, &msg));
        assert_eq!(
            run(&enc(
                &m,
                &w,
                &w,
                0,
                b"Studio Mac",
                1_790_000_000,
                [&ms, &ws, &ws]
            )),
            word(false)
        );
    }

    #[test]
    fn label_and_index_rules_match_cluster() {
        assert!(label_is_valid(b"Studio Mac"));
        assert!(label_is_valid(b"Larry's box-2.0_x"));
        assert!(!label_is_valid(b""));
        assert!(!label_is_valid(b" lead"));
        assert!(!label_is_valid(b"trail "));
        assert!(!label_is_valid(b"two\nlines"));
        assert!(!label_is_valid(&[b'a'; 49]));
        assert!(label_is_valid(&[b'a'; 48]));
        // A correctly signed link with an invalid label or index is still refused.
        let (mk, dk, wk) = (key(1), key(2), key(3));
        let (m, d, w) = (address(&mk), address(&dk), address(&wk));
        let msg = device_link_message(&m, &d, &w, 1024, "ok", 5);
        let input = encode_device_link(
            &m,
            &d,
            &w,
            1024,
            b"ok",
            5,
            &sign(&mk, &msg),
            &sign(&dk, &msg),
            &sign(&wk, &msg),
        )
        .expect("encode");
        assert_eq!(run(&input), word(false));
    }

    /// The explicit low-s rule mirrors cluster-daemon. With k256 0.13 the
    /// recovery itself also refuses high-s (it re-verifies, and k256 verification
    /// rejects high-s), so this test passes with either guard; the explicit check
    /// keeps the rule independent of the library version.
    #[test]
    fn high_s_and_bad_v_are_refused() {
        let f = fixture("Studio Mac");
        // Flip member_sig to its high-s twin: s' = n - s, v flipped. It still recovers the same
        // key mathematically, so only the low-s rule stops it.
        let sig = Signature::from_slice(&f.ms[..64]).expect("sig");
        let (r, s) = sig.split_scalars();
        let high = Signature::from_scalars(r, -(*s)).expect("high-s");
        let mut ms_high = [0u8; 65];
        ms_high[..64].copy_from_slice(&high.to_bytes());
        ms_high[64] = if f.ms[64] == 27 { 28 } else { 27 };
        let input = encode_device_link(
            &f.m,
            &f.d,
            &f.w,
            0,
            b"Studio Mac",
            1_790_000_000,
            &ms_high,
            &f.ds,
            &f.ws,
        )
        .expect("encode");
        assert_eq!(run(&input), word(false));
        let mut bad_v = f.ms;
        bad_v[64] = 29;
        let input = encode_device_link(
            &f.m,
            &f.d,
            &f.w,
            0,
            b"Studio Mac",
            1_790_000_000,
            &bad_v,
            &f.ds,
            &f.ws,
        )
        .expect("encode");
        assert_eq!(run(&input), word(false));
    }

    #[test]
    fn revocation_verifies_only_for_the_member() {
        let (mk, dk) = (key(1), key(2));
        let (m, d) = (address(&mk), address(&dk));
        let msg = device_revocation_message(&m, &d, 1_790_000_100);
        assert_eq!(
            run(&encode_device_revocation(
                &m,
                &d,
                1_790_000_100,
                &sign(&mk, &msg)
            )),
            word(true)
        );
        assert_eq!(
            run(&encode_device_revocation(
                &m,
                &d,
                1_790_000_100,
                &sign(&dk, &msg)
            )),
            word(false)
        );
        assert_eq!(
            run(&encode_device_revocation(
                &m,
                &d,
                1_790_000_101,
                &sign(&mk, &msg)
            )),
            word(false)
        );
    }

    #[test]
    fn malformed_input_and_gas_are_errors() {
        assert!(execute(&[], 1_000_000).is_err());
        assert!(execute(&[0x09], 1_000_000).is_err());
        let f = fixture("Studio Mac");
        let input = encode_device_link(
            &f.m,
            &f.d,
            &f.w,
            0,
            b"Studio Mac",
            1_790_000_000,
            &f.ms,
            &f.ds,
            &f.ws,
        )
        .expect("encode");
        assert!(execute(&input[..input.len() - 1], 1_000_000).is_err());
        let mut extra = input.clone();
        extra.push(0);
        assert!(execute(&extra, 1_000_000).is_err());
        let msg_len =
            device_link_message(&f.m, &f.d, &f.w, 0, "Studio Mac", 1_790_000_000).len() as u64;
        let need = 1_000 + 3 * 3_000 + 6 * msg_len.div_ceil(32);
        assert!(execute(&input, need - 1).is_err());
        assert_eq!(execute(&input, need).expect("ok").gas_used, need);
        assert!(execute(&[0x02, 0, 0], 1_000_000).is_err());
    }
}
