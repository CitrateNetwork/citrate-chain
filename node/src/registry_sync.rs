// node/src/registry_sync.rs
//
// VALIDATOR-S1 (v5) — epoch snapshot sync.
//
// At each epoch snapshot block S(E) = E*EPOCH - SNAPSHOT_LAG, the node reads the
// ValidatorRegistry's active set + minStake via a read-only contract call against the
// state AS OF S(E), and rebuilds the shared VrfProposerSelector so admission enforces
// the correct membership for epoch E. Because S(E) is finalized and every node performs
// the read at the identical logical point (right after applying block S(E), before any
// later registry-mutating tx), all nodes derive the byte-identical set — no divergence.
//
// This is the piece that POPULATES membership; the eligibility gate, activation-height
// gate, and vote signing are dormant until this feeds the selector.

use std::sync::Arc;

use citrate_consensus::types::{BlockBuilder, PublicKey, Signature, Transaction};
use citrate_consensus::vrf::VrfProposerSelector;
use citrate_execution::Executor;
use sha3::{Digest, Keccak256};

/// MUST match the on-chain ValidatorRegistry constants and the node's canonical epoch math
/// (dag_store activation + docs/consensus/VALIDATOR_S1_...): S(E) = E*EPOCH - SNAPSHOT_LAG.
pub const EPOCH: u64 = 1000;
pub const SNAPSHOT_LAG: u64 = 200;

/// If `height` is the snapshot block S(E) = E*EPOCH - SNAPSHOT_LAG for some epoch E >= 1,
/// return that epoch E. Otherwise None. This is the trigger predicate for a resync.
pub fn snapshot_epoch_at(height: u64) -> Option<u64> {
    let n = height.checked_add(SNAPSHOT_LAG)?;
    if n % EPOCH == 0 {
        let e = n / EPOCH;
        if e >= 1 {
            return Some(e);
        }
    }
    None
}

/// 4-byte selector for `activeSet()` — verified == 0xfd4665ae.
pub fn active_set_selector() -> [u8; 4] {
    selector("activeSet()")
}

/// 4-byte selector for `minStake()` — verified == 0x375b3c0a.
pub fn min_stake_selector() -> [u8; 4] {
    selector("minStake()")
}

fn selector(sig: &str) -> [u8; 4] {
    let mut h = Keccak256::new();
    h.update(sig.as_bytes());
    let out = h.finalize();
    [out[0], out[1], out[2], out[3]]
}

/// Decode the ABI return of `activeSet() returns (bytes32[] pubkeys, uint256[] effStakes)`
/// into (pubkey, effective_stake) pairs. Fully bounds-checked — never panics; returns Err
/// on any malformed/truncated encoding so a bad read can't silently corrupt membership.
pub fn decode_active_set(ret: &[u8]) -> Result<Vec<([u8; 32], u128)>, String> {
    // Head: two 32-byte offsets (to the pubkeys array, to the stakes array).
    if ret.len() < 64 {
        return Err(format!("activeSet: return too short ({} bytes)", ret.len()));
    }
    let off_pk = read_usize(ret, 0)?;
    let off_st = read_usize(ret, 32)?;

    let (len_pk, pk_base) = read_array_header(ret, off_pk, "pubkeys")?;
    let (len_st, st_base) = read_array_header(ret, off_st, "stakes")?;
    if len_pk != len_st {
        return Err(format!("activeSet: array length mismatch {len_pk} != {len_st}"));
    }

    let mut out = Vec::with_capacity(len_pk);
    for i in 0..len_pk {
        let pk_off = pk_base
            .checked_add(i.checked_mul(32).ok_or("overflow")?)
            .ok_or("overflow")?;
        let st_off = st_base
            .checked_add(i.checked_mul(32).ok_or("overflow")?)
            .ok_or("overflow")?;
        let pk = read_word(ret, pk_off)?;
        let stake = word_to_u128(read_word(ret, st_off)?);
        out.push((pk, stake));
    }
    Ok(out)
}

/// Decode `minStake() returns (uint256)` into u128 (saturating on the impossible >u128 case).
pub fn decode_min_stake(ret: &[u8]) -> Result<u128, String> {
    if ret.len() < 32 {
        return Err(format!("minStake: return too short ({} bytes)", ret.len()));
    }
    Ok(word_to_u128(read_word(ret, 0)?))
}

fn read_word(buf: &[u8], off: usize) -> Result<[u8; 32], String> {
    let end = off.checked_add(32).ok_or("offset overflow")?;
    if end > buf.len() {
        return Err(format!("word out of bounds at {off} (len {})", buf.len()));
    }
    let mut w = [0u8; 32];
    w.copy_from_slice(&buf[off..end]);
    Ok(w)
}

fn read_usize(buf: &[u8], off: usize) -> Result<usize, String> {
    let w = read_word(buf, off)?;
    // High 24 bytes must be zero for a sane offset/length.
    if w[..24].iter().any(|&b| b != 0) {
        return Err("value exceeds usize range".to_string());
    }
    let mut b8 = [0u8; 8];
    b8.copy_from_slice(&w[24..32]);
    Ok(u64::from_be_bytes(b8) as usize)
}

/// Read a dynamic-array header at `off`: returns (length, base_offset_of_elements).
fn read_array_header(buf: &[u8], off: usize, name: &str) -> Result<(usize, usize), String> {
    let len = read_usize(buf, off).map_err(|e| format!("{name} length: {e}"))?;
    let base = off.checked_add(32).ok_or("array base overflow")?;
    // Ensure the declared elements fit within the buffer.
    let need = base
        .checked_add(len.checked_mul(32).ok_or("array size overflow")?)
        .ok_or("array end overflow")?;
    if need > buf.len() {
        return Err(format!("{name} array truncated: need {need}, have {}", buf.len()));
    }
    Ok((len, base))
}

/// uint256 word -> u128. Saturates if the (impossible for SALT) high 16 bytes are set,
/// deterministically on every node.
fn word_to_u128(w: [u8; 32]) -> u128 {
    if w[..16].iter().any(|&b| b != 0) {
        return u128::MAX;
    }
    let mut b16 = [0u8; 16];
    b16.copy_from_slice(&w[16..32]);
    u128::from_be_bytes(b16)
}

/// Reads the ValidatorRegistry over the executor's current state and rebuilds the
/// shared proposer selector. Constructed only when the registry is configured.
pub struct RegistrySync {
    executor: Arc<Executor>,
    selector: Arc<VrfProposerSelector>,
    registry: [u8; 20],
}

impl RegistrySync {
    pub fn new(executor: Arc<Executor>, selector: Arc<VrfProposerSelector>, registry: [u8; 20]) -> Self {
        Self { executor, selector, registry }
    }

    /// Read activeSet() + minStake() against the CURRENT executor state and atomically
    /// replace the selector's membership. Call this right after applying block S(E) so the
    /// current state == state at S(E). Returns the number of validators loaded.
    ///
    /// `snapshot_height` is used only for the view's block context; the STATE read is the
    /// executor's current state.
    pub async fn sync_for_snapshot(&self, snapshot_height: u64) -> Result<usize, String> {
        let active_ret = self.view_call(&active_set_selector(), snapshot_height).await?;
        let min_ret = self.view_call(&min_stake_selector(), snapshot_height).await?;

        let entries = decode_active_set(&active_ret)?;
        let min_stake = decode_min_stake(&min_ret)?;

        let mapped: Vec<(PublicKey, u128)> = entries
            .into_iter()
            .map(|(pk, stake)| (PublicKey::new(pk), stake))
            .collect();
        let n = mapped.len();
        self.selector.sync_active_set(mapped, min_stake).await;
        Ok(n)
    }

    /// Read-only contract call against current state, via the executor's simulate path
    /// (same mechanism as eth_call). Returns the ABI-encoded return bytes.
    async fn view_call(&self, calldata: &[u8; 4], snapshot_height: u64) -> Result<Vec<u8>, String> {
        // Registry address as a 32-byte PublicKey (EVM 20-byte address in the high bytes).
        let mut to_bytes = [0u8; 32];
        to_bytes[..20].copy_from_slice(&self.registry);
        let to_pk = PublicKey::new(to_bytes);

        // A fixed, deterministic reader EOA (0x00..01) — only used to satisfy nonce/from.
        let mut from_bytes = [0u8; 32];
        from_bytes[19] = 1;
        let from_pk = PublicKey::new(from_bytes);
        let sender_addr = citrate_execution::address_utils::normalize_address(&from_pk);
        let sender_nonce = self.executor.get_nonce(&sender_addr);

        let blk = BlockBuilder::new()
            .base_fee_per_gas(1_000_000_000)
            .height(snapshot_height)
            .build_unhashed();

        let mut tx = Transaction {
            hash: citrate_consensus::types::Hash::default(),
            nonce: sender_nonce,
            from: from_pk,
            to: Some(to_pk),
            value: 0,
            gas_limit: 50_000_000,
            gas_price: 1,
            data: calldata.to_vec(),
            signature: Signature::new([0u8; 64]),
            tx_type: None,
            ..Default::default()
        };
        tx.determine_type();

        let receipt = self
            .executor
            .simulate_transaction(&blk, &tx)
            .await
            .map_err(|e| format!("registry view call failed: {e}"))?;
        if !receipt.status {
            return Err(format!(
                "registry view call reverted: {}",
                receipt.revert_reason.as_deref().unwrap_or("no reason")
            ));
        }
        Ok(receipt.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_epoch_at_boundaries() {
        // S(E) = E*1000 - 200
        assert_eq!(snapshot_epoch_at(800), Some(1)); // S(1)
        assert_eq!(snapshot_epoch_at(1800), Some(2)); // S(2)
        assert_eq!(snapshot_epoch_at(9800), Some(10)); // S(10)
        // non-boundaries
        assert_eq!(snapshot_epoch_at(799), None);
        assert_eq!(snapshot_epoch_at(801), None);
        assert_eq!(snapshot_epoch_at(1000), None);
        assert_eq!(snapshot_epoch_at(0), None);
    }

    #[test]
    fn test_selectors_match_contract() {
        assert_eq!(active_set_selector(), [0xfd, 0x46, 0x65, 0xae]);
        assert_eq!(min_stake_selector(), [0x37, 0x5b, 0x3c, 0x0a]);
    }

    #[test]
    fn test_decode_min_stake() {
        let mut ret = [0u8; 32];
        // 32_000 * 10^18 = 0x6c6b935b8bbd400000
        let v: u128 = 32_000u128 * 1_000_000_000_000_000_000u128;
        ret[16..32].copy_from_slice(&v.to_be_bytes());
        assert_eq!(decode_min_stake(&ret).unwrap(), v);
    }

    #[test]
    fn test_decode_min_stake_truncated_errs() {
        assert!(decode_min_stake(&[0u8; 16]).is_err());
    }

    /// Hand-encode `activeSet()` returning two pubkeys + two stakes and decode it.
    #[test]
    fn test_decode_active_set_roundtrip() {
        // ABI: head = [off_pk=0x40][off_st=0x40 + 32 + 2*32]
        // pk array @ 0x40: [len=2][pk0][pk1]
        // st array @ 0xC0: [len=2][st0][st1]
        let mut buf = Vec::new();
        let word = |n: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&n.to_be_bytes());
            w
        };
        // head
        buf.extend_from_slice(&word(0x40)); // off_pk = 64
        buf.extend_from_slice(&word(0xA0)); // off_st = 160 (= 64 + 32(len) + 64(2 pubkeys))
        // pk array
        buf.extend_from_slice(&word(2)); // len
        let mut pk0 = [0u8; 32];
        pk0[0] = 0xAA;
        let mut pk1 = [0u8; 32];
        pk1[31] = 0xBB;
        buf.extend_from_slice(&pk0);
        buf.extend_from_slice(&pk1);
        // st array
        buf.extend_from_slice(&word(2)); // len
        buf.extend_from_slice(&word(40_000));
        buf.extend_from_slice(&word(32_000));

        let decoded = decode_active_set(&buf).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], (pk0, 40_000u128));
        assert_eq!(decoded[1], (pk1, 32_000u128));
    }

    #[test]
    fn test_decode_active_set_empty() {
        let mut buf = Vec::new();
        let word = |n: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&n.to_be_bytes());
            w
        };
        buf.extend_from_slice(&word(0x40)); // off_pk
        buf.extend_from_slice(&word(0x60)); // off_st = 64 + 32
        buf.extend_from_slice(&word(0)); // pk len 0
        buf.extend_from_slice(&word(0)); // st len 0
        assert_eq!(decode_active_set(&buf).unwrap().len(), 0);
    }

    #[test]
    fn test_decode_active_set_length_mismatch_errs() {
        let word = |n: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&n.to_be_bytes());
            w
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&word(0x40));
        buf.extend_from_slice(&word(0x80)); // off_st = 64 + 32(len) + 32(one pk) = 128
        buf.extend_from_slice(&word(1)); // pk len 1
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&word(2)); // st len 2 (true mismatch: 1 != 2)
        buf.extend_from_slice(&[0u8; 64]);
        assert!(decode_active_set(&buf).is_err());
    }

    #[test]
    fn test_decode_active_set_truncated_errs() {
        let word = |n: u64| {
            let mut w = [0u8; 32];
            w[24..32].copy_from_slice(&n.to_be_bytes());
            w
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&word(0x40));
        buf.extend_from_slice(&word(0xC0));
        buf.extend_from_slice(&word(5)); // claims 5 pubkeys but no data follows
        assert!(decode_active_set(&buf).is_err());
    }
}
