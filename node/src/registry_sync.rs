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

/// The GREATEST snapshot height S(E) <= `height` (for E >= 1), or `None` if
/// `height` is below the first snapshot S(1) = EPOCH - SNAPSHOT_LAG. Used at boot
/// to find which epoch snapshot governs the resumed mid-epoch tip: for a tip at
/// height H, the policy in force is the one materialized at the last S(E) <= H.
pub fn greatest_snapshot_at(height: u64) -> Option<u64> {
    let e = height.checked_add(SNAPSHOT_LAG)? / EPOCH; // floor((H + LAG) / EPOCH)
    if e == 0 {
        return None;
    }
    // S(E) = E*EPOCH - LAG. e = floor((H+LAG)/EPOCH) guarantees S(E) <= H.
    e.checked_mul(EPOCH)?.checked_sub(SNAPSHOT_LAG)
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
    /// VALIDATOR-S1 activation height (fleet-wide), embedded into the materialized
    /// reward policy so `settle_block_rewards` gates §R' vesting on it.
    activation_height: u64,
    /// The SAME `SharedRewardPolicy` cell the `Executor` reads in
    /// `settle_block_rewards`. Rewritten here at each snapshot boundary S(E) so the
    /// §R' reward beneficiary + share are read from the FINALIZED snapshot, never
    /// the live tip.
    reward_policy: citrate_execution::block_rewards::SharedRewardPolicy,
    /// Durable store for the materialized snapshot (policy + active set), so a
    /// restart rehydrates the byte-identical finalized S(E) snapshot rather than
    /// re-deriving it from the (possibly governance-mutated) mid-epoch tip.
    storage: Arc<citrate_storage::StorageManager>,
}

impl RegistrySync {
    pub fn new(
        executor: Arc<Executor>,
        selector: Arc<VrfProposerSelector>,
        registry: [u8; 20],
        activation_height: u64,
        storage: Arc<citrate_storage::StorageManager>,
    ) -> Self {
        let reward_policy = executor.reward_policy_handle();
        Self { executor, selector, registry, activation_height, reward_policy, storage }
    }

    /// Read activeSet() + minStake() against the CURRENT executor state and atomically
    /// replace the selector's membership. Call this right after applying block S(E) so the
    /// current state == state at S(E). Returns the number of validators loaded.
    ///
    /// Also materializes the VALIDATOR-S1 §R' reward policy for this epoch
    /// (priorityFeeShareBps + rewardMinter + proposer->staker map) into the shared
    /// cell the executor reads — so the reward beneficiary + share are fixed at the
    /// finalized snapshot, not re-read from a governance-mutable live tip.
    ///
    /// `snapshot_height` is used only for the view's block context; the STATE read is the
    /// executor's current state.
    pub async fn sync_for_snapshot(&self, snapshot_height: u64) -> Result<usize, String> {
        let active_ret = self.view_call(active_set_selector().to_vec(), snapshot_height).await?;
        let min_ret = self.view_call(min_stake_selector().to_vec(), snapshot_height).await?;

        let entries = decode_active_set(&active_ret)?;
        let min_stake = decode_min_stake(&min_ret)?;

        // Materialize the §R' reward policy from the SAME finalized snapshot and
        // publish it into the shared cell the executor reads.
        let policy = self.build_reward_policy(snapshot_height, &entries).await?;
        *self.reward_policy.write() = Some(policy.clone());

        // Durably persist the materialized snapshot (policy + active set + minStake)
        // so a restart rehydrates THIS finalized S(E) snapshot verbatim, rather than
        // re-deriving it from a possibly-mutated mid-epoch tip. Non-fatal on failure
        // (the in-memory sync already succeeded); a boot with no durable snapshot
        // falls back to a live recompute.
        if let Err(e) = self
            .storage
            .blocks
            .put_reward_snapshot(&encode_reward_snapshot(&policy, &entries, min_stake))
        {
            tracing::warn!(
                "VALIDATOR-S1: materialized epoch-{} snapshot but failed to persist it durably: {}",
                policy.epoch, e
            );
        }

        let mapped: Vec<(PublicKey, u128)> = entries
            .into_iter()
            .map(|(pk, stake)| (PublicKey::new(pk), stake))
            .collect();
        let n = mapped.len();
        self.selector.sync_active_set(mapped, min_stake).await;
        Ok(n)
    }

    /// VALIDATOR-S1 §R' (reorg in-loop): re-materialize ONLY the reward-policy half
    /// of the snapshot at `snapshot_height`, against the executor's CURRENT (reorg-
    /// reapplied) state — WITHOUT touching the proposer selector and WITHOUT durably
    /// persisting. The reorg driver calls this after reapplying the block at S(E) on
    /// the winning branch, because that block's — and every subsequent reapplied
    /// block's — state root is settled against the epoch-E policy; the policy cell
    /// must therefore be current DURING the in-memory reapply. The SELECTOR half is
    /// deliberately deferred to after the reorg commits (it gates only future
    /// admission and must stay abort-safe), and durable persistence happens then too
    /// via the post-commit full `sync_for_snapshot`.
    pub async fn resync_policy_only(&self, snapshot_height: u64) -> Result<(), String> {
        let active_ret = self.view_call(active_set_selector().to_vec(), snapshot_height).await?;
        let entries = decode_active_set(&active_ret)?;
        let policy = self.build_reward_policy(snapshot_height, &entries).await?;
        *self.reward_policy.write() = Some(policy);
        Ok(())
    }

    /// Read priorityFeeShareBps() + rewardMinter() + each active validator's staker
    /// (validatorInfo(pubkey).staker) at the snapshot state, and BUILD (not publish)
    /// an `EpochRewardPolicy`. Every value comes from the SAME S(E) state the
    /// membership set was read from, so producer and receiver — which share the one
    /// cell — settle §R' rewards identically.
    async fn build_reward_policy(
        &self,
        snapshot_height: u64,
        entries: &[([u8; 32], u128)],
    ) -> Result<citrate_execution::block_rewards::EpochRewardPolicy, String> {
        use citrate_execution::block_rewards as br;

        let epoch = snapshot_epoch_at(snapshot_height).unwrap_or(0);

        let share_ret = self
            .view_call(br::PRIORITY_FEE_SHARE_BPS_SELECTOR.to_vec(), snapshot_height)
            .await?;
        let priority_fee_share_bps = br::decode_u64_word(&share_ret)?;

        let minter_ret = self
            .view_call(br::REWARD_MINTER_SELECTOR.to_vec(), snapshot_height)
            .await?;
        let reward_minter = br::decode_address_word(&minter_ret)?;

        let mut staker_of = std::collections::HashMap::with_capacity(entries.len());
        for (pubkey, _stake) in entries {
            let mut calldata = br::VALIDATOR_INFO_SELECTOR.to_vec();
            calldata.extend_from_slice(pubkey);
            let info_ret = self.view_call(calldata, snapshot_height).await?;
            let staker = br::decode_address_word(&info_ret)?;
            staker_of.insert(*pubkey, staker);
        }

        Ok(br::EpochRewardPolicy {
            epoch,
            snapshot_height,
            activation_height: self.activation_height,
            registry: self.registry,
            reward_minter,
            priority_fee_share_bps,
            staker_of,
        })
    }

    /// BOOT REHYDRATION (fixes the restart fork + the pre-existing membership
    /// restart-brick): restore the epoch reward policy AND the proposer selector
    /// BEFORE the node serves or drains any block. Preferred path: reload the
    /// durably-persisted finalized snapshot (byte-identical to a continuously-up
    /// node). Fallback (no durable snapshot — e.g. a store written before this
    /// feature): recompute from the persisted state at the greatest S(E) <= the
    /// resumed applied tip, so at least both halves are populated and the node does
    /// not brick on the §R' hard-reject / admit against an empty selector.
    ///
    /// Returns a short human-readable description of what was rehydrated, for the log.
    pub async fn hydrate_on_boot(&self, applied_height: u64) -> Result<String, String> {
        // Preferred: durable snapshot reload.
        match self.storage.blocks.get_reward_snapshot() {
            Ok(Some(blob)) => {
                let (policy, entries, min_stake) = decode_reward_snapshot(&blob)?;
                let n = entries.len();
                let epoch = policy.epoch;
                let snap_h = policy.snapshot_height;
                *self.reward_policy.write() = Some(policy);
                let mapped: Vec<(PublicKey, u128)> = entries
                    .into_iter()
                    .map(|(pk, stake)| (PublicKey::new(pk), stake))
                    .collect();
                self.selector.sync_active_set(mapped, min_stake).await;
                return Ok(format!(
                    "durable epoch-{epoch} snapshot (S={snap_h}, {n} validators) reloaded"
                ));
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("VALIDATOR-S1: reading durable reward snapshot failed: {e}");
            }
        }

        // Fallback: recompute from the persisted state at the greatest S(E) <= H.
        match greatest_snapshot_at(applied_height) {
            Some(s_e) => {
                let n = self.sync_for_snapshot(s_e).await?;
                Ok(format!(
                    "no durable snapshot; recomputed policy+selector from persisted state at S={s_e} ({n} validators)"
                ))
            }
            None => Ok(format!(
                "applied tip {applied_height} below first snapshot S(1)={}; nothing to rehydrate (pre-activation)",
                EPOCH - SNAPSHOT_LAG
            )),
        }
    }

    /// Read-only contract call against current state, via the executor's simulate path
    /// (same mechanism as eth_call). Returns the ABI-encoded return bytes.
    async fn view_call(&self, calldata: Vec<u8>, snapshot_height: u64) -> Result<Vec<u8>, String> {
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
            data: calldata,
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

/// Durable snapshot codec version. Bump on any layout change; `decode_reward_snapshot`
/// rejects an unknown version so a format change can never be silently misread.
const REWARD_SNAPSHOT_VERSION: u8 = 1;

/// Serialize the materialized epoch snapshot — the `EpochRewardPolicy` plus the
/// active-set (pubkey, effective stake, registered staker) and minStake needed to
/// rebuild the proposer selector — into a self-describing, length-checked blob.
/// Layout (all integers big-endian):
///   [0]      version (=1)
///   [1..9]   epoch u64
///   [9..17]  snapshot_height u64
///   [17..25] activation_height u64
///   [25..45] registry [20]
///   [45..65] reward_minter [20]
///   [65..73] priority_fee_share_bps u64
///   [73..89] min_stake u128
///   [89..93] validator count u32
///   then count * (pubkey[32] ‖ stake u128 ‖ staker[20]) = 68 bytes each
///
/// `pub(crate)` so the node's multi-node integration harness (canonical_apply
/// tests) can persist a byte-identical durable snapshot at a modeled snapshot
/// boundary, exercising the real `hydrate_on_boot` durable-reload path.
pub(crate) fn encode_reward_snapshot(
    policy: &citrate_execution::block_rewards::EpochRewardPolicy,
    entries: &[([u8; 32], u128)],
    min_stake: u128,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(93 + entries.len() * 68);
    buf.push(REWARD_SNAPSHOT_VERSION);
    buf.extend_from_slice(&policy.epoch.to_be_bytes());
    buf.extend_from_slice(&policy.snapshot_height.to_be_bytes());
    buf.extend_from_slice(&policy.activation_height.to_be_bytes());
    buf.extend_from_slice(&policy.registry);
    buf.extend_from_slice(&policy.reward_minter);
    buf.extend_from_slice(&policy.priority_fee_share_bps.to_be_bytes());
    buf.extend_from_slice(&min_stake.to_be_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (pubkey, stake) in entries {
        buf.extend_from_slice(pubkey);
        buf.extend_from_slice(&stake.to_be_bytes());
        // The registered staker for this validator (from the materialized map);
        // always present because `build_reward_policy` inserts one per active entry.
        let staker = policy.staker_of.get(pubkey).copied().unwrap_or([0u8; 20]);
        buf.extend_from_slice(&staker);
    }
    buf
}

/// Inverse of [`encode_reward_snapshot`]. Fully bounds-checked — a truncated or
/// unknown-version blob returns `Err` (so the boot path falls back to a recompute)
/// rather than panicking or silently loading a partial snapshot.
#[allow(clippy::type_complexity)]
fn decode_reward_snapshot(
    buf: &[u8],
) -> Result<
    (
        citrate_execution::block_rewards::EpochRewardPolicy,
        Vec<([u8; 32], u128)>,
        u128,
    ),
    String,
> {
    if buf.len() < 93 {
        return Err(format!("reward snapshot too short ({} bytes)", buf.len()));
    }
    if buf[0] != REWARD_SNAPSHOT_VERSION {
        return Err(format!("unknown reward snapshot version {}", buf[0]));
    }
    let u64_at = |o: usize| -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[o..o + 8]);
        u64::from_be_bytes(b)
    };
    let u128_at = |o: usize| -> u128 {
        let mut b = [0u8; 16];
        b.copy_from_slice(&buf[o..o + 16]);
        u128::from_be_bytes(b)
    };
    let epoch = u64_at(1);
    let snapshot_height = u64_at(9);
    let activation_height = u64_at(17);
    let mut registry = [0u8; 20];
    registry.copy_from_slice(&buf[25..45]);
    let mut reward_minter = [0u8; 20];
    reward_minter.copy_from_slice(&buf[45..65]);
    let priority_fee_share_bps = u64_at(65);
    let min_stake = u128_at(73);
    let count = {
        let mut b = [0u8; 4];
        b.copy_from_slice(&buf[89..93]);
        u32::from_be_bytes(b) as usize
    };
    let need = 93usize
        .checked_add(count.checked_mul(68).ok_or("validator count overflow")?)
        .ok_or("snapshot size overflow")?;
    if buf.len() < need {
        return Err(format!(
            "reward snapshot truncated: need {need}, have {}",
            buf.len()
        ));
    }
    let mut entries = Vec::with_capacity(count);
    let mut staker_of = std::collections::HashMap::with_capacity(count);
    let mut off = 93;
    for _ in 0..count {
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&buf[off..off + 32]);
        let mut sb = [0u8; 16];
        sb.copy_from_slice(&buf[off + 32..off + 48]);
        let stake = u128::from_be_bytes(sb);
        let mut staker = [0u8; 20];
        staker.copy_from_slice(&buf[off + 48..off + 68]);
        entries.push((pubkey, stake));
        staker_of.insert(pubkey, staker);
        off += 68;
    }
    let policy = citrate_execution::block_rewards::EpochRewardPolicy {
        epoch,
        snapshot_height,
        activation_height,
        registry,
        reward_minter,
        priority_fee_share_bps,
        staker_of,
    };
    Ok((policy, entries, min_stake))
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
    fn test_greatest_snapshot_at() {
        // Below the first snapshot S(1)=800 → None.
        assert_eq!(greatest_snapshot_at(0), None);
        assert_eq!(greatest_snapshot_at(799), None);
        // At/above S(1): the greatest S(E) <= H.
        assert_eq!(greatest_snapshot_at(800), Some(800)); // exactly S(1)
        assert_eq!(greatest_snapshot_at(801), Some(800));
        assert_eq!(greatest_snapshot_at(1799), Some(800)); // still in epoch-1 window
        assert_eq!(greatest_snapshot_at(1800), Some(1800)); // S(2)
        assert_eq!(greatest_snapshot_at(2500), Some(1800));
        assert_eq!(greatest_snapshot_at(9800), Some(9800)); // S(10)
        assert_eq!(greatest_snapshot_at(9799), Some(8800)); // S(9)
    }

    #[test]
    fn test_reward_snapshot_codec_roundtrip() {
        use citrate_execution::block_rewards::EpochRewardPolicy;
        let mut staker_of = std::collections::HashMap::new();
        let pk_a = [0xA1u8; 32];
        let pk_b = [0xB2u8; 32];
        staker_of.insert(pk_a, [0x11u8; 20]);
        staker_of.insert(pk_b, [0x22u8; 20]);
        let policy = EpochRewardPolicy {
            epoch: 3,
            snapshot_height: 2800,
            activation_height: 800,
            registry: [0x99u8; 20],
            reward_minter: [0x50u8; 20],
            priority_fee_share_bps: 2500,
            staker_of,
        };
        let entries = vec![(pk_a, 40_000u128), (pk_b, 32_000u128)];
        let min_stake = 32_000u128;
        let blob = encode_reward_snapshot(&policy, &entries, min_stake);
        let (p2, e2, ms2) = decode_reward_snapshot(&blob).expect("decode");
        assert_eq!(p2.epoch, 3);
        assert_eq!(p2.snapshot_height, 2800);
        assert_eq!(p2.activation_height, 800);
        assert_eq!(p2.registry, [0x99u8; 20]);
        assert_eq!(p2.reward_minter, [0x50u8; 20]);
        assert_eq!(p2.priority_fee_share_bps, 2500);
        assert_eq!(p2.staker_of.get(&pk_a).copied(), Some([0x11u8; 20]));
        assert_eq!(p2.staker_of.get(&pk_b).copied(), Some([0x22u8; 20]));
        assert_eq!(ms2, 32_000u128);
        // entries order-independent (compare as sets of the pieces present)
        assert_eq!(e2.len(), 2);
        assert!(e2.contains(&(pk_a, 40_000u128)));
        assert!(e2.contains(&(pk_b, 32_000u128)));
        // Truncated / bad-version blobs error (never panic, never partial-load).
        assert!(decode_reward_snapshot(&blob[..50]).is_err());
        let mut bad = blob.clone();
        bad[0] = 0xFF;
        assert!(decode_reward_snapshot(&bad).is_err());
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

    // ========================================================================
    // BOOT REHYDRATION (test (a)) — fixes BUG-1 (restart reward-policy fork) +
    // BUG-3 (membership restart-brick).
    //
    // A "continuously-up" node holds the epoch policy + selector in memory. A
    // "restarted" node — a FRESH executor + selector + store with the durable
    // snapshot persisted — must, after `hydrate_on_boot`, settle a forward
    // NON-boundary block carrying a nonzero vested share to the BYTE-IDENTICAL
    // state root AND return the identical membership-admission verdict.
    // ========================================================================
    use citrate_consensus::types::{Block, BlockBuilder, Hash, Signature, VrfProof};
    use citrate_execution::block_rewards::{
        EpochRewardPolicy, CANONICAL_BASE_FEE_PER_GAS, REWARD_MINTER_ADDRESS,
    };
    use citrate_execution::types::Address;
    use citrate_execution::{address_utils, StateDB};
    use citrate_storage::pruning::PruningConfig;
    use primitive_types::U256;

    const CB: [u8; 20] = [0x77; 20];
    const REG: [u8; 20] = [0x99; 20];
    const PROPOSER: [u8; 32] = [0x5A; 32];
    const ACTIVATION: u64 = 800;
    const FWD_HEIGHT: u64 = 850; // >= activation, NON-boundary (snapshot_epoch_at==None)
    const SHARE_BPS: u64 = 2500;

    fn snd(seed: u8) -> PublicKey {
        let mut pk = [0u8; 32];
        pk[0] = seed;
        pk[31] = seed;
        PublicKey::new(pk)
    }

    fn priority_tx(from: PublicKey, to: PublicKey, nonce: u64, max_fee: u64, max_prio: u64, seed: u8) -> Transaction {
        let mut hb = [0u8; 32];
        hb[0] = seed;
        let mut tx = Transaction {
            hash: Hash::new(hb),
            nonce,
            from,
            to: Some(to),
            value: 500,
            gas_limit: 100_000,
            gas_price: max_fee,
            data: vec![],
            signature: Signature::new([0u8; 64]),
            tx_type: None,
            eth_tx_type: 2,
            max_fee_per_gas: Some(max_fee),
            max_priority_fee_per_gas: Some(max_prio),
            ..Default::default()
        };
        tx.determine_type();
        tx
    }

    fn test_policy() -> EpochRewardPolicy {
        let mut staker_of = std::collections::HashMap::new();
        staker_of.insert(PROPOSER, CB); // coinbase == registered staker
        EpochRewardPolicy {
            epoch: 1,
            snapshot_height: 800,
            activation_height: ACTIVATION,
            registry: REG,
            reward_minter: REWARD_MINTER_ADDRESS,
            priority_fee_share_bps: SHARE_BPS,
            staker_of,
        }
    }

    fn fund(exec: &Executor) -> (PublicKey, PublicKey) {
        let a = snd(1);
        let b = snd(2);
        exec.set_balance(&address_utils::normalize_address(&a), U256::from(u128::MAX));
        (a, b)
    }

    fn fwd_txs(a: PublicKey, b: PublicKey) -> Vec<Transaction> {
        vec![priority_tx(a, b, 0, CANONICAL_BASE_FEE_PER_GAS + 900, 250, 0xA1)]
    }

    fn seal_block(height: u64, txs: Vec<Transaction>, root: Hash) -> Block {
        let mut blk = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(Hash::default())
            .coinbase(CB)
            .proposer(PublicKey::new(PROPOSER))
            .timestamp(1_700_000_000)
            .base_fee_per_gas(CANONICAL_BASE_FEE_PER_GAS)
            .vrf_reveal(VrfProof { proof: vec![], output: Hash::new([0x5A; 32]) })
            .transactions(txs)
            .state_root(root)
            .build_unhashed();
        blk.header.block_hash = blk.compute_hash();
        blk
    }

    /// Produce the forward block on `exec` exactly as `apply_block_inner` settles:
    /// set context → execute txs → settle §R' rewards → state root.
    async fn produce_fwd(exec: &Executor, txs: &[Transaction]) -> Hash {
        exec.set_block_context(citrate_execution::revm_adapter::BlockContext {
            coinbase: CB,
            prevrandao: [0x5A; 32],
            block_hashes: std::collections::HashMap::new(),
        });
        let tmpl = seal_block(FWD_HEIGHT, txs.to_vec(), Hash::default());
        let mut receipts = Vec::new();
        for tx in txs {
            receipts.push(exec.execute_transaction(&tmpl, tx).await.expect("tx executes"));
        }
        let basic = [
            (Address(CB), U256::from(10_000_000_000u64)),
            (Address([0x11; 20]), U256::from(1_000_000_000u64)),
        ];
        exec.settle_block_rewards(
            FWD_HEIGHT,
            CB,
            PROPOSER,
            CANONICAL_BASE_FEE_PER_GAS,
            txs,
            &receipts,
            &basic,
        )
        .await
        .expect("settle");
        exec.calculate_state_root()
    }

    #[tokio::test]
    async fn boot_rehydration_matches_continuously_up_node() {
        let basic = [
            (Address(CB), U256::from(10_000_000_000u64)),
            (Address([0x11; 20]), U256::from(1_000_000_000u64)),
        ];

        // --- Continuously-up node U: policy + selector in memory. ---
        let u = Arc::new(Executor::new(Arc::new(StateDB::new())));
        u.set_validator_activation_height(ACTIVATION);
        *u.reward_policy_handle().write() = Some(test_policy());
        let sel_u = Arc::new(VrfProposerSelector::production());
        sel_u.sync_active_set(vec![(PublicKey::new(PROPOSER), 40_000u128)], 32_000u128).await;
        let (a, b) = fund(&u);
        let txs = fwd_txs(a, b);
        let root_u = produce_fwd(&u, &txs).await;
        let reg_u = u.get_balance(&Address(REG));
        let admit_u = sel_u
            .is_eligible_proposer(&PublicKey::new(PROPOSER), &Hash::default(), FWD_HEIGHT)
            .await
            .expect("admission verdict U");
        let sealed = seal_block(FWD_HEIGHT, txs.clone(), root_u);

        // --- Restarted node R: FRESH executor+selector+store, durable snapshot on disk. ---
        let dir = tempfile::tempdir().expect("dir");
        let storage = Arc::new(
            citrate_storage::StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"),
        );
        // Persist the durable snapshot exactly as `sync_for_snapshot` would have at S(1).
        let entries = vec![(PROPOSER, 40_000u128)];
        storage
            .blocks
            .put_reward_snapshot(&encode_reward_snapshot(&test_policy(), &entries, 32_000u128))
            .expect("persist snapshot");

        let r = Arc::new(Executor::new(Arc::new(StateDB::new())));
        r.set_validator_activation_height(ACTIVATION);
        let sel_r = Arc::new(VrfProposerSelector::production());
        // Selector starts EMPTY — admission would brick (ValidatorNotFound) pre-boot (BUG-3).
        assert!(sel_r
            .is_eligible_proposer(&PublicKey::new(PROPOSER), &Hash::default(), FWD_HEIGHT)
            .await
            .is_err());
        let rs = RegistrySync::new(r.clone(), sel_r.clone(), REG, ACTIVATION, storage.clone());

        // Boot rehydration: durable path restores BOTH policy (BUG-1) and selector (BUG-3).
        let desc = rs.hydrate_on_boot(849).await.expect("hydrate");
        assert!(desc.contains("durable"), "durable path used: {desc}");
        fund(&r);

        // The restarted node reproduces the continuously-up node's forward-block root.
        let got = r
            .apply_block(&sealed, sealed.header.coinbase, &basic)
            .await
            .expect("restarted node reproduces + accepts the forward block");
        assert_eq!(got, root_u, "BUG-1 closed: restarted state root == continuously-up node");
        assert_eq!(r.get_balance(&Address(REG)), reg_u, "vested share matches after rehydration");
        assert!(reg_u > U256::zero(), "a positive §R' share must have vested");

        // BUG-3 closed: the selector is repopulated → identical admission verdict.
        let admit_r = sel_r
            .is_eligible_proposer(&PublicKey::new(PROPOSER), &Hash::default(), FWD_HEIGHT)
            .await
            .expect("admission verdict R (selector rehydrated)");
        assert_eq!(admit_r, admit_u, "membership admission verdict matches after boot");
        assert!(admit_r, "proposer is eligible on the rehydrated selector");
        assert_eq!(sel_r.active_validator_count().await, 1, "selector repopulated on boot");
    }

    /// Fallback path: no durable snapshot present → `hydrate_on_boot` recomputes at
    /// the greatest S(E) <= the tip; below S(1) there is simply nothing to rehydrate.
    #[tokio::test]
    async fn boot_rehydration_below_first_snapshot_is_noop() {
        let dir = tempfile::tempdir().expect("dir");
        let storage = Arc::new(
            citrate_storage::StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"),
        );
        let r = Arc::new(Executor::new(Arc::new(StateDB::new())));
        let sel = Arc::new(VrfProposerSelector::production());
        let rs = RegistrySync::new(r.clone(), sel, REG, ACTIVATION, storage);
        let desc = rs.hydrate_on_boot(500).await.expect("hydrate");
        assert!(desc.contains("below first snapshot"), "got: {desc}");
        assert!(r.reward_policy_handle().read().is_none(), "no policy below S(1)");
    }
}
