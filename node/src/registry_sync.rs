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

/// How many recent epoch snapshots to retain in the per-epoch durable store so a reorg
/// pre-seed can load the EXACT governing epoch's policy. The in-memory reorg fork point is
/// bounded to `MAX_REORG_DEPTH` (100) blocks below the applied tip, well under one `EPOCH`
/// (1000), so a reorg crosses at most one S(E) boundary — 2 epochs would suffice. We keep a
/// generous margin (snapshots are ~KB) so any interplay with the from-genesis rebuild path
/// or slightly deeper windows is still covered; older snapshots are pruned on each write.
pub const REWARD_SNAPSHOT_RETENTION_EPOCHS: u64 = 8;

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
        return Err(format!(
            "activeSet: array length mismatch {len_pk} != {len_st}"
        ));
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
        return Err(format!(
            "{name} array truncated: need {need}, have {}",
            buf.len()
        ));
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
        Self {
            executor,
            selector,
            registry,
            activation_height,
            reward_policy,
            storage,
        }
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
        let active_ret = self
            .view_call(active_set_selector().to_vec(), snapshot_height)
            .await?;
        let min_ret = self
            .view_call(min_stake_selector().to_vec(), snapshot_height)
            .await?;

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
        let blob = encode_reward_snapshot(&policy, &entries, min_stake);
        if let Err(e) = self.storage.blocks.put_reward_snapshot(&blob) {
            tracing::warn!(
                "VALIDATOR-S1: materialized epoch-{} snapshot but failed to persist it durably: {}",
                policy.epoch,
                e
            );
        }
        // Also persist under the per-epoch S(E) key so a boundary-crossing reorg can
        // rehydrate THIS exact policy even after the tip advances into a later epoch (the
        // latest-only key above would then hold a newer epoch). Then prune the snapshot that
        // has fallen out of the retention window. Both are non-fatal (best-effort durability).
        if let Err(e) = self
            .storage
            .blocks
            .put_reward_snapshot_at(policy.snapshot_height, &blob)
        {
            tracing::warn!(
                "VALIDATOR-S1: failed to persist per-epoch snapshot S({}): {}",
                policy.snapshot_height,
                e
            );
        }
        if let Some(evicted) = policy
            .snapshot_height
            .checked_sub(REWARD_SNAPSHOT_RETENTION_EPOCHS * EPOCH)
        {
            if let Err(e) = self.storage.blocks.delete_reward_snapshot_at(evicted) {
                tracing::warn!(
                    "VALIDATOR-S1: failed to prune per-epoch snapshot S({evicted}): {e}"
                );
            }
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
        let active_ret = self
            .view_call(active_set_selector().to_vec(), snapshot_height)
            .await?;
        let entries = decode_active_set(&active_ret)?;
        let policy = self.build_reward_policy(snapshot_height, &entries).await?;
        *self.reward_policy.write() = Some(policy);
        Ok(())
    }

    /// VALIDATOR-S1 §R' (reorg PRE-SEED — hardening, 2026-08-25): install the reward
    /// policy governing `snapshot_height` (the greatest S(E) <= the reorg fork point)
    /// WITHOUT recomputing it from the executor's current state. Prefer the durably-
    /// persisted finalized snapshot — captured from state@S(E) at forward-apply time
    /// and byte-identical to what the producer/fleet settled — when it is for THIS
    /// exact epoch; only fall back to a live recompute (`resync_policy_only`) if no
    /// matching durable snapshot exists (e.g. a reorg deeper than any snapshot this
    /// node ever forward-applied).
    ///
    /// WHY this must not just call `resync_policy_only` at the pre-seed: that reads the
    /// registry via `view_call` -> `simulate_transaction` against CURRENT state, and at
    /// the pre-seed the executor is reverted to the FORK POINT. If the registry's
    /// active-set / subsidy / share changed between S(E) and the fork point, the
    /// recomputed policy diverges from the producer's — the first §R'-active reapplied
    /// block then settles a different reward and the reorg aborts at it forever. The
    /// durable snapshot (`block_store.get_reward_snapshot`) was frozen at S(E) and
    /// cannot drift with the mid-epoch tip. Mirrors `hydrate_on_boot`'s preferred path.
    /// Data source: `StorageManager.blocks.get_reward_snapshot()` (the S(E) blob
    /// persisted by `sync_for_snapshot`); fallback source: `ValidatorRegistry` via
    /// `resync_policy_only`.
    pub async fn seed_governing_policy(&self, snapshot_height: u64) -> Result<(), String> {
        if let Some(policy) = self.load_durable_policy_at(snapshot_height) {
            *self.reward_policy.write() = Some(policy);
            return Ok(());
        }
        // Fallback: no durable snapshot for this exact epoch (a pre-upgrade store, or a
        // reorg reaching deeper than the retention window). Recompute against the CURRENT
        // (fork-point) state — the ONLY path that can diverge from the producer if the
        // registry changed since S(E). Logged so a rare recurrence of the pre-seed
        // divergence is diagnosable rather than silent.
        tracing::warn!(
            "VALIDATOR-S1: reorg pre-seed found no durable snapshot for S({snapshot_height}); \
             recomputing reward policy from current state (may diverge if the ValidatorRegistry \
             changed since S(E))"
        );
        self.resync_policy_only(snapshot_height).await
    }

    /// Load the durably-persisted reward policy governing snapshot height `snapshot_height`,
    /// or `None` if no epoch-matching durable snapshot exists. Tries the PER-EPOCH keyed
    /// store first (survives a boundary-crossing reorg where the latest-persisted snapshot
    /// is a newer epoch), then the legacy latest-only key (a pre-upgrade store whose single
    /// snapshot happens to be this epoch). A blob that decodes to a DIFFERENT epoch, or fails
    /// to decode, yields `None` so the caller recomputes. Data source:
    /// `block_store.get_reward_snapshot_at` then `get_reward_snapshot`.
    fn load_durable_policy_at(
        &self,
        snapshot_height: u64,
    ) -> Option<citrate_execution::block_rewards::EpochRewardPolicy> {
        let decode_matching = |blob: Vec<u8>| match decode_reward_snapshot(&blob) {
            Ok((policy, _entries, _min_stake)) if policy.snapshot_height == snapshot_height => {
                Some(policy)
            }
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(
                    "VALIDATOR-S1: durable snapshot for S({snapshot_height}) failed to decode ({e})"
                );
                None
            }
        };
        // Per-epoch keyed store first — the exact S(E) snapshot, boundary-crossing safe.
        match self.storage.blocks.get_reward_snapshot_at(snapshot_height) {
            Ok(Some(blob)) => {
                if let Some(p) = decode_matching(blob) {
                    return Some(p);
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(
                "VALIDATOR-S1: reading per-epoch snapshot S({snapshot_height}) failed ({e})"
            ),
        }
        // Legacy latest-only key: covers a store written before per-epoch keys existed.
        match self.storage.blocks.get_reward_snapshot() {
            Ok(Some(blob)) => decode_matching(blob),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("VALIDATOR-S1: reading latest reward snapshot failed ({e})");
                None
            }
        }
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
            .view_call(
                br::PRIORITY_FEE_SHARE_BPS_SELECTOR.to_vec(),
                snapshot_height,
            )
            .await?;
        let priority_fee_share_bps = br::decode_u64_word(&share_ret)?;

        let minter_ret = self
            .view_call(br::REWARD_MINTER_SELECTOR.to_vec(), snapshot_height)
            .await?;
        let reward_minter = br::decode_address_word(&minter_ret)?;

        // CBF-S1 / ADR-4: the flat per-block issuance, read from the SAME
        // finalized snapshot as every other policy field so producer and
        // receiver settle byte-identically for the whole epoch.
        let subsidy_ret = self
            .view_call(br::BLOCK_SUBSIDY_SELECTOR.to_vec(), snapshot_height)
            .await?;
        let block_subsidy = br::decode_u256_word(&subsidy_ret)?;

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
            block_subsidy,
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
        let sender_nonce = self.executor.get_canonical_account(&sender_addr).nonce; // SRP-S4 WP-2.2: non-warming committed read

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
/// v2 (CBF-S1 / ADR-4) added the 32-byte `block_subsidy` word. A v1 blob written
/// by an older binary is REJECTED, not reinterpreted — the boot path then falls
/// back to a live recompute, which reads the subsidy from the registry anyway.
/// Silently accepting v1 would leave `block_subsidy` at zero on a rehydrating
/// node while the rest of the fleet vested the subsidy: a state-root fork.
const REWARD_SNAPSHOT_VERSION: u8 = 2;

/// Fixed-size prefix of a v2 snapshot blob, before the variable validator array.
/// Named so the encoder, the length checks, and the array offset can never drift
/// apart again (v1 hard-coded `93` in four places).
const REWARD_SNAPSHOT_HEADER_LEN: usize = 125;

/// Serialize the materialized epoch snapshot — the `EpochRewardPolicy` plus the
/// active-set (pubkey, effective stake, registered staker) and minStake needed to
/// rebuild the proposer selector — into a self-describing, length-checked blob.
/// Layout (all integers big-endian):
///   [0]       version (=2)
///   [1..9]    epoch u64
///   [9..17]   snapshot_height u64
///   [17..25]  activation_height u64
///   [25..45]  registry [20]
///   [45..65]  reward_minter [20]
///   [65..73]  priority_fee_share_bps u64
///   [73..105] block_subsidy u256          (v2, CBF-S1)
///   [105..121] min_stake u128
///   [121..125] validator count u32
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
    let mut buf = Vec::with_capacity(REWARD_SNAPSHOT_HEADER_LEN + entries.len() * 68);
    buf.push(REWARD_SNAPSHOT_VERSION);
    buf.extend_from_slice(&policy.epoch.to_be_bytes());
    buf.extend_from_slice(&policy.snapshot_height.to_be_bytes());
    buf.extend_from_slice(&policy.activation_height.to_be_bytes());
    buf.extend_from_slice(&policy.registry);
    buf.extend_from_slice(&policy.reward_minter);
    buf.extend_from_slice(&policy.priority_fee_share_bps.to_be_bytes());
    let mut subsidy_be = [0u8; 32];
    policy.block_subsidy.to_big_endian(&mut subsidy_be);
    buf.extend_from_slice(&subsidy_be);
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
    if buf.len() < REWARD_SNAPSHOT_HEADER_LEN {
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
    // v2 (CBF-S1): full-width subsidy word — the contract ceiling is 1e21, far
    // above u64, so this must not be narrowed.
    let block_subsidy = primitive_types::U256::from_big_endian(&buf[73..105]);
    let min_stake = u128_at(105);
    let count = {
        let mut b = [0u8; 4];
        b.copy_from_slice(&buf[121..REWARD_SNAPSHOT_HEADER_LEN]);
        u32::from_be_bytes(b) as usize
    };
    let need = REWARD_SNAPSHOT_HEADER_LEN
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
    let mut off = REWARD_SNAPSHOT_HEADER_LEN;
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
        block_subsidy,
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
            block_subsidy: U256::zero(),
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

    /// CBF-S1 / ADR-4: the subsidy must survive the durable snapshot round-trip
    /// at FULL width. If it were narrowed or dropped, a node that rehydrated from
    /// disk would vest a different amount than the fleet computing it live — a
    /// state-root fork, which is exactly the class of bug SRP-S4 chased.
    #[test]
    fn test_reward_snapshot_roundtrip_preserves_block_subsidy() {
        use citrate_execution::block_rewards::EpochRewardPolicy;
        let pk = [0xC3u8; 32];
        let mut staker_of = std::collections::HashMap::new();
        staker_of.insert(pk, [0x33u8; 20]);
        // The contract ceiling, well above u64::MAX — proves no narrowing.
        let subsidy = U256::from(1_000u64) * U256::exp10(18);
        assert!(subsidy > U256::from(u64::MAX));

        let policy = EpochRewardPolicy {
            epoch: 7,
            snapshot_height: 6800,
            activation_height: 800,
            registry: [0x99u8; 20],
            reward_minter: [0x50u8; 20],
            priority_fee_share_bps: 10_000,
            block_subsidy: subsidy,
            staker_of,
        };
        let entries = vec![(pk, 32_000u128)];
        let blob = encode_reward_snapshot(&policy, &entries, 32_000u128);
        let (p2, e2, ms2) = decode_reward_snapshot(&blob).expect("decode");

        assert_eq!(p2.block_subsidy, subsidy, "subsidy must round-trip exactly");
        // Every neighbouring field must still land at the right offset after the
        // v2 header grew by 32 bytes.
        assert_eq!(p2.epoch, 7);
        assert_eq!(p2.snapshot_height, 6800);
        assert_eq!(p2.priority_fee_share_bps, 10_000);
        assert_eq!(ms2, 32_000u128);
        assert_eq!(e2, vec![(pk, 32_000u128)]);
        assert_eq!(p2.staker_of.get(&pk).copied(), Some([0x33u8; 20]));
    }

    /// A v1 blob (written before the subsidy existed) must be REJECTED, not
    /// reinterpreted. Accepting it would silently leave `block_subsidy` at zero on
    /// the rehydrating node while the rest of the fleet vests the subsidy.
    /// Rejection sends the boot path to a live recompute, which reads the real
    /// value from the registry.
    #[test]
    fn test_v1_reward_snapshot_is_rejected_not_reinterpreted() {
        // A structurally valid v1 blob: 93-byte header, zero validators.
        let mut v1 = vec![0u8; 93];
        v1[0] = 1; // version 1
        assert!(
            decode_reward_snapshot(&v1).is_err(),
            "a v1 snapshot must not decode under v2 — silent acceptance is a fork"
        );
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

    fn priority_tx(
        from: PublicKey,
        to: PublicKey,
        nonce: u64,
        max_fee: u64,
        max_prio: u64,
        seed: u8,
    ) -> Transaction {
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
            block_subsidy: U256::zero(),
            staker_of,
        }
    }

    /// HARDENING (2026-08-25): the reorg PRE-SEED must install the governing-epoch
    /// policy from the DURABLE persisted snapshot, NOT recompute it from the executor's
    /// current (fork-point) state. Proof by construction: the executor has an EMPTY
    /// registry (no `ValidatorRegistry` code/state), so a recompute path
    /// (`resync_policy_only` -> `view_call` -> `simulate_transaction`) would revert and
    /// return `Err`. If `seed_governing_policy` SUCCEEDS and installs the epoch-1 policy
    /// verbatim, it can only have read the durable S(1)=800 blob — the exact property
    /// that prevents the mid-epoch-registry-change fork.
    #[tokio::test]
    async fn seed_governing_policy_prefers_durable_over_recompute() {
        let dir = tempfile::tempdir().expect("dir");
        let storage = Arc::new(
            citrate_storage::StorageManager::new(dir.path(), PruningConfig::default())
                .expect("storage"),
        );
        // Durable S(1)=800 snapshot on disk, exactly as `sync_for_snapshot` persists it.
        let entries = vec![(PROPOSER, 40_000u128)];
        storage
            .blocks
            .put_reward_snapshot(&encode_reward_snapshot(
                &test_policy(),
                &entries,
                32_000u128,
            ))
            .expect("persist snapshot");

        // Fresh executor with NO registry contract in state — a recompute WOULD fail.
        let exec = Arc::new(Executor::new(Arc::new(StateDB::new())));
        exec.set_validator_activation_height(ACTIVATION);
        let sel = Arc::new(VrfProposerSelector::production());
        let rs = RegistrySync::new(exec.clone(), sel, REG, ACTIVATION, storage.clone());

        assert!(
            exec.reward_policy_handle().read().is_none(),
            "resident policy starts empty"
        );

        // Seed the epoch the durable snapshot governs (S(1)=800). Must succeed from the
        // durable blob without touching the empty registry.
        rs.seed_governing_policy(800)
            .await
            .expect("seed must succeed from the durable snapshot (recompute would revert)");

        let resident = exec
            .reward_policy_handle()
            .read()
            .clone()
            .expect("policy installed from durable snapshot");
        assert_eq!(resident.snapshot_height, 800, "durable S(1) height");
        assert_eq!(resident.epoch, 1, "durable epoch");
        assert_eq!(
            resident.priority_fee_share_bps, SHARE_BPS,
            "installed the durable snapshot policy verbatim, not a recompute"
        );

        // A governing epoch the durable (latest-only) snapshot does NOT cover falls back
        // to the recompute path, which reverts against the empty registry → Err. Guards
        // that the fallback stays wired (no silent success on epoch mismatch).
        assert!(
            rs.seed_governing_policy(2800).await.is_err(),
            "epoch mismatch must fall back to recompute (which fails on the empty registry)"
        );
    }

    /// FOLLOW-UP HARDENING (PR #168 review, finding 1): the PER-EPOCH durable store lets the
    /// reorg pre-seed load the EXACT governing epoch even when the LATEST-persisted snapshot is
    /// a NEWER epoch — the boundary-crossing reorg the old latest-only store could not cover.
    /// Persist S(1)=800 (2500 bps) and S(2)=1800 (5000 bps) both per-epoch and as latest (so
    /// the latest key ends up holding S(2)). Seeding the governing epoch S(1) against an EMPTY
    /// registry (a recompute would revert) must load S(1)'s 2500 bps from the per-epoch key,
    /// NOT S(2)'s 5000 and NOT a recompute.
    #[tokio::test]
    async fn seed_governing_policy_loads_exact_epoch_when_latest_is_newer() {
        let dir = tempfile::tempdir().expect("dir");
        let storage = Arc::new(
            citrate_storage::StorageManager::new(dir.path(), PruningConfig::default())
                .expect("storage"),
        );
        let entries = vec![(PROPOSER, 40_000u128)];

        // S(1)=800 (share = SHARE_BPS = 2500): per-epoch AND latest.
        let p1 = test_policy();
        let blob1 = encode_reward_snapshot(&p1, &entries, 32_000u128);
        storage
            .blocks
            .put_reward_snapshot_at(800, &blob1)
            .expect("s1 per-epoch");
        storage
            .blocks
            .put_reward_snapshot(&blob1)
            .expect("s1 latest");

        // S(2)=1800 (share = 5000): per-epoch AND the NEW latest — the tip advanced past S(2).
        let mut p2 = test_policy();
        p2.epoch = 2;
        p2.snapshot_height = 1800;
        p2.priority_fee_share_bps = 5000;
        let blob2 = encode_reward_snapshot(&p2, &entries, 32_000u128);
        storage
            .blocks
            .put_reward_snapshot_at(1800, &blob2)
            .expect("s2 per-epoch");
        storage
            .blocks
            .put_reward_snapshot(&blob2)
            .expect("s2 latest");

        // Empty registry — a recompute would revert, so success proves the per-epoch read.
        let exec = Arc::new(Executor::new(Arc::new(StateDB::new())));
        exec.set_validator_activation_height(ACTIVATION);
        let sel = Arc::new(VrfProposerSelector::production());
        let rs = RegistrySync::new(exec.clone(), sel, REG, ACTIVATION, storage.clone());

        // Seed the GOVERNING epoch S(1)=800 while the LATEST persisted snapshot is S(2)=1800.
        rs.seed_governing_policy(800)
            .await
            .expect("must load the exact S(1) per-epoch snapshot, not recompute");
        let resident = exec
            .reward_policy_handle()
            .read()
            .clone()
            .expect("policy installed from per-epoch snapshot");
        assert_eq!(
            resident.snapshot_height, 800,
            "exact governing epoch, not the newer latest S(2)"
        );
        assert_eq!(resident.epoch, 1);
        assert_eq!(
            resident.priority_fee_share_bps, SHARE_BPS,
            "loaded S(1)'s 2500 bps, NOT S(2)'s 5000 — the boundary-crossing case is covered"
        );
    }

    fn fund(exec: &Executor) -> (PublicKey, PublicKey) {
        let a = snd(1);
        let b = snd(2);
        exec.set_balance(&address_utils::normalize_address(&a), U256::from(u128::MAX));
        (a, b)
    }

    fn fwd_txs(a: PublicKey, b: PublicKey) -> Vec<Transaction> {
        vec![priority_tx(
            a,
            b,
            0,
            CANONICAL_BASE_FEE_PER_GAS + 900,
            250,
            0xA1,
        )]
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
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
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
            receipts.push(
                exec.execute_transaction(&tmpl, tx)
                    .await
                    .expect("tx executes"),
            );
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
        sel_u
            .sync_active_set(vec![(PublicKey::new(PROPOSER), 40_000u128)], 32_000u128)
            .await;
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
            citrate_storage::StorageManager::new(dir.path(), PruningConfig::default())
                .expect("storage"),
        );
        // Persist the durable snapshot exactly as `sync_for_snapshot` would have at S(1).
        let entries = vec![(PROPOSER, 40_000u128)];
        storage
            .blocks
            .put_reward_snapshot(&encode_reward_snapshot(
                &test_policy(),
                &entries,
                32_000u128,
            ))
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
            .apply_block(
                &sealed,
                sealed.header.coinbase,
                &citrate_execution::executor::fixed_reward(&basic),
            )
            .await
            .expect("restarted node reproduces + accepts the forward block");
        assert_eq!(
            got, root_u,
            "BUG-1 closed: restarted state root == continuously-up node"
        );
        assert_eq!(
            r.get_balance(&Address(REG)),
            reg_u,
            "vested share matches after rehydration"
        );
        assert!(
            reg_u > U256::zero(),
            "a positive §R' share must have vested"
        );

        // BUG-3 closed: the selector is repopulated → identical admission verdict.
        let admit_r = sel_r
            .is_eligible_proposer(&PublicKey::new(PROPOSER), &Hash::default(), FWD_HEIGHT)
            .await
            .expect("admission verdict R (selector rehydrated)");
        assert_eq!(
            admit_r, admit_u,
            "membership admission verdict matches after boot"
        );
        assert!(admit_r, "proposer is eligible on the rehydrated selector");
        assert_eq!(
            sel_r.active_validator_count().await,
            1,
            "selector repopulated on boot"
        );
    }

    /// Fallback path: no durable snapshot present → `hydrate_on_boot` recomputes at
    /// the greatest S(E) <= the tip; below S(1) there is simply nothing to rehydrate.
    #[tokio::test]
    async fn boot_rehydration_below_first_snapshot_is_noop() {
        let dir = tempfile::tempdir().expect("dir");
        let storage = Arc::new(
            citrate_storage::StorageManager::new(dir.path(), PruningConfig::default())
                .expect("storage"),
        );
        let r = Arc::new(Executor::new(Arc::new(StateDB::new())));
        let sel = Arc::new(VrfProposerSelector::production());
        let rs = RegistrySync::new(r.clone(), sel, REG, ACTIVATION, storage);
        let desc = rs.hydrate_on_boot(500).await.expect("hydrate");
        assert!(desc.contains("below first snapshot"), "got: {desc}");
        assert!(
            r.reward_policy_handle().read().is_none(),
            "no policy below S(1)"
        );
    }
}
