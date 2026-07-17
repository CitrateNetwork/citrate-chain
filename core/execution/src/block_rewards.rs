// core/execution/src/block_rewards.rs
//
// VALIDATOR-S1 §R' — priority-fee reallocation (execution layer, CONSENSUS-CRITICAL).
//
// WHY THIS MODULE EXISTS (the fleet-fork it prevents):
//   Priority fees were 100% BURNED. The executor deducts gas_limit*gas_price up
//   front and refunds the unused portion, but the net gas_used*gas_price is
//   credited to NO ONE (REVM credits the coinbase internally, but
//   `StateDBAdapter::commit` discards REVM balance writes — Sprint EL-1 Fix #19).
//   §R' redirects the validator's SHARE of the *priority* portion into bonded,
//   slashable stake via `ValidatorRegistry.creditReward`.
//
//   The block PRODUCER (`node/src/producer.rs`) and the RECEIVER
//   (`Executor::apply_block_inner`) are SEPARATE code paths. If they computed the
//   reward credit even one wei differently, every produced block would fail the
//   receiver's `state_root` check and the fleet would HALT. Therefore BOTH paths
//   funnel through the SINGLE shared entrypoint `Executor::settle_block_rewards`
//   (in `executor.rs`), which uses ONLY the deterministic helpers in this module.
//   There is no second implementation to drift from.
//
// DETERMINISM CONTRACT (every value below is a pure function of committed /
// on-chain data that BOTH paths observe identically):
//   * base fee is a REROLL CONSTANT (`CANONICAL_BASE_FEE_PER_GAS`), committed in
//     the block hash, and re-validated on import — a producer cannot set it to 0
//     to inflate the priority pool (that block is rejected).
//   * the priority-fee SHARE (`priorityFeeShareBps`) and the proposer->staker map
//     are read from the FINALIZED epoch snapshot S(E) that `registry_sync`
//     materializes into `EpochRewardPolicy`, NEVER from the live tip — so a
//     mid-epoch governance change cannot fork the reward.
//   * the per-tx TRUE priority is `min(max_priority_fee, gas_price - base_fee)`
//     (EIP-1559), computed identically for producer and receiver.
//   * the vesting is an execution->contract system-call to `creditReward` run on
//     the identical post-transaction state on both paths (same EVM, same inputs,
//     same success/revert verdict).
//
// See docs/consensus/REROLL_ADDENDUM_execute_on_receive_and_validator_s1.md (§C/§R')
// and contracts/src/ValidatorRegistry.sol (creditReward / rewardMinter / priorityFeeShareBps).

use std::collections::HashMap;
use std::sync::Arc;

use citrate_consensus::types::Transaction;
use parking_lot::RwLock;
use primitive_types::U256;

use crate::types::{ExecutionError, TransactionReceipt};

// ─────────────────────────────────────────────────────────────────────────────
// Reroll constants — fleet-wide identical, activated at the v2 genesis.
// ─────────────────────────────────────────────────────────────────────────────

/// The base fee, fixed as a REROLL CONSTANT under v2 (execute-on-receive).
///
/// WHY A CONSTANT (not the dynamic EIP-1559 parent formula): the producer's
/// EIP-1559 base-fee code reads `parent_gas_used` which it never actually loads
/// (hard-coded 0), so today it already emits a constant 1 gwei on every block.
/// Making that explicit — and validating it on import — removes an entire class
/// of fork: a producer that sets `base_fee_per_gas = 0` (or any other value)
/// would enlarge / shrink the priority pool and diverge from receivers. With a
/// fixed constant the receiver simply REJECTS any v2 block whose committed
/// `header.base_fee_per_gas` differs. A dynamic fee market is a FUTURE change
/// that must first make the parent-gas formula a *validated* consensus rule
/// (producer computes it, importer re-derives and rejects on mismatch).
///
/// Value = 1 gwei, byte-identical to the producer's current effective output.
pub const CANONICAL_BASE_FEE_PER_GAS: u64 = 1_000_000_000;

/// The execution-layer system address that funds + authorizes `creditReward`.
/// It is the `msg.sender` of the vesting system-call and MUST equal the
/// `rewardMinter` immutable set in the `ValidatorRegistry` constructor (WS-5).
///
/// Chosen well above the precompile range (0x01..=0x0120) so it can never alias
/// a precompile; low 4 bytes spell "PRIP". This address holds no persistent
/// balance (each block it is transiently funded with exactly the vested amount
/// and drained back to net-zero) and never has code, so EIP-3607 never rejects
/// it as the caller.
///
/// ==> WS-5 RECONCILE: `ValidatorRegistry(..., rewardMinter_ = 0x0000000000000000000000000000000050524950, ...)`.
pub const REWARD_MINTER_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x52, 0x49, 0x50,
];

/// `creditReward(bytes32,uint256)` — verified `cast sig` == 0xb8491252.
pub const CREDIT_REWARD_SELECTOR: [u8; 4] = [0xb8, 0x49, 0x12, 0x52];
/// `priorityFeeShareBps()` — verified `cast sig` == 0xc88b62d3.
pub const PRIORITY_FEE_SHARE_BPS_SELECTOR: [u8; 4] = [0xc8, 0x8b, 0x62, 0xd3];
/// `rewardMinter()` — verified `cast sig` == 0x9b8e5563.
pub const REWARD_MINTER_SELECTOR: [u8; 4] = [0x9b, 0x8e, 0x55, 0x63];
/// `validatorInfo(bytes32)` — verified `cast sig` == 0x00408838. Returns
/// `(address staker, uint256 bonded, ... )`; the first word is the staker.
pub const VALIDATOR_INFO_SELECTOR: [u8; 4] = [0x00, 0x40, 0x88, 0x38];

/// Gas ceiling for the `creditReward` system-call. Generous vs. its real cost
/// (a couple of SSTOREs + an SLOAD ~ 60k). Gas price is 0 so this never charges
/// anyone; the value only bounds runaway execution.
pub const SYSTEM_CALL_GAS_LIMIT: u64 = 1_000_000;

// ─────────────────────────────────────────────────────────────────────────────
// Epoch reward policy — the FINALIZED S(E) snapshot the reward path reads.
// ─────────────────────────────────────────────────────────────────────────────

/// Everything the §R' reward path needs, captured AS-OF the finalized snapshot
/// block S(E). Materialized by `registry_sync` at each snapshot boundary and read
/// (never re-derived from the live tip) by `Executor::settle_block_rewards`.
///
/// Because producer and receiver share ONE `SharedRewardPolicy` cell (it hangs
/// off the single shared `Executor`) that is rewritten at the same S(E) heights
/// on every node, both always read byte-identical policy for a given block.
#[derive(Clone, Debug)]
pub struct EpochRewardPolicy {
    /// Epoch E this snapshot governs. Diagnostic / assertion aid.
    pub epoch: u64,
    /// The snapshot height S(E) this was read at. Diagnostic aid.
    pub snapshot_height: u64,
    /// Height at/above which §R' vesting + its import rules are ENFORCED. Below
    /// it, priority fees burn exactly as before (no behavior change pre-reroll
    /// activation). Fleet-wide identical (`CITRATE_VALIDATOR_ACTIVATION_HEIGHT`).
    pub activation_height: u64,
    /// The `ValidatorRegistry` address (20-byte EVM).
    pub registry: [u8; 20],
    /// The registry's immutable `rewardMinter` (the system-call `msg.sender`).
    pub reward_minter: [u8; 20],
    /// `priorityFeeShareBps` as-of S(E). `< 10000` (contract-enforced).
    pub priority_fee_share_bps: u64,
    /// proposer ed25519 pubkey (canonical 32-byte) -> registered `stakerAddress`,
    /// for every ACTIVE validator at S(E). The reward beneficiary is resolved
    /// through THIS map (§R' #1), never `header.coinbase` directly.
    pub staker_of: HashMap<[u8; 32], [u8; 20]>,
}

/// Interior-mutable, cheaply-clonable handle to the current epoch policy. `None`
/// until the first snapshot is materialized (pre-activation / fresh boot).
pub type SharedRewardPolicy = Arc<RwLock<Option<EpochRewardPolicy>>>;

/// A fresh, empty shared policy cell (no snapshot yet).
pub fn new_shared_reward_policy() -> SharedRewardPolicy {
    Arc::new(RwLock::new(None))
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure priority-fee math — the ONLY place per-tx priority is computed.
// ─────────────────────────────────────────────────────────────────────────────

/// The EIP-1559 TRUE priority (tip) per gas for `tx` at `base_fee`, or `None`
/// if the transaction is INVALID under §R' because its offered price cannot
/// cover the base fee (`gas_price < base_fee`). `None` => the whole block must be
/// rejected (a valid block never includes such a tx).
///
/// `gas_price` is the decoder's field: the real all-in price for legacy/2930
/// txs, and the `maxFeePerGas` PROXY for type-2 (see `eth_tx_decoder`). We
/// deliberately recompute the true tip rather than trust that proxy, which
/// OVERCOUNTS type-2 tips:
///   * legacy / 2930 (`eth_tx_type` 0/1): tip = `gas_price - base_fee`.
///   * type-2 (`eth_tx_type` 2): tip = `min(max_priority_fee, gas_price - base_fee)`
///     (with `gas_price == max_fee_per_gas`) — the canonical EIP-1559 effective tip.
pub fn true_priority_per_gas(tx: &Transaction, base_fee: u64) -> Option<u64> {
    if tx.gas_price < base_fee {
        return None; // §R' reject rule: cannot cover the base fee.
    }
    let over_base = tx.gas_price - base_fee; // >= 0, checked above.
    let tip = if tx.eth_tx_type == 2 {
        // gas_price == max_fee_per_gas for type-2; clamp by the explicit tip cap.
        let cap = tx.max_priority_fee_per_gas.unwrap_or(over_base);
        over_base.min(cap)
    } else {
        over_base
    };
    Some(tip)
}

/// The gas actually CHARGED to the sender for `receipt`, mirroring the executor's
/// real accounting so the vested pool can never exceed collected fees:
///   * success (`status == true`): `gas_used` (the up-front `gas_limit` charge is
///     refunded down to `gas_used`).
///   * failure (`status == false`, i.e. a revert): the executor charges the FULL
///     `gas_limit` with no refund, so the priority is levied on `gas_limit`.
fn gas_charged(receipt: &TransactionReceipt, gas_limit: u64) -> u64 {
    if receipt.status {
        receipt.gas_used
    } else {
        gas_limit
    }
}

/// The block's total priority-fee pool = sum of tip_per_gas * gas_charged over
/// every transaction, in wei. Returns `Err` (=> REJECT the block) if any included
/// tx is invalid under §R' (`gas_price < base_fee`). `txs` and `receipts` MUST be
/// positionally aligned (same order, same length) — they are, because both the
/// producer and the receiver iterate the block's committed transaction list.
///
/// All arithmetic is `U256` (a u64 tip x u64 gas fits easily; the running sum
/// cannot realistically overflow 256 bits) and order-independent (a commutative
/// sum), so parallel vs. sequential execution cannot change the result.
pub fn compute_priority_pool(
    txs: &[Transaction],
    receipts: &[TransactionReceipt],
    base_fee: u64,
) -> Result<U256, ExecutionError> {
    if txs.len() != receipts.len() {
        return Err(ExecutionError::RewardSettlement(format!(
            "tx/receipt count mismatch: {} txs vs {} receipts",
            txs.len(),
            receipts.len()
        )));
    }
    let mut pool = U256::zero();
    for (tx, receipt) in txs.iter().zip(receipts.iter()) {
        let tip = true_priority_per_gas(tx, base_fee).ok_or_else(|| {
            ExecutionError::RewardSettlement(format!(
                "tx {} gas_price {} below base_fee {} (EIP-1559 invalid)",
                tx.hash, tx.gas_price, base_fee
            ))
        })?;
        if tip == 0 {
            continue;
        }
        let charged = gas_charged(receipt, tx.gas_limit);
        pool = pool.saturating_add(U256::from(tip) * U256::from(charged));
    }
    Ok(pool)
}

/// The validator's vested share of `pool`, `floor(pool * share_bps / 10000)`.
/// `share_bps` is contract-bounded `< 10000`; we clamp defensively. Integer
/// floor division => deterministic; the remainder (incl. the burned complement)
/// stays out of supply exactly as the whole pool did before §R'.
pub fn vested_share(pool: U256, share_bps: u64) -> U256 {
    let bps = share_bps.min(10_000);
    // `saturating_mul` for consistency with `compute_priority_pool`'s
    // `saturating_add`: a u256 pool * a <=10000 bps cannot realistically
    // overflow, but we never panic on the arithmetic (a panic mid-settle would
    // be a fleet-wide liveness fault). Saturation is deterministic on every node.
    pool.saturating_mul(U256::from(bps)) / U256::from(10_000u64)
}

// ─────────────────────────────────────────────────────────────────────────────
// ABI helpers for the vesting system-call + snapshot materialization reads.
// ─────────────────────────────────────────────────────────────────────────────

/// ABI calldata for `creditReward(bytes32 pubkey, uint256 amount)`:
/// selector then pubkey(32) then amount(32, big-endian).
pub fn encode_credit_reward(pubkey: &[u8; 32], amount: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 + 32);
    data.extend_from_slice(&CREDIT_REWARD_SELECTOR);
    data.extend_from_slice(pubkey);
    let mut amt = [0u8; 32];
    amount.to_big_endian(&mut amt);
    data.extend_from_slice(&amt);
    data
}

/// Decode a `uint256` return word into `u64`, saturating on the impossible
/// (for a bps / share) >u64 case — deterministically on every node.
pub fn decode_u64_word(ret: &[u8]) -> Result<u64, String> {
    if ret.len() < 32 {
        return Err(format!("uint256 return too short ({} bytes)", ret.len()));
    }
    // Low 8 bytes hold the value for any in-range quantity; require the high 24
    // bytes are zero, else saturate to u64::MAX (never silently truncate).
    if ret[..24].iter().any(|&b| b != 0) {
        return Ok(u64::MAX);
    }
    let mut b8 = [0u8; 8];
    b8.copy_from_slice(&ret[24..32]);
    Ok(u64::from_be_bytes(b8))
}

/// Decode a right-aligned 20-byte address from a 32-byte ABI word (`address` or
/// the first field of a struct return, e.g. `validatorInfo(...).staker`).
pub fn decode_address_word(ret: &[u8]) -> Result<[u8; 20], String> {
    if ret.len() < 32 {
        return Err(format!("address return too short ({} bytes)", ret.len()));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&ret[12..32]);
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{Hash, PublicKey, Signature};

    fn mk_tx(eth_tx_type: u8, gas_price: u64, max_prio: Option<u64>, gas_limit: u64) -> Transaction {
        Transaction {
            hash: Hash::default(),
            nonce: 0,
            from: PublicKey::new([0u8; 32]),
            to: None,
            value: 0,
            gas_limit,
            gas_price,
            data: vec![],
            signature: Signature::new([0u8; 64]),
            tx_type: None,
            eth_tx_type,
            max_fee_per_gas: if eth_tx_type == 2 { Some(gas_price) } else { None },
            max_priority_fee_per_gas: max_prio,
            access_list: None,
            chain_id: None,
            ecdsa_verified: false,
        }
    }

    fn mk_receipt(status: bool, gas_used: u64) -> TransactionReceipt {
        TransactionReceipt {
            tx_hash: Hash::default(),
            block_hash: Hash::default(),
            block_number: 0,
            from: crate::types::Address([0u8; 20]),
            to: None,
            gas_used,
            status,
            logs: vec![],
            output: vec![],
            eth_tx_type: 0,
            effective_gas_price: 0,
            revert_reason: None,
        }
    }

    const BASE: u64 = CANONICAL_BASE_FEE_PER_GAS; // 1 gwei

    #[test]
    fn legacy_tip_is_price_minus_base() {
        let tx = mk_tx(0, BASE + 5, None, 21_000);
        assert_eq!(true_priority_per_gas(&tx, BASE), Some(5));
    }

    #[test]
    fn type2_tip_is_min_of_cap_and_over_base() {
        // over_base = 10, cap = 3 -> 3.
        let tx = mk_tx(2, BASE + 10, Some(3), 21_000);
        assert_eq!(true_priority_per_gas(&tx, BASE), Some(3));
        // over_base = 2, cap = 9 -> 2 (the max_fee proxy would have overcounted).
        let tx2 = mk_tx(2, BASE + 2, Some(9), 21_000);
        assert_eq!(true_priority_per_gas(&tx2, BASE), Some(2));
    }

    #[test]
    fn gas_price_below_base_is_rejected() {
        let tx = mk_tx(0, BASE - 1, None, 21_000);
        assert_eq!(true_priority_per_gas(&tx, BASE), None);
        let err = compute_priority_pool(&[tx], &[mk_receipt(true, 21_000)], BASE);
        assert!(err.is_err(), "block with sub-base-fee tx must be rejected");
    }

    #[test]
    fn pool_sums_success_on_gas_used_failure_on_gas_limit() {
        // tx0: legacy, tip 5, success, gas_used 20_000 -> 100_000
        // tx1: type-2, over_base 10 cap 4 -> tip 4, FAIL -> charged gas_limit 30_000 -> 120_000
        let txs = vec![
            mk_tx(0, BASE + 5, None, 21_000),
            mk_tx(2, BASE + 10, Some(4), 30_000),
        ];
        let receipts = vec![mk_receipt(true, 20_000), mk_receipt(false, 12_000)];
        let pool = compute_priority_pool(&txs, &receipts, BASE).expect("pool");
        assert_eq!(pool, U256::from(5u64 * 20_000 + 4u64 * 30_000));
    }

    #[test]
    fn zero_tip_contributes_nothing() {
        let tx = mk_tx(0, BASE, None, 21_000); // tip 0
        let pool = compute_priority_pool(&[tx], &[mk_receipt(true, 21_000)], BASE).expect("pool");
        assert_eq!(pool, U256::zero());
    }

    #[test]
    fn vested_share_floors_deterministically() {
        // 100 wei @ 2500 bps = 25.
        assert_eq!(vested_share(U256::from(100u64), 2500), U256::from(25u64));
        // 7 wei @ 3333 bps = floor(2.333) = 2.
        assert_eq!(vested_share(U256::from(7u64), 3333), U256::from(2u64));
        // out-of-range bps clamps to 10000 (defense; contract forbids >=10000).
        assert_eq!(vested_share(U256::from(9u64), 20000), U256::from(9u64));
    }

    #[test]
    fn encode_credit_reward_layout() {
        let pk = [0xABu8; 32];
        let data = encode_credit_reward(&pk, U256::from(0x1234u64));
        assert_eq!(&data[..4], &CREDIT_REWARD_SELECTOR);
        assert_eq!(&data[4..36], &pk);
        // amount occupies the last 32-byte word, big-endian: 0x1234.
        assert_eq!(&data[66..68], &[0x12, 0x34]);
        assert!(data[36..66].iter().all(|&b| b == 0));
        assert_eq!(data.len(), 68);
    }

    #[test]
    fn decode_helpers_roundtrip() {
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&2500u64.to_be_bytes());
        assert_eq!(decode_u64_word(&word).expect("u64"), 2500);
        let mut aw = [0u8; 32];
        aw[12..32].copy_from_slice(&[0x11u8; 20]);
        assert_eq!(decode_address_word(&aw).expect("addr"), [0x11u8; 20]);
    }

    #[test]
    fn count_mismatch_is_rejected() {
        let txs = vec![mk_tx(0, BASE + 1, None, 21_000)];
        let receipts: Vec<TransactionReceipt> = vec![];
        assert!(compute_priority_pool(&txs, &receipts, BASE).is_err());
    }

    /// Share-rounding PROPERTY: over a spread of pools and bps, `vested_share` is
    /// exactly `floor(pool * bps / 10000)`, is monotonic-bounded by the pool, and
    /// the vested part plus the (implicitly burned) remainder always reconstitute
    /// the pool with no wei created or lost. Deterministic integer floor division
    /// — the same on every node, so producer and receiver never split a wei.
    #[test]
    fn vested_share_rounding_property() {
        let pools: [u128; 8] = [0, 1, 7, 9_999, 10_000, 10_001, 123_456_789, u64::MAX as u128];
        let bpss: [u64; 7] = [0, 1, 2500, 3333, 5000, 9999, 10000];
        for &p in &pools {
            for &bps in &bpss {
                let pool = U256::from(p);
                let share = vested_share(pool, bps);
                let bps_c = bps.min(10_000);
                // exact floor semantics
                let expected = pool * U256::from(bps_c) / U256::from(10_000u64);
                assert_eq!(share, expected, "pool={p} bps={bps}");
                // never exceeds the pool; complement + share == pool (conservation)
                assert!(share <= pool, "share exceeds pool: pool={p} bps={bps}");
                let burned = pool - share; // the un-vested remainder stays burned
                assert_eq!(burned + share, pool, "wei created/lost: pool={p} bps={bps}");
            }
        }
    }
}
