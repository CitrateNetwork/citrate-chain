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
/// `blockSubsidy()` — verified `cast sig` == 0xce0400b7. CBF-S1 / ADR-4: the
/// per-block issuance the registry has always been parameterised for but which
/// no execution path ever paid, leaving validators on an idle chain earning
/// exactly zero (live proof at 40204: `emittedInEpoch` == 0 for every epoch).
pub const BLOCK_SUBSIDY_SELECTOR: [u8; 4] = [0xce, 0x04, 0x00, 0xb7];

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
    /// `blockSubsidy` as-of S(E) — the flat per-block issuance vested to the
    /// proposer ON TOP of its priority-fee share (CBF-S1 / ADR-4). Contract-
    /// bounded by `BLOCK_SUBSIDY_CEIL` (1k SALT) and, together with the fee
    /// share, by the per-epoch `maxEpochEmission` cap enforced inside
    /// `creditReward`. Read from the SAME finalized snapshot as every other
    /// policy field, so producer and receiver settle byte-identically.
    pub block_subsidy: U256,
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

/// The TOTAL amount vested to the proposer for one block (CBF-S1 / ADR-4):
/// its priority-fee share PLUS the flat `block_subsidy`.
///
/// The subsidy is what makes "run a node, earn SALT" true on a chain with no
/// fee volume. Before it, `settle_block_rewards` short-circuited on a zero
/// share and `creditReward` was never called — verified on live 40204, where
/// four fully-staked validators had accrued 0.00207 SALT in total.
///
/// `saturating_add` for the same reason `vested_share` saturates: a panic
/// mid-settle would be a fleet-wide liveness fault, and saturation is
/// deterministic on every node. The per-epoch `maxEpochEmission` cap inside
/// `creditReward` remains the binding supply limit — if this total would breach
/// it the contract reverts and the block's reward is burned, exactly as before.
pub fn total_vested(pool: U256, share_bps: u64, block_subsidy: U256) -> U256 {
    vested_share(pool, share_bps).saturating_add(block_subsidy)
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

/// Decode a full-width `uint256` from a 32-byte ABI word.
///
/// Unlike [`decode_u64_word`] this never saturates, which is REQUIRED for
/// `blockSubsidy`: its contract ceiling (`BLOCK_SUBSIDY_CEIL` = 1k SALT = 1e21
/// wei) is two orders of magnitude above `u64::MAX`, so a u64 decode would clamp
/// every realistic subsidy to a wrong value and vest the wrong amount.
pub fn decode_u256_word(ret: &[u8]) -> Result<U256, String> {
    if ret.len() < 32 {
        return Err(format!("uint256 return too short ({} bytes)", ret.len()));
    }
    Ok(U256::from_big_endian(&ret[..32]))
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

    /// CBF-S1 / ADR-4 REGRESSION — the bug this sprint exists to fix.
    ///
    /// On an idle chain the priority pool is zero, so the pre-subsidy reward was
    /// `vested_share(0, bps) == 0`, `settle_block_rewards` short-circuited, and
    /// `creditReward` was never called. Live proof at 40204 before this change:
    /// `emittedInEpoch(e) == 0` for every epoch, and four fully-staked validators
    /// had accrued 0.00207 SALT between them across ~138k blocks.
    ///
    /// With the subsidy, a proposer earns on a chain with no transactions at all.
    #[test]
    fn subsidy_vests_on_an_idle_chain() {
        let ten_salt = U256::from(10_000_000_000_000_000_000u128); // 10 SALT
        // No fees whatsoever — the exact condition that paid zero before.
        assert_eq!(vested_share(U256::zero(), 10_000), U256::zero());
        assert_eq!(total_vested(U256::zero(), 10_000, ten_salt), ten_salt);
        // And the zero short-circuit in `settle_block_rewards` is no longer taken.
        assert!(!total_vested(U256::zero(), 10_000, ten_salt).is_zero());
    }

    #[test]
    fn total_vested_is_fee_share_plus_subsidy() {
        // 100 wei pool @ 2500 bps = 25, plus a 7-wei subsidy = 32.
        assert_eq!(
            total_vested(U256::from(100u64), 2500, U256::from(7u64)),
            U256::from(32u64)
        );
        // A zero subsidy is exactly the pre-CBF-S1 behavior (governance may set it
        // to 0 to return to a fee-only regime without a binary change).
        assert_eq!(
            total_vested(U256::from(100u64), 2500, U256::zero()),
            vested_share(U256::from(100u64), 2500)
        );
        // Both zero => still zero, so the short-circuit still applies on a chain
        // with no fees AND no subsidy.
        assert!(total_vested(U256::zero(), 2500, U256::zero()).is_zero());
    }

    /// A panic mid-settle is a fleet-wide liveness fault, so the addition must
    /// saturate rather than overflow — deterministically on every node.
    #[test]
    fn total_vested_saturates_without_panic() {
        assert_eq!(total_vested(U256::MAX, 10_000, U256::MAX), U256::MAX);
        assert_eq!(total_vested(U256::zero(), 0, U256::MAX), U256::MAX);
    }

    /// `blockSubsidy`'s contract ceiling is 1e21 wei — above `u64::MAX` (~1.8e19).
    /// Decoding it through the u64 path would silently clamp and vest a wrong
    /// amount, so the full-width decoder is mandatory.
    #[test]
    fn decode_u256_word_does_not_narrow_the_subsidy_ceiling() {
        let ceil = U256::from(1_000u64) * U256::exp10(18); // BLOCK_SUBSIDY_CEIL = 1k SALT
        assert!(ceil > U256::from(u64::MAX));
        let mut word = [0u8; 32];
        ceil.to_big_endian(&mut word);

        assert_eq!(decode_u256_word(&word).expect("decode"), ceil);
        // The narrow decoder saturates — proving why it must not be used here.
        assert_eq!(decode_u64_word(&word).expect("decode"), u64::MAX);
        assert!(decode_u256_word(&word[..31]).is_err(), "short word must error");
    }

    #[test]
    fn block_subsidy_selector_matches_the_contract() {
        // `cast sig 'blockSubsidy()'` == 0xce0400b7
        assert_eq!(BLOCK_SUBSIDY_SELECTOR, [0xce, 0x04, 0x00, 0xb7]);
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

    // Expose the test constructors to the sibling proptest module. (The private
    // `gas_charged` is reachable there directly as `super::gas_charged`, since
    // that module is a descendant of `block_rewards`.)
    pub(super) fn mk_tx_pub(t: u8, gp: u64, mp: Option<u64>, gl: u64) -> Transaction {
        mk_tx(t, gp, mp, gl)
    }
    pub(super) fn mk_receipt_pub(status: bool, gas_used: u64) -> TransactionReceipt {
        mk_receipt(status, gas_used)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROPERTY / FUZZ suite (campaign-rprime-math-fuzz).
//
// These tests throw thousands of proptest-generated inputs at the §R' pure math
// to try to BREAK the six load-bearing invariants of the priority-fee reroll.
// Every assertion is a determinism / conservation guarantee: a single failing
// case is a consensus fork or a wei created/destroyed. Reference computations
// are done in U512 so overflow behaviour of the U256 code under test is checked
// against an oracle that cannot itself overflow.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod proptests {
    use super::tests::{mk_receipt_pub, mk_tx_pub};
    use super::*;
    use primitive_types::U512;
    use proptest::prelude::*;

    /// EIP-1559 tip oracle, written independently of the implementation.
    fn expected_tip(eth_tx_type: u8, gas_price: u64, max_prio: Option<u64>, base_fee: u64) -> Option<u64> {
        if gas_price < base_fee {
            return None;
        }
        let over_base = gas_price - base_fee;
        if eth_tx_type == 2 {
            let cap = max_prio.unwrap_or(over_base);
            Some(over_base.min(cap))
        } else {
            Some(over_base)
        }
    }

    /// U256 -> U512 widening (lossless) so the oracle never overflows.
    fn to512(x: U256) -> U512 {
        let mut be = [0u8; 32];
        x.to_big_endian(&mut be);
        U512::from_big_endian(&be)
    }

    fn u256_from_bytes(b: [u8; 32]) -> U256 {
        U256::from_big_endian(&b)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

        // ── INVARIANT 2: EIP-1559 tip correctness across ALL tx types + edges ──
        // eth_tx_type spans 0..=5 (covers legacy/2930, type-2, and unknown-high
        // which §R' must treat as legacy). Full u64 range on prices + priority.
        #[test]
        fn prop_tip_matches_eip1559_oracle(
            eth_tx_type in 0u8..=5,
            gas_price in any::<u64>(),
            base_fee in any::<u64>(),
            max_prio in proptest::option::of(any::<u64>()),
        ) {
            let tx = mk_tx_pub(eth_tx_type, gas_price, max_prio, 21_000);
            let got = true_priority_per_gas(&tx, base_fee);
            let want = expected_tip(eth_tx_type, gas_price, max_prio, base_fee);
            prop_assert_eq!(got, want, "tip mismatch t={} gp={} bf={} mp={:?}", eth_tx_type, gas_price, base_fee, max_prio);

            match got {
                None => prop_assert!(gas_price < base_fee, "None only when gas_price < base_fee"),
                Some(tip) => {
                    let over_base = gas_price - base_fee;
                    // tip can never exceed the room above base fee.
                    prop_assert!(tip <= over_base, "tip {} exceeds over_base {}", tip, over_base);
                    // edge: gas_price == base_fee => tip exactly 0.
                    if gas_price == base_fee { prop_assert_eq!(tip, 0u64); }
                    // type-2 explicit-cap edges.
                    if eth_tx_type == 2 {
                        if let Some(cap) = max_prio {
                            if cap == 0 { prop_assert_eq!(tip, 0u64); }
                            if cap >= over_base { prop_assert_eq!(tip, over_base); }
                            if cap < over_base { prop_assert_eq!(tip, cap); }
                        } else {
                            // absent cap on type-2 => behaves like legacy (full over_base).
                            prop_assert_eq!(tip, over_base);
                        }
                    }
                }
            }
        }

        // ── INVARIANT 2 (reject path): gas_price < base_fee => None AND the whole
        //    block is rejected by compute_priority_pool. ──
        #[test]
        fn prop_sub_base_fee_rejected(
            base_fee in 1u64..=u64::MAX,
            deficit in 1u64..=u64::MAX,
        ) {
            let gas_price = base_fee.saturating_sub(deficit);
            prop_assume!(gas_price < base_fee);
            let tx = mk_tx_pub(0, gas_price, None, 21_000);
            prop_assert_eq!(true_priority_per_gas(&tx, base_fee), None);
            let res = compute_priority_pool(&[tx], &[mk_receipt_pub(true, 21_000)], base_fee);
            prop_assert!(res.is_err(), "block with sub-base-fee tx must be rejected");
        }

        // ── INVARIANT 3: vested_share — floor semantics, bps clamp, NO PANIC even
        //    near U256::MAX (the saturating_mul fix). Oracle in U512. ──
        #[test]
        fn prop_vested_share_floor_and_no_panic(
            pool_bytes in any::<[u8; 32]>(),
            share_bps in any::<u64>(),
        ) {
            let pool = u256_from_bytes(pool_bytes);
            // MUST NOT PANIC for any pool/bps (this line is the actual assertion
            // for the overflow-safety half of the invariant).
            let share = vested_share(pool, share_bps);

            let bps_c = share_bps.min(10_000);
            // Never exceeds the pool; complement is exact (no wei created/lost).
            prop_assert!(share <= pool, "share > pool: pool={} bps={}", pool, share_bps);
            let burned = pool - share;
            prop_assert_eq!(burned + share, pool, "wei created/lost: pool={} bps={}", pool, share_bps);

            // Exact floor semantics in the region where pool*bps does NOT overflow
            // U256 (the only region that occurs on a real chain). Oracle: U512.
            let prod512 = to512(pool) * U512::from(bps_c);
            let max256 = to512(U256::MAX);
            if prod512 <= max256 {
                let expected512 = prod512 / U512::from(10_000u64);
                prop_assert_eq!(to512(share), expected512, "floor mismatch pool={} bps={}", pool, share_bps);
            } else {
                // Overflow region: code saturates deterministically; still bounded.
                prop_assert!(share <= pool);
            }
        }

        // ── INVARIANT 4: gas_charged — success -> gas_used, revert -> gas_limit. ──
        #[test]
        fn prop_gas_charged_matches_executor(
            status in any::<bool>(),
            gas_used in any::<u64>(),
            gas_limit in any::<u64>(),
        ) {
            let receipt = mk_receipt_pub(status, gas_used);
            let charged = super::gas_charged(&receipt, gas_limit);
            if status {
                prop_assert_eq!(charged, gas_used);
            } else {
                prop_assert_eq!(charged, gas_limit);
            }
        }

        // ── INVARIANT 1 (conservation) + INVARIANT 5 (commutativity) ──
        // A valid tx set (gas_price >= base_fee by construction). The pool equals
        // Σ tip*gas_charged; vested_share <= pool; share + burned == pool; and the
        // pool is invariant under any permutation of the (tx,receipt) order.
        #[test]
        fn prop_conservation_and_commutativity(
            base_fee in 0u64..=2_000_000_000u64,
            share_bps in any::<u64>(),
            perm_seed in any::<u64>(),
            specs in proptest::collection::vec(
                (0u8..=5, any::<u64>(), proptest::option::of(any::<u64>()), 0u64..=30_000_000, any::<bool>(), 0u64..=30_000_000),
                0..24usize),
        ) {
            // Build valid txs: gas_price = base_fee + delta (saturating => always >= base_fee).
            let mut txs = Vec::with_capacity(specs.len());
            let mut receipts = Vec::with_capacity(specs.len());
            for (t, delta, mp, gl, status, gu) in &specs {
                let gas_price = base_fee.saturating_add(*delta);
                txs.push(mk_tx_pub(*t, gas_price, *mp, *gl));
                receipts.push(mk_receipt_pub(*status, *gu));
            }

            let pool = compute_priority_pool(&txs, &receipts, base_fee)
                .expect("valid tx set must produce a pool");

            // Independent oracle sum (same saturating semantics).
            let mut oracle = U256::zero();
            for (tx, receipt) in txs.iter().zip(receipts.iter()) {
                let tip = expected_tip(tx.eth_tx_type, tx.gas_price, tx.max_priority_fee_per_gas, base_fee)
                    .expect("constructed valid");
                if tip == 0 { continue; }
                let charged = if receipt.status { receipt.gas_used } else { tx.gas_limit };
                oracle = oracle.saturating_add(U256::from(tip) * U256::from(charged));
            }
            prop_assert_eq!(pool, oracle, "pool != Σ tip*gas_charged oracle");

            // CONSERVATION: share <= pool <= Σ(effective_tip*gas_charged) [== oracle];
            // share + burned == pool exactly.
            let share = vested_share(pool, share_bps);
            prop_assert!(share <= pool, "vested share exceeds pool");
            prop_assert!(pool <= oracle, "pool exceeds Σ tip*gas_charged");
            let burned = pool - share;
            prop_assert_eq!(share + burned, pool, "wei created/lost in split");

            // COMMUTATIVITY: shuffle (tx,receipt) pairs with a seeded Fisher–Yates
            // (deterministic per case) and re-derive the pool — must be identical.
            let mut idx: Vec<usize> = (0..txs.len()).collect();
            let mut state = perm_seed ^ 0x9E37_79B9_7F4A_7C15;
            let mut i = idx.len();
            while i > 1 {
                i -= 1;
                // xorshift64* step for a deterministic pseudo-random index.
                state ^= state >> 12; state ^= state << 25; state ^= state >> 27;
                let r = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
                let j = (r % (i as u64 + 1)) as usize;
                idx.swap(i, j);
            }
            let sh_txs: Vec<Transaction> = idx.iter().map(|&k| txs[k].clone()).collect();
            let sh_receipts: Vec<TransactionReceipt> = idx.iter().map(|&k| receipts[k].clone()).collect();
            let pool_shuffled = compute_priority_pool(&sh_txs, &sh_receipts, base_fee)
                .expect("shuffled valid tx set must produce a pool");
            prop_assert_eq!(pool, pool_shuffled, "pool changed under permutation (non-determinism!)");
        }

        // ── INVARIANT 5 (count mismatch): unequal lengths => Err (reject). ──
        #[test]
        fn prop_count_mismatch_rejected(
            n_tx in 0usize..8,
            n_rc in 0usize..8,
        ) {
            prop_assume!(n_tx != n_rc);
            let txs: Vec<Transaction> = (0..n_tx).map(|_| mk_tx_pub(0, 2_000_000_000, None, 21_000)).collect();
            let receipts: Vec<TransactionReceipt> = (0..n_rc).map(|_| mk_receipt_pub(true, 21_000)).collect();
            prop_assert!(compute_priority_pool(&txs, &receipts, CANONICAL_BASE_FEE_PER_GAS).is_err());
        }

        // ── INVARIANT 6: encode_credit_reward exact layout (4+32+32) + roundtrip. ──
        #[test]
        fn prop_encode_credit_reward_layout(
            pubkey in any::<[u8; 32]>(),
            amount_bytes in any::<[u8; 32]>(),
        ) {
            let amount = u256_from_bytes(amount_bytes);
            let data = encode_credit_reward(&pubkey, amount);
            prop_assert_eq!(data.len(), 68, "calldata must be 4+32+32");
            prop_assert_eq!(&data[..4], &CREDIT_REWARD_SELECTOR, "selector");
            prop_assert_eq!(&data[4..36], &pubkey, "pubkey word");
            let mut want_amt = [0u8; 32];
            amount.to_big_endian(&mut want_amt);
            prop_assert_eq!(&data[36..68], &want_amt, "amount big-endian word");
            // Roundtrip the amount back out of the last word.
            prop_assert_eq!(U256::from_big_endian(&data[36..68]), amount, "amount roundtrip");
        }

        // ── INVARIANT 6: decode_u64_word — roundtrip low, saturate on high, error short. ──
        #[test]
        fn prop_decode_u64_word(word in any::<[u8; 32]>()) {
            let got = decode_u64_word(&word).expect("32-byte word decodes");
            let high_nonzero = word[..24].iter().any(|&b| b != 0);
            if high_nonzero {
                prop_assert_eq!(got, u64::MAX, "must saturate, never truncate");
            } else {
                let mut b8 = [0u8; 8];
                b8.copy_from_slice(&word[24..32]);
                prop_assert_eq!(got, u64::from_be_bytes(b8), "low-8 roundtrip");
            }
        }

        // decode_u64_word MUST error deterministically on short input.
        #[test]
        fn prop_decode_u64_word_short_errors(len in 0usize..32) {
            let buf = vec![0xABu8; len];
            prop_assert!(decode_u64_word(&buf).is_err(), "short input must error");
        }

        // ── INVARIANT 6: decode_address_word — roundtrip [12..32], error on short. ──
        #[test]
        fn prop_decode_address_word(word in any::<[u8; 32]>()) {
            let got = decode_address_word(&word).expect("32-byte word decodes");
            let mut want = [0u8; 20];
            want.copy_from_slice(&word[12..32]);
            prop_assert_eq!(got, want, "address is the right-aligned 20 bytes");
        }

        #[test]
        fn prop_decode_address_word_short_errors(len in 0usize..32) {
            let buf = vec![0xABu8; len];
            prop_assert!(decode_address_word(&buf).is_err(), "short input must error");
        }
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
