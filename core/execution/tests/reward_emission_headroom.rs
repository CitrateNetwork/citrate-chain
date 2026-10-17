// VALIDATOR-S1 §R' — per-epoch emission headroom (RCAP).
//
// `ValidatorRegistry.creditReward` reverts `EmissionCapped` when a credit would
// take `emittedInEpoch[epoch]` past `maxEpochEmission`, and the executor then
// burns the WHOLE block's vested share. With `maxEpochEmission == blockSubsidy *
// EPOCH` (the r1005 parameters) there is zero headroom: in any epoch with a
// priority fee, the block that crosses the cap vests nothing at all.
//
// From the RCAP activation height the executor clamps the share to the
// remaining headroom before the system-call, so the cap is still never
// exceeded but the block vests what fits and only the excess is burned.
//
// The registry here carries no code (as in `rprime_priority_fee_parity.rs`), so
// the system-call is a plain value transfer and the registry balance shows
// exactly what was credited. The cap and emitted values are written into the
// registry's storage at the contract's real slots (pinned against the contract
// by `ValidatorRegistry.t.sol::test_storage_slots_match_the_executor`).

use citrate_execution::block_rewards::{
    emitted_in_epoch_slot, EpochRewardPolicy, CANONICAL_BASE_FEE_PER_GAS, MAX_EPOCH_EMISSION_SLOT,
    REWARD_MINTER_ADDRESS,
};
use citrate_execution::types::Address;
use citrate_execution::{Executor, StateDB};
use primitive_types::U256;
use std::collections::HashMap;
use std::sync::Arc;

const COINBASE: [u8; 20] = [0x77; 20];
const REGISTRY: [u8; 20] = [0x99; 20];
const PROPOSER: [u8; 32] = [0x5A; 32];
const SUBSIDY: u64 = 10;
const CAP: u64 = 10_000;
const HEIGHT: u64 = 5_500; // epoch 5

fn word(v: u64) -> Vec<u8> {
    let mut w = [0u8; 32];
    U256::from(v).to_big_endian(&mut w);
    w.to_vec()
}

fn executor(emitted: u64) -> Arc<Executor> {
    let db = Arc::new(StateDB::new());
    let reg = Address(REGISTRY);
    db.set_storage(reg, MAX_EPOCH_EMISSION_SLOT.to_vec(), word(CAP));
    db.set_storage(reg, emitted_in_epoch_slot(HEIGHT).to_vec(), word(emitted));
    let ex = Arc::new(Executor::new(db));
    let mut staker_of = HashMap::new();
    staker_of.insert(PROPOSER, COINBASE);
    *ex.reward_policy_handle().write() = Some(EpochRewardPolicy {
        epoch: 5,
        snapshot_height: 4_800,
        activation_height: 0,
        registry: REGISTRY,
        reward_minter: REWARD_MINTER_ADDRESS,
        priority_fee_share_bps: 0,
        block_subsidy: U256::from(SUBSIDY),
        staker_of,
    });
    ex
}

async fn vested(ex: &Executor) -> U256 {
    ex.settle_block_rewards(
        HEIGHT,
        COINBASE,
        PROPOSER,
        CANONICAL_BASE_FEE_PER_GAS,
        &[],
        &[],
        &[],
    )
    .await
    .expect("settle");
    ex.get_balance(&Address(REGISTRY))
}

#[tokio::test]
async fn rcap_clamps_the_share_to_the_remaining_headroom() {
    let ex = executor(CAP - 4);
    ex.set_reward_headroom_clamp_height(0);
    assert_eq!(
        vested(&ex).await,
        U256::from(4u64),
        "only the 4 that fit vest"
    );
}

#[tokio::test]
async fn rcap_vests_nothing_when_the_epoch_is_full() {
    let ex = executor(CAP);
    ex.set_reward_headroom_clamp_height(0);
    assert_eq!(vested(&ex).await, U256::zero());
}

#[tokio::test]
async fn rcap_is_a_no_op_while_the_share_fits() {
    // The r1005 case: no fees, so the share is the 10-SALT subsidy, and an
    // epoch of 1,000 blocks reaches the cap exactly on its last block. Every
    // such credit fits, so the clamp changes no block of that history.
    for emitted in [0, CAP / 2, CAP - SUBSIDY] {
        let ex = executor(emitted);
        ex.set_reward_headroom_clamp_height(0);
        assert_eq!(vested(&ex).await, U256::from(SUBSIDY), "emitted {emitted}");
    }
}

#[tokio::test]
async fn rcap_below_activation_keeps_the_old_rule() {
    // Below the activation height the full share goes to the system-call (on
    // the real contract it would then revert and burn).
    let ex = executor(CAP - 4);
    ex.set_reward_headroom_clamp_height(HEIGHT + 1);
    assert_eq!(vested(&ex).await, U256::from(SUBSIDY));
}
