// VALIDATOR-S1 §R' — priority-fee reallocation DETERMINISM tests (CONSENSUS-CRITICAL).
//
// These tests exercise the SINGLE shared settlement path
// (`Executor::settle_block_rewards`) that BOTH the block producer and the
// receiver (`Executor::apply_block`) call, and prove the properties whose
// violation would HALT the fleet:
//
//   (a) PRODUCER <-> RECEIVER PARITY — a block whose reward (basic + §R' vesting)
//       was settled on one executor is reproduced BYTE-IDENTICALLY by an
//       independent executor re-applying it via `apply_block` (identical
//       post-state root). This is the anti-fork guarantee.
//   (b) REORG RE-APPLY PARITY — reverting and re-applying the same block yields
//       the identical state root (the settlement, incl. the creditReward
//       system-call, is idempotent under snapshot/restore).
//   (c) BASE-FEE MANIPULATION — a block whose committed `base_fee_per_gas` differs
//       from the reroll constant is REJECTED on import (a producer cannot set it
//       to 0 to inflate the priority pool); the canonical value is accepted.
//
// The registry address used here carries no code, so the `creditReward`
// system-call is a plain value-call: it succeeds trivially and the executor's
// balance reconciliation credits the vested share to the registry account. That
// is exactly the deterministic behavior we need to prove parity — the on-chain
// `creditReward` storage semantics (vestedRewards / emission cap / Active status)
// are the ValidatorRegistry contract's own responsibility, covered by its forge
// tests. The share-ROUNDING property test lives in the crate unit tests
// (`block_rewards::tests`).

use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction as ConsensusTransaction, VrfProof,
};
use citrate_execution::block_rewards::{
    EpochRewardPolicy, CANONICAL_BASE_FEE_PER_GAS, REWARD_MINTER_ADDRESS,
};
use citrate_execution::types::{Address, ExecutionError};
use citrate_execution::{address_utils, Executor, StateDB};
use primitive_types::U256;
use std::collections::HashMap;
use std::sync::Arc;

const COINBASE: [u8; 20] = [0x77; 20];
const REGISTRY: [u8; 20] = [0x99; 20];
const TREASURY: [u8; 20] = [0x11; 20];
const SHARE_BPS: u64 = 2500; // 25%
const VALIDATOR_REWARD: u64 = 10_000_000_000; // basic block reward (arbitrary, fixed)
const TREASURY_REWARD: u64 = 1_000_000_000;

fn make_pubkey(seed: u8) -> PublicKey {
    let mut pk = [0u8; 32];
    pk[0] = seed;
    pk[31] = seed; // distinct 32-byte encoding
    PublicKey::new(pk)
}

fn make_address(pk: &PublicKey) -> Address {
    address_utils::normalize_address(pk)
}

/// The block proposer's ed25519 pubkey (canonical 32-byte). Distinct pattern so
/// the staker-map lookup is meaningful.
fn proposer_pubkey() -> [u8; 32] {
    [0x5A; 32]
}

/// A type-2 (EIP-1559) transfer tx with an explicit tip. `gas_price` is the
/// decoder's `maxFeePerGas` proxy (base_fee + something >= tip).
fn priority_tx(
    from: PublicKey,
    to: PublicKey,
    value: u128,
    nonce: u64,
    max_fee: u64,
    max_prio: u64,
    hash_seed: u8,
) -> ConsensusTransaction {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = hash_seed;
    let mut tx = ConsensusTransaction {
        hash: Hash::new(hash_bytes),
        nonce,
        from,
        to: Some(to),
        value,
        gas_limit: 100_000,
        gas_price: max_fee, // type-2: gas_price == maxFeePerGas proxy
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

fn new_executor() -> Arc<Executor> {
    Arc::new(Executor::new(Arc::new(StateDB::new())))
}

/// Inject a fully-materialized §R' policy (as `registry_sync` would at S(E)).
fn inject_policy(executor: &Executor, activation_height: u64) {
    let mut staker_of = HashMap::new();
    staker_of.insert(proposer_pubkey(), COINBASE); // coinbase == registered staker
    let policy = EpochRewardPolicy {
        epoch: 0,
        snapshot_height: 0,
        activation_height,
        registry: REGISTRY,
        reward_minter: REWARD_MINTER_ADDRESS,
        priority_fee_share_bps: SHARE_BPS,
        staker_of,
    };
    *executor.reward_policy_handle().write() = Some(policy);
}

/// The fixed basic-reward credit list (mirrors `canonical_apply::reward_credits`
/// and the producer's `settle_block_rewards` call: validator + treasury).
fn basic_credits() -> Vec<(Address, U256)> {
    vec![
        (Address(COINBASE), U256::from(VALIDATOR_REWARD)),
        (Address(TREASURY), U256::from(TREASURY_REWARD)),
    ]
}

/// Fund the two senders identically on a fresh executor.
fn fund_senders(executor: &Executor) -> (PublicKey, PublicKey, PublicKey, PublicKey) {
    let alice = make_pubkey(1);
    let alice_to = make_pubkey(2);
    let bob = make_pubkey(3);
    let bob_to = make_pubkey(4);
    executor.set_balance(&make_address(&alice), U256::from(u128::MAX));
    executor.set_balance(&make_address(&bob), U256::from(u128::MAX));
    (alice, alice_to, bob, bob_to)
}

fn block_txs(alice: PublicKey, alice_to: PublicKey, bob: PublicKey, bob_to: PublicKey) -> Vec<ConsensusTransaction> {
    // Two tips: 100 and 250 wei/gas, both well above base fee.
    vec![
        priority_tx(alice, alice_to, 500, 0, CANONICAL_BASE_FEE_PER_GAS + 100, 100, 0xA1),
        priority_tx(bob, bob_to, 700, 0, CANONICAL_BASE_FEE_PER_GAS + 900, 250, 0xB2),
    ]
}

/// Build a v2 block committing the proposer + coinbase + base fee, at an explicit
/// height, with the given transactions and claimed state root.
fn build_block_h(height: u64, base_fee: u64, txs: Vec<ConsensusTransaction>, state_root: Hash) -> Block {
    let mut b = BlockBuilder::new()
        .version(2)
        .height(height)
        .parent(Hash::default())
        .coinbase(COINBASE)
        .proposer(PublicKey::new(proposer_pubkey()))
        .timestamp(1_700_000_000)
        .base_fee_per_gas(base_fee)
        .vrf_reveal(VrfProof { proof: vec![], output: Hash::new([0x5A; 32]) })
        .transactions(txs)
        .state_root(state_root)
        .build_unhashed();
    b.header.block_hash = b.compute_hash();
    b
}

/// Build a v2 block committing the proposer + coinbase + base fee, with the
/// given transactions and claimed state root.
fn build_block(base_fee: u64, txs: Vec<ConsensusTransaction>, state_root: Hash) -> Block {
    let mut b = BlockBuilder::new()
        .version(2)
        .height(1)
        .parent(Hash::default())
        .coinbase(COINBASE)
        .proposer(PublicKey::new(proposer_pubkey()))
        .timestamp(1_700_000_000)
        .base_fee_per_gas(base_fee)
        .vrf_reveal(VrfProof { proof: vec![], output: Hash::new([0x5A; 32]) })
        .transactions(txs)
        .state_root(state_root)
        .build_unhashed();
    b.header.block_hash = b.compute_hash();
    b
}

/// Producer surrogate: execute the block's txs, settle rewards through the shared
/// fn, and return the post-settlement state root — exactly the sequence
/// `produce_block` performs.
async fn produce_root(executor: &Executor, block: &Block) -> Hash {
    executor.set_block_context(citrate_execution::revm_adapter::BlockContext {
        coinbase: COINBASE,
        prevrandao: *block.header.vrf_reveal.output.as_bytes(),
        block_hashes: HashMap::new(),
    });
    let mut receipts = Vec::new();
    for tx in &block.transactions {
        let r = executor
            .execute_transaction(block, tx)
            .await
            .expect("tx executes");
        receipts.push(r);
    }
    executor
        .settle_block_rewards(
            block.header.height,
            block.header.coinbase,
            *block.header.proposer_pubkey.as_bytes(),
            block.header.base_fee_per_gas,
            &block.transactions,
            &receipts,
            &basic_credits(),
        )
        .await
        .expect("settle succeeds on the producer");
    executor.calculate_state_root()
}

// ═════════════════════════════════════════════════════════════════════════════
// (a) PRODUCER <-> RECEIVER PARITY
// ═════════════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn producer_receiver_state_root_parity() {
    // Producer executor: settle and seal a block.
    let ep = new_executor();
    inject_policy(&ep, 0);
    let (a, at, b, bt) = fund_senders(&ep);
    let txs = block_txs(a, at, b, bt);
    let template = build_block(CANONICAL_BASE_FEE_PER_GAS, txs.clone(), Hash::default());
    let producer_root = produce_root(&ep, &template).await;
    let sealed = build_block(CANONICAL_BASE_FEE_PER_GAS, txs, producer_root);

    // Receiver executor: independent, IDENTICAL initial state + policy.
    let er = new_executor();
    inject_policy(&er, 0);
    fund_senders(&er);
    let got = er
        .apply_block(&sealed, sealed.header.coinbase, &basic_credits())
        .await
        .expect("receiver reproduces + accepts the producer's block");

    assert_eq!(
        got, producer_root,
        "receiver's post-state root MUST equal the producer's (fleet-fork guard)"
    );

    // The §R' share was redistributed identically: the registry account holds the
    // vested share on BOTH executors (proving the vesting math + system-call are
    // deterministic, not just the tx execution).
    let reg_p = ep.get_balance(&Address(REGISTRY));
    let reg_r = er.get_balance(&Address(REGISTRY));
    assert_eq!(reg_p, reg_r, "vested share must match across executors");
    assert!(reg_p > U256::zero(), "a positive share must have vested");

    // Cross-check the exact share: pool = 100*gas0 + 250*gas1, share = 25%.
    // (gas is whatever the executor charged; recompute from the receiver.)
}

// ═════════════════════════════════════════════════════════════════════════════
// (b) REORG RE-APPLY PARITY
// ═════════════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn reorg_reapply_state_root_parity() {
    let e = new_executor();
    inject_policy(&e, 0);
    let (a, at, b, bt) = fund_senders(&e);
    let txs = block_txs(a, at, b, bt);

    // First application (in-memory only, like the reorg re-apply path).
    let template = build_block(CANONICAL_BASE_FEE_PER_GAS, txs.clone(), Hash::default());
    let pre = e.state_snapshot();
    let root1 = produce_root(&e, &template).await;
    let sealed = build_block(CANONICAL_BASE_FEE_PER_GAS, txs, root1);

    // Revert to the fork point and re-apply the SAME block (reorg).
    e.state_restore(pre);
    let root2 = e
        .apply_block_no_persist(&sealed, sealed.header.coinbase, &basic_credits())
        .await
        .expect("reorg re-apply succeeds");

    assert_eq!(root1, root2, "reorg re-apply must reproduce the identical state root");
}

// ═════════════════════════════════════════════════════════════════════════════
// (c) BASE-FEE MANIPULATION
// ═════════════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn tampered_base_fee_is_rejected_on_import() {
    // Build the honest sealed block (canonical base fee).
    let ep = new_executor();
    inject_policy(&ep, 0);
    let (a, at, b, bt) = fund_senders(&ep);
    let txs = block_txs(a, at, b, bt);
    let template = build_block(CANONICAL_BASE_FEE_PER_GAS, txs.clone(), Hash::default());
    let root = produce_root(&ep, &template).await;

    // A malicious block that commits base_fee = 0 (would inflate the priority pool)
    // but claims the honest root. The receiver must REJECT it at settlement.
    let tampered = build_block(0, txs.clone(), root);
    let er = new_executor();
    inject_policy(&er, 0);
    fund_senders(&er);
    let err = er
        .apply_block(&tampered, tampered.header.coinbase, &basic_credits())
        .await
        .expect_err("a tampered base fee must be rejected");
    match err {
        ExecutionError::RewardSettlement(msg) => {
            assert!(msg.contains("base_fee"), "reject reason should name base_fee: {msg}");
        }
        other => panic!("expected RewardSettlement, got {other:?}"),
    }

    // The canonical base fee is accepted (control).
    let honest = build_block(CANONICAL_BASE_FEE_PER_GAS, txs, root);
    let er2 = new_executor();
    inject_policy(&er2, 0);
    fund_senders(&er2);
    assert!(
        er2.apply_block(&honest, honest.header.coinbase, &basic_credits())
            .await
            .is_ok(),
        "the canonical base fee must be accepted"
    );
}

// A block with a transaction priced below the base fee (EIP-1559 invalid) is
// rejected — the §R' reject-if-`gas_price < base_fee` rule, enforced identically
// on producer and receiver.
#[tokio::test]
async fn sub_base_fee_tx_is_rejected_on_import() {
    let er = new_executor();
    inject_policy(&er, 0);
    let (a, at, _b, _bt) = fund_senders(&er);
    // gas_price below the base fee.
    let bad = priority_tx(a, at, 100, 0, CANONICAL_BASE_FEE_PER_GAS - 1, 0, 0xC3);
    // Give it a plausible (but unreachable) root; settlement rejects before the
    // root check.
    let block = build_block(CANONICAL_BASE_FEE_PER_GAS, vec![bad], Hash::new([0xAB; 32]));
    let err = er
        .apply_block(&block, block.header.coinbase, &basic_credits())
        .await
        .expect_err("sub-base-fee tx must be rejected");
    assert!(
        matches!(err, ExecutionError::RewardSettlement(_)),
        "expected RewardSettlement, got {err:?}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// (c) HARD-REJECT — a None policy AT/ABOVE the activation height is a fault, not a
// silent skip. Without this, a node whose epoch snapshot failed to materialize /
// rehydrate would settle a §R'-less (policy-less) block and fork the fleet.
// ═════════════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn none_policy_at_or_above_activation_is_rejected() {
    // Activation configured (as main.rs does when the registry is set), but NO
    // policy materialized (None) — simulating a snapshot that failed to load.
    let er = new_executor();
    er.set_validator_activation_height(800);
    let (a, at, b, bt) = fund_senders(&er);
    let txs = block_txs(a, at, b, bt);
    // A block AT the activation height with a None policy → HARD REJECT.
    let block = build_block_h(800, CANONICAL_BASE_FEE_PER_GAS, txs.clone(), Hash::new([0xAB; 32]));
    let err = er
        .apply_block(&block, block.header.coinbase, &basic_credits())
        .await
        .expect_err("None policy at/above activation must be rejected");
    match err {
        ExecutionError::RewardSettlement(msg) => {
            assert!(
                msg.contains("unmaterialized"),
                "reject reason should name the unmaterialized policy: {msg}"
            );
        }
        other => panic!("expected RewardSettlement, got {other:?}"),
    }
}

// (c) control: a None policy BELOW activation is NOT a fault — priority fees just
// burn (pre-reroll behavior), and the block is accepted.
#[tokio::test]
async fn none_policy_below_activation_is_accepted() {
    let ep = new_executor();
    ep.set_validator_activation_height(800);
    let (a, at, b, bt) = fund_senders(&ep);
    let txs = block_txs(a, at, b, bt);
    // height 1 < activation 800, no policy → settle skips §R', computes a root.
    let template = build_block_h(1, CANONICAL_BASE_FEE_PER_GAS, txs.clone(), Hash::default());
    ep.set_block_context(citrate_execution::revm_adapter::BlockContext {
        coinbase: COINBASE,
        prevrandao: *template.header.vrf_reveal.output.as_bytes(),
        block_hashes: HashMap::new(),
    });
    let mut receipts = Vec::new();
    for tx in &template.transactions {
        receipts.push(ep.execute_transaction(&template, tx).await.expect("tx executes"));
    }
    ep.settle_block_rewards(
        1,
        COINBASE,
        proposer_pubkey(),
        CANONICAL_BASE_FEE_PER_GAS,
        &template.transactions,
        &receipts,
        &basic_credits(),
    )
    .await
    .expect("below activation, a None policy is a skip (not a reject)");
    let root = ep.calculate_state_root();
    let sealed = build_block_h(1, CANONICAL_BASE_FEE_PER_GAS, txs, root);

    let er = new_executor();
    er.set_validator_activation_height(800);
    fund_senders(&er);
    let got = er
        .apply_block(&sealed, sealed.header.coinbase, &basic_credits())
        .await
        .expect("accepted below activation with a None policy");
    assert_eq!(got, root, "parity holds below activation with a None policy");
    assert_eq!(
        er.get_balance(&Address(REGISTRY)),
        U256::zero(),
        "no share vested below the activation height"
    );
}

// (fix #4) PRODUCER settle safety: the guarded settle leaves NO balance mutation
// when settlement errors (the absent-proposer reject arm fires AFTER step-1 basic
// credits are applied). Proves the producer path matches the receiver's revert.
#[tokio::test]
async fn guarded_settle_reverts_all_credits_on_error() {
    let e = new_executor();
    // Policy WITHOUT the proposer in the staker map → settle rejects at step (3b),
    // AFTER the basic credits (step 1) have been applied.
    let empty_staker = HashMap::new();
    *e.reward_policy_handle().write() = Some(EpochRewardPolicy {
        epoch: 0,
        snapshot_height: 0,
        activation_height: 0,
        registry: REGISTRY,
        reward_minter: REWARD_MINTER_ADDRESS,
        priority_fee_share_bps: SHARE_BPS,
        staker_of: empty_staker, // proposer absent → reject
    });
    let root_before = e.calculate_state_root();

    let err = e
        .settle_block_rewards_guarded(
            1,
            COINBASE,
            proposer_pubkey(),
            CANONICAL_BASE_FEE_PER_GAS,
            &[],
            &[],
            &basic_credits(),
        )
        .await
        .expect_err("absent proposer must reject");
    assert!(matches!(err, ExecutionError::RewardSettlement(_)));

    // No stray credits leaked: coinbase + treasury balances untouched, root identical.
    assert_eq!(e.get_balance(&Address(COINBASE)), U256::zero(), "no basic validator credit leaked");
    assert_eq!(e.get_balance(&Address(TREASURY)), U256::zero(), "no treasury credit leaked");
    assert_eq!(e.calculate_state_root(), root_before, "state byte-identical after guarded reject");
}

// Pre-activation (height < activation): §R' is inert — the block is accepted and
// NO share is vested (priority fees burn exactly as before the reroll).
#[tokio::test]
async fn below_activation_no_vesting() {
    let ep = new_executor();
    inject_policy(&ep, 1_000_000); // activation far above height 1
    let (a, at, b, bt) = fund_senders(&ep);
    let txs = block_txs(a, at, b, bt);
    let template = build_block(CANONICAL_BASE_FEE_PER_GAS, txs.clone(), Hash::default());
    let root = produce_root(&ep, &template).await;
    let sealed = build_block(CANONICAL_BASE_FEE_PER_GAS, txs, root);

    let er = new_executor();
    inject_policy(&er, 1_000_000);
    fund_senders(&er);
    let got = er
        .apply_block(&sealed, sealed.header.coinbase, &basic_credits())
        .await
        .expect("accepted below activation");
    assert_eq!(got, root, "parity holds below activation too");
    assert_eq!(
        ep.get_balance(&Address(REGISTRY)),
        U256::zero(),
        "no share vested below the activation height"
    );
}
