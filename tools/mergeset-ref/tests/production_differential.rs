//! S3-3c (spec 06 §8.3, I6) at the executor boundary, under the r1007
//! activations: the production `Executor::execute_mergeset` and the
//! independent reference (`State::accept_with`) execute the same ordered
//! mergesets on the same genesis, and must commit the same state root,
//! accepted root, receipt root, gas used and accepted list, chain block after
//! chain block.
//!
//! The node-level differential (`node/src/mergeset_tests.rs`) runs through
//! GHOSTDAG, admission, fork choice and RocksDB, under the activations of the
//! node's test process, where supply hardening and exact-create-code are
//! unset. This one fixes the order (a generated mergeset with generated
//! colors) and runs the r1007 rules of spec 06 §3.12. It is its own test
//! binary, so it can publish those process-wide heights: supply hardening
//! and exact-create-code at block 1, as the r1007 genesis sets them.
//!
//! Each seed is one chain of accepting blocks over a fresh genesis. Every
//! adversarial class is generated:
//! - duplicates across members, double spends and nonce gaps;
//! - balance conflicts, and gas-budget overflow (B3);
//! - reverting and out-of-gas calls, and reverting deployments;
//! - deployments that carry value (T2), and calldata calls with value to
//!   accounts without code (T1);
//! - internal value transfers and internal CREATE (T3);
//! - order-dependent storage and logs;
//! - red members, ineligible proposers, and vests into a registry with code.
//! `CITRATE_DIFF_SEEDS` sets the number of seeds (default 200); the spec's
//! nightly gate is 10,000.

use std::collections::HashMap;
use std::sync::Arc;

use citrate_consensus::acceptance::InclusionColor;
use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_economics::{RewardCalculator, RewardConfig};
use citrate_execution::acceptance::AcceptedBlock;
use citrate_execution::block_rewards::{EpochRewardPolicy, REWARD_MINTER_ADDRESS};
use citrate_execution::executor::Emission;
use citrate_execution::types::{Address, ExecutionError, TransactionReceipt};
use citrate_execution::{Executor, StateDB};
use citrate_mergeset_ref::exec::{SkipKind, State};
use citrate_mergeset_ref::ghostdag::Color;
use citrate_mergeset_ref::{EvmRules, RefConfig, RefPolicy};
use primitive_types::U256;

const CHAIN_ID: u64 = 40204;
const BASE_FEE: u64 = 1_000_000_000;
const FUND: u128 = 1_000_000_000_000_000_000_000_000;
const SMALL_FUND: u128 = 50_000_000_000_000_000; // a few transfers' worth
const TREASURY: [u8; 20] = [0x11; 20];
const REG: [u8; 20] = [0x99; 20];
/// `sstore(pubkey, sload(pubkey) + callvalue)`: records every vest.
const REG_CODE: [u8; 11] = [
    0x34, 0x60, 0x04, 0x35, 0x54, 0x01, 0x60, 0x04, 0x35, 0x55, 0x00,
];
const REVERTER: [u8; 20] = [0xEF; 20];
const REVERTER_CODE: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xFD];
const COUNTER: [u8; 20] = [0xC1; 20];
const COUNTER_CODE: [u8; 25] = [
    0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x80, 0x60, 0x00, 0x55, 0x60, 0x00, 0x52, 0x33, 0x60, 0x01,
    0x55, 0x60, 0xAA, 0x60, 0x20, 0x60, 0x00, 0xA1, 0x00,
];
const FORWARDER: [u8; 20] = [0xF1; 20];
const FORWARDER_CODE: [u8; 34] = [
    0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x34, 0x73, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x5A, 0xF1,
    0x50, 0x00,
];
const FACTORY: [u8; 20] = [0xFA; 20];
const FACTORY_CODE: [u8; 23] = [
    0x69, 0x60, 0x00, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xF3, 0x60, 0x00, 0x52, 0x60, 0x0A,
    0x60, 0x16, 0x60, 0x00, 0xF0, 0x50, 0x00,
];
const DEPLOY_INIT: [u8; 22] = [
    0x60, 0x0A, 0x60, 0x0C, 0x60, 0x00, 0x39, 0x60, 0x0A, 0x60, 0x00, 0xF3, 0x60, 0x00, 0x54, 0x60,
    0x01, 0x01, 0x60, 0x00, 0x55, 0x00,
];
const DEPLOY_INIT_REVERTS: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xFD];
const HEAVY_GAS: u64 = 29_990_000;
const SENDERS: u8 = 6;
/// Sender 5 is poor: its spends conflict on balance.
const POOR: u8 = 5;
const PROPOSERS: u8 = 4;

/// splitmix64.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn sender(i: u8) -> [u8; 20] {
    [0x50 + i; 20]
}

fn embed(a: [u8; 20]) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&a);
    PublicKey::new(b)
}

fn proposer(i: u8) -> [u8; 32] {
    [0x60 + i; 32]
}

fn coinbase(i: u8) -> [u8; 20] {
    [0x20 + i; 20]
}

fn genesis_code() -> Vec<([u8; 20], Vec<u8>)> {
    vec![
        (REG, REG_CODE.to_vec()),
        (REVERTER, REVERTER_CODE.to_vec()),
        (COUNTER, COUNTER_CODE.to_vec()),
        (FORWARDER, FORWARDER_CODE.to_vec()),
        (FACTORY, FACTORY_CODE.to_vec()),
    ]
}

fn genesis_alloc() -> Vec<([u8; 20], U256)> {
    (0..SENDERS)
        .map(|i| {
            let f = if i == POOR { SMALL_FUND } else { FUND };
            (sender(i), U256::from(f))
        })
        .collect()
}

/// §R' policy: proposer 3 is not its coinbase's staker (its shares burn).
fn staker_of() -> HashMap<[u8; 32], [u8; 20]> {
    (0..PROPOSERS)
        .map(|i| {
            let staker = if i == 3 { [0xDD; 20] } else { coinbase(i) };
            (proposer(i), staker)
        })
        .collect()
}

const SUBSIDY: u128 = 3_000_000_000_000_000;

fn reference_config() -> RefConfig {
    RefConfig {
        chain_id: CHAIN_ID,
        k: 18,
        genesis_alloc: genesis_alloc(),
        reward_policy: Some(RefPolicy {
            activation_height: 1,
            registry: REG,
            priority_fee_share_bps: 5_000,
            block_subsidy: U256::from(SUBSIDY),
            reward_minter: REWARD_MINTER_ADDRESS,
            staker_of: staker_of(),
        }),
        pba_hardening_height: None,
        supply_hardening_height: Some(1),
        storage_root_hardening_height:
            citrate_execution::storage_root_hardening::storage_root_hardening_height(),
        genesis_code: genesis_code(),
        evm: EvmRules {
            value_transfer_height: 0,
            create_nonce_fix_height: 0,
            exact_create_code_height: Some(1),
        },
    }
}

fn production() -> Executor {
    let exec = Executor::new(Arc::new(StateDB::new()));
    assert_eq!(exec.chain_id(), CHAIN_ID, "Executor::new runs chain 40204");
    for (a, b) in genesis_alloc() {
        exec.set_balance(&Address(a), b);
    }
    for (a, code) in genesis_code() {
        exec.set_code(&Address(a), code);
    }
    exec.set_validator_activation_height(1);
    *exec.reward_policy_handle().write() = Some(EpochRewardPolicy {
        epoch: 0,
        snapshot_height: 0,
        activation_height: 1,
        registry: REG,
        reward_minter: REWARD_MINTER_ADDRESS,
        priority_fee_share_bps: 5_000,
        block_subsidy: U256::from(SUBSIDY),
        staker_of: staker_of(),
    });
    exec
}

/// The chain's emission rule for an accepting block (the node's
/// `canonical_emission`: the canonical reward config, the rule selected by
/// the supply-hardening height).
fn emission(
    calc: &RewardCalculator,
    height: u64,
    txs: &[Transaction],
    receipts: &[TransactionReceipt],
) -> Result<Emission, ExecutionError> {
    let virtual_block = BlockBuilder::new()
        .height(height)
        .transactions(txs.to_vec())
        .build_unhashed();
    let r = calc
        .calculate_block_reward(
            &virtual_block,
            receipts,
            citrate_execution::supply_hardening::active_at(
                citrate_execution::supply_hardening::supply_hardening_height(),
                height,
            ),
        )
        .map_err(|e| ExecutionError::RewardSettlement(e.to_string()))?;
    Ok(Emission {
        validator: r.validator_reward,
        treasury: Address(TREASURY),
        treasury_amount: r.treasury_reward,
    })
}

#[derive(Default, Debug, Clone, Copy)]
struct Coverage {
    chain_blocks: u64,
    executed: u64,
    failed: u64,
    skipped_nonce: u64,
    skipped_balance: u64,
    skipped_gas: u64,
    reds: u64,
    t1_value_calls: u64,
    t2_value_deploys: u64,
    created: u64,
    logs: u64,
    max_members: u64,
}

struct Gen {
    rng: Rng,
    next_nonce: [u64; SENDERS as usize],
    pool: Vec<Transaction>,
    salt: u32,
}

impl Gen {
    fn tx(&mut self, from: u8) -> Transaction {
        // Nonce: usually the next one; sometimes one ahead (a gap) or one
        // behind (a double spend of an earlier nonce).
        let n = self.next_nonce[from as usize];
        let nonce = match self.rng.below(10) {
            0 => n + 1,
            1 if n > 0 => n - 1,
            _ => n,
        };
        if nonce == n {
            self.next_nonce[from as usize] += 1;
        }
        let price = BASE_FEE * (1 + self.rng.below(2));
        let (to, value, data, gas): (Option<[u8; 20]>, u128, Vec<u8>, u64) =
            match self.rng.below(12) {
                0 | 1 => (
                    Some([0x70 + from; 20]),
                    1_000 + self.rng.below(1_000) as u128,
                    vec![],
                    21_000,
                ),
                2 => (Some(COUNTER), 0, vec![0x01], 120_000),
                3 => (Some(FORWARDER), 5_000, vec![0x02], 120_000),
                4 => (Some(REVERTER), 0, vec![0x03], 60_000),
                5 => (Some(FACTORY), 0, vec![0x04], 200_000),
                6 => (
                    None,
                    self.rng.below(3) as u128 * 777,
                    DEPLOY_INIT.to_vec(),
                    200_000,
                ),
                7 => (None, 0, DEPLOY_INIT_REVERTS.to_vec(), 120_000),
                8 => (Some(COUNTER), 0, vec![0x05], 21_800),
                // T1: calldata and value to an account without code.
                9 => (Some([0x8A + from; 20]), 333, vec![0x01, 0x02], 60_000),
                10 if self.rng.below(4) == 0 => (Some(REVERTER), 0, vec![0x06], HEAVY_GAS),
                _ => {
                    let v = if from == POOR { SMALL_FUND / 2 } else { 10 };
                    (Some([0x70 + from; 20]), v, vec![], 21_000)
                }
            };
        self.salt += 1;
        let mut h = [0u8; 32];
        h[0] = 0xD1;
        h[1] = from;
        h[2..10].copy_from_slice(&nonce.to_be_bytes());
        h[10..14].copy_from_slice(&self.salt.to_be_bytes());
        h[14..22].copy_from_slice(&self.rng.next().to_be_bytes());
        let tx = Transaction {
            hash: Hash::new(h),
            nonce,
            from: embed(sender(from)),
            to: to.map(embed),
            value,
            gas_limit: gas,
            gas_price: price,
            data,
            signature: Signature::new([1; 64]),
            tx_type: None,
            chain_id: Some(CHAIN_ID),
            ecdsa_verified: true,
            ..Default::default()
        };
        self.pool.push(tx.clone());
        tx
    }

    /// A member block's own list: fresh txs, plus duplicates of earlier ones.
    fn list(&mut self) -> Vec<Transaction> {
        let mut out = Vec::new();
        for _ in 0..(1 + self.rng.below(6)) {
            if !self.pool.is_empty() && self.rng.below(5) == 0 {
                let i = self.rng.below(self.pool.len() as u64) as usize;
                let dup = self.pool[i].clone();
                if !out.iter().any(|t: &Transaction| t.hash == dup.hash) {
                    out.push(dup);
                }
                continue;
            }
            let from = self.rng.below(SENDERS as u64) as u8;
            out.push(self.tx(from));
        }
        out
    }
}

fn member_block(height: u64, tag: u64, p: u8, txs: Vec<Transaction>) -> Block {
    let mut h = [0u8; 32];
    h[0] = 0xB0;
    h[1..9].copy_from_slice(&height.to_be_bytes());
    h[9..17].copy_from_slice(&tag.to_be_bytes());
    BlockBuilder::new()
        .hash(Hash::new(h))
        .height(height)
        .coinbase(coinbase(p))
        .proposer(PublicKey::new(proposer(p)))
        .transactions(txs)
        .build_unhashed()
}

/// One seed: a chain of accepting blocks. Returns the coverage, or the first
/// divergence.
async fn run_seed(seed: u64, calc: &RewardCalculator) -> Result<Coverage, String> {
    let cfg = reference_config();
    let exec = production();
    let mut reference = State::genesis_of(&cfg);
    let mut gen = Gen {
        rng: Rng(seed),
        next_nonce: [0; SENDERS as usize],
        pool: Vec::new(),
        salt: 0,
    };
    let mut cov = Coverage::default();
    let mut ancestors: Vec<(u64, Hash)> = vec![(0, Hash::new([0xEE; 32]))];
    let em = |h: u64, t: &[Transaction], r: &[TransactionReceipt]| emission(calc, h, t, r);
    let chain_len = 2 + gen.rng.below(4);
    for height in 1..=chain_len {
        // Mergeset(C): SP first, then up to 7 more members (deep ones too).
        let extra = gen.rng.below(8);
        let mut members: Vec<(Block, InclusionColor)> = Vec::new();
        for m in 0..=extra {
            let p = gen.rng.below(PROPOSERS as u64) as u8;
            let list = gen.list();
            let b = member_block(height - 1, seed.wrapping_mul(1000) + m, p, list);
            let color = if m == 0 {
                InclusionColor::SelectedParent
            } else if gen.rng.below(3) == 0 {
                InclusionColor::Red
            } else {
                InclusionColor::Blue
            };
            members.push((b, color));
        }
        let p = gen.rng.below(PROPOSERS as u64) as u8;
        let mut vrf = [0u8; 32];
        vrf[..8].copy_from_slice(&gen.rng.next().to_be_bytes());
        let mut c = BlockBuilder::new()
            .height(height)
            .timestamp(1_700_000_000 + height)
            .coinbase(coinbase(p))
            .proposer(PublicKey::new(proposer(p)))
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new(vrf),
            })
            .build_unhashed();
        c.header.base_fee_per_gas = BASE_FEE;
        let mut ch = [0u8; 32];
        ch[0] = 0xCC;
        ch[1..9].copy_from_slice(&seed.to_be_bytes());
        ch[9..17].copy_from_slice(&height.to_be_bytes());
        c.header.block_hash = Hash::new(ch);
        let window: HashMap<u64, [u8; 32]> = ancestors
            .iter()
            .filter(|(h, _)| *h < height && *h + 256 >= height)
            .map(|(h, hh)| (*h, *hh.as_bytes()))
            .collect();
        ancestors.push((height, c.header.block_hash));

        let prod_members: Vec<AcceptedBlock<'_>> = members
            .iter()
            .map(|(b, color)| AcceptedBlock {
                block: b,
                color: *color,
            })
            .collect();
        let prod = exec
            .execute_mergeset(&c.header, &prod_members, &em, window.clone())
            .await
            .map_err(|e| format!("seed {seed} height {height}: production error: {e}"))?;
        let ref_members: Vec<(&Block, Color)> = members
            .iter()
            .map(|(b, color)| {
                let col = match color {
                    InclusionColor::SelectedParent => Color::SelectedParent,
                    InclusionColor::Blue => Color::Blue,
                    InclusionColor::Red => Color::Red,
                };
                (b, col)
            })
            .collect();
        let acc = reference
            .accept_with(&cfg, &c, &ref_members, &window)
            .map_err(|u| {
                format!(
                    "seed {seed} height {height}: reference unsupported: {}",
                    u.0
                )
            })?;

        let prod_list: Vec<(Hash, Hash, bool)> = prod
            .receipts
            .iter()
            .map(|r| {
                let incl = r
                    .acceptance
                    .as_ref()
                    .map(|a| a.including_block_hash)
                    .unwrap_or_default();
                (r.tx_hash, incl, r.status)
            })
            .collect();
        let ref_list: Vec<(Hash, Hash, bool)> = acc
            .receipts
            .iter()
            .map(|r| (r.tx_hash, r.including_block, r.status))
            .collect();
        let checks = [
            (
                "accepted list",
                format!("{prod_list:?}"),
                format!("{ref_list:?}"),
            ),
            (
                "gas used",
                prod.gas_used.to_string(),
                acc.gas_used.to_string(),
            ),
            (
                "receipt root",
                format!("{:?}", prod.receipt_root),
                format!("{:?}", acc.receipt_root),
            ),
            (
                "accepted root",
                format!("{:?}", prod.accepted_root),
                format!("{:?}", acc.accepted_root),
            ),
            (
                "state root",
                format!("{:?}", prod.state_root),
                format!("{:?}", acc.state_root),
            ),
        ];
        for (field, p, r) in checks {
            if p != r {
                return Err(format!(
                    "seed {seed} height {height}: {field} differs\n  production {p}\n  reference  {r}"
                ));
            }
        }

        cov.chain_blocks += 1;
        cov.executed += acc.receipts.len() as u64;
        cov.failed += acc.receipts.iter().filter(|r| !r.status).count() as u64;
        cov.created += acc.created;
        cov.logs += acc
            .receipts
            .iter()
            .map(|r| r.logs.len() as u64)
            .sum::<u64>();
        cov.max_members = cov.max_members.max(members.len() as u64);
        cov.reds += members
            .iter()
            .filter(|(_, c)| *c == InclusionColor::Red)
            .count() as u64;
        for (_, _, k) in &acc.skipped {
            match k {
                SkipKind::Nonce => cov.skipped_nonce += 1,
                SkipKind::Balance => cov.skipped_balance += 1,
                SkipKind::Gas => cov.skipped_gas += 1,
                _ => {}
            }
        }
        let by_hash: HashMap<Hash, &Transaction> =
            prod.executed.iter().map(|t| (t.hash, t)).collect();
        for r in acc.receipts.iter().filter(|r| r.status) {
            let t = by_hash[&r.tx_hash];
            if t.to.is_none() && t.value > 0 {
                cov.t2_value_deploys += 1;
            }
            if t.value > 0
                && !t.data.is_empty()
                && t.to
                    .is_some_and(|k| k.as_bytes()[0] >= 0x8A && k.as_bytes()[0] < 0x8A + SENDERS)
            {
                cov.t1_value_calls += 1;
            }
        }
    }
    Ok(cov)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_executor_matches_the_reference_under_r1007_rules() {
    citrate_execution::supply_hardening::set_supply_hardening_height(Some(1));
    citrate_execution::exact_code::set_exact_create_code_height(Some(1));
    let seeds: u64 = std::env::var("CITRATE_DIFF_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let calc = Arc::new(RewardCalculator::new(RewardConfig {
        block_reward: 10,
        halving_interval: 2_100_000,
        inference_bonus: 1,
        model_deployment_bonus: 1,
        treasury_percentage: 10,
        treasury_address: Address(TREASURY),
    }));
    // Seeds in parallel (each one is its own executor and reference).
    let workers = 8u64;
    let mut handles = Vec::new();
    for w in 0..workers {
        let calc = calc.clone();
        handles.push(tokio::spawn(async move {
            let mut total = Coverage::default();
            let mut seed = 1 + w;
            while seed <= seeds {
                let c = run_seed(seed, &calc).await?;
                total.chain_blocks += c.chain_blocks;
                total.executed += c.executed;
                total.failed += c.failed;
                total.skipped_nonce += c.skipped_nonce;
                total.skipped_balance += c.skipped_balance;
                total.skipped_gas += c.skipped_gas;
                total.reds += c.reds;
                total.t1_value_calls += c.t1_value_calls;
                total.t2_value_deploys += c.t2_value_deploys;
                total.created += c.created;
                total.logs += c.logs;
                total.max_members = total.max_members.max(c.max_members);
                seed += workers;
            }
            Ok::<Coverage, String>(total)
        }));
    }
    let mut total = Coverage::default();
    for h in handles {
        let c = h.await.expect("worker").unwrap_or_else(|e| panic!("{e}"));
        total.chain_blocks += c.chain_blocks;
        total.executed += c.executed;
        total.failed += c.failed;
        total.skipped_nonce += c.skipped_nonce;
        total.skipped_balance += c.skipped_balance;
        total.skipped_gas += c.skipped_gas;
        total.reds += c.reds;
        total.t1_value_calls += c.t1_value_calls;
        total.t2_value_deploys += c.t2_value_deploys;
        total.created += c.created;
        total.logs += c.logs;
        total.max_members = total.max_members.max(c.max_members);
    }
    println!("r1007 executor differential: {seeds} seeds, {total:?}");
    assert!(total.failed > 0, "{total:?}");
    assert!(total.skipped_nonce > 0, "{total:?}");
    assert!(total.skipped_balance > 0, "{total:?}");
    assert!(total.skipped_gas > 0, "{total:?}");
    assert!(total.reds > 0, "{total:?}");
    assert!(
        total.t1_value_calls > 0,
        "no T1 call moved value: {total:?}"
    );
    assert!(
        total.t2_value_deploys > 0,
        "no T2 deployment carried value: {total:?}"
    );
    assert!(total.created > 0 && total.logs > 0, "{total:?}");
}
