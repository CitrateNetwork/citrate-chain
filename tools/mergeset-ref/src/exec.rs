//! The reference state transition (spec 06 §3.4-§3.9), written from the spec,
//! not from `citrate_execution::executor`.
//!
//! COVERAGE (what the reference executes):
//!   * value transfers (empty calldata, `to` set): 21,000 gas, the self-
//!     transfer no-op, a value above the balance after the fee fails the tx;
//!   * the outcome classes: B1 nonce, B2 balance, B3 ACCEPT gas budget, B4
//!     sender has code, stateless skips (chain id / signature via the trusted
//!     `tx_auth`, gas price below the base fee); C (failed: full gas_limit
//!     charged, nonce bumped, no other effect) and D (ok);
//!   * fees: the sender pays `gas_used * gas_price`; the base fee burns;
//!   * settlement: R(h) (base subsidy with halving, the executed-basis bonus
//!     for deployments), split among the blue members with a proposer per
//!     O3, the treasury part, the §R' eligibility rule (coinbase must be the
//!     proposer's staker in the policy, otherwise the share burns), and §R'
//!     vesting as a plain value transfer minter -> registry;
//!   * the commitments: state root (through the trusted trie hash),
//!     accepted_root, receipt_root v3, gas_used.
//!
//! NOT COVERED (the reference refuses with [`Unsupported`] instead of
//! guessing): any transaction with calldata (contract calls, deployments and
//! AI operations need the EVM, which the reference does not embed), §R'
//! vesting into a registry that has code, and genesis state other than
//! balances.

use std::collections::BTreeMap;

use citrate_consensus::types::{Block, Hash, Transaction};
use primitive_types::U256;
use sha3::{Digest, Keccak256, Sha3_256};

use crate::ghostdag::Color;
use crate::{RefConfig, RefPolicy};

/// Gas of a plain value transfer.
pub const TRANSFER_GAS: u64 = 21_000;
/// O5: the per-accepting-block gas budget (spec 06 §3.6).
pub const ACCEPT_GAS_LIMIT: u64 = 60_000_000;
/// The treasury address and share of R(h) (the chain's reward rule).
pub const TREASURY: [u8; 20] = [0x11; 20];
pub const TREASURY_PERCENT: u64 = 10;
/// 10 SALT per chain block, halving every 2,100,000 heights; 1 SALT for a
/// deployment (executed basis).
pub const BLOCK_REWARD_SALT: u64 = 10;
pub const HALVING_INTERVAL: u64 = 2_100_000;
pub const MODEL_DEPLOYMENT_BONUS_SALT: u64 = 1;
/// The §R' base fee constant.
pub const CANONICAL_BASE_FEE: u64 = 1_000_000_000;

/// A transaction the reference cannot execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported(pub String);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    pub balance: U256,
    pub nonce: u64,
    pub has_code: bool,
}

/// One executed transaction's receipt as the reference computes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefReceipt {
    pub tx_hash: Hash,
    pub including_block: Hash,
    pub status: bool,
    pub gas_used: u64,
    /// (address, topics, data) of each log, in emission order.
    pub logs: Vec<RefLog>,
}

/// One log as the reference commits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// What one chain block's acceptance produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub receipts: Vec<RefReceipt>,
    /// Skipped occurrences: (tx hash, including block, why).
    pub skipped: Vec<(Hash, Hash, SkipKind)>,
    /// Contracts created.
    pub created: u64,
    pub gas_used: u64,
    pub accepted_root: Hash,
    pub receipt_root: Hash,
    pub state_root: Hash,
}

/// Why an occurrence was skipped (spec 06 §3.4 class B, plus the stateless
/// leftovers). Not consensus: only "skipped" is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipKind {
    /// B1: the nonce is not the sender's state nonce (a duplicate, a double
    /// spend's loser, or a gap).
    Nonce,
    /// B2: balance below gas_limit * gas_price + value.
    Balance,
    /// B3: gas_limit above what is left of ACCEPT_GAS_LIMIT.
    Gas,
    /// B4: the sender has code (EIP-3607).
    Code,
    /// Signature / chain id, a gas price below the base fee, or a shape no
    /// transaction type decodes.
    Invalid,
}

/// The reference world state.
pub struct State {
    pub accounts: BTreeMap<[u8; 20], Account>,
}

/// The address a transaction's sender or recipient key denotes: an embedded
/// 20-byte EVM address (key bytes 20.. zero), otherwise the last 20 bytes of
/// keccak256(key).
pub fn address_of(key: &[u8; 32]) -> [u8; 20] {
    let mut out = [0u8; 20];
    if key[20..].iter().all(|b| *b == 0) && !key[..20].iter().all(|b| *b == 0) {
        out.copy_from_slice(&key[..20]);
    } else {
        let h: [u8; 32] = Keccak256::digest(key).into();
        out.copy_from_slice(&h[12..]);
    }
    out
}

fn wei(salt: u64) -> U256 {
    U256::from(salt) * U256::exp10(18)
}

impl State {
    pub fn genesis(alloc: &[([u8; 20], U256)]) -> Self {
        let mut accounts = BTreeMap::new();
        for (a, b) in alloc {
            accounts.insert(
                *a,
                Account {
                    balance: *b,
                    ..Account::default()
                },
            );
        }
        Self { accounts }
    }

    fn acct(&mut self, a: [u8; 20]) -> &mut Account {
        self.accounts.entry(a).or_default()
    }

    fn credit(&mut self, a: [u8; 20], v: U256) {
        if v.is_zero() {
            return;
        }
        let acct = self.acct(a);
        acct.balance = acct.balance.saturating_add(v);
    }

    /// The state root through the trusted trie hash (`StateDB`), with the
    /// storage-root rule for `height`.
    pub fn root(&self, storage_root_activation: Option<u64>, height: u64) -> Hash {
        let db = citrate_execution::StateDB::new();
        for (a, acct) in &self.accounts {
            if acct.balance.is_zero() && acct.nonce == 0 {
                continue;
            }
            let addr = citrate_execution::types::Address(*a);
            db.accounts.set_balance(addr, acct.balance);
            db.accounts.set_nonce(addr, acct.nonce);
        }
        db.calculate_state_root_with(storage_root_activation, height)
    }

    /// Execute `members` (Mergeset(C) in consensus order) for chain block
    /// `c` and settle it.
    pub fn accept(
        &mut self,
        cfg: &RefConfig,
        c: &Block,
        members: &[(&Block, Color)],
    ) -> Result<Accepted, Unsupported> {
        let height = c.header.height;
        let base_fee = c.header.base_fee_per_gas;
        let pba = match cfg.pba_hardening_height {
            Some(h) => citrate_consensus::hardening::PbaHardening::at(h),
            None => citrate_consensus::hardening::PbaHardening::off(),
        };
        let mut receipts: Vec<RefReceipt> = Vec::new();
        let mut executed: Vec<&Transaction> = Vec::new();
        let mut skipped = Vec::new();
        let mut cumulative: u64 = 0;
        for (block, _) in members {
            for tx in &block.transactions {
                if !tx.data.is_empty() {
                    return Err(Unsupported(format!(
                        "tx {} in {} carries calldata (contract call, deployment or AI \
                         operation); the reference executes value transfers only",
                        tx.hash, block.header.block_hash
                    )));
                }
                let from = address_of(tx.from.as_bytes());
                let acct = self.accounts.get(&from).cloned().unwrap_or_default();
                let need =
                    U256::from(tx.gas_limit) * U256::from(tx.gas_price) + U256::from(tx.value);
                // Spec 06 §3.4, in the order the checks apply: stateless
                // leftovers, B3 budget, B4 code, B1 nonce, B2 balance, then an
                // undecodable shape (empty calldata and no recipient).
                let skip = if (pba.active_at(height)
                    && citrate_consensus::tx_auth::verify_for_block(tx, cfg.chain_id).is_err())
                    || tx.gas_price < base_fee
                {
                    Some(SkipKind::Invalid)
                } else if tx.gas_limit > ACCEPT_GAS_LIMIT.saturating_sub(cumulative) {
                    Some(SkipKind::Gas)
                } else if acct.has_code {
                    Some(SkipKind::Code)
                } else if tx.nonce != acct.nonce {
                    Some(SkipKind::Nonce)
                } else if acct.balance < need {
                    Some(SkipKind::Balance)
                } else if tx.to.is_none() {
                    Some(SkipKind::Invalid)
                } else {
                    None
                };
                if let Some(kind) = skip {
                    skipped.push((tx.hash, block.header.block_hash, kind));
                    continue;
                }
                let Some(to_key) = tx.to else {
                    continue;
                };
                let to = address_of(to_key.as_bytes());
                // Executed: the fee for the gas used, the nonce, the value.
                let (status, gas_used) = if tx.gas_limit < TRANSFER_GAS {
                    (false, tx.gas_limit)
                } else {
                    let after_fee =
                        acct.balance - U256::from(tx.gas_limit) * U256::from(tx.gas_price);
                    if after_fee < U256::from(tx.value) {
                        (false, tx.gas_limit)
                    } else {
                        (true, TRANSFER_GAS)
                    }
                };
                let fee = U256::from(gas_used) * U256::from(tx.gas_price);
                {
                    let a = self.acct(from);
                    a.balance -= fee;
                    a.nonce += 1;
                }
                if status && from != to {
                    let v = U256::from(tx.value);
                    self.acct(from).balance -= v;
                    self.credit(to, v);
                }
                cumulative += gas_used;
                receipts.push(RefReceipt {
                    tx_hash: tx.hash,
                    including_block: block.header.block_hash,
                    status,
                    gas_used,
                    logs: Vec::new(),
                });
                executed.push(tx);
            }
        }
        self.settle(cfg, c, members, &executed, &receipts)?;
        Ok(Accepted {
            accepted_root: accepted_root(&receipts),
            receipt_root: receipt_root(&receipts),
            created: 0,
            gas_used: cumulative,
            state_root: self.root(cfg.storage_root_hardening_height, height),
            receipts,
            skipped,
        })
    }

    fn settle(
        &mut self,
        cfg: &RefConfig,
        c: &Block,
        members: &[(&Block, Color)],
        executed: &[&Transaction],
        receipts: &[RefReceipt],
    ) -> Result<(), Unsupported> {
        let height = c.header.height;
        // R(h): base subsidy, halving; executed-basis bonus for a deployment
        // (never reached here: deployments carry calldata and are refused).
        let halvings = height / HALVING_INTERVAL;
        let base = if halvings >= 64 {
            U256::zero()
        } else {
            wei(BLOCK_REWARD_SALT >> halvings)
        };
        let deployed = cfg.executed_basis_at(height)
            && executed
                .iter()
                .zip(receipts)
                .any(|(t, r)| r.status && t.to.is_none());
        let bonus = if deployed {
            (wei(MODEL_DEPLOYMENT_BONUS_SALT) >> halvings as usize).min(base)
        } else {
            U256::zero()
        };
        let total = base + bonus;
        let treasury = total * U256::from(TREASURY_PERCENT) / U256::from(100u64);
        let validator = total - treasury;

        let policy: Option<&RefPolicy> = cfg
            .reward_policy
            .as_ref()
            .filter(|p| height >= p.activation_height);
        let blues: Vec<&Block> = members
            .iter()
            .filter(|(b, col)| col.is_blue() && b.header.height > 0)
            .map(|(b, _)| *b)
            .collect();
        let shares = split(validator, blues.len());
        let subsidy = split(
            policy.map(|p| p.block_subsidy).unwrap_or_default(),
            blues.len(),
        );

        self.credit(TREASURY, treasury);
        // Blue recipients in mergeset order, then the red fees' recipient
        // (O4 default: the accepting block).
        let mut recipients: Vec<([u8; 32], [u8; 20], Vec<Hash>, U256, U256)> = blues
            .iter()
            .zip(shares.iter().zip(subsidy.iter()))
            .map(|(b, (e, s))| {
                (
                    *b.header.proposer_pubkey.as_bytes(),
                    b.header.coinbase,
                    vec![b.header.block_hash],
                    *e,
                    *s,
                )
            })
            .collect();
        let reds: Vec<Hash> = members
            .iter()
            .filter(|(_, col)| *col == Color::Red)
            .map(|(b, _)| b.header.block_hash)
            .collect();
        if !reds.is_empty() {
            recipients.push((
                *c.header.proposer_pubkey.as_bytes(),
                c.header.coinbase,
                reds,
                U256::zero(),
                U256::zero(),
            ));
        }
        for (proposer, coinbase, fee_blocks, emission, sub) in recipients {
            let eligible = match policy {
                None => true,
                Some(p) => p.staker_of.get(&proposer) == Some(&coinbase),
            };
            if !eligible {
                continue;
            }
            self.credit(coinbase, emission);
            let Some(p) = policy else { continue };
            let mut pool = U256::zero();
            for (t, r) in executed.iter().zip(receipts) {
                if fee_blocks.contains(&r.including_block) {
                    // EIP-1559: the price above the base fee, capped by the
                    // explicit tip for a type-2 transaction.
                    let over = t.gas_price.saturating_sub(c.header.base_fee_per_gas);
                    let tip = if t.eth_tx_type == 2 {
                        over.min(t.max_priority_fee_per_gas.unwrap_or(over))
                    } else {
                        over
                    };
                    pool += U256::from(tip) * U256::from(r.gas_used);
                }
            }
            let share = pool * U256::from(p.priority_fee_share_bps) / U256::from(10_000u64) + sub;
            if share.is_zero() {
                continue;
            }
            if self.accounts.get(&p.registry).is_some_and(|a| a.has_code) {
                return Err(Unsupported(
                    "the §R' registry has code; the reference vests only by value transfer".into(),
                ));
            }
            self.credit(p.registry, share);
        }
        Ok(())
    }
}

fn split(total: U256, n: usize) -> Vec<U256> {
    if n == 0 {
        return Vec::new();
    }
    let each = total / U256::from(n as u64);
    let rem = total % U256::from(n as u64);
    let mut v = vec![each; n];
    v[0] += rem;
    v
}

/// `accepted_root` (spec 06 §3.9): SHA3-256 over "CITRATE-ACCEPTED-V1" ‖
/// u64le count ‖ (tx_hash ‖ including_block_hash ‖ u8 status)*.
pub fn accepted_root(receipts: &[RefReceipt]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(b"CITRATE-ACCEPTED-V1");
    h.update((receipts.len() as u64).to_le_bytes());
    for r in receipts {
        h.update(r.tx_hash.as_bytes());
        h.update(r.including_block.as_bytes());
        h.update([u8::from(r.status)]);
    }
    Hash::new(h.finalize().into())
}

/// `receipt_root` v3 (spec 06 §3.9): SHA3-256 over "CITRATE-RECEIPTS-V3" ‖
/// u64le count ‖ (tx_hash ‖ u8 status ‖ u64le cumulative ‖ u64le gas_used ‖
/// logs_commitment)*. Value transfers emit no logs: the commitment of an
/// empty log list is SHA3-256(u64le 0).
pub fn receipt_root(receipts: &[RefReceipt]) -> Hash {
    let empty_logs: [u8; 32] = Sha3_256::digest(0u64.to_le_bytes()).into();
    let mut h = Sha3_256::new();
    h.update(b"CITRATE-RECEIPTS-V3");
    h.update((receipts.len() as u64).to_le_bytes());
    let mut cumulative = 0u64;
    for r in receipts {
        cumulative += r.gas_used;
        h.update(r.tx_hash.as_bytes());
        h.update([u8::from(r.status)]);
        h.update(cumulative.to_le_bytes());
        h.update(r.gas_used.to_le_bytes());
        h.update(empty_logs);
    }
    Hash::new(h.finalize().into())
}
