//! The reference state transition (spec 06 §3.4-§3.9), written from the spec,
//! not from `citrate_execution::executor`.
//!
//! COVERAGE (what the reference executes):
//!   * value transfers (empty calldata, `to` set): 21,000 gas, the self-
//!     transfer no-op, a value above the balance after the fee fails the tx;
//!   * contract calls and deployments through the reference's own EVM driver
//!     (`crate::evm`, rules E1-E6 there): storage, code, logs, internal value
//!     transfers and CREATEs, reverts, halts and out-of-gas;
//!   * the outcome classes: B1 nonce, B2 balance, B3 ACCEPT gas budget, B4
//!     sender has code, stateless skips (chain id / signature via the trusted
//!     `tx_auth`, gas price below the base fee); C (failed: full gas_limit
//!     charged, nonce bumped, no other effect) and D (ok);
//!   * fees: the sender pays `gas_used * gas_price`; the base fee burns;
//!   * settlement: R(h) (base subsidy with halving, the executed-basis bonus
//!     for deployments), split among the blue members with a proposer per
//!     O3, the treasury part, the §R' eligibility rule (coinbase must be the
//!     proposer's staker in the policy, otherwise the share burns), and §R'
//!     vesting as the `creditReward` system call (E6);
//!   * the commitments: state root (through the trusted trie hash, with code
//!     and storage), accepted_root, receipt_root v3 (with logs), gas_used.
//!
//! NOT COVERED (the reference refuses with [`Unsupported`] instead of
//! guessing): AI operations, any call frame into a Citrate precompile or a
//! reserved low address (see `crate::evm`), and blocks below an EVM rule's
//! activation height.

use std::collections::{BTreeMap, HashMap};

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
/// The legacy (pre-supply-hardening) bonus arms: calldata prefixes and the
/// inference bonus in hundredths of a SALT.
pub const LEGACY_INFERENCE_SELECTOR: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
pub const LEGACY_MODEL_REGISTER_SELECTOR: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
pub const LEGACY_INFERENCE_BONUS_CENTI_SALT: u64 = 1;
/// The §R' base fee constant.
pub const CANONICAL_BASE_FEE: u64 = 1_000_000_000;

/// A transaction the reference cannot execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported(pub String);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    pub balance: U256,
    pub nonce: u64,
    /// Set when the account has a code hash (possibly of empty code).
    pub code: Option<Vec<u8>>,
    /// Storage slots, 32-byte big-endian key and value (zero values kept).
    pub storage: BTreeMap<[u8; 32], [u8; 32]>,
}

impl Account {
    /// EIP-3607 / B4: the account has (non-empty) code.
    pub fn has_code(&self) -> bool {
        self.code.as_ref().is_some_and(|c| !c.is_empty())
    }

    fn is_blank(&self) -> bool {
        self.balance.is_zero() && self.nonce == 0 && self.code.is_none() && self.storage.is_empty()
    }
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
    /// Code by keccak256 hash (REVM's `code_by_hash`).
    pub codes: HashMap<[u8; 32], Vec<u8>>,
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
        Self {
            accounts,
            codes: HashMap::new(),
        }
    }

    /// The genesis state of `cfg`: its balances and its contract code.
    pub fn genesis_of(cfg: &RefConfig) -> Self {
        let mut s = Self::genesis(&cfg.genesis_alloc);
        for (a, code) in &cfg.genesis_code {
            s.set_code(*a, code.clone());
        }
        s
    }

    /// Give `a` the code `code` (and its hash).
    pub fn set_code(&mut self, a: [u8; 20], code: Vec<u8>) {
        self.codes.insert(crate::evm::keccak(&code), code.clone());
        self.acct(a).code = Some(code);
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
            if acct.is_blank() {
                continue;
            }
            let addr = citrate_execution::types::Address(*a);
            db.accounts.set_balance(addr, acct.balance);
            db.accounts.set_nonce(addr, acct.nonce);
            if let Some(code) = &acct.code {
                db.set_code(addr, code.clone());
            }
            for (k, v) in &acct.storage {
                db.set_storage(addr, k.to_vec(), v.to_vec());
            }
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
        self.accept_with(cfg, c, members, &HashMap::new())
    }

    /// [`State::accept`] with the BLOCKHASH window of `c` (height -> hash of
    /// `c`'s selected-chain ancestor, for the 256 heights below it).
    pub fn accept_with(
        &mut self,
        cfg: &RefConfig,
        c: &Block,
        members: &[(&Block, Color)],
        block_hashes: &HashMap<u64, [u8; 32]>,
    ) -> Result<Accepted, Unsupported> {
        let height = c.header.height;
        let env = crate::evm::Env {
            chain_id: cfg.chain_id,
            number: height,
            timestamp: c.header.timestamp,
            coinbase: c.header.coinbase,
            prevrandao: *c.header.vrf_reveal.output.as_bytes(),
            block_hashes,
            exact_create_code: matches!(
                cfg.evm.exact_create_code_height,
                Some(a) if height > 0 && height >= a
            ),
            contract_nonces: height >= cfg.evm.create_nonce_fix_height,
        };
        let mut created: u64 = 0;
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
                } else if acct.has_code() {
                    Some(SkipKind::Code)
                } else if tx.nonce != acct.nonce {
                    Some(SkipKind::Nonce)
                } else if acct.balance < need {
                    Some(SkipKind::Balance)
                } else if tx.to.is_none() && tx.data.is_empty() {
                    Some(SkipKind::Invalid)
                } else {
                    None
                };
                if let Some(kind) = skip {
                    skipped.push((tx.hash, block.header.block_hash, kind));
                    continue;
                }
                let upfront = U256::from(tx.gas_limit) * U256::from(tx.gas_price);
                let (status, gas_used, logs) = if tx.data.is_empty() {
                    // A value transfer (the shape check above guarantees `to`).
                    let to_key = tx.to.map(|k| *k.as_bytes()).unwrap_or_default();
                    let to = address_of(&to_key);
                    let ok = tx.gas_limit >= TRANSFER_GAS
                        && acct.balance - upfront >= U256::from(tx.value);
                    let gas_used = if ok { TRANSFER_GAS } else { tx.gas_limit };
                    let fee = U256::from(gas_used) * U256::from(tx.gas_price);
                    {
                        let a = self.acct(from);
                        a.balance -= fee;
                        a.nonce += 1;
                    }
                    if ok && from != to {
                        let v = U256::from(tx.value);
                        self.acct(from).balance -= v;
                        self.credit(to, v);
                    }
                    (ok, gas_used, Vec::new())
                } else {
                    let run = self.contract_tx(cfg, &env, tx, from, acct.balance - upfront)?;
                    match run {
                        Some((total, success)) => {
                            self.acct(from).balance = acct.balance - upfront;
                            success.apply(self);
                            created += success.created;
                            let refund =
                                U256::from(tx.gas_limit - total) * U256::from(tx.gas_price);
                            let a = self.acct(from);
                            a.nonce = tx.nonce + 1;
                            a.balance += refund;
                            (true, total, success.logs)
                        }
                        None => {
                            let a = self.acct(from);
                            a.balance = acct.balance - upfront;
                            a.nonce = tx.nonce + 1;
                            (false, tx.gas_limit, Vec::new())
                        }
                    }
                };
                cumulative += gas_used;
                receipts.push(RefReceipt {
                    tx_hash: tx.hash,
                    including_block: block.header.block_hash,
                    status,
                    gas_used,
                    logs,
                });
                executed.push(tx);
            }
        }
        self.settle(cfg, c, &env, members, &executed, &receipts)?;
        Ok(Accepted {
            accepted_root: accepted_root(&receipts),
            receipt_root: receipt_root(&receipts),
            created,
            gas_used: cumulative,
            state_root: self.root(cfg.storage_root_hardening_height, height),
            receipts,
            skipped,
        })
    }

    /// Run a transaction with calldata (E1, E2, E3 in `crate::evm`):
    /// `Some((gas charged, effect))` on success, `None` when it fails.
    fn contract_tx(
        &self,
        cfg: &RefConfig,
        env: &crate::evm::Env<'_>,
        tx: &Transaction,
        from: [u8; 20],
        post_fee: U256,
    ) -> Result<Option<(u64, crate::evm::Success)>, Unsupported> {
        use crate::evm::{is_low, is_standard_precompile, Kind, CALL_BASE_GAS, CREATE_BASE_GAS};
        let height = env.number;
        if height < cfg.evm.value_transfer_height {
            return Err(Unsupported(format!(
                "tx {} at height {height}: below the value-transfer activation ({}), whose \
                 legacy value semantics the reference does not implement",
                tx.hash, cfg.evm.value_transfer_height
            )));
        }
        let (kind, base) = match tx.to {
            None => (
                Kind::Create {
                    init: tx.data.clone(),
                },
                CREATE_BASE_GAS,
            ),
            Some(key) => {
                if citrate_consensus::types::AiOpKind::classify(true, &tx.data).is_some() {
                    return Err(Unsupported(format!(
                        "tx {} is an AI operation; the reference does not implement them",
                        tx.hash
                    )));
                }
                let to = address_of(key.as_bytes());
                if is_low(&to) && !is_standard_precompile(&to) {
                    return Err(Unsupported(format!(
                        "tx {} calls 0x{}, a precompile the reference does not implement",
                        tx.hash,
                        hex::encode(to)
                    )));
                }
                let pba = match cfg.pba_hardening_height {
                    Some(h) => citrate_consensus::hardening::PbaHardening::at(h),
                    None => citrate_consensus::hardening::PbaHardening::off(),
                };
                let runs = self.accounts.get(&to).is_some_and(|a| a.code.is_some())
                    || (is_standard_precompile(&to) && pba.active_at(height));
                if !runs {
                    // E1: no code, nothing runs, no value moves.
                    return Ok((tx.gas_limit >= CALL_BASE_GAS)
                        .then(|| (CALL_BASE_GAS, crate::evm::Success::nothing())));
                }
                (
                    Kind::Call {
                        to,
                        data: tx.data.clone(),
                        value: U256::from(tx.value),
                    },
                    CALL_BASE_GAS,
                )
            }
        };
        if tx.gas_limit < base {
            return Ok(None);
        }
        let out = crate::evm::run(
            self,
            env,
            from,
            post_fee,
            kind,
            tx.gas_limit - base,
            env.timestamp,
        )?;
        Ok(out.and_then(|s| {
            let total = base.checked_add(s.gas_used)?;
            (total <= tx.gas_limit).then_some((total, s))
        }))
    }

    fn settle(
        &mut self,
        cfg: &RefConfig,
        c: &Block,
        env: &crate::evm::Env<'_>,
        members: &[(&Block, Color)],
        executed: &[&Transaction],
        receipts: &[RefReceipt],
    ) -> Result<(), Unsupported> {
        let height = c.header.height;
        // R(h): base subsidy, halving; executed-basis bonus for a deployment.
        let halvings = height / HALVING_INTERVAL;
        let base = if halvings >= 64 {
            U256::zero()
        } else {
            wei(BLOCK_REWARD_SALT >> halvings)
        };
        let bonus = if cfg.executed_basis_at(height) {
            // Supply hardening: the bonus arms count SUCCESSFUL executed txs,
            // decay with the halvings and are capped by the base. (AI
            // inference and model registration are refused upstream.)
            let deployed = executed
                .iter()
                .zip(receipts)
                .any(|(t, r)| r.status && t.to.is_none());
            if deployed {
                (wei(MODEL_DEPLOYMENT_BONUS_SALT) >> halvings as usize).min(base)
            } else {
                U256::zero()
            }
        } else {
            // The legacy rule, below supply hardening: calldata-based arms
            // over every executed tx whatever its status, undecayed and
            // uncapped. 0.01 SALT per tx whose calldata starts with the
            // inference selector; 1 SALT if any is a deployment or carries
            // the model-register selector.
            let inferences = executed
                .iter()
                .filter(|t| t.data.starts_with(&LEGACY_INFERENCE_SELECTOR))
                .count() as u64;
            let deployed = executed
                .iter()
                .any(|t| t.to.is_none() || t.data.starts_with(&LEGACY_MODEL_REGISTER_SELECTOR));
            let inference = U256::from(LEGACY_INFERENCE_BONUS_CENTI_SALT)
                * U256::from(inferences)
                * U256::exp10(16);
            let model = if deployed {
                wei(MODEL_DEPLOYMENT_BONUS_SALT)
            } else {
                U256::zero()
            };
            inference + model
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
            // E6: the vest is a system call into the registry; a failed call
            // changes nothing (the share burns).
            let minter = p.reward_minter;
            let before = self
                .accounts
                .get(&minter)
                .map(|a| a.balance)
                .unwrap_or_default();
            let funded = before + share;
            let vest = crate::evm::run(
                self,
                env,
                minter,
                funded,
                crate::evm::Kind::Call {
                    to: p.registry,
                    data: crate::evm::credit_reward_calldata(&proposer, share),
                    value: share,
                },
                crate::evm::SYSTEM_CALL_GAS_LIMIT,
                0,
            )?;
            if let Some(success) = vest {
                self.acct(minter).balance = funded;
                success.apply(self);
            }
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

/// The commitment of one receipt's logs (spec 06 §3.9): SHA3-256 over u64le
/// count ‖ (address ‖ u32le topic count ‖ topics ‖ u64le data length ‖
/// data)*.
pub fn logs_commitment(logs: &[RefLog]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update((logs.len() as u64).to_le_bytes());
    for l in logs {
        h.update(l.address);
        h.update((l.topics.len() as u32).to_le_bytes());
        for t in &l.topics {
            h.update(t);
        }
        h.update((l.data.len() as u64).to_le_bytes());
        h.update(&l.data);
    }
    h.finalize().into()
}

/// `receipt_root` v3 (spec 06 §3.9): SHA3-256 over "CITRATE-RECEIPTS-V3" ‖
/// u64le count ‖ (tx_hash ‖ u8 status ‖ u64le cumulative ‖ u64le gas_used ‖
/// logs_commitment)*.
pub fn receipt_root(receipts: &[RefReceipt]) -> Hash {
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
        h.update(logs_commitment(&r.logs));
    }
    Hash::new(h.finalize().into())
}
