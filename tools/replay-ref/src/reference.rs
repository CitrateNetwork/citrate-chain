//! The reference path: the recorded chain replayed from genesis, linearly.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use anyhow::{bail, Result};
use citrate_consensus::hardening::PbaHardening;
use citrate_consensus::types::{Block, Hash};
use citrate_economics::rewards::{RewardCalculator, RewardConfig};
use citrate_execution::types::{Address, ExecutionError, TransactionReceipt};
use citrate_execution::{Executor, StateDB};
use primitive_types::U256;

use crate::recording::{ChainEntry, Recording};

/// The block-reward rule the reference settles with, restated from the chain
/// rule (`node::canonical_apply::canonical_reward_config`) so this crate never
/// imports the node. The node's test suite asserts the two are equal
/// (`replay_reference_reward_rule_matches_the_node`).
pub fn reference_reward_config() -> RewardConfig {
    RewardConfig {
        block_reward: 10,
        halving_interval: 2_100_000,
        inference_bonus: 1,
        model_deployment_bonus: 1,
        treasury_percentage: 10,
        treasury_address: Address([0x11; 20]),
    }
}

/// Which blocks each chain block executes, in order.
///
/// `SelectedChain` is the r1006 rule. Mergeset execution (S3-3b) is a second
/// implementation returning the chain block's ordered mergeset
/// (`consensus_ordered_mergeset`, spec 06 section 3.2) from the recorded DAG.
pub trait OrderingMode {
    fn name(&self) -> &'static str;

    /// The blocks the chain block `chain[index]` executes, in execution order.
    fn accepted<'a>(
        &self,
        dag: &HashMap<Hash, &'a Block>,
        chain: &[ChainEntry],
        index: usize,
    ) -> std::result::Result<Vec<&'a Block>, String>;
}

/// The r1006 rule: a chain block executes its own transactions.
pub struct SelectedChain;

impl OrderingMode for SelectedChain {
    fn name(&self) -> &'static str {
        "selected-chain"
    }

    fn accepted<'a>(
        &self,
        dag: &HashMap<Hash, &'a Block>,
        chain: &[ChainEntry],
        index: usize,
    ) -> std::result::Result<Vec<&'a Block>, String> {
        let entry = chain
            .get(index)
            .ok_or_else(|| format!("no chain entry {index}"))?;
        let block = dag
            .get(&entry.hash)
            .ok_or_else(|| format!("chain block {} @ {} not recorded", entry.hash, entry.height))?;
        Ok(vec![*block])
    }
}

/// A hash in full (`Hash`'s `Display` is an 8-digit prefix).
pub fn full_hash(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

/// What differed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// The recorded chain does not start at genesis.
    ChainStart,
    /// A chain block is not in the recording.
    MissingBlock,
    /// A chain block's height or selected parent does not continue the chain.
    ChainLink,
    /// The reference root differs from the block header's `state_root`.
    HeaderStateRoot,
    /// The reference root differs from the root the node committed.
    CommittedStateRoot,
    /// The from-scratch root of the replayed state (`StateDB::reference_state_root_with`:
    /// every account and slot re-encoded, no cache) differs from the incremental root
    /// the same state was given (CV-14 (b)).
    FromScratchStateRoot,
    /// The reference could not execute the block at all (the node did).
    Execution,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ChainStart => "chain start",
            Self::MissingBlock => "missing block",
            Self::ChainLink => "chain link",
            Self::HeaderStateRoot => "state root (block header)",
            Self::CommittedStateRoot => "state root (committed by the node)",
            Self::FromScratchStateRoot => "state root (from scratch vs incremental)",
            Self::Execution => "execution",
        })
    }
}

/// The first block where the reference and the node disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    pub height: u64,
    pub hash: Hash,
    pub field: Field,
    /// The reference's value.
    pub reference: String,
    /// The node's value.
    pub node: String,
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "height {} block {}: {}: reference {} node {}",
            self.height,
            full_hash(&self.hash),
            self.field,
            self.reference,
            self.node
        )
    }
}

/// The outcome of a replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub mode: &'static str,
    /// Chain blocks replayed and matched (genesis excluded).
    pub matched: u64,
    /// Chain blocks with a committed root to compare (of `matched`).
    pub committed_compared: u64,
    pub tip_height: u64,
    /// Chain blocks whose from-scratch root was computed and matched.
    pub from_scratch_compared: u64,
    pub divergence: Option<Divergence>,
}

/// Replay `rec`'s chain from genesis under `mode` and report the first
/// divergence. Errors are configuration problems (nothing was compared);
/// any disagreement with the node is a [`Divergence`] in the report.
pub async fn replay(rec: &Recording, mode: &dyn OrderingMode) -> Result<Report> {
    let cfg = &rec.config;
    let process_srh = citrate_execution::storage_root_hardening::storage_root_hardening_height();
    if process_srh != cfg.storage_root_hardening_height {
        bail!(
            "storage-root hardening is {process_srh:?} in this process, the recording ran with \
             {:?}; set it first (replay-diff does)",
            cfg.storage_root_hardening_height
        );
    }
    let process_mpt = citrate_execution::mpt_state_root::mpt_state_root_height();
    if process_mpt != cfg.mpt_state_root_height {
        bail!(
            "the MPT state root is {process_mpt:?} in this process, the recording ran with \
             {:?}; set it first (replay-diff does)",
            cfg.mpt_state_root_height
        );
    }
    let exec = Executor::with_chain_id(Arc::new(StateDB::new()), cfg.chain_id);
    exec.set_pba_hardening(match cfg.pba_hardening_height {
        Some(h) => PbaHardening::at(h),
        None => PbaHardening::off(),
    });
    if let Some(h) = cfg.validator_activation_height {
        exec.set_validator_activation_height(h);
    }
    if let Some(p) = &cfg.reward_policy {
        *exec.reward_policy_handle().write() = Some(p.to_policy());
    }
    for (addr, balance) in &cfg.genesis_alloc {
        exec.set_balance(&Address(*addr), U256::from_big_endian(balance));
    }

    let calculator = RewardCalculator::new(reference_reward_config());
    let treasury = reference_reward_config().treasury_address;
    let supply = cfg.supply_hardening_height;
    let reward = move |b: &Block,
                       receipts: &[TransactionReceipt]|
          -> std::result::Result<Vec<(Address, U256)>, ExecutionError> {
        let r = calculator
            .calculate_block_reward(
                b,
                receipts,
                citrate_execution::supply_hardening::active_at(supply, b.header.height),
            )
            .map_err(|e| ExecutionError::RewardSettlement(e.to_string()))?;
        Ok(vec![
            (Address(b.header.coinbase), r.validator_reward),
            (treasury, r.treasury_reward),
        ])
    };

    let mut report = Report {
        mode: mode.name(),
        matched: 0,
        committed_compared: 0,
        tip_height: rec.chain.last().map(|e| e.height).unwrap_or(0),
        from_scratch_compared: 0,
        divergence: None,
    };
    let dag = rec.index();
    let Some(first) = rec.chain.first() else {
        bail!("the recording holds no chain");
    };
    if first.height != 0 {
        report.divergence = Some(Divergence {
            height: first.height,
            hash: first.hash,
            field: Field::ChainStart,
            reference: "height 0".into(),
            node: format!("chain starts at {}", first.height),
        });
        return Ok(report);
    }

    for index in 1..rec.chain.len() {
        let entry = &rec.chain[index];
        let parent = &rec.chain[index - 1];
        let diverge = |field: Field, reference: String, node: String| Divergence {
            height: entry.height,
            hash: entry.hash,
            field,
            reference,
            node,
        };
        let Some(block) = dag.get(&entry.hash) else {
            report.divergence = Some(diverge(
                Field::MissingBlock,
                "a block".into(),
                "not recorded".into(),
            ));
            return Ok(report);
        };
        if block.header.height != entry.height
            || entry.height != parent.height + 1
            || block.selected_parent() != parent.hash
        {
            report.divergence = Some(diverge(
                Field::ChainLink,
                format!(
                    "height {} on {}",
                    parent.height + 1,
                    full_hash(&parent.hash)
                ),
                format!(
                    "height {} on {}",
                    block.header.height,
                    full_hash(&block.selected_parent())
                ),
            ));
            return Ok(report);
        }
        let accepted = match mode.accepted(&dag, &rec.chain, index) {
            Ok(a) => a,
            Err(e) => {
                report.divergence = Some(diverge(Field::MissingBlock, e, "recorded".into()));
                return Ok(report);
            }
        };
        let mut root = None;
        for b in accepted {
            match exec
                .apply_block_no_persist_with_receipts(b, b.header.coinbase, &reward)
                .await
            {
                Ok((r, _)) => root = Some(r),
                Err(ExecutionError::StateRootMismatch { expected, got }) => {
                    report.divergence = Some(diverge(
                        Field::HeaderStateRoot,
                        full_hash(&got),
                        full_hash(&expected),
                    ));
                    return Ok(report);
                }
                Err(e) => {
                    report.divergence =
                        Some(diverge(Field::Execution, e.to_string(), "applied".into()));
                    return Ok(report);
                }
            }
        }
        // CV-14 (b): the roots above are the executor's incremental roots (the
        // node computes them the same way). The from-scratch reference of the
        // same state must agree, and it is what the node's committed root is
        // then judged against.
        let root = match root {
            Some(incremental) => {
                let scratch = exec
                    .state_db()
                    .reference_state_root_with(cfg.storage_root_hardening_height, entry.height);
                report.from_scratch_compared += 1;
                if scratch != incremental {
                    report.divergence = Some(diverge(
                        Field::FromScratchStateRoot,
                        full_hash(&scratch),
                        full_hash(&incremental),
                    ));
                    return Ok(report);
                }
                Some(scratch)
            }
            None => None,
        };
        if let (Some(root), Some(committed)) = (root, entry.committed_root) {
            report.committed_compared += 1;
            if root != committed {
                report.divergence = Some(diverge(
                    Field::CommittedStateRoot,
                    full_hash(&root),
                    full_hash(&committed),
                ));
                return Ok(report);
            }
        }
        report.matched += 1;
    }
    Ok(report)
}
