//! Independent reference for r1007 mergeset acceptance (ADR CV-4a; spec
//! `06_CONSENSUS_SPEC.md` §2 G3/G4/G6/G7, §3 and §8.3).
//!
//! Given a DAG (every block, bodies included) and the node's applied selected
//! chain, the reference recomputes from block data alone:
//!   1. GHOSTDAG records (selected parent, blues, reds, blue score and work),
//!      compared with each chain block's committed header values;
//!   2. each chain block's ordered mergeset (SP first, then `Mergeset*`
//!      ascending by key);
//!   3. the outcome of every transaction occurrence and the settlement;
//!   4. the four commitments (state_root, accepted_root, receipt_root,
//!      gas_used), compared with the chain block's header;
//!   5. when the caller supplies them, the node's accepted list per chain
//!      block (tx hash, including block, status), compared entry by entry.
//!
//! Independence: nothing here imports `citrate_consensus::{ghostdag,
//! ordering}`, `citrate_execution::executor` or the node. The trusted base
//! is the block/tx types, `tx_auth` (signature and chain id) and the
//! state-trie hash (`StateDB::calculate_state_root_with`). See `exec` for
//! exactly which transactions are covered; anything else is reported as
//! [`Field::Unsupported`], never guessed.

pub mod exec;
pub mod ghostdag;

use std::collections::HashMap;
use std::fmt;

use citrate_consensus::types::{Block, Hash};
use primitive_types::U256;

/// The §R' reward policy the node settled with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefPolicy {
    pub activation_height: u64,
    pub registry: [u8; 20],
    pub priority_fee_share_bps: u64,
    pub block_subsidy: U256,
    /// The system account §R' vests from (`creditReward`'s caller).
    pub reward_minter: [u8; 20],
    pub staker_of: HashMap<[u8; 32], [u8; 20]>,
}

/// What the reference needs besides the blocks.
#[derive(Debug, Clone)]
pub struct RefConfig {
    pub chain_id: u64,
    /// GHOSTDAG K the node ran with (18 on the network, smaller in tests).
    pub k: u32,
    pub genesis_alloc: Vec<([u8; 20], U256)>,
    pub reward_policy: Option<RefPolicy>,
    pub pba_hardening_height: Option<u64>,
    pub supply_hardening_height: Option<u64>,
    pub storage_root_hardening_height: Option<u64>,
    /// Genesis contract code: (address, runtime bytecode).
    pub genesis_code: Vec<([u8; 20], Vec<u8>)>,
    /// The EVM activation rules the node executed under.
    pub evm: EvmRules,
}

/// The node's EVM activation heights (network-profile values). The reference
/// executes contract transactions only where it implements the rule in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmRules {
    /// From this height REVM's balance changes are authoritative: every value
    /// movement a call makes, top-level and internal, lands.
    pub value_transfer_height: u64,
    /// From this height a contract account's nonce, as REVM computes it, is
    /// stored (EIP-161: 1 at creation, +1 per CREATE it runs).
    pub create_nonce_fix_height: u64,
    /// From this height code created inside a call is stored as its original
    /// bytes; below it, as REVM's analysed (zero-padded) form.
    pub exact_create_code_height: Option<u64>,
}

impl Default for EvmRules {
    /// The r1007 genesis rules: everything active from block 1.
    fn default() -> Self {
        Self {
            value_transfer_height: 0,
            create_nonce_fix_height: 0,
            exact_create_code_height: Some(1),
        }
    }
}

impl RefConfig {
    /// Whether the reward's bonus arms count executed transactions at
    /// `height` (supply hardening, active from its height and never at 0).
    pub fn executed_basis_at(&self, height: u64) -> bool {
        matches!(self.supply_hardening_height, Some(a) if height > 0 && height >= a)
    }
}

/// What differed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// The chain does not start at a parentless block, or a chain block's
    /// selected parent is not the previous chain block.
    ChainLink,
    /// The chain block is not in the DAG.
    MissingBlock,
    /// The header's selected parent is not the heaviest parent by key.
    SelectedParent,
    /// The header's blue score or blue work is not the reference's.
    Ghostdag,
    StateRoot,
    AcceptedRoot,
    ReceiptRoot,
    GasUsed,
    /// The node's accepted list for the block differs.
    AcceptedList,
    /// The reference does not cover something in this block.
    Unsupported,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ChainLink => "chain link",
            Self::MissingBlock => "missing block",
            Self::SelectedParent => "selected parent",
            Self::Ghostdag => "GHOSTDAG blue score / work",
            Self::StateRoot => "state root",
            Self::AcceptedRoot => "accepted root",
            Self::ReceiptRoot => "receipt root",
            Self::GasUsed => "gas used",
            Self::AcceptedList => "accepted list",
            Self::Unsupported => "unsupported by the reference",
        })
    }
}

/// The first chain block where the reference and the node disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    pub height: u64,
    pub hash: Hash,
    pub field: Field,
    pub reference: String,
    pub node: String,
}

fn full(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "height {} block {}: {}: reference {} node {}",
            self.height,
            full(&self.hash),
            self.field,
            self.reference,
            self.node
        )
    }
}

/// One accepted-list entry: (tx hash, including block, status).
pub type ListEntry = (Hash, Hash, bool);

/// The outcome of a replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Chain blocks (genesis excluded) whose every compared field matched.
    pub matched: u64,
    /// Of `matched`, how many had a node accepted list to compare.
    pub lists_compared: u64,
    /// Transactions executed and occurrences skipped over the matched blocks.
    pub executed: u64,
    pub skipped: u64,
    /// Skipped occurrences by reason: B1 nonce, B2 balance, B3 gas.
    pub skipped_nonce: u64,
    pub skipped_balance: u64,
    pub skipped_gas: u64,
    /// Of `executed`, how many failed (status 0: revert, halt, out of gas).
    pub failed: u64,
    /// Contracts created (top-level deployments and CREATE inside calls).
    pub created: u64,
    /// Logs emitted by executed transactions.
    pub logs: u64,
    /// The largest |Mergeset(C)| over the matched chain blocks, and the
    /// number of red members accepted.
    pub max_mergeset: u64,
    pub reds: u64,
    pub tip_height: u64,
    pub divergence: Option<Divergence>,
}

/// Replay `chain` (the node's applied selected chain, genesis first) over
/// the DAG `blocks`. `node_lists`, when given, returns the node's accepted
/// list for a chain block. Errors are input problems (nothing compared);
/// every disagreement is a [`Divergence`].
pub fn replay(
    cfg: &RefConfig,
    blocks: &[Block],
    chain: &[Hash],
    node_lists: Option<&dyn Fn(&Hash) -> Option<Vec<ListEntry>>>,
) -> Result<Report, String> {
    // A recording of a node that never stored a genesis block starts its
    // chain at the zero-hash sentinel; the reference holds it as a parentless,
    // empty, height-0 block, so height 1 accepts it like any genesis.
    let with_sentinel: Vec<Block>;
    let blocks: &[Block] = if chain.first() == Some(&Hash::default())
        && !blocks
            .iter()
            .any(|b| b.header.block_hash == Hash::default())
    {
        let mut v = blocks.to_vec();
        v.push(citrate_consensus::types::BlockBuilder::new().build_unhashed());
        with_sentinel = v;
        &with_sentinel
    } else {
        blocks
    };
    let mut dag = ghostdag::Dag::new(blocks)?;
    dag.color_all(cfg.k)?;
    let mut report = Report {
        matched: 0,
        lists_compared: 0,
        executed: 0,
        skipped: 0,
        skipped_nonce: 0,
        skipped_balance: 0,
        skipped_gas: 0,
        failed: 0,
        created: 0,
        logs: 0,
        max_mergeset: 0,
        reds: 0,
        tip_height: 0,
        divergence: None,
    };
    let Some(genesis) = chain.first() else {
        return Ok(report);
    };
    let diverge = |height, hash, field, reference: String, node: String| Divergence {
        height,
        hash,
        field,
        reference,
        node,
    };
    match dag.blocks.get(genesis) {
        Some(g) if g.header.selected_parent_hash == Hash::default() => {}
        _ => {
            report.divergence = Some(diverge(
                0,
                *genesis,
                Field::ChainLink,
                "a parentless genesis".into(),
                "the chain starts elsewhere".into(),
            ));
            return Ok(report);
        }
    }
    let mut state = exec::State::genesis(&cfg.genesis_alloc);
    for w in chain.windows(2) {
        let (prev, h) = (w[0], w[1]);
        let Some(c) = dag.blocks.get(&h).copied() else {
            report.divergence = Some(diverge(
                0,
                h,
                Field::MissingBlock,
                "a block".into(),
                "none".into(),
            ));
            return Ok(report);
        };
        let height = c.header.height;
        report.tip_height = height;
        if c.header.selected_parent_hash != prev {
            report.divergence = Some(diverge(
                height,
                h,
                Field::ChainLink,
                full(&prev),
                full(&c.header.selected_parent_hash),
            ));
            return Ok(report);
        }
        let rec = dag
            .records
            .get(&h)
            .cloned()
            .ok_or("uncolored chain block")?;
        if rec.selected_parent != Some(c.header.selected_parent_hash) {
            report.divergence = Some(diverge(
                height,
                h,
                Field::SelectedParent,
                rec.selected_parent.map(|x| full(&x)).unwrap_or_default(),
                full(&c.header.selected_parent_hash),
            ));
            return Ok(report);
        }
        if rec.blue_score != c.header.blue_score || rec.blue_work != c.header.blue_work {
            report.divergence = Some(diverge(
                height,
                h,
                Field::Ghostdag,
                format!("score {} work {}", rec.blue_score, rec.blue_work),
                format!("score {} work {}", c.header.blue_score, c.header.blue_work),
            ));
            return Ok(report);
        }
        let members: Vec<(&Block, ghostdag::Color)> = dag
            .ordered_mergeset(&h)
            .into_iter()
            .map(|(m, col)| (dag.blocks[&m], col))
            .collect();
        let acc = match state.accept(cfg, c, &members) {
            Ok(a) => a,
            Err(exec::Unsupported(why)) => {
                report.divergence =
                    Some(diverge(height, h, Field::Unsupported, why, String::new()));
                return Ok(report);
            }
        };
        let checks = [
            (
                Field::AcceptedRoot,
                full(&acc.accepted_root),
                full(&c.accepted_root),
            ),
            (
                Field::ReceiptRoot,
                full(&acc.receipt_root),
                full(&c.receipt_root),
            ),
            (
                Field::GasUsed,
                acc.gas_used.to_string(),
                c.header.gas_used.to_string(),
            ),
            (Field::StateRoot, full(&acc.state_root), full(&c.state_root)),
        ];
        for (field, r, n) in checks {
            if r != n {
                report.divergence = Some(diverge(height, h, field, r, n));
                return Ok(report);
            }
        }
        if let Some(lists) = node_lists {
            if let Some(node_list) = lists(&h) {
                let ours: Vec<ListEntry> = acc
                    .receipts
                    .iter()
                    .map(|r| (r.tx_hash, r.including_block, r.status))
                    .collect();
                if ours != node_list {
                    let show = |v: &[ListEntry]| {
                        v.iter()
                            .map(|(t, b, s)| format!("{}@{}:{}", full(t), full(b), u8::from(*s)))
                            .collect::<Vec<_>>()
                            .join(",")
                    };
                    report.divergence = Some(diverge(
                        height,
                        h,
                        Field::AcceptedList,
                        show(&ours),
                        show(&node_list),
                    ));
                    return Ok(report);
                }
                report.lists_compared += 1;
            }
        }
        report.executed += acc.receipts.len() as u64;
        report.skipped += acc.skipped.len() as u64;
        for (_, _, kind) in &acc.skipped {
            match kind {
                exec::SkipKind::Nonce => report.skipped_nonce += 1,
                exec::SkipKind::Balance => report.skipped_balance += 1,
                exec::SkipKind::Gas => report.skipped_gas += 1,
                exec::SkipKind::Code | exec::SkipKind::Invalid => {}
            }
        }
        report.failed += acc.receipts.iter().filter(|r| !r.status).count() as u64;
        report.created += acc.created;
        report.logs += acc
            .receipts
            .iter()
            .map(|r| r.logs.len() as u64)
            .sum::<u64>();
        report.max_mergeset = report.max_mergeset.max(members.len() as u64);
        report.reds += members
            .iter()
            .filter(|(_, col)| *col == ghostdag::Color::Red)
            .count() as u64;
        report.matched += 1;
    }
    Ok(report)
}
