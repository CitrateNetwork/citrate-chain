// citrate/core/execution/src/acceptance.rs
//
// r1007 S3-3b (spec 06 §3.4, §3.9, §3.11): the data model of mergeset
// acceptance and the two new commitments a chain block's header carries.
//
// A chain block C executes the transactions of Mergeset(C), in
// `citrate_consensus::ordering::consensus_ordered_mergeset` order, on top of
// post(SP(C)) (`Executor::execute_mergeset` / `apply_accepting_block`). Every
// transaction occurrence gets exactly one outcome:
//   * Skipped (class B): nonce, balance, gas budget, sender has code, or a
//     stateless rule the including block should have enforced. No state
//     change, no fee, no nonce bump, no receipt.
//   * Executed (class C failed / D ok): a receipt, the fee charged, the nonce
//     bumped.
// The commitments cover executed occurrences only. Skip records are local
// (non-consensus) data.

use crate::types::{Log, TransactionReceipt};
use citrate_consensus::acceptance::{InclusionColor, ACCEPTED_ROOT_DOMAIN, RECEIPT_ROOT_DOMAIN};
use citrate_consensus::types::{Block, Hash};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// One block of an accepting block's mergeset, in execution order.
#[derive(Debug, Clone, Copy)]
pub struct AcceptedBlock<'a> {
    pub block: &'a Block,
    pub color: InclusionColor,
}

/// Why an occurrence was skipped (spec 06 §3.4 class B, plus the stateless
/// rules a malformed including block could carry past admission).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SkipReason {
    /// B1: `tx.nonce != state.nonce(sender)` (covers duplicates).
    Nonce,
    /// B2: `balance < gas_limit * gas_price + value`.
    Balance,
    /// B3: `gas_limit` above the accepting block's remaining ACCEPT budget.
    Gas,
    /// B4: the sender has code (EIP-3607).
    Code,
    /// A stateless rule (signature, chain id, base fee, decodable type) the
    /// including block's admission should have rejected. Skipped rather than
    /// letting one merged block disqualify the accepting block.
    Invalid,
}

impl SkipReason {
    /// The RPC spelling (spec 06 §5.4).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nonce => "skipped:nonce",
            Self::Balance => "skipped:balance",
            Self::Gas => "skipped:gas",
            Self::Code => "skipped:code",
            Self::Invalid => "skipped:invalid",
        }
    }
}

/// The outcome of one transaction occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OccurrenceOutcome {
    /// Executed: `status` is the receipt status (class D true, class C false).
    Executed {
        status: bool,
    },
    Skipped(SkipReason),
}

/// One transaction occurrence (block, index) of an accepted mergeset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Occurrence {
    pub tx_hash: Hash,
    pub including_block: Hash,
    pub including_height: u64,
    pub color: InclusionColor,
    pub index_in_block: u64,
    pub outcome: OccurrenceOutcome,
}

/// The result of executing one accepting block's mergeset.
#[derive(Debug, Clone)]
pub struct MergesetExecution {
    /// Every occurrence, in execution order.
    pub occurrences: Vec<Occurrence>,
    /// The executed transactions, in execution order.
    pub executed: Vec<citrate_consensus::types::Transaction>,
    /// Their receipts (aligned with `executed`), with the acceptance fields
    /// set. `block_hash` is the accepting block's hash once it is known (the
    /// producer stamps it after sealing).
    pub receipts: Vec<TransactionReceipt>,
    /// Cumulative gas of the executed transactions.
    pub gas_used: u64,
    pub accepted_root: Hash,
    pub receipt_root: Hash,
    /// post(C), after settlement.
    pub state_root: Hash,
}

impl MergesetExecution {
    /// The receipts stamped with the accepting block's hash and height.
    pub fn stamp(&mut self, accepting_hash: Hash, accepting_height: u64) {
        for r in &mut self.receipts {
            r.block_hash = accepting_hash;
            r.block_number = accepting_height;
        }
    }
}

/// Spec 06 §3.9 `accepted_root`: SHA3-256 over `"CITRATE-ACCEPTED-V1" ‖ u64
/// count ‖ (tx_hash ‖ including_block_hash ‖ u8 status)*`, executed
/// occurrences only, in execution order. Integers little-endian (the block
/// hash preimage's convention).
pub fn accepted_root(occurrences: &[Occurrence]) -> Hash {
    let executed: Vec<(&Occurrence, bool)> = occurrences
        .iter()
        .filter_map(|o| match o.outcome {
            OccurrenceOutcome::Executed { status } => Some((o, status)),
            OccurrenceOutcome::Skipped(_) => None,
        })
        .collect();
    let mut h = Sha3_256::new();
    h.update(ACCEPTED_ROOT_DOMAIN);
    h.update((executed.len() as u64).to_le_bytes());
    for (o, status) in executed {
        h.update(o.tx_hash.as_bytes());
        h.update(o.including_block.as_bytes());
        h.update([u8::from(status)]);
    }
    Hash::new(h.finalize().into())
}

/// The commitment to one receipt's logs: SHA3-256 over `u64 n ‖ (address[20]
/// ‖ u32 n_topics ‖ topics[32]* ‖ u64 data_len ‖ data)*`.
pub fn logs_commitment(logs: &[Log]) -> Hash {
    let mut h = Sha3_256::new();
    h.update((logs.len() as u64).to_le_bytes());
    for log in logs {
        h.update(log.address.0);
        h.update((log.topics.len() as u32).to_le_bytes());
        for t in &log.topics {
            h.update(t.as_bytes());
        }
        h.update((log.data.len() as u64).to_le_bytes());
        h.update(&log.data);
    }
    Hash::new(h.finalize().into())
}

/// Spec 06 §3.9 v3 `receipt_root`: SHA3-256 over `"CITRATE-RECEIPTS-V3" ‖ u64
/// count ‖ (tx_hash ‖ u8 status ‖ u64 cumulative_gas_used ‖ u64 gas_used ‖
/// logs_commitment)*` over the executed receipts in execution order.
pub fn receipt_root(receipts: &[TransactionReceipt]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(RECEIPT_ROOT_DOMAIN);
    h.update((receipts.len() as u64).to_le_bytes());
    let mut cumulative: u64 = 0;
    for r in receipts {
        cumulative = cumulative.saturating_add(r.gas_used);
        h.update(r.tx_hash.as_bytes());
        h.update([u8::from(r.status)]);
        h.update(cumulative.to_le_bytes());
        h.update(r.gas_used.to_le_bytes());
        h.update(logs_commitment(&r.logs).as_bytes());
    }
    Hash::new(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn occ(tx: u8, block: u8, outcome: OccurrenceOutcome) -> Occurrence {
        Occurrence {
            tx_hash: Hash::new([tx; 32]),
            including_block: Hash::new([block; 32]),
            including_height: 1,
            color: InclusionColor::Blue,
            index_in_block: 0,
            outcome,
        }
    }

    #[test]
    fn accepted_root_covers_executed_occurrences_only() {
        let a = vec![
            occ(1, 7, OccurrenceOutcome::Executed { status: true }),
            occ(2, 8, OccurrenceOutcome::Skipped(SkipReason::Nonce)),
        ];
        let b = vec![occ(1, 7, OccurrenceOutcome::Executed { status: true })];
        assert_eq!(accepted_root(&a), accepted_root(&b));
        let c = vec![occ(1, 7, OccurrenceOutcome::Executed { status: false })];
        assert_ne!(accepted_root(&b), accepted_root(&c), "status is committed");
        let d = vec![occ(1, 8, OccurrenceOutcome::Executed { status: true })];
        assert_ne!(
            accepted_root(&b),
            accepted_root(&d),
            "including block is committed"
        );
        assert_ne!(accepted_root(&[]), Hash::default());
    }
}
