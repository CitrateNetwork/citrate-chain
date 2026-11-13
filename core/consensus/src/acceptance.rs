// citrate/core/consensus/src/acceptance.rs
//
// r1007 S3-3b (ADR CV-4a, spec 06 §3): the block-0 constants of mergeset
// acceptance. A chain block C accepts Mergeset(C) = {SP(C)} ∪ Mergeset*(C)
// and executes the transactions of those blocks, in the order of
// `ordering::consensus_ordered_mergeset`, on top of post(SP(C)). Its header
// commits the result (state_root, accepted_root, receipt_root, gas_used).
//
// Where the spec leaves an owner or reviewer question open, the spec default
// is implemented and named here so the decision is one edit:
//   O3 -> EMISSION_ATTRIBUTION
//   O4 -> RED_FEE_RECIPIENT
//   O5 -> INCLUDE_GAS_LIMIT, ACCEPT_GAS_LIMIT
//   R1 -> COMMITMENT_VALIDATION
//   R2 -> ACCEPTANCE_MODEL
// R1 and R2 are structural (they decide where execution happens), so their
// enums name only the model that is implemented; the reviewer's alternative
// is documented on the enum and would be a new variant plus its code path.

/// O5 / D9: Σ tx.gas_limit over one block's own list (class A, stateless).
/// Provisional until S1-2.
pub const INCLUDE_GAS_LIMIT: u64 = 30_000_000;

/// O5 / D9: gas one accepting block may execute across its whole mergeset.
/// The header `gas_limit` of a block that accepts a mergeset must equal it.
/// Provisional until S1-2.
pub const ACCEPT_GAS_LIMIT: u64 = 60_000_000;

/// O3: how the per-chain-block emission R(h) is attributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmissionAttribution {
    /// Spec default: R(height(C)) is split equally among the blue blocks of
    /// Mergeset(C) that have a proposer; the integer remainder goes to the
    /// first share (SP's, when SP has a proposer). Emission per unit of time
    /// is independent of DAG width.
    SplitAmongBlues,
    /// Alternative: every blue block of Mergeset(C) is credited the full R(h).
    /// Emission then scales with the number of parallel producers.
    FullPerBlue,
}

/// O3 (spec default).
pub const EMISSION_ATTRIBUTION: EmissionAttribution = EmissionAttribution::SplitAmongBlues;

/// O4: who earns the priority fees of transactions included in a RED block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedFeeRecipient {
    /// Spec default (Kaspa coinbase): the accepting chain block C.
    AcceptingBlock,
    /// ADR CV-4a's original wording: the including (red) block's proposer.
    IncludingBlock,
}

/// O4 (spec default).
pub const RED_FEE_RECIPIENT: RedFeeRecipient = RedFeeRecipient::AcceptingBlock;

/// R1: when a chain block's commitments (state_root, accepted_root,
/// receipt_root, gas_used) are checked against execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentValidation {
    /// Spec default (Kaspa, D11): admission checks headers and class A only;
    /// a block's commitments are checked by executing its mergeset when the
    /// node's applied selected chain reaches it (drain, reorg, rebuild).
    /// The reviewer's alternative, eager validation at admission (every
    /// block executes its mergeset when admitted, about N times the work per
    /// slot), is not implemented.
    Lazy,
}

/// R1 (spec default).
pub const COMMITMENT_VALIDATION: CommitmentValidation = CommitmentValidation::Lazy;

/// R2: what a block's header commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptanceModel {
    /// Spec default (Kaspa, D6): block B commits the state after executing
    /// Mergeset(B) on post(SP(B)); B's own transactions run when its chain
    /// child accepts B. The reviewer's alternative, self-acceptance (C runs
    /// Mergeset*(C) and then its own list), is not implemented.
    Kaspa,
}

/// R2 (spec default).
pub const ACCEPTANCE_MODEL: AcceptanceModel = AcceptanceModel::Kaspa;

/// Domain tag of `accepted_root` (spec 06 §3.9).
pub const ACCEPTED_ROOT_DOMAIN: &[u8] = b"CITRATE-ACCEPTED-V1";

/// Domain tag of the v3 `receipt_root` (spec 06 §3.9).
pub const RECEIPT_ROOT_DOMAIN: &[u8] = b"CITRATE-RECEIPTS-V3";

/// The color of an accepted block relative to its accepting block
/// (spec 06 §3.11 `inclusion_color`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum InclusionColor {
    /// The accepting block's selected parent (always blue).
    SelectedParent,
    /// A blue block of `Mergeset*(C)`.
    Blue,
    /// A red block of `Mergeset*(C)`.
    Red,
}

impl InclusionColor {
    /// The color's code in commitments and stored records.
    pub fn code(self) -> u8 {
        match self {
            Self::SelectedParent => 0,
            Self::Blue => 1,
            Self::Red => 2,
        }
    }

    /// Whether the block counts as blue (SP or a blue of `Mergeset*`).
    pub fn is_blue(self) -> bool {
        !matches!(self, Self::Red)
    }

    /// The RPC spelling (spec 06 §5.4).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelectedParent => "selected_parent",
            Self::Blue => "blue",
            Self::Red => "red",
        }
    }
}

/// Class-A body rules (spec 06 §3.4) that need no state: the block's own
/// transaction list fits INCLUDE_GAS_LIMIT, pays at least `base_fee`, and
/// repeats neither a tx hash nor a (sender, nonce) pair. `Err` names the
/// first violation. Signature, chain-id and tx-root checks live with the
/// existing PBA body rules.
pub fn class_a_violation(txs: &[crate::types::Transaction], base_fee: u64) -> Result<(), String> {
    let mut gas: u64 = 0;
    let mut hashes = std::collections::HashSet::with_capacity(txs.len());
    let mut sender_nonces = std::collections::HashSet::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        gas = gas
            .checked_add(tx.gas_limit)
            .ok_or_else(|| format!("tx #{i}: gas limit sum overflows"))?;
        if gas > INCLUDE_GAS_LIMIT {
            return Err(format!(
                "tx #{i}: block gas limit sum {gas} exceeds INCLUDE_GAS_LIMIT {INCLUDE_GAS_LIMIT}"
            ));
        }
        if tx.gas_price < base_fee {
            return Err(format!(
                "tx #{i} ({}): gas price {} below base fee {base_fee}",
                tx.hash, tx.gas_price
            ));
        }
        if !hashes.insert(tx.hash) {
            return Err(format!("tx #{i} ({}): repeated in the block", tx.hash));
        }
        if !sender_nonces.insert((*tx.from.as_bytes(), tx.nonce)) {
            return Err(format!(
                "tx #{i} ({}): repeats (sender, nonce {}) in the block",
                tx.hash, tx.nonce
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Hash, PublicKey, Transaction};

    fn tx(h: u8, from: u8, nonce: u64, gas: u64, price: u64) -> Transaction {
        Transaction {
            hash: Hash::new([h; 32]),
            from: PublicKey::new([from; 32]),
            nonce,
            gas_limit: gas,
            gas_price: price,
            ..Default::default()
        }
    }

    #[test]
    fn class_a_accepts_a_clean_list() {
        let txs = vec![tx(1, 1, 0, 21_000, 10), tx(2, 1, 1, 21_000, 10)];
        assert!(class_a_violation(&txs, 10).is_ok());
    }

    #[test]
    fn class_a_rejects_include_gas_overflow_repeats_and_low_price() {
        let big = vec![tx(1, 1, 0, INCLUDE_GAS_LIMIT, 10), tx(2, 2, 0, 1, 10)];
        assert!(class_a_violation(&big, 10).is_err());
        let dup_hash = vec![tx(1, 1, 0, 21_000, 10), tx(1, 2, 0, 21_000, 10)];
        assert!(class_a_violation(&dup_hash, 10).is_err());
        let dup_nonce = vec![tx(1, 1, 0, 21_000, 10), tx(2, 1, 0, 21_000, 10)];
        assert!(class_a_violation(&dup_nonce, 10).is_err());
        let cheap = vec![tx(1, 1, 0, 21_000, 9)];
        assert!(class_a_violation(&cheap, 10).is_err());
    }

    #[test]
    fn open_question_defaults_are_the_spec_defaults() {
        assert_eq!(EMISSION_ATTRIBUTION, EmissionAttribution::SplitAmongBlues);
        assert_eq!(RED_FEE_RECIPIENT, RedFeeRecipient::AcceptingBlock);
        assert_eq!(COMMITMENT_VALIDATION, CommitmentValidation::Lazy);
        assert_eq!(ACCEPTANCE_MODEL, AcceptanceModel::Kaspa);
        assert_eq!(
            (INCLUDE_GAS_LIMIT, ACCEPT_GAS_LIMIT),
            (30_000_000, 60_000_000)
        );
    }

    #[test]
    fn accept_limit_holds_two_full_blocks() {
        assert_eq!(ACCEPT_GAS_LIMIT, 2 * INCLUDE_GAS_LIMIT);
    }
}
