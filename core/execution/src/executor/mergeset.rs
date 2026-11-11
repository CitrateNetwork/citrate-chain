// citrate/core/execution/src/executor/mergeset.rs
//
// r1007 S3-3b (ADR CV-4a, spec 06 §3): mergeset execution. The ONE function
// the producer (sealing C) and every applier (draining, reorging, rebuilding
// to C) run: execute the transactions of Mergeset(C), in consensus order, on
// post(SP(C)), with class-B skips, the ACCEPT gas budget and settlement per
// recipient block; then commit (state_root, accepted_root, receipt_root,
// gas_used).

// The parent module's PANIC-S1 lints apply here too.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use super::{DeferGuard, Executor, ReceiptIndexBatch};
use crate::acceptance::{
    accepted_root, receipt_root, AcceptedBlock, MergesetExecution, Occurrence, OccurrenceOutcome,
    SkipReason,
};
use crate::types::{Address, ExecutionError, ReceiptAcceptance, TransactionReceipt};
use citrate_consensus::acceptance::{
    EmissionAttribution, InclusionColor, RedFeeRecipient, ACCEPT_GAS_LIMIT, EMISSION_ATTRIBUTION,
    RED_FEE_RECIPIENT,
};
use citrate_consensus::types::{Block, BlockHeader, Hash, Transaction};
use primitive_types::U256;
use tracing::warn;

/// The per-chain-block emission R(h) (spec 06 §3.8 step 3): the validator
/// part, split among the accepted blue blocks, and the treasury part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emission {
    pub validator: U256,
    pub treasury: Address,
    pub treasury_amount: U256,
}

/// The node's emission rule for the accepting block at `height`, from the
/// transactions it executed and their receipts (the reward bonuses count
/// executed transactions). Injected so this crate stays free of economics,
/// exactly as [`super::RewardFn`] is for the legacy single-block apply.
pub type EmissionFn<'a> = &'a (dyn Fn(u64, &[Transaction], &[TransactionReceipt]) -> Result<Emission, ExecutionError>
         + Send
         + Sync);

/// Integer split of `total` into `n` equal shares; the remainder goes to the
/// first share (spec 06 §3.8 step 3: SP's share).
fn split_equally(total: U256, n: usize) -> Vec<U256> {
    if n == 0 {
        return Vec::new();
    }
    let n_u = U256::from(n as u64);
    let each = total.checked_div(n_u).unwrap_or_default();
    let rem = total.checked_rem(n_u).unwrap_or_default();
    let mut out = vec![each; n];
    if let Some(first) = out.first_mut() {
        *first = first.saturating_add(rem);
    }
    out
}

/// One fee-and-reward recipient of an accepting block (spec 06 §3.8).
struct Recipient {
    proposer: [u8; 32],
    coinbase: [u8; 20],
    /// The block whose transactions' priority fees this recipient earns.
    fee_blocks: Vec<Hash>,
    /// Emission share (validator part), already split.
    emission: U256,
    /// §R' subsidy share, already split.
    subsidy: U256,
}

impl Executor {
    /// Execute `members` (Mergeset(C) in consensus order) for the accepting
    /// block whose header is `header`, on the current world state, and settle.
    /// Leaves the post(C) state in the executor; the CALLER owns rollback
    /// (snapshot/restore or a production round). Receipts carry
    /// `header.block_hash` (the zero hash while the producer is sealing).
    ///
    /// Determinism: every input is consensus data (headers and bodies of the
    /// mergeset, C's header fields other than its own roots, the shared reward
    /// policy and world state).
    ///
    /// `block_hashes` answers BLOCKHASH (spec 06 §3.7): height → hash of C's
    /// selected-chain ancestor, for the 256 heights below height(C).
    pub async fn execute_mergeset(
        &self,
        header: &BlockHeader,
        members: &[AcceptedBlock<'_>],
        emission: EmissionFn<'_>,
        block_hashes: std::collections::HashMap<u64, [u8; 32]>,
    ) -> Result<MergesetExecution, ExecutionError> {
        let _defer = DeferGuard::engage(&self.defer_persist);
        // The EVM context for every tx C accepts (spec 06 §3.7): NUMBER and
        // TIMESTAMP from C, COINBASE = C.coinbase, PREVRANDAO = C's VRF output,
        // BLOCKHASH(n) = C's selected-chain ancestor at n, GASLIMIT =
        // ACCEPT_GAS_LIMIT.
        let ctx_block = Block {
            header: header.clone(),
            ..citrate_consensus::types::BlockBuilder::new().build_unhashed()
        };
        self.set_block_context(crate::revm_adapter::BlockContext {
            coinbase: header.coinbase,
            prevrandao: *header.vrf_reveal.output.as_bytes(),
            block_hashes,
            // GASLIMIT (spec 06 §3.7): the budget C executes under.
            gas_limit: Some(ACCEPT_GAS_LIMIT),
        });
        let pba = self.pba_hardening();
        let base_fee = header.base_fee_per_gas;

        let mut occurrences: Vec<Occurrence> = Vec::new();
        let mut executed: Vec<Transaction> = Vec::new();
        let mut receipts: Vec<TransactionReceipt> = Vec::new();
        let mut cumulative: u64 = 0;
        let mut log_index: u64 = 0;
        for member in members {
            let block = member.block;
            for (i, tx) in block.transactions.iter().enumerate() {
                let skip = self.class_b_precheck(tx, pba, header.height, base_fee, cumulative);
                let outcome = match skip {
                    Some(reason) => OccurrenceOutcome::Skipped(reason),
                    None => match self.execute_transaction(&ctx_block, tx).await {
                        Ok(mut receipt) => {
                            cumulative = cumulative.saturating_add(receipt.gas_used);
                            receipt.acceptance = Some(ReceiptAcceptance {
                                including_block_hash: block.header.block_hash,
                                including_block_height: block.header.height,
                                inclusion_color: member.color,
                                transaction_index: executed.len() as u64,
                                cumulative_gas_used: cumulative,
                                first_log_index: log_index,
                            });
                            log_index = log_index.saturating_add(receipt.logs.len() as u64);
                            let status = receipt.status;
                            receipts.push(receipt);
                            executed.push(tx.clone());
                            OccurrenceOutcome::Executed { status }
                        }
                        Err(ExecutionError::InvalidNonce { .. }) => {
                            OccurrenceOutcome::Skipped(SkipReason::Nonce)
                        }
                        Err(ExecutionError::InsufficientBalance { .. }) => {
                            OccurrenceOutcome::Skipped(SkipReason::Balance)
                        }
                        // Pre-dispatch rejections (an undecodable type, a
                        // nonce at u64::MAX): deterministic and state-free,
                        // the journal was discarded.
                        Err(ExecutionError::InvalidInput | ExecutionError::Overflow(_)) => {
                            OccurrenceOutcome::Skipped(SkipReason::Invalid)
                        }
                        // Anything else is not a property of the transaction
                        // (a node-local fault): fail the acceptance rather
                        // than record a skip another node would not.
                        Err(e) => return Err(e),
                    },
                };
                occurrences.push(Occurrence {
                    tx_hash: tx.hash,
                    including_block: block.header.block_hash,
                    including_height: block.header.height,
                    color: member.color,
                    index_in_block: i as u64,
                    outcome,
                });
            }
        }

        self.settle_accepting_block(header, members, &executed, &receipts, emission)
            .await?;

        let accepted = accepted_root(&occurrences);
        let receipt_commitment = receipt_root(&receipts);
        let state_root = self.calculate_state_root();
        Ok(MergesetExecution {
            occurrences,
            executed,
            receipts,
            gas_used: cumulative,
            accepted_root: accepted,
            receipt_root: receipt_commitment,
            state_root,
        })
    }

    /// The class-B (and leftover stateless) checks made before a tx runs
    /// (spec 06 §3.4). Nonce and balance (B1, B2) are decided by
    /// `execute_transaction` itself, against the same journal-first state.
    fn class_b_precheck(
        &self,
        tx: &Transaction,
        pba: citrate_consensus::hardening::PbaHardening,
        height: u64,
        base_fee: u64,
        cumulative: u64,
    ) -> Option<SkipReason> {
        // Signature, canonical id and chain id: admission checked the body of
        // every stored block; a block that reached the DAG another way must
        // not have its txs run as someone else.
        if pba.active_at(height)
            && citrate_consensus::tx_auth::verify_for_block(tx, self.chain_id).is_err()
        {
            return Some(SkipReason::Invalid);
        }
        if tx.gas_price < base_fee {
            return Some(SkipReason::Invalid);
        }
        // B3: the remaining ACCEPT budget.
        if tx.gas_limit > ACCEPT_GAS_LIMIT.saturating_sub(cumulative) {
            return Some(SkipReason::Gas);
        }
        // B4: EIP-3607, the sender must not have code.
        let sender = crate::address_utils::normalize_address(&tx.from);
        let code = self.resident_account(&sender).code_hash;
        if code != Hash::default() && code != empty_code_hash() {
            return Some(SkipReason::Code);
        }
        None
    }

    /// Spec 06 §3.8: settlement of the accepting block C, after its last
    /// executed transaction.
    ///
    /// 1. Base fees burn (they were never credited to anyone).
    /// 2. Emission R(height(C)) is attributed per [`EMISSION_ATTRIBUTION`]
    ///    among the blue blocks of Mergeset(C) that have a proposer (genesis
    ///    has none: its share is not minted); the treasury part is credited.
    /// 3. With the §R' policy active: each blue recipient X vests the
    ///    priority fees of the executed txs X included plus its subsidy
    ///    share; red blocks' priority fees go per [`RED_FEE_RECIPIENT`].
    ///    A recipient whose coinbase is not the registered staker of its
    ///    proposer in the governing snapshot earns nothing (its emission
    ///    share and vest burn): one merged block cannot disqualify C, and no
    ///    proposer can redirect a reward.
    async fn settle_accepting_block(
        &self,
        header: &BlockHeader,
        members: &[AcceptedBlock<'_>],
        executed: &[Transaction],
        receipts: &[TransactionReceipt],
        emission: EmissionFn<'_>,
    ) -> Result<(), ExecutionError> {
        use crate::block_rewards as br;
        let height = header.height;
        self.state_db.set_root_height(height);

        let em = emission(height, executed, receipts)?;

        // The §R' policy governing height(C) (the same gating as
        // `settle_block_rewards`).
        let policy = match self.reward_policy.read().clone() {
            Some(p) if height >= p.activation_height => Some(p),
            Some(_) => None,
            None => {
                let activation = self
                    .validator_activation_height
                    .load(std::sync::atomic::Ordering::SeqCst);
                if height >= activation {
                    return Err(ExecutionError::RewardSettlement(format!(
                        "VALIDATOR-S1 reward policy unmaterialized at height {height} \
                         (>= activation {activation}); refusing to settle a divergent \
                         (policy-less) block — epoch snapshot must be rehydrated"
                    )));
                }
                None
            }
        };
        if policy.is_some() && header.base_fee_per_gas != br::CANONICAL_BASE_FEE_PER_GAS {
            return Err(ExecutionError::RewardSettlement(format!(
                "base_fee_per_gas {} != canonical {}",
                header.base_fee_per_gas,
                br::CANONICAL_BASE_FEE_PER_GAS
            )));
        }

        // Blue recipients, in mergeset order (SP first).
        let blues: Vec<&Block> = members
            .iter()
            .filter(|m| m.color.is_blue() && m.block.header.height > 0)
            .map(|m| m.block)
            .collect();
        let emission_shares = match EMISSION_ATTRIBUTION {
            EmissionAttribution::SplitAmongBlues => split_equally(em.validator, blues.len()),
            EmissionAttribution::FullPerBlue => vec![em.validator; blues.len()],
        };
        let subsidy_total = policy.as_ref().map(|p| p.block_subsidy).unwrap_or_default();
        let subsidy_shares = match EMISSION_ATTRIBUTION {
            EmissionAttribution::SplitAmongBlues => split_equally(subsidy_total, blues.len()),
            EmissionAttribution::FullPerBlue => vec![subsidy_total; blues.len()],
        };
        let mut recipients: Vec<Recipient> = blues
            .iter()
            .zip(emission_shares.iter().zip(subsidy_shares.iter()))
            .map(|(b, (e, s))| Recipient {
                proposer: *b.header.proposer_pubkey.as_bytes(),
                coinbase: b.header.coinbase,
                fee_blocks: vec![b.header.block_hash],
                emission: *e,
                subsidy: *s,
            })
            .collect();
        let reds: Vec<&Block> = members
            .iter()
            .filter(|m| m.color == InclusionColor::Red)
            .map(|m| m.block)
            .collect();
        if !reds.is_empty() {
            match RED_FEE_RECIPIENT {
                RedFeeRecipient::AcceptingBlock => recipients.push(Recipient {
                    proposer: *header.proposer_pubkey.as_bytes(),
                    coinbase: header.coinbase,
                    fee_blocks: reds.iter().map(|b| b.header.block_hash).collect(),
                    emission: U256::zero(),
                    subsidy: U256::zero(),
                }),
                RedFeeRecipient::IncludingBlock => {
                    for b in &reds {
                        recipients.push(Recipient {
                            proposer: *b.header.proposer_pubkey.as_bytes(),
                            coinbase: b.header.coinbase,
                            fee_blocks: vec![b.header.block_hash],
                            emission: U256::zero(),
                            subsidy: U256::zero(),
                        });
                    }
                }
            }
        }

        // Treasury part of R(h).
        if em.treasury_amount > U256::zero() {
            let bal = self.resident_account(&em.treasury).balance;
            let credited = bal.checked_add(em.treasury_amount).ok_or_else(|| {
                ExecutionError::RewardSettlement("treasury reward overflows balance".into())
            })?;
            self.set_balance(&em.treasury, credited);
        }

        for r in &recipients {
            let eligible = match &policy {
                None => true,
                Some(p) => p.staker_of.get(&r.proposer) == Some(&r.coinbase),
            };
            if !eligible {
                warn!(
                    "mergeset settlement @ {height}: proposer {} with coinbase {} is not its \
                     registered staker; its share burns",
                    hex::encode(r.proposer),
                    hex::encode(r.coinbase)
                );
                continue;
            }
            if r.emission > U256::zero() {
                let addr = Address(r.coinbase);
                let bal = self.resident_account(&addr).balance;
                let credited = bal.checked_add(r.emission).ok_or_else(|| {
                    ExecutionError::RewardSettlement("emission share overflows balance".into())
                })?;
                self.set_balance(&addr, credited);
            }
            let Some(p) = &policy else { continue };
            let mut fee_txs: Vec<Transaction> = Vec::new();
            let mut fee_receipts: Vec<TransactionReceipt> = Vec::new();
            for (tx, rc) in executed.iter().zip(receipts.iter()) {
                let including = rc.acceptance.as_ref().map(|a| a.including_block_hash);
                if including.is_some_and(|h| r.fee_blocks.contains(&h)) {
                    fee_txs.push(tx.clone());
                    fee_receipts.push(rc.clone());
                }
            }
            let pool = br::compute_priority_pool(&fee_txs, &fee_receipts, header.base_fee_per_gas)?;
            let share = br::total_vested(pool, p.priority_fee_share_bps, r.subsidy);
            if share.is_zero() {
                continue;
            }
            self.credit_validator_reward(p.reward_minter, p.registry, &r.proposer, share, height)
                .await?;
        }
        Ok(())
    }

    /// Apply chain block `block`: execute its mergeset `members` on the
    /// current state (post(SP(block))), check the four commitments (spec 06
    /// §3.10), and with `persist` commit state, receipts and the applied tip
    /// atomically. On any error world state is restored and nothing is
    /// written. Returns the verified state root and the execution.
    ///
    /// `verify` false is the trusted local replay (`apply_block_trusted`):
    /// the full-trie state root is not recomputed, the other commitments are.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_accepting_block(
        &self,
        block: &Block,
        members: &[AcceptedBlock<'_>],
        emission: EmissionFn<'_>,
        block_hashes: std::collections::HashMap<u64, [u8; 32]>,
        persist: bool,
        verify: bool,
    ) -> Result<(Hash, MergesetExecution), ExecutionError> {
        let _defer_guard = DeferGuard::engage(&self.defer_persist);
        // The chain block's own list is class-A clean (it is executed later,
        // when its chain child accepts it): tx root binds the body, the list
        // fits INCLUDE_GAS_LIMIT and repeats nothing.
        self.verify_block_body_structure(block)?;
        if let Err(e) = citrate_consensus::acceptance::class_a_violation(
            &block.transactions,
            block.header.base_fee_per_gas,
        ) {
            return Err(ExecutionError::InvalidBlockBody(e));
        }
        let model_job_generation = self.state_db.model_job_generation();
        let snapshot = self.state_db.snapshot();
        let prev_ctx = self.get_block_context();
        let fail = |e: ExecutionError, snapshot| {
            self.state_db.restore(snapshot);
            self.set_block_context(prev_ctx.clone());
            Err(e)
        };
        let mut exec = match self
            .execute_mergeset(&block.header, members, emission, block_hashes)
            .await
        {
            Ok(x) => x,
            Err(e) => return fail(e, snapshot),
        };
        exec.stamp(block.header.block_hash, block.header.height);

        let full = |h: &Hash| format!("0x{}", hex::encode(h.as_bytes()));
        let mismatch = if exec.accepted_root != block.accepted_root {
            Some((
                "accepted_root",
                full(&block.accepted_root),
                full(&exec.accepted_root),
            ))
        } else if exec.receipt_root != block.receipt_root {
            Some((
                "receipt_root",
                full(&block.receipt_root),
                full(&exec.receipt_root),
            ))
        } else if exec.gas_used != block.header.gas_used {
            Some((
                "gas_used",
                block.header.gas_used.to_string(),
                exec.gas_used.to_string(),
            ))
        } else if block.header.gas_limit != ACCEPT_GAS_LIMIT {
            Some((
                "gas_limit",
                block.header.gas_limit.to_string(),
                ACCEPT_GAS_LIMIT.to_string(),
            ))
        } else {
            None
        };
        if let Some((field, expected, got)) = mismatch {
            return fail(
                ExecutionError::AcceptanceCommitmentMismatch {
                    field,
                    expected,
                    got,
                },
                snapshot,
            );
        }
        let root = if verify {
            if exec.state_root != block.state_root {
                let got = exec.state_root;
                return fail(
                    ExecutionError::StateRootMismatch {
                        expected: block.state_root,
                        got,
                    },
                    snapshot,
                );
            }
            exec.state_root
        } else {
            block.state_root
        };
        if !persist {
            return Ok((root, exec));
        }
        let index = ReceiptIndexBatch::for_accepting_block(block, &exec);
        let models_jobs = self
            .state_db
            .model_job_pre_images(&snapshot, model_job_generation);
        if let Err(e) = self
            .persist_state_changes_with_undo(
                Some((block.header.block_hash, block.header.height)),
                &index,
                Some(&models_jobs),
            )
            .await
        {
            return fail(
                ExecutionError::Reverted(format!("persist after apply_accepting_block: {e}")),
                snapshot,
            );
        }
        Ok((root, exec))
    }
}

/// keccak256 of the empty byte string: the code hash some paths store for an
/// account deployed with empty code. Such an account has no code (EIP-3607).
fn empty_code_hash() -> Hash {
    use sha3::{Digest, Keccak256};
    Hash::new(Keccak256::digest([]).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_gives_the_remainder_to_the_first_share_and_sums_to_total() {
        let s = split_equally(U256::from(10u64), 3);
        assert_eq!(
            s,
            vec![U256::from(4u64), U256::from(3u64), U256::from(3u64)]
        );
        assert!(split_equally(U256::from(10u64), 0).is_empty());
        let total = split_equally(U256::from(1_000_003u64), 7)
            .into_iter()
            .fold(U256::zero(), |a, b| a + b);
        assert_eq!(total, U256::from(1_000_003u64));
    }
}
