// citrate/core/execution/tests/mergeset_execution.rs
//
// r1007 S3-3b (spec 06 §3.4-§3.6, §3.9, reviewer R10): the outcome classes
// of `Executor::execute_mergeset`, directly on the executor.
//
//   * B1 nonce (a duplicate across members is a nonce skip), B2 balance,
//     B3 the ACCEPT gas budget, B4 a sender with code: skipped, no fee, no
//     nonce bump, no receipt;
//   * C (executed, failed) and D (executed, ok): a receipt, the fee, the
//     nonce bump, for every transaction shape the executor runs here
//     (transfer, call, deploy, a failing call);
//   * the receipts carry the acceptance fields, and the commitments are the
//     spec encodings over executed occurrences only.

use std::sync::Arc;

use citrate_consensus::acceptance::{InclusionColor, ACCEPT_GAS_LIMIT};
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::acceptance::{
    accepted_root, receipt_root, AcceptedBlock, OccurrenceOutcome, SkipReason,
};
use citrate_execution::executor::Emission;
use citrate_execution::types::{Address, ExecutionError, TransactionReceipt};
use citrate_execution::{Executor, StateDB};
use primitive_types::U256;

const PRICE: u64 = 1_000_000_000;
const FUND: u128 = 1_000_000_000_000_000_000_000;

fn addr(b: u8) -> Address {
    Address([b; 20])
}

fn key(a: Address) -> PublicKey {
    let mut k = [0u8; 32];
    k[..20].copy_from_slice(&a.0);
    PublicKey::new(k)
}

fn tx(
    tag: u8,
    from: Address,
    nonce: u64,
    to: Option<Address>,
    data: Vec<u8>,
    gas: u64,
) -> Transaction {
    let mut h = [tag; 32];
    h[1..9].copy_from_slice(&nonce.to_be_bytes());
    Transaction {
        hash: Hash::new(h),
        nonce,
        from: key(from),
        to: to.map(key),
        value: 7,
        gas_limit: gas,
        gas_price: PRICE,
        data,
        signature: Signature::new([1; 64]),
        chain_id: Some(40204),
        ecdsa_verified: true,
        ..Default::default()
    }
}

fn block(tag: u8, height: u64, txs: Vec<Transaction>) -> Block {
    let mut b = BlockBuilder::new()
        .hash(Hash::new([tag; 32]))
        .height(height)
        .coinbase([0xC0u8.wrapping_add(tag); 20])
        .base_fee_per_gas(PRICE)
        .transactions(txs)
        .build_unhashed();
    b.header.gas_limit = ACCEPT_GAS_LIMIT;
    b
}

fn no_emission(
    _h: u64,
    _t: &[Transaction],
    _r: &[TransactionReceipt],
) -> Result<Emission, ExecutionError> {
    Ok(Emission {
        validator: U256::zero(),
        treasury: addr(0x11),
        treasury_amount: U256::zero(),
    })
}

fn funded(accts: &[Address]) -> Executor {
    let e = Executor::new(Arc::new(StateDB::new()));
    for a in accts {
        e.set_balance(a, U256::from(FUND));
    }
    e
}

#[tokio::test]
async fn skips_change_nothing_and_executed_outcomes_bump_the_nonce() {
    let (alice, bob, carol, poor, code_sender) =
        (addr(0xA1), addr(0xB2), addr(0xC3), addr(0xD4), addr(0xE5));
    let reverter = addr(0xEF);
    let exec = funded(&[alice, bob, carol, code_sender]);
    exec.set_balance(&poor, U256::from(1_000u64));
    // `revert(0, 0)`: every call to it fails (class C).
    exec.set_code(&reverter, vec![0x60, 0x00, 0x60, 0x00, 0xfd]);
    // A sender with code (B4).
    exec.set_code(&code_sender, vec![0x00]);

    let t_ok = tx(1, alice, 0, Some(bob), vec![], 21_000);
    let t_dup = t_ok.clone(); // the same tx in a later member: B1
    let t_gap = tx(2, carol, 5, Some(bob), vec![], 21_000); // B1 nonce gap
    let t_poor = tx(3, poor, 0, Some(bob), vec![], 21_000); // B2
    let t_code = tx(4, code_sender, 0, Some(bob), vec![], 21_000); // B4
    let t_fail = tx(5, carol, 0, Some(reverter), vec![0x01], 50_000); // C
    let t_deploy = tx(
        6,
        alice,
        1,
        None,
        vec![0x60, 0x00, 0x60, 0x00, 0xf3],
        100_000,
    ); // D
    let sp = block(0x10, 1, vec![t_ok.clone(), t_gap.clone()]);
    let other = block(
        0x20,
        1,
        vec![
            t_dup,
            t_poor.clone(),
            t_code.clone(),
            t_fail.clone(),
            t_deploy.clone(),
        ],
    );
    let c = block(0x30, 2, vec![]);
    let members = [
        AcceptedBlock {
            block: &sp,
            color: InclusionColor::SelectedParent,
        },
        AcceptedBlock {
            block: &other,
            color: InclusionColor::Red,
        },
    ];
    let before_poor = exec.get_balance(&poor);
    let before_code = exec.get_balance(&code_sender);
    let out = exec
        .execute_mergeset(&c.header, &members, &no_emission, Default::default())
        .await
        .expect("execute");

    let outcomes: Vec<OccurrenceOutcome> = out.occurrences.iter().map(|o| o.outcome).collect();
    assert_eq!(
        outcomes,
        vec![
            OccurrenceOutcome::Executed { status: true },
            OccurrenceOutcome::Skipped(SkipReason::Nonce),
            OccurrenceOutcome::Skipped(SkipReason::Nonce),
            OccurrenceOutcome::Skipped(SkipReason::Balance),
            OccurrenceOutcome::Skipped(SkipReason::Code),
            OccurrenceOutcome::Executed { status: false },
            OccurrenceOutcome::Executed { status: true },
        ]
    );
    // Skips: no fee, no nonce bump, no receipt.
    assert_eq!(exec.get_balance(&poor), before_poor);
    assert_eq!(exec.get_nonce(&poor), 0);
    assert_eq!(exec.get_balance(&code_sender), before_code);
    assert_eq!(exec.get_nonce(&code_sender), 0);
    let receipted: Vec<Hash> = out.receipts.iter().map(|r| r.tx_hash).collect();
    assert_eq!(receipted, vec![t_ok.hash, t_fail.hash, t_deploy.hash]);
    // R10: every executed outcome bumps the nonce, failed ones included.
    assert_eq!(exec.get_nonce(&alice), 2, "transfer + deploy");
    assert_eq!(exec.get_nonce(&carol), 1, "the failed call");
    // C pays its whole gas limit; the failed call moved no value.
    assert_eq!(
        exec.get_balance(&carol),
        U256::from(FUND) - U256::from(50_000u64 * PRICE)
    );
    // Acceptance fields and the commitments.
    let acc: Vec<(u64, InclusionColor, u64)> = out
        .receipts
        .iter()
        .map(|r| {
            let a = r.acceptance.as_ref().expect("acceptance");
            (
                a.transaction_index,
                a.inclusion_color,
                a.cumulative_gas_used,
            )
        })
        .collect();
    let g0 = out.receipts[0].gas_used;
    let g1 = out.receipts[1].gas_used;
    assert_eq!(acc[0], (0, InclusionColor::SelectedParent, g0));
    assert_eq!(acc[1], (1, InclusionColor::Red, g0 + g1));
    assert_eq!(
        out.gas_used,
        out.receipts.iter().map(|r| r.gas_used).sum::<u64>()
    );
    assert_eq!(out.accepted_root, accepted_root(&out.occurrences));
    assert_eq!(out.receipt_root, receipt_root(&out.receipts));
}

#[tokio::test]
async fn gas_budget_overflow_skips_tail_deterministically() {
    let senders: Vec<Address> = (0..5u8).map(|i| addr(0x40 + i)).collect();
    let reverter = addr(0xEF);
    let exec = funded(&senders);
    exec.set_code(&reverter, vec![0x60, 0x00, 0x60, 0x00, 0xfd]);
    // Five failing calls of 20M each: charged 20M each, so three fit 60M.
    let txs: Vec<Transaction> = senders
        .iter()
        .enumerate()
        .map(|(i, s)| {
            tx(
                0x50 + i as u8,
                *s,
                0,
                Some(reverter),
                vec![0x01],
                20_000_000,
            )
        })
        .collect();
    let sp = block(0x60, 1, txs);
    let c = block(0x70, 2, vec![]);
    let members = [AcceptedBlock {
        block: &sp,
        color: InclusionColor::SelectedParent,
    }];
    let out = exec
        .execute_mergeset(&c.header, &members, &no_emission, Default::default())
        .await
        .expect("execute");
    assert_eq!(out.gas_used, ACCEPT_GAS_LIMIT);
    let skipped: Vec<usize> = out
        .occurrences
        .iter()
        .enumerate()
        .filter(|(_, o)| o.outcome == OccurrenceOutcome::Skipped(SkipReason::Gas))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(skipped, vec![3, 4], "the tail past the budget, in order");
    for s in &senders[3..] {
        assert_eq!(exec.get_nonce(s), 0);
        assert_eq!(exec.get_balance(s), U256::from(FUND));
    }
}
