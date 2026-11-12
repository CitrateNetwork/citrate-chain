//! The reference's own state transition on a hand-built DAG (spec 06 §3.2,
//! §3.4, §3.5, §3.8), independent of the node: two siblings carry the same
//! transfer and a follow-up nonce; the block that merges them executes the
//! first copy (its selected parent's), skips the second with no fee, runs the
//! follow-up, and pays R(h) to its blue blocks only.

use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Transaction};
use citrate_mergeset_ref::exec::{self, State, TRANSFER_GAS, TREASURY};
use citrate_mergeset_ref::ghostdag::{Color, Dag, WORK_UNIT};
use citrate_mergeset_ref::RefConfig;
use primitive_types::U256;

const SENDER: [u8; 20] = [0x51; 20];
const TO: [u8; 20] = [0x71; 20];
const PRICE: u64 = 1_000_000_000;

fn key(a: [u8; 20]) -> PublicKey {
    let mut k = [0u8; 32];
    k[..20].copy_from_slice(&a);
    PublicKey::new(k)
}

fn transfer(tag: u8, nonce: u64) -> Transaction {
    Transaction {
        hash: Hash::new([tag; 32]),
        nonce,
        from: key(SENDER),
        to: Some(key(TO)),
        value: 1_000,
        gas_limit: TRANSFER_GAS,
        gas_price: PRICE,
        ..Default::default()
    }
}

fn block(tag: u8, height: u64, sp: Hash, merges: Vec<Hash>, txs: Vec<Transaction>) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([tag; 32]))
        .parent(sp)
        .merge_parents(merges)
        .height(height)
        .coinbase([tag; 20])
        .transactions(txs)
        .build_unhashed()
}

#[test]
fn merging_block_executes_first_copy_skips_duplicate_and_pays_blues() {
    let g = block(0x10, 0, Hash::default(), vec![], vec![]);
    let t = transfer(0xA1, 0);
    let u = transfer(0xA2, 1);
    let a = block(0x20, 1, g.header.block_hash, vec![], vec![t.clone()]);
    let b = block(
        0x30,
        1,
        g.header.block_hash,
        vec![],
        vec![t.clone(), u.clone()],
    );
    // C names a as selected parent; the reference derives its own.
    let c = block(
        0x40,
        2,
        a.header.block_hash,
        vec![b.header.block_hash],
        vec![],
    );
    let blocks = vec![g, a.clone(), b.clone(), c.clone()];
    let mut dag = Dag::new(&blocks).expect("dag");
    dag.color_all(18).expect("color");
    let rec = &dag.records[&c.header.block_hash];
    // a and b tie on blue work and VRF; the larger hash (b) is the SP.
    assert_eq!(rec.selected_parent, Some(b.header.block_hash));
    assert_eq!(rec.blue_score, 3, "G, a and b are blue in past(C)");
    assert_eq!(rec.blue_work, 3 * WORK_UNIT);
    let order = dag.ordered_mergeset(&c.header.block_hash);
    assert_eq!(
        order,
        vec![
            (b.header.block_hash, Color::SelectedParent),
            (a.header.block_hash, Color::Blue)
        ]
    );
    let members: Vec<(&Block, Color)> =
        order.iter().map(|(h, col)| (dag.blocks[h], *col)).collect();

    let fund = U256::from(10u64).pow(U256::from(24u64));
    let cfg = RefConfig {
        chain_id: 40204,
        k: 18,
        genesis_alloc: vec![(SENDER, fund)],
        reward_policy: None,
        pba_hardening_height: None,
        supply_hardening_height: None,
        storage_root_hardening_height: None,
        genesis_code: Vec::new(),
        evm: citrate_mergeset_ref::EvmRules::default(),
    };
    let mut state = State::genesis(&cfg.genesis_alloc);
    let out = state.accept(&cfg, &c, &members).expect("covered");
    let executed: Vec<(Hash, Hash)> = out
        .receipts
        .iter()
        .map(|r| (r.tx_hash, r.including_block))
        .collect();
    assert_eq!(
        executed,
        vec![(t.hash, b.header.block_hash), (u.hash, b.header.block_hash)],
        "SP's copy of t and then u run"
    );
    assert_eq!(
        out.skipped,
        vec![(t.hash, a.header.block_hash, exec::SkipKind::Nonce)],
        "a's copy is a nonce skip"
    );
    assert_eq!(out.gas_used, 2 * TRANSFER_GAS);
    let s = &state.accounts[&SENDER];
    assert_eq!(s.nonce, 2);
    assert_eq!(
        s.balance,
        fund - U256::from(2_000u64) - U256::from(2 * TRANSFER_GAS) * U256::from(PRICE),
        "two values and two fees; nothing for the skip"
    );
    // R(2) = 10 SALT: 10% treasury, 9 SALT split between the two blues.
    let salt = U256::exp10(18);
    assert_eq!(state.accounts[&TREASURY].balance, salt);
    let half = salt * U256::from(9u64) / U256::from(2u64);
    assert_eq!(state.accounts[&b.header.coinbase].balance, half);
    assert_eq!(state.accounts[&a.header.coinbase].balance, half);
    assert_eq!(out.accepted_root, exec::accepted_root(&out.receipts));
}
