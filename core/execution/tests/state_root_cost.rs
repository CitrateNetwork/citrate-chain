//! CV-14 / H7 bench: the per-block state-root cost against state size, legacy vs MPT.
//!
//! Run in release (it is `#[ignore]`d; timings in a debug build mean little):
//!
//! ```text
//! cargo test --release -p citrate-execution --test state_root_cost -- --ignored --nocapture
//! ```
//!
//! For each state size it builds the state, then times BLOCKS blocks, each
//! changing `TOUCH_ACCOUNTS` balances and `TOUCH_SLOTS` slots (a busy r1006 block),
//! and prints one `STATEROOTCOST` line with the median ms per block of:
//!
//! * `legacy`: `calculate_state_root` with the MPT rule off (the r1006 root,
//!   rebuilt from scratch every block, children embedded);
//! * `mpt_inc`: `calculate_state_root` under the MPT rule (CV-14 (a)+(b));
//! * `mpt_scratch`: `reference_state_root` (the standard MPT from scratch: what
//!   (a) alone would cost);
//! * `persist`: collecting the block's new trie nodes for the node store, and
//!   `node_bytes`, the bytes that adds per block (the storage overhead).
//!
//! The shape follows r1006's live state (132 accounts, 737 slots on 2026-11-01):
//! a dozen contracts, sequential slots (long shared key prefixes, which the legacy
//! trie turns into deep chains) and mapping slots.
//!
//! Gates (release build): at r1006 size the MPT root is >= 10x cheaper than the
//! legacy root, and from the smallest to the largest state the MPT per-block cost
//! grows by at most 4x while the state grows 100x.

use citrate_execution::state::mpt::keccak;
use citrate_execution::types::Address;
use citrate_execution::StateDB;
use primitive_types::U256;
use std::time::Instant;

const BLOCKS: usize = 15;
const TOUCH_ACCOUNTS: u32 = 40;
const TOUCH_SLOTS: u32 = 20;

fn addr(i: u32) -> Address {
    let mut a = [0u8; 20];
    // Real addresses are hash-like; mix the index.
    let h = keccak(&i.to_be_bytes());
    a.copy_from_slice(&h[..20]);
    Address(a)
}

fn slot(c: u32, i: u32) -> Vec<u8> {
    if i % 2 == 0 {
        let mut k = vec![0u8; 32];
        k[28..].copy_from_slice(&(i / 2).to_be_bytes());
        k
    } else {
        keccak(&[c.to_be_bytes(), i.to_be_bytes()].concat()).to_vec()
    }
}

fn word(n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[24..].copy_from_slice(&n.to_be_bytes());
    v
}

/// `accounts` EOAs plus `contracts` contracts holding `slots` slots in total.
fn build(db: &StateDB, accounts: u32, contracts: u32, slots: u32) {
    for i in 0..accounts {
        db.accounts
            .set_balance(addr(i), U256::from(u64::from(i) * 1_000 + 1));
        db.accounts.set_nonce(addr(i), u64::from(i % 7));
    }
    for c in 0..contracts {
        let a = addr(1_000_000 + c);
        let _ = db.set_code(a, vec![0x60, c as u8, 0x00]);
        for s in 0..slots / contracts {
            db.set_storage(a, slot(c, s), word(u64::from(c * 31 + s + 1)));
        }
    }
    db.set_root_height(1);
}

fn block(db: &StateDB, n: u32, accounts: u32, contracts: u32, slots: u32) {
    for j in 0..TOUCH_ACCOUNTS {
        let i = (n.wrapping_mul(7919).wrapping_add(j * 104_729)) % accounts;
        db.accounts
            .set_balance(addr(i), U256::from(u64::from(n) * 13 + u64::from(j)));
    }
    for j in 0..TOUCH_SLOTS {
        let c = (n + j) % contracts;
        let s = (n.wrapping_mul(31).wrapping_add(j * 17)) % (slots / contracts).max(1);
        db.set_storage(
            addr(1_000_000 + c),
            slot(c, s),
            word(u64::from(n * 100 + j)),
        );
    }
    db.set_root_height(u64::from(n) + 2);
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    v[v.len() / 2]
}

struct Cost {
    legacy: f64,
    mpt_inc: f64,
    mpt_scratch: f64,
    persist: f64,
    node_bytes: f64,
}

fn measure(accounts: u32, contracts: u32, slots: u32) -> Cost {
    // Legacy.
    citrate_execution::mpt_state_root::set_mpt_state_root_height(None);
    let db = StateDB::new();
    build(&db, accounts, contracts, slots);
    let _ = db.calculate_state_root();
    let mut legacy = Vec::new();
    for n in 0..BLOCKS as u32 {
        block(&db, n, accounts, contracts, slots);
        let t = Instant::now();
        let _ = db.calculate_state_root();
        legacy.push(t.elapsed().as_secs_f64() * 1e3);
        let _ = db.commit();
    }

    // MPT.
    citrate_execution::mpt_state_root::set_mpt_state_root_height(Some(0));
    let db = StateDB::new();
    build(&db, accounts, contracts, slots);
    let mut sink = |_: &citrate_consensus::types::Hash, _: &[([u8; 32], Vec<u8>)]| Ok(());
    let _ = db.persist_trie_nodes(&mut sink);
    let (mut inc, mut scratch, mut persist, mut bytes) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for n in 0..BLOCKS as u32 {
        block(&db, n, accounts, contracts, slots);
        let t = Instant::now();
        let root = db.calculate_state_root();
        inc.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        let reference = db.reference_state_root();
        scratch.push(t.elapsed().as_secs_f64() * 1e3);
        assert_eq!(root, reference, "incremental == from scratch");
        let mut written = 0usize;
        let mut count = |_: &citrate_consensus::types::Hash, nodes: &[([u8; 32], Vec<u8>)]| {
            written = nodes.iter().map(|(_, n)| n.len() + 32).sum();
            Ok(())
        };
        let t = Instant::now();
        let _ = db.persist_trie_nodes(&mut count);
        persist.push(t.elapsed().as_secs_f64() * 1e3);
        bytes.push(written as f64);
        let _ = db.commit();
    }
    Cost {
        legacy: median(legacy),
        mpt_inc: median(inc),
        mpt_scratch: median(scratch),
        persist: median(persist),
        node_bytes: median(bytes),
    }
}

#[test]
#[ignore = "bench: run in release with --ignored --nocapture"]
fn state_root_cost_per_block_does_not_grow_with_state() {
    // (accounts, contracts, slots): r1006 live size, then 10x and 100x.
    let sizes = [
        (132u32, 12u32, 737u32),
        (1_320, 12, 7_370),
        (13_200, 12, 73_700),
    ];
    let mut costs = Vec::new();
    for (a, c, s) in sizes {
        let cost = measure(a, c, s);
        eprintln!(
            "STATEROOTCOST accounts={a} contracts={c} slots={s} blocks={BLOCKS} \
             touch={TOUCH_ACCOUNTS}a+{TOUCH_SLOTS}s legacy_ms={:.3} mpt_inc_ms={:.3} \
             mpt_scratch_ms={:.3} persist_ms={:.3} node_bytes_per_block={:.0} \
             speedup_vs_legacy={:.1}x",
            cost.legacy,
            cost.mpt_inc,
            cost.mpt_scratch,
            cost.persist,
            cost.node_bytes,
            cost.legacy / cost.mpt_inc
        );
        costs.push(cost);
    }
    if cfg!(debug_assertions) {
        eprintln!("debug build: gates not applied");
        return;
    }
    assert!(
        costs[0].legacy / costs[0].mpt_inc >= 10.0,
        "at r1006 size the MPT root must be >= 10x cheaper than the legacy root"
    );
    assert!(
        costs[2].mpt_inc <= costs[0].mpt_inc * 4.0,
        "the MPT per-block cost grew with the state: {:.3} -> {:.3} ms",
        costs[0].mpt_inc,
        costs[2].mpt_inc
    );
}
