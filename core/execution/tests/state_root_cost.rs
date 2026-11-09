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
    if i.is_multiple_of(2) {
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

/// Heights the boot reorg-window rebuild walks in the S1-2 measurement (fed
/// `ops/r1007-apply-cost` @ 13830e51: 100 real heights, 305183..305283).
const REBUILD_HEIGHTS: u32 = 100;

/// `node/src/canonical_apply.rs` `rooted`, step for step: the state root of
/// `snap` as the post-state of `height`, on a fresh `StateDB`, and the snapshot
/// a running node holds after it. Copied (it is private to the node) so the
/// bench times exactly the per-height work of `restore_reorg_window`.
fn rooted(
    snap: citrate_execution::state::StateSnapshot,
    height: u64,
) -> (
    citrate_consensus::types::Hash,
    citrate_execution::state::StateSnapshot,
) {
    let scratch = StateDB::new();
    scratch.restore(snap);
    scratch.set_root_height(height);
    let root = scratch.calculate_state_root();
    scratch.accounts.clear_dirty();
    let _ = scratch.take_dirty_storage();
    (root, scratch.snapshot())
}

/// Per-height cost of the boot reorg-window rebuild (the path S1-2 profiled on
/// r1006 data), under one root rule. Builds the state, applies
/// [`REBUILD_HEIGHTS`] blocks the way a node does (root per block, then the
/// undo pre-images of that block against the state before it), then walks
/// back down from the tip as `restore_reorg_window` does: pre-images applied
/// to the state above (`with_pre_images`), then `rooted`. Every rebuilt root
/// must equal the root the forward pass committed at that height.
///
/// Returns the median ms per rebuilt height of (pre-images + `rooted`).
fn rebuild_cost(mpt: bool, accounts: u32, contracts: u32, slots: u32) -> f64 {
    citrate_execution::mpt_state_root::set_mpt_state_root_height(mpt.then_some(0));
    let db = StateDB::new();
    build(&db, accounts, contracts, slots);
    let _ = db.calculate_state_root();
    db.accounts.clear_dirty();
    let _ = db.take_dirty_storage();
    // Forward: height h's committed root and undo record (pre-images in the
    // state of h-1). Heights start at 2 (`block` sets n + 2).
    let mut roots = Vec::new();
    let mut undo = Vec::new();
    let mut prev = db.snapshot();
    roots.push(db.calculate_state_root());
    for n in 0..REBUILD_HEIGHTS {
        block(&db, n, accounts, contracts, slots);
        let root = db.calculate_state_root();
        db.accounts.clear_dirty();
        let _ = db.take_dirty_storage();
        let cur = db.snapshot();
        undo.push(cur.pre_images_since(&prev));
        roots.push(root);
        prev = cur;
    }
    // The tip as a restarted node holds it, root-checked first (as the node does).
    let (tip_root, mut above) = rooted(prev, u64::from(REBUILD_HEIGHTS) + 1);
    assert_eq!(tip_root, roots[REBUILD_HEIGHTS as usize], "tip root");
    let mut per_height = Vec::new();
    for i in (0..REBUILD_HEIGHTS as usize).rev() {
        // Undo record i reverts height i + 2 to height i + 1.
        let below = i as u64 + 1;
        let (acc, sto) = &undo[i];
        let t = Instant::now();
        let reverted = above.with_pre_images(acc, sto, below);
        let (root, snap) = rooted(reverted, below);
        per_height.push(t.elapsed().as_secs_f64() * 1e3);
        assert_eq!(root, roots[i], "rebuilt root at {below} (mpt={mpt})");
        above = snap;
    }
    median(per_height)
}

/// The S1-2 workload's hot path, before and after CV-14: the per-height cost
/// of the boot reorg-window rebuild over [`REBUILD_HEIGHTS`] heights at r1006's
/// live state size (and 10x), legacy root vs the incremental MPT root. Prints
/// one `REBUILDCOST` line per size. Gate (release): at r1006 size the MPT
/// rebuild is >= 2x cheaper per height than the legacy rebuild.
///
/// Measured 2026-11-09 on a DO s-4vcpu-8gb (prod-1's class), 3 runs: legacy
/// 11.3-14.5 ms/height, MPT 4.2-5.0 ms/height (2.3-2.9x) at r1006 size; 3.3-3.4x
/// at 10x. The root itself is 15-23x cheaper (`STATEROOTCOST`), so the rebuild
/// is now bound by something else: perf on the MPT arm puts ~40% in
/// `Arc::make_mut` copying a touched contract's whole storage `Trie` (the
/// legacy `TrieNode` tree and the slot `HashMap`) while a snapshot shares it,
/// and ~27% in dropping those copies; `mpt_state_root` is ~4.5%. That copy is
/// O(slots of the contract) per touched contract per block, on the apply path
/// as well. It is outside the state root and tracked as its own follow-up
/// (persistent storage map; no legacy tree under the MPT rule). The gate is
/// set below the measured ratio so it catches a regression of the root.
#[test]
#[ignore = "bench: run in release with --ignored --nocapture"]
fn reorg_window_rebuild_cost_per_height_legacy_vs_mpt() {
    let sizes = [(132u32, 12u32, 737u32), (1_320, 12, 7_370)];
    let mut ratios = Vec::new();
    for (a, c, s) in sizes {
        let legacy = rebuild_cost(false, a, c, s);
        let mpt = rebuild_cost(true, a, c, s);
        eprintln!(
            "REBUILDCOST accounts={a} contracts={c} slots={s} heights={REBUILD_HEIGHTS} \
             touch={TOUCH_ACCOUNTS}a+{TOUCH_SLOTS}s legacy_ms_per_height={legacy:.3} \
             mpt_ms_per_height={mpt:.3} speedup={:.1}x",
            legacy / mpt
        );
        ratios.push(legacy / mpt);
    }
    if cfg!(debug_assertions) {
        eprintln!("debug build: gates not applied");
        return;
    }
    assert!(
        ratios[0] >= 2.0,
        "at r1006 size the MPT rebuild must be >= 2x cheaper per height: {:.1}x",
        ratios[0]
    );
}
