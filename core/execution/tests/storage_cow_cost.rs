//! r1007 storage copy-on-write: the cost of writing a few slots of a large
//! contract while snapshots share its storage is proportional to the slots
//! written (times the log of the contract's size), not to the contract's size.
//!
//! Background (benchmarks/2026-11-09-cv14-mpt-state-root.md): with the CV-14
//! MPT root in place, the boot reorg-window rebuild spent ~40% of its time in
//! `Arc::make_mut` copying a touched contract's WHOLE storage (the slot map and
//! the legacy `TrieNode` tree) whenever a snapshot shared it, and ~27% freeing
//! those copies. The same copy runs on the apply path: the node keeps a ring of
//! snapshots, so the first write of every block to a contract copies it.
//!
//! The assertions count heap allocations made by this thread (a counting
//! global allocator), never wall-clock, so they hold on any host and in debug
//! builds:
//!
//! * a snapshot plus a one-slot write plus the state root, against a contract
//!   of 100,000 slots, allocates a bounded number of bytes, and about as many
//!   as against a contract of 1,000 slots;
//! * the undo record of that write (`pre_images_since`) and the rebuild of the
//!   state below it (`with_pre_images`, then the root on a fresh db, the
//!   node's `rooted`) are bounded the same way;
//! * dropping a snapshot that differs from the live state in one slot frees a
//!   bounded number of allocations.
//!
//! Under the MPT rule (activation 0, the r1007 genesis rule) no legacy tree is
//! maintained, so none of this may grow with the contract either.
//!
//! The rule is process-wide; every test in this binary sets the same value.

use citrate_execution::state::mpt::keccak;
use citrate_execution::state::StateSnapshot;
use citrate_execution::types::Address;
use citrate_execution::StateDB;
use primitive_types::U256;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Counting;

thread_local! {
    static BYTES: Cell<u64> = const { Cell::new(0) };
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
    static FREES: Cell<u64> = const { Cell::new(0) };
}

fn bump(c: &'static std::thread::LocalKey<Cell<u64>>, by: u64) {
    let _ = c.try_with(|v| v.set(v.get().wrapping_add(by)));
}

// SAFETY: forwards every call to `System` unchanged; the counters are
// const-initialised thread-locals without destructors, so touching them never
// allocates or re-enters the allocator.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump(&BYTES, layout.size() as u64);
        bump(&ALLOCS, 1);
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump(&BYTES, layout.size() as u64);
        bump(&ALLOCS, 1);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        bump(&FREES, 1);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump(&BYTES, new_size as u64);
        bump(&ALLOCS, 1);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[derive(Debug, Clone, Copy)]
struct Cost {
    bytes: u64,
    allocs: u64,
    frees: u64,
}

fn read() -> Cost {
    Cost {
        bytes: BYTES.with(Cell::get),
        allocs: ALLOCS.with(Cell::get),
        frees: FREES.with(Cell::get),
    }
}

/// What `f` allocated and freed on this thread.
fn measure<R>(f: impl FnOnce() -> R) -> (R, Cost) {
    let a = read();
    let r = f();
    let b = read();
    (
        r,
        Cost {
            bytes: b.bytes - a.bytes,
            allocs: b.allocs - a.allocs,
            frees: b.frees - a.frees,
        },
    )
}

fn mpt_on() {
    citrate_execution::mpt_state_root::set_mpt_state_root_height(Some(0));
}

fn addr(i: u32) -> Address {
    let h = keccak(&i.to_be_bytes());
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[..20]);
    Address(a)
}

/// Half sequential slots (long shared prefixes), half mapping slots.
fn slot(i: u32) -> Vec<u8> {
    if i.is_multiple_of(2) {
        let mut k = vec![0u8; 32];
        k[28..].copy_from_slice(&(i / 2).to_be_bytes());
        k
    } else {
        keccak(&i.to_be_bytes()).to_vec()
    }
}

fn word(n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[24..].copy_from_slice(&n.to_be_bytes());
    v
}

const CONTRACT: u32 = 7;
/// Snapshots held at once while the contract is written (the reorg ring
/// keeps one per block).
const RING: usize = 16;

/// A db holding one contract of `slots` slots and a few EOAs, rooted, with
/// nothing dirty.
fn contract_db(slots: u32) -> StateDB {
    mpt_on();
    let db = StateDB::new();
    db.set_root_height(1);
    for i in 0..4 {
        db.accounts.set_balance(addr(i), U256::from(1_000 + i));
    }
    let c = addr(CONTRACT);
    let _ = db.set_code(c, vec![0x60, 0x00, 0x00]);
    for s in 0..slots {
        db.set_storage(c, slot(s), word(u64::from(s) + 1));
    }
    let _ = db.calculate_state_root();
    db.accounts.clear_dirty();
    let _ = db.take_dirty_storage();
    db
}

/// One block: snapshot (kept in the ring), write one slot, root it.
fn block(db: &StateDB, ring: &mut Vec<StateSnapshot>, n: u32, slots: u32) {
    ring.push(db.snapshot());
    if ring.len() > RING {
        ring.remove(0);
    }
    db.set_storage(
        addr(CONTRACT),
        slot((n.wrapping_mul(7919)) % slots),
        word(u64::from(n) + 1_000_000),
    );
    db.set_root_height(u64::from(n) + 2);
    let _ = db.calculate_state_root();
    db.accounts.clear_dirty();
    let _ = db.take_dirty_storage();
}

/// The largest per-block cost over `RING * 2` blocks (the ring full of
/// snapshots that share the contract), with the root checked at the end.
fn per_block_cost(slots: u32) -> Cost {
    let db = contract_db(slots);
    let mut ring = Vec::new();
    // Fill the ring first (every block after this finds its contract shared).
    for n in 0..RING as u32 {
        block(&db, &mut ring, n, slots);
    }
    let mut worst = Cost {
        bytes: 0,
        allocs: 0,
        frees: 0,
    };
    for n in RING as u32..(RING as u32 * 2) {
        let ((), c) = measure(|| block(&db, &mut ring, n, slots));
        worst.bytes = worst.bytes.max(c.bytes);
        worst.allocs = worst.allocs.max(c.allocs);
        worst.frees = worst.frees.max(c.frees);
    }
    assert_eq!(db.calculate_state_root(), db.reference_state_root());
    worst
}

const BIG: u32 = 100_000;
const SMALL: u32 = 1_000;

/// A snapshot + a one-slot write + the state root, with the contract shared by
/// the ring: bounded, and independent of the contract's size (within a small
/// factor for the deeper tree: log16(100x) is under 2 levels).
#[test]
fn a_one_slot_write_under_shared_snapshots_does_not_copy_the_contract() {
    let big = per_block_cost(BIG);
    let small = per_block_cost(SMALL);
    eprintln!("COWCOST block slots={BIG}: {big:?}; slots={SMALL}: {small:?}");
    assert!(
        big.bytes < 256 * 1024,
        "a one-slot block on a {BIG}-slot contract allocated {} bytes (whole-storage copy?)",
        big.bytes
    );
    assert!(
        big.allocs < 2_000,
        "a one-slot block on a {BIG}-slot contract made {} allocations",
        big.allocs
    );
    assert!(
        big.bytes <= small.bytes.max(1) * 3,
        "cost grows with the contract: {} bytes at {BIG} slots vs {} at {SMALL}",
        big.bytes,
        small.bytes
    );
    assert!(
        big.frees < 2_000,
        "a one-slot block on a {BIG}-slot contract freed {} allocations (dropping a copy?)",
        big.frees
    );
}

/// The node's `rooted` (`node/src/canonical_apply.rs`): restore onto a fresh db,
/// root, snapshot.
fn rooted(snap: StateSnapshot, height: u64) -> StateSnapshot {
    let scratch = StateDB::new();
    scratch.restore(snap);
    scratch.set_root_height(height);
    let _ = scratch.calculate_state_root();
    scratch.accounts.clear_dirty();
    let _ = scratch.take_dirty_storage();
    scratch.snapshot()
}

/// The undo record of a one-slot block and the rebuild of the state below it
/// (the boot reorg-window rebuild, per height) are bounded too.
#[test]
fn undo_record_and_rebuild_of_a_one_slot_block_are_bounded() {
    let cost = |slots: u32| {
        let db = contract_db(slots);
        let mut ring = Vec::new();
        for n in 0..4 {
            block(&db, &mut ring, n, slots);
        }
        let prev = db.snapshot();
        let mut ring2 = vec![prev.clone()];
        block(&db, &mut ring2, 99, slots);
        let cur = rooted(db.snapshot(), 101);
        let ((acc, sto), undo) = measure(|| cur.pre_images_since(&prev));
        assert_eq!(sto.len(), 1, "one slot changed");
        let (below, rebuild) = measure(|| rooted(cur.with_pre_images(&acc, &sto, 100), 100));
        // The rebuilt state is the state before the block.
        let check = StateDB::new();
        check.restore(below);
        check.set_root_height(100);
        let back = StateDB::new();
        back.restore(prev);
        back.set_root_height(100);
        assert_eq!(check.calculate_state_root(), back.calculate_state_root());
        assert_eq!(check.calculate_state_root(), check.reference_state_root());
        (undo, rebuild)
    };
    let (undo_big, rebuild_big) = cost(BIG);
    let (undo_small, rebuild_small) = cost(SMALL);
    eprintln!(
        "COWCOST undo slots={BIG}: {undo_big:?}, rebuild {rebuild_big:?}; \
         slots={SMALL}: {undo_small:?}, rebuild {rebuild_small:?}"
    );
    assert!(
        undo_big.bytes < 64 * 1024,
        "the undo record of one slot of a {BIG}-slot contract allocated {} bytes",
        undo_big.bytes
    );
    assert!(
        rebuild_big.bytes < 512 * 1024,
        "rebuilding one height on a {BIG}-slot contract allocated {} bytes",
        rebuild_big.bytes
    );
    assert!(
        rebuild_big.allocs < 4_000,
        "rebuilding one height on a {BIG}-slot contract made {} allocations",
        rebuild_big.allocs
    );
    assert!(
        rebuild_big.bytes <= rebuild_small.bytes.max(1) * 3,
        "rebuild cost grows with the contract: {} bytes at {BIG} slots vs {} at {SMALL}",
        rebuild_big.bytes,
        rebuild_small.bytes
    );
}

/// Dropping a snapshot that differs from the live state in one slot frees only
/// what it alone holds.
#[test]
fn dropping_a_snapshot_frees_only_what_it_alone_holds() {
    let db = contract_db(BIG);
    let mut ring = Vec::new();
    block(&db, &mut ring, 0, BIG);
    block(&db, &mut ring, 1, BIG);
    // ring[0] is the state before block 0; the live state and ring[1] have
    // moved on by one and two slots.
    let oldest = ring.remove(0);
    let ((), c) = measure(move || drop(oldest));
    eprintln!("COWCOST drop slots={BIG}: {c:?}");
    assert!(
        c.frees < 2_000,
        "dropping a snapshot one slot away from the live state freed {} allocations",
        c.frees
    );
}
