// Memory bound for a ring of consecutive state snapshots.
//
// The execute-on-receive reorg path keeps one `StateSnapshot` per applied
// block for the last 100 blocks. Each snapshot was a deep copy of every
// contract's storage trie, so the ring cost ~100x the contract state even when
// a block touched one slot. Snapshots now share every storage trie that did not
// change between them (copy on write), so the ring costs one copy of the state
// plus what each block actually changed.
//
// Measured with a counting global allocator; exactly ONE #[test] in this file
// so no concurrent test pollutes the count.

use citrate_execution::state::{StateDB, StateSnapshot};
use citrate_execution::types::Address;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

struct Counting;
static LIVE: AtomicI64 = AtomicI64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as i64 - l.size() as i64, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

const CONTRACTS: u8 = 60;
const SLOTS: u32 = 300;
const RING: usize = 100;

fn addr(i: u8) -> Address {
    let mut a = [0u8; 20];
    a[0] = 0xC0;
    a[19] = i;
    Address(a)
}

fn slot(k: u32) -> Vec<u8> {
    let mut s = vec![0u8; 32];
    s[28..].copy_from_slice(&k.to_be_bytes());
    s
}

#[test]
fn snapshot_ring_shares_unchanged_contract_storage() {
    let db = StateDB::new();
    let before_state = live();
    for c in 0..CONTRACTS {
        for k in 0..SLOTS {
            db.set_storage(addr(c), slot(k), vec![c; 32]);
        }
    }
    db.commit();
    // The persist path drains the dirty set every block.
    let _ = db.take_dirty_storage();
    let state_cost = live() - before_state;

    // A ring of RING snapshots, one per "block", each block touching one slot
    // of one contract.
    let before_ring = live();
    let mut ring: Vec<StateSnapshot> = Vec::with_capacity(RING);
    for b in 0..RING {
        let c = (b % CONTRACTS as usize) as u8;
        db.set_storage(addr(c), slot(0), vec![(b % 251) as u8; 32]);
        db.commit();
        let _ = db.take_dirty_storage();
        ring.push(db.snapshot());
    }
    let ring_cost = live() - before_ring;
    eprintln!(
        "contract state = {state_cost} B; ring of {RING} snapshots = {ring_cost} B ({:.1}x the state)",
        ring_cost as f64 / state_cost.max(1) as f64
    );
    // Each block changed one contract (1/CONTRACTS of the state), so a sharing
    // ring costs about RING/CONTRACTS ~ 1.7 state copies. A deep-copy ring
    // costs about RING state copies. Allow 4x.
    assert!(
        ring_cost < state_cost * 4,
        "ring of {RING} snapshots cost {ring_cost} B = {}x the contract state ({state_cost} B)",
        ring_cost / state_cost.max(1)
    );

    // Copy-on-write must never leak a later write into an earlier snapshot.
    let first_val = ring[0]
        .storage_map()
        .get(&addr(0))
        .and_then(|m| m.get(&slot(0)).cloned());
    assert_eq!(first_val, Some(vec![0u8; 32]), "snapshot 0 sees its own write");
    db.restore(ring[0].clone());
    assert_eq!(db.get_storage(&addr(0), &slot(0)), Some(vec![0u8; 32]));
    assert_eq!(db.get_storage(&addr(1), &slot(0)), Some(vec![1u8; 32]));
    db.set_storage(addr(0), slot(5), vec![0xEE; 32]);
    assert_eq!(
        ring[0]
            .storage_map()
            .get(&addr(0))
            .and_then(|m| m.get(&slot(5)).cloned()),
        Some(vec![0u8; 32]),
        "a write after restore must not reach the stored snapshot"
    );
}
