//! CV-14 trie-node persistence on RocksDB (`StateStore` as the node's trie-node
//! store), under the MPT state root rule:
//!
//! * `restart_reuses_persisted_trie_nodes`: a node restarted from its RocksDB
//!   (flat state hydrated as `boot_state` does, trie nodes reused) has the same
//!   root without re-folding a single account, and keeps agreeing afterwards;
//! * `reorg_rolls_back_trie_nodes`: a reorg inside the undo window rolls the trie
//!   back (in memory from the snapshot ring, and through undo pre-images as a
//!   deep revert does), rewrites the root records of the new branch, and a prune
//!   keeps every node reachable from a root in the window while removing the
//!   abandoned branch's and those below the window.
//!
//! The MPT rule is process-wide; this test binary switches it on.

use citrate_consensus::types::Hash;
use citrate_execution::executor::{StateStorageChange, StateStoreTrait};
use citrate_execution::state::mpt::{Mpt, EMPTY_ROOT};
use citrate_execution::state::mpt_state;
use citrate_execution::types::Address;
use citrate_execution::StateDB;
use citrate_storage::db::RocksDB;
use citrate_storage::state::{StateStore, REORG_UNDO_DEPTH, TRIE_PRUNE_INTERVAL};
use primitive_types::U256;
use std::sync::Arc;
use tempfile::TempDir;

fn mpt_on() {
    citrate_execution::mpt_state_root::set_mpt_state_root_height(Some(0));
}

fn open(dir: &TempDir) -> StateStore {
    StateStore::new(Arc::new(RocksDB::open(dir.path()).expect("open rocksdb")))
}

fn addr(i: u32) -> Address {
    let mut a = [0u8; 20];
    a[..4].copy_from_slice(&i.to_be_bytes());
    a[19] = 0x5a;
    Address(a)
}

fn slot(i: u32) -> Vec<u8> {
    let mut k = vec![0u8; 32];
    k[28..].copy_from_slice(&i.to_be_bytes());
    k
}

fn word(n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[24..].copy_from_slice(&n.to_be_bytes());
    v
}

/// The state change of block `height` on branch `branch`: a few balances and
/// a few slots, deterministic.
fn block(db: &StateDB, height: u64, branch: u64) {
    let seed = height
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add(branch.wrapping_mul(0x85EB_CA6B));
    for j in 0..4u64 {
        let a = ((seed >> (j * 8)) % 200) as u32;
        db.accounts
            .set_balance(addr(a), U256::from(seed.wrapping_add(j) % 1_000_000 + 1));
    }
    for j in 0..3u64 {
        let c = ((seed >> (j * 5)) % 10) as u32;
        let s = ((seed >> (j * 7)) % 25) as u32;
        db.set_storage(addr(1_000 + c), slot(s), word(seed % 977 + j));
    }
    db.set_root_height(height);
}

/// The genesis-like base state: 200 accounts, 10 contracts with 25 slots.
fn base(db: &StateDB) {
    for i in 0..200 {
        db.accounts
            .set_balance(addr(i), U256::from(u64::from(i) + 1));
    }
    for c in 0..10 {
        let _ = db.set_code(addr(1_000 + c), vec![0x60, c as u8]);
        for s in 0..25 {
            db.set_storage(addr(1_000 + c), slot(s), word(u64::from(c * 100 + s + 1)));
        }
    }
    db.set_root_height(1);
}

/// Commit `db`'s trie nodes for `height` (as `Executor::persist_trie_nodes_at`).
fn persist(db: &StateDB, store: &StateStore, height: u64) -> Hash {
    db.set_root_height(height);
    let mut write =
        |root: &Hash, nodes: &[([u8; 32], Vec<u8>)]| store.put_trie_nodes(height, root, nodes);
    db.persist_trie_nodes(&mut write)
        .expect("persist trie nodes")
        .0
}

/// Commit `db`'s dirty flat state (accounts, slots) to the store, as the
/// executor's persist path does.
fn persist_flat(db: &StateDB, store: &StateStore) {
    let accounts: Vec<_> = db
        .accounts
        .get_dirty_accounts()
        .into_iter()
        .map(|a| (a, db.accounts.get_account(&a)))
        .collect();
    let storage: Vec<StateStorageChange> = db
        .take_dirty_storage()
        .into_iter()
        .map(|(address, key)| StateStorageChange {
            value: db.get_storage(&address, &key),
            address,
            key,
        })
        .collect();
    store
        .write_state_batch_sync(&accounts, &storage)
        .expect("flat state");
    db.accounts.clear_dirty();
}

/// A restarted node's db: the flat state read back from the store (as
/// `node/src/boot_state.rs` hydrates).
fn hydrate(store: &StateStore, height: u64) -> StateDB {
    let db = StateDB::new();
    for (a, s) in store.get_all_accounts().expect("accounts") {
        db.accounts.load_account(a, s);
    }
    for rec in store.get_all_storage().expect("storage") {
        let ((a, k), v) = rec;
        db.set_storage(a, k.as_bytes().to_vec(), v.as_bytes().to_vec());
    }
    let _ = db.take_dirty_storage();
    db.set_root_height(height);
    db
}

/// Whether the trie rooted at `root` (its account trie and every storage trie
/// its leaves name) loads completely from the store.
fn fully_loadable(store: &StateStore, root: &Hash) -> bool {
    let source = |h: &[u8; 32]| store.get_trie_node(h).ok().flatten();
    let Ok(accounts) = Mpt::load(root.as_bytes(), &source) else {
        return false;
    };
    accounts.entries().iter().all(|(_, leaf)| {
        let sr = mpt_state::account_leaf_storage_root(leaf).unwrap_or(EMPTY_ROOT);
        Mpt::load(&sr, &source).is_ok()
    })
}

#[test]
fn restart_reuses_persisted_trie_nodes() {
    mpt_on();
    let dir = TempDir::new().expect("tmp");
    let (root5, root6) = {
        let store = open(&dir);
        let db = StateDB::new();
        base(&db);
        persist(&db, &store, 1);
        persist_flat(&db, &store);
        for h in 2..=5 {
            block(&db, h, 0);
            persist(&db, &store, h);
            persist_flat(&db, &store);
        }
        let root5 = db.calculate_state_root();
        assert_eq!(root5, db.reference_state_root());
        block(&db, 6, 0);
        (root5, db.calculate_state_root())
    };

    // Restart: a new process opens the same RocksDB.
    let store = open(&dir);
    assert_eq!(store.trie_root_at(5).expect("record"), Some(root5));
    let restarted = hydrate(&store, 5);
    let source = |h: &[u8; 32]| store.get_trie_node(h).ok().flatten();
    let reuse = restarted
        .reuse_persisted_trie(&root5, &source)
        .expect("the persisted trie matches the hydrated state");
    assert_eq!(reuse.accounts, 210);
    assert_eq!(reuse.storage_tries, 10);
    let folded_before = restarted.mpt_folded_accounts();
    assert_eq!(
        restarted.calculate_state_root(),
        root5,
        "same root after restart"
    );
    assert_eq!(
        restarted.mpt_folded_accounts(),
        folded_before,
        "no account re-folded: the trie was reused, not rebuilt"
    );

    // A cold restart (no node store) folds every account, for the same root.
    let cold = hydrate(&store, 5);
    let cold_before = cold.mpt_folded_accounts();
    assert_eq!(cold.calculate_state_root(), root5);
    assert_eq!(cold.mpt_folded_accounts() - cold_before, 210);

    // The reused trie keeps working incrementally: the next block matches the
    // node that never restarted, folding only what the block touched.
    let before = restarted.mpt_folded_accounts();
    block(&restarted, 6, 0);
    assert_eq!(restarted.calculate_state_root(), root6);
    assert!(restarted.mpt_folded_accounts() - before <= 7);
    assert_eq!(restarted.reference_state_root(), root6);
}

#[test]
fn reorg_rolls_back_trie_nodes() {
    mpt_on();
    let dir = TempDir::new().expect("tmp");
    let store = open(&dir);
    let db = StateDB::new();
    base(&db);
    let mut roots_a = vec![Hash::default(); 31];
    let mut ring = Vec::new();
    roots_a[1] = persist(&db, &store, 1);
    ring.push(db.snapshot());
    for h in 2..=30u64 {
        block(&db, h, 0);
        roots_a[h as usize] = persist(&db, &store, h);
        ring.push(db.snapshot());
    }
    assert!(fully_loadable(&store, &roots_a[30]));
    let (nodes_a, bytes_a) = store.trie_node_usage().expect("usage");

    // Reorg at fork point 20: roll back to the state after block 20 (the
    // in-memory snapshot ring), then apply branch B 21..=25.
    let f = 20usize;
    db.restore(ring[f - 1].clone());
    assert_eq!(
        db.calculate_state_root(),
        roots_a[f],
        "rolled back to the fork point"
    );
    let mut roots_b = vec![Hash::default(); 26];
    let mut ring_b = Vec::new();
    for h in 21..=25u64 {
        block(&db, h, 1);
        roots_b[h as usize] = persist(&db, &store, h);
        ring_b.push(db.snapshot());
        assert_ne!(roots_b[h as usize], roots_a[h as usize]);
    }
    for h in 1..=20 {
        assert_eq!(
            store.trie_root_at(h).expect("record"),
            Some(roots_a[h as usize])
        );
    }
    for h in 21..=25 {
        assert_eq!(
            store.trie_root_at(h).expect("record"),
            Some(roots_b[h as usize])
        );
    }
    for h in 26..=30 {
        assert_eq!(
            store.trie_root_at(h).expect("record"),
            None,
            "the abandoned branch's record above the new tip is gone"
        );
    }

    // A deep revert inside the window goes through the undo pre-images (S3-4),
    // not the ring: back from B25 to B22.
    let target = ring_b[1].clone(); // after B22
    let cur = db.snapshot();
    let (accounts, storage) = cur.pre_images_since(&target);
    db.restore(cur.with_pre_images(&accounts, &storage, 22));
    assert_eq!(
        db.calculate_state_root(),
        roots_b[22],
        "undo pre-images roll the trie back"
    );
    assert_eq!(db.calculate_state_root(), db.reference_state_root());
    // And forward again to B25 (re-applying the same blocks gives the same nodes).
    for h in 23..=25u64 {
        block(&db, h, 1);
        assert_eq!(db.calculate_state_root(), roots_b[h as usize]);
    }

    // A restart at the new tip reuses B25's trie.
    let restarted = hydrate_from(&db, 25);
    assert!(restarted
        .reuse_persisted_trie(&roots_b[25], &|h| store.get_trie_node(h).ok().flatten())
        .is_ok());

    // Prune with a window of 10 at tip 25: roots 16..=25 are the mark set.
    let window = 10;
    let stats = store.prune_trie_nodes(25, window).expect("prune");
    assert_eq!(stats.roots, 10);
    assert!(stats.nodes_removed > 0, "{stats:?}");
    for h in 16..=20 {
        assert!(fully_loadable(&store, &roots_a[h]), "window root A{h} kept");
    }
    for h in 21..=25 {
        assert!(fully_loadable(&store, &roots_b[h]), "window root B{h} kept");
    }
    for h in 26..=30 {
        assert!(
            !fully_loadable(&store, &roots_a[h]),
            "abandoned branch root A{h} pruned"
        );
    }
    for h in 2..=10 {
        assert!(
            !fully_loadable(&store, &roots_a[h]),
            "root A{h} below the window pruned"
        );
        assert_eq!(store.trie_root_at(h as u64).expect("record"), None);
    }
    let (nodes_after, bytes_after) = store.trie_node_usage().expect("usage");
    assert_eq!(nodes_after, stats.nodes_kept);
    assert!(nodes_after < nodes_a);
    eprintln!(
        "TRIENODES before_prune nodes={nodes_a} bytes={bytes_a} after_prune nodes={nodes_after} \
         bytes={bytes_after} (210 accounts, 250 slots, window {window})"
    );

    // A reorg back into the window still restarts from disk: B21's trie loads.
    assert!(fully_loadable(&store, &roots_b[21]));

    // Production: the window is the undo window = retention (CV-7a), swept
    // every TRIE_PRUNE_INTERVAL heights.
    assert_eq!(REORG_UNDO_DEPTH, 10_000);
    assert!(TRIE_PRUNE_INTERVAL > 0 && TRIE_PRUNE_INTERVAL <= REORG_UNDO_DEPTH);
}

/// A fresh db with `src`'s resident state, as a restart hydrates it.
fn hydrate_from(src: &StateDB, height: u64) -> StateDB {
    let db = StateDB::new();
    let snap = src.snapshot();
    for (a, s) in snap.account_entries() {
        db.accounts.load_account(*a, s.clone());
    }
    for (a, slots) in snap.storage_map() {
        for (k, v) in slots {
            db.set_storage(a, k, v);
        }
    }
    let _ = db.take_dirty_storage();
    db.set_root_height(height);
    db
}
