//! CV-14 (a)+(b) at the `StateDB` level, under the MPT state root rule:
//!
//! * `incremental_root_equals_from_scratch`: over random sequences of account and
//!   storage changes, deletes, re-creates, non-dirtying loads, snapshots, restores
//!   and undo pre-images, the incremental root always equals the from-scratch
//!   reference (`StateDB::reference_state_root`) and the root of a fresh db
//!   holding the same state;
//! * `root_is_pure_function_of_state`: a trie cache's presence, absence or
//!   corruption, or another node's cache, never changes the root;
//! * `storage_proof_verifies`: the `eth_getProof` accessor's account and storage
//!   proofs verify against the state root (ours and alloy-trie's verifier).
//!
//! The rule is process-wide, so this file (its own test binary) switches it on
//! for every test in it.

use alloy_primitives::{Bytes, B256};
use alloy_trie::Nibbles;
use citrate_consensus::types::Hash;
use citrate_execution::state::mpt::{self, keccak, EMPTY_ROOT};
use citrate_execution::state::mpt_state;
use citrate_execution::types::{AccountState, Address, ModelId};
use citrate_execution::StateDB;
use primitive_types::U256;
use proptest::prelude::*;
use std::collections::HashMap;

fn mpt_on() {
    citrate_execution::mpt_state_root::set_mpt_state_root_height(Some(0));
}

fn db() -> StateDB {
    mpt_on();
    let db = StateDB::new();
    db.set_root_height(1);
    db
}

fn addr(i: u8) -> Address {
    let mut a = [0u8; 20];
    a[0] = i;
    a[19] = i.wrapping_mul(7);
    Address(a)
}

/// Slot keys: sequential EVM slots (long shared prefixes before hashing), a
/// mapping-style key, and a non-EVM key.
fn slot(i: u8) -> Vec<u8> {
    match i % 4 {
        0 | 1 => {
            let mut k = vec![0u8; 32];
            k[31] = i;
            k
        }
        2 => keccak(&[i]).to_vec(),
        _ => format!("PARAM:{i}").into_bytes(),
    }
}

fn value(kind: u8, n: u8) -> Vec<u8> {
    match kind % 4 {
        // An EVM value.
        0 | 1 => {
            let mut v = vec![0u8; 32];
            v[31] = n;
            v[0] = n & 0x03;
            v
        }
        // An EVM zero (absent from the trie, but resident).
        2 => vec![0u8; 32],
        // A non-EVM value.
        _ => vec![n; usize::from(n % 5)],
    }
}

/// A fresh db holding exactly `src`'s resident accounts and slots, loaded in
/// a different order (as a restarted node hydrates).
fn rehydrated(src: &StateDB) -> StateDB {
    let fresh = db();
    let snap = src.snapshot();
    let mut accounts: Vec<(Address, AccountState)> = snap.account_entries().to_vec();
    accounts.reverse();
    for (a, s) in accounts {
        fresh.accounts.load_account(a, s);
    }
    for (a, slots) in snap.storage_map() {
        for (k, v) in slots {
            fresh.set_storage(a, k, v);
        }
    }
    let _ = fresh.take_dirty_storage();
    fresh
}

#[derive(Debug, Clone)]
enum Op {
    Balance(u8, u64),
    Nonce(u8, u64),
    Code(u8, u8),
    Model(u8, u8),
    /// Make the account empty again (deleted from the trie).
    Clear(u8),
    Store(u8, u8, u8, u8),
    /// A non-dirtying read-through (`cache_storage`).
    Cache(u8, u8, u8, u8),
    Delete(u8, u8),
    /// A non-dirtying account load (restart hydration, read-through).
    Load(u8, u64),
    Root,
    Snapshot,
    Restore(u8),
    /// Undo back to a snapshot through pre-images (the deep-undo path, S3-4).
    Undo(u8),
    Commit,
}

fn op() -> impl Strategy<Value = Op> {
    let a = 0u8..6;
    prop_oneof![
        4 => (a.clone(), any::<u64>()).prop_map(|(a, b)| Op::Balance(a, b % 3)),
        2 => (a.clone(), 0u64..3).prop_map(|(a, n)| Op::Nonce(a, n)),
        1 => (a.clone(), any::<u8>()).prop_map(|(a, c)| Op::Code(a, c)),
        1 => (a.clone(), any::<u8>()).prop_map(|(a, m)| Op::Model(a, m)),
        1 => a.clone().prop_map(Op::Clear),
        6 => (a.clone(), 0u8..10, any::<u8>(), any::<u8>()).prop_map(|(a, s, k, n)| Op::Store(a, s, k, n)),
        2 => (a.clone(), 0u8..10, any::<u8>(), any::<u8>()).prop_map(|(a, s, k, n)| Op::Cache(a, s, k, n)),
        3 => (a.clone(), 0u8..10).prop_map(|(a, s)| Op::Delete(a, s)),
        1 => (a.clone(), any::<u64>()).prop_map(|(a, b)| Op::Load(a, b % 3)),
        3 => Just(Op::Root),
        1 => Just(Op::Snapshot),
        1 => any::<u8>().prop_map(Op::Restore),
        1 => any::<u8>().prop_map(Op::Undo),
        1 => Just(Op::Commit),
    ]
}

fn apply(db: &StateDB, op: &Op, snaps: &mut Vec<citrate_execution::state::StateSnapshot>) {
    match op {
        Op::Balance(a, b) => db.accounts.set_balance(addr(*a), U256::from(*b)),
        Op::Nonce(a, n) => db.accounts.set_nonce(addr(*a), *n),
        Op::Code(a, c) => {
            let _ = db.set_code(addr(*a), vec![0x60, *c, 0x00]);
        }
        Op::Model(a, m) => db
            .accounts
            .add_model_permission(addr(*a), ModelId(Hash::new([*m; 32]))),
        Op::Clear(a) => db.accounts.set_account(addr(*a), AccountState::default()),
        Op::Store(a, s, k, n) => db.set_storage(addr(*a), slot(*s), value(*k, *n)),
        Op::Cache(a, s, k, n) => db.cache_storage(addr(*a), slot(*s), value(*k, *n)),
        Op::Delete(a, s) => db.delete_storage(addr(*a), &slot(*s)),
        Op::Load(a, b) => db.accounts.load_account(
            addr(*a),
            AccountState {
                balance: U256::from(*b),
                ..Default::default()
            },
        ),
        Op::Root => {
            let _ = db.calculate_state_root();
        }
        Op::Snapshot => snaps.push(db.snapshot()),
        Op::Restore(i) => {
            if !snaps.is_empty() {
                let s = snaps[usize::from(*i) % snaps.len()].clone();
                db.restore(s);
            }
        }
        Op::Undo(i) => {
            if !snaps.is_empty() {
                let prev = snaps[usize::from(*i) % snaps.len()].clone();
                let cur = db.snapshot();
                let (accounts, storage) = cur.pre_images_since(&prev);
                db.restore(cur.with_pre_images(&accounts, &storage, 1));
            }
        }
        Op::Commit => {
            let _ = db.commit();
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// CV-14 (b): incremental == from scratch, after every step, whatever the
    /// history; and == the root a freshly hydrated db computes.
    #[test]
    fn incremental_root_equals_from_scratch(ops in prop::collection::vec(op(), 1..80)) {
        let db = db();
        let mut snaps = Vec::new();
        for (i, o) in ops.iter().enumerate() {
            apply(&db, o, &mut snaps);
            if matches!(o, Op::Root | Op::Restore(_) | Op::Undo(_)) || i.is_multiple_of(7) {
                let incremental = db.calculate_state_root();
                prop_assert_eq!(
                    incremental,
                    db.reference_state_root(),
                    "step {} ({:?}): incremental root != from-scratch reference", i, o
                );
            }
        }
        let incremental = db.calculate_state_root();
        prop_assert_eq!(incremental, db.reference_state_root());
        let fresh = rehydrated(&db);
        prop_assert_eq!(fresh.calculate_state_root(), incremental, "a fresh db, same state");
        // Idempotent: computing again changes nothing.
        prop_assert_eq!(db.calculate_state_root(), incremental);
    }
}

/// CV-14 + ADR-2026-07-21: a cache never changes the root.
#[test]
fn root_is_pure_function_of_state() {
    // `a`: a long history (roots computed in between, snapshots, a revert, a
    // non-dirtying read-through, a delete and a re-create).
    let a = db();
    a.accounts.set_balance(addr(1), U256::from(10));
    a.set_storage(addr(1), slot(0), value(0, 1));
    let _ = a.calculate_state_root();
    let snap = a.snapshot();
    a.accounts.set_balance(addr(2), U256::from(99));
    a.set_storage(addr(2), slot(4), value(0, 4));
    let _ = a.calculate_state_root();
    a.restore(snap);
    a.accounts.set_balance(addr(3), U256::from(7));
    a.cache_storage(addr(3), slot(3), value(3, 9));
    a.set_storage(addr(1), slot(1), value(1, 2));
    a.delete_storage(addr(1), &slot(1));
    a.set_storage(addr(1), slot(1), value(1, 2));
    let _ = a.commit();
    a.set_storage(addr(1), slot(5), value(0, 5));
    let root_a = a.calculate_state_root();

    // `b`: the same state reached directly, root computed once (no cache to speak of).
    let b = db();
    b.accounts.set_balance(addr(1), U256::from(10));
    b.set_storage(addr(1), slot(0), value(0, 1));
    b.set_storage(addr(1), slot(1), value(1, 2));
    b.set_storage(addr(1), slot(5), value(0, 5));
    b.accounts.set_balance(addr(3), U256::from(7));
    b.set_storage(addr(3), slot(3), value(3, 9));
    assert_eq!(
        b.calculate_state_root(),
        root_a,
        "presence vs absence of a cache"
    );
    assert_eq!(a.reference_state_root(), root_a);

    // Persist `a`'s trie nodes (another node's cache, for `c` below).
    let mut store: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let mut write = |_: &Hash, nodes: &[([u8; 32], Vec<u8>)]| {
        store.extend(nodes.iter().cloned());
        Ok(())
    };
    let (persisted_root, n) = a.persist_trie_nodes(&mut write).expect("persist");
    assert_eq!(persisted_root, root_a);
    assert!(n > 0);

    // `c`: a restarted node with the same state, reusing `a`'s nodes: same root.
    let c = rehydrated(&b);
    let reuse = c
        .reuse_persisted_trie(&root_a, &|h| store.get(h).cloned())
        .expect("same state: the cache is reused");
    assert_eq!(reuse.accounts, 2);
    assert_eq!(c.calculate_state_root(), root_a, "another node's cache");

    // A corrupted cache: one node's bytes changed. Not reused, same root.
    let victim = *store.keys().next().expect("a node");
    let mut corrupt = store.clone();
    let mut bytes = corrupt[&victim].clone();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    corrupt.insert(victim, bytes);
    let d = rehydrated(&b);
    assert!(d
        .reuse_persisted_trie(&root_a, &|h| corrupt.get(h).cloned())
        .is_err());
    assert_eq!(d.calculate_state_root(), root_a, "a corrupt cache");

    // A cache missing a node: not reused, same root.
    let mut missing = store.clone();
    missing.remove(&victim);
    let e = rehydrated(&b);
    assert!(e
        .reuse_persisted_trie(&root_a, &|h| missing.get(h).cloned())
        .is_err());
    assert_eq!(e.calculate_state_root(), root_a, "an incomplete cache");

    // Another node's cache for a DIFFERENT state (valid nodes, wrong root): a
    // node holding `f`'s state must refuse it and keep its own root.
    let f = rehydrated(&b);
    f.accounts.set_balance(addr(4), U256::from(1));
    let root_f = f.reference_state_root();
    assert_ne!(root_f, root_a);
    assert!(f
        .reuse_persisted_trie(&root_a, &|h| store.get(h).cloned())
        .is_err());
    assert_eq!(f.calculate_state_root(), root_f, "another state's cache");

    // An isolated clone (RPC simulation) shares the trie and agrees.
    assert_eq!(a.isolated_clone().calculate_state_root(), root_a);
}

/// r1007 genesis rule (lead decision 2026-11-09): activation 0 covers block 0
/// itself, so the genesis post-state is rooted under the MPT rule like every
/// later block. (Until 3e5db765 height 0 kept the legacy root; that is now
/// only so for an activation above 0, see `mpt_state_root::active_at`.)
#[test]
fn activation_0_roots_block_0_under_the_mpt_rule() {
    let a = db();
    a.accounts.set_balance(addr(1), U256::from(10));
    a.set_storage(addr(2), slot(1), value(0, 9));
    let at_0 = a.calculate_state_root_at(0);
    assert_eq!(at_0, a.calculate_state_root_at(1), "one rule at 0 and 1");
    assert_eq!(
        at_0,
        a.reference_state_root(),
        "block 0: the standard MPT root"
    );
    a.set_root_height(0);
    assert!(
        a.mpt_rule_active(),
        "the post-state of block 0 is under the rule"
    );
}

/// The `eth_getProof` accessor: the account proof verifies against the state
/// root to the account leaf, the storage proofs against its storage hash to
/// each slot's value (or its absence), under our verifier and alloy-trie's.
#[test]
fn storage_proof_verifies() {
    let db = db();
    let c = addr(9);
    let _ = db.set_code(c, vec![0x60, 0x00]);
    db.accounts.set_balance(c, U256::from(1234));
    for i in 0..40u8 {
        db.set_storage(c, slot(i), value(i, i.wrapping_add(1)));
    }
    db.set_storage(c, slot(41), vec![0u8; 32]); // a zero: absent from the trie
    for i in 100..120u8 {
        db.accounts
            .set_balance(addr(i), U256::from(u64::from(i) + 1));
    }
    let present = slot(5);
    let zero = slot(41);
    let never = slot(77);
    let p = db
        .get_proof(&c, &[present.clone(), zero.clone(), never.clone()])
        .expect("proof under the MPT rule");
    let root = *p.state_root.as_bytes();
    assert_eq!(p.state_root, db.reference_state_root());

    // Account proof.
    let akey = mpt_state::account_trie_key(&c.0);
    let leaf = mpt::verify_proof(&root, &akey, &p.account_proof)
        .expect("account proof")
        .expect("present");
    assert_eq!(Some(&leaf), p.account_leaf.as_ref());
    assert_eq!(
        mpt_state::account_leaf_storage_root(&leaf),
        Some(p.storage_hash)
    );
    let bytes: Vec<Bytes> = p
        .account_proof
        .iter()
        .map(|n| Bytes::from(n.clone()))
        .collect();
    assert!(alloy_trie::proof::verify_proof(
        B256::from(root),
        Nibbles::unpack(akey),
        Some(leaf.clone()),
        bytes.iter()
    )
    .is_ok());
    // An ordinary account leaf decodes as Ethereum's 4-item account.
    let r = rlp::Rlp::new(&leaf);
    assert_eq!(r.item_count().expect("list"), 4);
    assert_eq!(r.val_at::<u64>(0).expect("nonce"), 0);
    assert_eq!(
        r.at(1).expect("balance").data().expect("bytes"),
        &[0x04, 0xd2]
    );

    // Storage proofs.
    let sroot = p.storage_hash;
    assert_ne!(sroot, EMPTY_ROOT);
    for sp in &p.storage {
        let skey = mpt_state::storage_trie_key(&sp.key);
        let got = mpt::verify_proof(&sroot, &skey, &sp.proof).expect("storage proof");
        let want = sp
            .value
            .as_deref()
            .and_then(mpt_state::encode_storage_value);
        assert_eq!(got, want, "slot {}", hex::encode(&sp.key));
        let bytes: Vec<Bytes> = sp.proof.iter().map(|n| Bytes::from(n.clone())).collect();
        assert!(alloy_trie::proof::verify_proof(
            B256::from(sroot),
            Nibbles::unpack(skey),
            want,
            bytes.iter()
        )
        .is_ok());
    }
    assert_eq!(p.storage[0].value, Some(value(5, 6)));
    assert_eq!(p.storage[1].value, Some(vec![0u8; 32]), "resident zero");
    assert_eq!(p.storage[2].value, None);

    // A tampered proof does not verify to the value.
    let mut bad = p.storage[0].proof.clone();
    let last = bad.len() - 1;
    let n = bad[last].len() - 1;
    bad[last][n] ^= 0x01;
    assert_ne!(
        mpt::verify_proof(&sroot, &mpt_state::storage_trie_key(&present), &bad),
        Ok(mpt_state::encode_storage_value(&value(5, 6)))
    );

    // An absent account: an exclusion proof.
    let ghost = Address([0xEE; 20]);
    let g = db.get_proof(&ghost, &[]).expect("proof");
    assert_eq!(g.account_leaf, None);
    assert_eq!(g.storage_hash, EMPTY_ROOT);
    assert_eq!(
        mpt::verify_proof(
            &root,
            &mpt_state::account_trie_key(&ghost.0),
            &g.account_proof
        ),
        Ok(None)
    );
}

/// The legacy rule has no proofs: the accessor refuses instead of returning a
/// proof against a different commitment.
#[test]
fn proofs_need_the_mpt_rule() {
    let db = db();
    db.set_root_height(0);
    assert!(db.get_proof(&addr(1), &[]).is_err());
}

// ---------------------------------------------------------------------------
// An independent reference, written from the spec text alone
// (docs/consensus/STATE_ROOT_MPT.md §2-§3), sharing no code with the node:
// parity's `rlp` encoder for the leaves and parity's `triehash` (OpenEthereum's
// root builder) for both tries. `reference_state_root` (the in-crate
// from-scratch builder) is a second reference; this one also checks the leaf
// encodings and the empty-account / zero-slot rules independently.
// ---------------------------------------------------------------------------

type Keccak = keccak_hasher::KeccakHasher;

/// Big-endian with leading zero bytes removed (an RLP integer's payload).
fn spec_trim(b: &[u8]) -> Vec<u8> {
    b.iter().copied().skip_while(|x| *x == 0).collect()
}

/// §3 storage leaf, or `None` when the slot is not in the trie.
fn spec_storage_leaf(v: &[u8]) -> Option<Vec<u8>> {
    if v.len() == 32 {
        let t = spec_trim(v);
        if t.is_empty() {
            return None;
        }
        Some(rlp::encode(&t).to_vec())
    } else {
        let mut s = rlp::RlpStream::new_list(1);
        s.append(&v.to_vec());
        Some(s.out().to_vec())
    }
}

/// The state root of `snap` per the spec, from its resident accounts and slots.
fn spec_state_root(snap: &citrate_execution::state::StateSnapshot) -> [u8; 32] {
    const EMPTY: [u8; 32] = EMPTY_ROOT;
    let keccak_empty: [u8; 32] = keccak(&[]);
    let storage = snap.storage_map();
    let mut accounts: HashMap<Address, AccountState> =
        snap.account_entries().iter().cloned().collect();
    // A contract's slots commit under its account even if no account entry is
    // resident (the account is then the default one).
    for a in storage.keys() {
        accounts.entry(*a).or_default();
    }
    let mut leaves: Vec<([u8; 20], Vec<u8>)> = Vec::new();
    for (a, acct) in &accounts {
        let storage_root: [u8; 32] = match storage.get(a) {
            Some(slots) => {
                let items: Vec<(Vec<u8>, Vec<u8>)> = slots
                    .iter()
                    .filter_map(|(k, v)| spec_storage_leaf(v).map(|l| (k.clone(), l)))
                    .collect();
                if items.is_empty() {
                    EMPTY
                } else {
                    triehash::sec_trie_root::<Keccak, _, _, _>(items)
                }
            }
            None => EMPTY,
        };
        let code_hash: [u8; 32] = if acct.code_hash == Hash::default() {
            keccak_empty
        } else {
            *acct.code_hash.as_bytes()
        };
        let empty = acct.nonce == 0
            && acct.balance.is_zero()
            && code_hash == keccak_empty
            && storage_root == EMPTY
            && acct.model_permissions.is_empty();
        if empty {
            continue;
        }
        let mut balance = [0u8; 32];
        acct.balance.to_big_endian(&mut balance);
        let items = if acct.model_permissions.is_empty() {
            4
        } else {
            5
        };
        let mut s = rlp::RlpStream::new_list(items);
        s.append(&acct.nonce);
        s.append(&spec_trim(&balance));
        s.append(&storage_root.to_vec());
        s.append(&code_hash.to_vec());
        if items == 5 {
            s.begin_list(acct.model_permissions.len());
            for m in &acct.model_permissions {
                s.append(&m.0.as_bytes().to_vec());
            }
        }
        leaves.push((a.0, s.out().to_vec()));
    }
    if leaves.is_empty() {
        return EMPTY;
    }
    triehash::sec_trie_root::<Keccak, _, _, _>(leaves)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// CV-14: over random histories (the same operations as above), the node's
    /// incremental root equals the root an independent implementation of the
    /// spec computes from the resident state alone, after every root step.
    #[test]
    fn incremental_root_equals_independent_spec_reference(ops in prop::collection::vec(op(), 1..80)) {
        let db = db();
        let mut snaps = Vec::new();
        for (i, o) in ops.iter().enumerate() {
            apply(&db, o, &mut snaps);
            if matches!(o, Op::Root | Op::Restore(_) | Op::Undo(_)) || i.is_multiple_of(5) {
                let root = db.calculate_state_root();
                prop_assert_eq!(
                    *root.as_bytes(),
                    spec_state_root(&db.snapshot()),
                    "step {} ({:?}): node root != independent spec root", i, o
                );
            }
        }
        prop_assert_eq!(*db.calculate_state_root().as_bytes(), spec_state_root(&db.snapshot()));
    }

    /// CV-14 purity, by apply order: the same final writes applied in two
    /// different orders, one db computing roots between writes and the other
    /// only at the end, give the same root.
    #[test]
    fn root_does_not_depend_on_apply_order(
        writes in prop::collection::vec((0u8..6, 0u8..10, any::<u8>(), any::<u8>(), any::<u64>()), 1..60),
        seed in any::<u64>(),
    ) {
        // The last write per (account, slot) wins, so collapse to the final state
        // first: both dbs then hold exactly the same state.
        let mut fin: std::collections::BTreeMap<(u8, u8), (u8, u8, u64)> = Default::default();
        for (a, s, k, n, b) in &writes {
            fin.insert((*a, *s), (*k, *n, *b));
        }
        let mut order: Vec<_> = fin.iter().collect();
        let a = db();
        for ((ad, s), (k, n, b)) in &order {
            a.accounts.set_balance(addr(*ad), U256::from(*b % 4));
            a.set_storage(addr(*ad), slot(*s), value(*k, *n));
            let _ = a.calculate_state_root();
        }
        // A deterministic shuffle of the same writes.
        let mut x = seed | 1;
        for i in (1..order.len()).rev() {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            order.swap(i, (x % (i as u64 + 1)) as usize);
        }
        let b = db();
        // Balances are per account: replay them so the last write per account
        // matches `a` (in `a`, the last (account, slot) in key order wins).
        let mut last_balance: std::collections::BTreeMap<u8, u64> = Default::default();
        for ((ad, _), (_, _, bal)) in fin.iter() {
            last_balance.insert(*ad, *bal % 4);
        }
        for ((ad, s), (k, n, _)) in &order {
            b.set_storage(addr(*ad), slot(*s), value(*k, *n));
        }
        for (ad, bal) in &last_balance {
            b.accounts.set_balance(addr(*ad), U256::from(*bal));
        }
        let ra = a.calculate_state_root();
        prop_assert_eq!(ra, b.calculate_state_root());
        prop_assert_eq!(*ra.as_bytes(), spec_state_root(&b.snapshot()));
    }
}

/// CV-14: storage held for an address with no resident account entry (the
/// governance precompile writes its `PARAM:` / `PENDING:` slots through
/// `set_storage` without creating an account) is state, so the root must
/// commit it: it commits as the default account holding those slots. Two
/// states that differ only in such a slot must have different roots, and a
/// restarted node must reproduce the root.
#[test]
fn storage_of_an_address_with_no_account_entry_is_committed() {
    let gov = addr(0xfe);
    let a = db();
    a.accounts.set_balance(addr(1), U256::from(5));
    let before = a.calculate_state_root();
    a.set_storage(gov, b"PARAM:artifact_replication".to_vec(), vec![3]);
    assert!(a.accounts.get_resident(&gov).is_none(), "no account entry");
    let after = a.calculate_state_root();
    assert_ne!(after, before, "a storage-only address moved no root");
    assert_eq!(after, a.reference_state_root());
    assert_eq!(*after.as_bytes(), spec_state_root(&a.snapshot()));

    // A different value: a different root.
    let b = db();
    b.accounts.set_balance(addr(1), U256::from(5));
    b.set_storage(gov, b"PARAM:artifact_replication".to_vec(), vec![4]);
    assert_ne!(b.calculate_state_root(), after);

    // Restart: the same root, and the persisted trie is reused.
    let mut store: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let mut write = |_: &Hash, nodes: &[([u8; 32], Vec<u8>)]| {
        store.extend(nodes.iter().cloned());
        Ok(())
    };
    a.persist_trie_nodes(&mut write).expect("persist");
    let c = rehydrated(&a);
    assert_eq!(c.calculate_state_root(), after, "a restarted node");
    let d = rehydrated(&a);
    d.reuse_persisted_trie(&after, &|h| store.get(h).cloned())
        .expect("same state: the cache is reused");
    assert_eq!(d.calculate_state_root(), after);

    // Deleting the slot again restores the earlier root.
    a.delete_storage(gov, b"PARAM:artifact_replication");
    assert_eq!(a.calculate_state_root(), before);
    assert_eq!(a.reference_state_root(), before);
}
