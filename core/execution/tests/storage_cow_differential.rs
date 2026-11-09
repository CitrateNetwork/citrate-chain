//! r1007 storage copy-on-write: the persistent storage map changes the cost of
//! a snapshot, never a value. This binary pins the behaviour of the
//! implementation it replaces (ghsa-p44f `r1007/s3-state-root` @ 3e5db765):
//!
//! * `transcripts_match_the_replaced_implementation`: seeded random histories
//!   of storage writes, deletes, non-dirtying loads, account changes, blocks,
//!   snapshot-ring reverts, deep undo through pre-images (the node's boot
//!   reorg-window rebuild), reorgs onto a new branch and isolated clones, under
//!   the legacy root (MPT unset), the MPT root from genesis (the r1007 rule) and
//!   an MPT activation inside the history (a rehearsal devnet). Every root (the
//!   committed one, the legacy and canonical legacy variants, the from-scratch
//!   reference), every undo record, every read, every proof and the final
//!   state are folded into one digest per (seed, activation). The digests were
//!   produced by 3e5db765 and are compared byte for byte.
//! * `random_histories_agree_with_a_plain_model`: proptest, the db against a
//!   `BTreeMap` model of the storage, with snapshots, reverts and undo; every
//!   read and every root equals the model's (the root of a fresh db holding the
//!   model's state).
//!
//! Heights stay >= 1, so the genesis rule change (block 0 under the MPT rule,
//! lead decision 2026-11-09) does not enter these digests; it has its own test
//! in `mpt_state_root.rs`.
//!
//! The MPT activation is process-wide: the tests here serialize on `RULE`.

use citrate_consensus::types::Hash;
use citrate_execution::state::mpt::keccak;
use citrate_execution::state::StateSnapshot;
use citrate_execution::types::{AccountState, Address};
use citrate_execution::StateDB;
use primitive_types::U256;
use proptest::prelude::*;
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use std::sync::Mutex;

static RULE: Mutex<()> = Mutex::new(());

fn set_rule(activation: Option<u64>) {
    citrate_execution::mpt_state_root::set_mpt_state_root_height(activation);
}

/// splitmix64: a fixed, dependency-free generator (the digests depend on it).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Addresses 0..3 are contracts with an account entry; 4 holds storage only
/// (no account entry ever: the empty-account commitment); 5..7 are EOAs.
fn addr(i: u64) -> Address {
    let h = keccak(&[b'a', i as u8]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[..20]);
    Address(a)
}

const STORAGE_ADDRS: u64 = 5;
const KEYS: u64 = 48;

/// Sequential EVM slots, mapping slots and non-EVM keys.
fn key(i: u64) -> Vec<u8> {
    match i % 3 {
        0 => {
            let mut k = vec![0u8; 32];
            k[24..].copy_from_slice(&i.to_be_bytes());
            k
        }
        1 => keccak(&i.to_be_bytes()).to_vec(),
        _ => format!("PARAM:{i}").into_bytes(),
    }
}

/// EVM words (some zero: resident but absent from the MPT) and non-EVM values.
fn value(rng: &mut Rng) -> Vec<u8> {
    match rng.below(6) {
        0 => vec![0u8; 32],
        1 => vec![rng.below(250) as u8; rng.below(5) as usize],
        _ => {
            let mut v = vec![0u8; 32];
            v[24..].copy_from_slice(&rng.below(1 << 20).to_be_bytes());
            v
        }
    }
}

struct Transcript(Keccak256);
impl Transcript {
    fn tag(&mut self, t: &str) {
        self.0.update((t.len() as u32).to_be_bytes());
        self.0.update(t.as_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.update((b.len() as u32).to_be_bytes());
        self.0.update(b);
    }
    fn hash(&mut self, h: &Hash) {
        self.0.update(h.as_bytes());
    }
    fn opt(&mut self, v: &Option<Vec<u8>>) {
        match v {
            Some(v) => {
                self.0.update([1]);
                self.bytes(v);
            }
            None => self.0.update([0]),
        }
    }
    fn account(&mut self, a: &Option<AccountState>) {
        match a {
            Some(a) => {
                self.0.update([1]);
                self.bytes(&bincode::serialize(a).expect("account encodes"));
            }
            None => self.0.update([0]),
        }
    }
}

type Undo = (
    Vec<(Address, Option<AccountState>)>,
    Vec<(Address, Vec<u8>, Option<Vec<u8>>)>,
);

fn record_undo(t: &mut Transcript, undo: &Undo) {
    let mut acc = undo.0.clone();
    acc.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
    let mut sto = undo.1.clone();
    sto.sort_by(|a, b| (a.0 .0, &a.1).cmp(&(b.0 .0, &b.1)));
    t.tag("undo");
    for (a, s) in &acc {
        t.bytes(&a.0);
        t.account(s);
    }
    for (a, k, v) in &sto {
        t.bytes(&a.0);
        t.bytes(k);
        t.opt(v);
    }
}

/// Every root this db can be asked for at `height`, in a fixed order.
fn record_roots(t: &mut Transcript, db: &StateDB, height: u64) {
    t.tag("roots");
    t.hash(&db.calculate_state_root());
    t.hash(&db.calculate_state_root_with(None, height));
    t.hash(&db.calculate_state_root_with(Some(0), height));
    t.hash(&db.reference_state_root());
    t.hash(&db.reference_state_root_with(None, height));
    for i in 0..STORAGE_ADDRS {
        match db.get_storage_root_recomputed(&addr(i)) {
            Some(h) => t.hash(&h),
            None => t.tag("no-trie"),
        }
    }
}

fn record_reads(t: &mut Transcript, db: &StateDB, rng: &mut Rng) {
    t.tag("reads");
    for _ in 0..6 {
        let a = rng.below(STORAGE_ADDRS);
        let k = key(rng.below(KEYS));
        t.opt(&db.get_storage(&addr(a), &k));
    }
}

fn record_proof(t: &mut Transcript, db: &StateDB, rng: &mut Rng) {
    let a = addr(rng.below(STORAGE_ADDRS));
    let keys = vec![key(rng.below(KEYS)), key(rng.below(KEYS))];
    t.tag("proof");
    match db.get_proof(&a, &keys) {
        Ok(p) => {
            t.hash(&p.state_root);
            for n in &p.account_proof {
                t.bytes(n);
            }
            t.opt(&p.account_leaf);
            t.bytes(&p.storage_hash);
            for s in &p.storage {
                t.bytes(&s.key);
                t.opt(&s.value);
                for n in &s.proof {
                    t.bytes(n);
                }
            }
        }
        Err(e) => t.tag(&e),
    }
}

fn record_state(t: &mut Transcript, snap: &StateSnapshot) {
    t.tag("state");
    let mut storage: Vec<(Address, BTreeMap<Vec<u8>, Vec<u8>>)> = snap
        .storage_map()
        .into_iter()
        .map(|(a, m)| (a, m.into_iter().collect()))
        .collect();
    storage.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
    for (a, m) in storage {
        t.bytes(&a.0);
        for (k, v) in m {
            t.bytes(&k);
            t.bytes(&v);
        }
    }
    let mut accounts = snap.account_entries().to_vec();
    accounts.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
    for (a, s) in accounts {
        t.bytes(&a.0);
        t.account(&Some(s));
    }
}

/// The node's `rooted` (`node/src/canonical_apply.rs`).
fn rooted(snap: StateSnapshot, height: u64) -> (Hash, StateSnapshot) {
    let scratch = StateDB::new();
    scratch.restore(snap);
    scratch.set_root_height(height);
    let root = scratch.calculate_state_root();
    scratch.accounts.clear_dirty();
    let _ = scratch.take_dirty_storage();
    (root, scratch.snapshot())
}

/// One applied block on the chain the history keeps.
struct Applied {
    height: u64,
    root: Hash,
    snap: StateSnapshot,
    /// Reverts this block to the one before it (`None` for the base).
    undo: Option<Undo>,
}

fn run(seed: u64, activation: Option<u64>) -> String {
    set_rule(activation);
    let mut rng = Rng(seed);
    let mut t = Transcript(Keccak256::new());
    let db = StateDB::new();
    db.set_root_height(1);
    for i in 0..8 {
        if i != 4 {
            db.accounts.set_balance(addr(i), U256::from(1 + i));
        }
    }
    let root = db.calculate_state_root();
    db.accounts.clear_dirty();
    let _ = db.take_dirty_storage();
    let mut chain = vec![Applied {
        height: 1,
        root,
        snap: db.snapshot(),
        undo: None,
    }];
    for _ in 0..240 {
        match rng.below(100) {
            // Storage writes (a block's execution).
            0..=34 => {
                let a = addr(rng.below(STORAGE_ADDRS));
                let k = key(rng.below(KEYS));
                let v = value(&mut rng);
                db.set_storage(a, k, v);
            }
            35..=44 => {
                let a = addr(rng.below(STORAGE_ADDRS));
                db.delete_storage(a, &key(rng.below(KEYS)));
            }
            45..=49 => {
                let a = addr(rng.below(STORAGE_ADDRS));
                let k = key(rng.below(KEYS));
                let v = value(&mut rng);
                db.cache_storage(a, k, v);
            }
            50..=56 => {
                let i = rng.below(8);
                if i != 4 {
                    db.accounts
                        .set_balance(addr(i), U256::from(rng.below(1_000)));
                }
            }
            57..=58 => {
                let i = rng.below(4);
                db.accounts.set_account(addr(i), AccountState::default());
            }
            // A block: root, commit, snapshot, undo record.
            59..=82 => {
                let height = db.root_height() + 1;
                db.set_root_height(height);
                record_roots(&mut t, &db, height);
                let root = db.calculate_state_root();
                let mut dirty = db.take_dirty_storage();
                dirty.sort_by(|a, b| (a.0 .0, &a.1).cmp(&(b.0 .0, &b.1)));
                t.tag("dirty");
                for (a, k) in &dirty {
                    t.bytes(&a.0);
                    t.bytes(k);
                }
                db.accounts.clear_dirty();
                let snap = db.snapshot();
                let prev = chain.last().expect("base");
                let undo = snap.pre_images_since(&prev.snap);
                record_undo(&mut t, &undo);
                chain.push(Applied {
                    height,
                    root,
                    snap,
                    undo: Some(undo),
                });
                record_reads(&mut t, &db, &mut rng);
            }
            // Snapshot-ring revert to an earlier block.
            83..=87 => {
                if chain.len() > 1 {
                    let keep = 1 + rng.below(chain.len() as u64) as usize;
                    chain.truncate(keep);
                    let back = chain.last().expect("kept");
                    db.restore(back.snap.clone());
                    t.tag("revert");
                    t.hash(&db.calculate_state_root());
                    t.hash(&back.root);
                }
            }
            // Deep undo through pre-images from the tip (the boot rebuild), then a
            // reorg onto a new branch from there.
            88..=93 => {
                if chain.len() > 1 {
                    let depth = 1 + rng.below((chain.len() - 1) as u64) as usize;
                    let tip = chain.last().expect("tip");
                    let (tip_root, mut above) = rooted(tip.snap.clone(), tip.height);
                    t.tag("rebuild");
                    t.hash(&tip_root);
                    for _ in 0..depth {
                        let top = chain.pop().expect("above base");
                        let below = chain.last().expect("below");
                        let (acc, sto) = top.undo.as_ref().expect("undo");
                        let reverted = above.with_pre_images(acc, sto, below.height);
                        let (root, snap) = rooted(reverted, below.height);
                        if activation.is_some_and(|a| below.height >= a) {
                            // The MPT root is a function of the state: the rebuilt
                            // root is the committed one.
                            assert_eq!(root, below.root, "rebuilt root at {}", below.height);
                            t.hash(&root);
                        } else {
                            // The structural legacy root depends on the remove
                            // history, and `with_pre_images` replays pre-images in
                            // hash-map order, so the replaced implementation itself
                            // gives it run to run differently. Pin the canonical
                            // legacy root of the rebuilt state instead.
                            let check = StateDB::new();
                            check.restore(snap.clone());
                            t.hash(&check.calculate_state_root_with(Some(0), below.height));
                        }
                        t.hash(&below.root);
                        above = snap;
                    }
                    // Reorg onto the rebuilt state; below the MPT rule onto the
                    // ring's snapshot of it (the same state, a fixed history).
                    let below = chain.last().expect("below");
                    if activation.is_some_and(|a| below.height >= a) {
                        db.restore(above);
                    } else {
                        db.restore(below.snap.clone());
                    }
                }
            }
            94..=96 => {
                let iso = db.isolated_clone();
                t.tag("isolated");
                t.hash(&iso.calculate_state_root());
                iso.set_storage(addr(0), key(1), vec![7; 32]);
                t.hash(&iso.calculate_state_root());
                t.opt(&db.get_storage(&addr(0), &key(1)));
            }
            _ => record_proof(&mut t, &db, &mut rng),
        }
    }
    let height = db.root_height() + 1;
    db.set_root_height(height);
    record_roots(&mut t, &db, height);
    t.hash(&db.full_state_fingerprint());
    record_state(&mut t, &db.snapshot());
    hex::encode(t.0.finalize())
}

const SEEDS: [u64; 4] = [1, 0x5EED, 0xC0FFEE, 0x1007];
const ACTIVATIONS: [Option<u64>; 3] = [None, Some(0), Some(6)];

/// Produced by `r1007/s3-state-root` @ 3e5db765 (the implementation this branch
/// replaces), one per (seed, activation), in `SEEDS` x `ACTIVATIONS` order.
const EXPECTED: [[&str; 3]; 4] = [
    [
        "7d7a4ca400c4da40e50a20a41dcc190930d161d6c83bfca8d5014bd28091cbf3",
        "318f2ae94bd2a0226e8ede1a3f9d5be5913bcab765f88f6fda757ccbcd49508e",
        "a51c56bf86b0d71a5d3bd621812ee5bab323282b82a377af195669702dbab098",
    ],
    [
        "3c7ead0107f6287bed2028144687936dc39944e9013b4613cc99866efdccda34",
        "ad6321c3b1ca6d1491a976d95d20b571fe7b1f3eb6313bf33e47b46aaf358cff",
        "34b0d83f5b18f27486778efcf3d73920adfd903506b992c808f687a7f8fa1d0c",
    ],
    [
        "39a3c37a2f35806044bb897caf515151cd1060761d4d422b2f73f36a65190100",
        "38ebae969afa28c30b1adfa9c01a417c7d97c4cbbbcb01905d7b21410b5c4117",
        "e59aa6532ce30645d202d20b1738938d16ecd4eee21b585ba867e8643c2af69b",
    ],
    [
        "a01b9890fefe860bb9e8d8d0a2fc0ddc6e3802116700708757bc13efcd0804a2",
        "1219f7b99bb6c383a07459afc977bd5dc40f07e80d7cc34de9e313c5045c78db",
        "951428ea50cb6acf5f81d06c5e7966818fbe15a511622ddc432fc6ba3e54df4a",
    ],
];

#[test]
fn transcripts_match_the_replaced_implementation() {
    let _g = RULE.lock().unwrap_or_else(|e| e.into_inner());
    let mut got = Vec::new();
    for seed in SEEDS {
        let row: Vec<String> = ACTIVATIONS.iter().map(|a| run(seed, *a)).collect();
        got.push(row);
    }
    let printed: Vec<String> = got
        .iter()
        .map(|r| format!("    [\"{}\", \"{}\", \"{}\"],", r[0], r[1], r[2]))
        .collect();
    eprintln!("COWDIGESTS\n{}", printed.join("\n"));
    for (i, seed) in SEEDS.iter().enumerate() {
        for (j, a) in ACTIVATIONS.iter().enumerate() {
            assert_eq!(
                got[i][j], EXPECTED[i][j],
                "seed {seed:#x}, MPT activation {a:?}: the transcript differs from 3e5db765"
            );
        }
    }
}

#[derive(Debug, Clone)]
enum Op {
    Store(u8, u8, u8),
    Delete(u8, u8),
    Cache(u8, u8, u8),
    Block,
    Snapshot,
    Revert(u8),
    Undo(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        8 => (0u8..5, 0u8..24, any::<u8>()).prop_map(|(a, k, v)| Op::Store(a, k, v)),
        3 => (0u8..5, 0u8..24).prop_map(|(a, k)| Op::Delete(a, k)),
        2 => (0u8..5, 0u8..24, any::<u8>()).prop_map(|(a, k, v)| Op::Cache(a, k, v)),
        3 => Just(Op::Block),
        2 => Just(Op::Snapshot),
        1 => any::<u8>().prop_map(Op::Revert),
        1 => any::<u8>().prop_map(Op::Undo),
    ]
}

fn val(v: u8) -> Vec<u8> {
    if v.is_multiple_of(5) {
        vec![0u8; 32]
    } else {
        let mut w = vec![0u8; 32];
        w[31] = v;
        w
    }
}

type Model = BTreeMap<(u8, Vec<u8>), Vec<u8>>;

/// The root of a fresh db holding exactly `model` (no history at all). The
/// canonical root (storage roots from the slot set): the structural legacy root
/// depends on the remove history by design (`Trie::legacy_root_hash`), which the
/// transcript test pins instead.
fn model_root(model: &Model, height: u64) -> Hash {
    let fresh = StateDB::new();
    for ((a, k), v) in model {
        fresh.set_storage(addr(u64::from(*a)), k.clone(), v.clone());
    }
    fresh.set_root_height(height);
    fresh.calculate_state_root_with(Some(0), height)
}

fn check_history(ops: &[Op], activation: Option<u64>) -> Result<(), TestCaseError> {
    set_rule(activation);
    let db = StateDB::new();
    db.set_root_height(1);
    let mut model: Model = BTreeMap::new();
    let mut snaps: Vec<(StateSnapshot, Model)> = Vec::new();
    for o in ops {
        match o {
            Op::Store(a, k, v) | Op::Cache(a, k, v) => {
                let (kk, vv) = (key(u64::from(*k)), val(*v));
                if matches!(o, Op::Store(..)) {
                    db.set_storage(addr(u64::from(*a)), kk.clone(), vv.clone());
                } else {
                    db.cache_storage(addr(u64::from(*a)), kk.clone(), vv.clone());
                }
                model.insert((*a, kk), vv);
            }
            Op::Delete(a, k) => {
                let kk = key(u64::from(*k));
                db.delete_storage(addr(u64::from(*a)), &kk);
                model.remove(&(*a, kk));
            }
            Op::Block => {
                let h = db.root_height() + 1;
                db.set_root_height(h);
                prop_assert_eq!(
                    db.calculate_state_root_with(Some(0), h),
                    model_root(&model, h)
                );
                db.accounts.clear_dirty();
                let _ = db.take_dirty_storage();
            }
            Op::Snapshot => snaps.push((db.snapshot(), model.clone())),
            Op::Revert(i) => {
                if !snaps.is_empty() {
                    let (s, m) = snaps[usize::from(*i) % snaps.len()].clone();
                    db.restore(s);
                    model = m;
                }
            }
            Op::Undo(i) => {
                if !snaps.is_empty() {
                    let (prev, m) = snaps[usize::from(*i) % snaps.len()].clone();
                    let cur = db.snapshot();
                    let (acc, sto) = cur.pre_images_since(&prev);
                    let h = db.root_height();
                    db.restore(cur.with_pre_images(&acc, &sto, h));
                    model = m;
                }
            }
        }
        for ((a, k), v) in &model {
            prop_assert_eq!(db.get_storage(&addr(u64::from(*a)), k), Some(v.clone()));
        }
    }
    let h = db.root_height() + 1;
    db.set_root_height(h);
    prop_assert_eq!(
        db.calculate_state_root_with(Some(0), h),
        model_root(&model, h)
    );
    let mut got: Model = BTreeMap::new();
    for (a, m) in db.snapshot().storage_map() {
        let i = (0u8..5)
            .find(|i| addr(u64::from(*i)) == a)
            .expect("known address");
        for (k, v) in m {
            got.insert((i, k), v);
        }
    }
    prop_assert_eq!(got, model);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn random_histories_agree_with_a_plain_model(ops in prop::collection::vec(op(), 1..120)) {
        let _g = RULE.lock().unwrap_or_else(|e| e.into_inner());
        check_history(&ops, Some(0))?;
        check_history(&ops, None)?;
    }
}
