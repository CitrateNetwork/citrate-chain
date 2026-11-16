// citrate/core/execution/src/state/slot_map.rs
//
// A persistent (structurally shared) map from a contract's storage slot key to
// its value: the slot set of a `Trie` (r1007 storage copy-on-write).
//
// WHY
//
// A `StateSnapshot` shares each contract's storage with the live `StateDB`, and
// the node keeps a ring of snapshots (one per block in the reorg window). With a
// plain `HashMap`, the first write to a contract after a snapshot copied the
// contract's WHOLE storage (`Arc::make_mut`), and dropping the snapshot later
// freed that copy: cost proportional to the contract's size, on the apply path
// and on the boot reorg-window rebuild (benchmarks/2026-11-09-cv14-mpt-state-root.md:
// ~40% of the rebuild copying, ~27% freeing). Here a write copies only the
// nodes on one path, O(log n), and every other node stays shared by every
// version that holds it. `diff` walks two versions and skips every subtree they
// share, so the undo record of a block costs O(changed slots x log n) too.
//
// SHAPE
//
// A 16-ary hash trie (a HAMT) on a 64-bit hash of the key, one nibble per
// level, children stored compactly behind a 16-bit occupancy mask:
//
//   * a `Leaf` holds every entry with one hash (one entry, unless two keys
//     collide on all 64 bits); it sits at the shallowest level at which its
//     hash prefix is unique, so the shape is a function of the key set (equal
//     maps have equal shapes, whatever their history), which keeps diffs of
//     neighbouring versions small;
//   * a `Branch` exists exactly where two or more distinct hashes share a
//     prefix, so depth is about log16(n): 5 levels at 1M slots.
//
// The hash is SipHash with one random key per process (std's `RandomState`,
// drawn once): slot keys are chosen by contracts, and an unkeyed fast hash would
// let a contract grind keys onto one deep path. The shape is never observable:
// nothing is persisted, hashed into a root or iterated in a consensus-relevant
// order from it (every consumer sorts, or folds into an order-independent
// structure). All versions in a process share the key, which `diff` relies on.
//
// Consensus: this is a container. Roots are computed from its contents by the
// MPT (`crate::state::mpt`) and the legacy tree, exactly as before.

// PANIC-S1 G2: consensus path (state root); panic-free outside tests.
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

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, OnceLock};

/// Levels of 4 bits in a 64-bit hash.
const LEVELS: u32 = 16;

static HASH_KEY: OnceLock<RandomState> = OnceLock::new();

fn hash_key(key: &[u8]) -> u64 {
    let mut h = HASH_KEY.get_or_init(RandomState::new).build_hasher();
    h.write(key);
    h.finish()
}

/// The child index of `hash` at `level` (< 16).
fn nibble(hash: u64, level: u32) -> u32 {
    // level < LEVELS, so the shift is < 64.
    ((hash >> (level.wrapping_mul(4) & 63)) & 0xf) as u32
}

type Entry = (Vec<u8>, Vec<u8>);

/// A `diff` visitor: `(key, value before, value after)` (`None`: absent).
type DiffVisitor<'f, 'a> = dyn FnMut(&'a [u8], Option<&'a [u8]>, Option<&'a [u8]>) + 'f;

enum Node {
    Branch {
        /// Bit i set: child i present, at `children[popcount(mask below i)]`.
        mask: u16,
        children: Vec<Arc<Node>>,
    },
    Leaf {
        hash: u64,
        entries: Vec<Entry>,
    },
}

fn slot_of(mask: u16, nib: u32) -> usize {
    let below = (1u32 << nib).wrapping_sub(1) as u16;
    (mask & below).count_ones() as usize
}

impl Node {
    fn leaf(hash: u64, key: Vec<u8>, value: Vec<u8>) -> Arc<Node> {
        Arc::new(Node::Leaf {
            hash,
            entries: vec![(key, value)],
        })
    }

    fn child(&self, nib: u32) -> Option<&Arc<Node>> {
        match self {
            Node::Branch { mask, children } if mask & (1 << nib) != 0 => {
                children.get(slot_of(*mask, nib))
            }
            _ => None,
        }
    }

    /// The single entry hash of a subtree that holds one distinct hash (a
    /// leaf), else `None`.
    fn as_leaf(&self) -> Option<u64> {
        match self {
            Node::Leaf { hash, .. } => Some(*hash),
            Node::Branch { .. } => None,
        }
    }

    fn for_each<'a>(&'a self, f: &mut dyn FnMut(&'a [u8], &'a [u8])) {
        match self {
            Node::Branch { children, .. } => {
                for c in children {
                    c.for_each(f);
                }
            }
            Node::Leaf { entries, .. } => {
                for (k, v) in entries {
                    f(k, v);
                }
            }
        }
    }
}

/// A branch at `level` holding two subtrees with distinct hashes `ha`, `hb`
/// (both leaves): nested branches down to the first level they differ.
fn join(level: u32, ha: u64, a: Arc<Node>, hb: u64, b: Arc<Node>) -> Arc<Node> {
    let (na, nb) = (nibble(ha, level), nibble(hb, level));
    if na == nb && level.wrapping_add(1) < LEVELS {
        let inner = join(level.wrapping_add(1), ha, a, hb, b);
        return Arc::new(Node::Branch {
            mask: 1 << na,
            children: vec![inner],
        });
    }
    // na != nb here: distinct 64-bit hashes differ in some nibble, and a
    // shared nibble recurses until they do.
    let (first, second) = if na < nb { (a, b) } else { (b, a) };
    Arc::new(Node::Branch {
        mask: (1 << na) | (1 << nb),
        children: vec![first, second],
    })
}

/// `node` with `key` set to `value`; the previous value if there was one.
fn insert(
    node: Option<&Arc<Node>>,
    level: u32,
    hash: u64,
    key: Vec<u8>,
    value: Vec<u8>,
) -> (Arc<Node>, Option<Vec<u8>>) {
    let Some(n) = node else {
        return (Node::leaf(hash, key, value), None);
    };
    match n.as_ref() {
        Node::Leaf { hash: h, entries } if *h == hash => {
            let mut entries = entries.clone();
            let old = match entries.iter_mut().find(|(k, _)| *k == key) {
                Some(e) => Some(std::mem::replace(&mut e.1, value)),
                None => {
                    entries.push((key, value));
                    None
                }
            };
            (Arc::new(Node::Leaf { hash, entries }), old)
        }
        Node::Leaf { hash: h, .. } => (
            join(level, *h, n.clone(), hash, Node::leaf(hash, key, value)),
            None,
        ),
        Node::Branch { mask, children } => {
            let nib = nibble(hash, level);
            let at = slot_of(*mask, nib);
            let mut children = children.clone();
            let (child, old) = insert(n.child(nib), level.wrapping_add(1), hash, key, value);
            if mask & (1 << nib) != 0 {
                if let Some(c) = children.get_mut(at) {
                    *c = child;
                }
            } else {
                children.insert(at.min(children.len()), child);
            }
            (
                Arc::new(Node::Branch {
                    mask: mask | (1 << nib),
                    children,
                }),
                old,
            )
        }
    }
}

enum Removed {
    /// The key was absent: the node is unchanged.
    Absent,
    /// The key was removed; the new subtree (`None`: empty) and its value.
    Gone(Option<Arc<Node>>, Vec<u8>),
}

fn remove(n: &Arc<Node>, level: u32, hash: u64, key: &[u8]) -> Removed {
    match n.as_ref() {
        Node::Leaf { hash: h, entries } => {
            if *h != hash {
                return Removed::Absent;
            }
            let Some(i) = entries.iter().position(|(k, _)| k.as_slice() == key) else {
                return Removed::Absent;
            };
            let mut entries = entries.clone();
            let (_, v) = entries.swap_remove(i);
            if entries.is_empty() {
                Removed::Gone(None, v)
            } else {
                Removed::Gone(Some(Arc::new(Node::Leaf { hash, entries })), v)
            }
        }
        Node::Branch { mask, children } => {
            let nib = nibble(hash, level);
            let Some(child) = n.child(nib) else {
                return Removed::Absent;
            };
            let (new_child, v) = match remove(child, level.wrapping_add(1), hash, key) {
                Removed::Absent => return Removed::Absent,
                Removed::Gone(c, v) => (c, v),
            };
            let at = slot_of(*mask, nib);
            let mut children = children.clone();
            let mut mask = *mask;
            match new_child {
                Some(c) => {
                    if let Some(slot) = children.get_mut(at) {
                        *slot = c;
                    }
                }
                None => {
                    if at < children.len() {
                        children.remove(at);
                    }
                    mask &= !(1 << nib);
                }
            }
            // Canonical shape: a branch left with one leaf below it gives way
            // to that leaf (its hash prefix is now unique one level up); an
            // empty branch disappears.
            match children.as_slice() {
                [] => Removed::Gone(None, v),
                [only] if only.as_leaf().is_some() => Removed::Gone(Some(only.clone()), v),
                _ => Removed::Gone(Some(Arc::new(Node::Branch { mask, children })), v),
            }
        }
    }
}

/// Every key whose value differs between `a` and `b`, with both values.
fn diff<'a>(a: Option<&'a Arc<Node>>, b: Option<&'a Arc<Node>>, f: &mut DiffVisitor<'_, 'a>) {
    match (a, b) {
        (None, None) => {}
        (Some(x), Some(y)) if Arc::ptr_eq(x, y) => {}
        (Some(x), Some(y))
            if matches!(x.as_ref(), Node::Branch { .. })
                && matches!(y.as_ref(), Node::Branch { .. }) =>
        {
            for nib in 0..16u32 {
                diff(x.child(nib), y.child(nib), f);
            }
        }
        _ => {
            // One side is a leaf or empty: the other side holds the same hash
            // prefix, so with the canonical shape its subtree is about as small
            // as the change. Compare the two entry lists directly.
            let mut ea: Vec<(&'a [u8], &'a [u8])> = Vec::new();
            let mut eb: Vec<(&'a [u8], &'a [u8])> = Vec::new();
            if let Some(x) = a {
                x.for_each(&mut |k, v| ea.push((k, v)));
            }
            if let Some(y) = b {
                y.for_each(&mut |k, v| eb.push((k, v)));
            }
            ea.sort_unstable_by(|p, q| p.0.cmp(q.0));
            eb.sort_unstable_by(|p, q| p.0.cmp(q.0));
            let (mut i, mut j) = (0usize, 0usize);
            loop {
                match (ea.get(i), eb.get(j)) {
                    (None, None) => break,
                    (Some(&(k, v)), None) => {
                        f(k, Some(v), None);
                        i = i.wrapping_add(1);
                    }
                    (None, Some(&(k, v))) => {
                        f(k, None, Some(v));
                        j = j.wrapping_add(1);
                    }
                    (Some(&(ka, va)), Some(&(kb, vb))) => match ka.cmp(kb) {
                        std::cmp::Ordering::Less => {
                            f(ka, Some(va), None);
                            i = i.wrapping_add(1);
                        }
                        std::cmp::Ordering::Greater => {
                            f(kb, None, Some(vb));
                            j = j.wrapping_add(1);
                        }
                        std::cmp::Ordering::Equal => {
                            if va != vb {
                                f(ka, Some(va), Some(vb));
                            }
                            i = i.wrapping_add(1);
                            j = j.wrapping_add(1);
                        }
                    },
                }
            }
        }
    }
}

/// A persistent map from slot key to value. `Clone` is O(1) and shares every
/// node; a write copies one root-to-leaf path.
#[derive(Clone, Default)]
pub struct SlotMap {
    root: Option<Arc<Node>>,
    len: usize,
}

impl SlotMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        let hash = hash_key(key);
        let mut node = self.root.as_ref()?;
        let mut level = 0u32;
        loop {
            match node.as_ref() {
                Node::Leaf { hash: h, entries } => {
                    if *h != hash {
                        return None;
                    }
                    return entries
                        .iter()
                        .find(|(k, _)| k.as_slice() == key)
                        .map(|(_, v)| v);
                }
                Node::Branch { .. } => {
                    node = node.child(nibble(hash, level))?;
                    level = level.wrapping_add(1);
                }
            }
        }
    }

    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    /// Set `key` to `value`; the previous value if there was one.
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
        let hash = hash_key(&key);
        let (root, old) = insert(self.root.as_ref(), 0, hash, key, value);
        self.root = Some(root);
        if old.is_none() {
            self.len = self.len.saturating_add(1);
        }
        old
    }

    /// Remove `key`; its value if it was present.
    pub fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let root = self.root.as_ref()?;
        match remove(root, 0, hash_key(key), key) {
            Removed::Absent => None,
            Removed::Gone(new_root, v) => {
                self.root = new_root;
                self.len = self.len.saturating_sub(1);
                Some(v)
            }
        }
    }

    /// Visit every entry (in no particular order).
    pub fn for_each<'a>(&'a self, mut f: impl FnMut(&'a [u8], &'a [u8])) {
        if let Some(r) = &self.root {
            r.for_each(&mut f);
        }
    }

    /// Every entry, in no particular order.
    pub fn entries(&self) -> Vec<(&[u8], &[u8])> {
        let mut out = Vec::with_capacity(self.len);
        self.for_each(|k, v| out.push((k, v)));
        out
    }

    /// Every key whose value differs between `self` (before) and `after`, as
    /// `(key, value in self, value in after)` (`None`: absent). Subtrees the two
    /// versions share are skipped unread, so two versions a few writes apart
    /// cost O(writes x log n), not O(n).
    pub fn diff<'a>(
        &'a self,
        after: &'a SlotMap,
        mut f: impl FnMut(&'a [u8], Option<&'a [u8]>, Option<&'a [u8]>),
    ) {
        diff(self.root.as_ref(), after.root.as_ref(), &mut f);
    }

    /// Whether the two maps share their root node (then they are equal).
    pub fn ptr_eq(&self, other: &SlotMap) -> bool {
        match (&self.root, &other.root) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl std::fmt::Debug for SlotMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotMap").field("len", &self.len).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn depth(n: Option<&Arc<Node>>) -> usize {
        match n.map(|n| n.as_ref()) {
            None | Some(Node::Leaf { .. }) => 0,
            Some(Node::Branch { children, .. }) => {
                1 + children.iter().map(|c| depth(Some(c))).max().unwrap_or(0)
            }
        }
    }

    /// No branch is empty or has a single leaf child (so every branch has two
    /// or more distinct hashes below it), and every mask matches its children.
    fn canonical(n: &Arc<Node>) -> bool {
        match n.as_ref() {
            Node::Leaf { entries, .. } => !entries.is_empty(),
            Node::Branch { mask, children } => {
                mask.count_ones() as usize == children.len()
                    && !children.is_empty()
                    && !(children.len() == 1 && children[0].as_leaf().is_some())
                    && children.iter().all(canonical)
            }
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Insert(u16, u8),
        Remove(u16),
        Fork,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            6 => (0u16..400, any::<u8>()).prop_map(|(k, v)| Op::Insert(k, v)),
            3 => (0u16..400).prop_map(Op::Remove),
            1 => Just(Op::Fork),
        ]
    }

    /// Injective; mixed lengths and long shared prefixes.
    fn key(k: u16) -> Vec<u8> {
        if k.is_multiple_of(3) {
            let mut v = k.to_be_bytes().to_vec();
            v.resize(2 + usize::from(k % 29), 0);
            return v;
        }
        let mut v = vec![0u8; 32];
        v[30..].copy_from_slice(&k.to_be_bytes());
        v
    }

    /// The mean depth of the entries.
    fn mean_depth(n: Option<&Arc<Node>>) -> f64 {
        fn walk(n: &Arc<Node>, d: usize, sum: &mut usize, count: &mut usize) {
            match n.as_ref() {
                Node::Leaf { entries, .. } => {
                    *sum += d * entries.len();
                    *count += entries.len();
                }
                Node::Branch { children, .. } => {
                    for c in children {
                        walk(c, d + 1, sum, count);
                    }
                }
            }
        }
        let (mut sum, mut count) = (0, 0);
        if let Some(n) = n {
            walk(n, 0, &mut sum, &mut count);
        }
        sum as f64 / count.max(1) as f64
    }

    type Model = BTreeMap<Vec<u8>, Vec<u8>>;
    type ModelDiff = BTreeMap<Vec<u8>, (Option<Vec<u8>>, Option<Vec<u8>>)>;

    fn model_diff(a: &Model, b: &Model) -> ModelDiff {
        let mut out = BTreeMap::new();
        for (k, v) in a {
            if b.get(k) != Some(v) {
                out.insert(k.clone(), (Some(v.clone()), b.get(k).cloned()));
            }
        }
        for (k, v) in b {
            if !a.contains_key(k) {
                out.insert(k.clone(), (None, Some(v.clone())));
            }
        }
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The map, every version kept along the way, and `diff` between any two
        /// of them agree with a `BTreeMap` model; the shape stays canonical.
        #[test]
        fn agrees_with_a_model(ops in prop::collection::vec(op(), 1..300)) {
            let mut m = SlotMap::new();
            let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
            let mut versions: Vec<(SlotMap, Model)> = Vec::new();
            for o in &ops {
                match o {
                    Op::Insert(k, v) => {
                        let old = m.insert(key(*k), vec![*v; 1 + usize::from(*v % 3)]);
                        prop_assert_eq!(old, model.insert(key(*k), vec![*v; 1 + usize::from(*v % 3)]));
                    }
                    Op::Remove(k) => {
                        prop_assert_eq!(m.remove(&key(*k)), model.remove(&key(*k)));
                    }
                    Op::Fork => versions.push((m.clone(), model.clone())),
                }
                prop_assert_eq!(m.len(), model.len());
                if let Some(r) = &m.root {
                    prop_assert!(canonical(r));
                }
            }
            for (k, v) in &model {
                prop_assert_eq!(m.get(k), Some(v));
            }
            prop_assert_eq!(m.get(b"absent"), None);
            let got: BTreeMap<Vec<u8>, Vec<u8>> =
                m.entries().into_iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
            prop_assert_eq!(&got, &model);
            versions.push((m.clone(), model.clone()));
            // Old versions are untouched by later writes.
            for (v, vm) in &versions {
                let got: BTreeMap<Vec<u8>, Vec<u8>> =
                    v.entries().into_iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
                prop_assert_eq!(&got, vm);
            }
            for (a, am) in &versions {
                for (b, bm) in &versions {
                    let mut d = BTreeMap::new();
                    a.diff(b, |k, x, y| {
                        d.insert(k.to_vec(), (x.map(<[u8]>::to_vec), y.map(<[u8]>::to_vec)));
                    });
                    prop_assert_eq!(d, model_diff(am, bm));
                }
            }
        }

        /// The shape is a function of the key set: two histories that end with
        /// the same entries have the same depth and the same diff (none).
        #[test]
        fn shape_is_history_independent(keys in prop::collection::btree_set(0u16..2000, 0..200), noise in prop::collection::vec(0u16..2000, 0..100)) {
            let mut a = SlotMap::new();
            for k in &keys {
                a.insert(key(*k), vec![1]);
            }
            let mut b = SlotMap::new();
            for k in &noise {
                b.insert(key(*k), vec![9]);
            }
            for k in keys.iter().rev() {
                b.insert(key(*k), vec![1]);
            }
            for k in &noise {
                if !keys.contains(k) {
                    b.remove(&key(*k));
                }
            }
            prop_assert_eq!(depth(a.root.as_ref()), depth(b.root.as_ref()));
            let mut n = 0;
            a.diff(&b, |_, _, _| n += 1);
            prop_assert_eq!(n, 0);
        }
    }

    /// Depth is logarithmic, and a write to a large map leaves every node off
    /// its path shared with the version before it.
    #[test]
    fn writes_copy_one_path() {
        let mut m = SlotMap::new();
        for i in 0u32..100_000 {
            m.insert(i.to_be_bytes().to_vec(), vec![1]);
        }
        // log16(100k) = 4.2: entries sit about that deep; the deepest pair of
        // 100k random hashes shares about 2 x log16(n) nibbles.
        let mean = mean_depth(m.root.as_ref());
        assert!(
            (3.5..=6.0).contains(&mean),
            "mean depth {mean} for 100k keys"
        );
        let d = depth(m.root.as_ref());
        assert!(d <= 13, "max depth {d} for 100k keys");
        let before = m.clone();
        m.insert(7u32.to_be_bytes().to_vec(), vec![2]);
        let mut changed = Vec::new();
        before.diff(&m, |k, a, b| {
            changed.push((k.to_vec(), a.map(<[u8]>::to_vec), b.map(<[u8]>::to_vec)))
        });
        assert_eq!(
            changed,
            vec![(7u32.to_be_bytes().to_vec(), Some(vec![1]), Some(vec![2]))]
        );
        // The roots' children other than the written one are shared.
        let (Some(r0), Some(r1)) = (&before.root, &m.root) else {
            panic!("non-empty");
        };
        let (Node::Branch { children: c0, .. }, Node::Branch { children: c1, .. }) =
            (r0.as_ref(), r1.as_ref())
        else {
            panic!("branches");
        };
        let shared = c0.iter().zip(c1).filter(|(a, b)| Arc::ptr_eq(a, b)).count();
        assert_eq!(shared, c0.len() - 1);
    }

    #[test]
    fn removing_everything_empties_the_map() {
        let mut m = SlotMap::new();
        for i in 0u32..500 {
            m.insert(i.to_be_bytes().to_vec(), vec![1]);
        }
        for i in 0u32..500 {
            assert_eq!(m.remove(&i.to_be_bytes()), Some(vec![1]));
        }
        assert!(m.is_empty());
        assert!(m.root.is_none());
        assert_eq!(m.remove(b"x"), None);
    }
}
