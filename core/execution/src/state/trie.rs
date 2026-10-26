// citrate/core/execution/src/state/trie.rs

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

// Merkle Patricia Trie implementation
use citrate_consensus::types::Hash;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

/// Merkle Patricia Trie node
#[derive(Debug, Serialize, Deserialize, Default)]
pub enum TrieNode {
    #[default]
    Empty,
    Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Branch {
        children: [Box<TrieNode>; 16],
        value: Option<Vec<u8>>,
    },
    Extension {
        prefix: Vec<u8>,
        node: Box<TrieNode>,
    },
}

// Default now derived above with Empty

/// Test-only operation counters: how many nodes were cloned and how many
/// were encoded, so tests can pin the cost of `insert`/`remove`/`root_hash`
/// rather than time it.
#[cfg(test)]
pub(crate) mod op_counters {
    use std::cell::Cell;
    thread_local! {
        pub static NODE_CLONES: Cell<u64> = const { Cell::new(0) };
        pub static NODE_ENCODES: Cell<u64> = const { Cell::new(0) };
    }
    pub fn reset() {
        NODE_CLONES.with(|c| c.set(0));
        NODE_ENCODES.with(|c| c.set(0));
    }
    pub fn clones() -> u64 {
        NODE_CLONES.with(|c| c.get())
    }
    pub fn encodes() -> u64 {
        NODE_ENCODES.with(|c| c.get())
    }
}

// Written out (not derived) only so tests can count node copies.
impl Clone for TrieNode {
    fn clone(&self) -> Self {
        #[cfg(test)]
        op_counters::NODE_CLONES.with(|c| c.set(c.get() + 1));
        match self {
            TrieNode::Empty => TrieNode::Empty,
            TrieNode::Leaf { key, value } => TrieNode::Leaf {
                key: key.clone(),
                value: value.clone(),
            },
            TrieNode::Branch { children, value } => TrieNode::Branch {
                children: children.clone(),
                value: value.clone(),
            },
            TrieNode::Extension { prefix, node } => TrieNode::Extension {
                prefix: prefix.clone(),
                node: node.clone(),
            },
        }
    }
}

/// Merkle Patricia Trie
#[derive(Clone)]
pub struct Trie {
    root: TrieNode,
    cache: HashMap<Vec<u8>, Vec<u8>>,
    /// `root_hash()` of `root`, remembered until the next `insert`/`remove`.
    /// A pure function of `root`, so remembering it cannot change any result;
    /// it only stops re-encoding storage tries that did not change, which the
    /// per-block state root otherwise does for every contract.
    root_memo: std::sync::OnceLock<Hash>,
}

impl Trie {
    pub fn new() -> Self {
        Self {
            root: TrieNode::Empty,
            cache: HashMap::new(),
            root_memo: std::sync::OnceLock::new(),
        }
    }

    /// Insert a key-value pair
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let nibbles = to_nibbles(&key);
        // Move the root out rather than deep-copying it: `insert_node` consumes
        // the old root and returns the new one, so nothing else observes it.
        let root = std::mem::take(&mut self.root);
        self.root = Self::insert_node(root, &nibbles, value.clone());
        self.cache.insert(key, value);
        self.root_memo = std::sync::OnceLock::new();
    }

    fn insert_node(node: TrieNode, key: &[u8], value: Vec<u8>) -> TrieNode {
        match node {
            TrieNode::Empty => TrieNode::Leaf {
                key: key.to_vec(),
                value,
            },

            TrieNode::Leaf {
                key: leaf_key,
                value: leaf_value,
            } => {
                if leaf_key == key {
                    // Update existing leaf
                    TrieNode::Leaf {
                        key: key.to_vec(),
                        value,
                    }
                } else {
                    // Convert to branch
                    Self::create_branch(leaf_key, leaf_value, key.to_vec(), value)
                }
            }

            TrieNode::Branch {
                mut children,
                value: branch_value,
            } => {
                match split_nibble(key) {
                    // Update branch value
                    None => TrieNode::Branch {
                        children,
                        value: Some(value),
                    },
                    Some((index, rest)) => {
                        let child = take_child(&mut children, index);
                        set_child(&mut children, index, Self::insert_node(child, rest, value));
                        TrieNode::Branch {
                            children,
                            value: branch_value,
                        }
                    }
                }
            }

            TrieNode::Extension { prefix, node } => {
                let common = common_prefix(&prefix, key);

                if common.len() == prefix.len() {
                    // Entire prefix matches
                    TrieNode::Extension {
                        prefix: prefix.clone(),
                        node: Box::new(Self::insert_node(*node, tail(key, common.len()), value)),
                    }
                } else {
                    // Partial match - split extension
                    Self::split_extension(prefix, *node, key.to_vec(), value, common.len())
                }
            }
        }
    }

    /// Enumerate all (key, value) pairs held by this trie.
    ///
    /// Every `insert` also records the pair in `cache` (and `cache` is
    /// serialized with the trie), so this is a complete key→value view — used by
    /// the execute-on-receive reorg to diff a contract's storage between two
    /// state snapshots and reconcile the durable store. Cloning is intentional:
    /// the caller owns the returned map.
    pub fn entries_map(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        self.cache.clone()
    }

    /// Get a value by key
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        // Check cache first
        if let Some(value) = self.cache.get(key) {
            return Some(value.clone());
        }

        let nibbles = to_nibbles(key);
        Self::get_node(&self.root, &nibbles)
    }

    fn get_node(node: &TrieNode, key: &[u8]) -> Option<Vec<u8>> {
        match node {
            TrieNode::Empty => None,

            TrieNode::Leaf {
                key: leaf_key,
                value,
            } => {
                if leaf_key == key {
                    Some(value.clone())
                } else {
                    None
                }
            }

            TrieNode::Branch { children, value } => match split_nibble(key) {
                None => value.clone(),
                Some((index, rest)) => Self::get_node(child(children, index), rest),
            },

            TrieNode::Extension { prefix, node } => key
                .strip_prefix(prefix.as_slice())
                .and_then(|rest| Self::get_node(node, rest)),
        }
    }

    /// Remove a key
    pub fn remove(&mut self, key: &[u8]) {
        let nibbles = to_nibbles(key);
        let root = std::mem::take(&mut self.root);
        self.root = Self::remove_node(root, &nibbles);
        self.cache.remove(key);
        self.root_memo = std::sync::OnceLock::new();
    }

    fn remove_node(node: TrieNode, key: &[u8]) -> TrieNode {
        match node {
            TrieNode::Empty => TrieNode::Empty,

            TrieNode::Leaf {
                key: ref leaf_key, ..
            } => {
                if leaf_key == key {
                    TrieNode::Empty
                } else {
                    node
                }
            }

            TrieNode::Branch {
                mut children,
                value,
            } => {
                match split_nibble(key) {
                    // Remove branch value
                    None => TrieNode::Branch {
                        children,
                        value: None,
                    },
                    Some((index, rest)) => {
                        let child = take_child(&mut children, index);
                        set_child(&mut children, index, Self::remove_node(child, rest));

                        // Check if branch can be simplified
                        Self::simplify_branch(children, value)
                    }
                }
            }

            TrieNode::Extension { prefix, node } => {
                if let Some(rest) = key.strip_prefix(prefix.as_slice()) {
                    let new_node = Self::remove_node(*node, rest);
                    if matches!(new_node, TrieNode::Empty) {
                        TrieNode::Empty
                    } else {
                        TrieNode::Extension {
                            prefix,
                            node: Box::new(new_node),
                        }
                    }
                } else {
                    TrieNode::Extension { prefix, node }
                }
            }
        }
    }

    /// The root, computed from the nodes (bypassing any remembered value).
    #[cfg(test)]
    pub(crate) fn recompute_root_hash(&self) -> Hash {
        let encoded = self.encode_node(&self.root);
        let mut hasher = Keccak256::new();
        hasher.update(&encoded);
        Hash::new(hasher.finalize().into())
    }

    /// Calculate the root hash
    pub fn root_hash(&self) -> Hash {
        *self.root_memo.get_or_init(|| {
            let encoded = self.encode_node(&self.root);
            let mut hasher = Keccak256::new();
            hasher.update(&encoded);
            Hash::new(hasher.finalize().into())
        })
    }

    #[allow(clippy::only_used_in_recursion)]
    fn encode_node(&self, node: &TrieNode) -> Vec<u8> {
        #[cfg(test)]
        op_counters::NODE_ENCODES.with(|c| c.set(c.get() + 1));
        match node {
            TrieNode::Empty => vec![],

            TrieNode::Leaf { key, value } => {
                let items: [&[u8]; 2] = [key.as_slice(), value.as_slice()];
                rlp::encode_list::<&[u8], _>(&items).to_vec()
            }

            TrieNode::Branch { children, value } => {
                let mut items: Vec<Vec<u8>> = Vec::new();
                for child in children.iter() {
                    items.push(self.encode_node(child));
                }
                if let Some(v) = value {
                    items.push(v.clone());
                } else {
                    items.push(vec![]);
                }
                let items_refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
                rlp::encode_list::<&[u8], _>(&items_refs).to_vec()
            }

            TrieNode::Extension { prefix, node } => {
                let node_encoded = self.encode_node(node);
                let items: [&[u8]; 2] = [prefix.as_slice(), node_encoded.as_slice()];
                rlp::encode_list::<&[u8], _>(&items).to_vec()
            }
        }
    }

    // Helper functions

    fn create_branch(key1: Vec<u8>, value1: Vec<u8>, key2: Vec<u8>, value2: Vec<u8>) -> TrieNode {
        let mut children: [Box<TrieNode>; 16] = default_children();

        match (split_nibble(&key1), split_nibble(&key2)) {
            // key1 goes to branch value
            (None, Some((index, rest))) => {
                set_child(
                    &mut children,
                    index,
                    TrieNode::Leaf {
                        key: rest.to_vec(),
                        value: value2,
                    },
                );
                TrieNode::Branch {
                    children,
                    value: Some(value1),
                }
            }
            // key2 goes to branch value
            (Some((index, rest)), None) => {
                set_child(
                    &mut children,
                    index,
                    TrieNode::Leaf {
                        key: rest.to_vec(),
                        value: value1,
                    },
                );
                TrieNode::Branch {
                    children,
                    value: Some(value2),
                }
            }
            // Both go to children
            (Some((index1, rest1)), Some((index2, rest2))) => {
                if index1 == index2 {
                    set_child(
                        &mut children,
                        index1,
                        Self::create_branch(rest1.to_vec(), value1, rest2.to_vec(), value2),
                    );
                } else {
                    set_child(
                        &mut children,
                        index1,
                        TrieNode::Leaf {
                            key: rest1.to_vec(),
                            value: value1,
                        },
                    );
                    set_child(
                        &mut children,
                        index2,
                        TrieNode::Leaf {
                            key: rest2.to_vec(),
                            value: value2,
                        },
                    );
                }
                TrieNode::Branch {
                    children,
                    value: None,
                }
            }
            // INVARIANT: unreachable. Callers only split two DIFFERENT keys, and equal
            // leading nibbles recurse on the tails, so both can't run out together.
            // Equal keys mean "update", which is what this returns.
            (None, None) => TrieNode::Leaf {
                key: key2,
                value: value2,
            },
        }
    }

    fn split_extension(
        prefix: Vec<u8>,
        node: TrieNode,
        key: Vec<u8>,
        value: Vec<u8>,
        common_len: usize,
    ) -> TrieNode {
        // `common_len` is the shared-prefix length of `prefix` and `key`, so it is
        // within both.
        let (common, remaining_prefix) = prefix
            .split_at_checked(common_len)
            .unwrap_or((prefix.as_slice(), &[]));
        let remaining_key = tail(&key, common_len);

        let mut children: [Box<TrieNode>; 16] = default_children();

        if let Some((index, rest)) = split_nibble(remaining_prefix) {
            if rest.is_empty() {
                set_child(&mut children, index, node);
            } else {
                set_child(
                    &mut children,
                    index,
                    TrieNode::Extension {
                        prefix: rest.to_vec(),
                        node: Box::new(node),
                    },
                );
            }
        }

        let branch_value = match split_nibble(remaining_key) {
            None => Some(value),
            Some((index, rest)) => {
                set_child(
                    &mut children,
                    index,
                    TrieNode::Leaf {
                        key: rest.to_vec(),
                        value,
                    },
                );
                None
            }
        };

        let branch = TrieNode::Branch {
            children,
            value: branch_value,
        };

        if common.is_empty() {
            branch
        } else {
            TrieNode::Extension {
                prefix: common.to_vec(),
                node: Box::new(branch),
            }
        }
    }

    fn simplify_branch(children: [Box<TrieNode>; 16], value: Option<Vec<u8>>) -> TrieNode {
        let non_empty: Vec<_> = children
            .iter()
            .enumerate()
            .filter(|(_, child)| !matches!(child.as_ref(), TrieNode::Empty))
            .collect();

        if let ([(index, child)], None) = (non_empty.as_slice(), &value) {
            // Only one child - convert to extension or leaf
            let index = *index;
            match child.as_ref() {
                TrieNode::Leaf { key, value } => {
                    let mut new_key = vec![index as u8];
                    new_key.extend(key);
                    TrieNode::Leaf {
                        key: new_key,
                        value: value.clone(),
                    }
                }
                _ => TrieNode::Extension {
                    prefix: vec![index as u8],
                    node: Box::clone(child),
                },
            }
        } else {
            TrieNode::Branch { children, value }
        }
    }
}

impl Default for Trie {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert bytes to nibbles (4-bit values)
fn to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    nibbles
}

/// Split a nibble path into its first nibble, as a child index, and the rest. The
/// mask is the identity on nibbles (always < 16); it makes the index provably in range.
fn split_nibble(key: &[u8]) -> Option<(usize, &[u8])> {
    key.split_first()
        .map(|(&nibble, rest)| (usize::from(nibble & 0x0f), rest))
}

/// `key[n..]`, or empty if `n` is past the end (callers only pass `n <= key.len()`).
fn tail(key: &[u8], n: usize) -> &[u8] {
    key.get(n..).unwrap_or_default()
}

static EMPTY_NODE: TrieNode = TrieNode::Empty;

fn child(children: &[Box<TrieNode>; 16], index: usize) -> &TrieNode {
    children.get(index).map_or(&EMPTY_NODE, |c| c.as_ref())
}

fn take_child(children: &mut [Box<TrieNode>; 16], index: usize) -> TrieNode {
    children
        .get_mut(index)
        .map(|c| std::mem::take(c.as_mut()))
        .unwrap_or_default()
}

fn set_child(children: &mut [Box<TrieNode>; 16], index: usize, node: TrieNode) {
    if let Some(slot) = children.get_mut(index) {
        **slot = node;
    }
}

/// Find common prefix length
fn common_prefix(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter()
        .zip(b.iter())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| *x)
        .collect()
}

fn default_children() -> [Box<TrieNode>; 16] {
    [
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
        Box::new(TrieNode::Empty),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k32(i: u32) -> Vec<u8> {
        // Spread keys like hashed addresses so the trie branches.
        let mut k = Keccak256::digest(i.to_be_bytes()).to_vec();
        k.truncate(32);
        k
    }

    fn filled(n: u32) -> Trie {
        let mut t = Trie::new();
        for i in 0..n {
            t.insert(k32(i), vec![(i % 251) as u8; 8]);
        }
        t
    }

    /// One insert into a populated trie must touch the path to the key, not
    /// copy the whole trie. Pre-fix `insert` began with `self.root.clone()`,
    /// a deep copy of every node, so building an n-key trie was O(n^2) — and
    /// the account trie is rebuilt from scratch for every block's state root.
    #[test]
    fn insert_does_not_copy_the_existing_trie() {
        let mut t = filled(1000);
        op_counters::reset();
        t.insert(k32(5000), vec![1; 8]);
        let clones = op_counters::clones();
        assert!(
            clones < 64,
            "one insert into a 1000-key trie cloned {clones} nodes"
        );
    }

    #[test]
    fn remove_does_not_copy_the_existing_trie() {
        let mut t = filled(1000);
        op_counters::reset();
        t.remove(&k32(7));
        let clones = op_counters::clones();
        assert!(
            clones < 64,
            "one remove from a 1000-key trie cloned {clones} nodes"
        );
    }

    /// The root of an unchanged trie is not re-derived. Every block's state
    /// root folds every contract's storage root, most of which did not change.
    #[test]
    fn root_hash_of_an_unchanged_trie_is_not_recomputed() {
        let mut t = filled(1000);
        let first = t.root_hash();
        op_counters::reset();
        assert_eq!(t.root_hash(), first);
        assert_eq!(op_counters::encodes(), 0, "unchanged trie was re-encoded");
        // A clone (state snapshot) carries the root with it.
        let c = t.clone();
        op_counters::reset();
        assert_eq!(c.root_hash(), first);
        assert_eq!(op_counters::encodes(), 0, "snapshot copy re-encoded");
        // Any change invalidates it.
        t.insert(k32(9999), vec![2; 8]);
        let second = t.root_hash();
        assert_ne!(second, first);
        assert!(op_counters::encodes() > 0);
        t.remove(&k32(9999));
        assert_eq!(t.root_hash(), t.recompute_root_hash());
    }

    proptest::proptest! {
        /// The remembered root always equals a fresh computation over the
        /// current nodes, after any sequence of inserts and removes.
        #[test]
        fn prop_remembered_root_matches_recomputed(
            ops in proptest::collection::vec((proptest::bool::ANY, 0u32..24, proptest::num::u8::ANY), 1..60),
        ) {
            let mut t = Trie::new();
            for (insert, key, val) in ops {
                if insert {
                    t.insert(k32(key), vec![val; 4]);
                } else {
                    t.remove(&k32(key));
                }
                proptest::prop_assert_eq!(t.root_hash(), t.recompute_root_hash());
            }
        }
    }

    #[test]
    fn test_trie_insert_get() {
        let mut trie = Trie::new();

        trie.insert(b"key1".to_vec(), b"value1".to_vec());
        trie.insert(b"key2".to_vec(), b"value2".to_vec());
        trie.insert(b"key3".to_vec(), b"value3".to_vec());

        assert_eq!(trie.get(b"key1"), Some(b"value1".to_vec()));
        assert_eq!(trie.get(b"key2"), Some(b"value2".to_vec()));
        assert_eq!(trie.get(b"key3"), Some(b"value3".to_vec()));
        assert_eq!(trie.get(b"key4"), None);
    }

    // -----------------------------------------------------------------------
    // Property-based tests (proptest)
    // -----------------------------------------------------------------------
    use proptest::prelude::*;

    proptest! {
        /// Property: Trie insert/get round-trip — insert(key, value) then get(key) returns value.
        #[test]
        fn prop_trie_insert_get_roundtrip(
            key in prop::collection::vec(any::<u8>(), 1..32),
            value in prop::collection::vec(any::<u8>(), 1..64),
        ) {
            let mut trie = Trie::new();
            trie.insert(key.clone(), value.clone());
            let retrieved = trie.get(&key);
            prop_assert_eq!(retrieved, Some(value), "get must return value inserted by insert");
        }

        /// Property: Trie root_hash is deterministic — same content always produces same hash.
        #[test]
        fn prop_trie_root_hash_deterministic(
            key in prop::collection::vec(any::<u8>(), 1..16),
            value in prop::collection::vec(any::<u8>(), 1..32),
        ) {
            let mut trie1 = Trie::new();
            let mut trie2 = Trie::new();
            trie1.insert(key.clone(), value.clone());
            trie2.insert(key, value);
            prop_assert_eq!(trie1.root_hash(), trie2.root_hash(),
                "Same insertions must produce same root hash");
        }
    }

    #[test]
    fn test_trie_remove() {
        let mut trie = Trie::new();

        trie.insert(b"key1".to_vec(), b"value1".to_vec());
        trie.insert(b"key2".to_vec(), b"value2".to_vec());

        trie.remove(b"key1");

        assert_eq!(trie.get(b"key1"), None);
        assert_eq!(trie.get(b"key2"), Some(b"value2".to_vec()));
    }

    #[test]
    fn test_trie_root_hash() {
        let mut trie1 = Trie::new();
        let mut trie2 = Trie::new();

        // Same data should produce same root
        trie1.insert(b"key".to_vec(), b"value".to_vec());
        trie2.insert(b"key".to_vec(), b"value".to_vec());

        assert_eq!(trie1.root_hash(), trie2.root_hash());

        // Different data should produce different root
        trie2.insert(b"key2".to_vec(), b"value2".to_vec());
        assert_ne!(trie1.root_hash(), trie2.root_hash());
    }
}

#[cfg(test)]
mod nondeterminism_probe {
    use super::*;

    /// DECISIVE PROBE (#85-followup non-determinism): the executor inserts
    /// dirty accounts into the state trie in `DashMap` iteration order, which
    /// differs per node/run. If `root_hash()` depends on insertion order, two
    /// nodes with identical state compute different roots — the exact fleet
    /// split (block 235: d9238df1 vs 5fb263db). Insert the SAME key/value set
    /// in two different orders and compare roots.
    #[test]
    fn root_hash_is_insertion_order_independent() {
        // 32-byte keys (like account addresses), varied to exercise branching.
        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for i in 0u16..64 {
            let mut k = vec![0u8; 32];
            k[0] = (i & 0xff) as u8;
            k[1] = ((i * 7 + 3) & 0xff) as u8;
            k[31] = (i * 3) as u8;
            pairs.push((k, vec![(i % 251) as u8; 8]));
        }
        let mut t1 = Trie::new();
        for (k, v) in pairs.iter() {
            t1.insert(k.clone(), v.clone());
        }
        // reversed order
        let mut t2 = Trie::new();
        for (k, v) in pairs.iter().rev() {
            t2.insert(k.clone(), v.clone());
        }
        // a rotated/shuffled order
        let mut t3 = Trie::new();
        let n = pairs.len();
        for idx in 0..n {
            let (k, v) = &pairs[(idx * 37 + 11) % n];
            t3.insert(k.clone(), v.clone());
        }
        assert_eq!(
            t1.root_hash(),
            t2.root_hash(),
            "reversed insertion order changed the root"
        );
        assert_eq!(
            t1.root_hash(),
            t3.root_hash(),
            "shuffled insertion order changed the root"
        );
    }
}

#[cfg(test)]
mod trie_shuffle_probe {
    use super::*;
    #[test]
    fn address_keys_all_orders() {
        let mk = |i: u8| {
            let mut k = vec![0u8; 20];
            k[0] = i;
            k[19] = i.wrapping_mul(3).wrapping_add(1);
            k
        };
        let val = |i: u8| vec![i.wrapping_mul(7); 32];
        let orders: Vec<Vec<u8>> = vec![
            (0u8..48).collect(),
            (0u8..48).rev().collect(),
            (0u8..48)
                .map(|i| ((i as usize * 37 + 5) % 48) as u8)
                .collect(),
            (0u8..48)
                .map(|i| ((i as usize * 13 + 7) % 48) as u8)
                .collect(),
        ];
        let mut roots = Vec::new();
        for ord in &orders {
            let mut t = Trie::new();
            for &i in ord {
                t.insert(mk(i), val(i));
            }
            roots.push(t.root_hash());
        }
        for (idx, r) in roots.iter().enumerate() {
            eprintln!("order {idx}: root {}", hex::encode(&r.as_bytes()[..8]));
        }
        for idx in 1..roots.len() {
            assert_eq!(
                roots[0], roots[idx],
                "trie root differs for order {idx} vs 0"
            );
        }
    }

    /// PANIC-S1 golden vector: a deterministic mix of inserts and removes over
    /// variable-length keys that prefix one another (exercising branch values,
    /// extension splits and branch simplification). The digest folds the root after
    /// every op; it was recorded on the pre-PANIC-S1 trie, so any change to the
    /// state-root function fails this test.
    fn golden_digest() -> String {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut trie = Trie::new();
        let mut live: Vec<Vec<u8>> = Vec::new();
        let mut fold = Keccak256::new();
        for _ in 0..2_000 {
            let r = next();
            if r % 4 == 0 && !live.is_empty() {
                let k = live.swap_remove((r >> 8) as usize % live.len());
                trie.remove(&k);
            } else {
                let len = 1 + (r >> 4) as usize % 5;
                let key: Vec<u8> = (0..len)
                    .map(|i| ((r >> (16 + 8 * i)) & 0x13) as u8)
                    .collect();
                let value = (r >> 32).to_be_bytes().to_vec();
                trie.insert(key.clone(), value.clone());
                assert_eq!(trie.get(&key), Some(value));
                live.push(key);
            }
            fold.update(trie.root_hash().as_bytes());
        }
        hex::encode(fold.finalize())
    }

    #[test]
    fn panic_s1_trie_root_golden_vector() {
        assert_eq!(
            golden_digest(),
            "93c7dc7f168d8201e6a06ab9ac81c1a3136861ce1731306b58e046adbf6d6dc2"
        );
    }
}
