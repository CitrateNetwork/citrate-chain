// citrate/core/execution/src/state/mpt.rs
//
// The standard Ethereum Merkle Patricia Trie (Yellow Paper appendix D), used for
// the state root from the `mpt_state_root` activation (ADR-2026-11-03 CV-14 (a)
// and (b), an r1007 genesis rule; spec 06 section "state root").
//
// ENCODING (consensus; the exact rules are restated in the spec text):
//
//   * A key is a byte string; its path is its nibbles, high nibble first.
//   * Leaf      = RLP[ HP(rest of path, leaf = true),  value ]
//     Extension = RLP[ HP(shared path, leaf = false), ref(child) ]
//     Branch    = RLP[ ref(c0), ..., ref(c15), value or "" ]
//     HP is the hex-prefix encoding: first nibble = 2*leaf + odd, an odd path
//     puts its first nibble in the same byte, an even one pads with a 0 nibble.
//   * ref(node) is keccak256(RLP(node)) as a 32-byte string when the RLP is 32
//     bytes or longer, and the RLP itself, embedded, when it is shorter. An
//     absent branch child is the empty string.
//   * The root hash is keccak256(RLP(root)) whatever its length; the empty
//     trie's root is keccak256(RLP("")) = 0x56e81f…b421.
//   * Every key/value set has exactly one trie shape: no branch with fewer than
//     two entries (children plus value), no extension with an empty path, no
//     extension whose child is a leaf or an extension.
//
// INCREMENTAL, AND STILL PURE (CV-14 (b)):
//
//   * Nodes are immutable and shared (`Arc`): an update copies only the nodes on
//     the changed path, and the rest of the trie, snapshots included, keeps
//     pointing at the old ones.
//   * Each node caches its reference (`ref(node)` above) the first time it is
//     needed. A node never changes after it is built, so its cache is a pure
//     function of its contents and cannot go stale. Re-hashing a block's changes
//     costs O(changed keys x depth), not O(state).
//   * `root_from_sorted` is an independent from-scratch builder (no cache, no
//     insert/remove): the reference the incremental root is tested and replayed
//     against.
//
// PERSISTENCE: `collect_unpersisted` hands out the hash-referenced nodes not yet
// written, and `load` rebuilds a trie from a node source, checking every node's
// hash, its canonical encoding and the canonical shape. A missing or corrupt
// node is an error the caller answers with a full rebuild from state, so the
// node store can make a root cheaper but never different.

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

use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// keccak256(RLP("")): the root of the empty trie.
pub const EMPTY_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// keccak256 of the empty byte string: the code hash of an account with no code.
pub const KECCAK_EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// keccak256 of `data`.
pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The nibbles of `key`, high nibble first.
pub fn nibbles(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len().saturating_mul(2));
    for b in key {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

/// Bytes from an even number of nibbles (`None` if odd or a nibble is >= 16).
pub fn from_nibbles(path: &[u8]) -> Option<Vec<u8>> {
    if path.len() & 1 != 0 || path.iter().any(|n| *n > 0x0f) {
        return None;
    }
    Some(
        path.chunks(2)
            .map(|c| match c {
                [hi, lo] => (hi << 4) | lo,
                _ => 0,
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// RLP (encoding only; decoding goes through the `rlp` crate)
// ---------------------------------------------------------------------------

fn rlp_header(out: &mut Vec<u8>, offset: u8, len: usize) {
    if len < 56 {
        // len < 56, so the sum stays below 0xc0 + 56.
        out.push(offset.saturating_add(len as u8));
    } else {
        let be = len.to_be_bytes();
        let skip = be.iter().take_while(|b| **b == 0).count();
        let digits = be.get(skip..).unwrap_or_default();
        out.push(offset.saturating_add(55).saturating_add(digits.len() as u8));
        out.extend_from_slice(digits);
    }
}

/// Append the RLP string encoding of `s`.
pub fn rlp_append_bytes(out: &mut Vec<u8>, s: &[u8]) {
    match s {
        [b] if *b < 0x80 => out.push(*b),
        _ => {
            rlp_header(out, 0x80, s.len());
            out.extend_from_slice(s);
        }
    }
}

/// The RLP list whose concatenated item encodings are `payload`.
pub fn rlp_list(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len().saturating_add(9));
    rlp_header(&mut out, 0xc0, payload.len());
    out.extend_from_slice(payload);
    out
}

/// A big-endian integer with its leading zero bytes removed (zero is empty).
pub fn trim_be(bytes: &[u8]) -> &[u8] {
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    bytes.get(skip..).unwrap_or_default()
}

/// Hex-prefix encoding of a nibble path.
pub fn hex_prefix(path: &[u8], leaf: bool) -> Vec<u8> {
    let flag: u8 = if leaf { 2 } else { 0 };
    let mut out = Vec::with_capacity((path.len() >> 1).saturating_add(1));
    let rest = match path.split_first() {
        Some((first, rest)) if path.len() & 1 == 1 => {
            out.push(((flag | 1) << 4) | (first & 0x0f));
            rest
        }
        _ => {
            out.push(flag << 4);
            path
        }
    };
    for pair in rest.chunks(2) {
        if let [hi, lo] = pair {
            out.push(((hi & 0x0f) << 4) | (lo & 0x0f));
        }
    }
    out
}

/// Decode a hex-prefix path: (nibbles, is_leaf). `None` for an invalid flag.
pub fn decode_hex_prefix(bytes: &[u8]) -> Option<(Vec<u8>, bool)> {
    let (first, rest) = bytes.split_first()?;
    let flag = first >> 4;
    if flag > 3 {
        return None;
    }
    let leaf = flag & 2 != 0;
    let odd = flag & 1 != 0;
    let mut path = Vec::with_capacity(rest.len().saturating_mul(2).saturating_add(1));
    if odd {
        path.push(first & 0x0f);
    } else if first & 0x0f != 0 {
        return None;
    }
    path.extend(nibbles(rest));
    Some((path, leaf))
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/// How a parent refers to a child: by hash (RLP >= 32 bytes) or embedded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeRef {
    Hash([u8; 32]),
    Inline(Box<[u8]>),
}

impl NodeRef {
    fn of_encoding(enc: Vec<u8>) -> Self {
        if enc.len() >= 32 {
            NodeRef::Hash(keccak(&enc))
        } else {
            NodeRef::Inline(enc.into_boxed_slice())
        }
    }

    /// Append this reference as a list item of its parent.
    fn append_to(&self, out: &mut Vec<u8>) {
        match self {
            NodeRef::Hash(h) => rlp_append_bytes(out, h),
            NodeRef::Inline(enc) => out.extend_from_slice(enc),
        }
    }

    /// The hash of the node this refers to (a root is always hashed).
    fn node_hash(&self) -> [u8; 32] {
        match self {
            NodeRef::Hash(h) => *h,
            NodeRef::Inline(enc) => keccak(enc),
        }
    }
}

type Children = [Option<Arc<Node>>; 16];

#[derive(Debug)]
enum Kind {
    Leaf {
        path: Box<[u8]>,
        value: Box<[u8]>,
    },
    Extension {
        path: Box<[u8]>,
        child: Arc<Node>,
    },
    Branch {
        children: Box<Children>,
        value: Option<Box<[u8]>>,
    },
}

/// One trie node. Immutable once built; `reference` is a cache of a pure
/// function of `kind`, and `persisted` records that the node store has it.
#[derive(Debug)]
pub struct Node {
    kind: Kind,
    reference: OnceLock<NodeRef>,
    persisted: AtomicBool,
}

impl Node {
    fn new(kind: Kind) -> Arc<Node> {
        Arc::new(Node {
            kind,
            reference: OnceLock::new(),
            persisted: AtomicBool::new(false),
        })
    }

    fn leaf(path: &[u8], value: &[u8]) -> Arc<Node> {
        Self::new(Kind::Leaf {
            path: path.into(),
            value: value.into(),
        })
    }

    fn extension(path: &[u8], child: Arc<Node>) -> Arc<Node> {
        Self::new(Kind::Extension {
            path: path.into(),
            child,
        })
    }

    fn branch(children: Children, value: Option<Box<[u8]>>) -> Arc<Node> {
        Self::new(Kind::Branch {
            children: Box::new(children),
            value,
        })
    }

    /// RLP of this node (uses the children's cached references).
    fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(64);
        match &self.kind {
            Kind::Leaf { path, value } => {
                rlp_append_bytes(&mut payload, &hex_prefix(path, true));
                rlp_append_bytes(&mut payload, value);
            }
            Kind::Extension { path, child } => {
                rlp_append_bytes(&mut payload, &hex_prefix(path, false));
                child.reference().append_to(&mut payload);
            }
            Kind::Branch { children, value } => {
                for c in children.iter() {
                    match c {
                        Some(c) => c.reference().append_to(&mut payload),
                        None => payload.push(0x80),
                    }
                }
                match value {
                    Some(v) => rlp_append_bytes(&mut payload, v),
                    None => payload.push(0x80),
                }
            }
        }
        rlp_list(&payload)
    }

    fn reference(&self) -> &NodeRef {
        self.reference
            .get_or_init(|| NodeRef::of_encoding(self.encode()))
    }
}

fn empty_children() -> Children {
    Default::default()
}

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len().saturating_add(b.len()));
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

fn common_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn set_child(children: &mut Children, nibble: u8, node: Option<Arc<Node>>) {
    if let Some(slot) = children.get_mut(usize::from(nibble & 0x0f)) {
        *slot = node;
    }
}

fn get_child(children: &Children, nibble: u8) -> Option<&Arc<Node>> {
    children
        .get(usize::from(nibble & 0x0f))
        .and_then(|c| c.as_ref())
}

/// What goes into a new branch when two paths part ways.
enum Item<'a> {
    /// A value whose remaining path is `rest`.
    Value(&'a [u8], &'a [u8]),
    /// An existing subtree hanging below the extension path `rest` (never empty).
    Subtree(&'a [u8], Arc<Node>),
}

fn place(children: &mut Children, branch_value: &mut Option<Box<[u8]>>, item: Item<'_>) {
    match item {
        Item::Value(rest, value) => match rest.split_first() {
            None => *branch_value = Some(value.into()),
            Some((n, tail)) => set_child(children, *n, Some(Node::leaf(tail, value))),
        },
        Item::Subtree(rest, node) => match rest.split_first() {
            None => {}
            Some((n, [])) => set_child(children, *n, Some(node)),
            Some((n, tail)) => set_child(children, *n, Some(Node::extension(tail, node))),
        },
    }
}

/// A branch holding `a` and `b` (which part at their first nibble), under an
/// extension of `shared` when it is not empty.
fn split(shared: &[u8], a: Item<'_>, b: Item<'_>) -> Arc<Node> {
    let mut children = empty_children();
    let mut value = None;
    place(&mut children, &mut value, a);
    place(&mut children, &mut value, b);
    let branch = Node::branch(children, value);
    if shared.is_empty() {
        branch
    } else {
        Node::extension(shared, branch)
    }
}

fn insert_at(node: Option<&Arc<Node>>, path: &[u8], value: &[u8]) -> Arc<Node> {
    let Some(n) = node else {
        return Node::leaf(path, value);
    };
    match &n.kind {
        Kind::Leaf {
            path: lp,
            value: lv,
        } => {
            if lp.as_ref() == path {
                if lv.as_ref() == value {
                    return n.clone();
                }
                return Node::leaf(path, value);
            }
            let c = common_len(lp, path);
            let (shared, lrest) = lp.split_at(c.min(lp.len()));
            let prest = path.get(c..).unwrap_or_default();
            split(shared, Item::Value(lrest, lv), Item::Value(prest, value))
        }
        Kind::Extension { path: ep, child } => {
            let c = common_len(ep, path);
            if c == ep.len() {
                let rest = path.get(c..).unwrap_or_default();
                let new_child = insert_at(Some(child), rest, value);
                if Arc::ptr_eq(&new_child, child) {
                    return n.clone();
                }
                return Node::extension(ep, new_child);
            }
            let (shared, erest) = ep.split_at(c);
            let prest = path.get(c..).unwrap_or_default();
            split(
                shared,
                Item::Subtree(erest, child.clone()),
                Item::Value(prest, value),
            )
        }
        Kind::Branch {
            children,
            value: bv,
        } => match path.split_first() {
            None => {
                if bv.as_deref() == Some(value) {
                    return n.clone();
                }
                Node::branch((**children).clone(), Some(value.into()))
            }
            Some((idx, rest)) => {
                let old = get_child(children, *idx);
                let new_child = insert_at(old, rest, value);
                if old.is_some_and(|o| Arc::ptr_eq(o, &new_child)) {
                    return n.clone();
                }
                let mut ch = (**children).clone();
                set_child(&mut ch, *idx, Some(new_child));
                Node::branch(ch, bv.clone())
            }
        },
    }
}

enum Removal {
    Unchanged,
    Gone,
    Replaced(Arc<Node>),
}

/// `node` moved under the nibble path `prefix`, in canonical form.
fn join(prefix: &[u8], node: &Arc<Node>) -> Arc<Node> {
    match &node.kind {
        Kind::Leaf { path, value } => Node::leaf(&concat(prefix, path), value),
        Kind::Extension { path, child } => Node::extension(&concat(prefix, path), child.clone()),
        Kind::Branch { .. } => {
            if prefix.is_empty() {
                node.clone()
            } else {
                Node::extension(prefix, node.clone())
            }
        }
    }
}

/// A branch with these entries, collapsed when fewer than two remain.
fn normalize(children: Children, value: Option<Box<[u8]>>) -> Removal {
    let mut live = children
        .iter()
        .enumerate()
        .filter_map(|(i, c)| c.as_ref().map(|c| (i, c)));
    let first = live.next();
    let second = live.next();
    match (first, second, &value) {
        (None, _, None) => Removal::Gone,
        (None, _, Some(v)) => Removal::Replaced(Node::leaf(&[], v)),
        (Some((i, c)), None, None) => Removal::Replaced(join(&[(i & 0x0f) as u8], c)),
        _ => Removal::Replaced(Node::branch(children, value)),
    }
}

fn remove_at(n: &Arc<Node>, path: &[u8]) -> Removal {
    match &n.kind {
        Kind::Leaf { path: lp, .. } => {
            if lp.as_ref() == path {
                Removal::Gone
            } else {
                Removal::Unchanged
            }
        }
        Kind::Extension { path: ep, child } => {
            let Some(rest) = path.strip_prefix(ep.as_ref()) else {
                return Removal::Unchanged;
            };
            match remove_at(child, rest) {
                Removal::Unchanged => Removal::Unchanged,
                Removal::Gone => Removal::Gone,
                Removal::Replaced(c) => Removal::Replaced(join(ep, &c)),
            }
        }
        Kind::Branch { children, value } => match path.split_first() {
            None => {
                if value.is_none() {
                    Removal::Unchanged
                } else {
                    normalize((**children).clone(), None)
                }
            }
            Some((idx, rest)) => {
                let Some(c) = get_child(children, *idx) else {
                    return Removal::Unchanged;
                };
                match remove_at(c, rest) {
                    Removal::Unchanged => Removal::Unchanged,
                    Removal::Gone => {
                        let mut ch = (**children).clone();
                        set_child(&mut ch, *idx, None);
                        normalize(ch, value.clone())
                    }
                    Removal::Replaced(nc) => {
                        let mut ch = (**children).clone();
                        set_child(&mut ch, *idx, Some(nc));
                        Removal::Replaced(Node::branch(ch, value.clone()))
                    }
                }
            }
        },
    }
}

// ---------------------------------------------------------------------------
// The trie
// ---------------------------------------------------------------------------

/// A Merkle Patricia Trie over raw byte keys. Cloning is O(1) (shared nodes).
/// The secure (keccak-keyed) state tries hash their keys before calling in.
#[derive(Clone, Debug, Default)]
pub struct Mpt {
    root: Option<Arc<Node>>,
}

/// Why a trie could not be loaded from a node source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The source does not hold this node.
    Missing([u8; 32]),
    /// The bytes under this hash do not hash to it.
    HashMismatch([u8; 32]),
    /// The bytes are not a valid trie node.
    Malformed(String),
    /// A valid node, but not in the one canonical shape.
    NonCanonical(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Missing(h) => write!(f, "trie node 0x{} missing", hex::encode(h)),
            LoadError::HashMismatch(h) => {
                write!(f, "trie node 0x{} does not hash to its key", hex::encode(h))
            }
            LoadError::Malformed(e) => write!(f, "malformed trie node: {e}"),
            LoadError::NonCanonical(e) => write!(f, "non-canonical trie node: {e}"),
        }
    }
}

/// Why a proof did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// The proof lacks the node with this hash.
    MissingNode([u8; 32]),
    Malformed(String),
}

impl Mpt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Insert `value` under `key`. An empty value removes the key (Ethereum
    /// trie semantics: the empty string is absence).
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        if value.is_empty() {
            self.remove(key);
            return;
        }
        let path = nibbles(key);
        self.root = Some(insert_at(self.root.as_ref(), &path, value));
    }

    pub fn remove(&mut self, key: &[u8]) {
        let Some(root) = &self.root else {
            return;
        };
        let path = nibbles(key);
        match remove_at(root, &path) {
            Removal::Unchanged => {}
            Removal::Gone => self.root = None,
            Removal::Replaced(n) => self.root = Some(n),
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let path = nibbles(key);
        let mut node = self.root.as_ref()?;
        let mut rest: &[u8] = &path;
        loop {
            match &node.kind {
                Kind::Leaf { path, value } => {
                    return (path.as_ref() == rest).then_some(value.as_ref());
                }
                Kind::Extension { path, child } => {
                    rest = rest.strip_prefix(path.as_ref())?;
                    node = child;
                }
                Kind::Branch { children, value } => match rest.split_first() {
                    None => return value.as_deref(),
                    Some((idx, tail)) => {
                        node = get_child(children, *idx)?;
                        rest = tail;
                    }
                },
            }
        }
    }

    /// The root hash (keccak256 of the root node's RLP; `EMPTY_ROOT` if empty).
    pub fn root_hash(&self) -> [u8; 32] {
        match &self.root {
            None => EMPTY_ROOT,
            Some(n) => n.reference().node_hash(),
        }
    }

    /// The proof for `key`: the RLP of every node on its path that is not
    /// embedded in its parent, root first (the `eth_getProof` format). It
    /// proves presence (with the value) or absence alike.
    pub fn proof(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let Some(mut node) = self.root.as_ref() else {
            return out;
        };
        let path = nibbles(key);
        let mut rest: &[u8] = &path;
        let mut first = true;
        loop {
            if first || matches!(node.reference(), NodeRef::Hash(_)) {
                out.push(node.encode());
            }
            first = false;
            match &node.kind {
                Kind::Leaf { .. } => return out,
                Kind::Extension { path, child } => match rest.strip_prefix(path.as_ref()) {
                    Some(r) => {
                        rest = r;
                        node = child;
                    }
                    None => return out,
                },
                Kind::Branch { children, .. } => match rest.split_first() {
                    None => return out,
                    Some((idx, tail)) => match get_child(children, *idx) {
                        Some(c) => {
                            node = c;
                            rest = tail;
                        }
                        None => return out,
                    },
                },
            }
        }
    }

    /// Every (key, value) pair, in key order.
    pub fn entries(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        if let Some(root) = &self.root {
            let mut prefix = Vec::new();
            walk_leaves(root, &mut prefix, &mut |path, value| {
                if let Some(k) = from_nibbles(path) {
                    out.push((k, value.to_vec()));
                }
            });
        }
        out
    }

    /// Number of stored pairs.
    pub fn len(&self) -> usize {
        let mut n: usize = 0;
        if let Some(root) = &self.root {
            let mut prefix = Vec::new();
            walk_leaves(root, &mut prefix, &mut |_, _| n = n.saturating_add(1));
        }
        n
    }

    /// The hash-referenced nodes (and the root, always) the node store does not
    /// have yet, as (hash, RLP). Pass them to the store, then call
    /// [`Self::mark_persisted`] with the same trie.
    pub fn collect_unpersisted(&self, out: &mut Vec<([u8; 32], Vec<u8>)>) {
        if let Some(root) = &self.root {
            collect(root, true, out);
        }
    }

    /// Record that every node of this trie is in the node store.
    pub fn mark_persisted(&self) {
        if let Some(root) = &self.root {
            mark(root);
        }
    }

    /// Rebuild the trie with root `root` from `source` (RLP by node hash). Every
    /// node is checked: it must hash to its key, re-encode to the same bytes and
    /// have the canonical shape. The loaded nodes count as persisted.
    pub fn load(
        root: &[u8; 32],
        source: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>,
    ) -> Result<Mpt, LoadError> {
        if *root == EMPTY_ROOT {
            return Ok(Mpt::new());
        }
        let bytes = source(root).ok_or(LoadError::Missing(*root))?;
        if keccak(&bytes) != *root {
            return Err(LoadError::HashMismatch(*root));
        }
        let node = decode_node(&bytes, source, true)?;
        Ok(Mpt { root: Some(node) })
    }
}

fn walk_leaves(node: &Arc<Node>, prefix: &mut Vec<u8>, f: &mut dyn FnMut(&[u8], &[u8])) {
    match &node.kind {
        Kind::Leaf { path, value } => {
            let len = prefix.len();
            prefix.extend_from_slice(path);
            f(prefix, value);
            prefix.truncate(len);
        }
        Kind::Extension { path, child } => {
            let len = prefix.len();
            prefix.extend_from_slice(path);
            walk_leaves(child, prefix, f);
            prefix.truncate(len);
        }
        Kind::Branch { children, value } => {
            if let Some(v) = value {
                f(prefix, v);
            }
            for (i, c) in children.iter().enumerate() {
                if let Some(c) = c {
                    prefix.push((i & 0x0f) as u8);
                    walk_leaves(c, prefix, f);
                    prefix.pop();
                }
            }
        }
    }
}

fn collect(node: &Arc<Node>, is_root: bool, out: &mut Vec<([u8; 32], Vec<u8>)>) {
    if node.persisted.load(Ordering::Acquire) {
        return;
    }
    match &node.kind {
        Kind::Leaf { .. } => {}
        Kind::Extension { child, .. } => collect(child, false, out),
        Kind::Branch { children, .. } => {
            for c in children.iter().flatten() {
                collect(c, false, out);
            }
        }
    }
    match node.reference() {
        NodeRef::Hash(h) => out.push((*h, node.encode())),
        NodeRef::Inline(enc) if is_root => out.push((keccak(enc), enc.to_vec())),
        NodeRef::Inline(_) => {}
    }
}

fn mark(node: &Arc<Node>) {
    if node.persisted.swap(true, Ordering::AcqRel) {
        return;
    }
    match &node.kind {
        Kind::Leaf { .. } => {}
        Kind::Extension { child, .. } => mark(child),
        Kind::Branch { children, .. } => {
            for c in children.iter().flatten() {
                mark(c);
            }
        }
    }
}

/// A child reference in a parsed node.
enum ParsedRef {
    Empty,
    Hash([u8; 32]),
    Inline(Vec<u8>),
}

fn parse_ref(item: &rlp::Rlp<'_>) -> Result<ParsedRef, String> {
    if item.is_list() {
        return Ok(ParsedRef::Inline(item.as_raw().to_vec()));
    }
    let data = item.data().map_err(|e| e.to_string())?;
    match data.len() {
        0 => Ok(ParsedRef::Empty),
        32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(data);
            Ok(ParsedRef::Hash(h))
        }
        n => Err(format!("a child reference of {n} bytes")),
    }
}

/// A parsed node: its kind with unresolved children.
enum Parsed {
    Leaf(Vec<u8>, Vec<u8>),
    Extension(Vec<u8>, ParsedRef),
    Branch(Vec<ParsedRef>, Option<Vec<u8>>),
}

fn parse_node(bytes: &[u8]) -> Result<Parsed, String> {
    let r = rlp::Rlp::new(bytes);
    if !r.is_list() {
        return Err("not a list".into());
    }
    if r.as_raw().len() != bytes.len() {
        return Err("trailing bytes".into());
    }
    match r.item_count().map_err(|e| e.to_string())? {
        2 => {
            let hp = r.at(0).map_err(|e| e.to_string())?;
            let hp = hp.data().map_err(|e| e.to_string())?;
            let (path, leaf) = decode_hex_prefix(hp).ok_or("bad hex-prefix")?;
            let second = r.at(1).map_err(|e| e.to_string())?;
            if leaf {
                let v = second.data().map_err(|e| e.to_string())?;
                Ok(Parsed::Leaf(path, v.to_vec()))
            } else {
                Ok(Parsed::Extension(path, parse_ref(&second)?))
            }
        }
        17 => {
            let mut children = Vec::with_capacity(16);
            for i in 0..16 {
                children.push(parse_ref(&r.at(i).map_err(|e| e.to_string())?)?);
            }
            let v = r.at(16).map_err(|e| e.to_string())?;
            let v = v.data().map_err(|e| e.to_string())?;
            Ok(Parsed::Branch(
                children,
                (!v.is_empty()).then(|| v.to_vec()),
            ))
        }
        n => Err(format!("a list of {n} items")),
    }
}

fn resolve(
    r: ParsedRef,
    source: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>,
) -> Result<Option<Arc<Node>>, LoadError> {
    match r {
        ParsedRef::Empty => Ok(None),
        ParsedRef::Hash(h) => {
            let bytes = source(&h).ok_or(LoadError::Missing(h))?;
            if keccak(&bytes) != h {
                return Err(LoadError::HashMismatch(h));
            }
            if bytes.len() < 32 {
                return Err(LoadError::NonCanonical(
                    "a node shorter than 32 bytes referenced by hash".into(),
                ));
            }
            decode_node(&bytes, source, false).map(Some)
        }
        ParsedRef::Inline(bytes) => {
            if bytes.len() >= 32 {
                return Err(LoadError::NonCanonical(
                    "a node of 32 bytes or more embedded".into(),
                ));
            }
            decode_node(&bytes, source, false).map(Some)
        }
    }
}

fn decode_node(
    bytes: &[u8],
    source: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>,
    is_root: bool,
) -> Result<Arc<Node>, LoadError> {
    let kind = match parse_node(bytes).map_err(LoadError::Malformed)? {
        Parsed::Leaf(path, value) => {
            if value.is_empty() {
                return Err(LoadError::NonCanonical("a leaf with an empty value".into()));
            }
            Kind::Leaf {
                path: path.into(),
                value: value.into(),
            }
        }
        Parsed::Extension(path, child) => {
            if path.is_empty() {
                return Err(LoadError::NonCanonical("an empty extension path".into()));
            }
            let child = resolve(child, source)?
                .ok_or_else(|| LoadError::NonCanonical("an extension with no child".into()))?;
            if !matches!(child.kind, Kind::Branch { .. }) {
                return Err(LoadError::NonCanonical(
                    "an extension whose child is not a branch".into(),
                ));
            }
            Kind::Extension {
                path: path.into(),
                child,
            }
        }
        Parsed::Branch(refs, value) => {
            let mut children = empty_children();
            let mut live: usize = usize::from(value.is_some());
            for (slot, r) in children.iter_mut().zip(refs) {
                *slot = resolve(r, source)?;
                live = live.saturating_add(usize::from(slot.is_some()));
            }
            if live < 2 {
                return Err(LoadError::NonCanonical(
                    "a branch with fewer than two entries".into(),
                ));
            }
            Kind::Branch {
                children: Box::new(children),
                value: value.map(Into::into),
            }
        }
    };
    let node = Node {
        kind,
        reference: OnceLock::new(),
        persisted: AtomicBool::new(true),
    };
    let enc = node.encode();
    if enc != bytes {
        return Err(LoadError::NonCanonical(
            "the node does not re-encode to its bytes".into(),
        ));
    }
    let r = if is_root && bytes.len() < 32 {
        NodeRef::Inline(bytes.into())
    } else {
        NodeRef::of_encoding(enc)
    };
    let _ = node.reference.set(r);
    Ok(Arc::new(node))
}

/// Every leaf value in `rlp` and in the nodes embedded in it, and every
/// hash-referenced child.
/// A node's hash-referenced children and leaf values (see [`node_refs_and_leaf_values`]).
pub type NodeScan = (Vec<[u8; 32]>, Vec<Vec<u8>>);

/// A trie node as stored: (keccak256 of its RLP, its RLP).
pub type TrieNodeRecord = ([u8; 32], Vec<u8>);

pub fn node_refs_and_leaf_values(rlp: &[u8]) -> Result<NodeScan, String> {
    let mut hashes = Vec::new();
    let mut leaf_values = Vec::new();
    scan_node(rlp, &mut hashes, &mut leaf_values)?;
    Ok((hashes, leaf_values))
}

fn scan_node(
    rlp: &[u8],
    hashes: &mut Vec<[u8; 32]>,
    values: &mut Vec<Vec<u8>>,
) -> Result<(), String> {
    let on_ref = |r: ParsedRef, hashes: &mut Vec<[u8; 32]>, values: &mut Vec<Vec<u8>>| match r {
        ParsedRef::Empty => Ok(()),
        ParsedRef::Hash(h) => {
            hashes.push(h);
            Ok(())
        }
        ParsedRef::Inline(b) => scan_node(&b, hashes, values),
    };
    match parse_node(rlp)? {
        Parsed::Leaf(_, v) => values.push(v),
        Parsed::Extension(_, c) => on_ref(c, hashes, values)?,
        Parsed::Branch(refs, v) => {
            for r in refs {
                on_ref(r, hashes, values)?;
            }
            if let Some(v) = v {
                values.push(v);
            }
        }
    }
    Ok(())
}

/// Verify `proof` for `key` against `root`: `Ok(Some(value))` if the key is
/// present, `Ok(None)` if the proof shows it absent.
pub fn verify_proof(
    root: &[u8; 32],
    key: &[u8],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, ProofError> {
    let by_hash: std::collections::HashMap<[u8; 32], &Vec<u8>> =
        proof.iter().map(|p| (keccak(p), p)).collect();
    if *root == EMPTY_ROOT && proof.is_empty() {
        return Ok(None);
    }
    let path = nibbles(key);
    let mut rest: &[u8] = &path;
    let mut current: Vec<u8> = by_hash
        .get(root)
        .map(|b| b.to_vec())
        .ok_or(ProofError::MissingNode(*root))?;
    loop {
        let next = match parse_node(&current).map_err(ProofError::Malformed)? {
            Parsed::Leaf(p, v) => return Ok((p == rest).then_some(v)),
            Parsed::Extension(p, c) => match rest.strip_prefix(p.as_slice()) {
                Some(r) => {
                    rest = r;
                    c
                }
                None => return Ok(None),
            },
            Parsed::Branch(mut refs, v) => match rest.split_first() {
                None => return Ok(v),
                Some((idx, tail)) => {
                    rest = tail;
                    let i = usize::from(*idx & 0x0f);
                    if i >= refs.len() {
                        return Err(ProofError::Malformed("branch arity".into()));
                    }
                    refs.swap_remove(i)
                }
            },
        };
        current = match next {
            ParsedRef::Empty => return Ok(None),
            ParsedRef::Inline(b) => b,
            ParsedRef::Hash(h) => by_hash
                .get(&h)
                .map(|b| b.to_vec())
                .ok_or(ProofError::MissingNode(h))?,
        };
    }
}

// ---------------------------------------------------------------------------
// The from-scratch reference
// ---------------------------------------------------------------------------

/// The root of the trie holding `entries` (keys unique; empty values are
/// absent), computed from scratch: no cache, no insert/remove, one recursive
/// pass over the entries sorted by key. The reference the incremental trie is
/// tested and replayed against.
pub fn root_from_sorted(mut entries: Vec<(Vec<u8>, Vec<u8>)>) -> [u8; 32] {
    entries.retain(|(_, v)| !v.is_empty());
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries.dedup_by(|a, b| a.0 == b.0);
    if entries.is_empty() {
        return EMPTY_ROOT;
    }
    let paths: Vec<(Vec<u8>, &[u8])> = entries
        .iter()
        .map(|(k, v)| (nibbles(k), v.as_slice()))
        .collect();
    keccak(&build(&paths, 0))
}

/// RLP of the subtrie of `entries` (sorted, all sharing `depth` nibbles).
fn build(entries: &[(Vec<u8>, &[u8])], depth: usize) -> Vec<u8> {
    let rest_of =
        |e: &(Vec<u8>, &[u8])| -> Vec<u8> { e.0.get(depth..).unwrap_or_default().to_vec() };
    if let [only] = entries {
        let mut payload = Vec::new();
        rlp_append_bytes(&mut payload, &hex_prefix(&rest_of(only), true));
        rlp_append_bytes(&mut payload, only.1);
        return rlp_list(&payload);
    }
    // Shared prefix of all entries beyond `depth` (sorted: first vs last).
    let (Some(first), Some(last)) = (entries.first(), entries.last()) else {
        return rlp_list(&[]);
    };
    let shared = common_len(
        first.0.get(depth..).unwrap_or_default(),
        last.0.get(depth..).unwrap_or_default(),
    );
    if shared > 0 {
        let prefix = first
            .0
            .get(depth..depth.saturating_add(shared))
            .unwrap_or_default();
        let child = build(entries, depth.saturating_add(shared));
        let mut payload = Vec::new();
        rlp_append_bytes(&mut payload, &hex_prefix(prefix, false));
        append_child(&mut payload, child);
        return rlp_list(&payload);
    }
    let mut payload = Vec::new();
    let mut value: Option<&[u8]> = None;
    let mut groups: [Vec<(Vec<u8>, &[u8])>; 16] = Default::default();
    for e in entries {
        match e.0.get(depth) {
            None => value = Some(e.1),
            Some(n) => {
                if let Some(g) = groups.get_mut(usize::from(*n & 0x0f)) {
                    g.push((e.0.clone(), e.1));
                }
            }
        }
    }
    for g in &groups {
        if g.is_empty() {
            payload.push(0x80);
        } else {
            append_child(&mut payload, build(g, depth.saturating_add(1)));
        }
    }
    match value {
        Some(v) => rlp_append_bytes(&mut payload, v),
        None => payload.push(0x80),
    }
    rlp_list(&payload)
}

fn append_child(payload: &mut Vec<u8>, child: Vec<u8>) {
    if child.len() >= 32 {
        rlp_append_bytes(payload, &keccak(&child));
    } else {
        payload.extend_from_slice(&child);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trie_root_is_keccak_of_rlp_empty_string() {
        assert_eq!(Mpt::new().root_hash(), EMPTY_ROOT);
        assert_eq!(keccak(&[0x80]), EMPTY_ROOT);
        assert_eq!(keccak(&[]), KECCAK_EMPTY);
        assert_eq!(root_from_sorted(Vec::new()), EMPTY_ROOT);
    }

    #[test]
    fn hex_prefix_round_trips() {
        for path in [vec![], vec![1], vec![1, 2], vec![0, 0xf, 1], vec![0xa; 7]] {
            for leaf in [false, true] {
                let enc = hex_prefix(&path, leaf);
                assert_eq!(decode_hex_prefix(&enc), Some((path.clone(), leaf)));
            }
        }
        // Yellow Paper examples.
        assert_eq!(hex_prefix(&[1, 2, 3, 4, 5], false), vec![0x11, 0x23, 0x45]);
        assert_eq!(
            hex_prefix(&[0, 1, 2, 3, 4, 5], false),
            vec![0x00, 0x01, 0x23, 0x45]
        );
        assert_eq!(
            hex_prefix(&[0, 0xf, 1, 0xc, 0xb, 8], true),
            vec![0x20, 0x0f, 0x1c, 0xb8]
        );
        assert_eq!(
            hex_prefix(&[0xf, 1, 0xc, 0xb, 8], true),
            vec![0x3f, 0x1c, 0xb8]
        );
    }

    /// The canonical "dog/doe/dogglesworth" example from the Ethereum wiki.
    #[test]
    fn known_root_doe_dog_dogglesworth() {
        let mut t = Mpt::new();
        t.insert(b"doe", b"reindeer");
        t.insert(b"dog", b"puppy");
        t.insert(b"dogglesworth", b"cat");
        let want = "8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3";
        assert_eq!(hex::encode(t.root_hash()), want);
        assert_eq!(
            hex::encode(root_from_sorted(vec![
                (b"dogglesworth".to_vec(), b"cat".to_vec()),
                (b"doe".to_vec(), b"reindeer".to_vec()),
                (b"dog".to_vec(), b"puppy".to_vec()),
            ])),
            want
        );
    }
}
