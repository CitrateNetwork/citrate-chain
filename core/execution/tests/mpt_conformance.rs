//! CV-14 (a) conformance: the standard MPT (`citrate_execution::state::mpt`) against
//!
//! 1. the Ethereum trie test vectors (ethereum/tests `TrieTests`, copied unmodified
//!    into `tests/fixtures/ethereum-trie-tests/`, MIT; see the README there), plain
//!    and secure (keccak-keyed), with deletes; and
//! 2. two independent implementations on random key/value sets and random
//!    insert/remove histories: parity's `triehash` (OpenEthereum's root builder,
//!    embedded nodes included) and alloy-trie (reth's root builder and proof
//!    verifier). Roots must be equal, and our proofs must verify under alloy's
//!    verifier.
//!
//!    alloy-trie 0.4.1 is used only where no node is shorter than 32 bytes: its
//!    `HashBuilder` assumes every branch child is hashed (it panics on an embedded
//!    child), and its verifier expects embedded nodes as separate proof items,
//!    while `eth_getProof` (geth's convention, which we follow) lists only the
//!    hash-referenced nodes and the root. In the secure state tries an embedded
//!    node needs a remaining path and value under 32 bytes together, which the
//!    random inputs below produce on purpose for `triehash`.
//!
//! Both the incremental trie (`Mpt::insert` / `Mpt::remove`) and the from-scratch
//! reference (`mpt::root_from_sorted`) are checked.

use alloy_primitives::{Bytes, B256};
use alloy_trie::{HashBuilder, Nibbles};
use citrate_execution::state::mpt::{self, keccak, Mpt, EMPTY_ROOT};
use proptest::prelude::*;
use serde_json::Value;
use std::collections::BTreeMap;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ethereum-trie-tests"
);

/// A vector string: `0x..` is hex, anything else its UTF-8 bytes.
fn bytes_of(v: &Value) -> Option<Vec<u8>> {
    let s = v.as_str()?;
    Some(match s.strip_prefix("0x") {
        Some(h) => hex::decode(h).expect("hex in vector"),
        None => s.as_bytes().to_vec(),
    })
}

/// (key, value-or-delete) operations of one vector, in order.
fn ops_of(input: &Value) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    match input {
        Value::Object(m) => m
            .iter()
            .map(|(k, v)| {
                let key = bytes_of(&Value::String(k.clone())).expect("key");
                (key, bytes_of(v))
            })
            .collect(),
        Value::Array(a) => a
            .iter()
            .map(|pair| {
                let p = pair.as_array().expect("[key, value]");
                (bytes_of(&p[0]).expect("key"), bytes_of(&p[1]))
            })
            .collect(),
        other => panic!("unexpected vector input {other}"),
    }
}

fn load(file: &str) -> serde_json::Map<String, Value> {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{file}")).expect("fixture");
    serde_json::from_str::<Value>(&text)
        .expect("json")
        .as_object()
        .expect("object")
        .clone()
}

/// Run every vector of `file`; `secure` keys the trie by keccak256(key);
/// `any_order` also checks reversed insertion (the vector's map is unordered).
fn run_vectors(file: &str, secure: bool, any_order: bool) -> usize {
    let vectors = load(file);
    assert!(!vectors.is_empty(), "{file}: no vectors");
    for (name, v) in &vectors {
        let want = v["root"].as_str().expect("root");
        let ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = ops_of(&v["in"])
            .into_iter()
            .map(|(k, val)| (if secure { keccak(&k).to_vec() } else { k }, val))
            .collect();
        let mut orders = vec![ops.clone()];
        if any_order {
            orders.push(ops.iter().rev().cloned().collect());
        }
        for (i, order) in orders.iter().enumerate() {
            let mut t = Mpt::new();
            let mut map: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
            for (k, val) in order {
                match val {
                    Some(val) if !val.is_empty() => {
                        t.insert(k, val);
                        map.insert(k.clone(), val.clone());
                    }
                    _ => {
                        t.remove(k);
                        map.remove(k);
                    }
                }
            }
            assert_eq!(
                format!("0x{}", hex::encode(t.root_hash())),
                want,
                "{file} {name} (order {i}): incremental root"
            );
            assert_eq!(
                format!(
                    "0x{}",
                    hex::encode(mpt::root_from_sorted(map.into_iter().collect()))
                ),
                want,
                "{file} {name} (order {i}): from-scratch root"
            );
        }
    }
    vectors.len()
}

#[test]
fn ethereum_trie_vectors_trieanyorder() {
    assert_eq!(run_vectors("trieanyorder.json", false, true), 7);
}

#[test]
fn ethereum_trie_vectors_trietest_with_deletes() {
    assert_eq!(run_vectors("trietest.json", false, false), 5);
}

#[test]
fn ethereum_trie_vectors_trieanyorder_secure() {
    assert_eq!(run_vectors("trieanyorder_secureTrie.json", true, true), 7);
}

#[test]
fn ethereum_trie_vectors_trietest_secure_with_deletes() {
    assert_eq!(run_vectors("trietest_secureTrie.json", true, false), 3);
}

/// State-shaped vectors: addresses keyed by keccak, values RLP accounts.
#[test]
fn ethereum_trie_vectors_hex_encoded_secure() {
    assert_eq!(
        run_vectors("hex_encoded_securetrie_test.json", true, true),
        3
    );
}

/// parity's `triehash` root of `entries`.
fn triehash_root(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    triehash::trie_root::<keccak_hasher::KeccakHasher, _, _, _>(
        entries.iter().map(|(k, v)| (k.clone(), v.clone())),
    )
}

/// alloy-trie's root of `entries` (keys of one length, so none is a prefix of
/// another, as in a secure trie; no embedded node, see the module docs).
fn alloy_root(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    let mut hb = HashBuilder::default();
    for (k, v) in entries {
        hb.add_leaf(Nibbles::unpack(k), v);
    }
    hb.root().0
}

/// Keys and values shaped like state: 32-byte keys (a few sharing long
/// prefixes, to force extensions), values of 1..=80 bytes (so some nodes embed
/// and some hash).
fn key_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 32),
        (any::<u8>(), any::<u8>()).prop_map(|(a, b)| {
            let mut k = vec![0xab; 32];
            k[30] = a;
            k[31] = b;
            k
        }),
    ]
}

fn value_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..80)
}

/// Uniform 32-byte keys and values of 32+ bytes: every node is 32 bytes or
/// more, so none embeds (the inputs alloy-trie 0.4 handles).
fn wide_key() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 32)
}

fn wide_value() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 32..80)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Random insert/remove histories (embedded nodes included): the
    /// incremental root, the from-scratch root and triehash's root of the final
    /// map are equal.
    #[test]
    fn roots_match_triehash_on_random_histories(
        ops in prop::collection::vec(
            (key_strategy(), prop::option::weighted(0.75, value_strategy())),
            0..120,
        ),
    ) {
        let mut t = Mpt::new();
        let mut map: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let mut inserted: Vec<Vec<u8>> = Vec::new();
        for (i, (k, v)) in ops.iter().enumerate() {
            match v {
                Some(v) => {
                    t.insert(k, v);
                    map.insert(k.clone(), v.clone());
                    inserted.push(k.clone());
                }
                None => {
                    // Remove a key that exists half the time.
                    let k = if i.is_multiple_of(2) && !inserted.is_empty() {
                        inserted[i % inserted.len()].clone()
                    } else {
                        k.clone()
                    };
                    t.remove(&k);
                    map.remove(&k);
                }
            }
        }
        let want = triehash_root(&map);
        prop_assert_eq!(t.root_hash(), want, "incremental vs triehash");
        prop_assert_eq!(
            mpt::root_from_sorted(map.clone().into_iter().collect()),
            want,
            "from-scratch vs triehash"
        );
        prop_assert_eq!(t.len(), map.len());
        prop_assert_eq!(t.entries(), map.into_iter().collect::<Vec<_>>());
    }

    /// Random histories without embedded nodes: the roots equal alloy-trie's.
    #[test]
    fn roots_match_alloy_trie_on_random_histories(
        ops in prop::collection::vec(
            (wide_key(), prop::option::weighted(0.8, wide_value())),
            0..120,
        ),
    ) {
        let mut t = Mpt::new();
        let mut map: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for (k, v) in &ops {
            match v {
                Some(v) => {
                    t.insert(k, v);
                    map.insert(k.clone(), v.clone());
                }
                None => {
                    let k = map.keys().next().cloned().unwrap_or_else(|| k.clone());
                    t.remove(&k);
                    map.remove(&k);
                }
            }
        }
        prop_assert_eq!(t.root_hash(), alloy_root(&map), "incremental vs alloy-trie");
        prop_assert_eq!(t.root_hash(), triehash_root(&map), "incremental vs triehash");
    }

    /// Our proofs verify under alloy-trie's verifier (no embedded nodes, see
    /// the module docs), for present and absent keys alike, and under ours; a
    /// tampered value does not.
    #[test]
    fn proofs_verify_under_alloy_trie(
        entries in prop::collection::btree_map(wide_key(), wide_value(), 1..60),
        absent in wide_key(),
    ) {
        let mut t = Mpt::new();
        for (k, v) in &entries {
            t.insert(k, v);
        }
        let root = t.root_hash();
        for (k, v) in entries.iter().take(8) {
            let proof = t.proof(k);
            let as_bytes: Vec<Bytes> = proof.iter().map(|p| Bytes::from(p.clone())).collect();
            prop_assert!(alloy_trie::proof::verify_proof(
                B256::from(root), Nibbles::unpack(k), Some(v.clone()), as_bytes.iter()
            ).is_ok());
            prop_assert_eq!(mpt::verify_proof(&root, k, &proof), Ok(Some(v.clone())));
            let mut wrong = v.clone();
            wrong[0] ^= 1;
            prop_assert!(alloy_trie::proof::verify_proof(
                B256::from(root), Nibbles::unpack(k), Some(wrong), as_bytes.iter()
            ).is_err());
        }
        if !entries.contains_key(&absent) {
            let proof = t.proof(&absent);
            let as_bytes: Vec<Bytes> = proof.iter().map(|p| Bytes::from(p.clone())).collect();
            prop_assert!(alloy_trie::proof::verify_proof(
                B256::from(root), Nibbles::unpack(&absent), None, as_bytes.iter()
            ).is_ok());
            prop_assert_eq!(mpt::verify_proof(&root, &absent, &proof), Ok(None));
        }
    }

    /// Our proofs verify under our verifier with embedded nodes too (the
    /// geth convention: only hash-referenced nodes and the root are listed).
    #[test]
    fn proofs_verify_with_embedded_nodes(
        entries in prop::collection::btree_map(key_strategy(), value_strategy(), 1..60),
    ) {
        let mut t = Mpt::new();
        for (k, v) in &entries {
            t.insert(k, v);
        }
        let root = t.root_hash();
        prop_assert_eq!(root, triehash_root(&entries));
        for (k, v) in &entries {
            prop_assert_eq!(mpt::verify_proof(&root, k, &t.proof(k)), Ok(Some(v.clone())));
        }
    }

    /// Persisting and reloading a trie reproduces it exactly (same root, same
    /// entries), and every loaded node is checked.
    #[test]
    fn load_round_trips_and_rejects_corruption(
        entries in prop::collection::btree_map(key_strategy(), value_strategy(), 1..60),
        victim in any::<usize>(),
    ) {
        let mut t = Mpt::new();
        for (k, v) in &entries {
            t.insert(k, v);
        }
        let mut nodes = Vec::new();
        t.collect_unpersisted(&mut nodes);
        let store: std::collections::HashMap<[u8; 32], Vec<u8>> = nodes.iter().cloned().collect();
        let loaded = Mpt::load(&t.root_hash(), &|h| store.get(h).cloned()).expect("load");
        prop_assert_eq!(loaded.root_hash(), t.root_hash());
        prop_assert_eq!(loaded.entries(), t.entries());
        // Nothing new to persist after marking, and a loaded trie counts as persisted.
        t.mark_persisted();
        let mut again = Vec::new();
        t.collect_unpersisted(&mut again);
        prop_assert!(again.is_empty());
        loaded.collect_unpersisted(&mut again);
        prop_assert!(again.is_empty());
        // Corrupt one stored node: the load fails (never a different trie).
        let (h, rlp) = &nodes[victim % nodes.len()];
        let mut bad = store.clone();
        let mut flipped = rlp.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        bad.insert(*h, flipped);
        prop_assert!(Mpt::load(&t.root_hash(), &|x| bad.get(x).cloned()).is_err());
        let mut missing = store.clone();
        missing.remove(h);
        prop_assert!(Mpt::load(&t.root_hash(), &|x| missing.get(x).cloned()).is_err());
    }
}

#[test]
fn empty_trie_matches_alloy() {
    assert_eq!(alloy_root(&BTreeMap::new()), EMPTY_ROOT);
    assert_eq!(triehash_root(&BTreeMap::new()), EMPTY_ROOT);
    assert_eq!(Mpt::new().root_hash(), EMPTY_ROOT);
}
