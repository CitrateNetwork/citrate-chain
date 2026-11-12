//! The reference's GHOSTDAG against rusty-kaspa's test DAGs (af6ff23a,
//! `testing/integration/testdata/dags/dag0..5.json`, ISC License, Copyright
//! (c) 2022-2024 Kaspa developers), read from the copies under
//! `core/consensus/tests/fixtures/kaspa_ghostdag/`. Kaspa orders by
//! (blue_work, hash); the reference by (blue_work, vrf_output, hash), the same
//! order with every VRF output zero, as here. The reference derives each
//! selected parent itself.

use std::collections::HashMap;

use citrate_consensus::types::{Block, BlockBuilder, Hash};
use citrate_mergeset_ref::ghostdag::Dag;

#[derive(serde::Deserialize)]
struct KaspaDag {
    #[serde(rename = "K")]
    k: u32,
    #[serde(rename = "GenesisID")]
    genesis_id: String,
    #[serde(rename = "Blocks")]
    blocks: Vec<KaspaBlock>,
}

#[derive(serde::Deserialize)]
struct KaspaBlock {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "ExpectedScore")]
    score: u64,
    #[serde(rename = "ExpectedSelectedParent")]
    selected_parent: String,
    #[serde(rename = "ExpectedReds")]
    reds: Vec<String>,
    #[serde(rename = "ExpectedBlues")]
    blues: Vec<String>,
    #[serde(rename = "Parents")]
    parents: Vec<String>,
}

fn h(id: &str) -> Hash {
    let mut b = [0u8; 32];
    for (d, s) in b.iter_mut().zip(id.as_bytes()) {
        *d = *s;
    }
    Hash::new(b)
}

#[test]
fn reference_coloring_matches_kaspa_vectors() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/consensus/tests/fixtures/kaspa_ghostdag");
    for n in 0..=5 {
        let raw = std::fs::read_to_string(dir.join(format!("dag{n}.json"))).expect("vector");
        let dag: KaspaDag = serde_json::from_str(&raw).expect("json");
        let mut height: HashMap<String, u64> = HashMap::new();
        height.insert(dag.genesis_id.clone(), 0);
        let mut blocks: Vec<Block> = vec![BlockBuilder::new()
            .hash(h(&dag.genesis_id))
            .height(0)
            .build_unhashed()];
        for kb in &dag.blocks {
            // The header names Kaspa's first parent as the selected parent;
            // the reference ignores that and derives it from keys.
            let first = &kb.parents[0];
            let merges: Vec<Hash> = kb.parents[1..].iter().map(|p| h(p)).collect();
            let hh = height[&kb.selected_parent] + 1;
            height.insert(kb.id.clone(), hh);
            blocks.push(
                BlockBuilder::new()
                    .hash(h(&kb.id))
                    .parent(h(first))
                    .merge_parents(merges)
                    .height(hh)
                    .build_unhashed(),
            );
        }
        let mut d = Dag::new(&blocks).expect("dag");
        d.color_all(dag.k).expect("color");
        for kb in &dag.blocks {
            let rec = &d.records[&h(&kb.id)];
            let names = |v: &[String]| v.iter().map(|x| h(x)).collect::<Vec<_>>();
            assert_eq!(
                rec.selected_parent,
                Some(h(&kb.selected_parent)),
                "dag{n} {} sp",
                kb.id
            );
            assert_eq!(rec.blues, names(&kb.blues), "dag{n} {} blues", kb.id);
            assert_eq!(rec.reds, names(&kb.reds), "dag{n} {} reds", kb.id);
            assert_eq!(rec.blue_score, kb.score, "dag{n} {} score", kb.id);
        }
    }
}
