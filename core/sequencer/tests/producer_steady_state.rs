//! PIL-13 WP-13.5 — producer steady-state memory tripwire.
//!
//! The PIL-13 leak: `BlockProducer::with_shared_dag`'s eager DAG-load loop
//! called `GhostDag::add_block` for every persisted block on startup, and each
//! call materialised + cached the FULL O(chain-length) cumulative blue
//! ancestry — O(N²) memory across the chain. At 281k blocks the 16 GB RPC
//! droplet kernel-OOM'd within ~30 s (RSS 15.8 GB). The fix (citrate-chain#1,
//! `4c2383c`) routes the eager load through
//! `GhostDag::register_existing_block`, which stores a lightweight `BlueSet`
//! (empty `.blocks`, header-derived score/work) — O(1) per block.
//!
//! This test replays the eager-load loop in-process over a 200-block linear
//! chain (the with_shared_dag shape: genesis → tip, register each) and
//! asserts the two properties that make the leak structurally impossible:
//!
//! 1. **Zero materialised cumulative ancestry.** The broken `add_block` path
//!    accumulates Σ(1..=N) ≈ 20k ancestry entries at N=200 and O(N²) at chain
//!    scale; the steady-state path must stay at 0
//!    (`materialised_blue_ancestry_entries`, the PIL-13 tripwire metric).
//! 2. **Bounded RSS growth** across the load — a generous absolute bound that
//!    catches gross regressions of any future producer-startup path without
//!    flaking on allocator noise.
//!
//! It also asserts `select_tip` still works over lightweight registrations —
//! the safety claim that made the fix sound (only `.score` is read back).
//!
//! Prometheus side of WP-13.5: `ProducerMemoryHigh` alert on
//! `process_resident_memory_bytes{job="citrate-node"} > 3e9`
//! (node/monitoring/alerts/citrate-alerts.yml).

use std::sync::Arc;

use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::{blue_work_for_score, Block, BlockBuilder, GhostDagParams, Hash};

const CHAIN_LEN: u64 = 200;

/// Build block N of a linear chain (height == blue_score == N), the same
/// shape the producer's eager-load loop walks on startup. Hashes are synthetic
/// but unique and stable.
fn linear_block(n: u64, parent: Hash) -> Block {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = 0xb1; // disambiguate from Hash::default() for n=0
    BlockBuilder::new()
        .hash(Hash::new(h))
        .parent(parent)
        .height(n)
        .blue_score(n)
        .blue_work(blue_work_for_score(n))
        .build_unhashed()
}

/// Current process resident set size in bytes (Linux: /proc/self/statm;
/// macOS: `ps -o rss=`). Test-grade — good enough to catch a gross leak.
fn rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(resident_pages) = statm
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u64>().ok())
            {
                return resident_pages * 4096;
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok();
        out.and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|kib| kib * 1024)
            .unwrap_or(0)
    }
}

#[tokio::test]
async fn eager_load_of_200_blocks_keeps_memory_flat() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store);

    let rss_before = rss_bytes();

    // Replay the with_shared_dag eager-load loop: genesis → tip, one
    // register_existing_block per persisted block.
    let mut parent = Hash::default();
    for n in 0..CHAIN_LEN {
        let block = linear_block(n, parent);
        parent = block.hash();
        ghostdag
            .register_existing_block(&block)
            .await
            .unwrap_or_else(|e| panic!("register block {n}: {e:?}"));
    }

    // 1. The PIL-13 tripwire: ZERO cumulative blue-ancestry entries
    //    materialised. The pre-fix add_block path would hold ~Σ(1..=200) =
    //    20,100 here and O(N²) at chain scale.
    let materialised = ghostdag.materialised_blue_ancestry_entries().await;
    assert_eq!(
        materialised, 0,
        "steady-state eager load materialised {materialised} cumulative \
         blue-ancestry entries — the PIL-13 O(N²) path is back"
    );

    // 2. Bounded RSS growth. 200 lightweight registrations cost well under a
    //    megabyte; 64 MiB is a generous allocator-noise ceiling that still
    //    catches any reintroduced per-block ancestry materialisation at scale.
    let rss_after = rss_bytes();
    if rss_before > 0 && rss_after > 0 {
        let growth = rss_after.saturating_sub(rss_before);
        assert!(
            growth < 64 * 1024 * 1024,
            "RSS grew {growth} bytes across a 200-block eager load (bound: 64 MiB)"
        );
    }

    // 3. The lightweight registrations still drive tip selection (the fix's
    //    safety claim: select_tip only reads .score, never .blocks).
    let tip = ghostdag.select_tip().await.expect("a tip exists");
    assert_eq!(tip, parent, "the chain head is the selected tip");
    let score = ghostdag.get_blue_score(&tip).await.expect("tip has a score");
    // SYNC-S1 D1: `register_existing_block` no longer copies the score out of
    // the header. It derives it locally and inductively — genesis is 1 and each
    // linear step adds 1 — so the tip of a CHAIN_LEN-block chain (heights
    // 0..CHAIN_LEN-1) scores CHAIN_LEN, one above the header's `height`.
    //
    // The shift is the POINT of D1, not a side effect: pre-D1 this path stored
    // `height` while the receive path (`add_block`) stored `height + 1`, so the
    // same block scored differently depending on whether it arrived live or was
    // rehydrated from disk after a restart, and `select_tip` compares those
    // numbers across tips. Deriving in both paths removes that inconsistency
    // and still keeps SECREM-01 CONS-2 (no header-reported score reaches the
    // fork-choice baseline).
    assert_eq!(
        score, CHAIN_LEN,
        "locally derived blue score: genesis 1 + one per linear step"
    );
}
