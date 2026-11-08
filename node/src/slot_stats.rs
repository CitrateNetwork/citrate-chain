//! Slot statistics for the S1 devnet (ADR CV-4b: sortition is designed and
//! measured, not implemented; spec `06_CONSENSUS_SPEC.md` §6, M2-M4).
//!
//! Once per slot the task samples the applied tip and counts selected-chain
//! reorgs; once per window it summarises the stored blocks of the last
//! completed window of slots:
//!
//! - blocks per slot (mean and max), the number of proposers per slot that
//!   sortition would cap at about τ;
//! - the empty-slot rate, which sortition would raise to about e^-τ;
//! - the merge rate (share of blocks with at least one merge parent) and the
//!   mean merge-parent count;
//! - the reorg rate (selected-chain reorgs per applied block) and the deepest
//!   reorg.
//!
//! Sources: the DAG store's slot index (stored headers: slot, proposer, merge
//! parents), the applied tip (`BlockStore::get_applied_tip`), the DAG headers
//! for the reorg walk, and the DAG store's equivocation evidence. Published as
//! `citrate_slot_stats{stat}`, `citrate_selected_chain_reorgs_total{depth}` and
//! `citrate_equivocations_recorded`, and logged as one `slot-stats:` line per
//! window.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn window_counts_blocks_empty_slots_and_merges() {
        // Slots 10..=19: slot 10 has 3 blocks (one merging 2 parents), slot 12
        // has 1 block, slot 30 is outside, the rest are empty.
        let by_slot = vec![(10, vec![0, 2, 0]), (12, vec![1]), (30, vec![0, 0])];
        let w = summarize(10, 19, &by_slot);
        assert_eq!(w.slots, 10);
        assert_eq!(w.blocks, 4);
        assert_eq!(w.max_blocks_in_a_slot, 3);
        assert_eq!(w.empty_slots, 8);
        assert_eq!(w.blocks_with_merges, 2);
        assert_eq!(w.merge_parents, 3);
        assert!((w.blocks_per_slot() - 0.4).abs() < 1e-9);
        assert!((w.empty_slot_rate() - 0.8).abs() < 1e-9);
        assert!((w.merge_rate() - 0.5).abs() < 1e-9);
        let empty = summarize(5, 4, &by_slot);
        assert_eq!((empty.slots, empty.blocks_per_slot()), (0, 0.0));
    }

    fn h(tag: u8, height: u64) -> Hash {
        let mut b = [0u8; 32];
        b[0] = tag;
        b[1..9].copy_from_slice(&height.to_be_bytes());
        Hash::new(b)
    }

    /// Chain `tag` forks off chain 0 at `fork`: blocks h(tag, n) for n > fork.
    fn parents() -> HashMap<Hash, Hash> {
        let mut m = HashMap::new();
        for n in 1..=20u64 {
            m.insert(h(0, n), h(0, n - 1));
            if n > 5 {
                m.insert(h(1, n), if n == 6 { h(0, 5) } else { h(1, n - 1) });
            }
        }
        m
    }

    #[tokio::test]
    async fn tracker_counts_extensions_and_reorgs_with_depth() {
        let p = parents();
        let sp = |x: Hash| {
            let v = p.get(&x).copied();
            async move { v }
        };
        let mut t = ReorgTracker::default();
        assert_eq!(t.observe((h(0, 3), 3), sp).await, TipMove::None);
        assert_eq!(t.observe((h(0, 8), 8), sp).await, TipMove::Extended(5));
        assert_eq!(t.observe((h(0, 8), 8), sp).await, TipMove::None);
        // To the other branch, which forked at 5: 3 blocks abandoned, 4 added.
        assert_eq!(
            t.observe((h(1, 9), 9), sp).await,
            TipMove::Reorg { depth: 3, added: 4 }
        );
        // Back, to a lower tip of chain 0 (depth 4 of chain 1 abandoned).
        assert_eq!(
            t.observe((h(0, 7), 7), sp).await,
            TipMove::Reorg { depth: 4, added: 2 }
        );
        assert_eq!(t.reorgs, 2);
        assert_eq!(t.max_depth, 4);
        assert_eq!(t.applied, 5 + 4 + 2);
        assert!((t.reorg_rate() - 2.0 / 11.0).abs() < 1e-9);
        t.reset_window();
        assert_eq!((t.reorgs, t.max_depth, t.applied), (0, 0, 0));
    }

    #[test]
    fn report_line_names_every_measure() {
        let w = summarize(1, 60, &[(3, vec![0, 1])]);
        let line = report_line(&w, &ReorgTracker::default(), 0);
        for k in [
            "blocks/slot",
            "empty-slot rate",
            "merge rate",
            "reorgs",
            "equivocations",
        ] {
            assert!(line.contains(k), "{k} missing from {line}");
        }
    }

    /// A move whose walk meets a header this node does not hold is neither an
    /// extension nor a reorg: it is not counted, so a pruned or not-yet-admitted
    /// ancestor never shows up as a phantom reorg.
    #[tokio::test]
    async fn tracker_does_not_count_a_move_it_cannot_trace() {
        let p = parents();
        let sp = |x: Hash| {
            let v = p.get(&x).copied();
            async move { v }
        };
        let mut t = ReorgTracker::default();
        assert_eq!(t.observe((h(0, 8), 8), sp).await, TipMove::None);
        // Chain 9 is unknown below its tip: no selected parent.
        assert_eq!(t.observe((h(9, 12), 12), sp).await, TipMove::Unknown);
        assert_eq!((t.reorgs, t.max_depth, t.applied), (0, 0, 0));
        // The next sample is judged from the untraceable tip.
        assert_eq!(t.observe((h(0, 13), 13), sp).await, TipMove::Unknown);
        assert_eq!(t.reorgs, 0);
    }

    /// The window is read from the DAG store: the stored headers by slot, each
    /// with its merge-parent count (`DagStore::merge_counts_by_slot`).
    #[tokio::test]
    async fn window_from_the_dag_store_slot_index() {
        use citrate_consensus::types::{BlockBuilder, PublicKey};
        const G_TS: u64 = 1_767_225_600;
        let dag = DagStore::with_permissive_vrf_for_testing();
        let at = |id: u8, sp: Hash, merges: Vec<Hash>, height: u64, slot: u64| {
            BlockBuilder::new()
                .hash(Hash::new([id; 32]))
                .parent(sp)
                .merge_parents(merges)
                .height(height)
                .blue_score(height)
                .timestamp(G_TS + slot * SLOT_DURATION_SECS)
                .proposer(PublicKey::new([id; 32]))
                .build_unhashed()
        };
        let g = citrate_consensus::types::BlockBuilder::new()
            .hash(Hash::new([0xEE; 32]))
            .timestamp(G_TS)
            .build_unhashed();
        dag.store_block(g.clone()).await.expect("genesis");
        // Slot 1: two siblings. Slot 2: empty. Slot 3: one block merging the
        // other sibling. Slot 4: empty.
        let a = at(1, g.hash(), vec![], 1, 1);
        let b = at(2, g.hash(), vec![], 1, 1);
        let c = at(3, a.hash(), vec![b.hash()], 2, 3);
        for x in [&a, &b, &c] {
            dag.store_block(x.clone()).await.expect("store");
        }
        let by_slot = dag.merge_counts_by_slot(1, 4).await;
        let slots: Vec<u64> = by_slot.iter().map(|(s, _)| *s).collect();
        assert_eq!(
            slots,
            vec![1, 3],
            "genesis is not slot-indexed; empty slots are absent"
        );
        let w = summarize(1, 4, &by_slot);
        assert_eq!(
            (w.slots, w.blocks, w.max_blocks_in_a_slot, w.empty_slots),
            (4, 3, 2, 2)
        );
        assert_eq!((w.blocks_with_merges, w.merge_parents), (1, 1));
        assert!(dag.merge_counts_by_slot(4, 1).await.is_empty());
    }

    /// A window is published to the metrics surface under the names the devnet
    /// dashboards read.
    #[test]
    fn a_window_is_published_to_the_metrics_surface() {
        use citrate_api::metrics_server as m;
        let w = summarize(1, 4, &[(1, vec![0, 0]), (3, vec![1])]);
        let r = ReorgTracker {
            reorgs: 1,
            max_depth: 2,
            applied: 4,
            ..ReorgTracker::default()
        };
        publish_for_test(&w, &r, 5);
        let close = |a: f64, b: f64| (a - b).abs() < 1e-9;
        assert!(close(m::slot_stat("blocks_per_slot"), 0.75));
        assert!(close(m::slot_stat("blocks_per_slot_max"), 2.0));
        assert!(close(m::slot_stat("empty_slot_rate"), 0.5));
        assert!(close(m::slot_stat("merge_rate"), 1.0 / 3.0));
        assert!(close(m::slot_stat("reorg_rate"), 0.25));
        assert!(close(m::slot_stat("reorg_depth_max"), 2.0));
        assert!(close(m::slot_stat("window_slots"), 4.0));
        assert!(close(m::equivocations_recorded(), 5.0));
        let before = m::selected_chain_reorgs("3");
        m::record_selected_chain_reorg(3);
        assert!(close(m::selected_chain_reorgs("3"), before + 1.0));
    }
}
