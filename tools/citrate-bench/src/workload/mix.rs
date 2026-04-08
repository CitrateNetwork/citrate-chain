//! Weighted multi-class workload dispatcher.
//!
//! `MixedWorkload` composes an ordered list of `WorkloadClass`es
//! with positive integer weights and dispatches each `build` call
//! to one of them. The dispatch policy is **deterministic** —
//! a shared `AtomicU64` counter chooses the sub-class via a
//! cumulative-weight lookup. Over any window of length N >>
//! total_weight, the distribution exactly matches the configured
//! weight ratios.
//!
//! Determinism matters here because the runner's `effective_mix`
//! metric must be reproducible across runs for regression tracking,
//! and the tests in this module assert exact counts. Realistic
//! benchmarks still see interleaved traffic from two sources:
//!
//! 1. Signer pool round-robin interacts with the counter to shuffle
//!    txs between signers.
//! 2. `tokio::spawn` submission ordering is not deterministic even
//!    if dispatch is.
//!
//! Phase 5+ may swap in a weighted-random policy if that ever gains
//! value; the trait surface does not need to change.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::signers::Signer;
use crate::tx::SignedTx;
use crate::workload::{WorkloadClass, WorkloadContext};
use crate::{Error, Result};

/// One entry in the mix: the concrete class plus its integer weight.
/// Weights only need to be positive; the mix normalizes internally.
pub struct MixEntry {
    pub class: Arc<dyn WorkloadClass>,
    pub weight: u32,
}

/// Deterministic weighted dispatcher over multiple workload classes.
pub struct MixedWorkload {
    classes: Vec<Arc<dyn WorkloadClass>>,
    cumulative_weights: Vec<u32>,
    total_weight: u32,
    counter: AtomicU64,
}

impl std::fmt::Debug for MixedWorkload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("MixedWorkload");
        dbg.field("total_weight", &self.total_weight);
        dbg.field("counter", &self.counter.load(Ordering::Relaxed));
        let names: Vec<&str> = self.classes.iter().map(|c| c.name()).collect();
        dbg.field("classes", &names);
        dbg.field("cumulative_weights", &self.cumulative_weights);
        dbg.finish()
    }
}

impl MixedWorkload {
    /// Build a `MixedWorkload` from an ordered list of entries.
    ///
    /// Errors:
    /// - Empty input
    /// - Any weight is zero
    /// - Weights overflow `u32` when summed
    pub fn new(entries: Vec<MixEntry>) -> Result<Self> {
        if entries.is_empty() {
            return Err(Error::Workload("mix: entries must not be empty".into()));
        }

        let mut cumulative = Vec::with_capacity(entries.len());
        let mut total: u32 = 0;
        for entry in &entries {
            if entry.weight == 0 {
                return Err(Error::Workload(format!(
                    "mix: class '{}' has weight 0",
                    entry.class.name()
                )));
            }
            total = total
                .checked_add(entry.weight)
                .ok_or_else(|| Error::Workload("mix: weight sum overflows u32".into()))?;
            cumulative.push(total);
        }

        let classes = entries.into_iter().map(|e| e.class).collect();
        Ok(Self {
            classes,
            cumulative_weights: cumulative,
            total_weight: total,
            counter: AtomicU64::new(0),
        })
    }

    /// Sum of all weights.
    pub fn total_weight(&self) -> u32 {
        self.total_weight
    }

    /// Number of sub-classes.
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// Pick the sub-class for the next call. Increments the internal
    /// counter. Exposed as `pub(crate)` so the runner's tests can
    /// pre-drive it in isolation.
    pub(crate) fn pick_class(&self) -> &Arc<dyn WorkloadClass> {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let pos = (n % self.total_weight as u64) as u32;
        let idx = self
            .cumulative_weights
            .iter()
            .position(|cw| pos < *cw)
            .unwrap_or(self.classes.len() - 1);
        &self.classes[idx]
    }
}

impl WorkloadClass for MixedWorkload {
    fn name(&self) -> &'static str {
        "mix"
    }

    fn required_contracts(&self) -> &'static [&'static str] {
        // The runner never asks a mix for a single static slice.
        // See `aggregate_required_contracts` for the union.
        &[]
    }

    fn build(&self, ctx: &WorkloadContext, signer: &Signer, nonce: u64) -> Result<SignedTx> {
        Ok(self.build_with_class(ctx, signer, nonce)?.0)
    }

    fn build_with_class(
        &self,
        ctx: &WorkloadContext,
        signer: &Signer,
        nonce: u64,
    ) -> Result<(SignedTx, &'static str)> {
        let class = self.pick_class();
        let tx = class.build(ctx, signer, nonce)?;
        Ok((tx, class.name()))
    }

    fn class_roster(&self) -> Vec<&'static str> {
        // Flatten: include sub-mixes recursively by calling
        // `class_roster` on each entry, not just its `name()`.
        let mut out = Vec::new();
        for class in &self.classes {
            for n in class.class_roster() {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
        out
    }

    fn aggregate_required_contracts(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for class in &self.classes {
            for c in class.aggregate_required_contracts() {
                if !out.contains(&c) {
                    out.push(c);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::transfer::SimpleTransfer;
    use crate::workload::wrapped_salt::WrappedSaltTransfer;
    use crate::address_table::AddressTable;
    use std::collections::HashMap;

    fn signer() -> Signer {
        let mut k = [0u8; 32];
        k[31] = 0x99;
        Signer::from_key_bytes(&k).expect("signer")
    }

    fn ctx_with_table() -> WorkloadContext {
        let json = r#"{
          "chainId": 40204,
          "contracts": [
            { "name": "WrappedSALT", "address": "0x1f73bb479f397a34b5e3145e51d25bc5007273bf" }
          ]
        }"#;
        let t: AddressTable = serde_json::from_str(json).expect("parse");
        WorkloadContext::for_dry_run(40204, 1_000_000_000).with_address_table(Arc::new(t))
    }

    fn mix_two() -> MixedWorkload {
        MixedWorkload::new(vec![
            MixEntry {
                class: Arc::new(SimpleTransfer::default_bench()),
                weight: 30,
            },
            MixEntry {
                class: Arc::new(WrappedSaltTransfer::default_bench()),
                weight: 70,
            },
        ])
        .expect("mix")
    }

    #[test]
    fn rejects_empty_entries() {
        assert!(MixedWorkload::new(vec![]).is_err());
    }

    #[test]
    fn rejects_zero_weight() {
        let bad = MixedWorkload::new(vec![MixEntry {
            class: Arc::new(SimpleTransfer::default_bench()),
            weight: 0,
        }]);
        assert!(bad.is_err());
    }

    #[test]
    fn class_roster_lists_sub_classes() {
        let mix = mix_two();
        let roster = mix.class_roster();
        assert_eq!(roster.len(), 2);
        assert!(roster.contains(&"simple_transfer"));
        assert!(roster.contains(&"wrapped_salt"));
    }

    #[test]
    fn aggregate_required_contracts_unions_sub_classes() {
        let mix = mix_two();
        let reqs = mix.aggregate_required_contracts();
        assert!(reqs.contains(&"WrappedSALT"));
        // simple_transfer contributes nothing.
        assert_eq!(reqs.len(), 1);
    }

    #[test]
    fn dispatch_respects_weights_over_a_window() {
        // With weights 30/70 and total_weight 100, 100 picks should
        // give exactly 30 of class A and 70 of class B.
        let mix = mix_two();
        let mut counts: HashMap<&'static str, u64> = HashMap::new();
        for _ in 0..100 {
            let class = mix.pick_class();
            *counts.entry(class.name()).or_default() += 1;
        }
        assert_eq!(counts["simple_transfer"], 30);
        assert_eq!(counts["wrapped_salt"], 70);
    }

    #[test]
    fn dispatch_is_deterministic_across_instances() {
        let a = mix_two();
        let b = mix_two();
        let picks_a: Vec<&str> =
            (0..20).map(|_| a.pick_class().name()).collect();
        let picks_b: Vec<&str> =
            (0..20).map(|_| b.pick_class().name()).collect();
        assert_eq!(picks_a, picks_b);
    }

    #[test]
    fn build_with_class_returns_picked_name() {
        // Weights (1, 1) so the deterministic dispatcher alternates
        // perfectly on each call and both classes are visited within
        // a handful of iterations.
        let ctx = ctx_with_table();
        let mix = MixedWorkload::new(vec![
            MixEntry {
                class: Arc::new(SimpleTransfer::default_bench()),
                weight: 1,
            },
            MixEntry {
                class: Arc::new(WrappedSaltTransfer::default_bench()),
                weight: 1,
            },
        ])
        .expect("mix");
        let mut seen_transfer = false;
        let mut seen_wrapped = false;
        for i in 0..20 {
            let (tx, name) = mix
                .build_with_class(&ctx, &signer(), i as u64)
                .expect("build");
            assert_eq!(tx.nonce, i as u64);
            match name {
                "simple_transfer" => seen_transfer = true,
                "wrapped_salt" => seen_wrapped = true,
                other => panic!("unexpected class name: {other}"),
            }
        }
        assert!(seen_transfer);
        assert!(seen_wrapped);
    }

    #[test]
    fn single_class_mix_behaves_like_leaf() {
        let only_simple = MixedWorkload::new(vec![MixEntry {
            class: Arc::new(SimpleTransfer::default_bench()),
            weight: 10,
        }])
        .expect("mix");
        for _ in 0..10 {
            assert_eq!(only_simple.pick_class().name(), "simple_transfer");
        }
    }

    #[test]
    fn build_through_mix_produces_matching_sender_and_nonce() {
        let ctx = WorkloadContext::for_dry_run(40204, 1_000_000_000);
        // Use a mix that never needs the address table.
        let mix = MixedWorkload::new(vec![MixEntry {
            class: Arc::new(SimpleTransfer::default_bench()),
            weight: 1,
        }])
        .expect("mix");
        let s = signer();
        let tx = mix.build(&ctx, &s, 42).expect("build");
        assert_eq!(tx.sender, s.address);
        assert_eq!(tx.nonce, 42);
    }
}
