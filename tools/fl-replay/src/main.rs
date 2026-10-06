// PANIC-S1 G2: production code in this crate may not panic. Every panic class is
// denied outside tests; a genuine invariant needs an item-level #[allow] with an
// `// INVARIANT:` comment (enforced by scripts/ci/panic_invariant_tripwire.sh).
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

//! `citrate-fl-replay`: replay a federated LoRA round from its bundle.
//!
//! ```text
//! citrate-fl-replay --bundle bundle.json --deltas DIR
//!                   [--start start.gguf --merged merged.gguf]
//!                   [--rules MIN,CHUNK_DIM,SCALE,TPOS,TNEG]
//! ```
//!
//! Prints a JSON report (the recomputed roots and record digest, and every
//! mismatch) and exits non-zero when anything disagrees. `--rules` takes the
//! cluster's rules as read from `FederatedRoundLedger.getCluster`, so the
//! report also says whether the config matches the chain.

use std::collections::BTreeMap;
use std::path::PathBuf;

use citrate_fl_replay::{replay, Bundle, ChainRules, Inputs};

fn main() -> anyhow::Result<()> {
    let mut args = BTreeMap::new();
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let key = k
            .strip_prefix("--")
            .ok_or_else(|| anyhow::anyhow!("expected --flag, got {k:?}"))?
            .to_string();
        let v = it
            .next()
            .ok_or_else(|| anyhow::anyhow!("--{key} needs a value"))?;
        args.insert(key, v);
    }
    let need = |k: &str| {
        args.get(k)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("--{k} is required"))
    };
    let bundle: Bundle = serde_json::from_slice(&std::fs::read(need("bundle")?)?)?;
    let deltas = PathBuf::from(need("deltas")?);
    let start = args.get("start").map(std::fs::read).transpose()?;
    let merged = args.get("merged").map(std::fs::read).transpose()?;
    let chain_rules = match args.get("rules") {
        None => None,
        Some(s) => {
            let p: Vec<&str> = s.split(',').map(str::trim).collect();
            let [min, dim, scale, tpos, tneg] = p.as_slice() else {
                anyhow::bail!("--rules is MIN,CHUNK_DIM,SCALE,TPOS,TNEG");
            };
            Some(ChainRules {
                min_participants: min.parse()?,
                chunk_dim: dim.parse()?,
                value_scale_log2: scale.parse()?,
                threshold_pos: tpos.parse()?,
                threshold_neg: tneg.parse()?,
            })
        }
    };
    let report = replay(&Inputs {
        bundle: &bundle,
        deltas: &deltas,
        start_adapter: start.as_deref(),
        merged_adapter: merged.as_deref(),
        chain_rules,
    })?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.ok() {
        std::process::exit(1);
    }
    Ok(())
}
