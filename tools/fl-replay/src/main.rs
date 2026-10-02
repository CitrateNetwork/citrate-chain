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
            anyhow::ensure!(p.len() == 5, "--rules is MIN,CHUNK_DIM,SCALE,TPOS,TNEG");
            Some(ChainRules {
                min_participants: p[0].parse()?,
                chunk_dim: p[1].parse()?,
                value_scale_log2: p[2].parse()?,
                threshold_pos: p[3].parse()?,
                threshold_neg: p[4].parse()?,
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
