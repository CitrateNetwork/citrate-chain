//! `replay-diff <recording> [--mode selected-chain]`
//!
//! Replays a recording (from `replay-record`) through the reference path and
//! prints the first block whose state root differs from the node's. Exit code
//! 0: no divergence; 1: a divergence; 2: the recording could not be replayed.

use std::path::PathBuf;
use std::process::ExitCode;

use citrate_replay_ref::{replay, OrderingMode, Recording, SelectedChain};

fn usage() -> ExitCode {
    eprintln!("usage: replay-diff <recording> [--mode selected-chain]");
    ExitCode::from(2)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut path: Option<PathBuf> = None;
    let mut mode: Box<dyn OrderingMode> = Box::new(SelectedChain);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--mode" => match args.next().as_deref() {
                Some("selected-chain") => mode = Box::new(SelectedChain),
                Some(other) => {
                    eprintln!("unknown mode {other} (available: selected-chain)");
                    return ExitCode::from(2);
                }
                None => return usage(),
            },
            "-h" | "--help" => return usage(),
            _ if path.is_none() => path = Some(PathBuf::from(a)),
            _ => return usage(),
        }
    }
    let Some(path) = path else {
        return usage();
    };
    let rec = match Recording::read_from(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("replay-diff: {e:#}");
            return ExitCode::from(2);
        }
    };
    // The process-wide activation heights the executor reads, as the node ran.
    citrate_consensus::hardening::set_pba_hardening_height(rec.config.pba_hardening_height);
    citrate_execution::supply_hardening::set_supply_hardening_height(
        rec.config.supply_hardening_height,
    );
    citrate_execution::storage_root_hardening::set_storage_root_hardening_height(
        rec.config.storage_root_hardening_height,
    );
    println!(
        "recording: {} (from {}; {} blocks; chain {}..={}; applied tip {} @ {})",
        path.display(),
        rec.source,
        rec.blocks.len(),
        rec.chain.first().map(|e| e.height).unwrap_or(0),
        rec.chain.last().map(|e| e.height).unwrap_or(0),
        rec.applied_tip.0,
        rec.applied_tip.1,
    );
    println!(
        "config: chain id {}, validator activation {:?}, reward policy {}, hardening pba {:?} \
         supply {:?} storage-root {:?}, {} genesis account(s)",
        rec.config.chain_id,
        rec.config.validator_activation_height,
        if rec.config.reward_policy.is_some() {
            "fixed"
        } else {
            "none"
        },
        rec.config.pba_hardening_height,
        rec.config.supply_hardening_height,
        rec.config.storage_root_hardening_height,
        rec.config.genesis_alloc.len(),
    );
    match replay(&rec, mode.as_ref()).await {
        Ok(report) => {
            println!(
                "mode {}: {} chain block(s) matched ({} against a committed root) of {}",
                report.mode, report.matched, report.committed_compared, report.tip_height
            );
            match report.divergence {
                None => {
                    println!("no divergence");
                    ExitCode::SUCCESS
                }
                Some(d) => {
                    println!("FIRST DIVERGENCE: {d}");
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("replay-diff: {e:#}");
            ExitCode::from(2)
        }
    }
}
