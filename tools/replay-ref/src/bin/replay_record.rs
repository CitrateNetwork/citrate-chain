//! `replay-record <data-dir> <out> [options]`
//!
//! Dumps a node's chain database (opened read-only; a running node's directory
//! is fine) into a replay recording for `replay-diff`.
//!
//! The execution parameters are the network profile's, not the data dir's, so
//! they are flags: `--chain-id N` (default 40204), `--validator-activation H`,
//! `--pba-hardening H`, `--supply-hardening H`, `--storage-root-hardening H`,
//! and `--genesis-alloc FILE` (JSON object: "0x<address>" -> balance as a
//! decimal string).

use std::path::PathBuf;
use std::process::ExitCode;

use citrate_replay_ref::{record_data_dir, ReplayConfig};

fn usage() -> ExitCode {
    eprintln!(
        "usage: replay-record <data-dir> <out> [--chain-id N] [--validator-activation H] \
         [--pba-hardening H] [--supply-hardening H] [--storage-root-hardening H] \
         [--genesis-alloc FILE]"
    );
    ExitCode::from(2)
}

fn parse_alloc(path: &str) -> anyhow::Result<Vec<([u8; 20], [u8; 32])>> {
    let text = std::fs::read_to_string(path)?;
    let map: std::collections::BTreeMap<String, String> = serde_json::from_str(&text)?;
    let mut out = Vec::new();
    for (addr, bal) in map {
        let raw = hex::decode(addr.trim_start_matches("0x"))?;
        let addr: [u8; 20] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("address {addr} is not 20 bytes"))?;
        let bal = primitive_types::U256::from_dec_str(&bal)
            .map_err(|e| anyhow::anyhow!("balance {bal}: {e:?}"))?;
        let mut be = [0u8; 32];
        bal.to_big_endian(&mut be);
        out.push((addr, be));
    }
    Ok(out)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut positional = Vec::new();
    let mut cfg = ReplayConfig {
        chain_id: 40204,
        validator_activation_height: None,
        reward_policy: None,
        pba_hardening_height: None,
        supply_hardening_height: None,
        storage_root_hardening_height: None,
        genesis_alloc: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = args.get(i + 1);
        let height = || value.and_then(|v| v.parse::<u64>().ok());
        match flag {
            "--chain-id" => match height() {
                Some(v) => cfg.chain_id = v,
                None => return usage(),
            },
            "--validator-activation"
            | "--pba-hardening"
            | "--supply-hardening"
            | "--storage-root-hardening" => {
                let Some(h) = height() else {
                    return usage();
                };
                let slot = match flag {
                    "--validator-activation" => &mut cfg.validator_activation_height,
                    "--pba-hardening" => &mut cfg.pba_hardening_height,
                    "--supply-hardening" => &mut cfg.supply_hardening_height,
                    _ => &mut cfg.storage_root_hardening_height,
                };
                *slot = Some(h);
            }
            "--genesis-alloc" => match value.map(|v| parse_alloc(v)) {
                Some(Ok(a)) => cfg.genesis_alloc = a,
                Some(Err(e)) => {
                    eprintln!("replay-record: genesis alloc: {e:#}");
                    return ExitCode::from(2);
                }
                None => return usage(),
            },
            "-h" | "--help" => return usage(),
            _ => {
                positional.push(args[i].clone());
                i += 1;
                continue;
            }
        }
        if value.is_none() {
            return usage();
        }
        i += 2;
    }
    let [data_dir, out] = positional.as_slice() else {
        return usage();
    };
    let rec = match record_data_dir(&PathBuf::from(data_dir), cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("replay-record: {e:#}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = rec.write_to(&PathBuf::from(out)) {
        eprintln!("replay-record: {e:#}");
        return ExitCode::from(2);
    }
    println!(
        "recorded {} blocks, chain {}..={} (applied tip {} @ {}) to {}",
        rec.blocks.len(),
        rec.chain.first().map(|e| e.height).unwrap_or(0),
        rec.chain.last().map(|e| e.height).unwrap_or(0),
        citrate_replay_ref::reference::full_hash(&rec.applied_tip.0),
        rec.applied_tip.1,
        out
    );
    ExitCode::SUCCESS
}
