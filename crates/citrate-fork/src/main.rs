//! `citrate-fork` — the Citrate-aware dry-run fork (HUP-S6.10). See the crate docs.
//!
//! ```text
//! citrate-fork precompiles [--chain-id N] [--block N] [--pba-hardening-height N|off] [--agent-precompiles-height N|off]
//! citrate-fork run --plan FILE|- [--rpc URL] [--block N] [--chain-id N]
//!                  [--pba-hardening-height N|off] [--agent-precompiles-height N|off] [--timestamp SECS]
//! citrate-fork --version
//! ```
//!
//! `run` prints one JSON report on stdout and exits 0 whenever the plan executed, including
//! when a step reverted (that is a finding, read it from the report). It exits 1 with the
//! reason on stderr when the plan could not run at all. Without `--rpc` the fork starts from
//! an empty state and `--block` is required.
use std::io::Read as _;
use std::process::ExitCode;

use citrate_fork::run::{pinned_hardening, ForkConfig, StateSource};
use citrate_fork::state::redacted_origin;
use citrate_fork::{ForkBlock, ForkError, ForkState, Plan, RpcState};

const USAGE: &str = "usage:
  citrate-fork precompiles [--chain-id N] [--block N] [--pba-hardening-height N|off] [--agent-precompiles-height N|off]
  citrate-fork run --plan FILE|- [--rpc URL] [--block N] [--chain-id N] [--pba-hardening-height N|off] [--agent-precompiles-height N|off] [--timestamp SECS]
  citrate-fork --version";

/// Chain 40204 (the default when no endpoint says otherwise).
const DEFAULT_CHAIN_ID: u64 = 40204;

#[derive(Default)]
struct Args {
    plan: Option<String>,
    rpc: Option<String>,
    block: Option<u64>,
    chain_id: Option<u64>,
    /// Some(None) = explicitly off.
    hardening: Option<Option<u64>>,
    /// Raw `--agent-precompiles-height` value (a height or `off`).
    agent_fork: Option<String>,
    timestamp: Option<u64>,
}

fn e(s: impl Into<String>) -> ForkError {
    ForkError(s.into())
}

fn num(v: Option<String>, flag: &str) -> Result<u64, ForkError> {
    let v = v.ok_or_else(|| e(format!("{flag} needs a value")))?;
    v.parse::<u64>()
        .map_err(|_| e(format!("{flag}: not a number: {v}")))
}

fn parse_args(rest: &[String]) -> Result<Args, ForkError> {
    let mut a = Args::default();
    let mut it = rest.iter().cloned();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--plan" => a.plan = Some(it.next().ok_or_else(|| e("--plan needs a value"))?),
            "--rpc" => a.rpc = Some(it.next().ok_or_else(|| e("--rpc needs a value"))?),
            "--block" => a.block = Some(num(it.next(), "--block")?),
            "--chain-id" => a.chain_id = Some(num(it.next(), "--chain-id")?),
            "--timestamp" => a.timestamp = Some(num(it.next(), "--timestamp")?),
            "--pba-hardening-height" => {
                let v = it
                    .next()
                    .ok_or_else(|| e("--pba-hardening-height needs a value"))?;
                a.hardening = Some(if v.eq_ignore_ascii_case("off") {
                    None
                } else {
                    Some(
                        v.parse::<u64>()
                            .map_err(|_| e(format!("--pba-hardening-height: {v}")))?,
                    )
                });
            }
            "--agent-precompiles-height" => {
                a.agent_fork = Some(
                    it.next()
                        .ok_or_else(|| e("--agent-precompiles-height needs a value"))?,
                );
            }
            other => return Err(e(format!("unknown argument: {other}"))),
        }
    }
    Ok(a)
}

/// The hardening height and where it came from. An override is refused on a release network
/// (the node refuses one that disagrees with its pin, so a dry run under it would mislead).
fn hardening(chain_id: u64, over: Option<Option<u64>>) -> Result<(Option<u64>, String), ForkError> {
    let pinned = pinned_hardening(chain_id);
    let release = citrate_consensus::hardening::is_release_network(chain_id);
    match over {
        Some(h) if release && h != pinned => Err(e(format!(
            "chain {chain_id} is a release network; its hardening height is pinned ({pinned:?}) and cannot be overridden"
        ))),
        Some(h) => Ok((h, "override".into())),
        None if release => Ok((pinned, "release pin".into())),
        None => Ok((None, "unset".into())),
    }
}

/// The agent precompile fork height (HUP-S7.2) and where it came from, resolved with the
/// node's own rule (`agent_fork::resolve`): on a release network the release pin wins and a
/// differing height is refused; elsewhere the flag, then `CITRATE_AGENT_PRECOMPILES_HEIGHT`,
/// then unset.
fn agent_fork(chain_id: u64, over: Option<&str>) -> Result<(Option<u64>, String), ForkError> {
    use citrate_execution::agent_fork::{pinned_for, resolve, resolve_for_chain};
    let r = match over {
        Some(raw) => resolve(pinned_for(chain_id), Some(raw), None),
        None => resolve_for_chain(chain_id, None),
    };
    let (h, source) = r.map_err(e)?;
    Ok((h, source.to_string()))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn cmd_precompiles(a: Args) -> Result<String, ForkError> {
    let chain_id = a.chain_id.unwrap_or(DEFAULT_CHAIN_ID);
    let (h, source) = hardening(chain_id, a.hardening)?;
    let hardened = match a.block {
        Some(b) => citrate_execution::activation::active_at(h, b),
        None => false,
    };
    let (ah, asrc) = agent_fork(chain_id, a.agent_fork.as_deref())?;
    let agent_active = match a.block {
        Some(b) => citrate_execution::agent_fork::active_at(ah, b),
        None => false,
    };
    serde_json::to_string_pretty(&serde_json::json!({
        "engine": citrate_fork::ENGINE,
        "engineVersion": env!("CARGO_PKG_VERSION"),
        "chainId": chain_id,
        "block": a.block,
        "pbaHardened": hardened,
        "pbaHardeningHeight": h,
        "pbaHardeningSource": source,
        "agentPrecompilesActive": agent_active,
        "agentPrecompilesHeight": ah,
        "agentPrecompilesSource": asrc,
        "precompiles": citrate_fork::table::table(hardened, agent_active),
    }))
    .map_err(|err| e(err.to_string()))
}

fn cmd_run(a: Args) -> Result<String, ForkError> {
    let plan_arg = a.plan.clone().ok_or_else(|| e("run needs --plan FILE|-"))?;
    let text = if plan_arg == "-" {
        let mut s = String::new();
        std::io::stdin()
            .take(4 * 1024 * 1024)
            .read_to_string(&mut s)
            .map_err(|err| e(format!("reading the plan from stdin: {err}")))?;
        s
    } else {
        std::fs::read_to_string(&plan_arg)
            .map_err(|err| e(format!("reading the plan {plan_arg}: {err}")))?
    };
    let plan = Plan::from_json(&text)?;
    let (state, chain_id, mut block, source) = match &a.rpc {
        Some(url) => {
            let (st, chain_id, block) = RpcState::connect(url, a.block)?;
            if let Some(want) = a.chain_id {
                if want != chain_id {
                    return Err(e(format!(
                        "the endpoint serves chain {chain_id}, not {want}"
                    )));
                }
            }
            (
                ForkState::Rpc(st),
                chain_id,
                block,
                StateSource::Rpc {
                    origin: redacted_origin(url),
                },
            )
        }
        None => {
            let number = a
                .block
                .ok_or_else(|| e("without --rpc, --block is required"))?;
            (
                ForkState::Empty,
                a.chain_id.unwrap_or(DEFAULT_CHAIN_ID),
                ForkBlock {
                    number,
                    timestamp: now_secs(),
                    hash: None,
                    coinbase: Default::default(),
                },
                StateSource::Empty,
            )
        }
    };
    if let Some(t) = a.timestamp {
        block.timestamp = t;
    }
    let (h, hsrc) = hardening(chain_id, a.hardening)?;
    let (ah, asrc) = agent_fork(chain_id, a.agent_fork.as_deref())?;
    let cfg = ForkConfig {
        chain_id,
        block,
        hardening_height: h,
        hardening_source: hsrc,
        agent_fork_height: ah,
        agent_fork_source: asrc,
        source,
    };
    let report = citrate_fork::run(&plan, state, &cfg)?;
    serde_json::to_string_pretty(&report).map_err(|err| e(err.to_string()))
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let out = match cmd.as_str() {
        "--version" | "-V" => Ok(format!("citrate-fork {}", env!("CARGO_PKG_VERSION"))),
        "--help" | "-h" => Ok(USAGE.to_string()),
        "precompiles" => parse_args(&argv[1..]).and_then(cmd_precompiles),
        "run" => parse_args(&argv[1..]).and_then(cmd_run),
        other => Err(e(format!("unknown command: {other}\n{USAGE}"))),
    };
    match out {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("citrate-fork: {err}");
            ExitCode::from(1)
        }
    }
}
