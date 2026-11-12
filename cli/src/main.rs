//citrate/cli/src/main.rs

// PANIC-S1 G2: production code in this crate may not panic (tests excepted).
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

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

mod commands;
mod config;
mod utils;

use commands::{account, advanced, contract, devx, governance, model, network, wizard};

#[derive(Parser)]
#[command(
    name = "citrate",
    version,
    about = "Citrate v3 CLI - AI-native Layer-1 BlockDAG",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Config file path
    #[arg(short, long, global = true, env = "CITRATE_CONFIG")]
    config: Option<PathBuf>,

    /// RPC endpoint
    #[arg(short, long, global = true, env = "CITRATE_RPC")]
    rpc: Option<String>,

    /// Verbosity level
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Account management commands
    #[command(subcommand)]
    Account(account::AccountCommands),

    /// Model deployment and management
    #[command(subcommand)]
    Model(model::ModelCommands),

    /// Smart contract deployment and interaction
    #[command(subcommand)]
    Contract(contract::ContractCommands),

    /// Network and node operations
    #[command(subcommand)]
    Network(network::NetworkCommands),

    /// Governance parameter management
    #[command(subcommand)]
    Governance(governance::GovernanceCommands),

    /// Advanced network monitoring and debugging tools
    #[command(subcommand)]
    Advanced(advanced::AdvancedCommands),

    /// Interactive wizards for setup and deployment
    #[command(subcommand)]
    Wizard(wizard::WizardCommands),

    /// Developer tools: federation contract table + embedded Keyring address prediction
    #[command(subcommand)]
    Devx(devx::DevxCommands),

    /// Initialize configuration
    Init {
        /// Force overwrite existing config
        #[arg(short, long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = match cli.verbose {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_target(false)
        .init();

    // Load or create config
    let config = config::Config::load(cli.config.as_deref(), cli.rpc.as_deref())?;

    if let Err(err) = run(cli.command, &config).await {
        if let Some(hint) = commands::rpc_hint::connect_failure_hint(&err, &config.rpc_endpoint) {
            eprintln!("{}", hint.yellow());
        }
        return Err(err);
    }
    Ok(())
}

async fn run(command: Commands, config: &config::Config) -> Result<()> {
    match command {
        Commands::Account(cmd) => account::execute(cmd, config).await?,
        Commands::Model(cmd) => model::execute(cmd, config).await?,
        Commands::Contract(cmd) => contract::execute(cmd, config).await?,
        Commands::Network(cmd) => network::execute(cmd, config).await?,
        Commands::Governance(cmd) => governance::execute(cmd, config).await?,
        Commands::Advanced(cmd) => advanced::execute(cmd, config).await?,
        Commands::Wizard(cmd) => wizard::execute(cmd, config).await?,
        Commands::Devx(cmd) => devx::execute(cmd)?,
        Commands::Init { force } => {
            config::Config::init(force)?;
            println!("{}", "✓ Configuration initialized successfully".green());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::{CommandFactory, Parser};

    /// Issue #448: clap only detects short/long flag clashes (a subcommand flag reusing a
    /// global flag's `-c`/`-v`/`-r`, or two flags in one subcommand sharing `-a`) through its
    /// debug assertions. A debug build panics at startup on a clash; a release build silently
    /// routes the value to whichever argument wins. This walks the whole command tree so CI
    /// fails on any clash before it ships.
    #[test]
    fn cli_command_tree_has_no_flag_clashes() {
        Cli::command().debug_assert();
    }

    fn parses(args: &[&str]) -> bool {
        Cli::try_parse_from(args).is_ok()
    }

    /// The short flags removed for #448 are rejected rather than silently read as another
    /// argument; the long spellings still parse, and the global short flags keep their meaning
    /// after a subcommand.
    #[test]
    fn removed_short_flags_are_rejected_and_long_flags_parse() {
        let addr = "0x5fbdb2315678afecb367f032d99f2f9fc9a2f74b";
        for args in [
            vec!["citrate", "contract", "deploy", "c.bin", "-a", "[1]"],
            vec!["citrate", "contract", "call", addr, "f()", "-a", "[1]"],
            vec![
                "citrate",
                "contract",
                "verify",
                addr,
                "s.sol",
                "-c",
                "v0.8.26+commit.8a97fa7a",
            ],
            vec!["citrate", "model", "deploy", "m.onnx", "-v", "1.0"],
            vec!["citrate", "advanced", "monitor", "-c", "3"],
            vec!["citrate", "advanced", "benchmark", "-c", "3"],
            vec!["citrate", "advanced", "model-stats", "-r", "7d"],
        ] {
            // `-a`/`-c`/`-r` now hit the global flag or nothing; each of these lines either
            // fails to parse or lands the value on the global flag, never on the old field.
            match Cli::try_parse_from(&args) {
                Err(_) => {}
                Ok(cli) => assert!(
                    cli.config.is_some() || cli.rpc.is_some() || cli.verbose > 0,
                    "{args:?} parsed into the subcommand field"
                ),
            }
        }
        assert!(!parses(&[
            "citrate", "contract", "deploy", "c.bin", "-a", "[1]"
        ]));
        assert!(!parses(&[
            "citrate", "contract", "call", addr, "f()", "-a", "[1]"
        ]));

        assert!(parses(&[
            "citrate",
            "contract",
            "deploy",
            "c.bin",
            "--args",
            "[1]",
            "--account",
            "0xabc",
            "--value",
            "5",
        ]));
        assert!(parses(&[
            "citrate",
            "contract",
            "call",
            addr,
            "f()",
            "--args",
            "[1]",
            "--account",
            "0xabc",
            "--value",
            "5",
        ]));
        assert!(parses(&[
            "citrate",
            "contract",
            "verify",
            addr,
            "s.sol",
            "--compiler",
            "v0.8.26+commit.8a97fa7a",
            "-o",
        ]));
        assert!(parses(&[
            "citrate",
            "model",
            "deploy",
            "m.onnx",
            "--version",
            "1.0"
        ]));
        assert!(parses(&["citrate", "advanced", "monitor", "--count", "3"]));
        assert!(parses(&[
            "citrate",
            "advanced",
            "benchmark",
            "--concurrency",
            "3"
        ]));
        assert!(parses(&[
            "citrate",
            "advanced",
            "model-stats",
            "--range",
            "7d"
        ]));

        // `-c` after `contract verify` is the global --config, as everywhere else.
        let cli = Cli::try_parse_from([
            "citrate",
            "contract",
            "verify",
            addr,
            "--get",
            addr,
            "-c",
            "/tmp/c.json",
            "-vv",
        ])
        .expect("global -c and -v parse after a subcommand");
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/tmp/c.json"))
        );
        assert_eq!(cli.verbose, 2);
    }

    /// Every write command signs locally: it takes the keystore account and a
    /// password file, and never a key on the command line.
    #[test]
    fn write_commands_take_signer_options_and_no_key_flag() {
        let addr = "0xbc6a39c7d861a8f3d791f8a025051e7eac7043bb";
        let signer = [
            "--account",
            addr,
            "--password-file",
            "/tmp/pw",
            "--gas-limit",
            "60000",
        ];
        let with = |base: &[&str]| {
            let mut v: Vec<&str> = base.to_vec();
            v.extend_from_slice(&signer);
            v.push("--allow-foreign-chain");
            v.iter().map(|s| s.to_string()).collect::<Vec<String>>()
        };
        for base in [
            vec![
                "citrate", "account", "send", "--to", addr, "--amount", "0.001",
            ],
            vec![
                "citrate",
                "contract",
                "call",
                addr,
                "deposit()",
                "--value",
                "5",
            ],
            vec!["citrate", "contract", "deploy", "c.bin"],
            vec!["citrate", "governance", "set-admin", addr],
            vec!["citrate", "governance", "queue-param", "k", "v", "100"],
            vec!["citrate", "governance", "execute-param", "k"],
        ] {
            let args = with(&base);
            assert!(Cli::try_parse_from(&args).is_ok(), "{args:?} did not parse");
            let mut bad = base.iter().map(|s| s.to_string()).collect::<Vec<String>>();
            bad.extend(["--private-key".to_string(), "00".repeat(32)]);
            assert!(
                Cli::try_parse_from(&bad).is_err(),
                "{bad:?} took a key on argv"
            );
        }
    }
}
