// node/src/commands/cli_tools.rs
// Adapts CLI tool commands as subcommands of the unified `citrate` binary.
// Delegates to the citrate_cli crate's command modules.

use anyhow::Result;
use clap::Subcommand;
use citrate_cli::commands::{account, advanced, contract, governance, model, network, wizard};
use citrate_cli::config::Config as CliConfig;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum CliToolCommands {
    /// Account management
    #[command(subcommand)]
    Account(account::AccountCommands),

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

    /// Initialize CLI configuration
    CliInit {
        /// Force overwrite existing config
        #[arg(short, long)]
        force: bool,
    },
}

pub async fn execute(
    cmd: CliToolCommands,
    config_path: Option<PathBuf>,
    rpc_override: Option<String>,
) -> Result<()> {
    match cmd {
        CliToolCommands::CliInit { force } => {
            CliConfig::init(force)?;
            println!("Configuration initialized successfully");
            Ok(())
        }
        other => {
            let config = CliConfig::load(
                config_path.as_deref(),
                rpc_override.as_deref(),
            )?;

            match other {
                CliToolCommands::Account(cmd) => account::execute(cmd, &config).await,
                CliToolCommands::Contract(cmd) => contract::execute(cmd, &config).await,
                CliToolCommands::Network(cmd) => network::execute(cmd, &config).await,
                CliToolCommands::Governance(cmd) => governance::execute(cmd, &config).await,
                CliToolCommands::Advanced(cmd) => advanced::execute(cmd, &config).await,
                CliToolCommands::Wizard(cmd) => wizard::execute(cmd, &config).await,
                CliToolCommands::CliInit { .. } => unreachable!(),
            }
        }
    }
}
