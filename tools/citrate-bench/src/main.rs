//! citrate-bench CLI entry point.
//!
//! Phase 1 supports config validation and address-table/keystore
//! inspection. It does NOT submit any transactions. Running a benchmark
//! requires Phase 3 or later.
//!
//! Subcommands:
//!
//!   validate        Parse a bench.toml and run offline validation.
//!   show-addresses  Parse a 30_address_table.json and print a summary.
//!   verify-bundle   Recompute and compare the ceremony bundle sha256.
//!   sign-dry-run    Build and sign a single transfer against a target
//!                   address without broadcasting (used to smoke-test
//!                   keystore decryption end-to-end).

use clap::{Parser, Subcommand};
use std::path::PathBuf;

use citrate_bench::signers::{keystore, pool::SignerPool, Signer};
use citrate_bench::tx::legacy::LegacyTx;

#[derive(Parser)]
#[command(
    name = "citrate-bench",
    version,
    about = "Post-ceremony Citrate testnet benchmark (Phase 1: config/keystore/dry-run only)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse and offline-validate a bench.toml config file.
    Validate {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Parse a 30_address_table.json and print the contract list.
    ShowAddresses {
        #[arg(short, long)]
        table: PathBuf,
    },
    /// Verify a ceremony bundle sha256 matches an expected value.
    VerifyBundle {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        expected: String,
    },
    /// Decrypt a keystore file and build (but do not broadcast) a
    /// signed transfer. Proves keystore → signer → tx pipeline works.
    SignDryRun {
        #[arg(long)]
        keystore_file: PathBuf,
        /// Read passphrase from this file. Mutually exclusive with
        /// interactive prompt.
        #[arg(long, conflicts_with = "prompt")]
        passphrase_file: Option<PathBuf>,
        /// Prompt for passphrase on the TTY.
        #[arg(long)]
        prompt: bool,
        #[arg(long, default_value_t = 40204)]
        chain_id: u64,
        #[arg(long, default_value_t = 0)]
        nonce: u64,
        #[arg(long, default_value = "0x0000000000000000000000000000000000000001")]
        to: String,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> citrate_bench::Result<()> {
    match cli.command {
        Command::Validate { config } => cmd_validate(&config),
        Command::ShowAddresses { table } => cmd_show_addresses(&table),
        Command::VerifyBundle { bundle, expected } => cmd_verify_bundle(&bundle, &expected),
        Command::SignDryRun {
            keystore_file,
            passphrase_file,
            prompt,
            chain_id,
            nonce,
            to,
        } => cmd_sign_dry_run(&keystore_file, passphrase_file, prompt, chain_id, nonce, &to),
    }
}

fn cmd_validate(config: &std::path::Path) -> citrate_bench::Result<()> {
    let cfg = citrate_bench::config::load(config)?;
    cfg.validate_offline()?;
    println!("config OK");
    println!("  rpc_url       = {}", cfg.target.rpc_url);
    println!("  chain_id      = {}", cfg.target.chain_id);
    println!("  signer_count  = {}", cfg.signers.accounts.len());
    println!("  target_tps    = {}", cfg.run.target_tps);
    println!("  duration_secs = {}", cfg.run.duration_secs);
    println!("  workload_mix  = {} classes", cfg.workload.mix.len());
    for (class, share) in cfg.normalized_mix() {
        println!("    {class:20} {:.1}%", share * 100.0);
    }
    Ok(())
}

fn cmd_show_addresses(path: &std::path::Path) -> citrate_bench::Result<()> {
    let tbl = citrate_bench::address_table::load(path)?;
    println!("chain_id       = {}", tbl.chain_id);
    println!("contract_count = {}", tbl.contracts.len());
    for c in &tbl.contracts {
        println!("  {:40} {}", c.name, c.address);
    }
    Ok(())
}

fn cmd_verify_bundle(bundle: &std::path::Path, expected: &str) -> citrate_bench::Result<()> {
    citrate_bench::fingerprint::verify_bundle_sha256(bundle, expected)?;
    println!("bundle sha256 OK: {}", bundle.display());
    Ok(())
}

fn cmd_sign_dry_run(
    keystore_file: &std::path::Path,
    passphrase_file: Option<PathBuf>,
    prompt: bool,
    chain_id: u64,
    nonce: u64,
    to_hex: &str,
) -> citrate_bench::Result<()> {
    let source = match (passphrase_file, prompt) {
        (Some(p), _) => keystore::PassphraseSource::File(p),
        (None, true) => keystore::PassphraseSource::Prompt {
            prompt: format!("Passphrase for {}: ", keystore_file.display()),
        },
        (None, false) => {
            return Err(citrate_bench::Error::Config(
                "must supply --passphrase-file or --prompt".into(),
            ));
        }
    };
    let passphrase = keystore::read_passphrase(&source)?;
    let signer: Signer = keystore::load(keystore_file, &passphrase)?;
    println!("signer = {}", signer.address_hex());

    // Use the signer pool machinery even for a single signer, to
    // exercise the code path.
    let pool = SignerPool::new(vec![signer], vec![nonce], 8)?;
    let (signer, permit) = pool
        .try_acquire()
        .ok_or_else(|| citrate_bench::Error::Config("pool saturated (unexpected)".into()))?;

    let to = parse_eth_address(to_hex)?;
    let tx = LegacyTx {
        nonce: permit.nonce,
        gas_price: 1_000_000_000,
        gas_limit: 21_000,
        to: Some(to),
        value: 1,
        data: Vec::new(),
        chain_id,
    };
    let signed = tx.sign(&signer)?;
    println!("nonce  = {}", signed.nonce);
    println!("hash   = {}", signed.hash_hex());
    println!("raw    = {}", signed.raw_hex());
    println!("(not broadcast — Phase 1 dry-run)");
    Ok(())
}

fn parse_eth_address(s: &str) -> citrate_bench::Result<[u8; 20]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 40 {
        return Err(citrate_bench::Error::Config(format!(
            "address must be 40 hex chars (optional 0x prefix), got {}",
            stripped.len()
        )));
    }
    let bytes = hex::decode(stripped)?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}
