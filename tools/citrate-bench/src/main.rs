//! citrate-bench CLI entry point.
//!
//! Phase 2 supports config validation, address-table inspection,
//! ceremony-bundle verification, single-tx dry-run, and the new
//! `dry-run` subcommand that drives the runner at a target rate.
//!
//! It does NOT submit any transactions. Running a benchmark requires
//! Phase 3 or later.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};

use citrate_bench::rpc::RpcClient;
use citrate_bench::runner::{RunMode, RunOptions, Runner};
use citrate_bench::signers::{keystore, pool::SignerPool, Signer};
use citrate_bench::tracker::TrackerOptions;
use citrate_bench::tx::legacy::LegacyTx;
use citrate_bench::workload::transfer::SimpleTransfer;
use citrate_bench::workload::{WorkloadClass, WorkloadContext};

#[derive(Parser)]
#[command(
    name = "citrate-bench",
    version,
    about = "Post-ceremony Citrate testnet benchmark (Phase 2: dry-run only)"
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
    /// single signed transfer. Proves the keystore → signer → tx
    /// pipeline without running the full loop.
    SignDryRun {
        #[arg(long)]
        keystore_file: PathBuf,
        #[arg(long, conflicts_with = "prompt")]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        prompt: bool,
        #[arg(long, default_value_t = 40204)]
        chain_id: u64,
        #[arg(long, default_value_t = 0)]
        nonce: u64,
        #[arg(long, default_value = "0x0000000000000000000000000000000000000001")]
        to: String,
    },
    /// Run the full signing loop at a target rate with no broadcast.
    /// Exercises the rate limiter, signer pool, and workload pipeline
    /// end-to-end without touching the network.
    DryRun {
        #[arg(long)]
        keystore_dir: PathBuf,
        /// Comma-separated keystore account names.
        #[arg(long, value_delimiter = ',')]
        accounts: Vec<String>,
        #[arg(long, conflicts_with = "prompt")]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        prompt: bool,
        #[arg(long, default_value_t = 40204)]
        chain_id: u64,
        #[arg(long, default_value_t = 1000)]
        target_tps: u64,
        #[arg(long, default_value_t = 5)]
        duration_secs: u64,
        #[arg(long, default_value_t = 1)]
        gas_price_gwei: u64,
        #[arg(long, default_value_t = 100)]
        per_signer_max_inflight: usize,
        #[arg(long, default_value = "0x00000000000000000000000000000000000000de")]
        recipient: String,
        /// Starting nonce applied to every signer. Phase 3 will read
        /// this per-signer from the chain.
        #[arg(long, default_value_t = 0)]
        starting_nonce: u64,
    },
    /// Real benchmark: submit signed txs via eth_sendRawTransaction,
    /// track receipts, cross-check ground truth against on-chain
    /// nonce deltas.
    Bench {
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        keystore_dir: PathBuf,
        /// Comma-separated keystore account names.
        #[arg(long, value_delimiter = ',')]
        accounts: Vec<String>,
        #[arg(long, conflicts_with = "prompt")]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        prompt: bool,
        /// Expected chain id. If the RPC's `eth_chainId` disagrees,
        /// the bench refuses to run.
        #[arg(long)]
        expected_chain_id: u64,
        #[arg(long, default_value_t = 1000)]
        target_tps: u64,
        #[arg(long, default_value_t = 10)]
        duration_secs: u64,
        #[arg(long, default_value_t = 1)]
        gas_price_gwei: u64,
        #[arg(long, default_value_t = 100)]
        per_signer_max_inflight: usize,
        #[arg(long, default_value_t = 500)]
        concurrency_cap: usize,
        #[arg(long, default_value_t = 15)]
        cooldown_secs: u64,
        #[arg(long, default_value_t = 16)]
        tracker_workers: usize,
        #[arg(long, default_value_t = 60)]
        receipt_timeout_secs: u64,
        #[arg(long, default_value = "0x00000000000000000000000000000000000000de")]
        recipient: String,
        /// Minimum balance (in wei) each signer must hold at preflight.
        #[arg(long, default_value_t = 1_000_000_000_000_000u128)]
        funding_floor_wei: u128,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> citrate_bench::Result<()> {
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
        Command::DryRun {
            keystore_dir,
            accounts,
            passphrase_file,
            prompt,
            chain_id,
            target_tps,
            duration_secs,
            gas_price_gwei,
            per_signer_max_inflight,
            recipient,
            starting_nonce,
        } => {
            cmd_dry_run(DryRunArgs {
                keystore_dir,
                accounts,
                passphrase_file,
                prompt,
                chain_id,
                target_tps,
                duration_secs,
                gas_price_gwei,
                per_signer_max_inflight,
                recipient,
                starting_nonce,
            })
            .await
        }
        Command::Bench {
            rpc_url,
            keystore_dir,
            accounts,
            passphrase_file,
            prompt,
            expected_chain_id,
            target_tps,
            duration_secs,
            gas_price_gwei,
            per_signer_max_inflight,
            concurrency_cap,
            cooldown_secs,
            tracker_workers,
            receipt_timeout_secs,
            recipient,
            funding_floor_wei,
        } => {
            cmd_bench(BenchArgs {
                rpc_url,
                keystore_dir,
                accounts,
                passphrase_file,
                prompt,
                expected_chain_id,
                target_tps,
                duration_secs,
                gas_price_gwei,
                per_signer_max_inflight,
                concurrency_cap,
                cooldown_secs,
                tracker_workers,
                receipt_timeout_secs,
                recipient,
                funding_floor_wei,
            })
            .await
        }
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
    let source = passphrase_source(passphrase_file, prompt, keystore_file.display().to_string())?;
    let passphrase = keystore::read_passphrase(&source)?;
    let signer: Signer = keystore::load(keystore_file, &passphrase)?;
    println!("signer = {}", signer.address_hex());

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
    println!("(not broadcast — single-tx dry-run)");
    Ok(())
}

struct DryRunArgs {
    keystore_dir: PathBuf,
    accounts: Vec<String>,
    passphrase_file: Option<PathBuf>,
    prompt: bool,
    chain_id: u64,
    target_tps: u64,
    duration_secs: u64,
    gas_price_gwei: u64,
    per_signer_max_inflight: usize,
    recipient: String,
    starting_nonce: u64,
}

async fn cmd_dry_run(args: DryRunArgs) -> citrate_bench::Result<()> {
    if args.accounts.is_empty() {
        return Err(citrate_bench::Error::Config(
            "--accounts must list at least one keystore account".into(),
        ));
    }

    let source = passphrase_source(
        args.passphrase_file,
        args.prompt,
        format!("{}", args.keystore_dir.display()),
    )?;

    let signers = keystore::load_many(&args.keystore_dir, &args.accounts, &source)?;
    let starting_nonces = vec![args.starting_nonce; signers.len()];
    let pool = Arc::new(SignerPool::new(
        signers,
        starting_nonces,
        args.per_signer_max_inflight,
    )?);

    println!("citrate-bench dry-run");
    println!("  chain_id       = {}", args.chain_id);
    println!("  target_tps     = {}", args.target_tps);
    println!("  duration_secs  = {}", args.duration_secs);
    println!("  signers        = {}", pool.len());
    for i in 0..pool.len() {
        if let Some(s) = pool.signer(i) {
            println!("    [{i}] {}", s.address_hex());
        }
    }
    let gas_price_wei = (args.gas_price_gwei as u128) * 1_000_000_000u128;
    println!("  gas_price_wei  = {gas_price_wei}");
    println!();

    let recipient = parse_eth_address(&args.recipient)?;
    let workload_inner = SimpleTransfer {
        recipient,
        value_wei: 1,
        gas_limit: 21_000,
    };
    let workload: Arc<dyn WorkloadClass> = Arc::new(workload_inner);

    let ctx = Arc::new(WorkloadContext::for_dry_run(args.chain_id, gas_price_wei));
    let options = RunOptions::for_dry_run(args.duration_secs, args.target_tps);
    let runner = Runner::new(pool, ctx, workload, options)?;

    let result = runner.run(RunMode::DryRun).await?;
    result.print_summary();
    println!();
    println!("(not broadcast — Phase 2 dry-run)");
    Ok(())
}

struct BenchArgs {
    rpc_url: String,
    keystore_dir: PathBuf,
    accounts: Vec<String>,
    passphrase_file: Option<PathBuf>,
    prompt: bool,
    expected_chain_id: u64,
    target_tps: u64,
    duration_secs: u64,
    gas_price_gwei: u64,
    per_signer_max_inflight: usize,
    concurrency_cap: usize,
    cooldown_secs: u64,
    tracker_workers: usize,
    receipt_timeout_secs: u64,
    recipient: String,
    funding_floor_wei: u128,
}

async fn cmd_bench(args: BenchArgs) -> citrate_bench::Result<()> {
    if args.accounts.is_empty() {
        return Err(citrate_bench::Error::Config(
            "--accounts must list at least one keystore account".into(),
        ));
    }

    // Build the RPC client first so we can preflight the chain.
    let client = RpcClient::new(&args.rpc_url, Duration::from_secs(10))?;

    // Preflight 1: chain id matches.
    let actual_chain_id = client.chain_id().await?;
    if actual_chain_id != args.expected_chain_id {
        return Err(citrate_bench::Error::Config(format!(
            "chain id mismatch: RPC reports {} but --expected-chain-id is {}",
            actual_chain_id, args.expected_chain_id
        )));
    }
    println!("preflight ok: chain_id = {actual_chain_id}");

    // Preflight 2: load signers + check funding floor + fetch nonces.
    let source = passphrase_source(
        args.passphrase_file,
        args.prompt,
        format!("{}", args.keystore_dir.display()),
    )?;
    let signers = keystore::load_many(&args.keystore_dir, &args.accounts, &source)?;
    println!("loaded {} signer(s)", signers.len());

    let mut starting_nonces = Vec::with_capacity(signers.len());
    for signer in &signers {
        let addr = signer.address_hex();
        let balance = client.get_balance(&addr, "latest").await?;
        if balance < args.funding_floor_wei {
            return Err(citrate_bench::Error::Config(format!(
                "signer {} balance {} wei < funding floor {} wei",
                addr, balance, args.funding_floor_wei
            )));
        }
        let nonce = client.get_transaction_count(&addr, "latest").await?;
        println!("  {addr}  balance={balance} wei  starting_nonce={nonce}");
        starting_nonces.push(nonce);
    }

    // Build the pool with chain-queried starting nonces.
    let pool = Arc::new(SignerPool::new(
        signers,
        starting_nonces,
        args.per_signer_max_inflight,
    )?);

    // Workload + context.
    let recipient = parse_eth_address(&args.recipient)?;
    let workload_inner = SimpleTransfer {
        recipient,
        value_wei: 1,
        gas_limit: 21_000,
    };
    let workload: Arc<dyn WorkloadClass> = Arc::new(workload_inner);
    let gas_price_wei = (args.gas_price_gwei as u128) * 1_000_000_000u128;
    let ctx = Arc::new(WorkloadContext::for_dry_run(
        args.expected_chain_id,
        gas_price_wei,
    ));

    // Runner + mode.
    let options = RunOptions {
        duration_secs: args.duration_secs,
        target_tps: args.target_tps,
        sample_cap: 16,
    };
    let runner = Runner::new(pool, ctx, workload, options)?;

    let tracker_options = TrackerOptions {
        worker_count: args.tracker_workers,
        per_tx_timeout: Duration::from_secs(args.receipt_timeout_secs),
        ..TrackerOptions::default()
    };
    let mode = RunMode::Broadcast {
        client,
        tracker_options,
        concurrency_cap: args.concurrency_cap,
        cooldown_secs: args.cooldown_secs,
    };

    println!();
    println!("starting bench");
    println!("  rpc_url               = {}", args.rpc_url);
    println!("  target_tps            = {}", args.target_tps);
    println!("  duration_secs         = {}", args.duration_secs);
    println!("  concurrency_cap       = {}", args.concurrency_cap);
    println!("  tracker_workers       = {}", args.tracker_workers);
    println!("  receipt_timeout_secs  = {}", args.receipt_timeout_secs);
    println!();

    let result = runner.run(mode).await?;
    result.print_summary();

    if let Some(b) = &result.broadcast {
        if !b.ground_truth_match {
            return Err(citrate_bench::Error::Runner(format!(
                "ground truth mismatch: mined_nonce_delta={} included_total={}",
                b.mined_nonce_delta_total, b.tracker_stats.included
            )));
        }
    }
    Ok(())
}

fn passphrase_source(
    passphrase_file: Option<PathBuf>,
    prompt: bool,
    ctx: String,
) -> citrate_bench::Result<keystore::PassphraseSource> {
    match (passphrase_file, prompt) {
        (Some(p), _) => Ok(keystore::PassphraseSource::File(p)),
        (None, true) => Ok(keystore::PassphraseSource::Prompt {
            prompt: format!("Passphrase for {ctx}: "),
        }),
        (None, false) => Err(citrate_bench::Error::Config(
            "must supply --passphrase-file or --prompt".into(),
        )),
    }
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
