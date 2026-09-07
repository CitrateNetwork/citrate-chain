// node/src/commands/wallet.rs
// Adapts wallet CLI functionality as a subcommand of the unified `citrate` binary.

use anyhow::{Context, Result};
use citrate_execution::types::Address;
use citrate_wallet::{Wallet, WalletConfig};
use clap::Subcommand;
use colored::*;
use console::Term;
use dialoguer::{Input, Password, Select};
use indicatif::{ProgressBar, ProgressStyle};
use primitive_types::U256;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Subcommand)]
pub enum WalletCommands {
    /// Create a new account
    New {
        /// Account alias
        #[arg(short, long)]
        alias: Option<String>,
    },

    /// Import account from private key.
    ///
    /// RM-K / WP-K1.6 (CHAIN-B-E003): secrets MUST NOT be passed on the
    /// command line in normal operation — argv is visible in the OS process
    /// list (`ps`), in shell history, and in command-audit logs. The default
    /// is to read the key from stdin with no echo (`--key-stdin`) or from a
    /// file (`--key-file`). `--insecure-key-from-arg` is the legacy opt-in
    /// that puts the key on argv and emits a loud warning; it exists only for
    /// scripts that have not yet migrated. This mirrors the hardened
    /// `citrate account import` path.
    Import {
        /// Read the 32-byte hex private key from stdin (no echo).
        /// This is the recommended path for interactive imports.
        #[arg(long, conflicts_with_all = ["key_file", "insecure_key_from_arg"])]
        key_stdin: bool,

        /// Read the 32-byte hex private key from a file. The file is read
        /// once and not modified; operators should `shred` or delete it
        /// after import.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["key_stdin", "insecure_key_from_arg"])]
        key_file: Option<PathBuf>,

        /// LEGACY: pass the private key on the command line. Visible in
        /// argv, shell history, and process listings. Emits a warning.
        /// Prefer --key-stdin or --key-file.
        #[arg(long, value_name = "HEX", conflicts_with_all = ["key_stdin", "key_file"])]
        insecure_key_from_arg: Option<String>,

        /// Account alias
        #[arg(short, long)]
        alias: Option<String>,
    },

    /// List all accounts
    List,

    /// Show account balance
    Balance {
        /// Account index or address
        account: Option<String>,
    },

    /// Send transaction
    Send {
        /// From account index
        #[arg(short, long)]
        from: usize,

        /// To address
        #[arg(short, long)]
        to: String,

        /// Amount in SALT
        #[arg(short, long)]
        amount: String,

        /// Gas price in gwei
        #[arg(short, long)]
        gas_price: Option<u64>,

        /// Gas limit
        #[arg(short, long)]
        gas_limit: Option<u64>,
    },

    /// Export private key
    Export {
        /// Account index
        index: usize,
    },

    /// Show wallet info
    Info,

    /// Interactive mode
    Interactive,
}

pub async fn execute(
    cmd: WalletCommands,
    keystore: Option<PathBuf>,
    rpc: String,
    chain_id: u64,
) -> Result<()> {
    let mut config = WalletConfig::default();
    if let Some(keystore) = keystore {
        config.keystore_path = keystore;
    }
    config.rpc_url = rpc;
    config.chain_id = chain_id;

    let mut wallet = Wallet::new(config)?;

    match cmd {
        WalletCommands::New { alias } => create_account(&mut wallet, alias).await,
        WalletCommands::Import {
            key_stdin,
            key_file,
            insecure_key_from_arg,
            alias,
        } => {
            let key = read_import_key(key_stdin, key_file, insecure_key_from_arg)?;
            import_account(&mut wallet, key, alias).await
        }
        WalletCommands::List => list_accounts(&mut wallet).await,
        WalletCommands::Balance { account } => show_balance(&mut wallet, account).await,
        WalletCommands::Send {
            from,
            to,
            amount,
            gas_price: _,
            gas_limit: _,
        } => send_transaction(&mut wallet, from, &to, &amount, None, None).await,
        WalletCommands::Export { index } => export_key(&mut wallet, index).await,
        WalletCommands::Info => show_info(&wallet).await,
        WalletCommands::Interactive => interactive_mode(&mut wallet).await,
    }
}

async fn create_account(wallet: &mut Wallet, alias: Option<String>) -> Result<()> {
    println!("{}", "Creating new account...".bright_cyan());

    let password = Password::new()
        .with_prompt("Enter password for new account")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;

    let account = wallet.create_account(&password, alias)?;

    println!("{}", "Account created successfully!".green());
    println!("  Index:   {}", account.index);
    println!("  Address: 0x{}", hex::encode(account.address.0));
    println!(
        "  Public:  0x{}",
        hex::encode(account.public_key.as_bytes())
    );

    if let Some(alias) = &account.alias {
        println!("  Alias:   {}", alias);
    }

    Ok(())
}

/// RM-K / WP-K1.6 (CHAIN-B-E003): resolve the private key from a
/// non-argv source. Mirrors `cli/src/commands/account.rs::read_import_key`.
/// `--key-stdin` prompts with no echo, `--key-file` reads from disk, and the
/// legacy `--insecure-key-from-arg` puts it on argv with a loud warning.
fn read_import_key(
    key_stdin: bool,
    key_file: Option<PathBuf>,
    insecure_key_from_arg: Option<String>,
) -> Result<String> {
    let raw = match (key_stdin, key_file, insecure_key_from_arg) {
        (true, _, _) => Password::new()
            .with_prompt("Paste 32-byte hex private key (no echo)")
            .interact()
            .context("Failed to read private key from stdin")?,
        (_, Some(path), _) => std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read key file {}", path.display()))?
            .trim()
            .to_string(),
        (_, _, Some(hex_arg)) => {
            // Loud warning: argv is visible in the OS.
            eprintln!(
                "{}",
                "WARNING: --insecure-key-from-arg passes the private key on the \
                 command line. argv is visible in `ps`, shell history, and audit \
                 logs. Use --key-stdin or --key-file in production."
                    .yellow()
                    .bold()
            );
            hex_arg
        }
        (false, None, None) => anyhow::bail!(
            "Provide one of --key-stdin (recommended), --key-file <PATH>, or \
             --insecure-key-from-arg <HEX> (legacy)."
        ),
    };
    Ok(raw.trim().to_string())
}

async fn import_account(
    wallet: &mut Wallet,
    private_key: String,
    alias: Option<String>,
) -> Result<()> {
    println!("{}", "Importing account...".bright_cyan());

    let password = Password::new()
        .with_prompt("Enter password to encrypt key")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;

    let account = wallet.import_account(&private_key, &password, alias)?;

    println!("{}", "Account imported successfully!".green());
    println!("  Index:   {}", account.index);
    println!("  Address: 0x{}", hex::encode(account.address.0));

    if let Some(alias) = &account.alias {
        println!("  Alias:   {}", alias);
    }

    Ok(())
}

async fn list_accounts(wallet: &mut Wallet) -> Result<()> {
    wallet.refresh_accounts()?;

    if wallet.list_accounts().is_empty() {
        println!(
            "{}",
            "No accounts found. Create one with 'citrate wallet new'".yellow()
        );
        return Ok(());
    }

    let unlocked = if let Ok(password) = Password::new()
        .with_prompt("Enter password to view balances (or press Enter to skip)")
        .allow_empty_password(true)
        .interact()
    {
        if !password.is_empty() {
            wallet.unlock(&password).is_ok()
        } else {
            false
        }
    } else {
        false
    };

    if unlocked {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
        pb.set_message("Fetching balances...");
        pb.enable_steady_tick(Duration::from_millis(100));
        wallet.update_balances().await?;
        pb.finish_and_clear();
    }

    let accounts = wallet.list_accounts();

    println!("{}", "Accounts:".bright_cyan());
    println!("{}", "-".repeat(80));

    for account in accounts {
        println!(
            "  [{}] {}",
            account.index,
            account
                .alias
                .as_ref()
                .unwrap_or(&"<no alias>".to_string())
                .bright_yellow()
        );
        println!("      Address: 0x{}", hex::encode(account.address.0));

        if unlocked {
            let balance_latt = format_latt(account.balance);
            println!("      Balance: {} SALT", balance_latt.bright_green());
            println!("      Nonce:   {}", account.nonce);
        }

        println!();
    }

    Ok(())
}

async fn show_balance(wallet: &mut Wallet, account: Option<String>) -> Result<()> {
    if let Some(acc) = account {
        if let Ok(index) = acc.parse::<usize>() {
            wallet.refresh_accounts()?;
            let account = wallet
                .get_account(index)
                .ok_or_else(|| anyhow::anyhow!("Account not found"))?
                .clone();

            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
            pb.set_message("Fetching balance...");
            pb.enable_steady_tick(Duration::from_millis(100));

            let balance = wallet.rpc_client().get_balance(&account.address).await?;
            let nonce = wallet.rpc_client().get_nonce(&account.address).await?;

            pb.finish_and_clear();

            println!("{}", "Account Balance:".bright_cyan());
            println!("  Address: 0x{}", hex::encode(account.address.0));

            if let Some(alias) = &account.alias {
                println!("  Alias:   {}", alias);
            }

            println!("  Balance: {} SALT", format_latt(balance).bright_green());
            println!("  Nonce:   {}", nonce);
        } else if let Some(stripped) = acc.strip_prefix("0x") {
            let addr_bytes = hex::decode(stripped)?;
            if addr_bytes.len() != 20 {
                anyhow::bail!("Invalid address length");
            }
            let mut addr_array = [0u8; 20];
            addr_array.copy_from_slice(&addr_bytes);
            let address = Address(addr_array);

            wallet.refresh_accounts()?;
            let account_info = wallet.get_account_by_address(&address);

            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
            pb.set_message("Fetching balance...");
            pb.enable_steady_tick(Duration::from_millis(100));

            let balance = wallet.rpc_client().get_balance(&address).await?;
            let nonce = wallet.rpc_client().get_nonce(&address).await?;

            pb.finish_and_clear();

            println!("{}", "Address Balance:".bright_cyan());
            println!("  Address: 0x{}", hex::encode(address.0));

            if let Some(account) = account_info {
                if let Some(alias) = &account.alias {
                    println!("  Alias:   {}", alias);
                }
            }

            println!("  Balance: {} SALT", format_latt(balance).bright_green());
            println!("  Nonce:   {}", nonce);
        } else {
            anyhow::bail!("Invalid account specifier");
        }
    } else {
        list_accounts(wallet).await?;
    }

    Ok(())
}

async fn send_transaction(
    wallet: &mut Wallet,
    from: usize,
    to: &str,
    amount: &str,
    _gas_price: Option<u64>,
    _gas_limit: Option<u64>,
) -> Result<()> {
    let to_bytes = hex::decode(to.trim_start_matches("0x"))?;
    if to_bytes.len() != 20 {
        anyhow::bail!("Invalid recipient address");
    }
    let mut to_array = [0u8; 20];
    to_array.copy_from_slice(&to_bytes);
    let to_address = Address(to_array);

    let amount_latt = amount.parse::<f64>()?;
    let amount_wei = latt_to_wei(amount_latt);

    let password = Password::new()
        .with_prompt("Enter password to unlock wallet")
        .interact()?;

    wallet.unlock(&password)?;
    wallet.update_balances().await?;

    println!("{}", "Transaction Details:".bright_cyan());
    println!("  From:   Account #{}", from);
    println!("  To:     0x{}", hex::encode(to_address.0));
    println!("  Amount: {} SALT", amount);

    let confirm = dialoguer::Confirm::new()
        .with_prompt("Send transaction?")
        .default(false)
        .interact()?;

    if !confirm {
        println!("{}", "Transaction cancelled".yellow());
        return Ok(());
    }

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.set_message("Sending transaction...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let tx_hash = wallet.transfer(from, to_address, amount_wei).await?;

    pb.finish_and_clear();

    println!("{}", "Transaction sent successfully!".green());
    println!("  Hash: 0x{}", hex::encode(tx_hash.as_bytes()));

    // Wait for receipt
    let mut receipt = None;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Ok(Some(r)) = wallet.get_transaction_receipt(&tx_hash).await {
            receipt = Some(r);
            break;
        }
    }

    if let Some(receipt) = receipt {
        let status = receipt["status"]
            .as_str()
            .map(|s| s == "0x1")
            .unwrap_or(false);

        if status {
            println!("{}", "Transaction confirmed!".green());
        } else {
            println!("{}", "Transaction failed!".red());
        }

        if let Some(block) = receipt["blockNumber"].as_str() {
            let block_num = u64::from_str_radix(block.trim_start_matches("0x"), 16)?;
            println!("  Block: #{}", block_num);
        }
    } else {
        println!("{}", "Transaction pending (check later)".yellow());
    }

    Ok(())
}

async fn export_key(wallet: &mut Wallet, index: usize) -> Result<()> {
    println!("{}", "WARNING: Never share your private key!".bright_red());

    let password = Password::new()
        .with_prompt("Enter password to unlock wallet")
        .interact()?;

    wallet.unlock(&password)?;

    let private_key = wallet.export_private_key(index)?;

    println!("{}", "Private key:".bright_cyan());
    println!("  {}", private_key.bright_yellow());

    Ok(())
}

async fn show_info(wallet: &Wallet) -> Result<()> {
    let config = wallet.config();

    println!("{}", "Wallet Information:".bright_cyan());
    println!("  Keystore: {:?}", config.keystore_path);
    println!("  RPC URL:  {}", config.rpc_url);
    println!("  Chain ID: {}", config.chain_id);

    if let Ok(block_number) = wallet.rpc_client().get_block_number().await {
        println!("  Block:    #{}", block_number);
    }

    if let Ok(gas_price) = wallet.rpc_client().get_gas_price().await {
        println!("  Gas:      {} gwei", gas_price / 1_000_000_000);
    }

    Ok(())
}

async fn interactive_mode(wallet: &mut Wallet) -> Result<()> {
    let term = Term::stdout();

    loop {
        term.clear_screen()?;

        println!(
            "{}",
            "Citrate Wallet - Interactive Mode".bright_cyan().bold()
        );
        println!("{}", "-".repeat(50));

        let options = vec![
            "Create new account",
            "Import account",
            "List accounts",
            "Check balance",
            "Send transaction",
            "Export private key",
            "Wallet info",
            "Exit",
        ];

        let selection = Select::new()
            .with_prompt("Select an option")
            .items(&options)
            .default(0)
            .interact()?;

        match selection {
            0 => {
                let alias = Input::<String>::new()
                    .with_prompt("Account alias (optional)")
                    .allow_empty(true)
                    .interact()?;

                let alias = if alias.is_empty() { None } else { Some(alias) };
                create_account(wallet, alias).await?;
            }
            1 => {
                // Interactive import reads the key from stdin with no echo
                // (never from argv) — see CHAIN-B-E003 / read_import_key.
                let key = read_import_key(true, None, None)?;
                import_account(wallet, key, None).await?;
            }
            2 => {
                list_accounts(wallet).await?;
            }
            3 => {
                let account = Input::<String>::new()
                    .with_prompt("Account index or address (or Enter for all)")
                    .allow_empty(true)
                    .interact()?;

                let account = if account.is_empty() {
                    None
                } else {
                    Some(account)
                };
                show_balance(wallet, account).await?;
            }
            4 => {
                let from = Input::<usize>::new()
                    .with_prompt("From account index")
                    .interact()?;

                let to = Input::<String>::new()
                    .with_prompt("To address (0x...)")
                    .interact()?;

                let amount = Input::<String>::new()
                    .with_prompt("Amount in SALT")
                    .interact()?;

                send_transaction(wallet, from, &to, &amount, None, None).await?;
            }
            5 => {
                let index = Input::<usize>::new()
                    .with_prompt("Account index")
                    .interact()?;

                export_key(wallet, index).await?;
            }
            6 => {
                show_info(wallet).await?;
            }
            7 => {
                println!("{}", "Goodbye!".bright_green());
                break;
            }
            _ => {}
        }

        if selection != 7 {
            println!();
            println!("Press Enter to continue...");
            term.read_line()?;
        }
    }

    Ok(())
}

fn format_latt(wei: U256) -> String {
    let decimals = U256::from(10).pow(U256::from(18));
    let whole = wei / decimals;
    let fraction = wei % decimals;

    let fraction_str = format!("{:018}", fraction);
    let fraction_trimmed = if fraction_str.len() >= 6 {
        fraction_str[..6].trim_end_matches('0')
    } else {
        fraction_str.trim_end_matches('0')
    };

    if fraction_trimmed.is_empty() {
        format!("{}", whole)
    } else {
        format!("{}.{}", whole, fraction_trimmed)
    }
}

fn latt_to_wei(latt: f64) -> U256 {
    let wei_per_latt = 1_000_000_000_000_000_000u128;
    let wei = (latt * wei_per_latt as f64) as u128;
    U256::from(wei)
}

#[cfg(test)]
mod tests_e003 {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    #[command(name = "test-wallet")]
    struct TestCli {
        #[command(subcommand)]
        cmd: WalletCommands,
    }

    #[test]
    fn test_e003_import_requires_explicit_key_source() {
        // No key source provided → the runtime must reject with a message
        // naming the secure alternatives.
        let result = read_import_key(false, None, None);
        assert!(
            result.is_err(),
            "E003: import without --key-stdin / --key-file / \
             --insecure-key-from-arg must fail at runtime"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("--key-stdin") && msg.contains("--key-file"),
            "E003: error must name the secure alternatives, got: {msg}"
        );
    }

    #[test]
    fn test_e003_import_key_file_path() {
        let tmp = std::env::temp_dir()
            .join(format!("e003_wallet_import_{}.key", std::process::id()));
        let hex_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        std::fs::write(&tmp, format!("0x{hex_key}\n")).expect("write test key file");

        let read = read_import_key(false, Some(tmp.clone()), None).expect("read key file");
        assert_eq!(read, format!("0x{hex_key}"));
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_e003_argparse_rejects_legacy_short_flags() {
        // Legacy `wallet import --key <hex>` MUST fail to parse — that shape
        // put the private key on argv (CHAIN-B-E003).
        let result = TestCli::try_parse_from(["test-wallet", "import", "--key", "abcd"]);
        assert!(
            result.is_err(),
            "E003: legacy `--key` flag must no longer parse"
        );
    }

    #[test]
    fn test_e003_argparse_accepts_stdin_flag() {
        let result = TestCli::try_parse_from(["test-wallet", "import", "--key-stdin"]);
        assert!(
            result.is_ok(),
            "E003: `--key-stdin` is the recommended secure path and must parse"
        );
    }

    #[test]
    fn test_e003_argparse_accepts_key_file_flag() {
        let result =
            TestCli::try_parse_from(["test-wallet", "import", "--key-file", "/tmp/k.key"]);
        assert!(
            result.is_ok(),
            "E003: `--key-file` must parse"
        );
    }

    #[test]
    fn test_e003_argparse_stdin_conflicts_with_insecure_arg() {
        let result = TestCli::try_parse_from([
            "test-wallet",
            "import",
            "--key-stdin",
            "--insecure-key-from-arg",
            "abcd",
        ]);
        assert!(
            result.is_err(),
            "E003: --key-stdin and --insecure-key-from-arg must conflict"
        );
    }
}
