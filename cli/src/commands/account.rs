//citrate/cli/src/commands/account.rs
//
// Ed25519 account management - aligned with wallet for account portability

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use sha3::{Digest, Keccak256};
use std::fs;
use std::path::PathBuf;

use crate::config::Config;
use crate::utils::keystore;
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub enum AccountCommands {
    /// Create a new account
    Create {
        /// DEPRECATED (PBA-L4-009): password on argv is visible in `ps`,
        /// shell history and audit logs. Prefer --password-file or the prompt.
        #[arg(short, long, conflicts_with = "password_file")]
        password: Option<String>,

        /// Read the keystore password from this file (first line).
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,

        /// Output path for the keystore file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// List all accounts
    List,

    /// Get account balance
    Balance {
        /// Account address
        address: String,
    },

    /// Import an account from private key.
    ///
    /// RM-K / WP-K1.6: secrets MUST NOT be passed on the command line
    /// in normal operation — argv is visible in the OS process list,
    /// in shell history, and in command-audit logs. Default is to
    /// prompt securely on stdin (no echo). `--key-file` reads from a
    /// file (which the operator should `shred` or delete after).
    /// `--insecure-key-from-arg` is the legacy opt-in that puts the
    /// key on argv and emits a loud warning; it exists only for
    /// scripts that have not yet migrated.
    Import {
        /// Read the 32-byte hex private key from stdin (no echo).
        /// This is the recommended path for interactive imports.
        #[arg(long, conflicts_with_all = ["key_file", "insecure_key_from_arg"])]
        key_stdin: bool,

        /// Read the 32-byte hex private key from a file. The file is
        /// read once and not modified; operators should `shred` or
        /// delete it after import.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["key_stdin", "insecure_key_from_arg"])]
        key_file: Option<PathBuf>,

        /// LEGACY: pass the private key on the command line. Visible
        /// in argv, shell history, and process listings. Emits a
        /// warning. Prefer --key-stdin or --key-file.
        #[arg(long, value_name = "HEX", conflicts_with_all = ["key_stdin", "key_file"])]
        insecure_key_from_arg: Option<String>,

        /// DEPRECATED (PBA-L4-009): password on argv is visible in `ps`,
        /// shell history and audit logs. If omitted, prompts on stdin.
        #[arg(short, long, conflicts_with = "password_file")]
        password: Option<String>,

        /// Read the keystore password from this file (first line).
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
    },

    /// Export account private key.
    ///
    /// RM-K / WP-K1.6: prints the secret to stdout, which can be
    /// captured in shell pipes, terminal scrollback, or screen
    /// recordings. Use `--out <path>` to write to a file with 0600
    /// perms instead. Add `--confirm-stdout` to keep the legacy
    /// stdout behavior; without it the export refuses to print.
    Export {
        /// Account address
        address: String,

        /// Write the exported key to this file (mode 0600 on Unix).
        /// Recommended: pipe into `shred` or store on an offline
        /// volume.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,

        /// Explicit acknowledgement that the key will be printed to
        /// stdout. Without this flag, stdout export is refused.
        #[arg(long)]
        confirm_stdout: bool,

        /// DEPRECATED (PBA-L4-009): password on argv is visible in `ps`,
        /// shell history and audit logs. If omitted, prompts on stdin.
        #[arg(short, long, conflicts_with = "password_file")]
        password: Option<String>,

        /// Read the keystore password from this file (first line).
        #[arg(long, value_name = "PATH")]
        password_file: Option<PathBuf>,
    },
}

pub async fn execute(cmd: AccountCommands, config: &Config) -> Result<()> {
    match cmd {
        AccountCommands::Create {
            password,
            password_file,
            output,
        } => {
            let password =
                resolve_password(password, password_file, "Enter password for keystore: ")?;
            create_account(config, password, output)?;
        }
        AccountCommands::List => {
            list_accounts(config)?;
        }
        AccountCommands::Balance { address } => {
            get_balance(config, &address).await?;
        }
        AccountCommands::Import {
            key_stdin,
            key_file,
            insecure_key_from_arg,
            password,
            password_file,
        } => {
            let key_hex = read_import_key(key_stdin, key_file, insecure_key_from_arg)?;
            let password =
                resolve_password(password, password_file, "Enter password for keystore: ")?;
            import_account(config, &key_hex, password)?;
        }
        AccountCommands::Export {
            address,
            out,
            confirm_stdout,
            password,
            password_file,
        } => {
            let password = resolve_password(password, password_file, "Enter keystore password: ")?;
            export_account(config, &address, out, confirm_stdout, password)?;
        }
    }
    Ok(())
}

fn create_account(
    config: &Config,
    password: Zeroizing<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    // Generate new ed25519 keypair from random bytes
    let mut rng = rand::thread_rng();
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    // Derive address from public key
    let address = derive_address(verifying_key.as_bytes());

    // Save to keystore
    let keystore_path = output.unwrap_or_else(|| {
        config
            .keystore_path
            .join(format!("{}.json", hex::encode(address)))
    });

    keystore::save_key(&signing_key, &password, &keystore_path)?;

    println!("{}", "✓ Account created successfully".green());
    println!("Address: {}", format!("0x{}", hex::encode(address)).cyan());
    println!(
        "Public Key: {}",
        format!("0x{}", hex::encode(verifying_key.as_bytes())).dimmed()
    );
    println!("Keystore: {:?}", keystore_path);

    Ok(())
}

fn list_accounts(config: &Config) -> Result<()> {
    let entries = fs::read_dir(&config.keystore_path).with_context(|| {
        format!(
            "Failed to read keystore directory {:?}",
            config.keystore_path
        )
    })?;

    println!("{}", "Accounts:".bold());

    let mut count = 0;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(filename) = path.file_stem().and_then(|s| s.to_str()) {
                println!("  • 0x{}", filename);
                count += 1;
            }
        }
    }

    if count == 0 {
        println!("  {}", "No accounts found".yellow());
        println!("  Use 'citrate account create' to create a new account");
    } else {
        println!("\nTotal: {} account(s)", count);
    }

    Ok(())
}

async fn get_balance(config: &Config, address: &str) -> Result<()> {
    // Clean address format
    let address = address.trim_start_matches("0x");

    // Make RPC call to get balance
    let client = reqwest::Client::new();
    let response = client
        .post(&config.rpc_endpoint)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [format!("0x{}", address), "latest"],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(balance_hex) = result["result"].as_str() {
        let balance = u128::from_str_radix(balance_hex.trim_start_matches("0x"), 16)
            .context("Failed to parse balance")?;

        println!("Address: {}", format!("0x{}", address).cyan());
        println!("Balance: {} wei", balance);
        println!("         {} ETH", balance as f64 / 1e18);
    } else if let Some(error) = result["error"].as_object() {
        anyhow::bail!(
            "RPC error: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Unexpected response from RPC");
    }

    Ok(())
}

fn import_account(config: &Config, private_key: &str, password: Zeroizing<String>) -> Result<()> {
    // Parse private key (32 bytes for ed25519)
    let key_bytes =
        hex::decode(private_key.trim_start_matches("0x")).context("Invalid private key format")?;

    if key_bytes.len() != 32 {
        anyhow::bail!("Invalid private key length. Expected 32 bytes for ed25519.");
    }

    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("private key must be exactly 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&key_array);

    // Derive public key and address
    let verifying_key = signing_key.verifying_key();
    let address = derive_address(verifying_key.as_bytes());

    // Save to keystore
    let keystore_path = config
        .keystore_path
        .join(format!("{}.json", hex::encode(address)));

    if keystore_path.exists() {
        anyhow::bail!("Account already exists in keystore");
    }

    keystore::save_key(&signing_key, &password, &keystore_path)?;

    println!("{}", "✓ Account imported successfully".green());
    println!("Address: {}", format!("0x{}", hex::encode(address)).cyan());

    Ok(())
}

fn export_account(
    config: &Config,
    address: &str,
    out: Option<PathBuf>,
    confirm_stdout: bool,
    password: Zeroizing<String>,
) -> Result<()> {
    let address = address.trim_start_matches("0x");
    let keystore_path = config.keystore_path.join(format!("{}.json", address));

    if !keystore_path.exists() {
        anyhow::bail!("Account not found in keystore");
    }

    // RM-K / WP-K1.6: refuse to print to stdout unless the operator
    // explicitly opts in OR redirects to a file. Without the gate the
    // private key lands in terminal scrollback, shell pipes, and
    // screen recordings.
    if out.is_none() && !confirm_stdout {
        anyhow::bail!(
            "Refusing to print private key to stdout. \
             Use --out <PATH> to write to a file (0600 on Unix), or \
             --confirm-stdout to acknowledge stdout export and proceed."
        );
    }

    // Load and decrypt key
    let signing_key = keystore::load_key(&keystore_path, &password)?;
    // PBA-L4-009: wipe the hex-encoded secret when this scope ends.
    let key_hex = Zeroizing::new(hex::encode(signing_key.to_bytes()));

    eprintln!(
        "{}",
        "⚠️  WARNING: Never share your private key!".red().bold()
    );

    if let Some(path) = out {
        write_secret_file(&path, key_hex.as_str())
            .with_context(|| format!("Failed to write private key to {}", path.display()))?;
        eprintln!(
            "Private key written to {} (mode 0600 on Unix). Delete or `shred` after use.",
            path.display()
        );
    } else {
        // confirm_stdout is true here per the gate above.
        println!("{}", key_hex.as_str());
    }

    Ok(())
}

/// PBA-L4-009: resolve the keystore password without putting it on argv.
///
/// Order: `--password-file` (first line), then the legacy `--password` argv
/// value (with a loud warning — argv is visible in `ps`, shell history and
/// audit logs), then an interactive no-echo prompt. Returned `Zeroizing` so
/// the password is wiped when the command finishes.
fn resolve_password(
    password: Option<String>,
    password_file: Option<PathBuf>,
    prompt: &str,
) -> Result<Zeroizing<String>> {
    if let Some(path) = password_file {
        let raw = Zeroizing::new(
            fs::read_to_string(&path)
                .with_context(|| format!("Failed to read password file {}", path.display()))?,
        );
        let line = raw.lines().next().unwrap_or("").to_string();
        return Ok(Zeroizing::new(line));
    }
    if let Some(p) = password {
        eprintln!(
            "{}",
            "⚠️  WARNING: --password puts the keystore password on the command line \
             (visible in `ps`, shell history and audit logs). Use --password-file or the \
             interactive prompt."
                .yellow()
                .bold()
        );
        return Ok(Zeroizing::new(p));
    }
    Ok(Zeroizing::new(
        rpassword::prompt_password(prompt).context("Failed to read password from terminal")?,
    ))
}

/// RM-K / WP-K1.6: helper for the `account import` private-key input
/// modes. Returns the hex-encoded key (without `0x` prefix). Does not
/// echo to terminal in the stdin path.
fn read_import_key(
    key_stdin: bool,
    key_file: Option<PathBuf>,
    insecure_key_from_arg: Option<String>,
) -> Result<String> {
    let raw = match (key_stdin, key_file, insecure_key_from_arg) {
        (true, _, _) => rpassword::prompt_password("Paste 32-byte hex private key (no echo): ")
            .context("Failed to read private key from stdin")?,
        (_, Some(path), _) => {
            std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read key file {}", path.display()))?
                .trim()
                .to_string()
        }
        (_, _, Some(hex_arg)) => {
            // Loud warning: argv is visible in the OS.
            eprintln!(
                "{}",
                "⚠️  WARNING: --insecure-key-from-arg passes the private key on \
                 the command line. argv is visible in `ps`, shell history, and \
                 audit logs. Use --key-stdin or --key-file in production."
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
    Ok(raw.trim().trim_start_matches("0x").to_string())
}

/// RM-K / WP-K1.6: write secret material with 0600 perms on Unix.
fn write_secret_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests_pba_l4_009 {
    use super::*;

    /// PBA-L4-009: `--password-file` reads the first line (no trailing newline)
    /// and takes precedence, so scripts never need the password on argv.
    #[test]
    fn pba_l4_009_password_file_is_read_and_preferred() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let f = dir.path().join("pw");
        std::fs::write(&f, "hunter2-hunter2\nignored\n").expect("write");
        let p = resolve_password(Some("from-argv".into()), Some(f), "unused").expect("resolve");
        assert_eq!(p.as_str(), "hunter2-hunter2");
        let p = resolve_password(Some("from-argv".into()), None, "unused").expect("resolve");
        assert_eq!(p.as_str(), "from-argv");
    }
}

#[cfg(test)]
mod tests_k1_6 {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    #[command(name = "test-cli")]
    struct TestCli {
        #[command(subcommand)]
        cmd: AccountCommands,
    }

    #[test]
    fn test_k1_6_import_requires_explicit_key_source() {
        // No key source provided → argparse must succeed (cli accepts
        // it) but the runtime must reject. We test the runtime path.
        let result = read_import_key(false, None, None);
        assert!(
            result.is_err(),
            "K1.6: import without --key-stdin / --key-file / \
             --insecure-key-from-arg must fail at runtime"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("--key-stdin") && msg.contains("--key-file"),
            "K1.6: error must name the secure alternatives, got: {}",
            msg
        );
    }

    #[test]
    fn test_k1_6_import_key_file_path() {
        // Write a hex key into a temp file and read it back.
        let tmp = std::env::temp_dir().join(format!(
            "k1_6_import_test_{}.key",
            std::process::id()
        ));
        let hex_key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        std::fs::write(&tmp, format!("0x{}\n", hex_key)).expect("write test key file");

        let read = read_import_key(false, Some(tmp.clone()), None).expect("read key file");
        assert_eq!(read, hex_key);
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_k1_6_argparse_rejects_legacy_short_flags() {
        // Legacy `account import --key <hex>` MUST fail to parse.
        // The new flags are `--key-stdin`, `--key-file`, and
        // `--insecure-key-from-arg`. Plain `--key` was the L-05
        // finding shape and should no longer be a recognized flag.
        let result = TestCli::try_parse_from([
            "test-cli",
            "import",
            "--key",
            "abcd",
        ]);
        assert!(
            result.is_err(),
            "K1.6: legacy `--key` flag must no longer parse. The shape \
             that put private keys on argv is what L-05 flagged."
        );
    }

    #[test]
    fn test_k1_6_argparse_accepts_stdin_flag() {
        let result = TestCli::try_parse_from(["test-cli", "import", "--key-stdin"]);
        assert!(
            result.is_ok(),
            "K1.6: `--key-stdin` is the recommended secure path and must parse"
        );
    }

    #[test]
    fn test_k1_6_argparse_accepts_key_file_flag() {
        let result = TestCli::try_parse_from([
            "test-cli",
            "import",
            "--key-file",
            "/tmp/some.key",
        ]);
        assert!(result.is_ok(), "K1.6: --key-file must parse");
    }

    #[test]
    fn test_k1_6_argparse_rejects_simultaneous_key_sources() {
        // The `conflicts_with_all` annotation on each option must
        // prevent two key sources from being supplied at once.
        let result = TestCli::try_parse_from([
            "test-cli",
            "import",
            "--key-stdin",
            "--insecure-key-from-arg",
            "abcd",
        ]);
        assert!(
            result.is_err(),
            "K1.6: --key-stdin and --insecure-key-from-arg must conflict"
        );
    }

    #[test]
    fn test_k1_6_export_argparse_accepts_out_flag() {
        let result = TestCli::try_parse_from([
            "test-cli",
            "export",
            "0x1234",
            "--out",
            "/tmp/key.txt",
        ]);
        assert!(result.is_ok(), "K1.6: export --out must parse");
    }

    #[test]
    fn test_k1_6_export_argparse_accepts_confirm_stdout_flag() {
        let result = TestCli::try_parse_from([
            "test-cli",
            "export",
            "0x1234",
            "--confirm-stdout",
        ]);
        assert!(
            result.is_ok(),
            "K1.6: export --confirm-stdout must parse"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_k1_6_write_secret_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!(
            "k1_6_secret_perms_{}.key",
            std::process::id()
        ));
        write_secret_file(&tmp, "deadbeef").expect("write secret file");
        let meta = std::fs::metadata(&tmp).expect("stat tmp file");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "K1.6: exported key file must be mode 0600, got {:#o}",
            mode
        );
        std::fs::remove_file(&tmp).ok();
    }
}

/// Derive Ethereum-compatible address from ed25519 public key
///
/// Address derivation follows the same logic as citrate-execution:
/// 1. If pubkey has embedded EVM address (20 bytes + 12 zeros), use directly
/// 2. Otherwise, Keccak256 hash the full 32-byte pubkey, take last 20 bytes
fn derive_address(pubkey: &[u8; 32]) -> [u8; 20] {
    // Check if embedded EVM address (20 bytes + 12 zeros)
    let is_evm_address = pubkey[20..].iter().all(|&b| b == 0)
        && !pubkey[..20].iter().all(|&b| b == 0);

    if is_evm_address {
        // Use first 20 bytes directly
        let mut address = [0u8; 20];
        address.copy_from_slice(&pubkey[..20]);
        return address;
    }

    // Full pubkey: Keccak256 hash, take last 20 bytes
    let mut hasher = Keccak256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();

    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_address_embedded_evm() {
        // 20 non-zero bytes followed by 12 zero bytes = embedded EVM address
        let mut pubkey = [0u8; 32];
        pubkey[..20].copy_from_slice(&[0xAA; 20]);
        let addr = derive_address(&pubkey);
        assert_eq!(addr, [0xAA; 20]);
    }

    #[test]
    fn test_derive_address_full_pubkey_uses_keccak() {
        // Full 32-byte pubkey (non-zero in last 12 bytes) -> Keccak256
        let pubkey = [0x42u8; 32];
        let addr = derive_address(&pubkey);
        // Verify it matches Keccak256 hash last 20 bytes
        let mut hasher = Keccak256::new();
        hasher.update(pubkey);
        let hash = hasher.finalize();
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&hash[12..]);
        assert_eq!(addr, expected);
    }

    #[test]
    fn test_derive_address_all_zeros_uses_keccak() {
        // All zeros: the embedded-EVM check requires non-zero first 20 bytes
        let pubkey = [0u8; 32];
        let addr = derive_address(&pubkey);
        // Should use Keccak path since first 20 bytes are all zero
        let mut hasher = Keccak256::new();
        hasher.update(pubkey);
        let hash = hasher.finalize();
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&hash[12..]);
        assert_eq!(addr, expected);
    }

    #[test]
    fn test_derive_address_deterministic() {
        let pubkey = [0x11u8; 32];
        let addr1 = derive_address(&pubkey);
        let addr2 = derive_address(&pubkey);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_derive_address_different_keys_different_addresses() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let addr_a = derive_address(&key_a);
        let addr_b = derive_address(&key_b);
        assert_ne!(addr_a, addr_b);
    }
}
