//citrate/cli/src/commands/signer.rs
//
// Local transaction signing for the CLI's write commands.
//
// The CLI used to send `eth_sendTransaction` and let the node sign. Public
// nodes refuse that, so every write signs locally and goes out through
// `eth_sendRawTransaction`:
//
//   * key: the CLI keystore (`--account`, password from `--password-file` or a
//     prompt) or the `PRIVATE_KEY` environment variable. Never argv.
//   * nonce, chain id and gas price come from the node; the gas limit comes
//     from `eth_estimateGas` unless `--gas-limit` is given.
//   * the node must be chain 40204 at the genesis in the root address book
//     (`contracts/addresses/40204.json`), unless `--allow-foreign-chain`.
//   * signing is citrate-wallet's `TransactionBuilder::build_and_sign`
//     (native ed25519, chain-bound V2 digest) and its bincode raw encoding.
//     No crypto lives in this file.

use anyhow::{Context, Result};
use citrate_consensus::types::PublicKey;
use citrate_execution::types::Address;
use citrate_wallet::{SignedTransaction, TransactionBuilder};
use clap::Args;
use ed25519_dalek::SigningKey;
use primitive_types::U256;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::utils::keystore;

/// The chain the CLI signs for unless `--allow-foreign-chain`.
pub const EXPECTED_CHAIN_ID: u64 = 40204;

/// The environment variable a raw signing key may come from (32-byte ed25519
/// secret, hex, as `account export` writes it).
pub const PRIVATE_KEY_ENV: &str = "PRIVATE_KEY";

/// The live network's root address book. Its `genesisHash` is the genesis the
/// CLI expects the node to serve.
const ROOT_BOOK: &str = include_str!("../../../contracts/addresses/40204.json");

/// Options shared by every command that signs a transaction.
#[derive(Args, Debug, Clone, Default)]
pub struct SignerArgs {
    /// Sign with this keystore key: the address of a key in the CLI keystore
    /// (`account create` / `account import`). Without it the key comes from the
    /// PRIVATE_KEY environment variable, then the config's default_account.
    #[arg(long)]
    pub account: Option<String>,

    /// Read the keystore password from this file (first line). Prompts if omitted.
    #[arg(long)]
    pub password_file: Option<PathBuf>,

    /// Gas limit. Estimated with eth_estimateGas when omitted.
    #[arg(long)]
    pub gas_limit: Option<u64>,

    /// Sign for a node whose chain id is not 40204 (a local development chain).
    /// A chain-40204 node at another genesis is always refused.
    #[arg(long)]
    pub allow_foreign_chain: bool,

    /// Gas price in gwei. Read from eth_gasPrice when omitted.
    #[arg(long, value_name = "GWEI")]
    pub gas_price: Option<u64>,

    /// Refuse to sign above this gas price, in gwei.
    #[arg(long, value_name = "GWEI", default_value_t = DEFAULT_MAX_GAS_PRICE_GWEI)]
    pub max_gas_price: u64,

    /// Refuse to sign when the fee (gas limit x gas price) is above this, in SALT.
    #[arg(long, value_name = "SALT", default_value = DEFAULT_MAX_FEE_SALT)]
    pub max_fee: String,

    /// Send without asking for confirmation.
    #[arg(long)]
    pub yes: bool,
}

/// Default `--max-gas-price`, in gwei (r1007 charges 1 gwei).
pub const DEFAULT_MAX_GAS_PRICE_GWEI: u64 = 100;

/// Default `--max-fee`, in SALT.
pub const DEFAULT_MAX_FEE_SALT: &str = "1";

/// Refuse a gas price or fee above the caps; return the fee in wei.
pub fn check_fee(
    gas_limit: u64,
    gas_price_wei: u64,
    max_gas_price_wei: u64,
    max_fee_wei: u128,
) -> Result<u128> {
    if gas_price_wei > max_gas_price_wei {
        anyhow::bail!(
            "Refusing to sign: gas price {} gwei is above --max-gas-price {} gwei",
            format_gwei(gas_price_wei),
            format_gwei(max_gas_price_wei)
        );
    }
    let fee = u128::from(gas_limit).saturating_mul(u128::from(gas_price_wei));
    if fee > max_fee_wei {
        anyhow::bail!(
            "Refusing to sign: the fee ({gas_limit} gas x {} gwei = {} SALT) is above \
             --max-fee {} SALT",
            format_gwei(gas_price_wei),
            format_salt(fee),
            format_salt(max_fee_wei)
        );
    }
    Ok(fee)
}

/// Whether to send after showing the fee. `answer` is the reply typed at the prompt.
pub fn confirm_decision(yes: bool, interactive: bool, answer: Option<&str>) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !interactive {
        anyhow::bail!(
            "Not sent: confirmation needs a terminal. Pass --yes to send without confirming."
        );
    }
    let a = answer.unwrap_or("").trim().to_ascii_lowercase();
    Ok(a == "y" || a == "yes")
}

fn format_units(amount: u128, decimals: u32) -> String {
    // `unit` is 10^9 or 10^18, never zero, so checked_div/checked_rem never fail.
    let unit = 10u128.pow(decimals);
    let whole = amount.checked_div(unit).unwrap_or(0);
    let frac = amount.checked_rem(unit).unwrap_or(0);
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:0width$}", width = decimals as usize);
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

/// A wei amount as SALT, exact (no floating point).
pub fn format_salt(wei: u128) -> String {
    format_units(wei, 18)
}

fn format_gwei(wei: u64) -> String {
    format_units(u128::from(wei), 9)
}

/// A warning when PRIVATE_KEY signs for an account other than the config's default.
pub fn env_default_mismatch_warning(
    key: &SigningKey,
    default_account: Option<&str>,
) -> Option<String> {
    let default = parse_address(default_account?).ok()?;
    let signer = address_of(key);
    if signer == default {
        return None;
    }
    Some(format!(
        "Warning: {PRIVATE_KEY_ENV} signs for 0x{}, not the configured default_account 0x{}.",
        hex::encode(signer),
        hex::encode(default)
    ))
}

/// The genesis hash in the root address book.
pub fn expected_genesis() -> Result<String> {
    let book: Value =
        serde_json::from_str(ROOT_BOOK).context("parsing contracts/addresses/40204.json")?;
    book.get("genesisHash")
        .and_then(Value::as_str)
        .map(str::to_lowercase)
        .context("contracts/addresses/40204.json has no genesisHash")
}

/// Refuse to sign for a node that is not the expected chain.
///
/// A node that reports chain 40204 must be at the expected genesis, always:
/// a 40204 transaction signed against another genesis (an old network, a
/// fork) is replayable on the live chain. `--allow-foreign-chain` only lets the
/// CLI sign for a different chain id, whose genesis it does not know.
pub fn check_chain(
    node_chain_id: u64,
    node_genesis: &str,
    expected_genesis: &str,
    allow_foreign: bool,
) -> Result<()> {
    if node_chain_id == EXPECTED_CHAIN_ID {
        if !node_genesis.eq_ignore_ascii_case(expected_genesis) {
            anyhow::bail!(
                "Refusing to sign: the node reports chain {EXPECTED_CHAIN_ID} but its genesis is \
                 {node_genesis}, not {expected_genesis} (contracts/addresses/40204.json). A \
                 transaction signed for it would be valid on the live chain. Point --rpc at a \
                 live node, or update the CLI. --allow-foreign-chain does not override this."
            );
        }
        return Ok(());
    }
    if !allow_foreign {
        anyhow::bail!(
            "Refusing to sign: the node serves chain {node_chain_id}, not chain \
             {EXPECTED_CHAIN_ID}. Pass --allow-foreign-chain to sign for it anyway."
        );
    }
    Ok(())
}

/// Parse a 32-byte ed25519 secret from hex (with or without 0x).
pub fn parse_secret_hex(hex_key: &str) -> Result<SigningKey> {
    let trimmed = hex_key.trim();
    let raw = Zeroizing::new(
        // hex's error names the offending character and its position; never pass it on.
        hex::decode(trimmed.strip_prefix("0x").unwrap_or(trimmed))
            .map_err(|_| anyhow::anyhow!("the private key is not valid hex"))?,
    );
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "the private key must be 32 bytes (64 hex characters), got {} bytes",
            raw.len()
        )
    })?;
    let bytes = Zeroizing::new(bytes);
    Ok(SigningKey::from_bytes(&bytes))
}

/// The account address of a signing key, as the chain derives it
/// (`Address::from_public_key`, the same rule `account create` names files by).
pub fn address_of(key: &SigningKey) -> [u8; 20] {
    Address::from_public_key(&PublicKey::new(*key.verifying_key().as_bytes())).0
}

fn parse_address(s: &str) -> Result<[u8; 20]> {
    let t = s.trim();
    let bytes = hex::decode(t.strip_prefix("0x").unwrap_or(t))
        .with_context(|| format!("invalid address {s}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("address {s} is not 20 bytes"))
}

/// Where the signing key comes from, in order: `--account` (keystore), the
/// PRIVATE_KEY value, the config's `default_account` (keystore). With a
/// keystore account and PRIVATE_KEY both present, they must be the same key.
pub fn resolve_key(
    account: Option<&str>,
    env_key: Option<Zeroizing<String>>,
    default_account: Option<&str>,
    keystore_dir: &Path,
    password: &dyn Fn() -> Result<Zeroizing<String>>,
) -> Result<SigningKey> {
    let from_keystore = |addr: &str| -> Result<SigningKey> {
        let a = parse_address(addr)?;
        let path = keystore_dir.join(format!("{}.json", hex::encode(a)));
        if !path.exists() {
            anyhow::bail!(
                "No keystore file for 0x{} in {:?}. Create or import the account first \
                 (`account create` / `account import`).",
                hex::encode(a),
                keystore_dir
            );
        }
        let pw = password()?;
        let key = keystore::load_key(&path, &pw)?;
        if address_of(&key) != a {
            anyhow::bail!("keystore file {:?} holds a key for another address", path);
        }
        Ok(key)
    };
    let env = env_key.filter(|k| !k.trim().is_empty());
    if let Some(addr) = account {
        let key = from_keystore(addr)?;
        if let Some(env) = env {
            let env_key = parse_secret_hex(&env)?;
            if address_of(&env_key) != address_of(&key) {
                anyhow::bail!(
                    "{PRIVATE_KEY_ENV} is set to a key for 0x{}, but --account is {addr}. \
                     Unset {PRIVATE_KEY_ENV} or drop --account.",
                    hex::encode(address_of(&env_key))
                );
            }
        }
        return Ok(key);
    }
    if let Some(env) = env {
        return parse_secret_hex(&env).with_context(|| format!("reading {PRIVATE_KEY_ENV}"));
    }
    if let Some(addr) = default_account {
        return from_keystore(addr);
    }
    anyhow::bail!(
        "No signing key. Pass --account <address> to sign with a keystore account, or set \
         {PRIVATE_KEY_ENV} to a 32-byte hex key (never pass a key on the command line)."
    )
}

/// The values the node supplies for one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxParams {
    pub nonce: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub chain_id: u64,
}

/// Build and sign a transaction with citrate-wallet's builder
/// (`TransactionBuilder::build_and_sign`: native ed25519, V2 digest, bincode raw).
pub fn build_signed(
    key: &SigningKey,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
    params: &TxParams,
) -> Result<SignedTransaction> {
    TransactionBuilder::new()
        .from(PublicKey::new(*key.verifying_key().as_bytes()))
        .to(to.map(Address))
        .value(U256::from(value))
        .data(data)
        .nonce(params.nonce)
        .gas_price(params.gas_price)
        .gas_limit(params.gas_limit)
        .chain_id(params.chain_id)
        .build_and_sign(key)
        .map_err(|e| anyhow::anyhow!("signing failed: {e}"))
}

/// The gas limit to use for an `eth_estimateGas` answer: 20% headroom for a
/// call or deploy (state can change between estimate and inclusion), none for
/// a plain transfer.
pub fn gas_with_headroom(estimate: u64, has_data: bool) -> u64 {
    if has_data {
        estimate.saturating_add(estimate / 5)
    } else {
        estimate
    }
}

/// A signed, submitted transaction and its receipt.
pub struct Sent {
    pub hash: String,
    pub from: [u8; 20],
    pub receipt: Value,
}

/// One JSON-RPC call to the configured endpoint; an RPC error becomes an error.
async fn rpc(
    client: &reqwest::Client,
    config: &Config,
    method: &str,
    params: Value,
) -> Result<Value> {
    let body: Value = client
        .post(&config.rpc_endpoint)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?
        .json()
        .await
        .with_context(|| format!("{method}: the endpoint did not answer with JSON"))?;
    if let Some(err) = body.get("error") {
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        anyhow::bail!("{method}: {message}");
    }
    Ok(body.get("result").cloned().unwrap_or(Value::Null))
}

fn hex_u64(v: &Value, what: &str) -> Result<u64> {
    let s = v
        .as_str()
        .with_context(|| format!("{what}: expected a hex quantity"))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .with_context(|| format!("{what}: invalid hex quantity {s}"))
}

/// Sign and submit one transaction, then wait for its receipt.
///
/// Data sources, all on the configured endpoint: `eth_chainId` and
/// `eth_getBlockByNumber("0x0")` (chain guard), `eth_getTransactionCount(from,
/// "pending")` (nonce), `eth_gasPrice`, `eth_estimateGas` (unless
/// `--gas-limit`), `eth_sendRawTransaction`, `eth_getTransactionReceipt`.
pub async fn sign_and_send(
    config: &Config,
    args: &SignerArgs,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
) -> Result<Sent> {
    let password_file = args.password_file.clone();
    let password = move || -> Result<Zeroizing<String>> {
        if let Some(path) = &password_file {
            let raw = Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("Failed to read password file {}", path.display()))?,
            );
            return Ok(Zeroizing::new(raw.lines().next().unwrap_or("").to_string()));
        }
        Ok(Zeroizing::new(
            rpassword::prompt_password("Keystore password: ")
                .context("Failed to read password from terminal")?,
        ))
    };
    let env_key = std::env::var(PRIVATE_KEY_ENV).ok().map(Zeroizing::new);
    let key = resolve_key(
        args.account.as_deref(),
        env_key,
        config.default_account.as_deref(),
        &config.keystore_path,
        &password,
    )?;
    let from = address_of(&key);
    let from_hex = format!("0x{}", hex::encode(from));
    let env_set = std::env::var(PRIVATE_KEY_ENV).is_ok_and(|k| !k.trim().is_empty());
    if args.account.is_none() && env_set {
        if let Some(w) = env_default_mismatch_warning(&key, config.default_account.as_deref()) {
            eprintln!("{w}");
        }
    }
    let max_gas_price_wei = args
        .max_gas_price
        .checked_mul(1_000_000_000)
        .context("--max-gas-price is too large")?;
    let max_fee_wei =
        crate::commands::account::parse_salt_amount(&args.max_fee).context("--max-fee")?;

    let client = reqwest::Client::new();
    let chain_id = hex_u64(
        &rpc(&client, config, "eth_chainId", json!([])).await?,
        "eth_chainId",
    )?;
    let genesis = rpc(
        &client,
        config,
        "eth_getBlockByNumber",
        json!(["0x0", false]),
    )
    .await?
    .get("hash")
    .and_then(Value::as_str)
    .map(str::to_string)
    .context("the node did not return block 0")?;
    check_chain(
        chain_id,
        &genesis,
        &expected_genesis()?,
        args.allow_foreign_chain,
    )?;

    let nonce = hex_u64(
        &rpc(
            &client,
            config,
            "eth_getTransactionCount",
            json!([from_hex, "pending"]),
        )
        .await?,
        "eth_getTransactionCount",
    )?;
    let gas_price = match args.gas_price {
        Some(gwei) => gwei
            .checked_mul(1_000_000_000)
            .context("--gas-price is too large")?,
        None => hex_u64(
            &rpc(&client, config, "eth_gasPrice", json!([])).await?,
            "eth_gasPrice",
        )?,
    };
    let gas_limit = match args.gas_limit {
        Some(g) => g,
        None => {
            let mut call = json!({
                "from": from_hex,
                "value": format!("0x{value:x}"),
                "data": format!("0x{}", hex::encode(&data)),
            });
            if let (Some(to), Some(obj)) = (to, call.as_object_mut()) {
                obj.insert("to".into(), json!(format!("0x{}", hex::encode(to))));
            }
            let estimate = hex_u64(
                &rpc(&client, config, "eth_estimateGas", json!([call])).await?,
                "eth_estimateGas",
            )?;
            gas_with_headroom(estimate, !data.is_empty())
        }
    };

    let fee = check_fee(gas_limit, gas_price, max_gas_price_wei, max_fee_wei)?;
    eprintln!("Chain:     {chain_id}");
    eprintln!("From:      {from_hex} (nonce {nonce})");
    match to {
        Some(t) => eprintln!("To:        0x{}", hex::encode(t)),
        None => eprintln!("To:        (contract creation)"),
    }
    eprintln!("Value:     {} SALT", format_salt(value));
    eprintln!("Gas:       {gas_limit} at {} gwei", format_gwei(gas_price));
    eprintln!("Max fee:   {} SALT", format_salt(fee));
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let answer = if !args.yes && interactive {
        eprint!("Send? [y/N] ");
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("Failed to read the confirmation")?;
        Some(line)
    } else {
        None
    };
    if !confirm_decision(args.yes, interactive, answer.as_deref())? {
        anyhow::bail!("Cancelled; nothing was sent.");
    }

    let params = TxParams {
        nonce,
        gas_price,
        gas_limit,
        chain_id,
    };
    let signed = build_signed(&key, to, value, data, &params)?;
    let raw = format!("0x{}", hex::encode(&signed.raw));
    let hash = rpc(&client, config, "eth_sendRawTransaction", json!([raw]))
        .await?
        .as_str()
        .map(str::to_string)
        .context("eth_sendRawTransaction returned no hash")?;
    eprintln!("Sent {hash}");

    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let receipt = rpc(&client, config, "eth_getTransactionReceipt", json!([hash])).await?;
        if receipt.is_object() {
            return Ok(Sent {
                hash,
                from,
                receipt,
            });
        }
    }
    anyhow::bail!("{hash} was submitted but has no receipt after 120 s; check it with `network transaction {hash}`")
}

/// Whether a receipt reports success (`status` 0x1).
pub fn receipt_ok(receipt: &Value) -> bool {
    receipt.get("status").and_then(Value::as_str) == Some("0x1")
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1007_GENESIS: &str =
        "0xcf68634502b4fca1e977ac8dd35aa006bb40c04208d5cd55f1c2b508bba96631";
    const R1006_GENESIS: &str =
        "0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4";
    /// A fixed test key (not a funded account).
    const TEST_SECRET: &str = "4242424242424242424242424242424242424242424242424242424242424242";

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    #[test]
    fn expects_the_r1007_genesis_from_the_root_book() {
        assert_eq!(expected_genesis().ok().as_deref(), Some(R1007_GENESIS));
    }

    #[test]
    fn signs_for_chain_40204_at_the_expected_genesis() {
        assert!(check_chain(40204, R1007_GENESIS, R1007_GENESIS, false).is_ok());
        // Case does not matter.
        let upper = R1007_GENESIS.to_uppercase().replacen("0X", "0x", 1);
        assert!(check_chain(40204, &upper, R1007_GENESIS, false).is_ok());
    }

    #[test]
    fn refuses_another_chain_id_unless_overridden() {
        let err = check_chain(1, R1007_GENESIS, R1007_GENESIS, false)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("chain 1"), "{err}");
        assert!(err.contains("--allow-foreign-chain"), "{err}");
        assert!(check_chain(1, R1007_GENESIS, R1007_GENESIS, true).is_ok());
    }

    #[test]
    fn a_40204_node_at_another_genesis_is_refused_even_with_the_flag() {
        // A 40204 transaction signed against another genesis (r1006, a fork) is
        // replayable on the live chain, so the flag must not wave it through.
        for allow in [false, true] {
            let err = check_chain(40204, R1006_GENESIS, R1007_GENESIS, allow)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(err.contains(R1006_GENESIS), "allow={allow}: {err}");
            assert!(err.contains(R1007_GENESIS), "allow={allow}: {err}");
        }
    }

    #[test]
    fn the_flag_only_allows_another_chain_id() {
        assert!(check_chain(31337, R1006_GENESIS, R1007_GENESIS, true).is_ok());
        assert!(check_chain(31337, R1006_GENESIS, R1007_GENESIS, false).is_err());
    }

    #[test]
    fn fees_above_the_caps_are_refused() {
        let gwei = 1_000_000_000u64;
        let one_salt = 1_000_000_000_000_000_000u128;
        assert_eq!(
            check_fee(21_000, gwei, 100 * gwei, one_salt).ok(),
            Some(21_000_000_000_000)
        );
        let price = check_fee(21_000, 101 * gwei, 100 * gwei, one_salt)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(price.contains("--max-gas-price"), "{price}");
        // 3,000,000 gas at 100 gwei is 0.3 SALT: over a 0.1 SALT cap.
        let fee = check_fee(3_000_000, 100 * gwei, 100 * gwei, one_salt / 10)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(fee.contains("--max-fee"), "{fee}");
        assert!(fee.contains("0.3 SALT"), "{fee}");
        // No overflow at the extremes.
        assert!(check_fee(u64::MAX, u64::MAX, u64::MAX, u128::MAX).is_ok());
    }

    #[test]
    fn salt_formats_exactly() {
        assert_eq!(format_salt(0), "0");
        assert_eq!(format_salt(1_000_000_000_000_000_000), "1");
        assert_eq!(format_salt(21_000_000_000_000), "0.000021");
        assert_eq!(format_salt(1), "0.000000000000000001");
        assert_eq!(format_salt(2_500_000_000_000_000_000), "2.5");
    }

    #[test]
    fn sending_needs_yes_or_a_typed_confirmation() {
        assert_eq!(confirm_decision(true, false, None).ok(), Some(true));
        assert_eq!(confirm_decision(false, true, Some("y")).ok(), Some(true));
        assert_eq!(
            confirm_decision(false, true, Some("YES\n")).ok(),
            Some(true)
        );
        assert_eq!(confirm_decision(false, true, Some("")).ok(), Some(false));
        assert_eq!(confirm_decision(false, true, Some("n")).ok(), Some(false));
        let err = confirm_decision(false, false, None)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("--yes"), "{err}");
    }

    #[test]
    fn warns_when_private_key_is_not_the_default_account() {
        let addr = hex::encode(address_of(&test_key()));
        assert!(env_default_mismatch_warning(&test_key(), None).is_none());
        assert!(env_default_mismatch_warning(&test_key(), Some(&format!("0x{addr}"))).is_none());
        let w = env_default_mismatch_warning(
            &test_key(),
            Some("0x1111111111111111111111111111111111111111"),
        )
        .unwrap_or_default();
        assert!(w.contains(PRIVATE_KEY_ENV), "{w}");
        assert!(w.contains(&addr), "{w}");
        assert!(
            w.contains("0x1111111111111111111111111111111111111111"),
            "{w}"
        );
    }

    #[test]
    fn a_malformed_key_is_not_echoed_in_the_error() {
        let mut bad = "42".repeat(32);
        bad.replace_range(10..11, "q");
        let err = parse_secret_hex(&bad)
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(!err.is_empty());
        assert!(!err.contains('q'), "{err}");
        assert!(!err.contains("position"), "{err}");
        assert!(!err.contains("4242"), "{err}");
    }

    #[test]
    fn parses_a_hex_secret_and_rejects_bad_ones() {
        let k = parse_secret_hex(TEST_SECRET).ok().map(|k| k.to_bytes());
        assert_eq!(k, Some([0x42; 32]));
        let k0x = parse_secret_hex(&format!("0x{TEST_SECRET}\n"))
            .ok()
            .map(|k| k.to_bytes());
        assert_eq!(k0x, Some([0x42; 32]));
        assert!(parse_secret_hex("0x1234").is_err());
        assert!(parse_secret_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn the_signer_address_is_the_keystore_address() {
        // The CLI keystore names files by this address (account create / import).
        let vk = test_key().verifying_key();
        let expected = Address::from_public_key(&PublicKey::new(*vk.as_bytes())).0;
        assert_eq!(address_of(&test_key()), expected);
        assert_ne!(expected, [0u8; 20]);
    }

    fn no_password() -> Result<Zeroizing<String>> {
        anyhow::bail!("no password expected")
    }

    #[test]
    fn env_key_is_used_when_no_account_is_given() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = resolve_key(
            None,
            Some(Zeroizing::new(TEST_SECRET.to_string())),
            None,
            dir.path(),
            &no_password,
        );
        assert_eq!(key.ok().map(|k| k.to_bytes()), Some([0x42; 32]));
    }

    #[test]
    fn keystore_account_is_loaded_with_the_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        let addr = hex::encode(address_of(&test_key()));
        let path = dir.path().join(format!("{addr}.json"));
        keystore::save_key(&test_key(), "correct horse battery", &path).expect("save");
        let pw = || Ok(Zeroizing::new("correct horse battery".to_string()));
        let key = resolve_key(Some(&format!("0x{addr}")), None, None, dir.path(), &pw);
        assert_eq!(key.ok().map(|k| k.to_bytes()), Some([0x42; 32]));
        // The config default is used when nothing else is given.
        let key = resolve_key(None, None, Some(&addr), dir.path(), &pw);
        assert_eq!(key.ok().map(|k| k.to_bytes()), Some([0x42; 32]));
    }

    #[test]
    fn an_env_key_for_another_account_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let addr = hex::encode(address_of(&test_key()));
        let path = dir.path().join(format!("{addr}.json"));
        keystore::save_key(&test_key(), "correct horse battery", &path).expect("save");
        let pw = || Ok(Zeroizing::new("correct horse battery".to_string()));
        let other = Zeroizing::new("11".repeat(32));
        let err = resolve_key(Some(&addr), Some(other), None, dir.path(), &pw)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("PRIVATE_KEY"), "{err}");
    }

    #[test]
    fn no_key_source_says_how_to_give_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = resolve_key(None, None, None, dir.path(), &no_password)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("--account"), "{err}");
        assert!(err.contains("PRIVATE_KEY"), "{err}");
    }

    fn params() -> TxParams {
        TxParams {
            nonce: 7,
            gas_price: 1_000_000_000,
            gas_limit: 50_000,
            chain_id: 40204,
        }
    }

    #[test]
    fn signed_transfer_authenticates_as_the_keystore_address() {
        let to = [0x11; 20];
        let signed =
            build_signed(&test_key(), Some(to), 1_000, Vec::new(), &params()).expect("sign");
        let tx = &signed.transaction;
        assert!(citrate_consensus::tx_auth::authenticate(tx).is_ok());
        assert_eq!(
            citrate_consensus::native_sig::signed_version(tx),
            Some(citrate_consensus::native_sig::NativeSigVersion::V2)
        );
        assert_eq!(tx.chain_id, Some(40204));
        assert_eq!(
            (tx.nonce, tx.gas_price, tx.gas_limit),
            (7, 1_000_000_000, 50_000)
        );
        assert_eq!(tx.value, 1_000);
        assert_eq!(
            Address::from_public_key(&tx.from).0,
            address_of(&test_key())
        );
        let to_pk = tx.to.map(|pk| Address::from_public_key(&pk).0);
        assert_eq!(to_pk, Some(to));
        // The raw bytes are what eth_sendRawTransaction receives.
        let decoded: citrate_consensus::types::Transaction =
            bincode::deserialize(&signed.raw).expect("decode raw");
        assert_eq!(decoded.signature, tx.signature);
    }

    #[test]
    fn a_deploy_has_no_recipient_and_carries_the_code() {
        let code = vec![0x60, 0x00, 0x60, 0x00];
        let signed = build_signed(&test_key(), None, 0, code.clone(), &params()).expect("sign");
        assert!(signed.transaction.to.is_none());
        assert_eq!(signed.transaction.data, code);
        assert!(citrate_consensus::tx_auth::authenticate(&signed.transaction).is_ok());
    }

    #[test]
    fn calls_get_gas_headroom_and_plain_transfers_do_not() {
        assert_eq!(gas_with_headroom(21_000, false), 21_000);
        assert_eq!(gas_with_headroom(144_294, true), 173_152);
        assert_eq!(gas_with_headroom(u64::MAX, true), u64::MAX);
    }
}
