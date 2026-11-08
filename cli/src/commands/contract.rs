//citrate/cli/src/commands/account.rs

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

use crate::commands::verify;
use crate::config::Config;

// The Verify variant carries every verification flag; the enum is built once per run.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub enum ContractCommands {
    /// Deploy a smart contract
    Deploy {
        /// Path to contract bytecode or WASM file
        contract: PathBuf,

        /// Constructor arguments (JSON)
        #[arg(short, long)]
        args: Option<String>,

        /// Account to deploy from
        #[arg(short, long)]
        account: Option<String>,

        /// Contract value in wei
        #[arg(short, long, default_value = "0")]
        value: String,
    },

    /// Call a contract method
    Call {
        /// Contract address
        address: String,

        /// Method signature (e.g., "transfer(address,uint256)")
        method: String,

        /// Method arguments (JSON array)
        #[arg(short, long)]
        args: Option<String>,

        /// Account to call from
        #[arg(short, long)]
        account: Option<String>,

        /// Value to send in wei
        #[arg(short, long, default_value = "0")]
        value: String,
    },

    /// Read contract state (call without transaction)
    Read {
        /// Contract address
        address: String,

        /// Method signature
        method: String,

        /// Method arguments (JSON array)
        #[arg(short, long)]
        args: Option<String>,
    },

    /// Get contract code
    Code {
        /// Contract address
        address: String,

        /// Output file path (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify contract source code on CitrateScan (the explorer's Etherscan-compatible API).
    ///
    /// Give one of: --build-info (forge `out/build-info/<id>.json` written with
    /// `forge build --build-info`, a hardhat `artifacts/build-info/<id>.json`, or a hardhat
    /// contract artifact), --standard-json, or a single SOURCE file with --compiler.
    Verify {
        /// Contract address
        address: String,

        /// Single Solidity source file (single-file mode)
        #[arg(conflicts_with_all = ["build_info", "standard_json"])]
        source: Option<PathBuf>,

        /// forge or hardhat build-info file, or a hardhat contract artifact
        #[arg(long, conflicts_with = "standard_json")]
        build_info: Option<PathBuf>,

        /// solc standard JSON input file (needs --contract path:Name and --compiler)
        #[arg(long)]
        standard_json: Option<PathBuf>,

        /// Contract to verify: `path/To.sol:Name`, or `Name` when unique in the build-info
        #[arg(long)]
        contract: Option<String>,

        /// solc long version, e.g. v0.8.26+commit.8a97fa7a (read from the build-info if omitted)
        #[arg(short, long)]
        compiler: Option<String>,

        /// Single-file mode: optimizer enabled
        #[arg(short, long)]
        optimized: bool,

        /// Single-file mode: optimizer runs
        #[arg(long, default_value_t = 200)]
        runs: u32,

        /// Single-file mode: EVM version (e.g. cancun)
        #[arg(long)]
        evm_version: Option<String>,

        /// Single-file mode: linked library, `Name:0xAddress` (repeatable, at most 10)
        #[arg(long = "library", value_name = "NAME:ADDRESS")]
        libraries: Vec<String>,

        /// ABI-encoded constructor arguments (hex). Optional: the explorer reads them from the
        /// creation transaction.
        #[arg(long)]
        constructor_args: Option<String>,

        /// Creation transaction hash, if the explorer has not indexed it
        #[arg(long)]
        creation_tx: Option<String>,

        /// Explorer API base URL
        #[arg(long, env = "CITRATE_EXPLORER_URL", default_value = verify::DEFAULT_EXPLORER_URL)]
        explorer_url: String,

        /// Explorer API key (sent as `apikey`; verification works without one)
        #[arg(long, env = "CITRATE_EXPLORER_API_KEY", hide_env_values = true)]
        api_key: Option<String>,

        /// Etherscan v2 `chainid` to send (e.g. 40204). Omit it for a local devnet.
        #[arg(long)]
        chain_id: Option<u64>,

        /// Wait for the verdict instead of printing the guid
        #[arg(long)]
        watch: bool,

        /// Status poll interval with --watch, in milliseconds
        #[arg(long, default_value_t = 3000)]
        poll_interval_ms: u64,

        /// Give up waiting after this many seconds
        #[arg(long, default_value_t = 300)]
        watch_timeout_secs: u64,

        /// Show the explorer's record for an address instead of submitting
        #[arg(long)]
        get: Option<String>,
    },

    /// Check (or with --watch, wait for) a verification job by guid
    VerifyStatus {
        /// The guid `verify` printed
        guid: String,

        /// Explorer API base URL
        #[arg(long, env = "CITRATE_EXPLORER_URL", default_value = verify::DEFAULT_EXPLORER_URL)]
        explorer_url: String,

        /// Explorer API key
        #[arg(long, env = "CITRATE_EXPLORER_API_KEY", hide_env_values = true)]
        api_key: Option<String>,

        /// Etherscan v2 `chainid` to send (e.g. 40204). Omit it for a local devnet.
        #[arg(long)]
        chain_id: Option<u64>,

        /// Wait for the verdict
        #[arg(long)]
        watch: bool,

        /// Status poll interval with --watch, in milliseconds
        #[arg(long, default_value_t = 3000)]
        poll_interval_ms: u64,

        /// Give up waiting after this many seconds
        #[arg(long, default_value_t = 300)]
        watch_timeout_secs: u64,
    },

    /// Show the explorer's verified source record for an address (`getsourcecode`)
    VerifyGet {
        /// Contract address
        address: String,

        /// Explorer API base URL
        #[arg(long, env = "CITRATE_EXPLORER_URL", default_value = verify::DEFAULT_EXPLORER_URL)]
        explorer_url: String,

        /// Explorer API key
        #[arg(long, env = "CITRATE_EXPLORER_API_KEY", hide_env_values = true)]
        api_key: Option<String>,

        /// Etherscan v2 `chainid` to send (e.g. 40204). Omit it for a local devnet.
        #[arg(long)]
        chain_id: Option<u64>,
    },

    /// List the verification records stored on the node (written by the node's
    /// operator-only tooling; public verification lives on the explorer)
    VerifyList,
}

pub async fn execute(cmd: ContractCommands, config: &Config) -> Result<()> {
    match cmd {
        ContractCommands::Deploy {
            contract,
            args,
            account,
            value,
        } => {
            deploy_contract(config, contract, args, account, value).await?;
        }
        ContractCommands::Call {
            address,
            method,
            args,
            account,
            value,
        } => {
            call_contract(config, &address, &method, args, account, value).await?;
        }
        ContractCommands::Read {
            address,
            method,
            args,
        } => {
            read_contract(config, &address, &method, args).await?;
        }
        ContractCommands::Code { address, output } => {
            get_contract_code(config, &address, output).await?;
        }
        ContractCommands::Verify {
            address,
            source,
            build_info,
            standard_json,
            contract,
            compiler,
            optimized,
            runs,
            evm_version,
            libraries,
            constructor_args,
            creation_tx,
            explorer_url,
            api_key,
            chain_id,
            watch,
            poll_interval_ms,
            watch_timeout_secs,
            get,
        } => {
            let client =
                verify::ExplorerClient::new(&explorer_url, api_key)?.with_chain_id(chain_id);
            if let Some(addr) = get {
                show_verified_source(&client, &addr).await?;
            } else {
                let source = build_source_submission(
                    source,
                    build_info,
                    standard_json,
                    contract.as_deref(),
                    compiler.as_deref(),
                    optimized,
                    runs,
                    evm_version,
                    &libraries,
                )?;
                let req = verify::VerifyRequest {
                    address,
                    source,
                    constructor_args,
                    creation_tx_hash: creation_tx,
                    chain_id,
                };
                let poll = poll_config(poll_interval_ms, watch_timeout_secs);
                verify_on_explorer(&client, &req, watch, &poll).await?;
            }
        }
        ContractCommands::VerifyStatus {
            guid,
            explorer_url,
            api_key,
            chain_id,
            watch,
            poll_interval_ms,
            watch_timeout_secs,
        } => {
            let client =
                verify::ExplorerClient::new(&explorer_url, api_key)?.with_chain_id(chain_id);
            let poll = poll_config(poll_interval_ms, watch_timeout_secs);
            let status = if watch {
                client.wait(&guid, &poll).await?
            } else {
                client.check_status(&guid).await?
            };
            report_status(&guid, &status)?;
        }
        ContractCommands::VerifyGet {
            address,
            explorer_url,
            api_key,
            chain_id,
        } => {
            let client =
                verify::ExplorerClient::new(&explorer_url, api_key)?.with_chain_id(chain_id);
            show_verified_source(&client, &address).await?;
        }
        ContractCommands::VerifyList => {
            list_verifications(config).await?;
        }
    }
    Ok(())
}

async fn deploy_contract(
    config: &Config,
    contract_path: PathBuf,
    args: Option<String>,
    account: Option<String>,
    value: String,
) -> Result<()> {
    println!("{}", "Deploying contract...".cyan());

    // Read contract bytecode
    let bytecode = if contract_path.extension().and_then(|s| s.to_str()) == Some("wasm") {
        // WASM contract
        let wasm_bytes = fs::read(&contract_path)
            .with_context(|| format!("Failed to read WASM file {:?}", contract_path))?;
        hex::encode(wasm_bytes)
    } else {
        // Assume hex bytecode
        let content = fs::read_to_string(&contract_path)
            .with_context(|| format!("Failed to read contract file {:?}", contract_path))?;
        content.trim().trim_start_matches("0x").to_string()
    };

    // Parse constructor arguments
    let _constructor_args = if let Some(args_str) = args {
        serde_json::from_str(&args_str).context("Invalid constructor arguments JSON")?
    } else {
        json!([])
    };

    // Get account
    let from_account = account
        .or(config.default_account.clone())
        .context("No account specified and no default account configured")?;

    // Parse value
    let value_wei = value.parse::<u128>().context("Invalid value")?;

    // Make RPC call to deploy
    let client = reqwest::Client::new();
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{
                "from": from_account,
                "data": format!("0x{}", bytecode),
                "value": format!("0x{:x}", value_wei),
                "gas": format!("0x{:x}", config.gas_limit),
                "gasPrice": format!("0x{:x}", config.gas_price),
            }],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(tx_hash) = result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_str()
    {
        println!("{}", "✓ Contract deployment initiated".green());
        println!("Transaction: {}", tx_hash.cyan());

        // Wait for receipt
        println!("Waiting for confirmation...");

        let receipt = wait_for_receipt(config, tx_hash).await?;

        if let Some(contract_address) = receipt
            .get("contractAddress")
            .unwrap_or(&serde_json::Value::Null)
            .as_str()
        {
            println!("{}", "✓ Contract deployed successfully".green().bold());
            println!("Contract Address: {}", contract_address.cyan().bold());
            println!(
                "Gas Used: {}",
                receipt
                    .get("gasUsed")
                    .unwrap_or(&serde_json::Value::Null)
                    .as_str()
                    .unwrap_or("N/A")
            );
        } else {
            anyhow::bail!("Contract deployment failed");
        }
    } else if let Some(error) = result
        .get("error")
        .unwrap_or(&serde_json::Value::Null)
        .as_object()
    {
        anyhow::bail!(
            "Deployment failed: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Unexpected response from RPC");
    }

    Ok(())
}

async fn call_contract(
    config: &Config,
    address: &str,
    method: &str,
    args: Option<String>,
    account: Option<String>,
    value: String,
) -> Result<()> {
    println!("{}", format!("Calling {}...", method).cyan());

    // Parse method arguments
    let method_args = if let Some(args_str) = args {
        serde_json::from_str(&args_str).context("Invalid method arguments JSON")?
    } else {
        json!([])
    };

    // Encode method call
    let call_data = encode_method_call(method, method_args)?;

    // Get account
    let from_account = account
        .or(config.default_account.clone())
        .context("No account specified and no default account configured")?;

    // Parse value
    let value_wei = value.parse::<u128>().context("Invalid value")?;

    // Make RPC call
    let client = reqwest::Client::new();
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{
                "from": from_account,
                "to": address,
                "data": call_data,
                "value": format!("0x{:x}", value_wei),
                "gas": format!("0x{:x}", config.gas_limit),
                "gasPrice": format!("0x{:x}", config.gas_price),
            }],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(tx_hash) = result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_str()
    {
        println!("{}", "✓ Transaction sent".green());
        println!("Transaction: {}", tx_hash.cyan());

        // Wait for receipt
        println!("Waiting for confirmation...");

        let receipt = wait_for_receipt(config, tx_hash).await?;

        if receipt
            .get("status")
            .unwrap_or(&serde_json::Value::Null)
            .as_str()
            == Some("0x1")
        {
            println!("{}", "✓ Transaction successful".green().bold());
            println!(
                "Gas Used: {}",
                receipt
                    .get("gasUsed")
                    .unwrap_or(&serde_json::Value::Null)
                    .as_str()
                    .unwrap_or("N/A")
            );

            // Decode logs if any
            if let Some(logs) = receipt
                .get("logs")
                .unwrap_or(&serde_json::Value::Null)
                .as_array()
            {
                if !logs.is_empty() {
                    println!("\nEvents emitted:");
                    for log in logs {
                        if let Some(topics) = log["topics"].as_array() {
                            if let Some(topic0) = topics.first() {
                                println!("  Event: {}", topic0.as_str().unwrap_or("Unknown"));
                            }
                        }
                    }
                }
            }
        } else {
            anyhow::bail!("Transaction failed");
        }
    } else if let Some(error) = result
        .get("error")
        .unwrap_or(&serde_json::Value::Null)
        .as_object()
    {
        anyhow::bail!(
            "Call failed: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Unexpected response from RPC");
    }

    Ok(())
}

async fn read_contract(
    config: &Config,
    address: &str,
    method: &str,
    args: Option<String>,
) -> Result<()> {
    // Parse method arguments
    let method_args = if let Some(args_str) = args {
        serde_json::from_str(&args_str).context("Invalid method arguments JSON")?
    } else {
        json!([])
    };

    // Encode method call
    let call_data = encode_method_call(method, method_args)?;

    // Make RPC call (eth_call doesn't require from address)
    let client = reqwest::Client::new();
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{
                "to": address,
                "data": call_data,
            }, "latest"],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(data) = result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_str()
    {
        println!("{}", "Result:".bold());
        println!("Raw: {}", data);

        // Try to decode as common types
        if data.len() == 66 {
            // Possibly uint256
            if let Ok(value) = u128::from_str_radix(data.get(2..).unwrap_or_default(), 16) {
                println!("Decoded (uint): {}", value);
            }
        } else if data.len() == 42 {
            // Possibly address
            println!("Decoded (address): {}", data);
        } else if data.len() > 2 {
            // Try as string
            if let Ok(bytes) = hex::decode(data.get(2..).unwrap_or_default()) {
                if let Ok(text) = String::from_utf8(bytes.clone()) {
                    if text
                        .chars()
                        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                    {
                        println!("Decoded (string): {}", text.trim());
                    }
                }
            }
        }
    } else if let Some(error) = result
        .get("error")
        .unwrap_or(&serde_json::Value::Null)
        .as_object()
    {
        anyhow::bail!(
            "Call failed: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Unexpected response from RPC");
    }

    Ok(())
}

async fn get_contract_code(config: &Config, address: &str, output: Option<PathBuf>) -> Result<()> {
    // Make RPC call to get code
    let client = reqwest::Client::new();
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getCode",
            "params": [address, "latest"],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(code) = result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_str()
    {
        if code == "0x" {
            println!("{}", "No contract code at this address".yellow());
        } else {
            let code_bytes =
                hex::decode(code.get(2..).unwrap_or_default()).context("Invalid code format")?;

            println!("{}", "Contract code retrieved".green());
            println!("Size: {} bytes", code_bytes.len());

            if let Some(path) = output {
                fs::write(&path, &code_bytes)
                    .with_context(|| format!("Failed to write code to {:?}", path))?;
                println!("Code saved to: {:?}", path);
            } else {
                println!("\nBytecode (first 100 bytes):");
                println!("{}", code.get(..202).unwrap_or(code));
                if code.len() > 202 {
                    println!("... ({} more bytes)", (code.len().saturating_sub(202)) / 2);
                }
            }
        }
    } else if let Some(error) = result
        .get("error")
        .unwrap_or(&serde_json::Value::Null)
        .as_object()
    {
        anyhow::bail!(
            "Query failed: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Unexpected response from RPC");
    }

    Ok(())
}

fn poll_config(interval_ms: u64, timeout_secs: u64) -> verify::PollConfig {
    verify::PollConfig {
        interval: std::time::Duration::from_millis(interval_ms.max(1)),
        timeout: std::time::Duration::from_secs(timeout_secs),
        ..verify::PollConfig::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_source_submission(
    source: Option<PathBuf>,
    build_info: Option<PathBuf>,
    standard_json: Option<PathBuf>,
    contract: Option<&str>,
    compiler: Option<&str>,
    optimized: bool,
    runs: u32,
    evm_version: Option<String>,
    libraries: &[String],
) -> Result<verify::SourceSubmission> {
    if let Some(path) = build_info.or(standard_json) {
        if !libraries.is_empty() {
            anyhow::bail!("--library applies to single-file mode; a build-info carries its own settings.libraries");
        }
        let ci = verify::load_compilation_input(&path)?;
        let s = verify::prepare_standard_json(&ci, contract, compiler)?;
        return Ok(verify::SourceSubmission::StandardJson(s));
    }
    let Some(path) = source else {
        anyhow::bail!("give --build-info <file>, --standard-json <file>, or a source file");
    };
    let text = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read source file {:?}", path))?;
    let compiler = compiler.context("single-file mode needs --compiler v0.8.x+commit.<hash>")?;
    let contract_name = match contract {
        Some(c) => c.rsplit_once(':').map_or(c, |(_, n)| n).to_owned(),
        None => path
            .file_stem()
            .and_then(|s| s.to_str())
            .context("cannot derive the contract name; pass --contract")?
            .to_owned(),
    };
    let libraries = libraries
        .iter()
        .map(|l| verify::parse_library(l))
        .collect::<Result<Vec<_>>>()?;
    Ok(verify::SourceSubmission::SingleFile {
        source: text,
        contract_name,
        compiler_version: compiler.to_owned(),
        optimization_used: optimized,
        runs,
        evm_version,
        libraries,
    })
}

async fn verify_on_explorer(
    client: &verify::ExplorerClient,
    req: &verify::VerifyRequest,
    watch: bool,
    poll: &verify::PollConfig,
) -> Result<()> {
    let (name, version) = match &req.source {
        verify::SourceSubmission::StandardJson(s) => {
            (s.contract_name.as_str(), s.compiler_version.as_str())
        }
        verify::SourceSubmission::SingleFile {
            contract_name,
            compiler_version,
            ..
        } => (contract_name.as_str(), compiler_version.as_str()),
    };
    println!(
        "{} {} ({}, {}) via {}",
        "Submitting".cyan(),
        req.address,
        name,
        version,
        client.base_url()
    );
    let guid = match client.submit(req, poll).await {
        Ok(g) => g,
        Err(verify::VerifyError::AlreadyVerified(m)) => {
            println!("{} {}", "✓ Already verified:".green().bold(), m);
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    println!("GUID: {}", guid);
    if !watch {
        println!(
            "Check it with: citrate contract verify-status {} --explorer-url {} --watch",
            guid,
            client.base_url()
        );
        return Ok(());
    }
    let status = client.wait(&guid, poll).await?;
    report_status(&guid, &status)
}

fn report_status(guid: &str, status: &verify::VerifyStatus) -> Result<()> {
    match status {
        verify::VerifyStatus::Verified(m) => {
            println!("{} {}", "✓ Contract verified:".green().bold(), m);
            Ok(())
        }
        verify::VerifyStatus::Pending(m) => {
            println!("{} {} ({})", "… Pending:".yellow(), m, guid);
            Ok(())
        }
        verify::VerifyStatus::Failed(m) => anyhow::bail!("Verification failed: {m} (guid {guid})"),
    }
}

async fn show_verified_source(client: &verify::ExplorerClient, address: &str) -> Result<()> {
    let entry = client.get_source_code(address).await?;
    let field = |k: &str| {
        entry
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned()
    };
    if field("SourceCode").is_empty() {
        println!("No verified source on the explorer for {}", address);
        return Ok(());
    }
    println!("{}", "Verified source record:".bold());
    println!("Address: {}", address);
    println!("Contract: {}", field("ContractName"));
    println!("Compiler: {}", field("CompilerVersion"));
    println!("EVM version: {}", field("EVMVersion"));
    let similar = field("SimilarMatch");
    if !similar.is_empty() {
        println!("Similar match: {}", similar);
    }
    if field("Proxy") == "1" {
        println!("Proxy implementation: {}", field("Implementation"));
    }
    Ok(())
}

async fn list_verifications(config: &Config) -> Result<()> {
    let client = reqwest::Client::new();
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "citrate_listVerifications",
            "params": [],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let v: serde_json::Value = response.json().await?;
    if let Some(arr) = v
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_array()
    {
        println!("{} {}", arr.len(), "verification record(s)".bold());
        for rec in arr {
            if let Some(addr) = rec["address"].as_str() {
                let status = rec["verified"].as_bool().unwrap_or(false);
                println!("- {} (verified: {})", addr, status);
            }
        }
    } else {
        println!("No verification records found");
    }
    Ok(())
}

async fn wait_for_receipt(config: &Config, tx_hash: &str) -> Result<serde_json::Value> {
    let client = reqwest::Client::new();

    for _ in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let response = client
            .post(&config.rpc_endpoint)
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1
            }))
            .send()
            .await?;

        let result: serde_json::Value = response.json().await?;

        if let Some(receipt) = result
            .get("result")
            .unwrap_or(&serde_json::Value::Null)
            .as_object()
        {
            return Ok(json!(receipt));
        }
    }

    anyhow::bail!("Transaction receipt not found after 60 seconds");
}

fn encode_method_call(method_sig: &str, args: serde_json::Value) -> Result<String> {
    use anyhow::bail;
    use sha3::{Digest, Keccak256};

    // Compute 4-byte selector from full signature
    let mut hasher = Keccak256::new();
    hasher.update(method_sig.as_bytes());
    let [s0, s1, s2, s3, ..]: [u8; 32] = hasher.finalize().into();
    let selector = &[s0, s1, s2, s3][..];

    // Parse types from signature, e.g. "transfer(address,uint256)"
    let open = method_sig.find('(').context(
        "Invalid method signature: missing '
'",
    )?;
    let close = method_sig
        .rfind(')')
        .context("Invalid method signature: missing ')'")?;
    // `(` and `)` are ASCII, so open + 1 is a char boundary.
    let types_str = method_sig
        .get(open.saturating_add(1)..close)
        .context("Invalid method signature: ')' before '('")?;
    let types: Vec<String> = if types_str.trim().is_empty() {
        vec![]
    } else {
        types_str
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .collect()
    };

    // Args must be an array
    let args_arr = match args {
        serde_json::Value::Array(v) => v,
        serde_json::Value::Null => vec![],
        _ => bail!("Method arguments must be a JSON array"),
    };

    if args_arr.len() != types.len() {
        bail!(
            "Argument count mismatch: expected {}, got {}",
            types.len(),
            args_arr.len()
        );
    }

    // Encode static arguments (subset of ABI: address, uint{8,16,32,64,128,256}, bool, bytes32)
    let mut encoded: Vec<u8> = Vec::new();
    for (ty, val) in types.iter().zip(args_arr) {
        match ty.as_str() {
            // address: 20 bytes, left-padded to 32
            "address" => {
                let s = val.as_str().context("address must be a hex string")?;
                let hexstr = s.trim().trim_start_matches("0x");
                let bytes = hex::decode(hexstr).context("invalid address hex")?;
                if bytes.len() != 20 {
                    bail!("address must be 20 bytes (40 hex chars)");
                }
                let mut word = [0u8; 32];
                word[12..32].copy_from_slice(&bytes);
                encoded.extend_from_slice(&word);
            }
            // bool: 0 or 1 in last byte, left-padded
            "bool" => {
                let b = match val {
                    serde_json::Value::Bool(b) => b,
                    serde_json::Value::Number(n) => n.as_u64().unwrap_or(0) != 0,
                    serde_json::Value::String(s) => {
                        let sl = s.to_lowercase();
                        sl == "true" || sl == "1"
                    }
                    _ => bail!("bool must be true/false or 0/1"),
                };
                let mut word = [0u8; 32];
                if b {
                    word[31] = 1u8;
                }
                encoded.extend_from_slice(&word);
            }
            // bytes32: fixed 32 bytes (or shorter and right-padded with zeros)
            "bytes32" => {
                let s = val.as_str().context("bytes32 must be a hex string")?;
                let hexstr = s.trim().trim_start_matches("0x");
                let mut bytes = hex::decode(hexstr).context("invalid bytes32 hex")?;
                if bytes.len() > 32 {
                    bail!("bytes32 must be <= 32 bytes");
                }
                bytes.resize(32, 0u8);
                encoded.extend_from_slice(&bytes);
            }
            // uint types
            ty if ty.starts_with("uint") => {
                // Determine bit size (default 256)
                let bits: u16 = ty.get(4..).unwrap_or_default().parse().unwrap_or(256);
                if bits == 0 || !bits.is_multiple_of(8) || bits > 256 {
                    bail!("unsupported uint size: {}", bits);
                }
                // Accept number or hex string
                let mut word = [0u8; 32];
                match val {
                    serde_json::Value::Number(n) => {
                        // Encode as big-endian; support up to u128 directly
                        if let Some(u) = n.as_u64() {
                            let be = (u as u128).to_be_bytes();
                            word[16..32].copy_from_slice(&be);
                        } else {
                            // Fallback: parse string representation
                            bail!("uint must be a positive integer within u64 for now");
                        }
                    }
                    serde_json::Value::String(s) => {
                        let ss = s.trim();
                        if let Some(stripped) = ss.strip_prefix("0x") {
                            let bytes = hex::decode(stripped).context("invalid uint hex")?;
                            if bytes.len() > 32 {
                                bail!("uint hex too large (max 32 bytes)");
                            }
                            // bytes.len() <= 32 (checked above): right-align.
                            if let Some(dst) = word.get_mut(32usize.saturating_sub(bytes.len())..) {
                                dst.copy_from_slice(&bytes);
                            }
                        } else {
                            // Decimal string, parse into u128
                            let val = ss.parse::<u128>().context("invalid uint decimal string")?;
                            let be = val.to_be_bytes();
                            word[16..32].copy_from_slice(&be);
                        }
                    }
                    _ => bail!("uint must be a number or string (hex or decimal)"),
                }
                encoded.extend_from_slice(&word);
            }
            // unsupported dynamic types
            ty if ty == "string" || ty == "bytes" => {
                bail!("dynamic types (string, bytes) are not supported in this CLI encoder yet")
            }
            other => bail!("unsupported or unknown type in signature: {}", other),
        }
    }

    let mut out = Vec::with_capacity(encoded.len().saturating_add(4));
    out.extend_from_slice(selector);
    out.extend_from_slice(&encoded);
    Ok(format!("0x{}", hex::encode(out)))
}

#[cfg(test)]
mod tests {
    use super::encode_method_call;
    use sha3::{Digest, Keccak256};

    #[test]
    fn test_encode_transfer_address_uint256() {
        let addr = "0x1111111111111111111111111111111111111111";
        let json = serde_json::json!([addr, "1000"]);
        let sig = "transfer(address,uint256)";
        let out = encode_method_call(sig, json).expect("encode");

        // selector correctness
        let mut hasher = Keccak256::new();
        hasher.update(sig.as_bytes());
        let selector = hex::encode(&hasher.finalize()[..4]);
        assert!(out.starts_with(&format!("0x{}", selector)));

        // length = 4 bytes selector + 2 words
        // hex length: 2 chars per byte, plus 2 for '0x'
        let expected_hex_len = 2 + (4 + 32 + 32) * 2;
        assert_eq!(out.len(), expected_hex_len);

        // address should be right-padded in last 40 hex of the first word after selector
        // Skip '0x' + 8 selector hex = 10 chars; next 64 hex is first word
        let first_word_hex = &out[10..10 + 64];
        // last 40 of word equals address without 0x
        assert_eq!(&first_word_hex[24..], &addr[2..]);
    }

    #[test]
    fn test_encode_no_args() {
        let sig = "totalSupply()";
        let out = encode_method_call(sig, serde_json::json!([])).expect("encode");
        // Just selector, no args = 4 bytes = 8 hex + 2 prefix
        assert_eq!(out.len(), 2 + 4 * 2);
    }

    #[test]
    fn test_encode_arg_count_mismatch() {
        let sig = "transfer(address,uint256)";
        let result = encode_method_call(
            sig,
            serde_json::json!(["0x1111111111111111111111111111111111111111"]),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn test_encode_invalid_signature_no_parens() {
        let result = encode_method_call("noparens", serde_json::json!([]));
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_uint_from_number() {
        let sig = "setValue(uint256)";
        let out = encode_method_call(sig, serde_json::json!([42])).expect("encode");
        // selector + 1 word
        assert_eq!(out.len(), 2 + (4 + 32) * 2);
        // Last byte of the word should encode 42 = 0x2a
        assert!(out.ends_with("2a"));
    }

    #[test]
    fn test_encode_bool_false() {
        let sig = "setFlag(bool)";
        let out = encode_method_call(sig, serde_json::json!([false])).expect("encode");
        let bool_word = &out[10..10 + 64];
        assert!(bool_word.ends_with("00"));
    }

    #[test]
    fn test_encode_bool_and_bytes32() {
        let bytes32 = "0x".to_string() + &"aa".repeat(32);
        let json = serde_json::json!([true, bytes32]);
        let sig = "setFlagAndHash(bool,bytes32)";
        let out = encode_method_call(sig, json).expect("encode");

        // Expect selector + 2 words
        let expected_hex_len = 2 + (4 + 32 + 32) * 2;
        assert_eq!(out.len(), expected_hex_len);

        // Bool word ends with 01
        let bool_word = &out[10..10 + 64];
        assert!(bool_word.ends_with("01"));
    }
}
