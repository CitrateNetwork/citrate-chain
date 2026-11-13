//citrate/cli/src/commands/network.rs

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use serde_json::json;

use crate::config::Config;

#[derive(Subcommand)]
pub enum NetworkCommands {
    /// Get network status
    Status,

    /// Get current block information
    Block {
        /// Block number or "latest"
        #[arg(default_value = "latest")]
        block: String,
    },

    /// Get transaction details
    Transaction {
        /// Transaction hash
        tx_hash: String,
    },

    /// Get current gas price
    GasPrice,

    /// Get peer information
    Peers,

    /// Get sync status
    Sync,

    /// Get DAG statistics
    DagStats,

    /// A-10: Bootnode health diagnostics — ping each configured bootnode
    /// and report reachability. Requires bootnode list from config file or
    /// --bootnodes flag.
    Bootnodes {
        /// Comma-separated list of bootnode addresses (ip:port or identity@ip:port)
        #[arg(long)]
        bootnodes: Option<String>,

        /// Timeout per bootnode in milliseconds
        #[arg(long, default_value = "3000")]
        timeout_ms: u64,
    },
}

pub async fn execute(cmd: NetworkCommands, config: &Config) -> Result<()> {
    match cmd {
        NetworkCommands::Status => get_status(config).await?,
        NetworkCommands::Block { block } => get_block(config, &block).await?,
        NetworkCommands::Transaction { tx_hash } => get_transaction(config, &tx_hash).await?,
        NetworkCommands::GasPrice => get_gas_price(config).await?,
        NetworkCommands::Peers => get_peers(config).await?,
        NetworkCommands::Sync => get_sync_status(config).await?,
        NetworkCommands::DagStats => get_dag_stats(config).await?,
        NetworkCommands::Bootnodes {
            bootnodes,
            timeout_ms,
        } => {
            check_bootnodes(bootnodes, timeout_ms).await?;
        }
    }
    Ok(())
}

/// A-10: Check reachability of every configured bootnode.
/// This is a standalone TCP ping — it does not require the local node to be running.
/// Operators use it for pilot rollout validation and failover debugging.
async fn check_bootnodes(bootnodes_arg: Option<String>, timeout_ms: u64) -> Result<()> {
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let list: Vec<String> = if let Some(s) = bootnodes_arg {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    } else {
        // Fall back to reading from CITRATE_BOOTNODES env var or a default config
        match std::env::var("CITRATE_BOOTNODES") {
            Ok(s) => s
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect(),
            Err(_) => {
                anyhow::bail!(
                    "No bootnodes specified. Use --bootnodes <list> or set CITRATE_BOOTNODES env var."
                );
            }
        }
    };

    if list.is_empty() {
        anyhow::bail!("Bootnode list is empty");
    }

    println!(
        "{}",
        format!(
            "Checking {} bootnodes (timeout: {}ms)",
            list.len(),
            timeout_ms
        )
        .bold()
    );
    println!();

    let mut reachable = 0usize;
    let mut unreachable = 0usize;
    let timeout_dur = Duration::from_millis(timeout_ms);

    for bootnode in &list {
        // Strip identity prefix (noise_abc@host:port -> host:port)
        let addr_str = bootnode
            .split_once('@')
            .map(|(_, rest)| rest)
            .unwrap_or(bootnode);

        // Try to parse as SocketAddr first; if that fails, try hostname resolution
        let socket_addrs: Vec<std::net::SocketAddr> = if let Ok(addr) = addr_str.parse() {
            vec![addr]
        } else {
            match tokio::net::lookup_host(addr_str).await {
                Ok(iter) => iter.collect(),
                Err(e) => {
                    println!(
                        "  {} {}: DNS resolution failed ({})",
                        "✗".red(),
                        bootnode,
                        e
                    );
                    unreachable = unreachable.saturating_add(1);
                    continue;
                }
            }
        };

        if socket_addrs.is_empty() {
            println!("  {} {}: no addresses", "✗".red(), bootnode);
            unreachable = unreachable.saturating_add(1);
            continue;
        }

        // Try each resolved address
        let mut connected = false;
        for addr in &socket_addrs {
            match timeout(timeout_dur, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => {
                    println!("  {} {} ({})", "✓".green(), bootnode, addr);
                    connected = true;
                    reachable = reachable.saturating_add(1);
                    break;
                }
                Ok(Err(e)) => {
                    // Connection refused / reset
                    println!("  {} {} ({}): {}", "✗".red(), bootnode, addr, e);
                }
                Err(_) => {
                    println!(
                        "  {} {} ({}): timeout after {}ms",
                        "✗".red(),
                        bootnode,
                        addr,
                        timeout_ms
                    );
                }
            }
        }

        if !connected {
            unreachable = unreachable.saturating_add(1);
        }
    }

    println!();
    println!("{}", "Summary:".bold());
    println!("  Reachable:   {}/{}", reachable, list.len());
    println!("  Unreachable: {}/{}", unreachable, list.len());

    if reachable == 0 {
        anyhow::bail!("No bootnodes are reachable — node will not bootstrap");
    } else if unreachable > 0 {
        println!();
        println!(
            "  {} {} of {} bootnodes unreachable — failover may be degraded",
            "⚠".yellow(),
            unreachable,
            list.len()
        );
    } else {
        println!();
        println!("  {} All bootnodes reachable", "✓".green());
    }

    Ok(())
}

async fn get_status(config: &Config) -> Result<()> {
    let client = reqwest::Client::new();

    // Get network ID
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "net_version",
            "params": [],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;
    let network_id = result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_str()
        .unwrap_or("Unknown");

    // Get latest block
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        }))
        .send()
        .await?;

    let result: serde_json::Value = response.json().await?;
    let block_number = if let Some(hex) = result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_str()
    {
        u64::from_str_radix(hex.get(2..).unwrap_or_default(), 16).unwrap_or(0)
    } else {
        0
    };

    // Get syncing status
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_syncing",
            "params": [],
            "id": 1
        }))
        .send()
        .await?;

    let result: serde_json::Value = response.json().await?;
    let syncing = !result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .is_boolean();

    // Which chain this endpoint serves: eth_chainId and the hash of block 0.
    let node_chain_id = rpc_result(&client, config, "eth_chainId", json!([]))
        .await
        .and_then(|v| v.as_str().map(str::to_string))
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
    let node_genesis = rpc_result(
        &client,
        config,
        "eth_getBlockByNumber",
        json!(["0x0", false]),
    )
    .await
    .and_then(|b| b.get("hash").and_then(|h| h.as_str()).map(str::to_string));

    println!("{}", "Network Status:".bold());
    println!("RPC Endpoint: {}", config.rpc_endpoint.cyan());
    println!("Network ID: {}", network_id);
    for line in super::rpc_hint::chain_lines(
        node_chain_id,
        config.chain_id,
        node_genesis.as_deref(),
        super::devx::vendored_genesis_hash().as_deref(),
    ) {
        if line.starts_with("WARNING") {
            println!("{}", line.yellow());
        } else {
            println!("{}", line);
        }
    }
    println!("Latest Block: {}", block_number);
    println!(
        "Syncing: {}",
        if syncing {
            "Yes".yellow()
        } else {
            "No (synced)".green()
        }
    );

    Ok(())
}

/// One JSON-RPC call; `None` on a transport error, an error reply or a null result.
async fn rpc_result(
    client: &reqwest::Client,
    config: &Config,
    method: &str,
    params: serde_json::Value,
) -> Option<serde_json::Value> {
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({ "jsonrpc": "2.0", "method": method, "params": params, "id": 1 }))
        .send()
        .await
        .ok()?;
    let body: serde_json::Value = response.json().await.ok()?;
    body.get("result").filter(|v| !v.is_null()).cloned()
}

async fn get_block(config: &Config, block: &str) -> Result<()> {
    let client = reqwest::Client::new();

    let block_param = if block == "latest" {
        "latest".to_string()
    } else if block.starts_with("0x") {
        block.to_string()
    } else {
        format!(
            "0x{:x}",
            block.parse::<u64>().context("Invalid block number")?
        )
    };

    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [block_param, true],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(block) = result.get("result").filter(|v| v.is_object()) {
        println!("{}", "Block Information:".bold());
        print!("{}", render_block(block));
    } else if let Some(error) = result.get("error").filter(|v| v.is_object()) {
        anyhow::bail!(
            "Query failed: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Block not found");
    }

    Ok(())
}

/// The block summary `network block` prints, one line per field.
///
/// `block` is the `eth_getBlockByNumber` result. It is indexed as a `Value`, so a
/// field the node does not send reads as null and prints a placeholder instead
/// of panicking.
fn render_block(block: &serde_json::Value) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "Number: {}",
        u64::from_str_radix(
            block["number"]
                .as_str()
                .unwrap_or("0x0")
                .trim_start_matches("0x"),
            16
        )
        .unwrap_or(0)
    ));
    lines.push(format!("Hash: {}", block["hash"].as_str().unwrap_or("N/A")));
    lines.push(format!(
        "Parent: {}",
        block["parentHash"].as_str().unwrap_or("N/A")
    ));
    lines.push(format!(
        "Timestamp: {}",
        u64::from_str_radix(
            block["timestamp"]
                .as_str()
                .unwrap_or("0x0")
                .trim_start_matches("0x"),
            16
        )
        .unwrap_or(0)
    ));
    lines.push(format!(
        "Miner: {}",
        block["miner"].as_str().unwrap_or("N/A")
    ));

    if let Some(txs) = block["transactions"].as_array() {
        lines.push(format!("Transactions: {}", txs.len()));

        if !txs.is_empty() && txs.len() <= 5 {
            lines.push("\nTransactions:".to_string());
            for tx in txs {
                if let Some(hash) = tx["hash"].as_str() {
                    lines.push(format!("  • {}", hash));
                }
            }
        } else if txs.len() > 5 {
            lines.push("  (showing first 5)".to_string());
            for tx in txs.iter().take(5) {
                if let Some(hash) = tx["hash"].as_str() {
                    lines.push(format!("  • {}", hash));
                }
            }
            lines.push(format!("  ... and {} more", txs.len().saturating_sub(5)));
        }
    }

    // GhostDAG specific fields. The node sends `mergeParentHashes`; older
    // nodes sent `mergeParents`.
    let merge_parents = block["mergeParentHashes"]
        .as_array()
        .or_else(|| block["mergeParents"].as_array());
    if let Some(merge_parents) = merge_parents {
        if !merge_parents.is_empty() {
            lines.push(format!("\nGhostDAG Merge Parents: {}", merge_parents.len()));
            for parent in merge_parents.iter().take(3) {
                if let Some(hash) = parent.as_str() {
                    lines.push(format!("  • {}", hash));
                }
            }
        }
    }

    // `blueScore` is a hex quantity like every other number in the response.
    let blue_score = block["blueScore"].as_u64().or_else(|| {
        block["blueScore"]
            .as_str()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    });
    if let Some(blue_score) = blue_score {
        lines.push(format!("Blue Score: {}", blue_score));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

async fn get_transaction(config: &Config, tx_hash: &str) -> Result<()> {
    let client = reqwest::Client::new();

    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionByHash",
            "params": [tx_hash],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(tx) = result.get("result").filter(|v| v.is_object()) {
        println!("{}", "Transaction Details:".bold());
        println!("Hash: {}", tx["hash"].as_str().unwrap_or("N/A").cyan());
        println!("From: {}", tx["from"].as_str().unwrap_or("N/A"));
        println!("To: {}", tx["to"].as_str().unwrap_or("(Contract Creation)"));

        if let Some(value_hex) = tx["value"].as_str() {
            let value = u128::from_str_radix(value_hex.trim_start_matches("0x"), 16).unwrap_or(0);
            println!("Value: {} wei ({} SALT)", value, value as f64 / 1e18);
        }

        println!(
            "Nonce: {}",
            u64::from_str_radix(
                tx["nonce"]
                    .as_str()
                    .unwrap_or("0x0")
                    .trim_start_matches("0x"),
                16
            )
            .unwrap_or(0)
        );

        println!(
            "Gas Price: {} gwei",
            u64::from_str_radix(
                tx["gasPrice"]
                    .as_str()
                    .unwrap_or("0x0")
                    .trim_start_matches("0x"),
                16
            )
            .unwrap_or(0)
                / 1_000_000_000
        );

        println!(
            "Gas Limit: {}",
            u64::from_str_radix(
                tx["gas"].as_str().unwrap_or("0x0").trim_start_matches("0x"),
                16
            )
            .unwrap_or(0)
        );

        if let Some(block_number) = tx["blockNumber"].as_str() {
            println!(
                "Block: {}",
                u64::from_str_radix(block_number.trim_start_matches("0x"), 16).unwrap_or(0)
            );
        } else {
            println!("Status: {}", "Pending".yellow());
        }

        // Get receipt if transaction is mined
        if tx["blockNumber"].is_string() {
            let receipt_response = client
                .post(&config.rpc_endpoint)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "method": "eth_getTransactionReceipt",
                    "params": [tx_hash],
                    "id": 1
                }))
                .send()
                .await?;

            let receipt_result: serde_json::Value = receipt_response.json().await?;

            if let Some(receipt) = receipt_result.get("result").filter(|v| v.is_object()) {
                println!("\nReceipt:");

                let status = receipt["status"].as_str().unwrap_or("0x0");
                if status == "0x1" {
                    println!("  Status: {}", "Success".green());
                } else {
                    println!("  Status: {}", "Failed".red());
                }

                println!(
                    "  Gas Used: {}",
                    u64::from_str_radix(
                        receipt["gasUsed"]
                            .as_str()
                            .unwrap_or("0x0")
                            .trim_start_matches("0x"),
                        16
                    )
                    .unwrap_or(0)
                );

                if let Some(contract_address) = receipt["contractAddress"].as_str() {
                    if contract_address != "null" {
                        println!("  Contract Created: {}", contract_address.cyan());
                    }
                }

                if let Some(logs) = receipt["logs"].as_array() {
                    if !logs.is_empty() {
                        println!("  Events: {} emitted", logs.len());
                    }
                }
            }
        }
    } else if let Some(error) = result.get("error").filter(|v| v.is_object()) {
        anyhow::bail!(
            "Query failed: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Transaction not found");
    }

    Ok(())
}

async fn get_gas_price(config: &Config) -> Result<()> {
    let client = reqwest::Client::new();

    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_gasPrice",
            "params": [],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(price_hex) = result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_str()
    {
        let price = u64::from_str_radix(price_hex.trim_start_matches("0x"), 16).unwrap_or(0);

        println!("{}", "Current Gas Price:".bold());
        println!("  {} wei", price);
        println!("  {} gwei", price as f64 / 1e9);
        println!("  {} SALT", price as f64 / 1e18);
    } else if let Some(error) = result.get("error").filter(|v| v.is_object()) {
        anyhow::bail!(
            "Query failed: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Unexpected response");
    }

    Ok(())
}

async fn get_peers(config: &Config) -> Result<()> {
    let client = reqwest::Client::new();

    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "net_peerCount",
            "params": [],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(count_hex) = result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_str()
    {
        let count = u64::from_str_radix(count_hex.trim_start_matches("0x"), 16).unwrap_or(0);

        println!("{}", "Network Peers:".bold());
        println!("Connected Peers: {}", count);

        // Try to get more detailed peer info
        let response = client
            .post(&config.rpc_endpoint)
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "admin_peers",
                "params": [],
                "id": 1
            }))
            .send()
            .await;

        if let Ok(response) = response {
            let result: serde_json::Value = response.json().await?;

            if let Some(peers) = result
                .get("result")
                .unwrap_or(&serde_json::Value::Null)
                .as_array()
            {
                if !peers.is_empty() {
                    println!("\nPeer Details:");
                    for (i, peer) in peers.iter().take(5).enumerate() {
                        if let Some(enode) = peer["enode"].as_str() {
                            println!(
                                "  {}. {}",
                                i.saturating_add(1),
                                enode.get(..60).unwrap_or(enode)
                            );
                        }
                    }

                    if peers.len() > 5 {
                        println!("  ... and {} more", peers.len().saturating_sub(5));
                    }
                }
            }
        }
    } else if let Some(error) = result.get("error").filter(|v| v.is_object()) {
        anyhow::bail!(
            "Query failed: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Unexpected response");
    }

    Ok(())
}

async fn get_sync_status(config: &Config) -> Result<()> {
    let client = reqwest::Client::new();

    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_syncing",
            "params": [],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(sync) = result.get("result").filter(|v| v.is_object()) {
        println!("{}", "Sync Status: SYNCING".yellow().bold());

        if let Some(current) = sync["currentBlock"].as_str() {
            let current = u64::from_str_radix(current.trim_start_matches("0x"), 16).unwrap_or(0);
            println!("Current Block: {}", current);
        }

        if let Some(highest) = sync["highestBlock"].as_str() {
            let highest = u64::from_str_radix(highest.trim_start_matches("0x"), 16).unwrap_or(0);
            println!("Highest Block: {}", highest);
        }

        if let (Some(current), Some(highest)) =
            (sync["currentBlock"].as_str(), sync["highestBlock"].as_str())
        {
            let current = u64::from_str_radix(current.trim_start_matches("0x"), 16).unwrap_or(0);
            let highest = u64::from_str_radix(highest.trim_start_matches("0x"), 16).unwrap_or(1);
            let progress = (current as f64 / highest as f64) * 100.0;

            println!("Progress: {:.2}%", progress);

            // Progress bar
            let bar_width = 40;
            // current can exceed `highest` momentarily; clamp so the bar never underflows.
            let filled = ((progress / 100.0 * bar_width as f64) as usize).min(bar_width);
            let bar = "█".repeat(filled) + &"░".repeat(bar_width.saturating_sub(filled));
            println!("[{}]", bar);
        }
    } else if result
        .get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_bool()
        == Some(false)
    {
        println!("{}", "Sync Status: SYNCED".green().bold());
        println!("Node is fully synchronized with the network");
    } else if let Some(error) = result.get("error").filter(|v| v.is_object()) {
        anyhow::bail!(
            "Query failed: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Unexpected response");
    }

    Ok(())
}

async fn get_dag_stats(config: &Config) -> Result<()> {
    let client = reqwest::Client::new();

    // Custom Citrate RPC method for DAG statistics
    let response = client
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "citrate_getDagStats",
            "params": [],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(stats) = result.get("result").filter(|v| v.is_object()) {
        println!("{}", "DAG Statistics:".bold());
        // A null field is one the node does not track (citrate_getDagStats);
        // show it as such instead of as 0.
        let field = |key: &str| {
            stats
                .get(key)
                .and_then(|v| v.as_u64())
                .map_or_else(|| "not tracked".to_string(), |n| n.to_string())
        };
        println!("Height: {}", field("height"));
        println!("Total Blocks: {}", field("totalBlocks"));
        println!("Blue Blocks: {}", field("blueBlocks"));
        println!("Red Blocks: {}", field("redBlocks"));
        println!("Tips Count: {}", field("tipsCount"));
        println!("Max Blue Score: {}", field("maxBlueScore"));

        if let Some(tips) = stats["currentTips"].as_array() {
            if !tips.is_empty() {
                println!("\nCurrent Tips:");
                for (i, tip) in tips.iter().take(3).enumerate() {
                    if let Some(hash) = tip.as_str() {
                        println!("  {}. {}", i.saturating_add(1), hash);
                    }
                }

                if tips.len() > 3 {
                    println!("  ... and {} more", tips.len().saturating_sub(3));
                }
            }
        }
    } else if let Some(error) = result.get("error").filter(|v| v.is_object()) {
        // Method might not be available
        if error["message"]
            .as_str()
            .unwrap_or("")
            .contains("not found")
        {
            println!(
                "{}",
                "DAG statistics not available (custom RPC method)".yellow()
            );
            println!("This feature requires a Citrate v3 node with GhostDAG support");
        } else {
            anyhow::bail!(
                "Query failed: {}",
                error["message"].as_str().unwrap_or("Unknown error")
            );
        }
    } else {
        anyhow::bail!("Unexpected response");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::render_block;

    /// Block 7059 of the live r1007 chain (genesis 0xcf686345…), fetched with
    /// `eth_getBlockByNumber("0x1b93", true)` from https://rpc.citrate.ai on 2026-11-12.
    /// It holds one native self-transfer. The node names the merge parents
    /// `mergeParentHashes` and sends `blueScore` as a hex string.
    const R1007_BLOCK_7059: &str = include_str!("../../tests/fixtures/r1007_block_7059.json");

    fn block() -> serde_json::Value {
        match serde_json::from_str::<serde_json::Value>(R1007_BLOCK_7059) {
            Ok(v) if v.is_object() => v,
            other => panic!("fixture is not a JSON object: {other:?}"),
        }
    }

    #[test]
    fn renders_a_live_r1007_block_without_panicking() {
        let out = render_block(&block());
        assert!(out.contains("Number: 7059"), "{out}");
        assert!(
            out.contains(
                "Hash: 0xeb9174b8db765758bb4a807f9a10e608f324268b630b6ba21cc0fc743eb6669d"
            ),
            "{out}"
        );
        assert!(out.contains("Transactions: 1"), "{out}");
        assert!(
            out.contains("0x4f26db08ecb21144dcdc0080967292085031340b846842ef15b606f6024b3c55"),
            "{out}"
        );
    }

    #[test]
    fn shows_the_merge_parents_and_blue_score_the_node_sends() {
        let b = block();
        let parents = b
            .get("mergeParentHashes")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let blue = b
            .get("blueScore")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(u64::MAX);
        let out = render_block(&b);
        if parents > 0 {
            assert!(
                out.contains(&format!("GhostDAG Merge Parents: {parents}")),
                "{out}"
            );
        }
        assert!(out.contains(&format!("Blue Score: {blue}")), "{out}");
    }

    #[test]
    fn a_block_with_only_a_number_renders_placeholders() {
        let b = serde_json::json!({ "number": "0x2a" });
        let out = render_block(&b);
        assert!(out.contains("Number: 42"), "{out}");
        assert!(out.contains("Hash: N/A"), "{out}");
    }
}
