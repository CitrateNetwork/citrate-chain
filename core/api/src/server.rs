// citrate/core/api/src/server.rs

use crate::filter::FilterRegistry;
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::{ai_rpc, economics_rpc, eth_rpc};
use crate::methods::{
    mempool::PendingQuery, AiApi, ChainApi, MempoolApi, NetworkApi, StateApi, TransactionApi,
};
use crate::metrics::rpc_request;
use crate::types::{
    error::ApiError,
    request::{BlockId, CallRequest},
};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::executor::block_on;
use jsonrpc_core::{IoHandler, Params, Value};
use jsonrpc_http_server::CloseHandle;
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use citrate_consensus::types::Hash;
use citrate_execution::executor::Executor;
use citrate_execution::types::{AccessPolicy, Address};
use citrate_network::peer::PeerManager;
use citrate_sequencer::mempool::Mempool;
use citrate_storage::StorageManager;
use once_cell::sync::Lazy;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use tracing::{info, warn};

/// S-01 FIX: Require operator authentication for model mutation endpoints.
///
/// Checks the `operator_token` parameter in the RPC request against the
/// `CITRATE_OPERATOR_TOKEN` environment variable. If no env var is set AND
/// no token is provided, the request is REJECTED (fail-closed).
///
/// Data source: `CITRATE_OPERATOR_TOKEN` environment variable.
///
/// `pub(crate)` so other modules in this crate (e.g., `eth_rpc.rs`) can
/// gate operator-only endpoints — RM-B1 / WP-C1.1 (audit H-API-01)
/// uses this for `citrate_getMempoolSnapshot`.
pub(crate) fn require_operator_auth(params: &serde_json::Map<String, Value>) -> Result<(), jsonrpc_core::Error> {
    let configured_token = std::env::var("CITRATE_OPERATOR_TOKEN").ok().filter(|t| !t.is_empty());
    let supplied_token = params.get("operator_token").and_then(|v| v.as_str());

    match (configured_token, supplied_token) {
        (Some(expected), Some(provided)) if provided == expected => Ok(()),
        (Some(_), Some(_)) => {
            warn!("operator auth failed: invalid operator_token");
            Err(jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::ServerError(-32001),
                message: "Unauthorized: invalid operator_token".to_string(),
                data: None,
            })
        }
        (Some(_), None) => {
            Err(jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::ServerError(-32001),
                message: "Unauthorized: operator_token required. Set CITRATE_OPERATOR_TOKEN and provide it in the request.".to_string(),
                data: None,
            })
        }
        (None, _) => {
            Err(jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::ServerError(-32001),
                message: "Unauthorized: CITRATE_OPERATOR_TOKEN not configured — model mutation operations are disabled. Set the environment variable to enable.".to_string(),
                data: None,
            })
        }
    }
}

/// Helper function to parse optional u64 field from JSON Value
fn parse_optional_u64_field(value: Option<&Value>, field_name: &str) -> Result<Option<u64>, jsonrpc_core::Error> {
    match value {
        Some(Value::String(s)) => {
            let trimmed = s.trim_start_matches("0x");
            u64::from_str_radix(trimmed, 16)
                .map(Some)
                .map_err(|_| jsonrpc_core::Error::invalid_params(format!("Invalid {} format", field_name)))
        }
        Some(Value::Number(n)) => {
            n.as_u64()
                .map(Some)
                .ok_or_else(|| jsonrpc_core::Error::invalid_params(format!("Invalid {} number", field_name)))
        }
        Some(_) => Err(jsonrpc_core::Error::invalid_params(format!("{} must be string or number", field_name))),
        None => Ok(None),
    }
}

/// Upload data to IPFS from a sync (non-tokio) context.
/// Spawns a dedicated thread with its own tokio runtime and reqwest client
/// to avoid deadlocking the jsonrpc-http-server's internal tokio runtime.
fn ipfs_add_blocking(data: Vec<u8>) -> Result<String, String> {
    let api_base = std::env::var("CITRATE_IPFS_PROVIDERS")
        .ok()
        .and_then(|list| list.split(',').next().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:5001".to_string());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime error: {}", e))?;
        rt.block_on(async {
            let client = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(3))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| format!("client error: {}", e))?;
            let url = format!("{}/api/v0/add?pin=true", api_base);
            let part = reqwest::multipart::Part::bytes(data).file_name("artifact.bin");
            let form = reqwest::multipart::Form::new().part("file", part);
            let resp = client.post(&url).multipart(form).send().await
                .map_err(|e| format!("IPFS upload error: {}", e))?;
            if !resp.status().is_success() {
                return Err(format!("IPFS status: {}", resp.status()));
            }
            let json: serde_json::Value = resp.json().await
                .map_err(|e| format!("IPFS parse error: {}", e))?;
            let cid = json["Hash"].as_str().unwrap_or("").to_string();
            if cid.is_empty() {
                return Err("IPFS returned empty CID".to_string());
            }
            Ok(cid)
        })
    })
    .join()
    .map_err(|_| "IPFS upload thread panicked".to_string())?
}

/// Pin artifact on IPFS from a sync context.
fn ipfs_pin_blocking(cid: &str) -> Result<(), String> {
    let api_base = std::env::var("CITRATE_IPFS_PROVIDERS")
        .ok()
        .and_then(|list| list.split(',').next().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:5001".to_string());
    let cid_owned = cid.to_string();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime error: {}", e))?;
        rt.block_on(async {
            let client = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(3))
                .timeout(std::time::Duration::from_secs(8))
                .build()
                .map_err(|e| format!("client error: {}", e))?;
            let url = format!("{}/api/v0/pin/add?arg={}&timeout=5s", api_base, cid_owned);
            let resp = client.post(&url).send().await
                .map_err(|e| format!("IPFS pin error: {}", e))?;
            if !resp.status().is_success() {
                return Err(format!("IPFS pin status: {}", resp.status()));
            }
            Ok(())
        })
    })
    .join()
    .map_err(|_| "IPFS pin thread panicked".to_string())?
}

/// Get artifact status from IPFS from a sync context.
fn ipfs_status_blocking(cid: &str) -> Result<String, String> {
    let api_base = std::env::var("CITRATE_IPFS_PROVIDERS")
        .ok()
        .and_then(|list| list.split(',').next().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:5001".to_string());
    let cid_owned = cid.to_string();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime error: {}", e))?;
        rt.block_on(async {
            let client = reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(3))
                .timeout(std::time::Duration::from_secs(8))
                .build()
                .map_err(|e| format!("client error: {}", e))?;
            let url = format!("{}/api/v0/pin/ls?arg={}", api_base, cid_owned);
            let status = match client.post(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.text().await {
                        Ok(body) if body.contains(&cid_owned) => "pinned",
                        _ => "unpinned",
                    }
                }
                _ => "unknown",
            };
            Ok(serde_json::json!([{"provider": api_base, "status": status}]).to_string())
        })
    })
    .join()
    .map_err(|_| "IPFS status thread panicked".to_string())?
}

// In-memory verification store (address -> record)
static VERIFICATIONS: Lazy<StdRwLock<HashMap<String, serde_json::Value>>> =
    Lazy::new(|| StdRwLock::new(HashMap::new()));

/// Helper: parse optional pagination from params object
fn parse_pagination(obj: &serde_json::Map<String, serde_json::Value>) -> (usize, Option<usize>) {
    let offset = obj.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let limit = obj
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    (offset, limit)
}

fn params_object_or_first_object(params: Params) -> serde_json::Map<String, Value> {
    match params {
        Params::Map(map) => map,
        Params::None => serde_json::Map::new(),
        Params::Array(arr) => {
            if let Some(Value::Object(map)) = arr.into_iter().next() {
                map
            } else {
                serde_json::Map::new()
            }
        }
    }
}

fn access_policy_to_json(policy: &AccessPolicy) -> serde_json::Value {
    match policy {
        AccessPolicy::Public => json!({ "type": "public" }),
        AccessPolicy::Private => json!({ "type": "private" }),
        AccessPolicy::Restricted(addresses) => json!({
            "type": "restricted",
            "allowed": addresses.iter().map(|addr| format!("0x{}", hex::encode(addr.0))).collect::<Vec<_>>()
        }),
        AccessPolicy::PayPerUse { fee } => json!({
            "type": "payPerUse",
            "fee": fee.to_string()
        }),
    }
}

/// Helper: slice with offset/limit
fn apply_pagination<T: Clone>(mut items: Vec<T>, offset: usize, limit: Option<usize>) -> Vec<T> {
    if offset > 0 {
        items = items.into_iter().skip(offset).collect();
    }
    if let Some(l) = limit {
        items.truncate(l);
    }
    items
}

// REM-13b (2026-05-20): collapsed two identical feature-gated and
// ungated variants of this function into one. The previous
// `verifier-ethers-solc` feature gate has been removed entirely
// (see core/api/Cargo.toml for rationale). Both variants
// delegated to `compile_runtime_bytecode_external`, which is the
// production path.
fn compile_runtime_bytecode(
    source: &str,
    _compiler: &str,
    optimized: bool,
    contract_name: Option<&str>,
) -> Result<Vec<u8>, String> {
    compile_runtime_bytecode_external(source, optimized, contract_name)
}

fn compile_runtime_bytecode_external(
    source: &str,
    optimized: bool,
    contract_name: Option<&str>,
) -> Result<Vec<u8>, String> {
    use std::fs::{self, File};
    use std::io::Write;
    use std::process::Command;
    // Prepare temp directory and file
    let dir = std::env::temp_dir().join(format!("citrate_verify_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).map_err(|e| e.to_string())?;
    let path = src_dir.join("Contract.sol");
    let mut f = File::create(&path).map_err(|e| e.to_string())?;
    f.write_all(source.as_bytes()).map_err(|e| e.to_string())?;

    // Build solc args
    let path_lossy = path.to_string_lossy().to_string();
    let mut args = vec!["--combined-json", "abi,bin,bin-runtime", &path_lossy];
    if optimized {
        args.splice(0..0, ["--optimize"]);
    }

    let out = Command::new("solc")
        .args(&args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("solc failed: {}", stderr));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).map_err(|e| e.to_string())?;
    let contracts = v
        .get("contracts")
        .and_then(|c| c.as_object())
        .ok_or("no contracts in output")?;
    // Find entry
    let mut binrt_opt: Option<String> = None;
    if let Some(name) = contract_name {
        for (k, val) in contracts {
            if k.ends_with(&format!(":{}", name)) {
                binrt_opt = val
                    .get("bin-runtime")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string());
                break;
            }
        }
    }
    if binrt_opt.is_none() {
        if let Some((_k, val)) = contracts.iter().next() {
            binrt_opt = val
                .get("bin-runtime")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());
        }
    }
    let binrt = binrt_opt.ok_or("missing bin-runtime")?;
    let s = binrt.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| e.to_string())
}

/// Compile using solc --standard-json. Returns (creation, runtime) bytecode for a selected contract.
/// If `contract_name` is Some, selects that contract name (matches suffix after ':'). Otherwise first found.
fn compile_standard_json(
    standard_json: &str,
    contract_name: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use std::process::Command;
    let mut child = Command::new("solc")
        .arg("--standard-json")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().ok_or("failed to open stdin")?;
        stdin
            .write_all(standard_json.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "solc --standard-json failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    let contracts = v
        .get("contracts")
        .and_then(|c| c.as_object())
        .ok_or("no contracts in output")?;
    let mut chosen: Option<(Vec<u8>, Vec<u8>)> = None;
    for (_file, obj) in contracts.iter() {
        let cmap = match obj.as_object() {
            Some(m) => m,
            None => continue,
        };
        for (name, art) in cmap.iter() {
            let matches = match contract_name {
                Some(n) => name == n,
                None => true,
            };
            if !matches {
                continue;
            }
            // creation bytecode
            let bytecode_obj = art
                .get("evm")
                .and_then(|e| e.get("bytecode"))
                .and_then(|b| b.get("object"))
                .and_then(|s| s.as_str());
            // runtime bytecode
            let deployed_obj = art
                .get("evm")
                .and_then(|e| e.get("deployedBytecode"))
                .and_then(|b| b.get("object"))
                .and_then(|s| s.as_str());
            if let (Some(c), Some(r)) = (bytecode_obj, deployed_obj) {
                let c_hex = c.trim().trim_start_matches("0x");
                let r_hex = r.trim().trim_start_matches("0x");
                let cbytes = hex::decode(c_hex).map_err(|e| e.to_string())?;
                let rbytes = hex::decode(r_hex).map_err(|e| e.to_string())?;
                chosen = Some((cbytes, rbytes));
                break;
            }
        }
        if chosen.is_some() {
            break;
        }
    }
    chosen.ok_or_else(|| format!("contract not found in output: {:?}", contract_name))
}

/// RPC Server configuration
#[derive(Clone)]
pub struct RpcConfig {
    pub listen_addr: SocketAddr,
    pub max_connections: u32,
    /// Configurable CORS origins (WP-X.1).
    /// Empty = no CORS headers. ["*"] = wildcard. Otherwise, explicit allowlist.
    pub cors_origins: Vec<String>,
    pub threads: usize,
    pub rate_limit: RateLimitConfig,
    /// Allow eth_sendTransaction (unsigned, arbitrary-from transactions).
    /// SECURITY: Must only be true in devnet/dev mode. In production, clients
    /// must use eth_sendRawTransaction with a proper signature. (C-02)
    pub allow_eth_send_transaction: bool,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8545".parse().unwrap_or_else(|e| panic!("valid hardcoded address: {e}")),
            max_connections: 100,
            // C-02 FIX: No wildcard CORS by default — prevents browser-to-localhost abuse
            cors_origins: vec!["http://localhost:*".to_string()],
            threads: 4,
            rate_limit: RateLimitConfig::default(),
            allow_eth_send_transaction: false, // Secure default: reject unsigned tx
        }
    }
}

/// RPC Server
pub struct RpcServer {
    config: RpcConfig,
    #[allow(dead_code)]
    storage: Arc<StorageManager>,
    #[allow(dead_code)]
    mempool: Arc<Mempool>,
    #[allow(dead_code)]
    peer_manager: Arc<PeerManager>,
    #[allow(dead_code)]
    executor: Arc<Executor>,
    io_handler: IoHandler,
}

impl RpcServer {
    pub fn new(
        config: RpcConfig,
        storage: Arc<StorageManager>,
        mempool: Arc<Mempool>,
        peer_manager: Arc<PeerManager>,
        executor: Arc<Executor>,
        chain_id: u64,
    ) -> Self {
        Self::with_economics(
            config,
            storage,
            mempool,
            peer_manager,
            executor,
            chain_id,
            None,
        )
    }

    pub fn with_economics(
        config: RpcConfig,
        storage: Arc<StorageManager>,
        mempool: Arc<Mempool>,
        peer_manager: Arc<PeerManager>,
        executor: Arc<Executor>,
        chain_id: u64,
        economics_manager: Option<Arc<citrate_economics::UnifiedEconomicsManager>>,
    ) -> Self {
        Self::with_economics_and_pause(
            config,
            storage,
            mempool,
            peer_manager,
            executor,
            chain_id,
            economics_manager,
            None,
        )
    }

    /// WP-I.3: Full constructor with pause_flag support.
    /// When pause_flag is Some, emergency pause/resume/status RPC methods
    /// are registered and can halt block production.
    #[allow(clippy::too_many_arguments)]
    pub fn with_economics_and_pause(
        config: RpcConfig,
        storage: Arc<StorageManager>,
        mempool: Arc<Mempool>,
        peer_manager: Arc<PeerManager>,
        executor: Arc<Executor>,
        chain_id: u64,
        economics_manager: Option<Arc<citrate_economics::UnifiedEconomicsManager>>,
        pause_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        let mut io_handler = IoHandler::new();

        // Create filter registry for eth_newFilter/eth_getFilterChanges
        let filter_registry = Arc::new(FilterRegistry::new());

        // Register Ethereum-compatible RPC methods
        // WP-I.3: Pass pause_flag so emergency methods are actually registered
        eth_rpc::register_eth_methods(
            &mut io_handler,
            storage.clone(),
            mempool.clone(),
            executor.clone(),
            chain_id,
            filter_registry,
            pause_flag,
        );

        // Register economics-related RPC methods
        economics_rpc::register_economics_methods(&mut io_handler, economics_manager, Some(mempool.clone()));

        // Register AI-related RPC methods
        ai_rpc::register_ai_methods(
            &mut io_handler,
            storage.clone(),
            mempool.clone(),
            executor.clone(),
        );

        // ========== Chain Methods ==========

        // chain_getHeight
        let storage_h = storage.clone();
        io_handler.add_sync_method("chain_getHeight", move |_params: Params| {
            rpc_request("chain_getHeight");
            let api = ChainApi::new(storage_h.clone());
            match block_on(api.get_height()) {
                Ok(height) => Ok(Value::Number(height.into())),
                Err(_e) => Err(jsonrpc_core::Error::internal_error()),
            }
        });

        // citrate_updateModel
        let executor_ai_update = executor.clone();
        let mempool_ai_update = mempool.clone();
        io_handler.add_sync_method("citrate_updateModel", move |params: Params| {
            rpc_request("citrate_updateModel");
            let _tx_api =
                TransactionApi::new(mempool_ai_update.clone(), executor_ai_update.clone(), chain_id);
            let value: serde_json::Value = match params.parse() {
                Ok(v) => v,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            let map = value
                .as_object()
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Expected object"))?;

            // S-01 FIX: Require operator authentication before model mutation
            require_operator_auth(map)?;

            let model_id_str = map
                .get("model_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'model_id'"))?;
            let from_hex = map
                .get("from")
                .and_then(|v| v.as_str())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'from'"))?;

            let mut metadata_value = map
                .get("metadata")
                .cloned()
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'metadata'"))?;
            let metadata_obj = metadata_value
                .as_object_mut()
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("'metadata' must be object"))?;

            metadata_obj
                .entry("name".to_string())
                .or_insert(json!("Updated Model"));
            metadata_obj
                .entry("version".to_string())
                .or_insert(json!("1.0.1"));
            metadata_obj
                .entry("description".to_string())
                .or_insert(json!("Updated model"));
            metadata_obj
                .entry("framework".to_string())
                .or_insert(json!("Unknown"));
            metadata_obj
                .entry("input_shape".to_string())
                .or_insert(json!([1]));
            metadata_obj
                .entry("output_shape".to_string())
                .or_insert(json!([1]));

            let mut model_bytes: Option<Vec<u8>> = None;
            if let Some(data_str) = map.get("model_data").and_then(|v| v.as_str()) {
                let decoded = STANDARD
                    .decode(data_str)
                    .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid base64 in 'model_data'"))?;
                metadata_obj.insert("size_bytes".to_string(), json!(decoded.len()));
                model_bytes = Some(decoded);
            }

            if !metadata_obj.contains_key("size_bytes") {
                metadata_obj.insert("size_bytes".to_string(), json!(0));
            }

            let from_bytes = hex::decode(from_hex.trim().trim_start_matches("0x"))
                .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'from'"))?;
            if from_bytes.len() != 20 {
                return Err(jsonrpc_core::Error::invalid_params("Invalid 'from' length"));
            }
            let _from_addr = citrate_execution::types::Address({
                let mut a = [0u8; 20];
                a.copy_from_slice(&from_bytes);
                a
            });

            let model_id_bytes = hex::decode(model_id_str.trim_start_matches("0x"))
                .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'model_id'"))?;
            if model_id_bytes.len() != 32 {
                return Err(jsonrpc_core::Error::invalid_params(
                    "'model_id' must be 32 bytes",
                ));
            }

            let mut model_id_array = [0u8; 32];
            model_id_array.copy_from_slice(&model_id_bytes);

            // Upload new artifact if model_data or ipfs_cid provided
            let artifact_cid = if let Some(cid) = map.get("ipfs_cid").and_then(|v| v.as_str()) {
                Some(cid.to_string())
            } else if let Some(bytes) = model_bytes.as_ref() {
                match ipfs_add_blocking(bytes.clone()) {
                    Ok(cid) => Some(cid),
                    Err(e) => {
                        return Err(jsonrpc_core::Error::invalid_params(format!(
                            "Failed to add artifact: {}",
                            e
                        )))
                    }
                }
            } else {
                None // Pure metadata update — no new artifact
            };

            if let Some(ref cid) = artifact_cid {
                metadata_obj.insert("artifact_cid".to_string(), json!(cid));
            }

            // Update model directly in state DB (synchronous, avoids async deadlocks)
            let model_hash = citrate_consensus::types::Hash::new(model_id_array);
            let model_id = citrate_execution::types::ModelId(model_hash);

            let existing = executor_ai_update.state_db().get_model(&model_id)
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Model not found"))?;

            // C-01 FIX: Validate caller ownership before allowing update
            // Parse the 'from' address and verify it matches the model owner
            let from_addr_trimmed = from_hex.trim_start_matches("0x");
            if from_addr_trimmed.len() >= 40 {
                let mut caller_addr = [0u8; 20];
                if let Ok(bytes) = hex::decode(&from_addr_trimmed[..40]) {
                    caller_addr.copy_from_slice(&bytes[..20]);
                    let caller = citrate_execution::types::Address(caller_addr);
                    if caller != existing.owner {
                        return Err(jsonrpc_core::Error {
                            code: jsonrpc_core::ErrorCode::ServerError(-32001),
                            message: "Unauthorized: caller is not the model owner".to_string(),
                            data: Some(json!({
                                "caller": format!("0x{}", hex::encode(caller_addr)),
                                "owner": format!("0x{}", hex::encode(existing.owner.0)),
                            })),
                        });
                    }
                }
            }

            // Merge metadata: update only the fields that were provided
            let updated_metadata = citrate_execution::types::ModelMetadata {
                name: metadata_obj.get("name").and_then(|v| v.as_str())
                    .map(String::from).unwrap_or(existing.metadata.name.clone()),
                version: metadata_obj.get("version").and_then(|v| v.as_str())
                    .map(String::from).unwrap_or(existing.metadata.version.clone()),
                description: metadata_obj.get("description").and_then(|v| v.as_str())
                    .map(String::from).unwrap_or(existing.metadata.description.clone()),
                framework: metadata_obj.get("framework").and_then(|v| v.as_str())
                    .map(String::from).unwrap_or(existing.metadata.framework.clone()),
                input_shape: existing.metadata.input_shape.clone(),
                output_shape: existing.metadata.output_shape.clone(),
                size_bytes: existing.metadata.size_bytes,
                created_at: existing.metadata.created_at,
            };

            let updated_model = citrate_execution::types::ModelState {
                owner: existing.owner,
                model_hash: existing.model_hash,
                version: existing.version + 1,
                metadata: updated_metadata,
                access_policy: existing.access_policy.clone(),
                usage_stats: existing.usage_stats.clone(),
            };

            executor_ai_update.state_db().update_model(model_id, updated_model)
                .map_err(|e| jsonrpc_core::Error::invalid_params(format!("update failed: {}", e)))?;

            if let Some(ref cid) = artifact_cid {
                executor_ai_update.add_model_artifact(&model_hash, cid);
            }

            Ok(json!({
                "status": "updated",
                "model_id": format!("0x{}", hex::encode(model_id_array)),
                "artifact_cid": artifact_cid
            }))
        });

        // chain_getTips
        let storage_t = storage.clone();
        io_handler.add_sync_method("chain_getTips", move |_params: Params| {
            rpc_request("chain_getTips");
            let api = ChainApi::new(storage_t.clone());
            match block_on(api.get_tips()) {
                Ok(tips) => Ok(serde_json::to_value(tips).unwrap_or(Value::Array(vec![]))),
                Err(_) => Ok(Value::Array(vec![])),
            }
        });

        // chain_getBlock
        let storage_b = storage.clone();
        io_handler.add_sync_method("chain_getBlock", move |params: Params| {
            rpc_request("chain_getBlock");
            let api = ChainApi::new(storage_b.clone());

            let block_id: BlockId = match params.parse() {
                Ok(id) => id,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            match block_on(api.get_block(block_id)) {
                Ok(block) => Ok(serde_json::to_value(block).unwrap_or(Value::Null)),
                Err(ApiError::BlockNotFound(_)) => Ok(Value::Null),
                Err(_e) => Err(jsonrpc_core::Error::internal_error()),
            }
        });

        // chain_getTransaction
        let storage_tx = storage.clone();
        io_handler.add_sync_method("chain_getTransaction", move |params: Params| {
            rpc_request("chain_getTransaction");
            let api = ChainApi::new(storage_tx.clone());

            let hash: Hash = match params.parse() {
                Ok(h) => h,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            match block_on(api.get_transaction(hash)) {
                Ok(tx) => Ok(serde_json::to_value(tx).unwrap_or(Value::Null)),
                Err(ApiError::TransactionNotFound(_)) => Ok(Value::Null),
                Err(_) => Err(jsonrpc_core::Error::internal_error()),
            }
        });

        // ========== State Methods ==========

        // state_getBalance
        let storage_bal = storage.clone();
        let executor_bal = executor.clone();
        io_handler.add_sync_method("state_getBalance", move |params: Params| {
            rpc_request("state_getBalance");
            let api = StateApi::new(storage_bal.clone(), executor_bal.clone());

            let address: Address = match params.parse() {
                Ok(addr) => addr,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            match block_on(api.get_balance(address)) {
                Ok(balance) => {
                    Ok(serde_json::to_value(balance).unwrap_or(Value::String("0".to_string())))
                }
                Err(_) => Ok(Value::String("0".to_string())),
            }
        });

        // state_getNonce
        let storage_n = storage.clone();
        let executor_n = executor.clone();
        io_handler.add_sync_method("state_getNonce", move |params: Params| {
            rpc_request("state_getNonce");
            let api = StateApi::new(storage_n.clone(), executor_n.clone());

            let address: Address = match params.parse() {
                Ok(addr) => addr,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            match block_on(api.get_nonce(address)) {
                Ok(nonce) => Ok(Value::Number(nonce.into())),
                Err(_) => Ok(Value::Number(0.into())),
            }
        });

        // state_getCode
        let storage_c = storage.clone();
        let executor_c = executor.clone();
        io_handler.add_sync_method("state_getCode", move |params: Params| {
            rpc_request("state_getCode");
            let api = StateApi::new(storage_c.clone(), executor_c.clone());

            let address: Address = match params.parse() {
                Ok(addr) => addr,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            match block_on(api.get_code(address)) {
                Ok(code) => Ok(Value::String(hex::encode(code))),
                Err(_) => Ok(Value::String("0x".to_string())),
            }
        });

        // ========== Transaction Methods ==========

        // tx_sendRawTransaction
        let mempool_raw = mempool.clone();
        let executor_raw = executor.clone();
        io_handler.add_sync_method("tx_sendRawTransaction", move |params: Params| {
            rpc_request("tx_sendRawTransaction");
            let api = TransactionApi::new(mempool_raw.clone(), executor_raw.clone(), chain_id);

            let raw_hex: String = match params.parse() {
                Ok(hex) => hex,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            let raw_bytes = match hex::decode(raw_hex.trim_start_matches("0x")) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(jsonrpc_core::Error::invalid_params(format!(
                        "Invalid hex: {}",
                        e
                    )))
                }
            };

            match block_on(api.send_raw_transaction(raw_bytes)) {
                Ok(hash) => Ok(Value::String(format!("0x{}", hex::encode(hash.as_bytes())))),
                Err(e) => Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            }
        });

        // tx_estimateGas
        let mempool_gas = mempool.clone();
        let executor_gas = executor.clone();
        io_handler.add_sync_method("tx_estimateGas", move |params: Params| {
            rpc_request("tx_estimateGas");
            let api = TransactionApi::new(mempool_gas.clone(), executor_gas.clone(), chain_id);

            let request: CallRequest = match params.parse() {
                Ok(req) => req,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            match block_on(api.estimate_gas(request)) {
                Ok(gas) => Ok(Value::String(format!("0x{:x}", gas))),
                Err(_) => Ok(Value::String("0x5208".to_string())), // Default 21000
            }
        });

        // tx_getGasPrice
        let mempool_price = mempool.clone();
        let executor_price = executor.clone();
        io_handler.add_sync_method("tx_getGasPrice", move |_params: Params| {
            rpc_request("tx_getGasPrice");
            let api = TransactionApi::new(mempool_price.clone(), executor_price.clone(), chain_id);

            match block_on(api.get_gas_price()) {
                Ok(price) => Ok(Value::String(format!("0x{:x}", price))),
                Err(_) => Ok(Value::String("0x3b9aca00".to_string())), // 1 Gwei
            }
        });

        // ========== Mempool Methods ==========

        // mempool_getStatus
        let mempool_status = mempool.clone();
        io_handler.add_sync_method("mempool_getStatus", move |_params: Params| {
            rpc_request("mempool_getStatus");
            let api = MempoolApi::new(mempool_status.clone());

            match block_on(api.get_status()) {
                Ok(status) => Ok(serde_json::to_value(status).unwrap_or(Value::Null)),
                Err(_) => Ok(serde_json::json!({
                    "pending": 0,
                    "queued": 0,
                    "total_size": 0,
                    "max_size": 10000000
                })),
            }
        });

        // mempool_getPending
        //
        // WP-J1.7 / T0-07: pending transaction detail is operator-only.
        // The response is paginated, capped, and redacted so this method
        // cannot serve as a public calldata/mempool dump.
        let mempool_pending = mempool.clone();
        io_handler.add_sync_method("mempool_getPending", move |params: Params| {
            rpc_request("mempool_getPending");
            let api = MempoolApi::new(mempool_pending.clone());

            let params_map = params_object_or_first_object(params);
            require_operator_auth(&params_map)?;
            let query = PendingQuery::from_params_map(&params_map)?;

            match block_on(api.get_pending(query)) {
                Ok(txs) => Ok(serde_json::to_value(txs).unwrap_or(Value::Null)),
                Err(err) => Err(err.into()),
            }
        });

        // ========== Network Methods ==========

        // net_peerCount
        let peers_count = peer_manager.clone();
        io_handler.add_sync_method("net_peerCount", move |_params: Params| {
            rpc_request("net_peerCount");
            let api = NetworkApi::new(peers_count.clone(), chain_id);

            match block_on(api.get_peer_count()) {
                Ok(count) => Ok(Value::String(format!("0x{:x}", count))),
                Err(_) => Ok(Value::String("0x0".to_string())),
            }
        });

        // net_listening
        let peers_listen = peer_manager.clone();
        io_handler.add_sync_method("net_listening", move |_params: Params| {
            rpc_request("net_listening");
            let api = NetworkApi::new(peers_listen.clone(), chain_id);

            match block_on(api.is_listening()) {
                Ok(listening) => Ok(Value::Bool(listening)),
                Err(_) => Ok(Value::Bool(true)),
            }
        });

        // Override eth_sendRawTransaction to also broadcast via P2P when available
        let mempool_raw_broadcast = mempool.clone();
        let peer_mgr_raw_broadcast = peer_manager.clone();
        let executor_raw_broadcast = executor.clone();
        io_handler.add_sync_method("eth_sendRawTransaction", move |params: Params| {
            rpc_request("eth_sendRawTransaction");
            use crate::eth_tx_decoder;
            use citrate_network::NetworkMessage;

            let mempool = mempool_raw_broadcast.clone();
            let peer_mgr = peer_mgr_raw_broadcast.clone();
            let exec = executor_raw_broadcast.clone();

            let params: Vec<Value> = match params.parse() {
                Ok(p) => p,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            if params.is_empty() {
                return Err(jsonrpc_core::Error::invalid_params(
                    "Missing transaction data",
                ));
            }
            let tx_hex = params[0]
                .as_str()
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Invalid tx hex"))?;
            let tx_bytes = match hex::decode(tx_hex.trim().trim_start_matches("0x")) {
                Ok(b) => b,
                Err(_) => return Err(jsonrpc_core::Error::invalid_params("Invalid hex")),
            };
            let tx = match eth_tx_decoder::decode_eth_transaction(&tx_bytes) {
                Ok(t) => t,
                Err(e) => {
                    return Err(jsonrpc_core::Error::invalid_params(format!(
                        "Failed to parse transaction: {}",
                        e
                    )))
                }
            };

            // Check sender balance covers value + gas
            let sender_addr = citrate_execution::address_utils::normalize_address(&tx.from);
            let balance = exec.get_balance(&sender_addr);
            let gas_cost = primitive_types::U256::from(tx.gas_limit) * primitive_types::U256::from(tx.gas_price);
            let total_cost = gas_cost + primitive_types::U256::from(tx.value);
            if balance < total_cost {
                return Err(jsonrpc_core::Error::invalid_params(
                    format!("Insufficient funds: account balance {} < required {}", balance, total_cost),
                ));
            }

            let hash = tx.hash;
            match block_on(
                mempool.add_transaction(tx.clone(), citrate_sequencer::mempool::TxClass::Standard),
            ) {
                Ok(_) => {
                    // Best-effort broadcast to peers
                    let _ = block_on(
                        peer_mgr.broadcast(&NetworkMessage::NewTransaction { transaction: tx }),
                    );
                    Ok(Value::String(format!("0x{}", hex::encode(hash.as_bytes()))))
                }
                Err(e) => Err(jsonrpc_core::Error::invalid_params(format!(
                    "Failed to submit transaction: {:?}",
                    e
                ))),
            }
        });

        // Override eth_sendTransaction: parse standard Ethereum JSON-RPC format with hex addresses,
        // enqueue via TransactionApi, then broadcast the tx if retrievable.
        // SECURITY (C-02): This method creates unsigned transactions from arbitrary `from`
        // addresses. It is ONLY available when allow_eth_send_transaction is true (devnet mode).
        // In production, clients must use eth_sendRawTransaction with a real signature.
        let mempool_send_broadcast = mempool.clone();
        let executor_send_broadcast = executor.clone();
        let peer_mgr_send_broadcast = peer_manager.clone();
        let allow_send_tx = config.allow_eth_send_transaction;
        if allow_send_tx {
            // PT-09: Warn when unsigned transaction submission is enabled on non-loopback
            let bind = config.listen_addr;
            if !bind.ip().is_loopback() {
                tracing::warn!("eth_sendTransaction is ENABLED on non-loopback address '{}'. This allows unsigned transactions from any caller. Use only for local development.", bind);
            }
        }
        io_handler.add_sync_method("eth_sendTransaction", move |params: Params| {
            rpc_request("eth_sendTransaction");

            // C-02 gate: reject if not in devnet/dev mode
            if !allow_send_tx {
                return Err(jsonrpc_core::Error {
                    code: jsonrpc_core::ErrorCode::MethodNotFound,
                    message: "eth_sendTransaction is disabled. Use eth_sendRawTransaction with a signed transaction.".into(),
                    data: None,
                });
            }

            use crate::types::request::TransactionRequest;
            use citrate_execution::types::Address;
            use citrate_network::NetworkMessage;

            // Parse as generic JSON first, then manually extract fields
            // (Address serde uses byte arrays for bincode compat, but JSON-RPC uses hex strings)
            let raw: Vec<Value> = match params.parse() {
                Ok(r) => r,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            let obj = raw.first()
                .and_then(|v| v.as_object())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Expected transaction object"))?;

            let from_str = obj.get("from")
                .and_then(|v| v.as_str())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'from' field"))?;
            let from = Address::from_hex(from_str)
                .map_err(|e| jsonrpc_core::Error::invalid_params(format!("Invalid 'from' address: {}", e)))?;

            let to = if let Some(to_val) = obj.get("to") {
                let to_str = to_val.as_str()
                    .ok_or_else(|| jsonrpc_core::Error::invalid_params("'to' must be a hex string"))?;
                Some(Address::from_hex(to_str)
                    .map_err(|e| jsonrpc_core::Error::invalid_params(format!("Invalid 'to' address: {}", e)))?)
            } else {
                None
            };

            let value = obj.get("value")
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    let s = s.trim_start_matches("0x").trim_start_matches("0X");
                    primitive_types::U256::from_str_radix(s, 16).ok()
                });

            let gas = obj.get("gas")
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .or_else(|| obj.get("gas").and_then(|v| v.as_u64()));

            let gas_price = obj.get("gasPrice")
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .or_else(|| obj.get("gasPrice").and_then(|v| v.as_u64()));

            let nonce = obj.get("nonce")
                .and_then(|v| v.as_str())
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .or_else(|| obj.get("nonce").and_then(|v| v.as_u64()));

            let data = obj.get("data")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok());

            let req = TransactionRequest {
                from,
                to,
                value,
                gas,
                gas_price,
                nonce,
                data,
            };

            let api = TransactionApi::new(
                mempool_send_broadcast.clone(),
                executor_send_broadcast.clone(),
                chain_id,
            );
            match block_on(api.send_transaction(req)) {
                Ok(hash) => {
                    // Try to fetch and broadcast
                    if let Some(tx) = block_on(mempool_send_broadcast.get_transaction(&hash)) {
                        let _ = block_on(
                            peer_mgr_send_broadcast
                                .broadcast(&NetworkMessage::NewTransaction { transaction: tx }),
                        );
                    }
                    Ok(Value::String(format!("0x{}", hex::encode(hash.as_bytes()))))
                }
                Err(e) => Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            }
        });

        // net_version (chain ID) - must use configured chain_id, not hardcoded
        let net_version_chain_id = chain_id;
        io_handler.add_sync_method("net_version", move |_params: Params| {
            rpc_request("net_version");
            Ok(Value::String(net_version_chain_id.to_string()))
        });

        // web3_clientVersion
        io_handler.add_sync_method("web3_clientVersion", |_params: Params| {
            rpc_request("web3_clientVersion");
            Ok(Value::String("citrate/v0.1.0".to_string()))
        });

        // eth_chainId (compatibility)
        let chain_id_for_handler = chain_id;
        io_handler.add_sync_method("eth_chainId", move |_params: Params| {
            rpc_request("eth_chainId");
            Ok(Value::String(format!("0x{:x}", chain_id_for_handler)))
        });

        // ========== AI/ML Methods ==========

        // citrate_verifyContract: verifies runtime bytecode matches on-chain code for address
        let storage_v = storage.clone();
        let executor_v = executor.clone();
        io_handler.add_sync_method("citrate_verifyContract", move |params: Params| {
            rpc_request("citrate_verifyContract");
            let payload: serde_json::Value = match params.parse() {
                Ok(v) => v,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            // Required: address; either runtime_bytecode (hex) or we fail (source-only not supported here)
            let obj = match payload.as_object() { Some(m) => m, None => {
                return Err(jsonrpc_core::Error::invalid_params("Expected object payload"));
            }};
            let address_str = obj.get("address").and_then(|v| v.as_str()).unwrap_or("");
            let runtime_hex = obj.get("runtime_bytecode").and_then(|v| v.as_str());
            let compiler_version = obj.get("compiler_version").and_then(|v| v.as_str()).unwrap_or("");
            let optimization_enabled = obj.get("optimization_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
            let source_code = obj.get("source_code").and_then(|v| v.as_str());
            let contract_name = obj.get("contract_name").and_then(|v| v.as_str());
            let standard_json = obj.get("standard_json");
            let constructor_args_hex = obj.get("constructor_args").and_then(|v| v.as_str());

            // Either use provided runtime bytecode, or compile from source/standard-json if present
            if runtime_hex.is_none() && source_code.is_none() && standard_json.is_none() {
                return Err(jsonrpc_core::Error::invalid_params("Provide runtime_bytecode, source_code, or standard_json"));
            }
            let provided = if let Some(rh) = runtime_hex {
                let s = rh.trim();
                let s = s.strip_prefix("0x").unwrap_or(s);
                match hex::decode(s) { Ok(b) => b, Err(_) => return Err(jsonrpc_core::Error::invalid_params("Invalid runtime_bytecode hex")), }
            } else if let Some(src) = source_code {
                // Attempt Phase 2: compile
                let compiled = match compile_runtime_bytecode(src, compiler_version, optimization_enabled, contract_name) {
                    Ok(bytes) => bytes,
                    Err(e) => return Ok(json!({
                        "verified": false,
                        "reason": format!("compile error: {}", e),
                    })),
                };
                compiled
            } else if let Some(stdj) = standard_json {
                // Standard JSON supports multi-file projects
                let sj_str = if stdj.is_string() { stdj.as_str().unwrap_or_default().to_string() } else { serde_json::to_string(stdj).unwrap_or_default() };
                let (_creation, runtime) = match compile_standard_json(&sj_str, contract_name) {
                    Ok(t) => t,
                    Err(e) => return Ok(json!({
                        "verified": false,
                        "reason": format!("standard-json compile error: {}", e),
                    })),
                };
                runtime
            } else {
                return Err(jsonrpc_core::Error::invalid_params("unreachable"));
            };
            let addr_hex = address_str.trim().trim_start_matches("0x");
            if addr_hex.len() != 40 { return Err(jsonrpc_core::Error::invalid_params("Invalid address length")); }
            let onchain_addr = {
                let mut a = [0u8; 20];
                match hex::decode(addr_hex) { Ok(b) if b.len()==20 => a.copy_from_slice(&b), _ => return Err(jsonrpc_core::Error::invalid_params("Invalid address")), }
                Address(a)
            };

            // Fetch on-chain runtime code via StateApi
            let api = StateApi::new(storage_v.clone(), executor_v.clone());
            let onchain = match block_on(api.get_code(onchain_addr)) {
                Ok(code) => code,
                Err(_) => return Ok(json!({
                    "verified": false,
                    "reason": "No code at address"
                })),
            };

            if onchain.is_empty() {
                return Ok(json!({"verified": false, "reason": "Empty code at address"}));
            }

            // Compare after stripping metadata trailers
            fn strip_metadata(code: &[u8]) -> &[u8] {
                if code.len() >= 2 {
                    let l = u16::from_be_bytes([code[code.len()-2], code[code.len()-1]]) as usize;
                    if code.len() >= l + 2 {
                        let start = code.len() - (l + 2);
                        let first = code[start];
                        if (first & 0xE0) == 0xA0 { // likely CBOR map (0xA0..0xBF)
                            return &code[..start];
                        }
                    }
                }
                code
            }
            let onchain_stripped = strip_metadata(&onchain);
            let provided_stripped = strip_metadata(&provided);
            let equal = onchain_stripped == provided_stripped;

            // Optional creation bytecode verification (with constructor args support)
            let creation_hex = obj.get("creation_bytecode").and_then(|v| v.as_str());
            let mut creation_verified = None;
            let mut creation_hash: Option<String> = None;
            let mut creation_stripped_hash: Option<String> = None;
            if let Some(ch) = creation_hex {
                let s = ch.trim();
                let s = s.strip_prefix("0x").unwrap_or(s);
                if let Ok(cbytes) = hex::decode(s) {
                    use sha3::Digest as _;
                    creation_hash = Some(format!("0x{}", hex::encode(Keccak256::digest(&cbytes))));
                    let cstr = strip_metadata(&cbytes);
                    creation_stripped_hash = Some(format!("0x{}", hex::encode(Keccak256::digest(cstr))));

                    // If standard_json provided, compute expected creation bytecode
                    let expected_creation_opt: Option<Vec<u8>> = if let Some(stdj) = standard_json {
                        let sj_str = if stdj.is_string() { stdj.as_str().unwrap_or_default().to_string() } else { serde_json::to_string(stdj).unwrap_or_default() };
                        if let Ok((creation, _runtime)) = compile_standard_json(&sj_str, contract_name) {
                            // Append constructor args if provided (hex-encoded ABI)
                            let extra = constructor_args_hex
                                .and_then(|h| hex::decode(h.trim().trim_start_matches("0x")).ok())
                                .unwrap_or_default();
                            let mut full = creation.clone();
                            full.extend_from_slice(&extra);
                            Some(full)
                        } else { None }
                    } else { None };

                    // Match stripped creation bytecode exactly if expected available, otherwise fallback to prefix match
                    creation_verified = Some(if let Some(exp) = expected_creation_opt {
                        let exp_s = strip_metadata(&exp);
                        cstr == exp_s
                    } else {
                        // Fallback legacy behavior
                        cbytes.starts_with(provided_stripped)
                    });
                }
            }
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::new();
            hasher.update(address_str.as_bytes());
            hasher.update(compiler_version.as_bytes());
            hasher.update([optimization_enabled as u8]);
            hasher.update(&provided);
            let verification_id = format!("0x{}", hex::encode(hasher.finalize()));

            // Build record
            let record = json!({
                "address": address_str,
                "runtime_bytecode_hash": format!("0x{}", hex::encode(Keccak256::digest(&provided))),
                "runtime_bytecode_stripped_hash": format!("0x{}", hex::encode(Keccak256::digest(provided_stripped))),
                "onchain_code_hash": format!("0x{}", hex::encode(Keccak256::digest(&onchain))),
                "onchain_code_stripped_hash": format!("0x{}", hex::encode(Keccak256::digest(onchain_stripped))),
                "compiler_version": compiler_version,
                "optimization_enabled": optimization_enabled,
                "source_hash": source_code.map(|s| format!("0x{}", hex::encode(Keccak256::digest(s.as_bytes())))),
                "contract_name": contract_name,
                "verified": equal,
                "creation_bytecode_hash": creation_hash,
                "creation_bytecode_stripped_hash": creation_stripped_hash,
                "creation_verified": creation_verified,
                "verification_id": verification_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });

            // Store record in memory
            {
                let mut map = VERIFICATIONS.write().unwrap_or_else(|e| e.into_inner());
                map.insert(address_str.to_string(), record.clone());
            }

            // Persist record in storage under metadata CF
            let key_addr = format!("verify:addr:{}", address_str.to_lowercase());
            let key_id = format!("verify:id:{}", verification_id.to_lowercase());
            if let Ok(bytes) = serde_json::to_vec(&record) {
                let _ = storage_v.db.put_cf("metadata", key_addr.as_bytes(), &bytes);
                // id → address index
                let _ = storage_v.db.put_cf("metadata", key_id.as_bytes(), address_str.as_bytes());
            }

            Ok(json!({"verified": equal, "verification_id": verification_id}))
        });

        // citrate_getVerification: return stored verification record
        let storage_get = storage.clone();
        io_handler.add_sync_method("citrate_getVerification", move |params: Params| {
            rpc_request("citrate_getVerification");
            let addr: String = match params.parse() {
                Ok(s) => s,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            // Try memory
            if let Some(val) = VERIFICATIONS.read().unwrap_or_else(|e| e.into_inner()).get(&addr).cloned() {
                return Ok(val);
            }
            // Try storage
            let key_addr = format!("verify:addr:{}", addr.to_lowercase());
            match storage_get.db.get_cf("metadata", key_addr.as_bytes()) {
                Ok(Some(bytes)) => {
                    let val: serde_json::Value =
                        serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    Ok(val)
                }
                _ => Ok(Value::Null),
            }
        });

        // citrate_listVerifications: return all verification records
        let storage_list = storage.clone();
        io_handler.add_sync_method("citrate_listVerifications", move |params: Params| {
            rpc_request("citrate_listVerifications");
            let obj = match params {
                Params::None => serde_json::Map::new(),
                Params::Array(_) => serde_json::Map::new(),
                Params::Map(m) => m.into_iter().collect(),
            };
            let (offset, limit) = parse_pagination(&obj);
            let want_verified = obj.get("verified").and_then(|v| v.as_bool());
            let addr_prefix = obj
                .get("address_prefix")
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase());
            let prefix = b"verify:addr:";
            let mut out = Vec::new();
            if let Ok(iter) = storage_list.db.prefix_iter_cf("metadata", prefix) {
                for (k, v) in iter {
                    if let Some(pref) = &addr_prefix {
                        if let Ok(kstr) = std::str::from_utf8(&k) {
                            if let Some(addr) = kstr.strip_prefix("verify:addr:") {
                                if !addr.starts_with(pref) {
                                    continue;
                                }
                            }
                        }
                    }
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) {
                        if let Some(wv) = want_verified {
                            if val
                                .get("verified")
                                .and_then(|b| b.as_bool())
                                .unwrap_or(false)
                                != wv
                            {
                                continue;
                            }
                        }
                        out.push(val);
                    }
                }
            }
            // Sort by timestamp desc if present
            out.sort_by(|a, b| {
                b.get("timestamp")
                    .and_then(|v| v.as_str())
                    .cmp(&a.get("timestamp").and_then(|v| v.as_str()))
            });
            let out = apply_pagination(out, offset, limit);
            Ok(Value::Array(out))
        });

        // citrate_listVerificationsByStatus [bool]
        let storage_list_status = storage.clone();
        io_handler.add_sync_method(
            "citrate_listVerificationsByStatus",
            move |params: Params| {
                rpc_request("citrate_listVerificationsByStatus");
                // Support payload { verified: bool, offset?: u64, limit?: u64 }
                let obj = match params {
                    Params::Map(m) => m.into_iter().collect::<serde_json::Map<_, _>>(),
                    _ => serde_json::Map::new(),
                };
                let want: bool = obj
                    .get("verified")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let (offset, limit) = parse_pagination(&obj);
                let prefix = b"verify:addr:";
                let mut out = Vec::new();
                if let Ok(iter) = storage_list_status.db.prefix_iter_cf("metadata", prefix) {
                    for (_k, v) in iter {
                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) {
                            if val
                                .get("verified")
                                .and_then(|b| b.as_bool())
                                .unwrap_or(false)
                                == want
                            {
                                out.push(val);
                            }
                        }
                    }
                }
                out.sort_by(|a, b| {
                    b.get("timestamp")
                        .and_then(|v| v.as_str())
                        .cmp(&a.get("timestamp").and_then(|v| v.as_str()))
                });
                let out = apply_pagination(out, offset, limit);
                Ok(Value::Array(out))
            },
        );

        // citrate_listVerificationsByAddressPrefix [string]
        let storage_list_prefix = storage.clone();
        io_handler.add_sync_method(
            "citrate_listVerificationsByAddressPrefix",
            move |params: Params| {
                rpc_request("citrate_listVerificationsByAddressPrefix");
                // Support payload { prefix: string, offset?: u64, limit?: u64 }
                let obj = match params {
                    Params::Map(m) => m.into_iter().collect::<serde_json::Map<_, _>>(),
                    _ => serde_json::Map::new(),
                };
                let prefix_str = obj
                    .get("prefix")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let (offset, limit) = parse_pagination(&obj);
                let meta_prefix = b"verify:addr:";
                let mut out = Vec::new();
                if let Ok(iter) = storage_list_prefix
                    .db
                    .prefix_iter_cf("metadata", meta_prefix)
                {
                    for (k, v) in iter {
                        // key format: verify:addr:<address>
                        if let Ok(key_str) = std::str::from_utf8(&k) {
                            if let Some(addr) = key_str.strip_prefix("verify:addr:") {
                                if addr.starts_with(&prefix_str) {
                                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v)
                                    {
                                        out.push(val);
                                    }
                                }
                            }
                        }
                    }
                }
                out.sort_by(|a, b| {
                    b.get("timestamp")
                        .and_then(|v| v.as_str())
                        .cmp(&a.get("timestamp").and_then(|v| v.as_str()))
                });
                let out = apply_pagination(out, offset, limit);
                Ok(Value::Array(out))
            },
        );

        // citrate_pruneVerifications: optional GC to prune by age or count
        let storage_gc = storage.clone();
        io_handler.add_sync_method("citrate_pruneVerifications", move |params: Params| {
            rpc_request("citrate_pruneVerifications");
            // Payload: { max_age_seconds?: u64, max_records?: u64 }
            let obj = match params {
                Params::Map(m) => m.into_iter().collect::<serde_json::Map<_, _>>(),
                _ => serde_json::Map::new(),
            };
            let max_age = obj.get("max_age_seconds").and_then(|v| v.as_u64());
            let max_records = obj.get("max_records").and_then(|v| v.as_u64());
            let prefix = b"verify:addr:";
            let mut items: Vec<(Vec<u8>, serde_json::Value)> = Vec::new();
            if let Ok(iter) = storage_gc.db.prefix_iter_cf("metadata", prefix) {
                for (k, v) in iter {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) {
                        items.push((k.to_vec(), val));
                    }
                }
            }
            // Sort by timestamp asc (oldest first)
            items.sort_by(|a, b| {
                a.1.get("timestamp")
                    .and_then(|v| v.as_str())
                    .cmp(&b.1.get("timestamp").and_then(|v| v.as_str()))
            });
            let now = chrono::Utc::now();
            let mut removed = 0usize;
            // Age-based removal
            if let Some(age) = max_age {
                for (k, v) in items.iter() {
                    if let Some(ts) = v.get("timestamp").and_then(|t| t.as_str()) {
                        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                            let dt_utc = dt.with_timezone(&chrono::Utc);
                            if (now - dt_utc).num_seconds() as u64 > age {
                                let _ = storage_gc.db.delete_cf("metadata", k);
                                removed += 1;
                            }
                        }
                    }
                }
            }
            // Count-based removal (keep newest max_records)
            if let Some(max) = max_records {
                // Re-list after age-based removal
                let mut remaining: Vec<(Vec<u8>, serde_json::Value)> = Vec::new();
                if let Ok(iter) = storage_gc.db.prefix_iter_cf("metadata", prefix) {
                    for (k, v) in iter {
                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) {
                            remaining.push((k.to_vec(), val));
                        }
                    }
                }
                // Sort by timestamp desc, keep first max
                remaining.sort_by(|a, b| {
                    b.1.get("timestamp")
                        .and_then(|v| v.as_str())
                        .cmp(&a.1.get("timestamp").and_then(|v| v.as_str()))
                });
                if remaining.len() > max as usize {
                    for (k, _v) in remaining.into_iter().skip(max as usize) {
                        let _ = storage_gc.db.delete_cf("metadata", &k);
                        removed += 1;
                    }
                }
            }
            Ok(json!({"removed": removed}))
        });

        // citrate_getVerificationById: fetch by verification_id
        let storage_by_id = storage.clone();
        io_handler.add_sync_method("citrate_getVerificationById", move |params: Params| {
            rpc_request("citrate_getVerificationById");
            let vid: String = match params.parse() {
                Ok(s) => s,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            let key_id = format!("verify:id:{}", vid.to_lowercase());
            if let Ok(Some(addr_bytes)) = storage_by_id.db.get_cf("metadata", key_id.as_bytes()) {
                if let Ok(addr) = std::str::from_utf8(&addr_bytes) {
                    let key_addr = format!("verify:addr:{}", addr.to_lowercase());
                    if let Ok(Some(bytes)) =
                        storage_by_id.db.get_cf("metadata", key_addr.as_bytes())
                    {
                        let val: serde_json::Value =
                            serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        return Ok(val);
                    }
                }
            }
            Ok(Value::Null)
        });

        // citrate_deployModel: register a model via model precompile
        // C-01 FIX: Model deployment is a privileged operation.
        // In production, this should go through a signed transaction to the ModelRegistry contract.
        // For testnet, we require a valid 'from' address that will be recorded as the owner.
        let executor_ai_deploy = executor.clone();
        io_handler.add_sync_method("citrate_deployModel", move |params: Params| {
            rpc_request("citrate_deployModel");
            let value: serde_json::Value = match params.parse() {
                Ok(v) => v,
                Err(e) => {
                    return Err(jsonrpc_core::Error::invalid_params(e.to_string()));
                }
            };
            let map = value
                .as_object()
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Expected object"))?;

            // S-01 FIX: Require operator authentication before model deployment
            require_operator_auth(map)?;

            let from_hex = map
                .get("from")
                .and_then(|v| v.as_str())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'from'"))?;
            let policy_str = map
                .get("access_policy")
                .and_then(|v| v.as_str())
                .unwrap_or("public");
            let price_wei = map
                .get("inference_price")
                .and_then(|v| v.as_str())
                .or_else(|| map.get("inference_price_wei").and_then(|v| v.as_str()));

            let mut metadata_value = map
                .get("metadata")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let metadata_obj = metadata_value.as_object_mut().ok_or_else(|| {
                jsonrpc_core::Error::invalid_params("'metadata' must be an object")
            })?;

            let model_data_b64 = map.get("model_data").and_then(|v| v.as_str());
            let ipfs_cid_param = map.get("ipfs_cid").and_then(|v| v.as_str());

            let mut model_bytes: Option<Vec<u8>> = None;
            if let Some(data_str) = model_data_b64 {
                let decoded = STANDARD.decode(data_str).map_err(|_| {
                    jsonrpc_core::Error::invalid_params("Invalid base64 in 'model_data'")
                })?;
                model_bytes = Some(decoded);
            }

            let size_bytes = map
                .get("size_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or_else(|| model_bytes.as_ref().map(|b| b.len() as u64).unwrap_or(0));
            if size_bytes == 0 {
                return Err(jsonrpc_core::Error::invalid_params(
                    "Provide 'model_data' or 'size_bytes'",
                ));
            }

            metadata_obj
                .entry("size_bytes".to_string())
                .or_insert(serde_json::json!(size_bytes));
            metadata_obj
                .entry("name".to_string())
                .or_insert(serde_json::json!("Unnamed Model"));
            metadata_obj
                .entry("version".to_string())
                .or_insert(serde_json::json!("1.0.0"));
            metadata_obj
                .entry("description".to_string())
                .or_insert(serde_json::json!("Registered via citrate_deployModel"));
            // Map "format" → "framework" if the caller used "format" instead
            if !metadata_obj.contains_key("framework") {
                if let Some(fmt) = metadata_obj.get("format").cloned() {
                    metadata_obj.insert("framework".to_string(), fmt);
                } else {
                    metadata_obj.insert("framework".to_string(), serde_json::json!("Unknown"));
                }
            }
            metadata_obj
                .entry("input_shape".to_string())
                .or_insert(serde_json::json!([1]));
            metadata_obj
                .entry("output_shape".to_string())
                .or_insert(serde_json::json!([1]));

            let from_bytes = hex::decode(from_hex.trim().trim_start_matches("0x"))
                .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'from'"))?;
            if from_bytes.len() != 20 {
                return Err(jsonrpc_core::Error::invalid_params("Invalid 'from' length"));
            }
            let mut from_pkb = [0u8; 32];
            from_pkb[..20].copy_from_slice(&from_bytes);
            let _from_pk = citrate_consensus::types::PublicKey::new(from_pkb);
            let from_addr = citrate_execution::types::Address({
                let mut a = [0u8; 20];
                a.copy_from_slice(&from_bytes);
                a
            });

            let cid = if let Some(existing) = ipfs_cid_param {
                existing.to_string()
            } else if let Some(bytes) = model_bytes.as_ref() {
                match ipfs_add_blocking(bytes.clone()) {
                    Ok(cid) => cid,
                    Err(e) => {
                        return Err(jsonrpc_core::Error::invalid_params(format!(
                            "Failed to add artifact: {}",
                            e
                        )))
                    }
                }
            } else {
                return Err(jsonrpc_core::Error::invalid_params(
                    "Provide 'model_data' or 'ipfs_cid'",
                ));
            };

            metadata_obj
                .entry("artifact_cid".to_string())
                .or_insert(serde_json::json!(cid.clone()));

            let model_hash_arr = if let Some(bytes) = model_bytes.as_ref() {
                use sha3::Digest as _;
                let mut hasher = sha3::Keccak256::default();
                hasher.update(bytes);
                // Include metadata name+version so same data with different
                // metadata produces a distinct model ID.
                if let Some(n) = metadata_obj.get("name").and_then(|v| v.as_str()) {
                    hasher.update(n.as_bytes());
                }
                if let Some(v) = metadata_obj.get("version").and_then(|v| v.as_str()) {
                    hasher.update(v.as_bytes());
                }
                let out = hasher.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&out);
                arr
            } else if let Some(hs) = map.get("model_hash").and_then(|v| v.as_str()) {
                let bytes = hex::decode(hs.trim_start_matches("0x"))
                    .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'model_hash'"))?;
                if bytes.len() != 32 {
                    return Err(jsonrpc_core::Error::invalid_params(
                        "Invalid 'model_hash' length",
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            } else {
                use sha3::Digest as _;
                let mut hasher = sha3::Keccak256::default();
                hasher.update(&from_bytes);
                hasher.update(cid.as_bytes());
                hasher.update(size_bytes.to_le_bytes());
                let out = hasher.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&out);
                arr
            };
            let model_hash = citrate_consensus::types::Hash::new(model_hash_arr);

            let policy_byte: u8 = match policy_str.to_lowercase().as_str() {
                "public" => 0,
                "private" => 1,
                "restricted" => 2,
                "payperuse" | "pay_per_use" | "pay-per-use" => 3,
                _ => 0,
            };

            let price_bytes: Option<[u8; 32]> = if policy_byte == 3 {
                if let Some(val) = price_wei {
                    let price = if let Some(h) = val
                        .trim()
                        .strip_prefix("0x")
                        .or_else(|| val.trim().strip_prefix("0X"))
                    {
                        primitive_types::U256::from_big_endian(&hex::decode(h).map_err(|_| {
                            jsonrpc_core::Error::invalid_params("Invalid price hex")
                        })?)
                    } else {
                        primitive_types::U256::from_dec_str(val.trim())
                            .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid price"))?
                    };
                    let mut tmp = [0u8; 32];
                    price.to_big_endian(&mut tmp);
                    Some(tmp)
                } else {
                    return Err(jsonrpc_core::Error::invalid_params(
                        "payPerUse policy requires 'inference_price'",
                    ));
                }
            } else {
                None
            };

            // Register model directly in state DB (synchronous) to avoid
            // async deadlocks when called from jsonrpc sync handler.
            let exec = executor_ai_deploy.clone();

            let model_metadata = citrate_execution::types::ModelMetadata {
                name: metadata_obj.get("name").and_then(|v| v.as_str()).unwrap_or("Unnamed Model").to_string(),
                version: metadata_obj.get("version").and_then(|v| v.as_str()).unwrap_or("1.0.0").to_string(),
                description: metadata_obj.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                framework: metadata_obj.get("framework").or_else(|| metadata_obj.get("format")).and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                input_shape: vec![1],
                output_shape: vec![1],
                size_bytes,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };

            let model_id = citrate_execution::types::ModelId(model_hash);
            let model_state = citrate_execution::types::ModelState {
                owner: from_addr,
                model_hash,
                version: 1,
                metadata: model_metadata,
                access_policy: match policy_byte {
                    0 => citrate_execution::types::AccessPolicy::Public,
                    1 => citrate_execution::types::AccessPolicy::Private,
                    2 => citrate_execution::types::AccessPolicy::Restricted(Vec::new()),
                    3 => citrate_execution::types::AccessPolicy::PayPerUse {
                        fee: price_bytes.map(|p| primitive_types::U256::from_big_endian(&p)).unwrap_or_default(),
                    },
                    _ => citrate_execution::types::AccessPolicy::Public,
                },
                usage_stats: Default::default(),
            };

            match exec.state_db().register_model(model_id, model_state.clone()) {
                Ok(()) => {
                    // Store artifact CID mapping
                    exec.add_model_artifact(&model_hash, &cid);
                    // Sync to MCP model registry so inference can find it
                    exec.sync_model_to_registry(model_id, &model_state, Some(&cid));
                    Ok(json!({
                        "model_id": format!("0x{}", hex::encode(model_hash.as_bytes())),
                        "tx_hash": format!("0x{}", hex::encode(model_hash.as_bytes())),
                        "artifact_cid": cid
                    }))
                }
                Err(e) => Err(jsonrpc_core::Error::invalid_params(format!(
                    "deploy failed: {}",
                    e
                ))),
            }
        });

        // ========== Extra Network Methods ==========
        // net_peers: return list of peer IDs (diagnostic)
        let peers_list = peer_manager.clone();
        io_handler.add_sync_method("net_peers", move |_params: Params| {
            rpc_request("net_peers");
            let api = NetworkApi::new(peers_list.clone(), chain_id);
            match block_on(api.get_peers()) {
                Ok(ids) => Ok(serde_json::to_value(ids).unwrap_or(Value::Array(vec![]))),
                Err(_) => Ok(Value::Array(vec![])),
            }
        });

        // net_peerInfo: detailed peer info (id, addr, direction)
        let peers_info_mgr = peer_manager.clone();
        io_handler.add_sync_method("net_peerInfo", move |_params: Params| {
            rpc_request("net_peerInfo");
            let peers = peers_info_mgr.get_all_peers();
            let mut arr = Vec::new();
            for p in peers {
                let info = block_on(p.info.read());
                let dir = match info.direction {
                    citrate_network::peer::Direction::Inbound => "inbound",
                    citrate_network::peer::Direction::Outbound => "outbound",
                };
                arr.push(serde_json::json!({
                    "id": info.id.to_string(),
                    "addr": info.addr.to_string(),
                    "direction": dir,
                }));
            }
            Ok(Value::Array(arr))
        });

        // citrate_getModel
        let _storage_ai_get = storage.clone();
        let _mempool_ai_get = mempool.clone();
        let executor_ai_get = executor.clone();
        io_handler.add_sync_method("citrate_getModel", move |params: Params| {
            rpc_request("citrate_getModel");

            // Accept either a plain string param or {model_id: "..."}
            let model_id_str: String = match params.clone().parse::<(String,)>() {
                Ok((id,)) => id,
                Err(_) => {
                    // Try object form: {model_id: "..."}
                    let fallback: serde_json::Value = params.parse()
                        .map_err(|e| jsonrpc_core::Error::invalid_params(e.to_string()))?;
                    let obj = if let Some(arr) = fallback.as_array() {
                        arr.first().and_then(|v| v.as_object()).cloned()
                    } else {
                        fallback.as_object().cloned()
                    };
                    obj.and_then(|m| m.get("model_id").and_then(|v| v.as_str()).map(String::from))
                        .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'model_id'"))?
                }
            };

            let model_id_str = model_id_str.trim_start_matches("0x").to_string();

            // Parse model ID from hex string
            match hex::decode(&model_id_str) {
                Ok(model_id_bytes) if model_id_bytes.len() == 32 => {
                    let mut model_id_array = [0u8; 32];
                    model_id_array.copy_from_slice(&model_id_bytes);
                    let model_id = citrate_execution::types::ModelId(Hash::new(model_id_array));

                    // Look up directly from executor's in-memory state DB
                    match executor_ai_get.state_db().get_model(&model_id) {
                        Some(model) => {
                            let artifacts = executor_ai_get
                                .list_model_artifacts(&model.model_hash);
                            let latest_artifact = artifacts.last().cloned();

                            let mut metadata_json = serde_json::to_value(&model.metadata)
                                .unwrap_or(Value::Null);
                            // Alias "framework" as "format" for SDK compatibility
                            if let Some(obj) = metadata_json.as_object_mut() {
                                if let Some(fw) = obj.get("framework").cloned() {
                                    obj.insert("format".to_string(), fw);
                                }
                            }
                            let usage_json = json!({
                                "total_inferences": model.usage_stats.total_inferences,
                                "total_gas_used": model.usage_stats.total_gas_used,
                                "total_fees_earned": model.usage_stats.total_fees_earned.to_string(),
                                "last_used": model.usage_stats.last_used,
                            });

                            Ok(json!({
                                "model": {
                                    "id": format!("0x{}", hex::encode(model_id.0.as_bytes())),
                                    "model_id": format!("0x{}", hex::encode(model_id.0.as_bytes())),
                                    "model_hash": format!("0x{}", hex::encode(model.model_hash.as_bytes())),
                                    "owner": format!("0x{}", hex::encode(model.owner.0)),
                                    "version": model.version,
                                    "metadata": metadata_json,
                                    "access_policy": access_policy_to_json(&model.access_policy),
                                    "usage_stats": usage_json,
                                    "artifacts": artifacts,
                                    "latest_artifact": latest_artifact,
                                }
                            }))
                        }
                        None => Ok(Value::Null),
                    }
                }
                _ => Err(jsonrpc_core::Error::invalid_params(
                    "Invalid model ID format".to_string(),
                )),
            }
        });

        // citrate_listModels
        let executor_ai_list = executor.clone();
        io_handler.add_sync_method("citrate_listModels", move |params: Params| {
            rpc_request("citrate_listModels");
            // Parse optional parameters
            let (owner, limit): (Option<String>, Option<usize>) =
                params.parse().unwrap_or((None, None));

            let parsed_owner: Option<Address> = owner.and_then(|addr_str| {
                hex::decode(addr_str.trim_start_matches("0x"))
                    .ok()
                    .and_then(|bytes| {
                        if bytes.len() == 20 {
                            let mut addr_array = [0u8; 20];
                            addr_array.copy_from_slice(&bytes);
                            Some(Address(addr_array))
                        } else {
                            None
                        }
                    })
            });

            // Pull models directly from executor's state DB
            let all = executor_ai_list.state_db().all_models();
            let mut models: Vec<serde_json::Value> = all
                .into_iter()
                .filter(|(_id, state)| match parsed_owner {
                    Some(addr) => state.owner == addr,
                    None => true,
                })
                .map(|(id, state)| {
                    json!({
                        "id": format!("0x{}", hex::encode(id.0.as_bytes())),
                        "model_id": format!("0x{}", hex::encode(id.0.as_bytes())),
                        "owner": format!("0x{}", hex::encode(state.owner.0)),
                        "name": state.metadata.name,
                        "version": state.metadata.version,
                    })
                })
                .collect();
            if let Some(l) = limit { models.truncate(l); }
            Ok(serde_json::json!({ "models": models }))
        });

        // citrate_getModels (alias for citrate_listModels)
        let executor_ai_list_alias = executor.clone();
        io_handler.add_sync_method("citrate_getModels", move |params: Params| {
            rpc_request("citrate_getModels");
            // Support optional (owner, limit) tuple or no params
            let (owner, limit): (Option<String>, Option<usize>) =
                params.parse().unwrap_or((None, None));

            let parsed_owner: Option<Address> = owner.and_then(|addr_str| {
                hex::decode(addr_str.trim_start_matches("0x"))
                    .ok()
                    .and_then(|bytes| {
                        if bytes.len() == 20 {
                            let mut addr_array = [0u8; 20];
                            addr_array.copy_from_slice(&bytes);
                            Some(Address(addr_array))
                        } else {
                            None
                        }
                    })
            });

            let all = executor_ai_list_alias.state_db().all_models();
            let mut models: Vec<serde_json::Value> = all
                .into_iter()
                .filter(|(_id, state)| match parsed_owner {
                    Some(addr) => state.owner == addr,
                    None => true,
                })
                .map(|(id, state)| {
                    json!({
                        "id": format!("0x{}", hex::encode(id.0.as_bytes())),
                        "model_id": format!("0x{}", hex::encode(id.0.as_bytes())),
                        "owner": format!("0x{}", hex::encode(state.owner.0)),
                        "name": state.metadata.name,
                        "version": state.metadata.version,
                    })
                })
                .collect();
            if let Some(l) = limit { models.truncate(l); }
            Ok(serde_json::json!({ "models": models }))
        });

        // citrate_requestInference — full implementation using Executor inference service
        let executor_ai_inf = executor.clone();
        io_handler.add_sync_method("citrate_requestInference", move |params: Params| {
            rpc_request("citrate_requestInference");

            let value: serde_json::Value = match params.parse() {
                Ok(v) => v,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            // Accept both {model_id: ...} and [{model_id: ...}]
            let obj_value = match &value {
                serde_json::Value::Array(arr) if !arr.is_empty() => arr[0].clone(),
                _ => value.clone(),
            };
            let obj = match obj_value.as_object() {
                Some(m) => m,
                None => {
                    return Err(jsonrpc_core::Error::invalid_params(
                        "Expected params object",
                    ))
                }
            };

            // model_id (hex, 32 bytes)
            let model_id_str = obj
                .get("model_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'model_id'"))?;
            let model_id_bytes = hex::decode(model_id_str.trim_start_matches("0x"))
                .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'model_id'"))?;
            if model_id_bytes.len() != 32 {
                return Err(jsonrpc_core::Error::invalid_params(
                    "'model_id' must be 32 bytes",
                ));
            }
            let mut model_arr = [0u8; 32];
            model_arr.copy_from_slice(&model_id_bytes);
            let model_id = citrate_execution::types::ModelId(Hash::new(model_arr));

            // input (any JSON → bytes)
            let input_val = obj
                .get("input")
                .cloned()
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'input'"))?;
            let input_bytes = serde_json::to_vec(&input_val)
                .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'input' JSON"))?;

            // optional from (hex 20-byte)
            let from_addr = if let Some(s) = obj.get("from").and_then(|v| v.as_str()) {
                let b = hex::decode(s.trim_start_matches("0x"))
                    .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'from'"))?;
                if b.len() != 20 {
                    return Err(jsonrpc_core::Error::invalid_params(
                        "'from' must be 20 bytes",
                    ));
                }
                let mut a = [0u8; 20];
                a.copy_from_slice(&b);
                Address(a)
            } else {
                Address([0u8; 20])
            };

            // optional max_gas
            let max_gas = parse_optional_u64_field(obj.get("max_gas"), "max_gas")?
                .unwrap_or(1_000_000);

            let res = match block_on(executor_ai_inf.run_inference_preview(
                from_addr,
                model_id,
                input_bytes,
                max_gas,
            )) {
                Ok(r) => r,
                Err(e) => {
                    return Err(jsonrpc_core::Error::invalid_params(format!(
                        "Inference failed: {}",
                        e
                    )))
                }
            };

            // Try to decode output as JSON; fallback to base64
            let (output_val, encoding) = match serde_json::from_slice::<serde_json::Value>(&res.output)
            {
                Ok(v) => (v, "json"),
                Err(_) => (
                    json!(STANDARD.encode(&res.output)),
                    "base64",
                ),
            };

            Ok(json!({
                "status": "success",
                "output": output_val,
                "encoding": encoding,
                "execution_time_ms": res.latency_ms,
                "gas_used": res.gas_used,
                "provider": format!("0x{}", hex::encode(res.provider.0)),
                "provider_fee": res.provider_fee.to_string(),
                "proof": res.proof.map(|p| format!("0x{}", hex::encode(p))),
            }))
        });

        // citrate_getAIStatus — reports model count, GGUF availability, inference readiness
        let executor_ai_status = executor.clone();
        io_handler.add_sync_method("citrate_getAIStatus", move |_params: Params| {
            rpc_request("citrate_getAIStatus");

            let all_models = executor_ai_status.state_db().all_models();
            let model_count = all_models.len();

            // Check if llama.cpp binary is reachable
            let gguf_available = std::process::Command::new("llama-cli")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            let has_inference_service = executor_ai_status.has_inference_service();

            Ok(json!({
                "model_count": model_count,
                "gguf_engine_available": gguf_available,
                "inference_service_ready": has_inference_service,
                "models": all_models.iter().take(50).map(|(id, state)| {
                    json!({
                        "id": hex::encode(id.0.as_bytes()),
                        "name": state.metadata.name,
                        "owner": format!("0x{}", hex::encode(state.owner.0)),
                    })
                }).collect::<Vec<_>>(),
            }))
        });

        // citrate_runInference (synchronous preview via Executor)
        let executor_ai_preview = executor.clone();
        io_handler.add_sync_method("citrate_runInference", move |params: Params| {
            rpc_request("citrate_runInference");

            // Expect an object payload
            let value: serde_json::Value = match params.parse() {
                Ok(v) => v,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            // Accept both {model_id: ...} and [{model_id: ...}]
            let obj_value = match &value {
                serde_json::Value::Array(arr) if !arr.is_empty() => arr[0].clone(),
                _ => value.clone(),
            };
            let obj = match obj_value.as_object() {
                Some(m) => m,
                None => {
                    return Err(jsonrpc_core::Error::invalid_params(
                        "Expected params object",
                    ))
                }
            };

            // model_id (hex, 32 bytes)
            let model_id_str = obj
                .get("model_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'model_id'"))?;
            let model_id_bytes = hex::decode(model_id_str.trim_start_matches("0x"))
                .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'model_id'"))?;
            if model_id_bytes.len() != 32 {
                return Err(jsonrpc_core::Error::invalid_params(
                    "'model_id' must be 32 bytes",
                ));
            }
            let mut model_arr = [0u8; 32];
            model_arr.copy_from_slice(&model_id_bytes);
            let model_id = citrate_execution::types::ModelId(Hash::new(model_arr));

            // input (any JSON)
            let input_val = obj
                .get("input")
                .cloned()
                .ok_or_else(|| jsonrpc_core::Error::invalid_params("Missing 'input'"))?;
            let input_bytes = serde_json::to_vec(&input_val)
                .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'input' JSON"))?;

            // optional from (hex 20‑byte)
            let from_addr = if let Some(s) = obj.get("from").and_then(|v| v.as_str()) {
                let b = hex::decode(s.trim_start_matches("0x"))
                    .map_err(|_| jsonrpc_core::Error::invalid_params("Invalid 'from'"))?;
                if b.len() != 20 {
                    return Err(jsonrpc_core::Error::invalid_params(
                        "'from' must be 20 bytes",
                    ));
                }
                let mut a = [0u8; 20];
                a.copy_from_slice(&b);
                Address(a)
            } else {
                Address([0u8; 20])
            };

            // optional max_gas
            let max_gas = parse_optional_u64_field(obj.get("max_gas"), "max_gas")?
                .unwrap_or(1_000_000);

            // optional with_proof (not used in preview other than returning proof if available)
            let _with_proof = obj.get("with_proof").and_then(|v| v.as_bool()).unwrap_or(false);

            // Spawn a dedicated thread with its own tokio runtime to avoid
            // deadlocking on tokio::sync::RwLock/Mutex inside the MCP layer
            // (futures::executor::block_on cannot drive tokio primitives).
            let exec_inf = executor_ai_preview.clone();
            let res = match std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("runtime: {}", e))?;
                rt.block_on(exec_inf.run_inference_preview(
                    from_addr,
                    model_id,
                    input_bytes,
                    max_gas,
                ))
                .map_err(|e| format!("{}", e))
            })
            .join()
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    return Err(jsonrpc_core::Error::invalid_params(format!(
                        "Inference failed: {}",
                        e
                    )))
                }
                Err(_) => {
                    return Err(jsonrpc_core::Error::internal_error())
                }
            };

            // Try to decode output as JSON; fallback to base64
            let (output_val, encoding) = match serde_json::from_slice::<serde_json::Value>(&res.output)
            {
                Ok(v) => (v, "json"),
                Err(_) => (
                    json!(base64::engine::general_purpose::STANDARD.encode(&res.output)),
                    "base64",
                ),
            };

            Ok(json!({
                "output": output_val,
                "encoding": encoding,
                "execution_time_ms": res.latency_ms,
                "gas_used": res.gas_used,
                "provider": format!("0x{}", hex::encode(res.provider.0)),
                "provider_fee": res.provider_fee.to_string(),
                "proof": res.proof.map(|p| format!("0x{}", hex::encode(p))),
            }))
        });

        // citrate_getInferenceResult
        let storage_ai_result = storage.clone();
        let mempool_ai_result = mempool.clone();
        let executor_ai_result = executor.clone();
        io_handler.add_sync_method("citrate_getInferenceResult", move |params: Params| {
            rpc_request("citrate_getInferenceResult");
            let api = AiApi::new(
                storage_ai_result.clone(),
                mempool_ai_result.clone(),
                executor_ai_result.clone(),
            );

            let request_id_str: String = match params.parse() {
                Ok(id) => id,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            match hex::decode(&request_id_str) {
                Ok(hash_bytes) if hash_bytes.len() == 32 => {
                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(&hash_bytes);
                    let request_hash = Hash::new(hash_array);

                    match block_on(api.get_inference_result(request_hash)) {
                        Ok(result) => Ok(serde_json::to_value(result).unwrap_or(Value::Null)),
                        Err(_) => Ok(Value::Null),
                    }
                }
                _ => Err(jsonrpc_core::Error::invalid_params(
                    "Invalid request ID format".to_string(),
                )),
            }
        });

        // citrate_createTrainingJob
        let storage_ai_job = storage.clone();
        let mempool_ai_job = mempool.clone();
        let executor_ai_job = executor.clone();
        io_handler.add_sync_method("citrate_createTrainingJob", move |_params: Params| {
            rpc_request("citrate_createTrainingJob");
            let _api = AiApi::new(
                storage_ai_job.clone(),
                mempool_ai_job.clone(),
                executor_ai_job.clone(),
            );

            match block_on(async {
                // Placeholder - would parse actual CreateTrainingJobRequest
                Ok::<serde_json::Value, ApiError>(serde_json::json!({
                    "status": "success",
                    "message": "Training job creation not fully implemented yet"
                }))
            }) {
                Ok(result) => Ok(result),
                Err(_e) => Err(jsonrpc_core::Error::internal_error()),
            }
        });

        // citrate_getTrainingJob
        let storage_ai_job_get = storage.clone();
        let mempool_ai_job_get = mempool.clone();
        let executor_ai_job_get = executor.clone();
        io_handler.add_sync_method("citrate_getTrainingJob", move |params: Params| {
            rpc_request("citrate_getTrainingJob");
            let api = AiApi::new(
                storage_ai_job_get.clone(),
                mempool_ai_job_get.clone(),
                executor_ai_job_get.clone(),
            );

            let job_id_str: String = match params.parse() {
                Ok(id) => id,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };

            match hex::decode(&job_id_str) {
                Ok(job_id_bytes) if job_id_bytes.len() == 32 => {
                    let mut job_id_array = [0u8; 32];
                    job_id_array.copy_from_slice(&job_id_bytes);
                    let job_id = citrate_execution::types::JobId(Hash::new(job_id_array));

                    match block_on(api.get_training_job(job_id)) {
                        Ok(job) => Ok(serde_json::to_value(job).unwrap_or(Value::Null)),
                        Err(_) => Ok(Value::Null),
                    }
                }
                _ => Err(jsonrpc_core::Error::invalid_params(
                    "Invalid job ID format".to_string(),
                )),
            }
        });

        // ========= Artifacts ==========
        // citrate_pinArtifact [cid, replicas]
        io_handler.add_sync_method("citrate_pinArtifact", move |params: Params| {
            rpc_request("citrate_pinArtifact");
            let (cid, _replicas): (String, u64) = match params.parse() {
                Ok(t) => t,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            match ipfs_pin_blocking(&cid) {
                Ok(()) => Ok(serde_json::json!({"status":"ok"})),
                Err(e) => Ok(serde_json::json!({"status":"error","message": e})),
            }
        });

        // citrate_getArtifactStatus [cid]
        io_handler.add_sync_method("citrate_getArtifactStatus", move |params: Params| {
            rpc_request("citrate_getArtifactStatus");
            let (cid,): (String,) = match params.parse() {
                Ok(c) => c,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            match ipfs_status_blocking(&cid) {
                Ok(s) => {
                    let parsed = serde_json::from_str::<serde_json::Value>(&s);
                    match parsed {
                        Ok(v) if v.is_array() => Ok(v),
                        Ok(v) => Ok(serde_json::json!([{"provider":"local","status": v.get("status").and_then(|s| s.as_str()).unwrap_or("unknown")}])),
                        Err(_) => Ok(serde_json::json!([{"provider":"local","status": s}])),
                    }
                }
                Err(_) => Ok(serde_json::json!([{"provider":"local","status":"unknown"}])),
            }
        });

        // citrate_listModelArtifacts [modelIdHex]
        let executor_art_list = executor.clone();
        io_handler.add_sync_method("citrate_listModelArtifacts", move |params: Params| {
            rpc_request("citrate_listModelArtifacts");
            let (model_id_str,): (String,) = match params.parse() {
                Ok(s) => s,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            let model_id_hex = model_id_str.trim_start_matches("0x");
            match hex::decode(model_id_hex) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    let hash = Hash::new(arr);
                    let list = executor_art_list.list_model_artifacts(&hash);
                    Ok(serde_json::to_value(list).unwrap_or(serde_json::json!([])))
                }
                _ => Err(jsonrpc_core::Error::invalid_params(
                    "Invalid model ID format",
                )),
            }
        });

        // citrate_listProofArtifacts [modelIdHex]
        let executor_proof_list = executor.clone();
        io_handler.add_sync_method("citrate_listProofArtifacts", move |params: Params| {
            rpc_request("citrate_listProofArtifacts");
            let (model_id_str,): (String,) = match params.parse() {
                Ok(s) => s,
                Err(e) => return Err(jsonrpc_core::Error::invalid_params(e.to_string())),
            };
            let model_id_hex = model_id_str.trim_start_matches("0x");
            match hex::decode(model_id_hex) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    let hash = Hash::new(arr);
                    let list = executor_proof_list.list_model_proofs(&hash);
                    Ok(serde_json::to_value(list).unwrap_or(serde_json::json!([])))
                }
                _ => Err(jsonrpc_core::Error::invalid_params(
                    "Invalid model ID format",
                )),
            }
        });

        Self {
            config,
            storage,
            mempool,
            peer_manager,
            executor,
            io_handler,
        }
    }

    /// Spawn the RPC server on a dedicated OS thread and return a CloseHandle and JoinHandle.
    /// If startup fails (e.g., port already in use), returns an error instead of panicking.
    pub fn spawn(self) -> Result<(CloseHandle, std::thread::JoinHandle<()>)> {
        let listen_addr = self.config.listen_addr;
        let threads = self.config.threads;
        let cors_origins = self.config.cors_origins.clone();
        let rate_limit_config = self.config.rate_limit.clone();
        let io = self.io_handler;

        // Channel to report startup result (CloseHandle or error string)
        let (result_tx, result_rx) =
            std::sync::mpsc::sync_channel::<Result<CloseHandle, String>>(1);

        let join_handle = std::thread::spawn(move || {
            let mut builder = ServerBuilder::new(io)
                .request_middleware(RateLimiter::new(rate_limit_config));
            // WP-X.1: Config-driven CORS — wildcard only allowed on localhost
            if cors_origins.iter().any(|o| o == "*") {
                tracing::warn!("CORS wildcard '*' configured — this is unsafe for public deployments. Use explicit origins in production.");
                builder = builder.cors(DomainsValidation::AllowOnly(vec![
                    AccessControlAllowOrigin::Any,
                ]));
            } else if !cors_origins.is_empty() {
                let origins: Vec<AccessControlAllowOrigin> = cors_origins
                    .iter()
                    .map(|o| AccessControlAllowOrigin::Value(o.clone().into()))
                    .collect();
                builder = builder.cors(DomainsValidation::AllowOnly(origins));
            }
            // Empty cors_origins = no CORS headers (browser cross-origin blocked by default)
            info!("RPC rate limiting enabled: {} req/{}s per IP",
                  100, 1); // defaults
            match builder
                .max_request_body_size(10 * 1024 * 1024)
                .threads(threads)
                .start_http(&listen_addr)
            {
                Ok(server) => {
                    info!("RPC server listening on {}", listen_addr);
                    // Send close handle back to caller
                    let _ = result_tx.send(Ok(server.close_handle()));
                    // Block until closed
                    server.wait();
                }
                Err(e) => {
                    let _ = result_tx.send(Err(format!(
                        "Failed to start RPC server on {}: {}",
                        listen_addr, e
                    )));
                    // Exit thread
                }
            }
        });

        // Receive startup result
        match result_rx.recv() {
            Ok(Ok(close)) => Ok((close, join_handle)),
            Ok(Err(msg)) => {
                // Ensure the thread has exited before returning error
                let _ = join_handle.join();
                Err(anyhow::anyhow!(msg))
            }
            Err(e) => {
                // Thread ended before sending a result
                let _ = join_handle.join();
                Err(anyhow::anyhow!("RPC thread failed: {}", e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{PublicKey, Signature, Transaction};
    use citrate_network::peer::PeerManagerConfig;
    use citrate_sequencer::mempool::{MempoolConfig, TxClass};
    use citrate_storage::pruning::PruningConfig;
    use std::sync::Mutex;
    use tempfile::TempDir;
    // no-op

    static OPERATOR_ENV_GUARD: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        key: &'static str,
        old: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let old = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, old }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(old) = self.old.take() {
                std::env::set_var(self.key, old);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn relaxed_mempool() -> Arc<Mempool> {
        Arc::new(Mempool::new(MempoolConfig {
            max_size: 20_000,
            max_per_sender: 20_000,
            min_gas_price: 1,
            require_valid_signature: false,
            chain_id: 40204,
            ..Default::default()
        }))
    }

    fn rpc_with_mempool(mempool: Arc<Mempool>) -> (RpcServer, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            Arc::new(StorageManager::new(temp_dir.path(), PruningConfig::default()).unwrap());
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let state_db = Arc::new(citrate_execution::StateDB::new());
        let executor = Arc::new(Executor::new(state_db));
        let rpc = RpcServer::new(
            RpcConfig::default(),
            storage,
            mempool,
            peer_manager,
            executor,
            40204,
        );
        (rpc, temp_dir)
    }

    fn make_test_tx(nonce: u64, data: Vec<u8>) -> Transaction {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[24..].copy_from_slice(&nonce.to_be_bytes());
        let mut from_bytes = [1u8; 32];
        from_bytes[0..8].copy_from_slice(&nonce.to_be_bytes());
        let mut to_bytes = [2u8; 32];
        to_bytes[0..8].copy_from_slice(&nonce.to_be_bytes());

        Transaction {
            hash: Hash::new(hash_bytes),
            nonce,
            from: PublicKey::new(from_bytes),
            to: Some(PublicKey::new(to_bytes)),
            value: nonce as u128,
            gas_limit: 21_000,
            gas_price: 1_000_000_000 + nonce,
            data,
            signature: Signature::new([7u8; 64]),
            chain_id: Some(40204),
            ..Default::default()
        }
    }

    fn add_test_tx(mempool: &Arc<Mempool>, nonce: u64, data: Vec<u8>) {
        futures::executor::block_on(mempool.add_transaction(
            make_test_tx(nonce, data),
            TxClass::Standard,
        ))
        .expect("test transaction admitted to relaxed mempool");
    }

    #[tokio::test]
    async fn test_rpc_chain_height_and_tx_submit() {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            Arc::new(StorageManager::new(temp_dir.path(), PruningConfig::default()).unwrap());
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let state_db = Arc::new(citrate_execution::StateDB::new());
        let executor = Arc::new(Executor::new(state_db));

        let rpc = RpcServer::new(
            RpcConfig::default(),
            storage,
            mempool.clone(),
            peer_manager,
            executor,
            1,
        );

        // chain_getHeight
        let req =
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"chain_getHeight","params":[]})
                .to_string();
        let resp = rpc.io_handler.handle_request(&req).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"], 0);

        // Note: tx submission path is covered via integration tests elsewhere.
    }

    // REM-13b: was gated on `verifier-ethers-solc`. The feature
    // gate has been removed; the test still skips itself if solc
    // is not on PATH.
    #[test]
    fn test_compile_single_contract_opt_and_unopt() {
        // Skip if solc is not available on PATH
        if std::process::Command::new("solc")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("solc not installed; skipping verifier test");
            return;
        }
        let src = r#"// SPDX-License-Identifier: MIT
        pragma solidity ^0.8.24;
        contract Single {
            uint256 private x;
            function set(uint256 v) public { x = v; }
            function get() public view returns (uint256) { return x; }
        }
        "#;

        let bin_opt = super::compile_runtime_bytecode(src, "0.8.24", true, Some("Single"))
            .expect("compile optimized");
        let bin_unopt = super::compile_runtime_bytecode(src, "0.8.24", false, Some("Single"))
            .expect("compile unoptimized");
        assert!(!bin_opt.is_empty());
        assert!(!bin_unopt.is_empty());
    }

    // REM-13b: was gated on `verifier-ethers-solc`. The feature
    // gate has been removed; the test still skips itself if solc
    // is not on PATH.
    #[test]
    fn test_compile_multi_contract_select_by_name() {
        // Skip if solc is not available on PATH
        if std::process::Command::new("solc")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("solc not installed; skipping verifier test");
            return;
        }
        let src = r#"// SPDX-License-Identifier: MIT
        pragma solidity ^0.8.24;
        contract A { function a() public pure returns (uint256) { return 1; } }
        contract B { function b() public pure returns (uint256) { return 2; } }
        "#;
        let bin_a =
            super::compile_runtime_bytecode(src, "0.8.24", true, Some("A")).expect("compile A");
        let bin_b =
            super::compile_runtime_bytecode(src, "0.8.24", true, Some("B")).expect("compile B");
        assert!(!bin_a.is_empty());
        assert!(!bin_b.is_empty());
        assert_ne!(bin_a, bin_b);
    }

    #[tokio::test]
    async fn test_rpc_invalid_params_error_shape() {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            Arc::new(StorageManager::new(temp_dir.path(), PruningConfig::default()).unwrap());
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let state_db = Arc::new(citrate_execution::StateDB::new());
        let executor = Arc::new(Executor::new(state_db));

        let rpc = RpcServer::new(
            RpcConfig::default(),
            storage,
            mempool.clone(),
            peer_manager,
            executor,
            1,
        );

        let req = serde_json::json!({
            "jsonrpc":"2.0","id":42,
            "method":"citrate_verifyContract",
            "params":[{"address":"0xdeadbeef","runtime_bytecode":"0x"}]
        })
        .to_string();
        let resp = rpc.io_handler.handle_request(&req).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 42);
        assert!(v.get("error").is_some());
    }

    #[test]
    fn test_t0_07_mempool_get_pending_requires_operator_token() {
        let _lock = OPERATOR_ENV_GUARD.lock().expect("operator env guard");
        let _env = EnvGuard::set("CITRATE_OPERATOR_TOKEN", "j1-7-token");
        let mempool = relaxed_mempool();
        add_test_tx(&mempool, 1, b"private-calldata".to_vec());
        let (rpc, _temp_dir) = rpc_with_mempool(mempool);

        let req =
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"mempool_getPending","params":{}})
                .to_string();
        let resp = futures::executor::block_on(rpc.io_handler.handle_request(&req)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();

        assert_eq!(v["error"]["code"], -32001);
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("operator_token required"),
            "T0-07: unauthenticated pending dump must fail closed: {}",
            v
        );
    }

    #[test]
    fn test_t0_07_mempool_get_pending_is_bounded_and_redacted() {
        let _lock = OPERATOR_ENV_GUARD.lock().expect("operator env guard");
        let _env = EnvGuard::set("CITRATE_OPERATOR_TOKEN", "j1-7-token");
        let mempool = relaxed_mempool();
        add_test_tx(&mempool, 1, b"super-secret-calldata-marker".to_vec());
        let (rpc, _temp_dir) = rpc_with_mempool(mempool);

        let req = serde_json::json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"mempool_getPending",
            "params":{"operator_token":"j1-7-token","limit":10}
        })
        .to_string();
        let resp = futures::executor::block_on(rpc.io_handler.handle_request(&req)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();

        assert!(v.get("error").is_none(), "T0-07 auth request failed: {}", v);
        assert_eq!(v["result"]["returned"], 1);
        assert_eq!(v["result"]["pending"][0]["dataSize"], 28);
        assert!(
            !resp.contains("super-secret-calldata-marker"),
            "T0-07: pending response must not expose raw calldata"
        );
    }

    #[test]
    fn test_t0_07_mempool_get_pending_caps_large_pages() {
        let _lock = OPERATOR_ENV_GUARD.lock().expect("operator env guard");
        let _env = EnvGuard::set("CITRATE_OPERATOR_TOKEN", "j1-7-token");
        let mempool = relaxed_mempool();
        for nonce in 0..150u64 {
            add_test_tx(&mempool, nonce, vec![0xAB; 2048]);
        }
        let (rpc, _temp_dir) = rpc_with_mempool(mempool);

        let req = serde_json::json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"mempool_getPending",
            "params":{"operator_token":"j1-7-token","limit":10_000}
        })
        .to_string();
        let resp = futures::executor::block_on(rpc.io_handler.handle_request(&req)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();

        assert!(v.get("error").is_none(), "T0-07 capped request failed: {}", v);
        assert_eq!(v["result"]["limit"], crate::methods::mempool::MAX_PENDING_LIMIT);
        assert_eq!(v["result"]["returned"], crate::methods::mempool::MAX_PENDING_LIMIT);
        assert_eq!(v["result"]["truncated"], true);
        assert!(
            resp.len() < crate::methods::mempool::MAX_PENDING_RESPONSE_BYTES,
            "T0-07: pending response exceeded response cap: {} bytes",
            resp.len()
        );
    }

    #[test]
    fn test_t0_07_pending_method_registrations_are_operator_gated() {
        let server_src = include_str!("server.rs");
        let pending_idx = server_src
            .find("add_sync_method(\"mempool_getPending\"")
            .expect("server.rs must register mempool_getPending");
        let pending_window =
            &server_src[pending_idx..(pending_idx + 1_500).min(server_src.len())];
        assert!(
            pending_window.contains("require_operator_auth"),
            "T0-07: mempool_getPending closure must require operator auth"
        );

        let eth_rpc_src = include_str!("eth_rpc.rs");
        let snapshot_idx = eth_rpc_src
            .find("add_sync_method(\"citrate_getMempoolSnapshot\"")
            .expect("eth_rpc.rs must register citrate_getMempoolSnapshot");
        let snapshot_window =
            &eth_rpc_src[snapshot_idx..(snapshot_idx + 1_500).min(eth_rpc_src.len())];
        assert!(
            snapshot_window.contains("require_operator_auth")
                && snapshot_window.contains("PendingQuery::from_params_map")
                && snapshot_window.contains("get_pending"),
            "T0-07: alternate pending-detail method must use the same bounded operator path"
        );
    }
}
