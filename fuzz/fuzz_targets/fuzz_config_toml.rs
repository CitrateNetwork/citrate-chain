#![no_main]
use libfuzzer_sys::fuzz_target;

/// Mirror of the node's NodeConfig structure for TOML fuzzing.
/// The actual NodeConfig lives in citrate-node (a binary crate, not importable).
/// We replicate the top-level shape here to exercise the same TOML parsing paths.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct FuzzNodeConfig {
    chain: Option<FuzzChainConfig>,
    network: Option<FuzzNetworkConfig>,
    rpc: Option<FuzzRpcConfig>,
    storage: Option<FuzzStorageConfig>,
    mining: Option<FuzzMiningConfig>,
    validator: Option<FuzzValidatorConfig>,
    vrf: Option<FuzzVrfConfig>,
    checkpoint: Option<FuzzCheckpointConfig>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FuzzChainConfig {
    chain_id: Option<u64>,
    genesis_file: Option<String>,
    data_dir: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FuzzNetworkConfig {
    listen_addr: Option<String>,
    boot_nodes: Option<Vec<String>>,
    max_peers: Option<usize>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FuzzRpcConfig {
    http_addr: Option<String>,
    ws_addr: Option<String>,
    enabled: Option<bool>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FuzzStorageConfig {
    db_path: Option<String>,
    cache_size: Option<usize>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FuzzMiningConfig {
    enabled: Option<bool>,
    block_time_ms: Option<u64>,
    max_block_size: Option<usize>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FuzzValidatorConfig {
    enabled: Option<bool>,
    validators: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FuzzVrfConfig {
    strict_vrf: Option<bool>,
    migration_mode: Option<bool>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FuzzCheckpointConfig {
    enabled: Option<bool>,
    interval: Option<u64>,
    committee_size: Option<usize>,
}

fuzz_target!(|data: &[u8]| {
    // Fuzz TOML config parsing with arbitrary bytes.
    // Exercises the same deserialization path used by NodeConfig::from_file().
    // The parser must never panic on malformed TOML.
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<FuzzNodeConfig, _> = toml::from_str(s);
    }
});
