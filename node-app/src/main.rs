// PANIC-S1 G2: production code in this crate may not panic (tests excepted).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use anyhow::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

use axum::{response::IntoResponse, routing::get, Router};
use citrate_api::{ApiService, RpcConfig};
use citrate_execution::executor::DEFAULT_CHAIN_ID;
use citrate_execution::precompiles::inference::InferenceMode;
use citrate_execution::{Executor, StateDB};
use citrate_network::peer::{PeerManager, PeerManagerConfig};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use prometheus::{gather, Encoder, TextEncoder};

/// REM-N-03 / WP-H1.2: resolve the inference determinism mode from
/// command-line arguments. The opt-out flag
/// `--allow-nondeterministic-inference` is gated behind the `dev-mode`
/// cargo feature: release / production builds do not even compile
/// the flag, so an operator cannot disable the C-01 gate by accident.
fn resolve_inference_mode(args: &[String]) -> InferenceMode {
    let production_default = Executor::production_inference_mode();
    #[cfg(feature = "dev-mode")]
    {
        if args
            .iter()
            .any(|a| a == "--allow-nondeterministic-inference")
        {
            warn!(
                "REM-N-03: --allow-nondeterministic-inference is set; \
                 the 0x0101 / 0x0102 inference precompiles will run \
                 non-deterministic FP code. This is a devnet-only \
                 opt-out and MUST NOT be used on mainnet validators."
            );
            return InferenceMode::AllowNonDeterministic;
        }
    }
    #[cfg(not(feature = "dev-mode"))]
    {
        if args
            .iter()
            .any(|a| a == "--allow-nondeterministic-inference")
        {
            warn!(
                "REM-N-03: --allow-nondeterministic-inference is only \
                 available in builds compiled with the `dev-mode` \
                 feature; ignoring on this production build."
            );
        }
    }
    production_default
}

fn resolve_data_dir(
    override_dir: Option<PathBuf>,
    home_dir: Option<PathBuf>,
    is_windows: bool,
) -> PathBuf {
    override_dir.unwrap_or_else(|| {
        if is_windows {
            home_dir
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".citrate")
                .join("node-app")
        } else {
            PathBuf::from("/data")
        }
    })
}
fn data_dir() -> PathBuf {
    resolve_data_dir(
        std::env::var_os("CITRATE_DATA_DIR").map(PathBuf::from),
        dirs::home_dir(),
        cfg!(windows),
    )
}

fn rpc_addr() -> SocketAddr {
    std::env::var("CITRATE_RPC_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        // WP-X.1: Default to loopback (was 0.0.0.0 — exposed to all interfaces)
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8545)))
}

fn metrics_addr() -> SocketAddr {
    std::env::var("CITRATE_METRICS_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 9100)))
}

async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = gather();
    let mut buf = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buf) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode error: {}", e),
        );
    }
    (
        axum::http::StatusCode::OK,
        String::from_utf8(buf).unwrap_or_default(),
    )
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,citrate=info".into()))
        .with_target(false)
        .init();

    // Storage
    let data_dir = data_dir();
    std::fs::create_dir_all(&data_dir)?;
    let pruning = PruningConfig::default();
    let storage = Arc::new(StorageManager::new(&data_dir, pruning)?);

    // Executor — REM-N-03 / WP-H1.2: production default is
    // `InferenceMode::Strict`. Devnet may opt in to non-deterministic
    // inference via `--allow-nondeterministic-inference`, but only
    // when the binary was built with `--features dev-mode`.
    let cli_args: Vec<String> = std::env::args().collect();
    let inference_mode = resolve_inference_mode(&cli_args);
    let chain_id = std::env::var("CITRATE_CHAIN_ID")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CHAIN_ID);
    // PBA-R2: honour the fleet activation height (CITRATE_PBA_HARDENING_HEIGHT)
    // so eth_call / eth_estimateGas apply the same rules as the node.
    let pba = citrate_execution::activation::init_pba_hardening_for_chain(chain_id, None, false)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    info!("PBA hardening activation: {}", pba.describe());
    // HUP-S7.2: the agent precompile fork height, through the node's resolver
    // (release pin for 40204; CITRATE_AGENT_PRECOMPILES_HEIGHT on dev chains),
    // so eth_call sees the same precompile set as the node at every height.
    let (agent_fork_height, agent_fork_source) =
        citrate_execution::agent_fork::init_for_chain(chain_id, None)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    match agent_fork_height {
        Some(h) => info!(
            "Agent precompile fork active from height {} (source: {})",
            h, agent_fork_source
        ),
        None => info!(
            "Agent precompile fork not scheduled (source: {})",
            agent_fork_source
        ),
    }
    let state_db = Arc::new(StateDB::new());
    let executor = Arc::new(Executor::with_chain_id_and_inference_mode(
        state_db,
        chain_id,
        inference_mode,
    ));

    // Mempool (default config)
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));

    // Network (placeholder manager)
    let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));

    // RPC config
    let rpc_cfg = RpcConfig {
        listen_addr: rpc_addr(),
        ..Default::default()
    };
    info!(
        "Starting Citrate RPC on {} (data_dir={:?})",
        rpc_cfg.listen_addr, data_dir
    );

    // Start metrics server
    let maddr = metrics_addr();
    tokio::spawn(async move {
        let app = Router::new().route("/metrics", get(metrics_handler));
        let listener = match tokio::net::TcpListener::bind(&maddr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind metrics server to {}: {}", maddr, e);
                return;
            }
        };
        info!("Metrics server listening on {}", maddr);
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("metrics server error: {}", e);
        }
    });

    // API service (WebSocket and REST addresses)
    // WP-X.1: Default to loopback (was 0.0.0.0)
    let ws_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 8546));
    let rest_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let api = ApiService::new(
        rpc_cfg,
        ws_addr,
        rest_addr,
        storage,
        mempool,
        peer_manager,
        executor,
        1,
    );

    // Start
    if let Err(e) = api.start().await {
        error!("API service exited with error: {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HUP-S7.2: this RPC binary executes eth_call / eth_estimateGas with the
    /// same execution crate as the node, so it must publish the agent
    /// precompile fork height through the same resolver, before the executor
    /// exists. Without it, once a release pins the fork for 40204, this binary
    /// would keep answering with the pre-fork precompile set.
    #[test]
    fn agent_fork_height_is_published_before_the_executor() {
        let main = include_str!("main.rs");
        let body = &main[..main.find("#[cfg(test)]").unwrap_or(main.len())];
        let init = body
            .find("citrate_execution::agent_fork::init_for_chain(chain_id, None)")
            .unwrap_or(usize::MAX);
        let pba = body
            .find("init_pba_hardening_for_chain(")
            .unwrap_or(usize::MAX);
        let exec = body
            .find("Executor::with_chain_id_and_inference_mode(")
            .unwrap_or(usize::MAX);
        assert!(
            init != usize::MAX,
            "node-app must publish the agent fork height"
        );
        assert!(
            pba < exec && init < exec,
            "both heights published before the executor"
        );
        assert!(
            !body.contains("set_agent_precompiles_height("),
            "one publication path"
        );
    }

    #[test]
    fn override_takes_precedence_on_windows() {
        let override_dir = PathBuf::from("custom-data");
        let home_dir = PathBuf::from("windows-home");

        assert_eq!(
            resolve_data_dir(Some(override_dir.clone()), Some(home_dir), true),
            override_dir,
            "CITRATE_DATA_DIR should override the Windows home-directory default"
        );
    }

    #[test]
    fn override_takes_precedence_on_non_windows() {
        let override_dir = PathBuf::from("custom-data");

        assert_eq!(
            resolve_data_dir(Some(override_dir.clone()), None, false),
            override_dir,
            "CITRATE_DATA_DIR should override the non-Windows /data default"
        );
    }

    #[test]
    fn windows_default_uses_home_directory() {
        let home_dir = PathBuf::from("windows-home");

        assert_eq!(
            resolve_data_dir(None, Some(home_dir.clone()), true),
            home_dir.join(".citrate").join("node-app"),
            "Windows should isolate node-app data under the user's .citrate directory"
        );
    }

    #[test]
    fn windows_default_falls_back_to_current_directory_without_home() {
        assert_eq!(
            resolve_data_dir(None, None, true),
            PathBuf::from(".").join(".citrate").join("node-app"),
            "Windows should use ./.citrate/node-app when no home directory is available"
        );
    }

    #[test]
    fn non_windows_default_remains_data() {
        assert_eq!(
            resolve_data_dir(None, Some(PathBuf::from("ignored-home")), false),
            PathBuf::from("/data"),
            "non-Windows platforms should preserve the /data default"
        );
    }
}
