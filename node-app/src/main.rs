use anyhow::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

use axum::{response::IntoResponse, routing::get, Router};
use citrate_api::{ApiService, RpcConfig};
use citrate_execution::{Executor, StateDB};
use citrate_network::peer::{PeerManager, PeerManagerConfig};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use prometheus::{gather, Encoder, TextEncoder};

/// Parse a hardcoded socket address literal. This is infallible for valid literals
/// but avoids a bare `.unwrap()` call in production code.
fn hardcoded_addr(s: &str) -> SocketAddr {
    s.parse()
        .unwrap_or_else(|_| unreachable!("BUG: invalid hardcoded address literal: {}", s))
}

fn data_dir() -> PathBuf {
    std::env::var_os("CITRATE_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/data"))
}

fn rpc_addr() -> SocketAddr {
    std::env::var("CITRATE_RPC_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        // WP-X.1: Default to loopback (was 0.0.0.0 — exposed to all interfaces)
        .unwrap_or_else(|| hardcoded_addr("127.0.0.1:8545"))
}

fn metrics_addr() -> SocketAddr {
    std::env::var("CITRATE_METRICS_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| hardcoded_addr("0.0.0.0:9100"))
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

    // Executor
    let state_db = Arc::new(StateDB::new());
    let executor = Arc::new(Executor::new(state_db));

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
    let ws_addr: SocketAddr = hardcoded_addr("127.0.0.1:8546");
    let rest_addr: SocketAddr = hardcoded_addr("127.0.0.1:3000");
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
