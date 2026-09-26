// citrate/core/api/src/eth_subscriptions.rs
//
// Ethereum-compatible WebSocket subscriptions (eth_subscribe / eth_unsubscribe)
// Supports: newHeads, logs, pendingTransactions, syncing

use citrate_consensus::types::{Block, Hash};
use citrate_sequencer::mempool::Mempool;
use citrate_storage::StorageManager;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::{
    accept_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message},
};
use tracing::{debug, error, info};

/// CHAIN-B-D013: structural caps on the WebSocket server the node actually binds
/// (`EthSubscriptionServer`). Pre-fix it had none — no connection cap, no frame
/// cap, no idle timeout, no per-connection subscription cap — while the hardened
/// (dead) `WebSocketServer` had all of them. An unauthenticated attacker could
/// open unbounded idle connections or send 64 MiB frames (tungstenite's default).
///
/// Maximum concurrent connections; new connections past this are dropped.
const MAX_WS_CONNECTIONS: usize = 1024;
/// Maximum subscriptions per connection.
const MAX_SUBSCRIPTIONS_PER_CONN: usize = 64;
/// Maximum WebSocket message/frame size in bytes (1 MiB); default is 64 MiB.
const WS_MAX_MESSAGE_SIZE: usize = 1_048_576;
/// Idle timeout: a connection with no inbound message for this long is dropped.
const WS_IDLE_TIMEOUT_SECS: u64 = 60;
/// PBA-L1a-005: a client must complete the WebSocket upgrade within this window.
const WS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// PBA-L1a-005: most simultaneous sockets (pre- AND post-handshake) from one IP.
const MAX_WS_CONNECTIONS_PER_IP: usize = 32;
/// PBA-L1a-005: accept-error backoff bounds (EMFILE/ENFILE must not kill the loop).
const WS_ACCEPT_BACKOFF_MIN_MS: u64 = 50;
const WS_ACCEPT_BACKOFF_MAX_MS: u64 = 1_000;

/// PBA-L1a-005: socket admission limits, counted from `accept()` (not from the
/// end of the handshake) so never-upgraded sockets are bounded too.
#[derive(Debug, Clone, Copy)]
pub struct WsLimits {
    pub max_sockets: usize,
    pub max_per_ip: usize,
    pub handshake_timeout: std::time::Duration,
}

impl Default for WsLimits {
    fn default() -> Self {
        Self {
            max_sockets: MAX_WS_CONNECTIONS,
            max_per_ip: MAX_WS_CONNECTIONS_PER_IP,
            handshake_timeout: std::time::Duration::from_secs(WS_HANDSHAKE_TIMEOUT_SECS),
        }
    }
}

/// PBA-L1a-005: held for a socket's whole lifetime; releases its global and
/// per-IP slots on drop.
struct SocketSlot {
    _permit: tokio::sync::OwnedSemaphorePermit,
    ip: std::net::IpAddr,
    per_ip: Arc<std::sync::Mutex<HashMap<std::net::IpAddr, usize>>>,
}

impl Drop for SocketSlot {
    fn drop(&mut self) {
        let mut m = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

/// PBA-L1a-005: the accept loop, generic over the accept source so the
/// "an accept error does not end the loop" property is testable: errors are
/// logged and retried with backoff.
pub async fn run_accept_loop<A, AF, H>(mut accept: A, mut handle: H)
where
    A: FnMut() -> AF,
    AF: std::future::Future<Output = std::io::Result<(TcpStream, SocketAddr)>>,
    H: FnMut(TcpStream, SocketAddr),
{
    let mut backoff_ms = WS_ACCEPT_BACKOFF_MIN_MS;
    loop {
        match accept().await {
            Ok((stream, peer)) => {
                backoff_ms = WS_ACCEPT_BACKOFF_MIN_MS;
                handle(stream, peer);
            }
            Err(e) => {
                error!(
                    "WebSocket accept error (retrying in {} ms): {}",
                    backoff_ms, e
                );
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(WS_ACCEPT_BACKOFF_MAX_MS);
            }
        }
    }
}

/// Subscription types for eth_subscribe
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EthSubscriptionType {
    /// New block headers
    NewHeads,
    /// Log events matching filter
    Logs,
    /// New pending transactions
    NewPendingTransactions,
    /// Sync status changes
    Syncing,
}

/// Log filter for eth_subscribe("logs", filter)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogFilter {
    /// Contract addresses to filter (empty = all)
    #[serde(default)]
    pub address: Option<AddressFilter>,
    /// Topics to filter (up to 4, null = any)
    #[serde(default)]
    pub topics: Option<Vec<Option<TopicFilter>>>,
}

/// Address filter - single or array
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AddressFilter {
    Single(String),
    Multiple(Vec<String>),
}

/// Topic filter - single or array
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TopicFilter {
    Single(String),
    Multiple(Vec<String>),
}

/// Subscription request from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
}

/// Subscription response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub result: serde_json::Value,
}

/// Subscription notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: SubscriptionParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionParams {
    pub subscription: String,
    pub result: serde_json::Value,
}

/// Active subscription
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub sub_type: EthSubscriptionType,
    pub filter: Option<LogFilter>,
}

/// Block header for newHeads subscription
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub number: String,
    pub hash: String,
    pub parent_hash: String,
    pub nonce: String,
    pub sha3_uncles: String,
    pub logs_bloom: String,
    pub transactions_root: String,
    pub state_root: String,
    pub receipts_root: String,
    pub miner: String,
    pub difficulty: String,
    pub total_difficulty: String,
    pub extra_data: String,
    pub size: String,
    pub gas_limit: String,
    pub gas_used: String,
    pub timestamp: String,
    pub base_fee_per_gas: Option<String>,
    // PIL-50: GHOSTDAG topology surfaced on the live newHeads stream so
    // the explorer's live-DAG worker can render spine + merge edges
    // without re-fetching each block via eth_getBlockByHash. Field
    // names match the explorer parser
    // (citrate-explorer/src/lib/citrate/rpc.ts).
    /// `header.blue_score` as a hex u64 string.
    pub blue_score: String,
    /// `header.blue_work` as a hex u128 string.
    pub blue_work: String,
    /// Duplicates `parent_hash` under the Citrate-spec name so DAG-aware
    /// callers don't have to special-case the spelling.
    pub selected_parent_hash: String,
    /// Sibling tips this block merged into the selected chain. Empty
    /// when the block extended a single tip.
    pub merge_parent_hashes: Vec<String>,
}

impl From<&Block> for BlockHeader {
    fn from(block: &Block) -> Self {
        let merge_parents: Vec<String> = block
            .header
            .merge_parent_hashes
            .iter()
            .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
            .collect();
        Self {
            number: format!("0x{:x}", block.header.height),
            hash: format!("0x{}", hex::encode(block.header.block_hash.as_bytes())),
            parent_hash: format!("0x{}", hex::encode(block.header.selected_parent_hash.as_bytes())),
            nonce: "0x0000000000000000".to_string(),
            sha3_uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".to_string(),
            logs_bloom: "0x".to_string() + &"00".repeat(256),
            transactions_root: format!("0x{}", hex::encode(block.tx_root.as_bytes())),
            state_root: format!("0x{}", hex::encode(block.state_root.as_bytes())),
            receipts_root: format!("0x{}", hex::encode(block.receipt_root.as_bytes())),
            miner: format!("0x{}", hex::encode(&block.header.proposer_pubkey.0[12..32])), // Last 20 bytes
            difficulty: "0x0".to_string(),
            total_difficulty: "0x0".to_string(),
            extra_data: "0x".to_string(),
            size: "0x0".to_string(),
            gas_limit: "0x1c9c380".to_string(), // 30M gas
            gas_used: "0x0".to_string(),
            timestamp: format!("0x{:x}", block.header.timestamp),
            base_fee_per_gas: Some("0x7".to_string()),
            // PIL-50: GHOSTDAG fields.
            blue_score: format!("0x{:x}", block.header.blue_score),
            blue_work: format!("0x{:x}", block.header.blue_work),
            selected_parent_hash: format!(
                "0x{}",
                hex::encode(block.header.selected_parent_hash.as_bytes())
            ),
            merge_parent_hashes: merge_parents,
        }
    }
}

/// Log entry for logs subscription
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub block_hash: String,
    pub transaction_hash: String,
    pub transaction_index: String,
    pub log_index: String,
    pub removed: bool,
}

/// Ethereum-compatible WebSocket subscription server
#[allow(dead_code)]
pub struct EthSubscriptionServer {
    addr: SocketAddr,
    storage: Arc<StorageManager>,
    mempool: Arc<Mempool>,
    /// Broadcast channel for new block headers
    new_heads_tx: broadcast::Sender<Block>,
    /// Broadcast channel for pending transactions
    pending_tx_tx: broadcast::Sender<Hash>,
    /// Active connections
    connections: Arc<RwLock<HashMap<String, Arc<RwLock<ConnectionState>>>>>,
    /// PBA-L1a-005: socket admission limits.
    limits: WsLimits,
    /// PBA-L1a-005: global socket slots, taken at accept().
    socket_slots: Arc<tokio::sync::Semaphore>,
    /// PBA-L1a-005: live sockets per remote IP.
    per_ip: Arc<std::sync::Mutex<HashMap<std::net::IpAddr, usize>>>,
}

/// State for each WebSocket connection
struct ConnectionState {
    subscriptions: HashMap<String, Subscription>,
    next_sub_id: u64,
}

impl ConnectionState {
    fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
            next_sub_id: 1,
        }
    }

    fn next_subscription_id(&mut self) -> String {
        let id = format!("0x{:x}", self.next_sub_id);
        self.next_sub_id += 1;
        id
    }
}

impl EthSubscriptionServer {
    /// Create a new subscription server
    pub fn new(
        addr: SocketAddr,
        storage: Arc<StorageManager>,
        mempool: Arc<Mempool>,
    ) -> Self {
        let (new_heads_tx, _) = broadcast::channel(100);
        let (pending_tx_tx, _) = broadcast::channel(1000);

        let limits = WsLimits::default();
        Self {
            addr,
            storage,
            mempool,
            new_heads_tx,
            pending_tx_tx,
            connections: Arc::new(RwLock::new(HashMap::new())),
            socket_slots: Arc::new(tokio::sync::Semaphore::new(limits.max_sockets)),
            per_ip: Arc::new(std::sync::Mutex::new(HashMap::new())),
            limits,
        }
    }

    /// PBA-L1a-005: override the socket admission limits (tests, operators).
    pub fn with_limits(mut self, limits: WsLimits) -> Self {
        self.socket_slots = Arc::new(tokio::sync::Semaphore::new(limits.max_sockets));
        self.limits = limits;
        self
    }

    /// PBA-L1a-005: claim a global + per-IP slot for a freshly accepted socket,
    /// or `None` when either limit is reached (the socket is then dropped).
    fn try_claim_slot(&self, ip: std::net::IpAddr) -> Option<SocketSlot> {
        let permit = self.socket_slots.clone().try_acquire_owned().ok()?;
        {
            let mut m = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
            let n = m.entry(ip).or_insert(0);
            if *n >= self.limits.max_per_ip {
                return None;
            }
            *n += 1;
        }
        Some(SocketSlot {
            _permit: permit,
            ip,
            per_ip: self.per_ip.clone(),
        })
    }

    /// Get sender for broadcasting new block headers
    pub fn new_heads_sender(&self) -> broadcast::Sender<Block> {
        self.new_heads_tx.clone()
    }

    /// Get sender for broadcasting pending transactions
    pub fn pending_tx_sender(&self) -> broadcast::Sender<Hash> {
        self.pending_tx_tx.clone()
    }

    /// Broadcast a new block to all newHeads subscribers
    pub fn broadcast_new_head(&self, block: &Block) {
        let _ = self.new_heads_tx.send(block.clone());
    }

    /// Broadcast a pending transaction to all pendingTransactions subscribers
    pub fn broadcast_pending_transaction(&self, tx_hash: Hash) {
        let _ = self.pending_tx_tx.send(tx_hash);
    }

    /// Start the WebSocket server
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("Ethereum subscription WebSocket server listening on ws://{}", self.addr);

        // PBA-L1a-005: never exits on an accept error (backoff + retry), and
        // every accepted socket must claim a global + per-IP slot BEFORE the
        // handshake, which itself is time-bounded.
        let server = self.clone();
        run_accept_loop(
            || listener.accept(),
            move |stream, peer_addr| {
                let Some(slot) = server.try_claim_slot(peer_addr.ip()) else {
                    debug!("Refusing WebSocket socket from {}: socket limit reached", peer_addr);
                    drop(stream);
                    return;
                };
                let server = server.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    if let Err(e) = server.handle_connection(stream, peer_addr).await {
                        error!("WebSocket connection error from {}: {}", peer_addr, e);
                    }
                });
            },
        )
        .await;
        Ok(())
    }

    async fn handle_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        debug!("New WebSocket connection from {}", peer_addr);

        // CHAIN-B-D013: cap the frame/message size at accept time (1 MiB) rather
        // than tungstenite's 64 MiB default.
        let ws_config = WebSocketConfig {
            max_message_size: Some(WS_MAX_MESSAGE_SIZE),
            max_frame_size: Some(WS_MAX_MESSAGE_SIZE),
            ..Default::default()
        };
        // PBA-L1a-005: a socket that never completes the upgrade is dropped.
        let ws_stream = tokio::time::timeout(
            self.limits.handshake_timeout,
            accept_async_with_config(stream, Some(ws_config)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("WebSocket handshake timed out from {}", peer_addr))??;
        let (mut write, mut read) = ws_stream.split();

        let conn_id = format!("{}-{}", peer_addr, chrono::Utc::now().timestamp_millis());
        let conn_state = Arc::new(RwLock::new(ConnectionState::new()));

        // Register connection.
        // CHAIN-B-D013: enforce the concurrent-connection cap. Refuse (and drop)
        // the connection when the server is already at capacity, so an attacker
        // cannot open unbounded idle connections until the node exhausts memory.
        {
            let mut connections = self.connections.write().await;
            if connections.len() >= MAX_WS_CONNECTIONS {
                debug!(
                    "Refusing WebSocket from {} — max_connections ({}) reached",
                    peer_addr, MAX_WS_CONNECTIONS
                );
                return Ok(());
            }
            connections.insert(conn_id.clone(), conn_state.clone());
        }

        // Subscribe to broadcasts
        let mut new_heads_rx = self.new_heads_tx.subscribe();
        let mut pending_tx_rx = self.pending_tx_tx.subscribe();

        // Message handling loop.
        // CHAIN-B-D013: drop the connection after WS_IDLE_TIMEOUT_SECS with no
        // inbound message so idle connections cannot accumulate forever.
        let idle_timeout = std::time::Duration::from_secs(WS_IDLE_TIMEOUT_SECS);
        let mut last_activity = std::time::Instant::now();
        let mut idle_check = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = idle_check.tick() => {
                    if last_activity.elapsed() >= idle_timeout {
                        debug!("WebSocket connection {} idle-timed-out", conn_id);
                        break;
                    }
                }

                // Handle incoming messages
                msg = read.next() => {
                    last_activity = std::time::Instant::now();
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Some(response) = self.handle_message(&conn_state, &text).await {
                                let _ = write.send(Message::Text(response)).await;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            debug!("WebSocket connection {} closed", conn_id);
                            break;
                        }
                        Some(Ok(Message::Ping(data))) => {
                            let _ = write.send(Message::Pong(data)).await;
                        }
                        Some(Err(e)) => {
                            error!("WebSocket error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }

                // Broadcast new heads
                block = new_heads_rx.recv() => {
                    if let Ok(block) = block {
                        let state = conn_state.read().await;
                        for (sub_id, sub) in &state.subscriptions {
                            if sub.sub_type == EthSubscriptionType::NewHeads {
                                let header = BlockHeader::from(&block);
                                let notification = SubscriptionNotification {
                                    jsonrpc: "2.0".to_string(),
                                    method: "eth_subscription".to_string(),
                                    params: SubscriptionParams {
                                        subscription: sub_id.clone(),
                                        result: serde_json::to_value(&header).unwrap_or_default(),
                                    },
                                };
                                if let Ok(json) = serde_json::to_string(&notification) {
                                    let _ = write.send(Message::Text(json)).await;
                                }
                            }
                        }
                    }
                }

                // Broadcast pending transactions
                tx_hash = pending_tx_rx.recv() => {
                    if let Ok(tx_hash) = tx_hash {
                        let state = conn_state.read().await;
                        for (sub_id, sub) in &state.subscriptions {
                            if sub.sub_type == EthSubscriptionType::NewPendingTransactions {
                                let notification = SubscriptionNotification {
                                    jsonrpc: "2.0".to_string(),
                                    method: "eth_subscription".to_string(),
                                    params: SubscriptionParams {
                                        subscription: sub_id.clone(),
                                        result: serde_json::Value::String(
                                            format!("0x{}", hex::encode(tx_hash.as_bytes()))
                                        ),
                                    },
                                };
                                if let Ok(json) = serde_json::to_string(&notification) {
                                    let _ = write.send(Message::Text(json)).await;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Cleanup
        {
            let mut connections = self.connections.write().await;
            connections.remove(&conn_id);
        }

        Ok(())
    }

    async fn handle_message(
        &self,
        conn_state: &Arc<RwLock<ConnectionState>>,
        text: &str,
    ) -> Option<String> {
        let request: SubscriptionRequest = match serde_json::from_str(text) {
            Ok(r) => r,
            Err(e) => {
                return Some(serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    }
                })).unwrap_or_default());
            }
        };

        match request.method.as_str() {
            "eth_subscribe" => {
                self.handle_subscribe(conn_state, request).await
            }
            "eth_unsubscribe" => {
                self.handle_unsubscribe(conn_state, request).await
            }
            _ => {
                Some(serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", request.method)
                    }
                })).unwrap_or_default())
            }
        }
    }

    async fn handle_subscribe(
        &self,
        conn_state: &Arc<RwLock<ConnectionState>>,
        request: SubscriptionRequest,
    ) -> Option<String> {
        if request.params.is_empty() {
            return Some(serde_json::to_string(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": request.id,
                "error": {
                    "code": -32602,
                    "message": "Missing subscription type"
                }
            })).unwrap_or_default());
        }

        let sub_type_str = request.params[0].as_str().unwrap_or("");
        let sub_type = match sub_type_str {
            "newHeads" => EthSubscriptionType::NewHeads,
            "logs" => EthSubscriptionType::Logs,
            "newPendingTransactions" => EthSubscriptionType::NewPendingTransactions,
            "syncing" => EthSubscriptionType::Syncing,
            _ => {
                return Some(serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "error": {
                        "code": -32602,
                        "message": format!("Unknown subscription type: {}", sub_type_str)
                    }
                })).unwrap_or_default());
            }
        };

        // PBA-L1a-010 (variant): the logs-subscription filter is retained for
        // the connection's lifetime, so bound it exactly like eth_newFilter.
        if sub_type == EthSubscriptionType::Logs && request.params.len() > 1 {
            if let Err(msg) = crate::filter::validate_log_filter_criteria(&request.params[1]) {
                return Some(serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "error": { "code": -32602, "message": msg }
                })).unwrap_or_default());
            }
        }

        // Parse filter for logs subscription
        let filter = if sub_type == EthSubscriptionType::Logs && request.params.len() > 1 {
            serde_json::from_value(request.params[1].clone()).ok()
        } else {
            None
        };

        let mut state = conn_state.write().await;
        // CHAIN-B-D013: cap subscriptions per connection so a single socket
        // cannot register unbounded subscriptions.
        if state.subscriptions.len() >= MAX_SUBSCRIPTIONS_PER_CONN {
            return Some(
                serde_json::to_string(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request.id,
                    "error": {
                        "code": -32005,
                        "message": format!(
                            "Too many subscriptions (max {})",
                            MAX_SUBSCRIPTIONS_PER_CONN
                        )
                    }
                }))
                .unwrap_or_default(),
            );
        }
        let sub_id = state.next_subscription_id();

        state.subscriptions.insert(
            sub_id.clone(),
            Subscription {
                id: sub_id.clone(),
                sub_type,
                filter,
            },
        );

        debug!("Created subscription {} for {:?}", sub_id, sub_type_str);

        Some(serde_json::to_string(&SubscriptionResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id,
            result: serde_json::Value::String(sub_id),
        }).unwrap_or_default())
    }

    async fn handle_unsubscribe(
        &self,
        conn_state: &Arc<RwLock<ConnectionState>>,
        request: SubscriptionRequest,
    ) -> Option<String> {
        if request.params.is_empty() {
            return Some(serde_json::to_string(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": request.id,
                "error": {
                    "code": -32602,
                    "message": "Missing subscription ID"
                }
            })).unwrap_or_default());
        }

        let sub_id = request.params[0].as_str().unwrap_or("");
        let mut state = conn_state.write().await;
        let removed = state.subscriptions.remove(sub_id).is_some();

        debug!("Removed subscription {}: {}", sub_id, removed);

        Some(serde_json::to_string(&SubscriptionResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id,
            result: serde_json::Value::Bool(removed),
        }).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_type_parsing() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}"#;
        let request: SubscriptionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.method, "eth_subscribe");
        assert_eq!(request.params[0].as_str().unwrap(), "newHeads");
    }

    #[test]
    fn test_logs_filter_parsing() {
        let json = r#"{"address":"0x1234","topics":[null,"0xabcd"]}"#;
        let filter: LogFilter = serde_json::from_str(json).unwrap();
        assert!(filter.address.is_some());
        assert!(filter.topics.is_some());
    }

    #[test]
    fn test_subscription_response_format() {
        let response = SubscriptionResponse {
            jsonrpc: "2.0".to_string(),
            id: serde_json::Value::Number(1.into()),
            result: serde_json::Value::String("0x1".to_string()),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"result\":\"0x1\""));
    }

    #[test]
    fn test_subscription_notification_format() {
        let notification = SubscriptionNotification {
            jsonrpc: "2.0".to_string(),
            method: "eth_subscription".to_string(),
            params: SubscriptionParams {
                subscription: "0x1".to_string(),
                result: serde_json::json!({"number": "0x10"}),
            },
        };
        let json = serde_json::to_string(&notification).unwrap();
        assert!(json.contains("eth_subscription"));
        assert!(json.contains("0x1"));
    }
}
