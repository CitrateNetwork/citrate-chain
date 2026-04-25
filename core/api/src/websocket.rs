// citrate/core/api/src/websocket.rs

use crate::methods::ai::InferenceResult;
use futures::{SinkExt, StreamExt};
use citrate_execution::types::{Address, JobId, ModelId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{Request, Response, ErrorResponse},
        http::StatusCode,
        protocol::WebSocketConfig,
        Message,
    },
};
use tracing::{debug, error, info, warn};

/// RM-B1 / WP-C1.4 (audit M-API-02): WebSocket configuration with
/// the structural caps that close the audit finding.
///
/// Defaults are conservative — production operators should tune
/// based on observed traffic. The pre-fix server had NO caps and
/// used tungstenite's 64MB default frame size.
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// Maximum concurrent connections. New connections beyond this
    /// cap are rejected at accept time.
    pub max_connections: usize,
    /// Maximum subscriptions per connection. Subscribe requests
    /// beyond this cap return a WsMessage::Error.
    pub max_subscriptions_per_conn: usize,
    /// Maximum frame size in bytes. Tungstenite's default is 64MB
    /// — we set 1MB to bound per-connection memory.
    pub max_frame_size: usize,
    /// Idle timeout: connections without any message for this long
    /// are dropped. Pre-fix idle connections lived forever.
    pub idle_timeout_secs: u64,
    /// CORS allowlist for the Origin header. RM-B1 / WP-C1.5
    /// (audit L-API-01). Empty list = allow all (dev / testnet).
    /// Wildcard `"*"` entries are NOT supported — require exact match.
    pub allowed_origins: Vec<String>,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_subscriptions_per_conn: 64,
            max_frame_size: 1_048_576, // 1 MiB
            idle_timeout_secs: 60,
            allowed_origins: vec![],
        }
    }
}

/// WebSocket subscription types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SubscriptionType {
    /// Subscribe to inference results
    InferenceResults { model_id: Option<String> },
    /// Subscribe to training job updates
    TrainingJobs { model_id: Option<String> },
    /// Subscribe to new model deployments
    NewModels,
    /// Subscribe to chat completions (OpenAI-compatible streaming)
    ChatStream { request_id: String },
}

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "camelCase")]
pub enum WsMessage {
    /// Subscribe to events
    Subscribe {
        id: String,
        subscription: SubscriptionType,
    },
    /// Unsubscribe from events
    Unsubscribe { id: String, subscription_id: String },
    /// Subscription confirmation
    SubscriptionConfirm { id: String, subscription_id: String },
    /// Subscription data
    SubscriptionData {
        subscription_id: String,
        data: serde_json::Value,
    },
    /// Error response
    Error { id: String, error: String },
    /// Ping for keep-alive
    Ping,
    /// Pong response
    Pong,
}

/// WebSocket connection handler
pub struct WebSocketConnection {
    pub id: String,
    pub subscriptions: HashMap<String, SubscriptionType>,
    pub sink: tokio_tungstenite::WebSocketStream<TcpStream>,
}

/// WebSocket server for real-time AI updates
pub struct WebSocketServer {
    addr: SocketAddr,
    connections:
        Arc<tokio::sync::RwLock<HashMap<String, Arc<tokio::sync::Mutex<WebSocketConnection>>>>>,
    /// RM-B1 / WP-C1.4 (audit M-API-02): bounds on connections,
    /// subscriptions, frame size, and idle timeout.
    config: WsConfig,
    /// Atomic counter of active connections — used to enforce
    /// `config.max_connections` at accept time.
    active_count: Arc<AtomicUsize>,
}

impl WebSocketServer {
    /// Create a new WebSocket server with default config (1024
    /// connections, 64 subscriptions/conn, 1MB frames, 60s idle).
    pub fn new(addr: SocketAddr) -> Self {
        Self::new_with_config(addr, WsConfig::default())
    }

    /// Create a new WebSocket server with explicit config.
    /// RM-B1 / WP-C1.4 (audit M-API-02).
    pub fn new_with_config(addr: SocketAddr, config: WsConfig) -> Self {
        Self {
            addr,
            connections: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            config,
            active_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Start the WebSocket server
    pub async fn start(self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!(
            "WebSocket server listening on {} (max_connections={}, max_frame={}KB, allowed_origins={:?})",
            self.addr,
            self.config.max_connections,
            self.config.max_frame_size / 1024,
            self.config.allowed_origins
        );

        let connections = self.connections.clone();
        let config = Arc::new(self.config.clone());
        let active_count = self.active_count.clone();

        while let Ok((stream, peer_addr)) = listener.accept().await {
            // M-API-02: enforce max_connections at accept time.
            let prior = active_count.fetch_add(1, AtomicOrdering::SeqCst);
            if prior >= config.max_connections {
                active_count.fetch_sub(1, AtomicOrdering::SeqCst);
                warn!(
                    "M-API-02: rejecting WS from {} — max_connections ({}) reached",
                    peer_addr, config.max_connections
                );
                drop(stream);
                continue;
            }

            let connections = connections.clone();
            let config = config.clone();
            let active_count = active_count.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, peer_addr, connections, config).await {
                    error!("WebSocket connection error from {}: {}", peer_addr, e);
                }
                active_count.fetch_sub(1, AtomicOrdering::SeqCst);
            });
        }

        Ok(())
    }

    /// Broadcast inference result to subscribers
    pub async fn broadcast_inference_result(&self, result: &InferenceResult) {
        let connections = self.connections.read().await;

        for (_conn_id, connection) in connections.iter() {
            let connection = connection.clone();
            let result = result.clone();

            tokio::spawn(async move {
                let mut conn = connection.lock().await;

                // Check if connection is subscribed to inference results
                let subscriptions = conn.subscriptions.clone();
                for (sub_id, sub_type) in &subscriptions {
                    if let SubscriptionType::InferenceResults { model_id } = sub_type {
                        // Filter by model ID if specified
                        if let Some(filter_model_id) = model_id {
                            if &result.model_id != filter_model_id {
                                continue;
                            }
                        }

                        let message = WsMessage::SubscriptionData {
                            subscription_id: sub_id.clone(),
                            data: serde_json::to_value(&result).unwrap_or(serde_json::Value::Null),
                        };

                        if let Ok(msg_json) = serde_json::to_string(&message) {
                            let _ = conn.sink.send(Message::Text(msg_json)).await;
                        }
                    }
                }
            });
        }
    }

    /// Broadcast training job update to subscribers
    pub async fn broadcast_training_job_update(
        &self,
        job_id: JobId,
        status: String,
        model_id: ModelId,
    ) {
        let connections = self.connections.read().await;

        let update_data = serde_json::json!({
            "job_id": hex::encode(job_id.0.as_bytes()),
            "model_id": hex::encode(model_id.0.as_bytes()),
            "status": status,
            "timestamp": chrono::Utc::now().timestamp()
        });

        for (_conn_id, connection) in connections.iter() {
            let connection = connection.clone();
            let update_data = update_data.clone();

            tokio::spawn(async move {
                let mut conn = connection.lock().await;

                let subscriptions = conn.subscriptions.clone();
                for (sub_id, sub_type) in &subscriptions {
                    if let SubscriptionType::TrainingJobs {
                        model_id: filter_model_id,
                    } = sub_type
                    {
                        // Filter by model ID if specified
                        if let Some(filter_model_id) = filter_model_id {
                            let filter_model_hex = filter_model_id;
                            let current_model_hex = hex::encode(model_id.0.as_bytes());
                            if filter_model_hex != &current_model_hex {
                                continue;
                            }
                        }

                        let message = WsMessage::SubscriptionData {
                            subscription_id: sub_id.clone(),
                            data: update_data.clone(),
                        };

                        if let Ok(msg_json) = serde_json::to_string(&message) {
                            let _ = conn.sink.send(Message::Text(msg_json)).await;
                        }
                    }
                }
            });
        }
    }

    /// Broadcast new model deployment
    pub async fn broadcast_new_model(&self, model_id: ModelId, owner: Address, name: String) {
        let connections = self.connections.read().await;

        let model_data = serde_json::json!({
            "model_id": hex::encode(model_id.0.as_bytes()),
            "owner": hex::encode(owner.0),
            "name": name,
            "timestamp": chrono::Utc::now().timestamp()
        });

        for (_conn_id, connection) in connections.iter() {
            let connection = connection.clone();
            let model_data = model_data.clone();

            tokio::spawn(async move {
                let mut conn = connection.lock().await;

                let subscriptions = conn.subscriptions.clone();
                for (sub_id, sub_type) in &subscriptions {
                    if matches!(sub_type, SubscriptionType::NewModels) {
                        let message = WsMessage::SubscriptionData {
                            subscription_id: sub_id.clone(),
                            data: model_data.clone(),
                        };

                        if let Ok(msg_json) = serde_json::to_string(&message) {
                            let _ = conn.sink.send(Message::Text(msg_json)).await;
                        }
                    }
                }
            });
        }
    }

    /// Stream chat completion chunks (OpenAI-compatible)
    pub async fn stream_chat_completion(&self, request_id: String, chunk: serde_json::Value) {
        let connections = self.connections.read().await;

        for (_conn_id, connection) in connections.iter() {
            let connection = connection.clone();
            let chunk = chunk.clone();
            let request_id = request_id.clone();

            tokio::spawn(async move {
                let mut conn = connection.lock().await;

                let subscriptions = conn.subscriptions.clone();
                for (sub_id, sub_type) in &subscriptions {
                    if let SubscriptionType::ChatStream {
                        request_id: filter_request_id,
                    } = sub_type
                    {
                        if filter_request_id == &request_id {
                            let message = WsMessage::SubscriptionData {
                                subscription_id: sub_id.clone(),
                                data: chunk.clone(),
                            };

                            if let Ok(msg_json) = serde_json::to_string(&message) {
                                let _ = conn.sink.send(Message::Text(msg_json)).await;
                            }
                        }
                    }
                }
            });
        }
    }
}

/// Handle a new WebSocket connection.
///
/// RM-B1 / WP-C1.4 + WP-C1.5 (audit M-API-02 + L-API-01): enforces
/// max_frame_size during the WebSocket handshake and validates the
/// Origin header against the CORS allowlist before upgrading.
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    connections: Arc<
        tokio::sync::RwLock<HashMap<String, Arc<tokio::sync::Mutex<WebSocketConnection>>>>,
    >,
    config: Arc<WsConfig>,
) -> anyhow::Result<()> {
    debug!("New WebSocket connection from {}", peer_addr);

    // L-API-01: capture the Origin header during upgrade and verify
    // it against `config.allowed_origins`. Empty allowlist = allow
    // all (devnet / testnet).
    let allowed_origins = config.allowed_origins.clone();
    let origin_callback = move |req: &Request, response: Response|
        -> Result<Response, ErrorResponse>
    {
        if allowed_origins.is_empty() {
            return Ok(response);
        }
        let origin = req
            .headers()
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !allowed_origins.iter().any(|allowed| allowed == origin) {
            warn!(
                "L-API-01: rejecting WS upgrade — Origin '{}' not in allowed_origins",
                origin
            );
            let body = "Origin not allowed";
            let resp = ErrorResponse::new(Some(body.to_string()));
            let (mut parts, body) = resp.into_parts();
            parts.status = StatusCode::FORBIDDEN;
            return Err(ErrorResponse::from_parts(parts, body));
        }
        Ok(response)
    };

    // M-API-02: tungstenite WebSocketConfig caps the frame size.
    let mut tungstenite_cfg = WebSocketConfig::default();
    tungstenite_cfg.max_message_size = Some(config.max_frame_size);
    tungstenite_cfg.max_frame_size = Some(config.max_frame_size);

    let ws_stream = accept_hdr_async_with_config(stream, origin_callback, Some(tungstenite_cfg))
        .await
        .map_err(|e| anyhow::anyhow!("WS upgrade failed: {}", e))?;

    let connection_id = format!("{}-{}", peer_addr, chrono::Utc::now().timestamp_millis());

    let connection = Arc::new(tokio::sync::Mutex::new(WebSocketConnection {
        id: connection_id.clone(),
        subscriptions: HashMap::new(),
        sink: ws_stream,
    }));

    // Add to connections map
    {
        let mut connections_map = connections.write().await;
        connections_map.insert(connection_id.clone(), connection.clone());
    }

    // Handle messages from this connection.
    // M-API-02: enforce idle timeout via tokio::time::timeout per
    // message read; on timeout, drop the connection.
    let result = handle_connection_messages(
        connection.clone(),
        config.idle_timeout_secs,
        config.max_subscriptions_per_conn,
    )
    .await;

    // Remove from connections map when done
    {
        let mut connections_map = connections.write().await;
        connections_map.remove(&connection_id);
    }

    debug!("WebSocket connection {} closed", connection_id);

    result
}

/// Handle messages from a WebSocket connection.
///
/// RM-B1 / WP-C1.4 (audit M-API-02): each `next()` is wrapped in a
/// `tokio::time::timeout(idle_timeout)`. A connection that goes
/// silent for longer than the timeout is dropped. Subscribe
/// requests beyond `max_subscriptions_per_conn` are rejected.
async fn handle_connection_messages(
    connection: Arc<tokio::sync::Mutex<WebSocketConnection>>,
    idle_timeout_secs: u64,
    max_subs_per_conn: usize,
) -> anyhow::Result<()> {
    let idle = std::time::Duration::from_secs(idle_timeout_secs);
    loop {
        let message = {
            let mut conn = connection.lock().await;
            match tokio::time::timeout(idle, conn.sink.next()).await {
                Ok(m) => m,
                Err(_) => {
                    info!(
                        "M-API-02: dropping idle WS connection {} after {}s without traffic",
                        conn.id, idle_timeout_secs
                    );
                    let _ = conn.sink.send(Message::Close(None)).await;
                    return Ok(());
                }
            }
        };

        match message {
            Some(Ok(Message::Text(text))) => {
                if let Err(e) = handle_text_message(connection.clone(), text, max_subs_per_conn).await {
                    warn!("Error handling WebSocket message: {}", e);
                }
            }
            Some(Ok(Message::Binary(_))) => {
                warn!("Binary messages not supported");
            }
            Some(Ok(Message::Close(_))) => {
                info!("WebSocket connection closed by client");
                break;
            }
            Some(Ok(Message::Ping(data))) => {
                let mut conn = connection.lock().await;
                let _ = conn.sink.send(Message::Pong(data)).await;
            }
            Some(Ok(Message::Pong(_))) => {
                // Handle pong
            }
            Some(Ok(Message::Frame(_))) => {
                // Frame messages are low-level and typically handled by the WebSocket library
                // We can safely ignore them here
            }
            Some(Err(e)) => {
                error!("WebSocket error: {}", e);
                break;
            }
            None => {
                info!("WebSocket connection ended");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a text message from a WebSocket client
async fn handle_text_message(
    connection: Arc<tokio::sync::Mutex<WebSocketConnection>>,
    text: String,
    max_subs_per_conn: usize,
) -> anyhow::Result<()> {
    let message: WsMessage = serde_json::from_str(&text)?;

    match message {
        WsMessage::Subscribe { id, subscription } => {
            let subscription_id = uuid::Uuid::new_v4().to_string();

            // RM-B1 / WP-C1.4 (audit M-API-02): cap per-connection
            // subscription count.
            {
                let conn = connection.lock().await;
                if conn.subscriptions.len() >= max_subs_per_conn {
                    drop(conn);
                    let err = WsMessage::Error {
                        id: id.clone(),
                        error: format!(
                            "M-API-02: subscription cap ({}) reached on this connection",
                            max_subs_per_conn
                        ),
                    };
                    let err_json = serde_json::to_string(&err)?;
                    let mut conn = connection.lock().await;
                    conn.sink.send(Message::Text(err_json)).await?;
                    return Ok(());
                }
            }

            {
                let mut conn = connection.lock().await;
                conn.subscriptions
                    .insert(subscription_id.clone(), subscription.clone());
            }

            let response = WsMessage::SubscriptionConfirm {
                id,
                subscription_id: subscription_id.clone(),
            };

            let response_json = serde_json::to_string(&response)?;

            {
                let mut conn = connection.lock().await;
                conn.sink.send(Message::Text(response_json)).await?;
            }

            debug!("WebSocket subscription created: {}", subscription_id);
        }

        WsMessage::Unsubscribe {
            id: _,
            subscription_id,
        } => {
            {
                let mut conn = connection.lock().await;
                conn.subscriptions.remove(&subscription_id);
            }

            debug!("WebSocket subscription removed: {}", subscription_id);
        }

        WsMessage::Ping => {
            let response = WsMessage::Pong;
            let response_json = serde_json::to_string(&response)?;

            {
                let mut conn = connection.lock().await;
                conn.sink.send(Message::Text(response_json)).await?;
            }
        }

        _ => {
            warn!("Unsupported WebSocket message type");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_websocket_server_creation() {
        let addr = "127.0.0.1:8546".parse().unwrap();
        let server = WebSocketServer::new(addr);
        assert_eq!(server.addr, addr);
    }

    #[test]
    fn test_message_serialization() {
        let msg = WsMessage::Subscribe {
            id: "test-1".to_string(),
            subscription: SubscriptionType::InferenceResults { model_id: None },
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: WsMessage = serde_json::from_str(&json).unwrap();

        match parsed {
            WsMessage::Subscribe { id, subscription } => {
                assert_eq!(id, "test-1");
                assert!(matches!(
                    subscription,
                    SubscriptionType::InferenceResults { model_id: None }
                ));
            }
            _ => panic!("Wrong message type"),
        }
    }
}
