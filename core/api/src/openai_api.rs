// citrate/core/api/src/openai_api.rs

use axum::{
    extract::{Path, Query, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Json, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use crate::methods::ai::{
    AiApi, ChatCompletionRequest, ChatCompletionResponse, CreateLoRARequest,
    CreateTrainingJobRequest, DeployModelRequest, EmbeddingsRequest, EmbeddingsResponse,
    InferenceRequest,
};
use citrate_execution::executor::Executor;
use citrate_execution::types::Address;
use citrate_sequencer::mempool::Mempool;
use citrate_storage::StorageManager;

/// OpenAI/Anthropic compatible REST API server
pub struct OpenAiRestServer {
    storage: Arc<StorageManager>,
    mempool: Arc<Mempool>,
    executor: Arc<Executor>,
    /// CORS origins (WP-X.1). Empty = no CORS. ["*"] = wildcard.
    cors_origins: Vec<String>,
    /// REST API key for mutating endpoints (WP-X.1).
    rest_api_key: Option<String>,
}

/// Server state for Axum handlers
#[derive(Clone)]
pub struct AppState {
    ai_api: AiApi,
    /// REST API key for Bearer auth on mutating endpoints (WP-X.1)
    rest_api_key: Option<String>,
}

/// Error response format
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub message: String,
    pub r#type: String,
    pub code: Option<String>,
}

/// Model list response (OpenAI compatible)
#[derive(Debug, Serialize)]
pub struct ModelListResponse {
    pub object: String,
    pub data: Vec<ModelInfo>,
}

/// Model info for list response
#[derive(Debug, Serialize)]
pub struct ModelInfo {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub owned_by: String,
}

impl OpenAiRestServer {
    /// Create a new OpenAI REST API server
    pub fn new(
        storage: Arc<StorageManager>,
        mempool: Arc<Mempool>,
        executor: Arc<Executor>,
    ) -> Self {
        Self {
            storage,
            mempool,
            executor,
            cors_origins: vec![],
            rest_api_key: None,
        }
    }

    /// Create with CORS and auth configuration (WP-X.1)
    pub fn with_config(
        storage: Arc<StorageManager>,
        mempool: Arc<Mempool>,
        executor: Arc<Executor>,
        cors_origins: Vec<String>,
        rest_api_key: Option<String>,
    ) -> Self {
        Self {
            storage,
            mempool,
            executor,
            cors_origins,
            rest_api_key,
        }
    }

    /// Create the Axum router with all API endpoints
    pub fn router(&self) -> Router {
        let ai_api = AiApi::new(
            self.storage.clone(),
            self.mempool.clone(),
            self.executor.clone(),
        );
        let state = AppState {
            ai_api,
            rest_api_key: self.rest_api_key.clone(),
        };

        // WP-X.1: Config-driven CORS — wildcard emits warning for unsafe deployments
        let cors = if self.cors_origins.iter().any(|o| o == "*") {
            tracing::warn!("REST API CORS wildcard '*' configured — unsafe for public deployments");
            CorsLayer::new()
                .allow_origin(AllowOrigin::any())
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        } else if self.cors_origins.is_empty() {
            // No CORS headers — browser cross-origin blocked by default
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        } else {
            let origins: Vec<HeaderValue> = self
                .cors_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        };

        // Mutating endpoints (require Bearer auth when rest_api_key is set)
        let mutating_routes = Router::new()
            .route("/v1/citrate/models", post(citrate_deploy_model))
            .route("/v1/citrate/inference", post(citrate_request_inference))
            .route("/v1/citrate/training", post(citrate_create_training_job))
            .route("/v1/citrate/lora", post(citrate_create_lora))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                require_rest_api_key,
            ));

        // Read-only and public endpoints (no auth required)
        let public_routes = Router::new()
            .route("/v1/models", get(list_models))
            .route("/v1/chat/completions", post(chat_completions))
            .route("/v1/completions", post(completions))
            .route("/v1/embeddings", post(embeddings))
            .route("/v1/messages", post(messages))
            .route("/v1/citrate/models", get(citrate_list_models))
            .route("/v1/citrate/models/:model_id", get(citrate_get_model))
            .route(
                "/v1/citrate/models/:model_id/stats",
                get(citrate_model_stats),
            )
            .route(
                "/v1/citrate/inference/:request_id",
                get(citrate_get_inference),
            )
            .route(
                "/v1/citrate/training/:job_id",
                get(citrate_get_training_job),
            )
            .route("/v1/citrate/lora/:adapter_id", get(citrate_get_lora))
            .route("/health", get(health_check))
            .route("/", get(root));

        public_routes
            .merge(mutating_routes)
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(cors),
            )
            .with_state(state)
    }

    /// Start the REST API server
    pub async fn start(&self, addr: std::net::SocketAddr) -> anyhow::Result<()> {
        let app = self.router();

        info!("Starting OpenAI-compatible REST API server on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

// ========== Auth Middleware (WP-X.1) ==========

/// Bearer auth middleware for mutating REST endpoints.
///
/// S-02 FIX: When `rest_api_key` is configured, requires `Authorization: Bearer <key>`.
/// When no key is configured, mutating endpoints (POST) are REJECTED (fail-closed)
/// to prevent unauthenticated model deployment/training. Read-only endpoints (GET)
/// are still allowed without a key.
async fn require_rest_api_key(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(ref expected_key) = state.rest_api_key {
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match auth_header {
            // CHAIN-B-D008 (SECREM-02 5.6): constant-time compare. A
            // short-circuiting `==` lets a remote caller measure how many
            // leading bytes matched and brute-force CITRATE_REST_API_KEY
            // byte-by-byte — the same class the operator-token and RPC api_key
            // compares already close. This is the third credential.
            Some(token)
                if crate::server::constant_time_eq(token.as_bytes(), expected_key.as_bytes()) =>
            {
                Ok(next.run(req).await)
            }
            Some(_) => {
                warn!("REST API auth failed: invalid Bearer token");
                Err(StatusCode::UNAUTHORIZED)
            }
            None => {
                warn!("REST API auth failed: missing Authorization header");
                Err(StatusCode::UNAUTHORIZED)
            }
        }
    } else {
        // S-02 FIX: No key configured — reject mutating operations (fail-closed).
        // GET requests are allowed for read-only access; POST/PUT/DELETE are blocked.
        if req.method() == Method::GET || req.method() == Method::OPTIONS || req.method() == Method::HEAD {
            Ok(next.run(req).await)
        } else {
            warn!(
                method = %req.method(),
                uri = %req.uri(),
                "REST API key not configured — mutating operation rejected"
            );
            let body = serde_json::json!({
                "error": {
                    "message": "REST API key not configured — mutating operations disabled. Set CITRATE_REST_API_KEY to enable.",
                    "type": "authentication_error",
                    "code": "api_key_not_configured"
                }
            });
            let response = axum::response::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_string(&body).unwrap_or_default()))
                .unwrap_or_else(|_| {
                    let mut response = axum::response::Response::new(axum::body::Body::empty());
                    *response.status_mut() = StatusCode::FORBIDDEN;
                    response
                });
            Ok(response)
        }
    }
}

/// Derive a deterministic operator address from the REST API key.
/// When no API key is set (devnet), returns a well-known devnet address.
fn derive_operator_address(rest_api_key: &Option<String>) -> Address {
    match rest_api_key {
        Some(key) => {
            // Keccak256(api_key)[12..32] = deterministic 20-byte address
            use sha3::{Digest, Keccak256};
            let hash = Keccak256::digest(key.as_bytes());
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&hash[12..32]);
            Address(addr)
        }
        None => {
            // Devnet operator: 0x1111...1111
            Address([0x11; 20])
        }
    }
}

// ========== OpenAI-Compatible Handlers ==========

/// GET /v1/models - List available models
async fn list_models(State(state): State<AppState>) -> Result<Json<ModelListResponse>, StatusCode> {
    match state.ai_api.list_models(None, None).await {
        Ok(model_ids) => {
            let models: Vec<ModelInfo> = model_ids
                .iter()
                .map(|id| ModelInfo {
                    id: hex::encode(id.0.as_bytes()),
                    object: "model".to_string(),
                    created: chrono::Utc::now().timestamp() as u64,
                    owned_by: "citrate".to_string(),
                })
                .collect();

            Ok(Json(ModelListResponse {
                object: "list".to_string(),
                data: models,
            }))
        }
        Err(e) => {
            error!("Failed to list models: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /v1/chat/completions - OpenAI chat completions
async fn chat_completions(
    State(state): State<AppState>,
    Json(request): Json<ChatCompletionRequest>,
) -> Result<Json<ChatCompletionResponse>, StatusCode> {
    match state.ai_api.chat_completions(request, None).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Chat completion failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /v1/completions - OpenAI text completions (legacy)
async fn completions(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Convert text completion to chat completion
    if let Some(prompt) = payload.get("prompt").and_then(|p| p.as_str()) {
        let chat_request = ChatCompletionRequest {
            model: payload
                .get("model")
                .and_then(|m| m.as_str())
                .unwrap_or("gpt-3.5-turbo")
                .to_string(),
            messages: vec![crate::methods::ai::ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens: payload
                .get("max_tokens")
                .and_then(|t| t.as_u64())
                .map(|t| t as u32),
            temperature: payload
                .get("temperature")
                .and_then(|t| t.as_f64())
                .map(|t| t as f32),
            top_p: payload
                .get("top_p")
                .and_then(|t| t.as_f64())
                .map(|t| t as f32),
            n: payload.get("n").and_then(|n| n.as_u64()).map(|n| n as u32),
            stop: payload.get("stop").and_then(|s| {
                if s.is_array() {
                    s.as_array().map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                } else {
                    s.as_str().map(|s| vec![s.to_string()])
                }
            }),
            stream: payload.get("stream").and_then(|s| s.as_bool()),
        };

        match state.ai_api.chat_completions(chat_request, None).await {
            Ok(chat_response) => {
                // Convert back to completions format
                let completions_response = serde_json::json!({
                    "id": chat_response.id,
                    "object": "text_completion",
                    "created": chat_response.created,
                    "model": chat_response.model,
                    "choices": chat_response.choices.into_iter().map(|choice| {
                        serde_json::json!({
                            "text": choice.message.content,
                            "index": choice.index,
                            "finish_reason": choice.finish_reason
                        })
                    }).collect::<Vec<_>>(),
                    "usage": chat_response.usage
                });
                Ok(Json(completions_response))
            }
            Err(e) => {
                error!("Completion failed: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

/// POST /v1/embeddings - OpenAI embeddings
async fn embeddings(
    State(state): State<AppState>,
    Json(request): Json<EmbeddingsRequest>,
) -> Result<Json<EmbeddingsResponse>, StatusCode> {
    match state.ai_api.embeddings(request, None).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Embeddings failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ========== Anthropic-Compatible Handlers ==========

/// POST /v1/messages - Anthropic messages API
async fn messages(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Convert Anthropic messages format to OpenAI chat format
    if let Some(messages) = payload.get("messages").and_then(|m| m.as_array()) {
        let chat_messages: Vec<crate::methods::ai::ChatMessage> = messages
            .iter()
            .filter_map(|msg| {
                let role = msg.get("role")?.as_str()?;
                let content = msg.get("content")?.as_str()?;
                Some(crate::methods::ai::ChatMessage {
                    role: role.to_string(),
                    content: content.to_string(),
                })
            })
            .collect();

        let chat_request = ChatCompletionRequest {
            model: payload
                .get("model")
                .and_then(|m| m.as_str())
                .unwrap_or("claude-3-sonnet")
                .to_string(),
            messages: chat_messages,
            max_tokens: payload
                .get("max_tokens")
                .and_then(|t| t.as_u64())
                .map(|t| t as u32),
            temperature: payload
                .get("temperature")
                .and_then(|t| t.as_f64())
                .map(|t| t as f32),
            top_p: payload
                .get("top_p")
                .and_then(|t| t.as_f64())
                .map(|t| t as f32),
            n: Some(1),
            stop: None,
            stream: payload.get("stream").and_then(|s| s.as_bool()),
        };

        match state.ai_api.chat_completions(chat_request, None).await {
            Ok(chat_response) => {
                // Convert to Anthropic format
                let anthropic_response = serde_json::json!({
                    "id": chat_response.id,
                    "type": "message",
                    "role": "assistant",
                    "content": chat_response.choices.first()
                        .map(|c| c.message.content.clone())
                        .unwrap_or_default(),
                    "model": chat_response.model,
                    "usage": {
                        "input_tokens": chat_response.usage.prompt_tokens,
                        "output_tokens": chat_response.usage.completion_tokens
                    }
                });
                Ok(Json(anthropic_response))
            }
            Err(e) => {
                error!("Anthropic message failed: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

// ========== Citrate-Specific Handlers ==========

/// GET /v1/citrate/models - List Citrate models with detailed info
async fn citrate_list_models(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let owner = params.get("owner").and_then(|addr_str| {
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

    let limit = params.get("limit").and_then(|l| l.parse().ok());

    match state.ai_api.list_models(owner, limit).await {
        Ok(model_ids) => {
            let models_detailed: Result<Vec<_>, _> =
                futures::future::join_all(model_ids.iter().map(|id| state.ai_api.get_model(*id)))
                    .await
                    .into_iter()
                    .collect();

            match models_detailed {
                Ok(models) => Ok(Json(serde_json::json!({
                    "models": models,
                    "count": models.len()
                }))),
                Err(e) => {
                    error!("Failed to get model details: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Err(e) => {
            error!("Failed to list models: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// POST /v1/citrate/models - Deploy a new model
async fn citrate_deploy_model(
    State(state): State<AppState>,
    Json(request): Json<DeployModelRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // WP-X.1: Derive operator address from API key (no more Address::zero())
    let from = derive_operator_address(&state.rest_api_key);
    let gas_limit = 1_000_000;
    let gas_price = 10000;

    match state
        .ai_api
        .deploy_model(request, from, gas_limit, gas_price)
        .await
    {
        Ok(tx_hash) => Ok(Json(serde_json::json!({
            "transaction_hash": hex::encode(tx_hash.as_bytes()),
            "status": "pending"
        }))),
        Err(e) => {
            error!("Model deployment failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /v1/citrate/models/:model_id - Get model details
async fn citrate_get_model(
    State(state): State<AppState>,
    Path(model_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match hex::decode(&model_id) {
        Ok(model_id_bytes) if model_id_bytes.len() == 32 => {
            let mut model_id_array = [0u8; 32];
            model_id_array.copy_from_slice(&model_id_bytes);
            let model_id = citrate_execution::types::ModelId(citrate_consensus::types::Hash::new(
                model_id_array,
            ));

            match state.ai_api.get_model(model_id).await {
                Ok(model) => Ok(Json(serde_json::to_value(model).unwrap_or_else(|e| serde_json::json!({"error": e.to_string()})))),
                Err(e) => {
                    error!("Failed to get model: {}", e);
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

/// GET /v1/citrate/models/:model_id/stats - Get model statistics
async fn citrate_model_stats(
    State(state): State<AppState>,
    Path(model_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match hex::decode(&model_id) {
        Ok(model_id_bytes) if model_id_bytes.len() == 32 => {
            let mut model_id_array = [0u8; 32];
            model_id_array.copy_from_slice(&model_id_bytes);
            let model_id = citrate_execution::types::ModelId(citrate_consensus::types::Hash::new(
                model_id_array,
            ));

            match state.ai_api.get_model_stats(model_id).await {
                Ok(stats) => Ok(Json(serde_json::to_value(stats).unwrap_or_else(|e| serde_json::json!({"error": e.to_string()})))),
                Err(e) => {
                    error!("Failed to get model stats: {}", e);
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

/// POST /v1/citrate/inference - Request inference
async fn citrate_request_inference(
    State(state): State<AppState>,
    Json(request): Json<InferenceRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // WP-X.1: Derive operator address from API key
    let from = derive_operator_address(&state.rest_api_key);
    let gas_price = 10000;

    match state
        .ai_api
        .request_inference(request, from, gas_price)
        .await
    {
        Ok(request_hash) => Ok(Json(serde_json::json!({
            "request_id": hex::encode(request_hash.as_bytes()),
            "status": "submitted"
        }))),
        Err(e) => {
            error!("Inference request failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /v1/citrate/inference/:request_id - Get inference result
async fn citrate_get_inference(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match hex::decode(&request_id) {
        Ok(hash_bytes) if hash_bytes.len() == 32 => {
            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(&hash_bytes);
            let request_hash = citrate_consensus::types::Hash::new(hash_array);

            match state.ai_api.get_inference_result(request_hash).await {
                Ok(result) => Ok(Json(serde_json::to_value(result).unwrap_or_else(|e| serde_json::json!({"error": e.to_string()})))),
                Err(e) => {
                    error!("Failed to get inference result: {}", e);
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

/// POST /v1/citrate/training - Create training job
async fn citrate_create_training_job(
    State(state): State<AppState>,
    Json(request): Json<CreateTrainingJobRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // WP-X.1: Derive operator address from API key
    let from = derive_operator_address(&state.rest_api_key);
    let gas_limit = 1_000_000;
    let gas_price = 10000;

    match state
        .ai_api
        .create_training_job(request, from, gas_limit, gas_price)
        .await
    {
        Ok(job_hash) => Ok(Json(serde_json::json!({
            "job_id": hex::encode(job_hash.as_bytes()),
            "status": "created"
        }))),
        Err(e) => {
            error!("Training job creation failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /v1/citrate/training/:job_id - Get training job
async fn citrate_get_training_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match hex::decode(&job_id) {
        Ok(job_id_bytes) if job_id_bytes.len() == 32 => {
            let mut job_id_array = [0u8; 32];
            job_id_array.copy_from_slice(&job_id_bytes);
            let job_id =
                citrate_execution::types::JobId(citrate_consensus::types::Hash::new(job_id_array));

            match state.ai_api.get_training_job(job_id).await {
                Ok(job) => Ok(Json(serde_json::to_value(job).unwrap_or_else(|e| serde_json::json!({"error": e.to_string()})))),
                Err(e) => {
                    error!("Failed to get training job: {}", e);
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

/// POST /v1/citrate/lora - Create LoRA adapter
async fn citrate_create_lora(
    State(state): State<AppState>,
    Json(request): Json<CreateLoRARequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // WP-X.1: Derive operator address from API key
    let from = derive_operator_address(&state.rest_api_key);

    match state.ai_api.create_lora(request, from).await {
        Ok(adapter_hash) => Ok(Json(serde_json::json!({
            "adapter_id": hex::encode(adapter_hash.as_bytes()),
            "status": "created"
        }))),
        Err(e) => {
            error!("LoRA creation failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /v1/citrate/lora/:adapter_id - Get LoRA adapter
async fn citrate_get_lora(
    State(state): State<AppState>,
    Path(adapter_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match hex::decode(&adapter_id) {
        Ok(adapter_id_bytes) if adapter_id_bytes.len() == 32 => {
            let mut adapter_id_array = [0u8; 32];
            adapter_id_array.copy_from_slice(&adapter_id_bytes);
            let adapter_hash = citrate_consensus::types::Hash::new(adapter_id_array);

            match state.ai_api.get_lora(adapter_hash).await {
                Ok(adapter) => Ok(Json(serde_json::to_value(adapter).unwrap_or_else(|e| serde_json::json!({"error": e.to_string()})))),
                Err(e) => {
                    error!("Failed to get LoRA adapter: {}", e);
                    Err(StatusCode::NOT_FOUND)
                }
            }
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

// ========== Utility Handlers ==========

/// GET /health - Health check
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().timestamp(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// GET / - Root endpoint
async fn root() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "Citrate AI API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "OpenAI/Anthropic compatible API for Citrate blockchain AI models",
        "endpoints": {
            "openai": {
                "models": "/v1/models",
                "chat": "/v1/chat/completions",
                "completions": "/v1/completions",
                "embeddings": "/v1/embeddings"
            },
            "anthropic": {
                "messages": "/v1/messages"
            },
            "citrate": {
                "models": "/v1/citrate/models",
                "inference": "/v1/citrate/inference",
                "training": "/v1/citrate/training",
                "lora": "/v1/citrate/lora"
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    #[test]
    fn test_error_response_format() {
        let error = ErrorResponse {
            error: ErrorDetail {
                message: "Test error".to_string(),
                r#type: "invalid_request_error".to_string(),
                code: Some("invalid_model".to_string()),
            },
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("Test error"));
        assert!(json.contains("invalid_request_error"));
    }

    // WP-X.1: CORS and auth tests

    fn make_test_server(
        cors_origins: Vec<String>,
        rest_api_key: Option<String>,
    ) -> Router {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Arc::new(
            StorageManager::new(
                temp_dir.path(),
                citrate_storage::pruning::PruningConfig::default(),
            )
            .unwrap(),
        );
        // Leak temp_dir so it persists for the test duration
        std::mem::forget(temp_dir);
        let mempool = Arc::new(Mempool::new(
            citrate_sequencer::mempool::MempoolConfig::default(),
        ));
        let state_db = Arc::new(citrate_execution::StateDB::new());
        let executor = Arc::new(citrate_execution::executor::Executor::new(state_db));
        let server =
            OpenAiRestServer::with_config(storage, mempool, executor, cors_origins, rest_api_key);
        server.router()
    }

    #[tokio::test]
    async fn test_cors_empty_blocks_cross_origin() {
        let app = make_test_server(vec![], None);
        let req = HttpRequest::builder()
            .uri("/health")
            .header("Origin", "https://evil.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // No Access-Control-Allow-Origin header when cors_origins is empty
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn test_cors_wildcard_works() {
        let app = make_test_server(vec!["*".to_string()], None);
        let req = HttpRequest::builder()
            .uri("/health")
            .header("Origin", "https://any-site.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let cors_header = resp
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap().to_string());
        assert_eq!(cors_header.as_deref(), Some("*"));
    }

    #[tokio::test]
    async fn test_cors_explicit_origin_allowed() {
        let app = make_test_server(vec!["https://app.citrate.ai".to_string()], None);
        let req = HttpRequest::builder()
            .uri("/health")
            .header("Origin", "https://app.citrate.ai")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let cors_header = resp
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap().to_string());
        assert_eq!(
            cors_header.as_deref(),
            Some("https://app.citrate.ai")
        );
    }

    #[tokio::test]
    async fn test_rest_bearer_auth_required() {
        let app = make_test_server(vec!["*".to_string()], Some("secret-key-123".to_string()));
        // POST to mutating endpoint without auth
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/citrate/lora")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rest_bearer_auth_wrong_key() {
        let app = make_test_server(vec!["*".to_string()], Some("secret-key-123".to_string()));
        let req = HttpRequest::builder()
            .method("POST")
            .uri("/v1/citrate/lora")
            .header("content-type", "application/json")
            .header("authorization", "Bearer wrong-key")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_read_endpoints_no_auth() {
        let app = make_test_server(vec!["*".to_string()], Some("secret-key-123".to_string()));
        // GET to read-only endpoint — should work without auth
        let req = HttpRequest::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_default_bind_is_loopback() {
        let config = crate::server::RpcConfig::default();
        assert!(
            config.listen_addr.ip().is_loopback(),
            "RPC default should bind to loopback, got {}",
            config.listen_addr
        );
    }

    #[test]
    fn test_derive_operator_address_not_zero() {
        let addr = derive_operator_address(&Some("test-key".to_string()));
        assert_ne!(addr, Address::zero(), "Derived address must not be zero");
        // Deterministic
        let addr2 = derive_operator_address(&Some("test-key".to_string()));
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_derive_operator_address_devnet_fallback() {
        let addr = derive_operator_address(&None);
        assert_eq!(addr, Address([0x11; 20]));
        assert_ne!(addr, Address::zero());
    }
}
