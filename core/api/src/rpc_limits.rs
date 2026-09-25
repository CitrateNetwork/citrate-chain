// citrate/core/api/src/rpc_limits.rs
//
// PBA-L1a-009 / PBA-L1a-016 / PBA-L1a-002: JSON-RPC request-shape limits that the
// HTTP-level `RateLimiter` cannot see.
//
// The HTTP middleware (`rate_limit::RateLimiter`) runs before the body is read, so
// it counts one POST as one request no matter how many calls the body carries.
// A single 10 MiB batch of ~100k calls was therefore charged as ONE request and
// executed in full. This `jsonrpc_core::Middleware` runs after the body is
// parsed, where the batch is visible:
//
//   * a batch larger than [`MAX_BATCH_SIZE`] is refused outright (-32600);
//   * every element beyond the first is charged to the SAME per-client request
//     bucket the HTTP limiter uses (so a batch of N costs N requests);
//   * heavy compute methods (model inference, embeddings, semantic search,
//     artifact pinning) are charged [`heavy_method_cost`] units against the
//     per-client method budget, instead of the flat 1 they cost before.

use crate::rate_limit::{check_method_budget, RateLimitHandle};
use jsonrpc_core::futures::future::{self, Either, Ready};
use jsonrpc_core::{Call, Error, ErrorCode, Id, Metadata, Middleware, Output, Request, Response};
use std::future::Future;

/// PBA-L1a-009: most calls one JSON-RPC batch may carry (geth's
/// `BatchRequestLimit` default is 1000; Citrate's heavier per-call handlers and
/// shared un-proxied bucket warrant a tighter bound).
pub const MAX_BATCH_SIZE: usize = 100;

/// PBA-L1a-016: method-budget units charged for heavy, unauthenticated compute
/// RPCs. The per-client budget is 1000 units per second, so each of these is
/// limited to 10 calls per second per client bucket (previously they cost 1,
/// i.e. were effectively unmetered). Methods that already charge themselves
/// in-handler (`eth_call`, `eth_estimateGas`, `eth_getLogs`) return 0 here so
/// they are not double-charged.
pub fn heavy_method_cost(method: &str) -> u32 {
    match method {
        "citrate_runInference"
        | "citrate_requestInference"
        | "citrate_chatCompletion"
        | "citrate_getTextEmbedding"
        | "citrate_semanticSearch"
        | "citrate_pinArtifact" => 100,
        _ => 0,
    }
}

fn batch_too_large(len: usize) -> Response {
    Response::from(
        Error {
            code: ErrorCode::InvalidRequest,
            message: format!(
                "Batch of {} calls exceeds the node limit of {} calls per request",
                len, MAX_BATCH_SIZE
            ),
            data: None,
        },
        Some(jsonrpc_core::Version::V2),
    )
}

fn rate_limited() -> Response {
    Response::from(
        Error {
            code: ErrorCode::ServerError(-32099),
            message: "Rate limit exceeded. Try again later.".into(),
            data: None,
        },
        Some(jsonrpc_core::Version::V2),
    )
}

/// Request-shape middleware installed by `RpcServer::spawn`.
pub struct RpcLimits {
    /// Handle onto the HTTP limiter's per-client buckets (batch elements are
    /// charged to the same bucket as whole HTTP requests). `None` disables the
    /// per-element charge (used by in-process handlers with no HTTP limiter).
    buckets: Option<RateLimitHandle>,
}

impl RpcLimits {
    pub fn new(buckets: Option<RateLimitHandle>) -> Self {
        Self { buckets }
    }
}

impl<M: Metadata> Middleware<M> for RpcLimits {
    type Future = Ready<Option<Response>>;
    type CallFuture = Ready<Option<Output>>;

    fn on_request<F, X>(&self, request: Request, meta: M, next: F) -> Either<Self::Future, X>
    where
        F: Fn(Request, M) -> X + Send + Sync,
        X: Future<Output = Option<Response>> + Send + 'static,
    {
        if let Request::Batch(ref calls) = request {
            if calls.len() > MAX_BATCH_SIZE {
                return Either::Left(future::ready(Some(batch_too_large(calls.len()))));
            }
            // The HTTP limiter already charged 1 for the POST itself.
            let extra = calls.len().saturating_sub(1) as u32;
            if extra > 0 {
                if let Some(b) = &self.buckets {
                    if !b.charge_current_client(extra) {
                        return Either::Left(future::ready(Some(rate_limited())));
                    }
                }
            }
        }
        Either::Right(next(request, meta))
    }

    fn on_call<F, X>(&self, call: Call, meta: M, next: F) -> Either<Self::CallFuture, X>
    where
        F: Fn(Call, M) -> X + Send + Sync,
        X: Future<Output = Option<Output>> + Send + 'static,
    {
        let (method, id, jsonrpc) = match &call {
            Call::MethodCall(c) => (c.method.as_str(), Some(c.id.clone()), c.jsonrpc),
            Call::Notification(n) => (n.method.as_str(), None, n.jsonrpc),
            Call::Invalid { .. } => return Either::Right(next(call, meta)),
        };
        let cost = heavy_method_cost(method);
        if cost > 0 {
            if let Err(e) = check_method_budget(cost) {
                // A notification has no id and gets no response.
                let out = id.map(|id: Id| Output::from(Err(e), id, jsonrpc));
                return Either::Left(future::ready(out));
            }
        }
        Either::Right(next(call, meta))
    }
}
