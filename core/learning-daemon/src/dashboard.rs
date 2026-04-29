//! Public dashboard backend — RM-FL-3 / WP-3.16.
//!
//! Read-only HTTP API at `federated.citrate.ai/api/*`. Exposes
//! cycle / embedding / mentor data sourced from the daemon's
//! [`DaemonState`] and the in-memory embedding cache.
//!
//! Per planset §RM-FL-3:
//!
//! > Public dashboard backend: daemon exposes `/api/cycles`,
//! > `/api/embeddings`, `/api/mentors` JSON read-only endpoints with
//! > CORS allowing `federated.citrate.ai`. Read-only, no auth needed
//! > (data is on-chain anyway).
//!
//! # Read-only contract (Rule 11 — see `check_daemon_api_readonly.py`
//! tripwire WP-3.17)
//!
//! Every route in [`router()`] MUST be HTTP `GET` only. The
//! tripwire greps this module for `Router::route` calls and
//! enforces that the verb arm is `get(...)`. PUT/POST/PATCH/DELETE
//! are forbidden — there is no mutation surface.
//!
//! # Mentor data
//!
//! Mentor matching lives in RM-FL-4. For RM-FL-3, the
//! `/api/mentors` endpoint returns `{ "available": false,
//! "reason": "mentor matching ships at RM-FL-4" }` so the dashboard
//! frontend (RM-FL-5) can branch on availability.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use crate::aggregator::EmbeddingCache;
use crate::state::{CycleStatus, DaemonState, FinalizeStatus};
use crate::types::{BlockNumber, CycleId};

/// Application state shared across dashboard handlers.
#[derive(Clone)]
pub struct DashboardState {
    /// Daemon RocksDB state (read-only access for dashboard).
    pub state: Arc<DaemonState>,
    /// Observed embeddings (in-memory cache populated by the
    /// watcher's event-handling path).
    pub cache: Arc<dyn EmbeddingCache>,
    /// Configured CORS origin (typically `https://federated.citrate.ai`).
    pub allowed_origin: String,
}

/// JSON response for `GET /api/cycles`.
#[derive(Serialize, Debug)]
pub struct CyclesResponse {
    /// Daemon's high-water-mark for finalized blocks observed.
    pub last_processed_block: BlockNumber,
    /// Per-cycle status snapshots.
    pub cycles: Vec<CycleSummary>,
}

/// One cycle's summary in `CyclesResponse`.
#[derive(Serialize, Debug, Clone)]
pub struct CycleSummary {
    /// Cycle identifier.
    pub cycle_id: CycleId,
    /// Daemon-side status: pending | computed | committed.
    pub status: &'static str,
    /// Whether the daemon has called `finalizeCycle` for this cycle.
    pub finalize_status: &'static str,
}

/// Query parameters for `GET /api/cycles`.
#[derive(Deserialize, Debug, Default)]
pub struct CyclesQuery {
    /// Inclusive lower bound on cycle id. Defaults to 1.
    pub from: Option<CycleId>,
    /// Inclusive upper bound on cycle id. Defaults to `from + 50`.
    pub to: Option<CycleId>,
}

/// JSON response for `GET /api/embeddings/:cycle_id`.
#[derive(Serialize, Debug)]
pub struct EmbeddingsResponse {
    /// Cycle the embeddings belong to.
    pub cycle_id: CycleId,
    /// Number of submissions observed.
    pub count: usize,
    /// Submitter addresses (hex 0x...). Vector contents only —
    /// the dashboard does not surface the raw Q16 embedding values
    /// to keep the response small; clients that need them can
    /// query the chain directly.
    pub submitters: Vec<String>,
}

/// JSON response for `GET /api/mentors`.
#[derive(Serialize, Debug)]
pub struct MentorsResponse {
    /// Whether mentor data is available. False until RM-FL-4 ships.
    pub available: bool,
    /// Human-readable reason if `available == false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Build the dashboard router.
///
/// Read-only contract: every route below uses `get(...)`. The
/// `check_daemon_api_readonly.py` tripwire (WP-3.17) enforces this
/// structurally.
pub fn router(app_state: DashboardState) -> Router {
    let cors = match app_state.allowed_origin.parse::<HeaderValue>() {
        Ok(origin) => CorsLayer::new()
            .allow_origin(origin)
            .allow_methods([Method::GET]),
        // If the configured origin is malformed, fall back to a
        // permissive same-site policy so the daemon doesn't refuse
        // to start. The operator is expected to surface this via
        // tracing.
        Err(_) => CorsLayer::new().allow_methods([Method::GET]),
    };

    Router::new()
        .route("/api/cycles", get(get_cycles))
        .route("/api/embeddings/:cycle_id", get(get_embeddings))
        .route("/api/mentors", get(get_mentors))
        .layer(cors)
        .with_state(app_state)
}

async fn get_cycles(
    State(s): State<DashboardState>,
    Query(q): Query<CyclesQuery>,
) -> impl IntoResponse {
    let from = q.from.unwrap_or(1);
    let to = q.to.unwrap_or(from.saturating_add(49));
    let mut cycles = Vec::new();
    for cid in from..=to {
        let status = match s.state.cycle_status(cid) {
            CycleStatus::Pending => "pending",
            CycleStatus::Computed => "computed",
            CycleStatus::Committed => "committed",
        };
        let finalize = match s.state.finalize_status(cid) {
            FinalizeStatus::NotCalled => "not_called",
            FinalizeStatus::Called => "called",
        };
        // Skip pending cycles that have never been observed (status
        // == Pending AND finalize == NotCalled is the default for
        // any cycle id we've never touched). This keeps the
        // response bounded for arbitrary scan ranges.
        if status == "pending" && finalize == "not_called" {
            continue;
        }
        cycles.push(CycleSummary {
            cycle_id: cid,
            status,
            finalize_status: finalize,
        });
    }
    Json(CyclesResponse {
        last_processed_block: s.state.last_processed_block(),
        cycles,
    })
}

async fn get_embeddings(
    State(s): State<DashboardState>,
    Path(cycle_id): Path<CycleId>,
) -> impl IntoResponse {
    let entries = s.cache.embeddings_for_cycle(cycle_id);
    let submitters = entries
        .iter()
        .map(|e| format!("0x{}", hex::encode(e.submitter.as_bytes())))
        .collect::<Vec<_>>();
    Json(EmbeddingsResponse {
        cycle_id,
        count: entries.len(),
        submitters,
    })
}

async fn get_mentors(State(_): State<DashboardState>) -> impl IntoResponse {
    // Mentor matching ships at RM-FL-4. Return an explicit
    // unavailable response with a 200 status so the dashboard
    // frontend can branch on `available == false` without
    // treating it as an error.
    (
        StatusCode::OK,
        Json(MentorsResponse {
            available: false,
            reason: Some(
                "mentor matching ships at RM-FL-4".to_string(),
            ),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::{EmbeddingEntry, MemoryEmbeddingCache};
    use axum::body::Body;
    use axum::http::Request;
    use ethereum_types::H160;
    use http_body_util::BodyExt;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn fixture() -> (DashboardState, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let state =
            Arc::new(DaemonState::open(dir.path()).expect("state open"));
        let cache: Arc<dyn EmbeddingCache> =
            Arc::new(MemoryEmbeddingCache::new());
        (
            DashboardState {
                state,
                cache,
                allowed_origin: "https://federated.citrate.ai".to_string(),
            },
            dir,
        )
    }

    async fn body_json(
        resp: axum::response::Response,
    ) -> serde_json::Value {
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("parse json")
    }

    #[tokio::test]
    async fn cycles_endpoint_returns_only_observed_cycles() {
        let (s, _dir) = fixture();
        // Promote cycle 3 + 7 to Committed; cycle 5 only to
        // Computed; the rest are untouched.
        s.state.set_cycle_status(3, CycleStatus::Computed).expect("ok");
        s.state.set_cycle_status(3, CycleStatus::Committed).expect("ok");
        s.state.mark_finalized(3).expect("ok");
        s.state.set_cycle_status(5, CycleStatus::Computed).expect("ok");
        s.state.set_cycle_status(7, CycleStatus::Computed).expect("ok");
        s.state.set_cycle_status(7, CycleStatus::Committed).expect("ok");

        let app = router(s.clone());
        let req = Request::builder()
            .uri("/api/cycles?from=1&to=10")
            .body(Body::empty())
            .expect("req");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;

        let cycles = body["cycles"].as_array().expect("array");
        // Only cycles 3, 5, 7 should appear; defaults are skipped.
        assert_eq!(cycles.len(), 3);
        assert_eq!(cycles[0]["cycle_id"], 3);
        assert_eq!(cycles[0]["status"], "committed");
        assert_eq!(cycles[0]["finalize_status"], "called");
        assert_eq!(cycles[1]["cycle_id"], 5);
        assert_eq!(cycles[1]["status"], "computed");
        assert_eq!(cycles[2]["cycle_id"], 7);
        assert_eq!(cycles[2]["status"], "committed");
        assert_eq!(cycles[2]["finalize_status"], "not_called");
    }

    #[tokio::test]
    async fn cycles_endpoint_defaults_to_first_50() {
        let (s, _dir) = fixture();
        s.state.set_cycle_status(2, CycleStatus::Computed).expect("ok");
        let app = router(s);
        let req = Request::builder()
            .uri("/api/cycles")
            .body(Body::empty())
            .expect("req");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["cycles"].as_array().expect("array").len(), 1);
    }

    #[tokio::test]
    async fn embeddings_endpoint_returns_submitter_count() {
        let (s, _dir) = fixture();
        // Pre-populate the cache for cycle 11.
        let cache: Arc<MemoryEmbeddingCache> =
            Arc::new(MemoryEmbeddingCache::new());
        cache.insert(
            11,
            EmbeddingEntry {
                submitter: H160::repeat_byte(0xAA),
                embedding: vec![1],
                confidence: vec![1],
                weight: 1,
            },
        );
        cache.insert(
            11,
            EmbeddingEntry {
                submitter: H160::repeat_byte(0xBB),
                embedding: vec![1],
                confidence: vec![1],
                weight: 1,
            },
        );
        let s = DashboardState {
            cache: cache.clone(),
            ..s
        };
        let app = router(s);
        let req = Request::builder()
            .uri("/api/embeddings/11")
            .body(Body::empty())
            .expect("req");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["cycle_id"], 11);
        assert_eq!(body["count"], 2);
        assert_eq!(body["submitters"].as_array().expect("array").len(), 2);
        assert_eq!(
            body["submitters"][0].as_str().expect("str"),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[tokio::test]
    async fn embeddings_endpoint_empty_for_unknown_cycle() {
        let (s, _dir) = fixture();
        let app = router(s);
        let req = Request::builder()
            .uri("/api/embeddings/999")
            .body(Body::empty())
            .expect("req");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["count"], 0);
    }

    #[tokio::test]
    async fn mentors_endpoint_signals_unavailable_pending_rm_fl_4() {
        let (s, _dir) = fixture();
        let app = router(s);
        let req = Request::builder()
            .uri("/api/mentors")
            .body(Body::empty())
            .expect("req");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["available"], false);
        assert!(
            body["reason"]
                .as_str()
                .expect("reason")
                .contains("RM-FL-4")
        );
    }

    #[tokio::test]
    async fn post_to_dashboard_returns_method_not_allowed() {
        // Read-only contract: only GET is registered. POST must
        // 405. This is a behavioral guard alongside the
        // structural check_daemon_api_readonly.py tripwire.
        let (s, _dir) = fixture();
        let app = router(s);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/cycles")
            .body(Body::empty())
            .expect("req");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
