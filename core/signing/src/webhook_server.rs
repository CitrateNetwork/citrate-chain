//! Axum-based webhook receiver factory for Docusign Connect callbacks.
//!
//! The bootstrap binary (`citrate-school-bootstrap`) uses this module to host a
//! long-running HTTP receiver while the operator collects signatures. Each
//! verified envelope event is dispatched through a callback the binary
//! provides — that callback is where bootstrap-state advancement happens.
//!
//! Design rationale: citrate-signing is a library; running an HTTP receiver
//! is a binary's job. This module returns a configured `axum::Router` that
//! the binary mounts onto its server. Verification + parsing happen inside
//! the router; the binary supplies only the side-effect closure.

use crate::error::SigningError;
use crate::providers::DocusignProvider;
use crate::provider::SigningProvider;
use crate::webhook::{parse_docusign_event, DocusignEvent};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use std::sync::Arc;

/// Header Docusign Connect uses to send the HMAC-SHA-256 signature over the
/// raw POST body. Hex-encoded.
pub const DOCUSIGN_SIGNATURE_HEADER: &str = "X-DocuSign-Signature-1";

/// Callback invoked for every verified, parsed envelope event. The bootstrap
/// binary supplies one of these to advance its state machine when an
/// envelope completes / declines / voids. Idempotency is the callback's
/// responsibility — Docusign retries on receiver failure, and a poorly-
/// behaved tenant could replay events.
///
/// `Send + Sync + 'static` because the axum router stores the closure in
/// shared state across handler invocations.
pub trait EventSink: Send + Sync + 'static {
    fn handle(&self, event: DocusignEvent) -> Result<(), SigningError>;
}

impl<F> EventSink for F
where
    F: Fn(DocusignEvent) -> Result<(), SigningError> + Send + Sync + 'static,
{
    fn handle(&self, event: DocusignEvent) -> Result<(), SigningError> {
        (self)(event)
    }
}

struct ReceiverState {
    provider: Arc<DocusignProvider>,
    sink: Arc<dyn EventSink>,
}

/// Build an axum `Router` that exposes `POST /webhooks/docusign`. Verifies
/// the HMAC signature, parses the payload, and dispatches the event to the
/// supplied sink. On signature failure, returns 401 (so Docusign retries).
/// On parse failure, returns 400 (Docusign should NOT retry — the payload
/// is structurally invalid, retrying won't fix it).
///
/// Mount with:
/// ```ignore
/// let app = build_docusign_webhook_router(provider, sink);
/// axum::serve(listener, app).await?;
/// ```
pub fn build_docusign_webhook_router(
    provider: Arc<DocusignProvider>,
    sink: Arc<dyn EventSink>,
) -> Router {
    let state = Arc::new(ReceiverState { provider, sink });
    Router::new()
        .route("/webhooks/docusign", post(handle_docusign_callback))
        .with_state(state)
}

async fn handle_docusign_callback(
    State(state): State<Arc<ReceiverState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Some(signature_header) = headers
        .get(DOCUSIGN_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
    else {
        tracing::warn!(
            "Docusign webhook rejected: missing {} header",
            DOCUSIGN_SIGNATURE_HEADER
        );
        return StatusCode::UNAUTHORIZED;
    };

    if let Err(e) = state
        .provider
        .verify_webhook_signature(&body, signature_header)
    {
        tracing::warn!("Docusign webhook signature verification failed: {e}");
        return StatusCode::UNAUTHORIZED;
    }

    let event = match parse_docusign_event(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Docusign webhook payload parse failed: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    let envelope_id = event.envelope_id.as_str().to_string();
    let status = event.status;
    if let Err(e) = state.sink.handle(event) {
        tracing::error!(
            "Docusign webhook sink rejected envelope {} (status {:?}): {e}",
            envelope_id,
            status
        );
        // Sink errors return 500 so Docusign retries (per Connect retry
        // policy — exponential backoff up to ~24h). The sink is responsible
        // for being idempotent so retries are safe.
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    tracing::info!(
        "Docusign webhook accepted: envelope {} → {:?}",
        envelope_id,
        status
    );
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::docusign::DocusignConfig;
    use axum::body::Body;
    use axum::http::Request;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::sync::Mutex;
    use tower::ServiceExt;

    type HmacSha256 = Hmac<Sha256>;

    fn provider() -> Arc<DocusignProvider> {
        let cfg = DocusignConfig {
            base_url: "https://demo.docusign.net/restapi".into(),
            account_id: "acct".into(),
            access_token: "token".into(),
            webhook_secret: "shhhh-test-secret".into(),
            clear_rbv_enabled: true,
        };
        Arc::new(DocusignProvider::new(cfg))
    }

    fn sign(secret: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    fn well_formed_body(envelope_id: &str, status: &str) -> Vec<u8> {
        format!(
            r#"{{"envelopeId":"{envelope_id}","status":"{status}","statusUpdateDateTime":"2026-05-04T22:45:00Z","generatedDateTime":"2026-05-04T22:45:01Z"}}"#
        )
        .into_bytes()
    }

    /// A mutable counter sink for asserting the sink was invoked with the right event.
    fn counting_sink() -> (Arc<dyn EventSink>, Arc<Mutex<Vec<DocusignEvent>>>) {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let recorded_for_closure = recorded.clone();
        let sink: Arc<dyn EventSink> = Arc::new(move |evt: DocusignEvent| {
            recorded_for_closure.lock().unwrap().push(evt);
            Ok(())
        });
        (sink, recorded)
    }

    #[tokio::test]
    async fn valid_signature_dispatches_event() {
        let provider = provider();
        let (sink, recorded) = counting_sink();
        let app = build_docusign_webhook_router(provider.clone(), sink);
        let body = well_formed_body("env-1", "Completed");
        let sig = sign("shhhh-test-secret", &body);

        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/docusign")
            .header(DOCUSIGN_SIGNATURE_HEADER, sig)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].envelope_id.as_str(), "env-1");
        assert_eq!(recorded[0].status, crate::EnvelopeStatus::Completed);
    }

    #[tokio::test]
    async fn missing_signature_header_rejects_with_401() {
        let provider = provider();
        let (sink, recorded) = counting_sink();
        let app = build_docusign_webhook_router(provider, sink);
        let body = well_formed_body("env-1", "Completed");
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/docusign")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(recorded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn wrong_signature_rejects_with_401() {
        let provider = provider();
        let (sink, recorded) = counting_sink();
        let app = build_docusign_webhook_router(provider, sink);
        let body = well_formed_body("env-1", "Completed");
        let bad_sig = sign("wrong-secret", &body);
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/docusign")
            .header(DOCUSIGN_SIGNATURE_HEADER, bad_sig)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(recorded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_payload_rejects_with_400() {
        let provider = provider();
        let (sink, recorded) = counting_sink();
        let app = build_docusign_webhook_router(provider.clone(), sink);
        let body = b"not-json".to_vec();
        let sig = sign("shhhh-test-secret", &body);
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/docusign")
            .header(DOCUSIGN_SIGNATURE_HEADER, sig)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(recorded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sink_error_returns_500_for_docusign_retry() {
        let provider = provider();
        let sink: Arc<dyn EventSink> = Arc::new(|_evt: DocusignEvent| {
            Err(SigningError::Config("simulated downstream failure".into()))
        });
        let app = build_docusign_webhook_router(provider.clone(), sink);
        let body = well_formed_body("env-1", "Completed");
        let sig = sign("shhhh-test-secret", &body);
        let req = Request::builder()
            .method("POST")
            .uri("/webhooks/docusign")
            .header(DOCUSIGN_SIGNATURE_HEADER, sig)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
