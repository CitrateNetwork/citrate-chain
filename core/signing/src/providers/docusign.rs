//! Docusign eSignature REST + CLEAR Risk-Based Verification backend.
//!
//! Implements `SigningProvider` against Docusign's REST API. The CLEAR
//! Risk-Based Verification is enabled per-envelope by setting the appropriate
//! `recipientAuthenticationStatus` requirements on each signer.
//!
//! Authentication: OAuth 2.0 JWT bearer flow (recommended for server-to-server
//! integration per Docusign's developer guide).
//!
//! Webhook signature verification: Docusign Connect signs every callback with
//! HMAC-SHA-256 over the raw POST body, with the secret configured in the
//! Docusign tenant. The header is `X-DocuSign-Signature-1`.

use crate::error::SigningError;
use crate::models::{Envelope, EnvelopeId, RiskLevel, SignedDocument, SignedDocumentBytes, Signer};
use crate::provider::SigningProvider;
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Configuration for the Docusign backend. Constructed from environment
/// variables in production (`DOCUSIGN_*`); tests use the builder.
#[derive(Debug, Clone)]
pub struct DocusignConfig {
    /// Docusign account API base URL — `https://www.docusign.net/restapi` for production
    /// or `https://demo.docusign.net/restapi` for sandbox.
    pub base_url: String,
    /// Docusign account GUID (UUID).
    pub account_id: String,
    /// OAuth bearer token (JWT-derived). The bootstrap auth lifecycle handles refresh;
    /// this struct treats the token as opaque.
    pub access_token: String,
    /// Webhook signing secret configured in the Docusign Connect tenant settings. Used by
    /// `verify_webhook_signature`. Required for production; tests can use a fixed value.
    pub webhook_secret: String,
    /// Whether CLEAR Risk-Based Verification is enabled on this Docusign tenant. If `false`,
    /// `RiskLevel::High` falls back to `Medium` (KBA) at envelope-create time.
    pub clear_rbv_enabled: bool,
}

impl DocusignConfig {
    /// Construct from `DOCUSIGN_BASE_URL`, `DOCUSIGN_ACCOUNT_ID`,
    /// `DOCUSIGN_ACCESS_TOKEN`, `DOCUSIGN_WEBHOOK_SECRET`,
    /// `DOCUSIGN_CLEAR_RBV_ENABLED` env vars. Hard-fails if any required var
    /// is missing — `unwrap_or` defaults are inappropriate for security
    /// configuration.
    pub fn from_env() -> Result<Self, SigningError> {
        let base_url = std::env::var("DOCUSIGN_BASE_URL")
            .map_err(|_| SigningError::Config("DOCUSIGN_BASE_URL not set".to_string()))?;
        let account_id = std::env::var("DOCUSIGN_ACCOUNT_ID")
            .map_err(|_| SigningError::Config("DOCUSIGN_ACCOUNT_ID not set".to_string()))?;
        let access_token = std::env::var("DOCUSIGN_ACCESS_TOKEN")
            .map_err(|_| SigningError::Config("DOCUSIGN_ACCESS_TOKEN not set".to_string()))?;
        let webhook_secret = std::env::var("DOCUSIGN_WEBHOOK_SECRET")
            .map_err(|_| SigningError::Config("DOCUSIGN_WEBHOOK_SECRET not set".to_string()))?;
        let clear_rbv_enabled = std::env::var("DOCUSIGN_CLEAR_RBV_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Ok(Self {
            base_url,
            account_id,
            access_token,
            webhook_secret,
            clear_rbv_enabled,
        })
    }
}

pub struct DocusignProvider {
    config: DocusignConfig,
    http: reqwest::Client,
}

impl DocusignProvider {
    pub fn new(config: DocusignConfig) -> Self {
        // 30s default timeout; Docusign envelope-create can take up to ~10s on first call
        // when their template engine warms up.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client build with default settings should never fail");
        Self { config, http }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.access_token)
    }

    /// Effective risk level after applying tenant capability gating: if CLEAR RBV is not
    /// enabled on this tenant, downgrade `High` to `Medium` (KBA) so the envelope can still
    /// send. Logs a warning so the operator knows.
    fn effective_risk_level(&self, requested: RiskLevel) -> RiskLevel {
        if requested == RiskLevel::High && !self.config.clear_rbv_enabled {
            tracing::warn!(
                "Docusign tenant does not have CLEAR RBV enabled; downgrading High → Medium for this envelope. \
                 Enable CLEAR Risk-Based Verification in tenant settings to unlock biometric ID verification."
            );
            RiskLevel::Medium
        } else {
            requested
        }
    }
}

#[async_trait]
impl SigningProvider for DocusignProvider {
    async fn create_and_send_envelope(
        &self,
        _subject: &str,
        _document_pdf: &[u8],
        _signers: &[Signer],
        risk_level: RiskLevel,
        _correlation_tag: &str,
    ) -> Result<Envelope, SigningError> {
        // The full Docusign envelope-create payload is built in WP-B2 (alongside the legal
        // template versioning work). This scaffold lands the type-correct trait
        // implementation + the effective_risk_level capability gating; the live API call
        // body lands in B2 once the legal templates are reviewed by counsel.
        let _effective = self.effective_risk_level(risk_level);
        let _ = &self.http;
        let _ = &self.config.base_url;
        Err(SigningError::Config(
            "DocusignProvider::create_and_send_envelope is not yet implemented; \
             full payload landing in WP-B2 after legal template counsel review."
                .to_string(),
        ))
    }

    async fn get_envelope(&self, id: &EnvelopeId) -> Result<Envelope, SigningError> {
        // GET /v2.1/accounts/{accountId}/envelopes/{envelopeId}
        // Lands in WP-B4 alongside the webhook-receiver wiring.
        Err(SigningError::Config(format!(
            "DocusignProvider::get_envelope({}) is not yet implemented; \
             lands in WP-B4 alongside webhook receiver.",
            id.as_str()
        )))
    }

    async fn download_signed_document(
        &self,
        id: &EnvelopeId,
    ) -> Result<(SignedDocument, SignedDocumentBytes), SigningError> {
        // GET /v2.1/accounts/{accountId}/envelopes/{envelopeId}/documents/combined
        // Lands in WP-B3 alongside the encrypted-at-rest storage layer.
        Err(SigningError::Config(format!(
            "DocusignProvider::download_signed_document({}) is not yet implemented; \
             lands in WP-B3 alongside encrypted storage.",
            id.as_str()
        )))
    }

    fn verify_webhook_signature(
        &self,
        payload: &[u8],
        signature_header: &str,
    ) -> Result<(), SigningError> {
        // Docusign Connect HMAC-SHA-256 over the raw POST body. The header value is the
        // hex-encoded MAC. Constant-time comparison via `Mac::verify_slice`.
        let mut mac = HmacSha256::new_from_slice(self.config.webhook_secret.as_bytes())
            .map_err(|e| SigningError::Config(format!("invalid webhook secret length: {e}")))?;
        mac.update(payload);
        let provided =
            hex::decode(signature_header).map_err(|_| SigningError::WebhookSignatureInvalid)?;
        mac.verify_slice(&provided)
            .map_err(|_| SigningError::WebhookSignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac;

    fn test_config() -> DocusignConfig {
        DocusignConfig {
            base_url: "https://demo.docusign.net/restapi".to_string(),
            account_id: "test-account-id".to_string(),
            access_token: "test-token".to_string(),
            webhook_secret: "test-webhook-secret".to_string(),
            clear_rbv_enabled: true,
        }
    }

    fn sign_payload(secret: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn verify_webhook_signature_accepts_valid_hmac() {
        let cfg = test_config();
        let provider = DocusignProvider::new(cfg.clone());
        let body = br#"{"event":"envelope-completed","envelopeId":"abc"}"#;
        let sig = sign_payload(&cfg.webhook_secret, body);
        provider.verify_webhook_signature(body, &sig).expect("valid sig");
    }

    #[test]
    fn verify_webhook_signature_rejects_wrong_secret() {
        let cfg = test_config();
        let provider = DocusignProvider::new(cfg);
        let body = br#"{"event":"envelope-completed","envelopeId":"abc"}"#;
        let sig = sign_payload("wrong-secret", body);
        let result = provider.verify_webhook_signature(body, &sig);
        assert!(matches!(
            result,
            Err(SigningError::WebhookSignatureInvalid)
        ));
    }

    #[test]
    fn verify_webhook_signature_rejects_tampered_body() {
        let cfg = test_config();
        let provider = DocusignProvider::new(cfg.clone());
        let original = br#"{"event":"envelope-completed","envelopeId":"abc"}"#;
        let tampered = br#"{"event":"envelope-completed","envelopeId":"xyz"}"#;
        let sig = sign_payload(&cfg.webhook_secret, original);
        let result = provider.verify_webhook_signature(tampered, &sig);
        assert!(matches!(
            result,
            Err(SigningError::WebhookSignatureInvalid)
        ));
    }

    #[test]
    fn verify_webhook_signature_rejects_malformed_hex() {
        let cfg = test_config();
        let provider = DocusignProvider::new(cfg);
        let body = br#"{"event":"envelope-completed","envelopeId":"abc"}"#;
        let result = provider.verify_webhook_signature(body, "not-hex-G");
        assert!(matches!(
            result,
            Err(SigningError::WebhookSignatureInvalid)
        ));
    }

    #[test]
    fn effective_risk_level_downgrades_when_clear_disabled() {
        let mut cfg = test_config();
        cfg.clear_rbv_enabled = false;
        let provider = DocusignProvider::new(cfg);
        assert_eq!(provider.effective_risk_level(RiskLevel::High), RiskLevel::Medium);
        assert_eq!(provider.effective_risk_level(RiskLevel::Medium), RiskLevel::Medium);
        assert_eq!(provider.effective_risk_level(RiskLevel::Low), RiskLevel::Low);
    }

    #[test]
    fn effective_risk_level_preserves_high_when_clear_enabled() {
        let cfg = test_config();
        let provider = DocusignProvider::new(cfg);
        assert_eq!(provider.effective_risk_level(RiskLevel::High), RiskLevel::High);
    }
}
