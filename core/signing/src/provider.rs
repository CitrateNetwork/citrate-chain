use crate::error::SigningError;
use crate::models::{Envelope, EnvelopeId, RiskLevel, SignedDocument, SignedDocumentBytes, Signer};
use async_trait::async_trait;

/// Abstract signing-service backend. Patterned after `agent-core::adapters::HermesAdapter`
/// (`citrate_v0.01.1/agent-core/src/adapters/hermes.rs`) — single struct + builder methods,
/// optional crypto gates surfaced by the trait, no excess generics.
///
/// Concrete implementations:
/// - `providers::DocusignProvider` (default; implements Docusign eSignature REST + CLEAR
///   Risk-Based Verification) — see `02_SIGNING_AND_KYC_ARCHITECTURE.md`.
///
/// The bootstrap CLI's signing track depends on this trait, not the concrete provider, so a
/// district that already has HelloSign / PandaDoc could plug in their own implementation
/// without touching the orchestration layer.
#[async_trait]
pub trait SigningProvider: Send + Sync {
    /// Create + send an envelope. The envelope subject and signers are routed per the
    /// provider's per-signer addressing (email + legal name); the risk level controls
    /// whether each signer is required to complete ID verification before signing.
    ///
    /// On success, returns the envelope record with `EnvelopeStatus::Sent`. The bootstrap
    /// state machine persists the returned `EnvelopeId` so it can correlate webhook
    /// callbacks and resume on restart.
    async fn create_and_send_envelope(
        &self,
        subject: &str,
        document_pdf: &[u8],
        signers: &[Signer],
        risk_level: RiskLevel,
        correlation_tag: &str,
    ) -> Result<Envelope, SigningError>;

    /// Fetch the current state of an envelope. Used for poll-based status checks when
    /// webhooks are not available (offline / sneakernet contexts).
    async fn get_envelope(&self, id: &EnvelopeId) -> Result<Envelope, SigningError>;

    /// Download the signed PDF + the audit trail metadata for a `Completed` envelope.
    /// Errors with `InvalidState` if the envelope is not yet completed.
    async fn download_signed_document(
        &self,
        id: &EnvelopeId,
    ) -> Result<(SignedDocument, SignedDocumentBytes), SigningError>;

    /// Verify a webhook signature (Docusign Connect HMAC-SHA-256). Returns Ok if the
    /// signature is valid for the supplied raw payload bytes; SigningError::WebhookSignatureInvalid
    /// otherwise. Webhook handler MUST call this before trusting any payload field.
    fn verify_webhook_signature(&self, payload: &[u8], signature_header: &str) -> Result<(), SigningError>;
}
