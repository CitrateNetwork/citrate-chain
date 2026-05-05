//! Docusign Connect webhook payload parsing.
//!
//! The HTTP receiver (axum handler) lives in the bootstrap CLI binary; this
//! module provides the typed parser the receiver hands raw bytes to. Keeping
//! the parser here means a future Sumsub-style webhook handler can live
//! alongside as a peer module.

use crate::error::SigningError;
use crate::models::{EnvelopeId, EnvelopeStatus};
use serde::Deserialize;

/// Parsed event from a Docusign Connect webhook callback. Maps the
/// provider-specific JSON shape to our `EnvelopeStatus` enum.
#[derive(Debug, Clone)]
pub struct DocusignEvent {
    pub envelope_id: EnvelopeId,
    pub status: EnvelopeStatus,
    pub event_timestamp: chrono::DateTime<chrono::Utc>,
    /// Provider-side delivery sequence — used for idempotency in the
    /// receiver (drop replays of the same generationTime).
    pub generation_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct RawDocusignPayload {
    #[serde(rename = "envelopeId")]
    envelope_id: String,
    status: String,
    #[serde(rename = "statusUpdateDateTime")]
    status_update: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "generatedDateTime")]
    generated: chrono::DateTime<chrono::Utc>,
}

/// Parse the raw bytes of a Docusign Connect callback into a typed event.
///
/// The signature MUST already have been verified by
/// `SigningProvider::verify_webhook_signature` before calling this function;
/// trusting an unverified payload is a security defect.
pub fn parse_docusign_event(payload: &[u8]) -> Result<DocusignEvent, SigningError> {
    let raw: RawDocusignPayload = serde_json::from_slice(payload)
        .map_err(|e| SigningError::WebhookPayloadInvalid(e.to_string()))?;
    let status = match raw.status.as_str() {
        "Created" | "created" => EnvelopeStatus::Draft,
        "Sent" | "sent" => EnvelopeStatus::Sent,
        "Delivered" | "delivered" => EnvelopeStatus::Delivered,
        "Completed" | "completed" => EnvelopeStatus::Completed,
        "Declined" | "declined" => EnvelopeStatus::Declined,
        "Voided" | "voided" => EnvelopeStatus::Voided,
        other => {
            return Err(SigningError::WebhookPayloadInvalid(format!(
                "unknown Docusign status: {other}"
            )));
        }
    };
    Ok(DocusignEvent {
        envelope_id: EnvelopeId::new(raw.envelope_id),
        status,
        event_timestamp: raw.status_update,
        generation_time: raw.generated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_docusign_event_completed_payload() {
        let body = br#"{
            "envelopeId": "abc-123",
            "status": "Completed",
            "statusUpdateDateTime": "2026-05-04T22:45:00Z",
            "generatedDateTime": "2026-05-04T22:45:01Z"
        }"#;
        let evt = parse_docusign_event(body).expect("parse");
        assert_eq!(evt.envelope_id.as_str(), "abc-123");
        assert_eq!(evt.status, EnvelopeStatus::Completed);
    }

    #[test]
    fn parse_docusign_event_declined_payload() {
        let body = br#"{
            "envelopeId": "xyz-789",
            "status": "Declined",
            "statusUpdateDateTime": "2026-05-04T22:46:00Z",
            "generatedDateTime": "2026-05-04T22:46:01Z"
        }"#;
        let evt = parse_docusign_event(body).expect("parse");
        assert_eq!(evt.status, EnvelopeStatus::Declined);
    }

    #[test]
    fn parse_docusign_event_unknown_status_rejected() {
        let body = br#"{
            "envelopeId": "x",
            "status": "Bogus",
            "statusUpdateDateTime": "2026-05-04T22:45:00Z",
            "generatedDateTime": "2026-05-04T22:45:01Z"
        }"#;
        let result = parse_docusign_event(body);
        assert!(matches!(result, Err(SigningError::WebhookPayloadInvalid(_))));
    }

    #[test]
    fn parse_docusign_event_malformed_json_rejected() {
        let body = b"not json {{";
        let result = parse_docusign_event(body);
        assert!(matches!(result, Err(SigningError::WebhookPayloadInvalid(_))));
    }
}
