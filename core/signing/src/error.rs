use thiserror::Error;

/// Errors surfaced by any `SigningProvider`. Provider-specific failure modes
/// are mapped onto these categories so the bootstrap state machine and webhook
/// handler don't need to know which backend is in use.
#[derive(Error, Debug)]
pub enum SigningError {
    #[error("network or HTTP transport failure: {0}")]
    Transport(String),

    #[error("provider API rejected the request: {status} — {message}")]
    Provider { status: u16, message: String },

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("envelope {envelope_id} not found")]
    EnvelopeNotFound { envelope_id: String },

    #[error("envelope {envelope_id} is in state {state:?}; cannot perform {operation}")]
    InvalidState {
        envelope_id: String,
        state: crate::models::EnvelopeStatus,
        operation: String,
    },

    #[error("webhook signature verification failed")]
    WebhookSignatureInvalid,

    #[error("webhook payload could not be parsed: {0}")]
    WebhookPayloadInvalid(String),

    #[error("identity verification rejected for signer {signer_email}: {reason}")]
    IdVerificationRejected {
        signer_email: String,
        reason: String,
    },

    #[error("serialization failure: {0}")]
    Serde(#[from] serde_json::Error),
}

impl From<reqwest::Error> for SigningError {
    fn from(value: reqwest::Error) -> Self {
        SigningError::Transport(value.to_string())
    }
}
