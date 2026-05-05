use serde::{Deserialize, Serialize};

/// Provider-issued envelope identifier (Docusign envelope GUID, HelloSign
/// signature_request_id, etc.). Treated as an opaque string by the rest of
/// the system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EnvelopeId(pub String);

impl EnvelopeId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lifecycle states an envelope may be in. Mapped from provider-specific status
/// strings on ingress.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnvelopeStatus {
    /// Envelope created locally; not yet sent to signers.
    Draft,
    /// Sent to one or more signers; awaiting first signature.
    Sent,
    /// At least one signer has opened but not yet signed.
    Delivered,
    /// All signers have signed.
    Completed,
    /// A signer declined; envelope is closed.
    Declined,
    /// Sender voided the envelope before completion.
    Voided,
    /// Envelope expired before completion.
    Expired,
}

/// Risk level for the CLEAR Risk-Based Verification toggle. Mapped from the
/// Citrate-side artifact-risk profile to Docusign's rbv level on send.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    /// SMS / email verification only. Use for low-stakes acknowledgments.
    Low,
    /// SMS + KBA. Use for budget allocations, role grants.
    Medium,
    /// CLEAR biometric + government ID. Use for DPAs, board resolutions,
    /// COPPA institutional consents.
    High,
}

/// Identity-verification artifact returned by the provider after a signer
/// completes their CLEAR (or equivalent) verification. The opaque
/// `provider_attestation` is the auditable artifact; `verified_at` and
/// `signer_email` are provider-extracted convenience fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdVerification {
    pub signer_email: String,
    pub verified_at: chrono::DateTime<chrono::Utc>,
    /// Provider-issued attestation token / reference. Opaque to Citrate;
    /// stored in the audit trail.
    pub provider_attestation: String,
    /// Which provider performed the verification ("clear" for Docusign+CLEAR).
    pub provider: String,
}

/// Role a signer plays on an envelope. Determines the order and routing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignerRole {
    /// District / CMO official signing the institutional artifact (DPA, etc.).
    InstitutionalSigner,
    /// Internal Citrate counter-signer (counsel) — required on every DPA.
    CitrateCounterSigner,
    /// School board member co-signing a board resolution.
    BoardMember,
    /// Witness signature (rare; e.g. notarization-equivalent).
    Witness,
}

/// A signer attached to an envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    pub email: String,
    pub legal_name: String,
    pub role: SignerRole,
    /// Order in which this signer is asked to sign. Lower numbers go first.
    pub routing_order: u8,
    /// Whether this signer must complete CLEAR Risk-Based Verification before
    /// their signature binds. Driven by the envelope's overall risk level.
    pub require_id_verification: bool,
}

/// An envelope as known to the bootstrap orchestrator. Mirrors a subset of
/// the provider's envelope record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: EnvelopeId,
    pub subject: String,
    pub status: EnvelopeStatus,
    pub risk_level: RiskLevel,
    pub signers: Vec<Signer>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Application-level correlation tag — typically the bootstrap step ID
    /// (e.g. "DPA", "BOARD_RES", "CA_SOPIPA") so the state machine can match
    /// webhook callbacks back to the right gate.
    pub correlation_tag: String,
}

/// Bytes of a signed-and-completed PDF. Returned by the provider on
/// `download_signed_document`.
#[derive(Debug, Clone)]
pub struct SignedDocumentBytes(pub Vec<u8>);

/// A signed document, the auditable artifact produced when an envelope
/// completes. Includes the per-signer ID-verification trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDocument {
    pub envelope_id: EnvelopeId,
    pub correlation_tag: String,
    pub signed_at: chrono::DateTime<chrono::Utc>,
    pub id_verifications: Vec<IdVerification>,
    /// SHA-256 of the final signed PDF bytes. The bytes themselves are
    /// stored separately by the bootstrap (encrypted at rest in
    /// ~/.citrate-edu/compliance/<correlation_tag>.pdf).
    pub pdf_sha256: String,
}
