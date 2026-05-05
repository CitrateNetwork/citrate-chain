//! `citrate-signing` — provider-abstracted electronic-signature service for
//! the IT-Turnkey bootstrap. Default backend is Docusign with CLEAR Risk-Based
//! Verification for adult signers; the trait surface is provider-agnostic so
//! HelloSign / PandaDoc / DocuFirst / etc. could be added later.
//!
//! See `.agentile/planset/2026-05-04-it-turnkey-deployment/02_SIGNING_AND_KYC_ARCHITECTURE.md`
//! for the architecture this crate implements.

pub mod auth_mode;
pub mod error;
pub mod models;
pub mod provider;
pub mod providers;
pub mod webhook;
pub mod webhook_server;

pub use auth_mode::{select_auth_mode, AuthMode, TenantCapabilities};
pub use error::SigningError;
pub use models::{
    Envelope, EnvelopeId, EnvelopeStatus, IdVerification, RiskLevel, SignedDocument,
    SignedDocumentBytes, Signer, SignerRole,
};
pub use provider::SigningProvider;
pub use webhook_server::{build_docusign_webhook_router, EventSink, DOCUSIGN_SIGNATURE_HEADER};
