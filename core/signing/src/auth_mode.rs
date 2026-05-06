//! Per-signer authentication mode selection for envelope creation.
//!
//! Each envelope has an overall `RiskLevel` (Low / Medium / High); each
//! signer has a `require_id_verification` flag. Combining those with the
//! tenant's `clear_rbv_enabled` capability produces the actual
//! Docusign-payload-shape authentication mode the envelope-create call
//! sets on each recipient.
//!
//! Lives next to B1's `effective_risk_level` capability gating; this is
//! the second translation step (envelope-level → per-signer-level).
//! Used by WP-B6's envelope-dispatch path when calling
//! `SigningProvider::create_and_send_envelope`.

use crate::models::{RiskLevel, Signer};

/// Per-signer authentication mode the Docusign envelope-create payload
/// requires for that recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// No identity verification beyond the email link Docusign emits.
    /// Lowest friction; appropriate for internal acknowledgments where
    /// the signer's identity is implicit (e.g. the per-staff AUP gate
    /// where the user is already authenticated to their wallet).
    EmailLink,

    /// SMS one-time-passcode verification. Adds a phone-number ownership
    /// check on top of email. Used for Medium-risk envelopes where ID
    /// verification is not required but identity assurance is desired.
    SmsOtp,

    /// Knowledge-Based Authentication (third-party verification by
    /// Docusign's identity provider — typically uses public records
    /// to ask the signer questions only they should know). Used for
    /// Medium-risk envelopes when CLEAR RBV is unavailable on the tenant.
    KnowledgeBasedAuth,

    /// CLEAR biometric + government-ID verification, integrated through
    /// Docusign's CLEAR partnership. Strongest mode; required for
    /// High-risk envelopes (DPA, COPPA Institutional Consent, standalone
    /// DPA). When the tenant doesn't have CLEAR RBV enabled, the envelope
    /// downgrades to KnowledgeBasedAuth (per `effective_risk_level` on
    /// `DocusignProvider`).
    ClearBiometric,
}

impl AuthMode {
    /// Translate to the Docusign-payload string Docusign's REST API expects
    /// in the recipient `idCheckConfigurationName` field. Used by B2's
    /// envelope-create payload builder.
    pub fn docusign_id_check_name(&self) -> &'static str {
        match self {
            AuthMode::EmailLink => "",
            AuthMode::SmsOtp => "SMS Auth $",
            AuthMode::KnowledgeBasedAuth => "ID Check $",
            AuthMode::ClearBiometric => "CLEAR Identity Verification",
        }
    }

    /// True if the mode requires the signer's email + at least one
    /// additional factor.
    pub fn is_multi_factor(&self) -> bool {
        !matches!(self, AuthMode::EmailLink)
    }

    /// True if the mode requires CLEAR (biometric + ID).
    pub fn requires_clear(&self) -> bool {
        matches!(self, AuthMode::ClearBiometric)
    }
}

/// Tenant capability flags that shape which `AuthMode` values are
/// available. Constructed from `DocusignConfig` at the call site.
#[derive(Debug, Clone, Copy)]
pub struct TenantCapabilities {
    pub clear_rbv_enabled: bool,
}

/// Map (envelope risk + per-signer flag + tenant capabilities) onto a
/// concrete `AuthMode`. The selection rules (in order of precedence):
///
/// 1. If the signer is flagged `require_id_verification = false`, the
///    mode is `EmailLink` regardless of envelope risk.
/// 2. If the envelope is `RiskLevel::Low`, the mode is `EmailLink`
///    (low-stakes acknowledgments).
/// 3. If the envelope is `RiskLevel::Medium`, the mode is `SmsOtp`
///    when the tenant has CLEAR RBV (CLEAR is overkill for Medium),
///    or `KnowledgeBasedAuth` when not (KBA is the next-best option).
/// 4. If the envelope is `RiskLevel::High` and the tenant has CLEAR RBV,
///    the mode is `ClearBiometric`.
/// 5. If the envelope is `RiskLevel::High` and the tenant does NOT have
///    CLEAR RBV, the mode is `KnowledgeBasedAuth` (downgrade — same
///    rule as `DocusignProvider::effective_risk_level`).
pub fn select_auth_mode(
    envelope_risk: RiskLevel,
    signer: &Signer,
    tenant: TenantCapabilities,
) -> AuthMode {
    if !signer.require_id_verification {
        return AuthMode::EmailLink;
    }
    match envelope_risk {
        RiskLevel::Low => AuthMode::EmailLink,
        RiskLevel::Medium => {
            // CLEAR RBV is overkill for Medium-risk; even when the tenant
            // has it, we use SMS OTP for the lighter-weight gate. KBA only
            // when the tenant has neither CLEAR nor SMS configured (rare).
            if tenant.clear_rbv_enabled {
                AuthMode::SmsOtp
            } else {
                AuthMode::KnowledgeBasedAuth
            }
        }
        RiskLevel::High => {
            if tenant.clear_rbv_enabled {
                AuthMode::ClearBiometric
            } else {
                AuthMode::KnowledgeBasedAuth
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SignerRole;

    fn signer_with_rbv(require: bool) -> Signer {
        Signer {
            email: "test@example.com".into(),
            legal_name: "Test Signer".into(),
            role: SignerRole::InstitutionalSigner,
            routing_order: 1,
            require_id_verification: require,
        }
    }

    fn tenant(clear: bool) -> TenantCapabilities {
        TenantCapabilities {
            clear_rbv_enabled: clear,
        }
    }

    #[test]
    fn signer_without_rbv_flag_always_gets_email_link() {
        let s = signer_with_rbv(false);
        assert_eq!(
            select_auth_mode(RiskLevel::Low, &s, tenant(true)),
            AuthMode::EmailLink
        );
        assert_eq!(
            select_auth_mode(RiskLevel::Medium, &s, tenant(true)),
            AuthMode::EmailLink
        );
        assert_eq!(
            select_auth_mode(RiskLevel::High, &s, tenant(true)),
            AuthMode::EmailLink
        );
        // Even without CLEAR on the tenant: signer-flag wins.
        assert_eq!(
            select_auth_mode(RiskLevel::High, &s, tenant(false)),
            AuthMode::EmailLink
        );
    }

    #[test]
    fn low_risk_envelope_is_email_link_for_rbv_signers() {
        let s = signer_with_rbv(true);
        assert_eq!(
            select_auth_mode(RiskLevel::Low, &s, tenant(true)),
            AuthMode::EmailLink
        );
    }

    #[test]
    fn medium_risk_with_clear_uses_sms_otp() {
        let s = signer_with_rbv(true);
        assert_eq!(
            select_auth_mode(RiskLevel::Medium, &s, tenant(true)),
            AuthMode::SmsOtp
        );
    }

    #[test]
    fn medium_risk_without_clear_falls_back_to_kba() {
        let s = signer_with_rbv(true);
        assert_eq!(
            select_auth_mode(RiskLevel::Medium, &s, tenant(false)),
            AuthMode::KnowledgeBasedAuth
        );
    }

    #[test]
    fn high_risk_with_clear_uses_clear_biometric() {
        let s = signer_with_rbv(true);
        assert_eq!(
            select_auth_mode(RiskLevel::High, &s, tenant(true)),
            AuthMode::ClearBiometric
        );
    }

    #[test]
    fn high_risk_without_clear_downgrades_to_kba() {
        let s = signer_with_rbv(true);
        assert_eq!(
            select_auth_mode(RiskLevel::High, &s, tenant(false)),
            AuthMode::KnowledgeBasedAuth
        );
    }

    #[test]
    fn docusign_id_check_names_match_docusign_recipient_field_values() {
        // These string values are what Docusign's REST API
        // recipient.idCheckConfigurationName field accepts. They are
        // tenant-scoped — each tenant defines its own ID check
        // configurations under those names. The bootstrap CLI's
        // operator-runbook (OPERATIONS.md) lists the names a tenant
        // should configure to match these strings.
        assert_eq!(AuthMode::EmailLink.docusign_id_check_name(), "");
        assert_eq!(AuthMode::SmsOtp.docusign_id_check_name(), "SMS Auth $");
        assert_eq!(
            AuthMode::KnowledgeBasedAuth.docusign_id_check_name(),
            "ID Check $"
        );
        assert_eq!(
            AuthMode::ClearBiometric.docusign_id_check_name(),
            "CLEAR Identity Verification"
        );
    }

    #[test]
    fn is_multi_factor_excludes_only_email_link() {
        assert!(!AuthMode::EmailLink.is_multi_factor());
        assert!(AuthMode::SmsOtp.is_multi_factor());
        assert!(AuthMode::KnowledgeBasedAuth.is_multi_factor());
        assert!(AuthMode::ClearBiometric.is_multi_factor());
    }

    #[test]
    fn requires_clear_only_for_clear_biometric() {
        assert!(!AuthMode::EmailLink.requires_clear());
        assert!(!AuthMode::SmsOtp.requires_clear());
        assert!(!AuthMode::KnowledgeBasedAuth.requires_clear());
        assert!(AuthMode::ClearBiometric.requires_clear());
    }
}
