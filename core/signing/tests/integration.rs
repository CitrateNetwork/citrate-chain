//! Integration-level smoke for `citrate-signing`. Webhook signature verification
//! end-to-end across the trait surface, plus payload-parser regression coverage.

use citrate_signing::providers::DocusignProvider;
use citrate_signing::providers::docusign::DocusignConfig;
use citrate_signing::webhook::parse_docusign_event;
use citrate_signing::{EnvelopeStatus, SigningError, SigningProvider};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn config() -> DocusignConfig {
    DocusignConfig {
        base_url: "https://demo.docusign.net/restapi".into(),
        account_id: "acct".into(),
        access_token: "token".into(),
        webhook_secret: "shhhhhhhhhhhh-this-is-a-test-secret".into(),
        clear_rbv_enabled: true,
    }
}

fn signature_for(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

#[test]
fn end_to_end_webhook_envelope_completed() {
    let cfg = config();
    let provider = DocusignProvider::new(cfg.clone());
    let body = br#"{
        "envelopeId": "envelope-abc",
        "status": "Completed",
        "statusUpdateDateTime": "2026-05-04T22:45:00Z",
        "generatedDateTime": "2026-05-04T22:45:01Z"
    }"#;
    let sig = signature_for(&cfg.webhook_secret, body);

    // Step 1: receiver verifies signature before parsing.
    provider
        .verify_webhook_signature(body, &sig)
        .expect("valid signature");

    // Step 2: receiver parses the verified payload.
    let event = parse_docusign_event(body).expect("parse");
    assert_eq!(event.envelope_id.as_str(), "envelope-abc");
    assert_eq!(event.status, EnvelopeStatus::Completed);
}

#[test]
fn webhook_rejects_replay_with_old_signature_for_new_body() {
    // Replay protection at the signature layer: a signature computed for the
    // original body must not validate against a tampered body.
    let cfg = config();
    let provider = DocusignProvider::new(cfg.clone());
    let original = br#"{"envelopeId":"a","status":"Completed","statusUpdateDateTime":"2026-05-04T22:45:00Z","generatedDateTime":"2026-05-04T22:45:01Z"}"#;
    let tampered = br#"{"envelopeId":"b","status":"Completed","statusUpdateDateTime":"2026-05-04T22:45:00Z","generatedDateTime":"2026-05-04T22:45:01Z"}"#;
    let sig = signature_for(&cfg.webhook_secret, original);
    let result = provider.verify_webhook_signature(tampered, &sig);
    assert!(matches!(result, Err(SigningError::WebhookSignatureInvalid)));
}
