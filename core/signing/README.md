# citrate-signing

Provider-abstracted electronic-signature service for the Citrate IT-Turnkey
bootstrap. The default backend is **Docusign + CLEAR Risk-Based Verification**;
the trait surface is provider-agnostic so HelloSign / PandaDoc / DocuFirst
could be added as peer modules in the future.

This crate is consumed by `cli-school-bootstrap` (the bootstrap CLI) at
each compliance gate; see `02_SIGNING_AND_KYC_ARCHITECTURE.md` in the
planset for the architecture.

## Status

**Scaffold landed in IT-TURNKEY-CODA WP-B1 (2026-05-04).** Trait + types +
webhook parser + HMAC verification are production-ready and unit-tested.
Live REST calls (`create_and_send_envelope`, `get_envelope`,
`download_signed_document`) are intentional placeholders that error with
"lands in WP-B[2-4]" — the full payload bodies and request/response
serialization land alongside legal-template counsel review (WP-B2) and the
encrypted-at-rest storage layer (WP-B3).

## Reuse from existing crates

- `agent-core::adapters::HermesAdapter` (struct + builder pattern, optional
  crypto gate via `with_signing_key`) — pattern this crate's
  `SigningProvider` trait shape mirrors.
- `gui/citrate_edu_app::encryption::OrgEncryption` — Argon2id + AES-256-GCM
  used for storing signed PDFs at rest. Wired from the bootstrap CLI in
  WP-B3, not from this crate directly.

## Configuration

In production, `DocusignProvider::new` takes a `DocusignConfig` constructed
from environment variables:

```bash
DOCUSIGN_BASE_URL=https://www.docusign.net/restapi   # or demo.docusign.net for sandbox
DOCUSIGN_ACCOUNT_ID=<account-uuid>
DOCUSIGN_ACCESS_TOKEN=<oauth-jwt-bearer>
DOCUSIGN_WEBHOOK_SECRET=<configured-in-tenant>
DOCUSIGN_CLEAR_RBV_ENABLED=true   # optional; downgrades High → Medium when false
```

`from_env()` hard-fails if a required var is missing — defaulting silently
on security configuration would be a bug.

## Tests

`cargo test -p citrate-signing` runs the provider unit tests:

- HMAC webhook signature accepts valid signatures
- HMAC webhook signature rejects wrong secret, tampered body, malformed hex
- Effective risk level downgrades High → Medium when CLEAR RBV is disabled
- Docusign webhook payload parser handles Completed / Declined / unknown / malformed JSON
