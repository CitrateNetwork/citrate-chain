---
created: 2026-05-05T00:00:00Z
sprint: IT-TURNKEY-CODA (WP-B7)
status: active
audience: Citrate ops + district IT
---

# `citrate-signing` Operations Runbook

How the operator stands up + maintains the Docusign tenant + CLEAR
Risk-Based Verification integration that the bootstrap CLI's
envelope-dispatch path (WP-B6) depends on.

## TL;DR — minimum bootstrap

```bash
# 1. Procure a Docusign Education tier account.
# 2. In the Docusign admin console: enable CLEAR Risk-Based Verification.
# 3. Create a Connect (webhook) endpoint pointing at the bootstrap
#    daemon's listener (default https://bootstrap.<district>.example/webhooks/docusign).
# 4. Generate a JWT app token for the bootstrap CLI.
# 5. Set the env vars below + start the bootstrap daemon.
```

## Tenant procurement (one-time)

### Docusign Education

1. Visit `https://www.docusign.com/products/docusign-for-education`.
2. Request the Education tier (district-managed). Pricing is per-seat
   for staff signers; student signers are free.
3. Determine tenant model per Larry's locked decision #6 (hybrid):
   - **Citrate-operated tenant**: Citrate sales contracts with Docusign
     and bundles per-district seats. District signs as a Citrate sub-tenant.
     Simpler for districts that don't already have Docusign.
   - **Per-district tenant**: District procures their own Docusign
     account. Familiar to districts already on Docusign for FERPA
     student-record signing. Requires the district to pay Docusign
     directly + register the bootstrap CLI as an API integration.
4. Note the **account_id** (UUID) — the bootstrap CLI's
   `DOCUSIGN_ACCOUNT_ID` env var.

### CLEAR Risk-Based Verification (RBV)

CLEAR for ID-verified signing is enabled inside Docusign, not as a
standalone CLEAR partnership. Steps:

1. In the Docusign admin console: **Admin → Identity Verification**.
2. Enable **CLEAR Risk-Based Verification**. Pricing is per-verification.
3. Configure the risk-tier mapping if Docusign provides it (varies by
   tier and account); the bootstrap CLI sends `RiskLevel::High` for
   DPA + COPPA Institutional Consent + standalone DPA, `Medium` for
   board resolutions + state addenda, `Low` for AUPs.
4. If CLEAR RBV is *not* enabled on the tenant, the bootstrap CLI's
   `DocusignProvider::effective_risk_level()` function downgrades
   `High` → `Medium` (KBA-only) automatically with a `tracing::warn!`.
   The bootstrap continues; the operator sees the warning in the
   daemon's logs.

## Connect (webhook) endpoint

Docusign Connect calls back to the bootstrap daemon when an envelope's
status changes. The daemon receives at `POST /webhooks/docusign`.

### Production endpoint (HTTPS required)

Docusign Connect requires HTTPS in production. The daemon itself
serves plain HTTP on `127.0.0.1:8091` by default — front it with a
reverse proxy (nginx, Caddy, Vercel) that terminates TLS + forwards
to the daemon.

Example Caddy config:

```
bootstrap.lincolnsd.k12.ca.us {
    reverse_proxy 127.0.0.1:8091
    tls admin@lincolnsd.k12.ca.us
}
```

In the Docusign admin console: **Admin → Integrations → Connect →
Add Configuration**:

- **URL to publish to**: `https://bootstrap.<district>.example/webhooks/docusign`
- **HMAC signature key**: generate a random 32-byte secret; copy into
  the `DOCUSIGN_WEBHOOK_SECRET` env var on the daemon
- **Events**: subscribe to `Envelope: Sent`, `Delivered`, `Completed`,
  `Declined`, `Voided`. Skip `Created` and per-recipient events
  (the daemon only acts on terminal envelope statuses).
- **Retries**: leave at default (4 retries with exponential backoff;
  the daemon is idempotent on Docusign retries — see WP-A4 daemon tests).

### Sandbox / lab endpoint

For local testing without Docusign Connect (which requires HTTPS):

- Use Docusign's **demo.docusign.net** API endpoint
  (`DOCUSIGN_BASE_URL=https://demo.docusign.net/restapi`).
- Connect can be configured to call back to a development reverse
  proxy (e.g. `ngrok http 8091`) — Docusign's demo tier accepts the
  ngrok HTTPS endpoint.
- The daemon's webhook signature verification works identically in
  sandbox + production; ensure `DOCUSIGN_WEBHOOK_SECRET` matches the
  HMAC key configured on the demo Connect endpoint.

## App token (JWT bearer for the REST API)

The bootstrap CLI calls Docusign REST API endpoints via OAuth 2.0 JWT
bearer flow.

### One-time setup

1. In Docusign: **Admin → Apps and Keys → Add an App**.
2. Generate an RSA keypair (Docusign provides the public key download;
   the operator keeps the private key in the district key vault — same
   custody model as the district signing key for profile packs).
3. Note the **Integration Key** (Docusign assigns this).
4. Configure scopes: `signature impersonation` minimum.

### Acquiring a token

The bootstrap CLI does this at run time. Cron or systemd timer should
refresh the token before its expiry (typically 1h).

```bash
# Pseudocode — actual JWT minting handled by the bootstrap CLI's
# auth path (lands in CODA-B2 alongside live envelope creation).
JWT="$(citrate-school-bootstrap docusign-mint-jwt \
        --integration-key <key> \
        --user-id <user> \
        --private-key /path/to/key.pem)"
export DOCUSIGN_ACCESS_TOKEN="$JWT"
```

For sandbox: use a long-lived demo token from
`https://account-d.docusign.com/oauth/token` — the bootstrap CLI's
sandbox-mode tests do not require JWT minting.

## Environment variables

Set on the daemon's environment (e.g. `/etc/citrate-school-bootstrap/env`
sourced by systemd):

| Variable | Required | Purpose |
|----------|----------|---------|
| `DOCUSIGN_BASE_URL` | yes | `https://www.docusign.net/restapi` (prod) or `https://demo.docusign.net/restapi` (sandbox) |
| `DOCUSIGN_ACCOUNT_ID` | yes | Account GUID from the Docusign admin console |
| `DOCUSIGN_ACCESS_TOKEN` | yes | OAuth 2.0 JWT bearer — refreshed periodically |
| `DOCUSIGN_WEBHOOK_SECRET` | yes | HMAC signing key — matches Connect endpoint config |
| `DOCUSIGN_CLEAR_RBV_ENABLED` | **required** (`true`/`false`) | `true` if CLEAR RBV is enabled on this tenant; `false` downgrades High → Medium. CHAIN-B-D022: hard-fails if unset — no silent default. |

`DocusignConfig::from_env()` hard-fails if any required var is missing.
This is intentional — silently defaulting on security configuration
would be a bug. Operators see `Config("DOCUSIGN_ACCOUNT_ID not set")`
on first daemon start if they missed a step.

## Webhook secret rotation

Rotate the HMAC webhook secret quarterly (or immediately on any
suspected compromise). Procedure:

1. Generate a new random 32-byte secret (`openssl rand -hex 32`).
2. In the Docusign admin console: update the Connect endpoint's HMAC key
   to the new value. (Docusign signs new callbacks with the new key
   from the moment you save.)
3. Update `DOCUSIGN_WEBHOOK_SECRET` on the daemon's environment.
4. Restart the daemon. Any callbacks sent after step 2 but before step 4
   verify against the new key on retry; the daemon returns 401 + Docusign
   retries.
5. Verify in the daemon's logs that callbacks resume verifying.

## App-token rotation

If the JWT-signing private key is compromised:

1. In Docusign: revoke the integration key + generate a new keypair.
2. Update the bootstrap CLI's JWT-mint config to use the new private key.
3. Restart the daemon.

If the access token leaks but the private key is intact, the leaked
token expires within 1h and is unusable thereafter. Refreshing the
daemon issues a new token from the unchanged private key.

## Tenant pricing model (for budget planning)

- **Docusign Education**: ~$24-50 per staff seat per month.
- **CLEAR RBV**: per-verification cost (Docusign quotes; varies by
  tier). Estimate ~$3-8 per High-risk-signed envelope.
- **Sandbox**: free.

For the hybrid tenant model: districts on the Citrate-operated tenant
see the costs bundled into Citrate's pricing. Districts on per-district
tenants pay Docusign directly + Citrate charges nothing for signing.

## Template version bump

Counsel-approved templates live at `.agentile/legal/templates/v1/`.
When counsel approves an updated set:

1. Counsel produces v2 in `.agentile/legal/templates/v2/`.
2. Update each template's frontmatter `status:` to
   `counsel-approved-v2`.
3. Engineering's CI verifies status before any production envelope dispatch.
4. The bootstrap CLI accepts a `--templates-version v2` flag; default is
   the latest counsel-approved version.
5. Districts that signed under v1 are NOT auto-upgraded — counsel
   proposes the migration path (re-sign vs grandfather).

## Incident response

| Incident | Response |
|----------|---------|
| Webhook callback fails verification (401) | Confirm `DOCUSIGN_WEBHOOK_SECRET` matches the Connect endpoint's HMAC key. Restart the daemon. Docusign auto-retries. |
| Webhook delivers but bootstrap state isn't advancing | Check daemon logs for `BootstrapEventSink` errors. Confirm the envelope_id is in `state.in_flight` (a Docusign envelope sent out-of-band by an operator is intentionally a no-op per WP-A4). |
| Signer reports they can't complete CLEAR | Confirm CLEAR RBV is enabled on the tenant. If the user's CLEAR account doesn't exist, they can create one inside the Docusign signing flow (per the partnership UX). |
| District signing key compromised | Treat as a re-bootstrap: generate a new district key, re-issue every profile pack (WP-A9), reissue the deployment bundle (WP-A6) signed by the new key. The previous deployment continues to work for already-installed devices until they receive the new bundle. |
| Bootstrap state corrupted on disk | Restore from backup. The atomic `save_state` (write-to-tmp + fsync + rename in WP-A3) prevents partial writes; corruption indicates filesystem-level damage. |

## Logging + observability

The daemon uses `tracing` with an env-filter from `RUST_LOG`. Recommended
production setting:

```
RUST_LOG=info,citrate_signing=debug,citrate_school_bootstrap=debug
```

Log to a structured sink (jsonl) for ops dashboards. Sensitive values
(`DOCUSIGN_ACCESS_TOKEN`, `DOCUSIGN_WEBHOOK_SECRET`) are not logged
under any log level — verified by the security tests in WP-B1's
`docusign.rs` (the `verify_webhook_signature` constant-time MAC compare
+ `effective_risk_level` warning paths).

## Reference

- Docusign Education tier: https://www.docusign.com/products/docusign-for-education
- Docusign + CLEAR integration: https://www.docusign.com/integrations/id-verification-with-clear
- Docusign Connect retry policy: https://developers.docusign.com/platform/webhooks/connect/
- bootstrap CLI architecture: `.agentile/planset/2026-05-04-it-turnkey-deployment/02_SIGNING_AND_KYC_ARCHITECTURE.md`
