# core/security/

Security infrastructure scaffolding for the Citrate node.

## Files

### mod.rs

Defines the `SecurityMonitor` struct with three subsystems:
- `DosProtection` -- denial-of-service mitigation
- `RateLimiter` -- request rate limiting
- `AnomalyDetector` -- anomalous behavior detection

These are currently empty structs (scaffolding from Sprint 10) awaiting
implementation. See the threat model at `docs/technical/threat-model.md`
for the security requirements these will address.
