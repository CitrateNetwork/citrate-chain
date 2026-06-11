# Security Policy — citrate-chain

`citrate-chain` is a **Tier-1** repository in the Citrate federation. This file
*augments* (does not replace) the organization-wide policy at
[`CitrateNetwork/.github/SECURITY.md`](https://github.com/CitrateNetwork/.github/blob/main/SECURITY.md).

## Reporting a vulnerability

- **Email:** security@citrate.ai — do **not** open a public GitHub issue.
- **Acknowledgement:** within 72 hours.
- **Coordinated-disclosure window:** 90 days.
- When reporting, identify the **commit SHA** and the affected crate
  (`core/consensus`, `core/network`, `core/bridge`, `core/api`, …).

## Scope

In scope: the L1 node and its crates — consensus (GhostDAG, finality,
checkpoints), sequencer/mempool, execution (LVM/EVM, precompiles), storage,
network (P2P transport, gossip, sync), the JSON-RPC + MCP API surface, the
SALT bridge, economics, and the wallet crates in this workspace.

Out of scope here (report against their own repos): the explorer, gateway,
node-agent, district-registration, SDKs, and other sibling repos.

## What we consider a vulnerability

Consensus safety/liveness (chain halt, reorg manipulation, finality violation),
remote DoS of a node, fund-loss or mint/withdrawal integrity in the bridge,
authentication/authorization bypass on the RPC surface, key-material exposure,
and signature/transaction malleability. The pre-audit threat model and the
remediation evidence for the 2026-06-09 readiness review live under
`audits/2026-06-09-SECREM-01-remediation-log.md`.

## Severity & audit tier

Severity tiers and audit cadence are in [`AUDIT_TIER.md`](AUDIT_TIER.md).
`citrate-chain` is pre-external-audit; a stable tag is gated on a named-firm
audit attestation per `AUDIT_TIER.md`.

## Defensive posture (verifiable)

- CI gates (restored 2026-06-09): `cargo audit` + `cargo deny` (advisory/license/
  banned-dep), clippy `-D warnings`, a Semgrep regression-rule pass over
  `tools/semgrep/rules/`, and a nightly fuzz matrix across all
  `fuzz/fuzz_targets/`.
- `overflow-checks = true` on the release profile.
- Releases are cosign-signed (keyless OIDC) with CycloneDX SBOMs.
- Per-finding remediation trail under `audits/`.

## Supply chain

Rust crates published from this repo are cosign-signed; SBOMs attach to every
Tier-1 release. Verification commands are in the org-level
[`.github/SECURITY.md`](https://github.com/CitrateNetwork/.github/blob/main/SECURITY.md).

---

© 2026 Mozi Cooperative.
