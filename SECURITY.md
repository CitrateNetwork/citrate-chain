# Security Policy — citrate-chain

`citrate-chain` is a **Tier-1** repository in the Citrate federation. This file
*augments* (does not replace) the organization-wide policy at
[`CitrateNetwork/.github/SECURITY.md`](https://github.com/CitrateNetwork/.github/blob/main/SECURITY.md).

## Reporting a vulnerability

- **Preferred:** GitHub private vulnerability reporting on this repository
  (Security tab, "Report a vulnerability").
- **Email:** security@citrate.ai. Do **not** open a public GitHub issue.
- **Acknowledgement:** within 72 hours.
- **Coordinated-disclosure window:** 90 days.
- When reporting, identify the **commit SHA** and the affected crate
  (`core/consensus`, `core/network`, `core/bridge`, `core/api`, …).
- Bounty policy: coming soon (see the org `SECURITY.md`).

## Scope

In scope: the L1 node and its crates — consensus (GhostDAG, finality,
checkpoints), sequencer/mempool, execution (LVM/EVM, precompiles), storage,
network (P2P transport, gossip, sync), the JSON-RPC + MCP API surface,
economics, the SALT bridge crate (code review only: the bridge is specified,
not deployed), and the wallet crates in this workspace.

Product status (see `verification/claims.json`): checkpoint finality is
specified, not running, so confirmation is probabilistic; the testnet has a
single block producer and stake-gated proposer eligibility is off by default;
19 governance and cooperative address-book entries have no code on chain 40204.

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

## Defensive posture (current practice)

- CI workflows in `.github/workflows/`: `cargo audit` + `cargo deny`
  (advisory/license/banned-dep), clippy, a Semgrep regression-rule pass over
  `tools/semgrep/rules/`, a nightly fuzz matrix over `fuzz/fuzz_targets/`, and
  `claims-truth` (public claims vs code). Hardening of branch protection and
  required checks is in progress.
- `overflow-checks = true` on the release profile.
- Per-finding remediation trail under `audits/`.

## Supply chain

The release workflow is built to cosign-sign (keyless OIDC) and attach
CycloneDX SBOMs. Signed public releases are in progress; treat current
prereleases as unsigned. Verification commands for signed artifacts, once
published, are in the org-level
[`.github/SECURITY.md`](https://github.com/CitrateNetwork/.github/blob/main/SECURITY.md).

---

© 2026 Citrate Inc..
