---
created: 2026-09-06T00:00:00Z
branch: prep/rm-q-chain-nonconsensus
author: Codex
status: active
---

# CRY-H4 MCP commitment-proof retirement tripwire

## Finding

The default MCP `ExecutionVerifier` accepted `SHA3(statement || response)` as a
ZK execution proof. Both statement and response were caller-controlled, so the
check provided no proof of model execution.

## Red-first reproduction

On parent commit `f88a52c`, a test built a complete `ExecutionProof` with correct
model/input/output hashes and IO commitment, then supplied an attacker-selected
statement and matching SHA3 commitment. The old verifier returned `true`:

```text
assertion failed: left == right
left: true
right: false
test result: FAILED. 0 passed; 1 failed
```

## Green verification

Default MCP verification now returns `false` until a real ZK verifier is enabled;
the legacy commitment verifier is test-only. The proof-generation path also
returns an explicit unavailable error instead of emitting a fake proof artifact.

```text
cargo test --locked -p citrate-mcp --tests
```

Result: MCP library 92/92, coverage 74/74, coverage-gap 37/37, CRY-H4 1/1,
gradient 18/18, Groth16 integration 14/14, inference routing 7/7, and model
discovery 8/8 passed.

The separately gated Groth16 path remains subject to CRY-H3’s circuit/VK review;
this closure covers the default forgeable commitment path only.
