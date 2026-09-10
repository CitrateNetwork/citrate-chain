---
created: 2026-09-06T00:00:00Z
branch: prep/rm-q-chain-nonconsensus
author: Codex
status: active
---

# CRY-H2 legacy 0x0104 retirement tripwire

## Finding

`CRY-H2` identified the legacy `0x0104` inference proof route as a forgeable
commitment check: a caller could choose `model_id`, statement, response, and a
Keccak commitment, with no inference proof or model binding.

## Red-first reproduction

On parent commit `f88a52c`, a test supplied an attacker-controlled statement and
response with the matching Keccak commitment to `InferencePrecompile::execute`
at `0x0104`. The old route returned success, so the retirement assertion failed:

```text
test cry_h2_legacy_0104_proof_route_is_disabled ... FAILED
retired 0x0104 must not accept a caller-forgeable commitment as an inference proof
test result: FAILED. 0 passed; 1 failed
```

## Green verification

The route now returns a deterministic retirement error and points callers to the
real `0x0108` verifier. The legacy helper remains only for compatibility tests and
is not reachable through dispatch.

```text
test cry_h2_legacy_0104_proof_route_is_disabled ... ok
test result: ok. 1 passed; 0 failed
```

Affected regression suites:

```text
ai_opcode_e2e: 53 passed; 0 failed
ai_opcode_validation: 20 passed; 0 failed
```

This is held for the coordinated reroll because the address behavior changes for
any callers still using the legacy route. Existing contract paths already target
`0x0108`; no deployment was performed.
