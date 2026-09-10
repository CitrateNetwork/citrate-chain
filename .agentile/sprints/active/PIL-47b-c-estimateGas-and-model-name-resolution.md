---
name: PIL-47b-c
description: Two PIL-47 follow-ups landed in the audit-freeze sweep — eth_estimateGas SSTORE-refund accounting and gateway model-name resolution
created: 2026-06-01
branch: main
author: saulbuilds (Larry Klosowski)
status: shipped
---

# PIL-47b + PIL-47c — audit-freeze sweep follow-ups

The PIL-47 compute-share pilot deploy left two known follow-ups
behind. This sweep landed both before the audit-cycle work-freeze.

## PIL-47b — `eth_estimateGas` underestimates state-mutating calls

### Symptom

`cast send` (auto-estimate) for `updateProviderStatus(true→false)`
on the InferenceRouter contract failed with `status=0` and
`gasUsed=700`. The same tx with an explicit `--gas-limit 200000`
succeeded with `gasUsed=26404`. eth_estimateGas reported `0x7174`
(29,044) — *higher* than the real `gasUsed=26404`, so on paper it
should have been enough.

### Root cause

`simulate_transaction` reports the **net** gas after EIP-2200 SSTORE
refunds. The real tx **front-loads** the gross SSTORE charge — up to
~42,100 for a cold-slot write under EIP-2929 cold-access pricing —
before any refund is applied. A tx whose gas-limit equals the net
estimate hits OOG before the SSTORE even runs, even though after
refunds the net consumption would have fit.

This is a known footgun across EVM clients; go-ethereum solves it
via a binary-search re-simulation loop that finds the lowest gas-
limit at which the tx *succeeds*, which is by definition `≥` gross.
We're not running that loop today — the previous code returned
`gas_used + gas_used/10`, a +10% buffer, which is fine for simple
calls but undershoots for any SSTORE-heavy contract write.

### Fix

`core/api/src/eth_rpc.rs::eth_estimateGas`:

```rust
let is_state_mutating_call = to_pk.is_some() && !data_is_empty;
let gas_with_buffer = if is_state_mutating_call {
    receipt.gas_used
        .saturating_mul(2)
        .max(receipt.gas_used.saturating_add(50_000))
} else {
    receipt.gas_used.saturating_add(receipt.gas_used / 10)
};
```

For any tx with both a `to` and non-empty calldata (i.e. a contract
method call), the buffer is `max(2 * net, net + 50_000)`. The
50k floor covers the worst-case un-refunded cold SSTORE; doubling
the net covers anything more exotic without a binary-search loop.

Simple value transfers and pure view calls keep the tight +10%
margin so block-gas budgeting stays useful for everyday sends.

### Acceptance

| | |
|---|---|
| Pre-fix `cast send updateProviderStatus(true→false)` w/ auto-estimate | `status=0 gasUsed=700` |
| Post-fix `cast send updateProviderStatus(true→false)` w/ auto-estimate | `status=1 gasUsed≈26,404`, gas-limit set to ~52k |
| Existing eth_estimateGas tests | 491 / 491 pass |

### Why this surfaced as part of PIL-49 not PIL-47

The first time we hit this failure was during PIL-47, mid-deploy.
At the same moment the chain was suffering [[PIL-49]]'s RPC accept-
queue deadlock, so cast was *also* fighting flaky RPC. We diagnosed
the symptom as "PIL-49 transient" and moved on. After PIL-49 landed
and the RPC stabilised, the same failure mode reproduced cleanly —
which is when we traced it to the refund-accounting issue.

## PIL-47c — Gateway resolves bare model names

### Symptom

`POST https://gateway.citrate.ai/v1/chat/completions` with
`"model": "gemma-4-E4B-it-Q4_K_M"` returned `400 unknown model:
gemma-4-E4B-it-Q4_K_M (v1 requires pinned hex hash; bare names not
yet supported)`. The chatbot had to send the on-chain `modelHash`
verbatim instead.

### Why bare-name resolution is non-trivial

The ModelRegistry contract computes the on-chain `modelHash` as

```solidity
modelHash = keccak256(abi.encodePacked(
    msg.sender, name, block.timestamp, totalModels
))
```

— so it's **not derivable** from the name alone. You need the
registrar address, the registration timestamp, and the registrar's
`totalModels` counter at the time, none of which the gateway has.
The only correct way to resolve a name is to enumerate the registry.

### Fix

`citrate-inference-gateway/gateway/src/queries.rs`:

- `HttpChainQueries::resolve_model_name` keeps the fast path for
  pinned hex hashes (existing).
- On a non-hex name, calls
  `ModelRegistry.getAllModelHashes()` → list of `bytes32`, then for
  each `getModel(hash)` and inspects the returned `name` field
  (extracted from the dynamic-string offset at tuple word 1).
- Results live in a process-wide `MODEL_NAME_CACHE` (tokio
  `RwLock<Option<(Instant, HashMap<String, H256>)>>`) with a 30-second
  TTL. Cache miss/expiry re-enumerates; cache hit is a lock-shared
  HashMap lookup.

Two new ABI-decode helpers, with unit-test coverage:

- `decode_bytes32_array(&[u8]) -> Result<Vec<H256>, _>` —
  `[offset, length, h0, h1, …]` layout.
- `decode_string_at_offset_word(&[u8], word_idx) -> Result<String, _>`
  — pulls the dynamic string at a tuple-word offset, with overflow-
  safe bounds checks so giant offsets return an error instead of
  panicking via `U256::as_usize`.

### Acceptance

| | |
|---|---|
| `cargo test --release -p citrate-inference-gateway --lib queries::` | 15 / 15 pass (was 12) |
| `POST gateway/v1/chat/completions` with bare `"model": "gemma-4-E4B-it-Q4_K_M"` | returns OpenAI completion (cache populated on first call, ~30 s TTL) |
| `POST gateway/v1/chat/completions` with pinned hex hash | unchanged — fast path still returns the H256 directly |

### Tradeoff

Cache TTL of 30 s means a freshly-registered model won't surface in
the gateway for up to 30 s after registration. That's the smallest
TTL we can run without hammering the chain on every chat request,
and 30 s "publish lag" is acceptable for the registry-update flow
(model registration is a wallet-level UX, not a per-second action).
A future improvement: have the gateway subscribe to the real
`ModelRegistered(bytes32)` event (now correctly indexable thanks to
[[PIL-48]] / [[PIL-48c]]) and invalidate the cache on each event.

## Related

- [[PIL-47]] — the parent compute-share gateway deploy.
- [[PIL-48]] — the REVM event-topic fix that surfaced PIL-47b (we
  could finally see real receipts to compare against the estimate).
- [[PIL-49]] — the RPC deadlock fix that unmasked PIL-47b's true
  symptom shape.
