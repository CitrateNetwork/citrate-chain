---
name: PIL-48
description: Restore real keccak256 event topics on REVM-emitted logs (was hardcoded ASCII)
created: 2026-05-31
branch: main
author: saulbuilds (Larry Klosowski)
status: shipped
---

# PIL-48 — REVM log topics: stop replacing real event hashes with synthetic ASCII

## Symptom

`eth_getLogs` against `InferenceRouter.registerProvider()` (and every other
contract execution since the chain went live) returns a single log whose
topic decodes to literal ASCII text:

```
topic[0] = 0x436f6e7472616374457865637574656430303030303030303030303030303030
         = "ContractExecuted00000000000000000000"  (32-byte ASCII string)
```

Tools that filter by the real keccak256 of an event signature
— `cast logs`, Foundry test assertions on events, The Graph, any
off-chain subscriber — silently see **nothing**, because no real event
in any contract was ever going to hash to that ASCII string.

Discovered during PIL-2 (compute-share POC): tried to verify the
`ProviderRegistered(address indexed, uint256)` event after a real
`registerProvider()` tx landed; on-chain state was correct, but
`cast logs --address $InferenceRouter $topicProviderRegistered` came back
empty. Diagnosis: pull the raw `eth_getLogs` via curl, see the synthetic
topic, grep the codebase for the literal ASCII string.

## Scope

| Affected | Notes |
|---|---|
| Every contract call going through `execute_contract_call_with_context` | All real Solidity events discarded; one synthetic per call. |
| Every contract creation going through `execute_contract_create_with_context` | Constructor events (e.g. OZ `Initialized()`) discarded; one synthetic per deploy. |
| Native value transfers in `journal_transfer` | One synthetic `"Transfer0000…"` log per transfer. *Not in this fix's blast radius — see follow-ups.* |
| Model-registry precompile in `execute_register_model` | One synthetic `"ModelRegistered0000…"` log. *Precompile path — separate fix needed for correct hash.* |

## Root cause

`core/execution/src/revm_adapter.rs` calls `revm.transact_commit()`, which
returns `ExecutionResult::Success { output, gas_used, logs, .. }`. The
existing code destructured **only `output, gas_used`** and discarded
`logs` via `..`.

Up in `core/execution/src/executor.rs`, the call-site then constructed a
single hand-rolled `Log` with `Hash::new(*b"ContractExecuted0000…")` as
the topic — a 32-byte ASCII literal — and attached it to the receipt.

So every real `LOG0/LOG1/.../LOG4` opcode from contract bytecode was
thrown away at the revm-adapter boundary, and every receipt got the
same fake "I ran a contract" marker instead.

## Fix

**`core/execution/src/revm_adapter.rs`**
- Add `RevmLog` import + `CitrateLog` re-name + `Hash` import.
- New helper `convert_revm_log(&RevmLog) -> CitrateLog` that maps
  alloy `Address`/`B256`/`Bytes` → citrate `Address`/`Hash`/`Vec<u8>`.
- Change return types:
  - `execute_contract_create_with_context` → `Result<(Address, Vec<u8>, u64, Vec<CitrateLog>), _>`
  - `execute_contract_call_with_context`   → `Result<(Vec<u8>, u64, Vec<CitrateLog>), _>`
- In each `Success` arm, also destructure `logs` and run the converter.
- Update legacy non-context wrappers (`execute_contract_create`,
  `execute_contract_call`) to discard the new `Vec<CitrateLog>` via
  `.map(|(…, _logs)| (…))`, preserving their existing return signature
  for tests + bench paths.

**`core/execution/src/executor.rs`**
- In both call sites (`execute_contract_create_with_context` at line ~1612
  and `execute_contract_call_with_context` at line ~1745), capture the
  new `revm_logs` field from the tuple and forward each via
  `context.add_log(log)`.
- Delete the two synthetic `Hash::new(*b"ContractDeployed0…")` and
  `Hash::new(*b"ContractExecuted0…")` emissions.

## Regression test

`core/execution/src/revm_adapter.rs` adds
`test_pil48_revm_log_topics_round_trip`:

- Deploys a 39-byte runtime: `PUSH32 <topic> + PUSH1 0 + PUSH1 0 + LOG1 + STOP`.
- Picks a deterministic non-ASCII, non-hash 32-byte topic
  (`0xDEAD…BEEF` repeating).
- Calls the contract; asserts the returned `logs` vec has exactly one
  entry with `topics[0] == Hash::new(expected_topic)`.

If the synthetic-topic regression returns, this assertion fails because
no ASCII string ever equals the chosen 32-byte literal.

## Acceptance criteria

| | |
|---|---|
| `cargo build --release -p citrate-execution` | ✅ clean (28s on DGX) |
| `cargo test --release -p citrate-execution --lib` | ✅ 491 passed (was 490; +1 = PIL-48 regression) |
| Post-deploy: `cast logs` finds `ProviderRegistered(address indexed,uint256)` events emitted by InferenceRouter | ⏳ pending build + deploy |
| Post-deploy: existing `providers(addr)` state-read still returns the registered DGX provider | ⏳ pending |

## Deployment plan

The fix is **forward-only**. Historical receipts (blocks 0..N) keep
their synthetic topics; future receipts (blocks N+1..) get real ones.
Single-node testnet means no peer-consensus mismatch on the receipt
root delta.

1. rsync `citrate-chain/` source → droplet `/root/citrate-chain/`
2. `cargo build --release --bin citrate-node` on droplet (x86_64)
3. Stop `citrate-node.service`
4. Move existing binary to `/home/citrate/bin/citrate-node.pre-pil48`
5. Install new binary
6. Start `citrate-node.service`, verify block height resumes
7. Send a no-op event-emitting tx (e.g. a fresh `registerProvider` from a
   different operator key) and confirm via `cast logs` that the topic
   now matches keccak256 of the event signature

## Follow-ups

- **PIL-48b ✅ shipped** (audit-freeze sweep): synthetic `"Transfer000…"`
  log in `journal_transfer` deleted. Native value transfers now emit
  zero logs, matching Ethereum-mainnet behaviour. Indexers that filter
  on real ERC20 `Transfer(address,address,uint256)` topics now see
  exactly what they expect — the source contracts' actual events.
- **PIL-48c ✅ shipped** (audit-freeze sweep): ModelRegistry precompile
  path replaced its synthetic `"ModelRegistered000…"` topic with a real
  `keccak256("ModelRegistered(bytes32)")` const (`0xa4b0af38…dee72`).
  Precompile bypasses REVM, so this needed its own hardcoded const.
- **PIL-48d — historical-receipt note** (operator-facing, not code):
  blocks ≤ ~296,743 (pre-PIL-48 deploy) keep synthetic topics
  permanently. Off-chain indexers backfilling history have to skip
  that range or special-case the ASCII topics. Going forward (block
  ~296,744+) every receipt has real keccak256 topics.

## Related

- Discovered during [[PIL-2]] (compute-share POC). PIL-2 needed the
  `ProviderRegistered` event for the pilot demo's on-chain proof
  story; without PIL-48 fixed, the demo has to fall back to a
  state-read (`getProviders(modelHash)` returns `[dgxAddr]`).
- [[PIL-49]] (RPC accept-queue hang) is a separate bug discovered in
  the same session.
