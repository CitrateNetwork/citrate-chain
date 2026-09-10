---
name: PIL-49d
description: Replace jsonrpc-http-server v18 with jsonrpsee for the RPC face
created: 2026-05-31
branch: main
author: saulbuilds (Larry Klosowski)
status: deferred-post-audit
---

# PIL-49d — Migrate from `jsonrpc-http-server` v18 to `jsonrpsee`

## Status

**Deferred until after the in-flight audit.** Not in tonight's freeze
sweep. This doc captures the case for it so whoever picks it up post-
audit doesn't have to re-derive the motivation or re-discover the
pitfalls.

## Why

`jsonrpc-http-server` v18 is unmaintained upstream. The crate landed
its last release in late 2021 and the upstream `paritytech/jsonrpc`
repository was archived in favour of `jsonrpsee`. Every active
ecosystem RPC client today is built against modern async Rust — our
continued reliance on the v0.18-era sync-worker-pool model is a
ticking sustainability debt.

Tonight's PIL-49 fixed the *symptom* (the deadlock between
`futures::executor::block_on` and `tokio::sync::*`-using async paths)
by routing all `block_on` calls through a shared multi-threaded Tokio
runtime. That stops the public RPC from going silent under chatbot
bursts, and it's the right interim fix. But the underlying
architectural mismatch — sync RPC handlers driving async code via
`block_on` — survives. Every new RPC method an author adds is one
more place where someone might reach for the wrong `block_on`
helper, or introduce a new tokio primitive that doesn't wake under
the wrong executor, or pile work onto a worker that's still doing a
synchronous `block_on`. `jsonrpsee` makes handlers natively async,
which removes the failure mode structurally.

## Scope

Replace the API-crate's HTTP and WebSocket servers with `jsonrpsee`:

- `core/api/src/server.rs` — replace `jsonrpc_core::IoHandler` +
  `jsonrpc_http_server::ServerBuilder` with `jsonrpsee::server::ServerBuilder`.
- `core/api/src/eth_rpc.rs`, `ai_rpc.rs`, `economics_rpc.rs`,
  `eth_rpc_simple.rs` — every `io_handler.add_sync_method(...)` call
  becomes an `RpcModule::register_async_method` call; every
  `block_on(api.some_fn())` becomes `api.some_fn().await`.
- `core/api/src/rpc_runtime.rs` — delete. No longer needed once the
  handlers are natively async.
- `core/api/src/metrics.rs::spawn_accept_queue_sampler` — keep (still
  useful as a deadlock canary even with async handlers).
- `node/src/main.rs` — replace the `RpcServer::spawn()` call with the
  jsonrpsee equivalent. The CloseHandle/JoinHandle return surface
  changes; main loop's shutdown wiring needs to follow.
- `core/api/src/websocket.rs` and `core/api/src/eth_subscriptions.rs`
  — both already use bare `tokio::net::TcpListener` + custom WS
  framing. Replace with `jsonrpsee::server::ServerBuilder` + its
  subscription machinery so the eth_subscribe surface stays Ethereum-
  spec compliant.

## Non-scope

- The contract layer doesn't change.
- The executor, mempool, storage layers don't change.
- The PIL-12 EthSubscriptionServer wire format stays the same — only
  the underlying transport implementation moves.

## Acceptance criteria

| | |
|---|---|
| `cargo build --release -p citrate-api` clean | — |
| All 82 existing api unit tests still pass | — |
| `/v1/chat/completions` from the chatbot still returns successful completions | — |
| 200 concurrent `eth_call` burst returns 200/200 with no RecvQ growth | — |
| `citrate_subscribe newHeads` + `eth_subscribe newHeads` (PIL-12 path) deliver block events with no regression | — |
| `rpc_runtime` module deletable without dangling imports | — |

## Risk

The migration touches every RPC method in the api crate. The unit-
test coverage for individual methods is uneven, so a "tests pass +
chat works" check isn't a strong-enough acceptance gate alone. A
staged plan:

1. Land an unmounted `core/api/src/server_v2.rs` jsonrpsee module
   alongside the existing one.
2. Plumb a CLI flag (`--rpc-server=jsonrpsee|v18`) so we can A/B at
   the node level without touching the wire format.
3. Run the chatbot + Foundry test suite + 64-concurrent burst
   against `jsonrpsee` for a week on testnet-beta.
4. Flip the default. Keep `--rpc-server=v18` as a one-release
   rollback escape hatch.
5. Delete `server.rs` (old) + `rpc_runtime.rs` next release.

## Related

- [[PIL-49]] — the deadlock root cause this migration would
  structurally prevent.
- [[PIL-49b]] — the spawn-thread workaround collapse, now landed.
- [[PIL-49c]] — the accept-queue depth gauge, now landed. Keep across
  the migration; useful as a regression canary.
