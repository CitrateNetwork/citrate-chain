---
name: PIL-49
description: RPC accept-queue hangs because every block_on call deadlocked on tokio::sync wakers with no Tokio reactor in scope
created: 2026-05-31
branch: main
author: saulbuilds (Larry Klosowski)
status: shipped
---

# PIL-49 — RPC accept-queue hang under chatbot load

## Symptom

`rpc.citrate.ai` periodically goes silent for HTTP clients while the
node is plainly healthy:

- `citrate-node` consensus thread keeps producing blocks (`Produced
  block #N hash=…`) every ~2 s, height climbs as expected.
- TCP listener on `0.0.0.0:8545` is still bound (four fds — one per
  RPC worker thread on `jsonrpc-http-server`'s pool).
- `ss -tlnp 0.0.0.0:8545` shows the per-fd `RecvQ` (which on a LISTEN
  socket is the kernel's accept backlog count) climbing to **110-145**
  — the kernel keeps three-way-handshaking incoming SYNs but userspace
  never calls `accept()`.
- From outside: `curl https://rpc.citrate.ai` hangs and times out.
- Recovery: `systemctl restart citrate-node`. Brings the chain back
  fully in under 10 s.

Seen at least twice today (2026-05-31): once mid-afternoon during PIL-2
work, once again while the PIL-48 build was running.

## Root cause

`jsonrpc-http-server` v18 registers our handlers via
`IoHandler::add_sync_method`. Each call runs on a sync worker thread
out of the server's pool, and the worker reaches into our async world
via `block_on(some_async_fn)`.

`core/api/src/eth_rpc.rs`, `ai_rpc.rs`, `economics_rpc.rs`,
`eth_rpc_simple.rs`, and `server.rs` all imported
`futures::executor::block_on` for this purpose. That executor has **no
Tokio reactor**; it polls the passed future on the calling thread with
the stock waker.

But every async fn we hand it eventually awaits something that
**requires** a Tokio reactor to wake:

- `tokio::sync::Mutex` / `RwLock` in `executor.rs`, `mempool.rs`,
  `mvcc/commit.rs`, `validator.rs`, `storage/ipfs/daemon.rs`
- `tokio::time::sleep` in `mempool.rs` and `validator.rs`
- `reqwest` (which spins up its own Tokio internals) in
  `storage/ipfs/daemon.rs`

The mutex's `lock().await` registers a waker against the Tokio reactor.
Without a reactor in scope, the waker never fires — the future stays
`Pending` forever, the worker thread blocks forever, and one of the
four sync workers is permanently lost.

The pool of four (`RpcConfig::default { threads: 4 }`) is small enough
that 4-ish concurrent slow `eth_call`s — easy to hit with a chatbot
that fires Foundry-style state-read bursts — saturates it. Once all
four workers are stuck, hyper has no available worker to dispatch new
connections to, the kernel queue piles up, and the public RPC looks
dead.

The codebase had **already noticed this** at four specific call sites
(IPFS upload, MCP preview, etc.) and worked around it by spawning a
*new* OS thread + *new* `current_thread` Tokio runtime per call (see
the comments at `server.rs:101–105` and `server.rs:2262–2266`). But the
workaround was never applied to the ~30+ other call sites in
`eth_rpc.rs` / `ai_rpc.rs` / `economics_rpc.rs`, so the deadlock window
stayed open. Every new `block_on(...)` added since reopened it.

## Fix

**`core/api/src/rpc_runtime.rs` (new)**
- Single shared multi-threaded Tokio runtime (`worker_threads = 16`,
  `enable_all()`) behind a `once_cell::Lazy`.
- `pub fn block_on<F: Future>(f: F) -> F::Output` that:
  - Uses `RPC_RT.block_on(f)` if not inside a runtime (the production
    path — jsonrpc-http-server workers are plain OS threads).
  - Falls back to `tokio::task::block_in_place(|| Handle::current().block_on(f))`
    if already inside a multi-thread runtime (so `#[tokio::test]`
    callers don't trip `"Cannot start a runtime from within a runtime"`).

**Replace imports** in:
- `core/api/src/eth_rpc.rs`
- `core/api/src/ai_rpc.rs`
- `core/api/src/economics_rpc.rs`
- `core/api/src/eth_rpc_simple.rs`
- `core/api/src/server.rs` (top-level + the one bare
  `futures::executor::block_on(mempool.add_transaction(...))` line)

…from `use futures::executor::block_on;` to `use crate::rpc_runtime::block_on;`.

**`core/api/src/server.rs` — bump default worker pool**

`RpcConfig::default().threads`: 4 → **16**.

Rationale: even with the deadlock fixed, four workers is too thin a
margin against bursty Foundry / chatbot traffic. Sixteen workers still
fits the 4 vCPU droplet (much of the work is REVM/storage I/O that
yields), gives 4× the headroom, and aligns with the rpc_runtime's
worker count.

**Test update**: `test_rpc_chain_height_and_tx_submit` switches from
default `#[tokio::test]` (current_thread) to
`#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` so it
can drive the now-runtime-aware `block_on` via `block_in_place`.

## Why this is the right fix and not just a band-aid

- **Symptom-only fix would be "increase threads"** — that just delays
  the deadlock under heavier load.
- **A blanket `timeout` around every `block_on`** would free the
  worker but lose any in-flight tx submission / read — worse UX.
- The actual broken contract was "use a `block_on` that has no reactor
  for futures whose wakers register against a reactor." Replacing the
  executor is the clean answer.

## Acceptance criteria

| | |
|---|---|
| `cargo build --release -p citrate-api` | ✅ clean (32s on DGX) |
| `cargo test --release -p citrate-api --lib` | ✅ 81 passed; 2 failures pre-existing (`solc-0.8.26` arm64 mismatch, not related) |
| Post-deploy: fire 32 concurrent `eth_call` bursts; **no** RecvQ growth on `0.0.0.0:8545`; all calls return < 5 s | ✅ ran 64 concurrent — 64/64 ok, p50=2.1 s, p99=2.3 s, RecvQ stayed at 0 |
| Post-deploy: chain stays serving for ≥ 24 h under continuous chatbot traffic without restart | ⏳ pending observation |

## Verification plan (post-deploy)

1. Pre-deploy: `ss -tlnp '( sport = :8545 )'` baseline (RecvQ should be 0).
2. Deploy binary, restart `citrate-node`.
3. Fire a burst: 64 concurrent `eth_call` requests to `getProviders(modelHash)`.
4. While the burst runs, observe `ss -tlnp ... | grep 8545` — RecvQ stays at 0 (or briefly spikes but drains).
5. Compare to pre-fix: previous tests showed RecvQ climbing to 110-145 and not draining.

## Follow-ups

- **PIL-49b ✅ shipped** (audit-freeze sweep): all four ad-hoc
  `std::thread::spawn + new_current_thread runtime` workarounds in
  `server.rs` (the three `ipfs_*_blocking` helpers and the MCP
  inference preview path) now call `crate::rpc_runtime::block_on`
  directly. Functional equivalence preserved; the per-call thread
  spin-up cost is gone and the comment "futures::executor::block_on
  cannot drive tokio primitives" is no longer a foot-gun for the next
  contributor to step on.
- **PIL-49c ✅ shipped** (audit-freeze sweep): new
  `citrate_rpc_accept_queue_depth` Prometheus gauge, sampled every 5 s
  by a dedicated `rpc-accept-q-sampler` thread that parses
  `/proc/net/tcp`. Healthy depth under load is 0; a sustained `> 1`
  reading means worker threads are stalled and lets ops alert *before*
  the next deadlock-class regression hangs the public endpoint. The
  sampler is independent of the RPC worker pool so it keeps reporting
  even when workers are stuck.
- **PIL-49d** — `jsonrpsee` migration. Out of scope for the audit-
  freeze sweep; documented as deferred at
  [`.agentile/sprints/active/PIL-49d-jsonrpsee-migration.md`](PIL-49d-jsonrpsee-migration.md)
  with full motivation, staged rollout plan, and acceptance criteria
  for the next session.
- **PIL-49e** — *new (2026-06-04)*: a **different** saturation class
  observed after the citratescan indexer + CitratePulse beacon
  started hammering the same RPC. PIL-49's fix is in the running
  binary (verified) but doesn't catch this — `RecvQ` climbs to the
  kernel ceiling (1025), not the 110-145 we saw pre-PIL-49. Seen
  twice in ~7 hours, recovers via `systemctl restart citrate-node`.
  Full diagnostic plan + hypotheses at
  [`.agentile/sprints/active/PIL-49e-recurring-hang-under-indexer-beacon-load.md`](PIL-49e-recurring-hang-under-indexer-beacon-load.md).

## Related

- [[PIL-48]] (event topics) — separate bug, same session.
- The PIL-12 / PIL-12.5 / PIL-13b deploys earlier today exposed this
  more often because they increased the rate of `eth_call` /
  `eth_getStorageAt` traffic from the chatbot dev's testing.
