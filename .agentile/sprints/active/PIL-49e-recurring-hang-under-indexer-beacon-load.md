---
name: PIL-49e
description: Recurring RPC accept-queue hang under sustained indexer + beacon load (NEW failure mode, PIL-49 fix is in binary but doesn't catch)
created: 2026-06-04
branch: main
author: saulbuilds (Larry Klosowski)
status: open
---

# PIL-49e — Recurring RPC accept-queue hang under sustained indexer + beacon load

## Status

**Re-scoped 2026-06-11 (Lane A): likely not-reproducible-post-reroll —
pending one operator confirmation.** Originally: open / not yet
diagnosed, a real recurring production failure PIL-49 does not catch.

### 2026-06-11 post-re-roll observations (remote, Lane A)

The failure was observed twice in ~7h on 2026-06-04 under combined
indexer + beacon load. The 2026-06-07/08 re-roll restarted the world.
Verified live on 2026-06-11 (~150 RPC calls during the session, two
46-address `eth_getCode` sweeps included):

- The citratescan indexer is **live at lag = 1 block** (explorer
  `/api/health`: chain head 147,876, indexer head 147,875) — it has
  been continuously hammering this RPC since the re-roll and is
  current, which it could not be across an unresolved multi-hour hang
  pattern.
- The re-rolled chain has produced **147,784 blocks over 3.42
  uninterrupted days** (2.00 s/block average).
- RPC burst latency from a cold client: 0.23–0.41 s per call, no
  timeouts, no accept stalls.
- `RpcAcceptQueueBacklog` alert added (citrate-chain, same change as
  this note): `citrate_rpc_accept_queue_depth > 1 for 1m` → critical,
  with capture-before-restart instructions. This was the sprint's own
  named alert path ("wire it before the next recurrence") — now wired.

**The one check this session could not run** (no droplet SSH from this
machine): confirm `citrate-node` was not restarted around hang windows
since the re-roll —

```bash
ssh root@142.93.58.145 'journalctl -u citrate-node --since "2026-06-08" \
  | grep -cE "Started|systemd.*restart"'
# 1 (the re-roll deploy itself) → no hangs since re-roll → CLOSE this
#   sprint as not-reproducible-post-reroll.
# >1 unexplained → the hang survived the re-roll → run the diagnostic
#   plan below at the next recurrence (capture BEFORE restart).
```

If the count is clean, close this sprint to `completed/` citing this
entry; the structural fix remains [[PIL-49d]] (jsonrpsee), deferred.

## Symptom

Same surface as [[PIL-49]]:

- `citrate-node` keeps producing blocks (consensus thread alive).
- `0.0.0.0:8545`'s `RecvQ` climbs past the kernel's listen backlog
  ceiling — observed at **1025** today, vs the 110-145 we saw under
  the original PIL-49 mode.
- All eth_blockNumber callers (explorer health endpoint, indexer
  worker, beacon worker, external curl) time out.
- `systemctl restart citrate-node` recovers cleanly in <10 s.

Observed **twice in ~7 hours** today (2026-06-04), both times after
sustained load from the citratescan indexer + the CitratePulse
beacon both hammering the local RPC.

## Why this is NOT PIL-49

PIL-49 fixed the `futures::executor::block_on` + `tokio::sync::*`
waker deadlock by routing every `block_on` site through a shared
multi-threaded Tokio runtime (`core/api/src/rpc_runtime.rs`).

We verified the running binary contains that fix today:

```
$ ssh root@142.93.58.145 'strings /home/citrate/bin/citrate-node \
    | grep -c "rpc_runtime\|citrate-rpc"'
61
```

So this is a *different* exhaustion class that PIL-49 didn't cover.
RecvQ climbing past 1024 (vs the prior 110-145) also suggests a
*different* saturation point — pre-fix, four sync workers stuck on
`block_on` caused accept-pool stall at modest depths; now we're
seeing complete accept-loop standstill at the kernel ceiling.

## What changed (load profile)

Three concurrent workloads now hit the same RPC continuously, where
before only the chatbot did:

1. **Citratescan indexer** (`/root/citrate-explorer`, systemd
   `citratescan-indexer`) — running at `INDEXER_PARALLEL=16`,
   issues 16 concurrent `eth_getBlockByNumber` per tick plus
   per-tx `eth_getTransactionReceipt` for any non-empty block, plus
   reconcile-finality reads.
2. **CitratePulse beacon** (`/root/citrate-explorer`, systemd
   `citratescan-beacon`) — issues one `eth_sendRawTransaction` per
   block (~every 2 s) + the implied `eth_getBlockNumber` /
   `eth_getTransactionCount` poll cycle.
3. **Chatbot + buyer-webapp + gateway** — pre-existing, but now
   coexisting with the above two on the same droplet.

Both recurrences correlated with this combined load.

## Hypotheses (none confirmed yet)

1. **Tokio runtime task queue saturation in the shared rpc_runtime.**
   PIL-49 set `worker_threads = 16`. Combined load may now schedule
   more than 16 long-lived `block_on`s simultaneously. Once all
   workers are mid-`block_on`, hyper's accept future doesn't get
   scheduled, the accept loop stops draining, and RecvQ piles up.
   *Test:* bump `rpc_runtime` worker threads to 32 or 64 and see if
   the failure window stretches under the same load.

2. **Hyper / jsonrpc-http-server connection cap.** v18's
   `start_http` may have a hidden per-listener concurrent-connection
   cap that interacts badly with persistent keep-alive sessions
   from the indexer's reqwest pool. Persistent connections that the
   server holds open could starve new ones.
   *Test:* set the indexer's RPC `keep-alive: false` and see if
   recurrence drops.

3. **Tokio reactor IO driver thread starvation.** The shared
   rpc_runtime's IO driver runs on one thread; if every worker is
   inside a long `block_on` that's polling network IO, the IO
   driver may not get poll slices.
   *Test:* check the runtime is `new_multi_thread` with
   `enable_all()` (it is) and that the rpc-block-on threads aren't
   pinned.

4. **StateDB read-lock starvation under load.** Many concurrent
   `eth_call` / `eth_getStorageAt` from the indexer might hold the
   StateDB's read locks long enough that the chain's commit thread
   blocks waiting for a write lock — propagating back into RPC
   handler stalls.
   *Test:* count contended locks in the chain via tracing during a
   load burst.

5. **OS-level fd / ephemeral-port exhaustion.** 1025 ≈ kernel
   default backlog (`net.core.somaxconn = 1024`) PLUS one. Maybe
   we're sitting exactly at backlog overflow. The pattern *could*
   be: the listener IS draining the queue, just too slowly to
   prevent overflow, and OS drops new SYNs once we hit somaxconn.
   *Test:* `sysctl net.core.somaxconn` (currently default 1024?),
   raise it to 65536, see if the hang threshold moves.

The hypotheses aren't mutually exclusive; #1 + #5 together is the
most likely combined story.

## Diagnostic plan for the next recurrence

The single most valuable artefact is **state captured during the
hang, before restart**. Once we restart we lose all the evidence.

When the indexer or beacon log shows the timeout pattern next time:

```bash
# 1. Confirm we're in the hang state
ssh root@142.93.58.145 'ss -tlnH "( sport = :8545 )" | awk "{print \$2}"'
# Expect: 1025 or close

# 2. Per-listener accept state — distinguishes accept-loop dead
#    vs workers blocked
ssh root@142.93.58.145 'ss -tnp "sport = :8545" | head -20'

# 3. citrate-node stack trace via gcore + gdb on a side process
ssh root@142.93.58.145 'gcore -o /tmp/citrate-node $(pgrep -f citrate-node | head -1) &
sleep 6
gdb --batch -ex "thread apply all bt" -ex quit \
    /home/citrate/bin/citrate-node /tmp/citrate-node.* > /tmp/citrate-node-stacks.txt 2>&1
'

# 4. Inflight RPC method count by method (if metrics endpoint is up)
ssh root@142.93.58.145 'curl -s http://127.0.0.1:9001/metrics 2>/dev/null \
  | grep citrate_rpc_requests_total | sort | tail -10'
```

The stack trace from (3) is the load-bearing one. It will show
*exactly* what every thread is doing — if all rpc_runtime workers
are inside `tokio::sync::Mutex::lock_owned` waiting on the same
mutex, that's hypothesis #4. If they're inside `recv()` /
`getrandom` / `connect()`, that's #2. If the accept-loop thread is
parked on a futex with no syscall, that's #1/#3.

## Operational levers (no rebuild needed)

While we don't have a fix, two env-only changes reduce recurrence:

- **Indexer**: drop `INDEXER_PARALLEL=16` → `8` (or `4`) in
  `/etc/citratescan-indexer.env`, then
  `systemctl restart citratescan-indexer`. Halves RPC pressure, ~2x
  catchup time.
- **Beacon**: set `BEACON_MIN_INTERVAL_MS=2000` (or `5000`) in
  `/etc/citratescan-beacon.env`, then `systemctl restart
  citratescan-beacon`. Pulses every 2-5s instead of every block;
  removes the sustained `eth_sendRawTransaction` cadence.

Neither closes the underlying bug — they're load-shaping bandaids.

## Acceptance criteria

| | |
|---|---|
| Root cause identified — one of the hypotheses confirmed by a hang-state stack trace | ⏳ |
| Fix landed in `citrate-api` or `citrate-node` and deployed | ⏳ |
| 24h continuous run with **both** indexer (`PARALLEL=16`) and beacon enabled, no RPC hang | ⏳ |
| `citrate_rpc_accept_queue_depth` gauge (from PIL-49c) stays at 0 throughout | ⏳ |

## Related

- [[PIL-49]] — the structural fix this is a successor to. Closed
  the `block_on`/`tokio::sync` deadlock; this is a *different*
  saturation class observed only after the indexer + beacon load
  came online today.
- [[PIL-49b]] — collapsed the four spawn-thread workarounds onto
  `rpc_runtime::block_on`. Increases the pressure on the shared
  runtime, possibly contributing to the saturation seen here.
- [[PIL-49c]] — the `citrate_rpc_accept_queue_depth` gauge. **This
  is now the alert path**: anything > 1 sustained means we are
  inside (or sliding into) a PIL-49e hang. Wire it to Grafana /
  PagerDuty before the next recurrence.
- [[PIL-49d]] — the deferred `jsonrpsee` migration. Almost
  certainly the ultimate fix — jsonrpsee is async-native and the
  whole sync-worker-pool failure mode goes away — but too big for
  a hot-fix. PIL-49e is the bandaid sprint until 49d lands.

## What we know is NOT the cause

- It's not "PIL-49 wasn't deployed" — binary has 61 `rpc_runtime`
  references.
- It's not the chain consensus path — block production continues
  through the entire hang window.
- It's not a CPU bottleneck — load average peaks ~12 on a 4-core
  box during catchup but the hang is observed even when load is
  low.
- It's not Caddy — the same hang is observed against
  `http://127.0.0.1:8545` directly, bypassing Caddy entirely.
