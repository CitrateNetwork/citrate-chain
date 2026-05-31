// citrate/core/api/src/rpc_runtime.rs
//
// PIL-49: A shared, multi-threaded Tokio runtime used by every RPC handler
// to drive `async fn` calls into the executor / mempool / storage layers.
//
// **Why this exists.** RPC handlers in `eth_rpc.rs`, `ai_rpc.rs`, and
// `economics_rpc.rs` are registered via `jsonrpc_core::IoHandler::add_sync_method`,
// so each call runs on a *sync* worker thread out of `jsonrpc-http-server`'s
// pool (default 4). Those workers reach into the async world via
// `block_on(some_async_fn)` to call into the executor / mempool.
//
// The previous code used `futures::executor::block_on`, which is a no-runtime
// poller. That works only for futures whose wakers register against the
// "stock" waker. Our async functions await `tokio::sync::Mutex`,
// `tokio::sync::RwLock`, `tokio::time::sleep`, and `reqwest` calls — **all of
// which register wakers against the Tokio reactor**. Without a Tokio runtime
// in scope, those wakers never fire, the future never resolves, and the
// worker thread blocks forever.
//
// Production effect (2026-05-31): four-ish concurrent slow chatbot
// `eth_call`s saturated the entire RPC worker pool. The OS kept queueing TCP
// connects in the listen backlog (`ss RecvQ` climbed to 110-145) but
// userspace never `accept()`ed them. From outside, `rpc.citrate.ai` looked
// dead even though `citrate-node` was happily producing blocks. Recovery
// required `systemctl restart citrate-node`.
//
// The codebase had already noticed this for a handful of specific call sites
// (IPFS upload, MCP preview, ai_rpc inference) and worked around it by
// spawning a *new* OS thread + *new* `current_thread` runtime per call. That
// works but is wasteful and easy to forget — every new RPC handler reopens
// the same deadlock unless the author remembers the dance.
//
// This module replaces that pattern with a single shared runtime: one
// `block_on` import, no foot-gun.

use once_cell::sync::Lazy;
use std::future::Future;
use tokio::runtime::Runtime;

/// Shared multi-threaded Tokio runtime for RPC handlers.
///
/// Sized for ~chatbot load + foundry tooling bursts:
///   * `worker_threads(16)` — independent of the jsonrpc-http-server thread
///     count, so even at 64 sync workers we still have enough Tokio worker
///     headroom for the futures they drive.
///   * `enable_all()` — IO driver + timer; needed for `tokio::time::sleep`
///     and `tokio::sync::*` wakers, and for `reqwest`-driven async work.
///
/// Lazily initialised so unit tests in other crates that depend on us don't
/// pay the cost unless they actually use it.
static RPC_RT: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(16)
        .enable_all()
        .thread_name("citrate-rpc")
        .build()
        .expect("citrate-rpc runtime should build (no fd / thread budget left?)")
});

/// Block the current sync worker until `f` resolves.
///
/// Production path (no enclosing Tokio runtime — jsonrpc-http-server's
/// worker threads are plain OS threads): drives `f` on the shared
/// multi-threaded `RPC_RT` above.
///
/// Test path (the caller is already inside a Tokio runtime, typically a
/// `#[tokio::test(flavor = "multi_thread")]`): uses `block_in_place` +
/// the current handle so we can synchronously wait without the
/// "Cannot start a runtime from within a runtime" panic that
/// `RPC_RT.block_on` would emit. This requires a multi-thread runtime —
/// single-threaded `#[tokio::test]` callers must opt in to multi-thread.
pub fn block_on<F: Future>(f: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(f)),
        Err(_) => RPC_RT.block_on(f),
    }
}
