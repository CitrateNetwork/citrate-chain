//! Receipt tracker.
//!
//! Receives accepted-by-RPC transaction hashes from the submission
//! workers and polls `eth_getTransactionReceipt` for each. Workers
//! use exponential backoff with a hard per-tx timeout. Results feed
//! into atomic counters so the runner can summarize at end-of-run
//! without a mutex on the hot path.
//!
//! Design choices:
//!
//! - Bounded mpsc channel gives natural backpressure. If the tracker
//!   falls behind, submission workers block on `tx.send().await` and
//!   the overall rate drops — that is the correct behavior, and is
//!   recorded in the report (because inclusion tps will trail
//!   submission tps).
//!
//! - Counters are `AtomicU64`. Sample receipts are collected into a
//!   Mutex-protected Vec, capped at `sample_cap`. The sample path is
//!   cold (only the first N receipts) so mutex contention is
//!   negligible.
//!
//! - On shutdown, the runner drops its sender half and awaits the
//!   tracker's join handle. This gives all outstanding receipts a
//!   chance to land within the cooldown window.
//!
//! Phase 5 adds optional depth-finality tracking. When `FinalityOptions`
//! is set, the tracker spawns a single head watcher task that polls
//! `eth_blockNumber` on a shared cadence and publishes the latest head
//! into an `AtomicU64`. After a tx's receipt lands, the worker waits
//! until the head is at least `depth_blocks - 1` blocks above the
//! receipt's inclusion block before recording depth-finalized latency.
//! Checkpoint finality is a Phase 5 extension point — there is no
//! `citrate_getLastCheckpoint` RPC on the current node, so the hook is
//! reserved (`checkpoint_finalized` / latency counters exist in the
//! stats struct but stay zero until the RPC surfaces).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::rpc::{ReceiptSummary, RpcClient};

/// Opaque handle passed from submission workers to the tracker.
#[derive(Debug, Clone)]
pub struct TxToTrack {
    pub tx_hash: String,
    pub submitted_at: Instant,
}

/// Snapshot of the tracker's state at drain time.
#[derive(Debug, Clone, Default)]
pub struct TrackerStats {
    pub received: u64,
    pub included: u64,
    pub reverted: u64,
    pub timeouts: u64,
    pub transport_errors: u64,
    pub avg_inclusion_latency_ms: f64,
    pub sample_receipts: Vec<ReceiptSummary>,
    // Phase 5: depth finality.
    /// Number of txs that reached the configured `depth_blocks`
    /// threshold before the finality timeout. Zero when finality
    /// is disabled.
    pub depth_finalized: u64,
    /// Number of txs that were included but did not reach depth
    /// finality before the per-tx finality timeout.
    pub depth_finality_timeouts: u64,
    /// Mean depth-finality latency across `depth_finalized` txs, in
    /// milliseconds. `0.0` when `depth_finalized` is zero.
    pub avg_depth_finality_latency_ms: f64,
    /// Reserved for when a checkpoint RPC exists on the node. All
    /// current code paths leave these at zero.
    pub checkpoint_finalized: u64,
    pub avg_checkpoint_finality_latency_ms: f64,
}

#[derive(Debug, Clone)]
pub struct TrackerOptions {
    pub worker_count: usize,
    pub per_tx_timeout: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub sample_cap: usize,
    pub channel_capacity: usize,
    /// Optional depth-finality configuration. `None` disables
    /// finality tracking entirely — the head watcher is not even
    /// spawned. See `FinalityOptions` for the semantics.
    pub finality: Option<FinalityOptions>,
}

/// Parameters for depth-finality tracking.
///
/// A transaction is **depth-finalized** when the chain head is at
/// least `depth_blocks - 1` blocks above the tx's inclusion block
/// (i.e., `head_height >= inclusion_height + depth_blocks - 1`).
/// `depth_blocks = 1` treats a tx as finalized as soon as the head
/// reaches its inclusion block; `depth_blocks = 6` requires five
/// confirmations on top.
///
/// The head watcher polls `eth_blockNumber` every `poll_interval`
/// and is shared across all tracker workers. The per-tx finality
/// timeout is independent of the receipt timeout on `TrackerOptions`.
#[derive(Debug, Clone)]
pub struct FinalityOptions {
    pub depth_blocks: u64,
    pub poll_interval: Duration,
    pub per_tx_timeout: Duration,
}

impl Default for FinalityOptions {
    fn default() -> Self {
        Self {
            depth_blocks: 6,
            poll_interval: Duration::from_millis(500),
            per_tx_timeout: Duration::from_secs(180),
        }
    }
}

impl Default for TrackerOptions {
    fn default() -> Self {
        Self {
            worker_count: 16,
            per_tx_timeout: Duration::from_secs(60),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
            sample_cap: 16,
            channel_capacity: 4096,
            finality: None,
        }
    }
}

#[derive(Default)]
struct SharedState {
    received: AtomicU64,
    included: AtomicU64,
    reverted: AtomicU64,
    timeouts: AtomicU64,
    transport_errors: AtomicU64,
    inclusion_latency_us_total: AtomicU64,
    sample_receipts: Mutex<Vec<ReceiptSummary>>,
    // Phase 5 depth finality.
    depth_finalized: AtomicU64,
    depth_finality_timeouts: AtomicU64,
    depth_finality_latency_us_total: AtomicU64,
    /// Latest head height as observed by the head watcher. `0` when
    /// the watcher has not yet published a first sample (finality
    /// checks should not succeed before the first sample lands).
    latest_head: AtomicU64,
}

/// Handle the runner holds onto to push work and collect results.
pub struct Tracker {
    sender: mpsc::Sender<TxToTrack>,
    workers: Vec<JoinHandle<()>>,
    head_watcher: Option<JoinHandle<()>>,
    shared: Arc<SharedState>,
    sample_cap: usize,
    finality_enabled: bool,
}

impl Tracker {
    /// Spawn a new tracker with its worker tasks.
    pub fn spawn(client: RpcClient, options: TrackerOptions) -> Self {
        let shared = Arc::new(SharedState::default());
        let (sender, receiver) = mpsc::channel::<TxToTrack>(options.channel_capacity);
        // Wrap the receiver in an Arc<Mutex<>> so multiple workers can
        // share it. Each worker takes the mutex just long enough to
        // call `recv`, then drops it before polling the RPC.
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
        let mut workers = Vec::with_capacity(options.worker_count);
        for _ in 0..options.worker_count {
            let client = client.clone();
            let receiver = Arc::clone(&receiver);
            let shared = Arc::clone(&shared);
            let options = options.clone();
            workers.push(tokio::spawn(worker_loop(client, receiver, shared, options)));
        }

        // Head watcher — only spawned when finality tracking is
        // enabled. One shared task per tracker, so N workers don't
        // each hammer `eth_blockNumber` independently.
        let (head_watcher, finality_enabled) = match &options.finality {
            Some(fin) => {
                let fin = fin.clone();
                let client = client.clone();
                let shared = Arc::clone(&shared);
                let handle = tokio::spawn(head_watcher_loop(client, fin, shared));
                (Some(handle), true)
            }
            None => (None, false),
        };

        Self {
            sender,
            workers,
            head_watcher,
            shared,
            sample_cap: options.sample_cap,
            finality_enabled,
        }
    }

    pub fn sender(&self) -> mpsc::Sender<TxToTrack> {
        self.sender.clone()
    }

    /// Close the input channel and wait for all workers to drain.
    pub async fn drain(self) -> TrackerStats {
        // Drop our sender half so workers see "channel closed" once
        // the buffer is empty.
        drop(self.sender);
        for handle in self.workers {
            let _ = handle.await;
        }
        // Shut down the head watcher. `abort` is graceful on a task
        // whose only state is a `sleep` future — it simply returns.
        if let Some(handle) = self.head_watcher {
            handle.abort();
            let _ = handle.await;
        }
        let received = self.shared.received.load(Ordering::Acquire);
        let included = self.shared.included.load(Ordering::Acquire);
        let reverted = self.shared.reverted.load(Ordering::Acquire);
        let timeouts = self.shared.timeouts.load(Ordering::Acquire);
        let transport_errors = self.shared.transport_errors.load(Ordering::Acquire);
        let total_lat_us = self.shared.inclusion_latency_us_total.load(Ordering::Acquire);
        let avg_inclusion_latency_ms = if included > 0 {
            (total_lat_us as f64 / included as f64) / 1000.0
        } else {
            0.0
        };
        let depth_finalized = self.shared.depth_finalized.load(Ordering::Acquire);
        let depth_finality_timeouts = self
            .shared
            .depth_finality_timeouts
            .load(Ordering::Acquire);
        let depth_lat_us = self
            .shared
            .depth_finality_latency_us_total
            .load(Ordering::Acquire);
        let avg_depth_finality_latency_ms = if depth_finalized > 0 {
            (depth_lat_us as f64 / depth_finalized as f64) / 1000.0
        } else {
            0.0
        };
        let sample_receipts = self
            .shared
            .sample_receipts
            .lock()
            .expect("sample mutex not poisoned")
            .iter()
            .take(self.sample_cap)
            .cloned()
            .collect();
        TrackerStats {
            received,
            included,
            reverted,
            timeouts,
            transport_errors,
            avg_inclusion_latency_ms,
            sample_receipts,
            depth_finalized,
            depth_finality_timeouts,
            avg_depth_finality_latency_ms,
            checkpoint_finalized: 0,
            avg_checkpoint_finality_latency_ms: 0.0,
        }
    }

    /// True if this tracker was spawned with `FinalityOptions`.
    pub fn finality_enabled(&self) -> bool {
        self.finality_enabled
    }
}

async fn worker_loop(
    client: RpcClient,
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<TxToTrack>>>,
    shared: Arc<SharedState>,
    options: TrackerOptions,
) {
    loop {
        let next = {
            let mut guard = receiver.lock().await;
            guard.recv().await
        };
        let Some(work) = next else {
            break; // channel closed
        };
        shared.received.fetch_add(1, Ordering::AcqRel);
        poll_until_mined(&client, work, &shared, &options).await;
    }
}

/// Periodically poll `eth_blockNumber` and publish the result to
/// `shared.latest_head`. One instance per tracker, shared across all
/// workers so the depth-finality wait loop doesn't spam the RPC.
///
/// This task loops forever; `Tracker::drain` calls `JoinHandle::abort`
/// to shut it down cleanly. Aborting a task parked in `sleep` is a
/// no-op from the task's perspective — the tokio runtime drops it.
async fn head_watcher_loop(
    client: RpcClient,
    finality: FinalityOptions,
    shared: Arc<SharedState>,
) {
    loop {
        if let Ok(head) = client.block_number().await {
            shared.latest_head.store(head, Ordering::Release);
        }
        tokio::time::sleep(finality.poll_interval).await;
    }
}

async fn poll_until_mined(
    client: &RpcClient,
    work: TxToTrack,
    shared: &SharedState,
    options: &TrackerOptions,
) {
    let deadline = work.submitted_at + options.per_tx_timeout;
    let mut backoff = options.initial_backoff;
    let receipt = loop {
        if Instant::now() >= deadline {
            shared.timeouts.fetch_add(1, Ordering::AcqRel);
            return;
        }
        match client.get_transaction_receipt(&work.tx_hash).await {
            Ok(Some(receipt)) => break receipt,
            Ok(None) => {
                // Not yet mined — sleep and retry.
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(options.max_backoff);
            }
            Err(_) => {
                shared.transport_errors.fetch_add(1, Ordering::AcqRel);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(options.max_backoff);
            }
        }
    };

    // Receipt has landed. Record inclusion.
    let elapsed = work.submitted_at.elapsed();
    shared
        .inclusion_latency_us_total
        .fetch_add(elapsed.as_micros() as u64, Ordering::AcqRel);
    if receipt.succeeded() {
        shared.included.fetch_add(1, Ordering::AcqRel);
    } else {
        shared.reverted.fetch_add(1, Ordering::AcqRel);
    }
    let inclusion_block = receipt.block_number_u64();
    if let Ok(mut sample) = shared.sample_receipts.lock() {
        if sample.len() < options.sample_cap {
            sample.push(receipt);
        }
    }

    // Phase 5: wait for depth finality if configured.
    if let Some(finality) = &options.finality {
        wait_for_depth_finality(work.submitted_at, inclusion_block, shared, finality).await;
    }
}

/// Wait until the head watcher reports a head height at least
/// `inclusion_block + depth_blocks - 1`. On success, record
/// depth-finality latency; on timeout, bump the timeout counter.
async fn wait_for_depth_finality(
    submitted_at: Instant,
    inclusion_block: u64,
    shared: &SharedState,
    finality: &FinalityOptions,
) {
    // depth_blocks == 0 or 1 both mean "as soon as the receipt lands"
    // for practical purposes: the inclusion block equals the head.
    // We require head >= target_height where target_height = inclusion
    // + (depth - 1) for depth >= 1, and target_height = inclusion for
    // depth == 0.
    let depth = finality.depth_blocks.max(1);
    let target_height = inclusion_block.saturating_add(depth.saturating_sub(1));
    let finality_deadline = submitted_at + finality.per_tx_timeout;

    loop {
        if Instant::now() >= finality_deadline {
            shared
                .depth_finality_timeouts
                .fetch_add(1, Ordering::AcqRel);
            return;
        }
        let head = shared.latest_head.load(Ordering::Acquire);
        if head >= target_height && head > 0 {
            let total = submitted_at.elapsed();
            shared.depth_finalized.fetch_add(1, Ordering::AcqRel);
            shared
                .depth_finality_latency_us_total
                .fetch_add(total.as_micros() as u64, Ordering::AcqRel);
            return;
        }
        tokio::time::sleep(finality.poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_are_sensible() {
        let o = TrackerOptions::default();
        assert_eq!(o.worker_count, 16);
        assert!(o.per_tx_timeout > o.initial_backoff);
        assert!(o.max_backoff >= o.initial_backoff);
        assert!(o.finality.is_none(), "finality must default to disabled");
    }

    #[test]
    fn default_stats_are_zero() {
        let s = TrackerStats::default();
        assert_eq!(s.received, 0);
        assert_eq!(s.included, 0);
        assert_eq!(s.timeouts, 0);
        assert!(s.sample_receipts.is_empty());
        assert_eq!(s.depth_finalized, 0);
        assert_eq!(s.depth_finality_timeouts, 0);
        assert_eq!(s.avg_depth_finality_latency_ms, 0.0);
        assert_eq!(s.checkpoint_finalized, 0);
    }

    #[test]
    fn default_finality_options() {
        let f = FinalityOptions::default();
        assert!(f.depth_blocks >= 1);
        assert!(f.per_tx_timeout > f.poll_interval);
    }

    /// Directly drive `wait_for_depth_finality` with a hand-controlled
    /// `SharedState.latest_head`. Proves the latency arithmetic is
    /// non-negative and the counter bumps exactly once on success.
    #[tokio::test]
    async fn wait_for_depth_finality_records_on_head_catchup() {
        let shared = Arc::new(SharedState::default());
        let finality = FinalityOptions {
            depth_blocks: 3,
            poll_interval: Duration::from_millis(10),
            per_tx_timeout: Duration::from_secs(5),
        };
        // Inclusion block 10, target = 10 + 2 = 12.
        // Head starts at 10 (equal to inclusion), not enough.
        shared.latest_head.store(10, Ordering::Release);

        let submitted = Instant::now();
        let inclusion_block = 10u64;

        // Spawn the wait; race it against a head increment.
        let shared_clone = Arc::clone(&shared);
        let bumper = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            shared_clone.latest_head.store(12, Ordering::Release);
        });

        let fin_clone = finality.clone();
        wait_for_depth_finality(submitted, inclusion_block, &shared, &fin_clone).await;
        let _ = bumper.await;

        assert_eq!(shared.depth_finalized.load(Ordering::Acquire), 1);
        assert_eq!(shared.depth_finality_timeouts.load(Ordering::Acquire), 0);
        let total = shared.depth_finality_latency_us_total.load(Ordering::Acquire);
        // Latency is elapsed since `submitted` and must be >= the 40ms
        // we waited for the head bump.
        assert!(total >= 40_000, "latency {total}us below 40ms floor");
    }

    /// If the head never catches up before the finality timeout, the
    /// tx is recorded as a finality timeout (not a success).
    #[tokio::test]
    async fn wait_for_depth_finality_times_out() {
        let shared = Arc::new(SharedState::default());
        let finality = FinalityOptions {
            depth_blocks: 10,
            poll_interval: Duration::from_millis(10),
            per_tx_timeout: Duration::from_millis(50),
        };
        shared.latest_head.store(5, Ordering::Release);
        // Target height = 5 + 9 = 14; head never moves.

        let submitted = Instant::now();
        wait_for_depth_finality(submitted, 5, &shared, &finality).await;

        assert_eq!(shared.depth_finalized.load(Ordering::Acquire), 0);
        assert_eq!(shared.depth_finality_timeouts.load(Ordering::Acquire), 1);
    }

    /// Zero-latest-head must not satisfy finality, even if the target
    /// is numerically <= 0. This defends against a race where the
    /// head watcher hasn't published its first sample yet.
    #[tokio::test]
    async fn wait_for_depth_finality_requires_nonzero_head() {
        let shared = Arc::new(SharedState::default());
        // depth_blocks=1, inclusion=0 → target=0. With head==0, we'd
        // satisfy `head >= target` trivially if not for the head>0
        // guard. The guard keeps us honest: a tracker running against
        // a freshly started node can't claim finality until it has
        // seen at least one real block.
        let finality = FinalityOptions {
            depth_blocks: 1,
            poll_interval: Duration::from_millis(10),
            per_tx_timeout: Duration::from_millis(50),
        };
        // latest_head stays at 0 — default.
        wait_for_depth_finality(Instant::now(), 0, &shared, &finality).await;
        assert_eq!(shared.depth_finalized.load(Ordering::Acquire), 0);
        assert_eq!(shared.depth_finality_timeouts.load(Ordering::Acquire), 1);
    }

    /// Depth==0 is normalized to 1 internally — a tx is finalized as
    /// soon as the head reaches its inclusion block.
    #[tokio::test]
    async fn wait_for_depth_finality_depth_zero_normalized_to_one() {
        let shared = Arc::new(SharedState::default());
        shared.latest_head.store(7, Ordering::Release);
        let finality = FinalityOptions {
            depth_blocks: 0,
            poll_interval: Duration::from_millis(10),
            per_tx_timeout: Duration::from_millis(100),
        };
        // inclusion=7, head=7, normalized depth=1, target=7+0=7 → pass.
        wait_for_depth_finality(Instant::now(), 7, &shared, &finality).await;
        assert_eq!(shared.depth_finalized.load(Ordering::Acquire), 1);
    }

    /// Full tracker round-trip with finality enabled. Uses mockito to
    /// simulate a node whose head is already past the finality depth
    /// and whose receipt comes back mined. Proves:
    ///
    /// 1. The head_watcher task spawns and publishes to `latest_head`.
    /// 2. The worker receives a tx, polls for the receipt, then waits
    ///    for depth finality.
    /// 3. `drain()` reports `depth_finalized == 1` and
    ///    `avg_depth_finality_latency_ms >= avg_inclusion_latency_ms`
    ///    (monotonic per-tx: finality is always after inclusion).
    /// 4. All latency samples are non-negative.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tracker_records_depth_finality_end_to_end() {
        let mut server = mockito::Server::new_async().await;

        // Head watcher: always returns 20 (comfortably past the tx's
        // inclusion block). `expect_at_least(1)` is implicit in the
        // head watcher spinning during the run.
        let _head = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(
                serde_json::json!({"method": "eth_blockNumber"}),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0x14"}"#) // 20
            .expect_at_least(1)
            .create_async()
            .await;

        // Receipt: mined at block 10, status success.
        let _receipt = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(
                serde_json::json!({"method": "eth_getTransactionReceipt"}),
            ))
            .with_status(200)
            .with_body(
                r#"{"jsonrpc":"2.0","id":1,"result":{"transactionHash":"0xaa","blockNumber":"0xa","status":"0x1","gasUsed":"0x5208"}}"#,
            )
            .expect_at_least(1)
            .create_async()
            .await;

        let client = RpcClient::new(server.url(), Duration::from_secs(5)).expect("rpc");
        let options = TrackerOptions {
            worker_count: 1,
            per_tx_timeout: Duration::from_secs(5),
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            sample_cap: 4,
            channel_capacity: 4,
            finality: Some(FinalityOptions {
                // depth=6, inclusion=10, target=10+5=15; head=20 > 15, pass.
                depth_blocks: 6,
                poll_interval: Duration::from_millis(20),
                per_tx_timeout: Duration::from_secs(5),
            }),
        };

        let tracker = Tracker::spawn(client, options);
        assert!(tracker.finality_enabled());
        let sender = tracker.sender();

        let submitted_at = Instant::now();
        sender
            .send(TxToTrack {
                tx_hash: "0xaa".to_string(),
                submitted_at,
            })
            .await
            .expect("send");
        // Drop our sender half so workers see channel close when
        // they next poll.
        drop(sender);

        let stats = tracker.drain().await;

        // --- Assertions ---
        assert_eq!(stats.received, 1);
        assert_eq!(stats.included, 1, "tx should have been counted as included");
        assert_eq!(stats.reverted, 0);
        assert_eq!(stats.timeouts, 0);

        // Depth finality succeeded.
        assert_eq!(stats.depth_finalized, 1);
        assert_eq!(stats.depth_finality_timeouts, 0);

        // Non-negative latencies — both metrics.
        assert!(
            stats.avg_inclusion_latency_ms >= 0.0,
            "inclusion latency negative: {}",
            stats.avg_inclusion_latency_ms
        );
        assert!(
            stats.avg_depth_finality_latency_ms >= 0.0,
            "depth finality latency negative: {}",
            stats.avg_depth_finality_latency_ms
        );

        // Monotonic per-tx: finality is always recorded AFTER
        // inclusion, so average finality latency is >= average
        // inclusion latency for a single-tx run.
        assert!(
            stats.avg_depth_finality_latency_ms >= stats.avg_inclusion_latency_ms,
            "monotonicity violated: finality={} ms, inclusion={} ms",
            stats.avg_depth_finality_latency_ms,
            stats.avg_inclusion_latency_ms
        );

        // Checkpoint finality is reserved — stays zero.
        assert_eq!(stats.checkpoint_finalized, 0);
    }
}
