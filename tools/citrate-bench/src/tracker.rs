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
}

#[derive(Debug, Clone)]
pub struct TrackerOptions {
    pub worker_count: usize,
    pub per_tx_timeout: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub sample_cap: usize,
    pub channel_capacity: usize,
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
}

/// Handle the runner holds onto to push work and collect results.
pub struct Tracker {
    sender: mpsc::Sender<TxToTrack>,
    workers: Vec<JoinHandle<()>>,
    shared: Arc<SharedState>,
    sample_cap: usize,
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
        Self {
            sender,
            workers,
            shared,
            sample_cap: options.sample_cap,
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
        }
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

async fn poll_until_mined(
    client: &RpcClient,
    work: TxToTrack,
    shared: &SharedState,
    options: &TrackerOptions,
) {
    let deadline = work.submitted_at + options.per_tx_timeout;
    let mut backoff = options.initial_backoff;
    loop {
        if Instant::now() >= deadline {
            shared.timeouts.fetch_add(1, Ordering::AcqRel);
            return;
        }
        match client.get_transaction_receipt(&work.tx_hash).await {
            Ok(Some(receipt)) => {
                let elapsed = work.submitted_at.elapsed();
                shared
                    .inclusion_latency_us_total
                    .fetch_add(elapsed.as_micros() as u64, Ordering::AcqRel);
                if receipt.succeeded() {
                    shared.included.fetch_add(1, Ordering::AcqRel);
                } else {
                    shared.reverted.fetch_add(1, Ordering::AcqRel);
                }
                if let Ok(mut sample) = shared.sample_receipts.lock() {
                    if sample.len() < options.sample_cap {
                        sample.push(receipt);
                    }
                }
                return;
            }
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
    }

    #[test]
    fn default_stats_are_zero() {
        let s = TrackerStats::default();
        assert_eq!(s.received, 0);
        assert_eq!(s.included, 0);
        assert_eq!(s.timeouts, 0);
        assert!(s.sample_receipts.is_empty());
    }
}
