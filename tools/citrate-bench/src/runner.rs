//! Benchmark runner.
//!
//! Phase 2 introduced the rate-limited dry-run loop. Phase 3 adds
//! `RunMode::Broadcast` which submits real signed transactions via
//! `eth_sendRawTransaction`, hands accepted hashes off to a receipt
//! tracker, and returns both RPC-acceptance and block-inclusion
//! counters as first-class metrics.
//!
//! Rate limiting is still **deadline-based**. The main loop signs
//! inline (fast) and, in broadcast mode, spawns one `tokio::spawn`
//! per submission. A global `Semaphore` bounds the total number of
//! concurrent submissions to `concurrency_cap`, giving
//! backpressure when the network can't keep up.
//!
//! The per-signer `NoncePermit` is owned by the submission task
//! until the RPC response lands, so the per-signer in-flight cap
//! (`max_per_sender`) correctly counts network-inflight, not just
//! locally-built-but-queued.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use crate::rpc::{RpcClient, SendRawOutcome};
use crate::signers::pool::SignerPool;
use crate::tracker::{Tracker, TrackerOptions, TrackerStats, TxToTrack};
use crate::tx::SignedTx;
use crate::workload::{WorkloadClass, WorkloadContext};
use crate::{Error, Result};

/// How the runner handles each signed tx.
#[derive(Clone)]
pub enum RunMode {
    /// Build + sign transactions, never broadcast.
    DryRun,
    /// Submit via `eth_sendRawTransaction`, track receipts.
    Broadcast {
        client: RpcClient,
        tracker_options: TrackerOptions,
        /// Max concurrent in-flight submissions across the whole
        /// runner (not per signer — the per-signer cap is enforced
        /// by `SignerPool::per_signer_max_inflight`).
        concurrency_cap: usize,
        /// How long to keep the tracker running after the main
        /// submission loop ends, giving late receipts a chance to
        /// land.
        cooldown_secs: u64,
    },
}

impl std::fmt::Debug for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunMode::DryRun => f.write_str("DryRun"),
            RunMode::Broadcast {
                client,
                concurrency_cap,
                cooldown_secs,
                ..
            } => f
                .debug_struct("Broadcast")
                .field("rpc_url", &client.url())
                .field("concurrency_cap", concurrency_cap)
                .field("cooldown_secs", cooldown_secs)
                .finish(),
        }
    }
}

/// Knobs the runner needs regardless of mode.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub duration_secs: u64,
    pub target_tps: u64,
    pub sample_cap: usize,
}

impl RunOptions {
    pub fn for_dry_run(duration_secs: u64, target_tps: u64) -> Self {
        Self {
            duration_secs,
            target_tps,
            sample_cap: 16,
        }
    }
}

/// Ground-truth broadcast results. Populated only in `Broadcast` mode.
#[derive(Debug, Clone, Default)]
pub struct BroadcastResult {
    pub rpc_accepted: u64,
    pub rpc_rejected: u64,
    pub rejected_reasons: Vec<String>,
    pub tracker_stats: TrackerStats,
    /// Summed over all signers, the difference between each signer's
    /// final `eth_getTransactionCount(latest)` and its starting
    /// nonce. This is the canonical "mined" count — if it disagrees
    /// with `tracker_stats.included`, one of the two is wrong, and
    /// the report flags the mismatch.
    pub mined_nonce_delta_total: u64,
    pub ground_truth_match: bool,
    pub included_tps: f64,
}

/// Full run outcome.
#[derive(Debug)]
pub struct RunResult {
    pub attempted: u64,
    pub pool_saturated: u64,
    pub signed_ok: u64,
    pub signing_errors: u64,
    pub duration_secs: f64,
    pub effective_tps: f64,
    pub per_signer_count: Vec<u64>,
    pub sample_txs: Vec<SignedTx>,
    pub mode: RunMode,
    /// Broadcast metrics. `None` in dry-run mode.
    pub broadcast: Option<BroadcastResult>,
    /// Per-class sign count. For leaf workloads this has one entry
    /// equal to `signed_ok`; for `MixedWorkload` this is the
    /// effective (as-built) breakdown across the mix's sub-classes.
    /// Preserved in `class_roster()` order.
    pub effective_mix: Vec<(&'static str, u64)>,
}

impl RunResult {
    pub fn print_summary(&self) {
        println!("mode               = {:?}", self.mode);
        println!("duration           = {:.3}s", self.duration_secs);
        println!("attempted          = {}", self.attempted);
        println!("signed_ok          = {}", self.signed_ok);
        println!("pool_saturated     = {}", self.pool_saturated);
        println!("signing_errors     = {}", self.signing_errors);
        println!("effective_tps      = {:.2}", self.effective_tps);
        for (i, n) in self.per_signer_count.iter().enumerate() {
            println!("  signer[{i}] signed = {n}");
        }
        if self.effective_mix.len() > 1 {
            println!("-- effective mix --");
            let total: u64 = self.effective_mix.iter().map(|(_, n)| *n).sum();
            for (class, n) in &self.effective_mix {
                let pct = if total > 0 {
                    (*n as f64) * 100.0 / (total as f64)
                } else {
                    0.0
                };
                println!("  {class:20} {n:8}  ({pct:5.1}%)");
            }
        }
        if let Some(b) = &self.broadcast {
            println!("-- broadcast --");
            println!("  rpc_accepted             = {}", b.rpc_accepted);
            println!("  rpc_rejected             = {}", b.rpc_rejected);
            println!("  included                 = {}", b.tracker_stats.included);
            println!("  reverted                 = {}", b.tracker_stats.reverted);
            println!("  inclusion_timeouts       = {}", b.tracker_stats.timeouts);
            println!("  tracker_transport_errors = {}", b.tracker_stats.transport_errors);
            println!(
                "  avg_inclusion_latency_ms = {:.2}",
                b.tracker_stats.avg_inclusion_latency_ms
            );
            println!("  mined_nonce_delta_total  = {}", b.mined_nonce_delta_total);
            println!("  ground_truth_match       = {}", b.ground_truth_match);
            println!("  included_tps             = {:.2}", b.included_tps);
            if b.tracker_stats.depth_finalized > 0
                || b.tracker_stats.depth_finality_timeouts > 0
            {
                println!("-- depth finality --");
                println!(
                    "  depth_finalized          = {}",
                    b.tracker_stats.depth_finalized
                );
                println!(
                    "  depth_finality_timeouts  = {}",
                    b.tracker_stats.depth_finality_timeouts
                );
                println!(
                    "  avg_depth_finality_ms    = {:.2}",
                    b.tracker_stats.avg_depth_finality_latency_ms
                );
            }
            if !b.rejected_reasons.is_empty() {
                println!("  reject samples           =");
                for r in b.rejected_reasons.iter().take(5) {
                    println!("    {r}");
                }
            }
        }
        for (i, s) in self.sample_txs.iter().take(3).enumerate() {
            println!(
                "  sample[{i}] nonce={} hash={} (len={} bytes)",
                s.nonce,
                s.hash_hex(),
                s.raw.len()
            );
        }
    }
}

/// Shared mutable state accumulated during the run. Atomics for the
/// hot path; a mutex for the cold sample path.
struct RunState {
    signing_errors: AtomicU64,
    rpc_accepted: AtomicU64,
    rpc_rejected: AtomicU64,
    per_signer_count: Vec<AtomicU64>,
    /// Per-class sign count, indexed parallel to `class_names`. Kept
    /// as a `Vec` (not a `HashMap`) so the hot path is branch-free
    /// after the initial class-name linear search.
    class_counts: Vec<AtomicU64>,
    class_names: Vec<&'static str>,
    sample_txs: Mutex<Vec<SignedTx>>,
    rejected_reasons: Mutex<Vec<String>>,
    sample_cap: usize,
}

impl RunState {
    fn new(pool_len: usize, class_names: Vec<&'static str>, sample_cap: usize) -> Self {
        let class_counts = (0..class_names.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            signing_errors: AtomicU64::new(0),
            rpc_accepted: AtomicU64::new(0),
            rpc_rejected: AtomicU64::new(0),
            per_signer_count: (0..pool_len).map(|_| AtomicU64::new(0)).collect(),
            class_counts,
            class_names,
            sample_txs: Mutex::new(Vec::with_capacity(sample_cap)),
            rejected_reasons: Mutex::new(Vec::with_capacity(16)),
            sample_cap,
        }
    }

    fn record_sample(&self, tx: &SignedTx) {
        if let Ok(mut v) = self.sample_txs.lock() {
            if v.len() < self.sample_cap {
                v.push(tx.clone());
            }
        }
    }

    fn record_rejection(&self, reason: String) {
        if let Ok(mut v) = self.rejected_reasons.lock() {
            if v.len() < 16 {
                v.push(reason);
            }
        }
    }

    /// Increment the counter for the class with the given name.
    /// Linear scan — the class list is small (typically <= 6).
    fn record_class(&self, name: &'static str) {
        if let Some(idx) = self.class_names.iter().position(|n| *n == name) {
            self.class_counts[idx].fetch_add(1, Ordering::AcqRel);
        }
        // If the name isn't in the roster (workload misconfigured),
        // it silently falls through — the effective_mix sum will
        // then be less than signed_ok, which the report surfaces.
    }
}

pub struct Runner {
    pool: Arc<SignerPool>,
    context: Arc<WorkloadContext>,
    workload: Arc<dyn WorkloadClass>,
    options: RunOptions,
}

impl Runner {
    pub fn new(
        pool: Arc<SignerPool>,
        context: Arc<WorkloadContext>,
        workload: Arc<dyn WorkloadClass>,
        options: RunOptions,
    ) -> Result<Self> {
        if pool.is_empty() {
            return Err(Error::Runner("runner requires a non-empty signer pool".into()));
        }
        if options.duration_secs == 0 {
            return Err(Error::Runner("duration_secs must be > 0".into()));
        }
        Ok(Self {
            pool,
            context,
            workload,
            options,
        })
    }

    /// Run the workload loop under the given mode.
    pub async fn run(&self, mode: RunMode) -> Result<RunResult> {
        let duration = Duration::from_secs(self.options.duration_secs);
        let target_tps = self.options.target_tps;
        let tx_interval_ns: u64 = if target_tps > 0 {
            1_000_000_000 / target_tps
        } else {
            0
        };

        let class_names = self.workload.class_roster();
        let state = Arc::new(RunState::new(
            self.pool.len(),
            class_names,
            self.options.sample_cap,
        ));
        let mut attempted: u64 = 0;
        let mut pool_saturated: u64 = 0;

        // Broadcast-mode setup: tracker + submission semaphore.
        let (tracker, submission_sem, starting_nonces) = match &mode {
            RunMode::DryRun => (None, None, Vec::new()),
            RunMode::Broadcast {
                client,
                tracker_options,
                concurrency_cap,
                ..
            } => {
                let starting = self.fetch_starting_nonces(client).await?;
                let tracker = Tracker::spawn(client.clone(), tracker_options.clone());
                let sem = Arc::new(Semaphore::new(*concurrency_cap));
                (Some(tracker), Some(sem), starting)
            }
        };

        let start = Instant::now();

        while start.elapsed() < duration {
            if tx_interval_ns > 0 {
                let target_elapsed = Duration::from_nanos(tx_interval_ns * attempted);
                let now_elapsed = start.elapsed();
                if target_elapsed > now_elapsed {
                    tokio::time::sleep(target_elapsed - now_elapsed).await;
                }
            }

            attempted += 1;

            let Some((lane_idx, signer, permit)) = self.pool.try_acquire_indexed() else {
                pool_saturated += 1;
                continue;
            };

            // Sign inline. `build_with_class` returns both the signed
            // tx and the concrete class name that produced it, so
            // `MixedWorkload` can report the effective mix.
            let (signed, class_name) =
                match self.workload.build_with_class(&self.context, &signer, permit.nonce) {
                    Ok(pair) => pair,
                    Err(_e) => {
                        state.signing_errors.fetch_add(1, Ordering::AcqRel);
                        drop(permit);
                        continue;
                    }
                };

            debug_assert_eq!(signed.sender, signer.address);
            debug_assert_eq!(signed.nonce, permit.nonce);

            state.per_signer_count[lane_idx].fetch_add(1, Ordering::AcqRel);
            state.record_class(class_name);
            state.record_sample(&signed);

            // Dispatch by mode.
            match &mode {
                RunMode::DryRun => {
                    // Drop permit immediately; no network activity.
                    drop(permit);
                }
                RunMode::Broadcast { client, .. } => {
                    // Acquire a submission slot (bounded). This blocks
                    // the main loop if concurrency_cap would be
                    // exceeded, applying backpressure to target TPS.
                    let sem = submission_sem.as_ref().expect("semaphore present in broadcast mode");
                    let submission_permit =
                        sem.clone().acquire_owned().await.map_err(|e| {
                            Error::Runner(format!("submission semaphore closed: {e}"))
                        })?;
                    let tracker_tx = tracker
                        .as_ref()
                        .expect("tracker present in broadcast mode")
                        .sender();
                    let client = client.clone();
                    let state = Arc::clone(&state);
                    // Move the NoncePermit into the task so it lives
                    // until the submission response is known.
                    let nonce_permit = permit;
                    tokio::spawn(async move {
                        let submitted_at = Instant::now();
                        match client.send_raw_transaction(&signed.raw_hex()).await {
                            Ok(SendRawOutcome::Accepted(hash)) => {
                                state.rpc_accepted.fetch_add(1, Ordering::AcqRel);
                                let _ = tracker_tx
                                    .send(TxToTrack {
                                        tx_hash: hash,
                                        submitted_at,
                                    })
                                    .await;
                            }
                            Ok(SendRawOutcome::Rejected { code, message }) => {
                                state.rpc_rejected.fetch_add(1, Ordering::AcqRel);
                                state.record_rejection(format!("code={code}: {message}"));
                            }
                            Err(e) => {
                                state.rpc_rejected.fetch_add(1, Ordering::AcqRel);
                                state.record_rejection(format!("transport: {e}"));
                            }
                        }
                        drop(nonce_permit);
                        drop(submission_permit);
                    });
                }
            }
        }

        // --- Drain ---
        let mode_final = mode.clone_for_result();
        let broadcast_result = match mode {
            RunMode::DryRun => None,
            RunMode::Broadcast {
                cooldown_secs,
                client,
                ..
            } => {
                // Give spawned submissions a moment to finish, then
                // drain the tracker.
                if cooldown_secs > 0 {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                let tracker = tracker.expect("tracker present in broadcast mode");
                let stats = tokio::time::timeout(
                    Duration::from_secs(cooldown_secs),
                    tracker.drain(),
                )
                .await
                .unwrap_or_default();

                // Ground truth: sum the per-signer nonce deltas.
                let mut mined_delta: u64 = 0;
                for (i, start_nonce) in starting_nonces.iter().enumerate() {
                    if let Some(signer) = self.pool.signer(i) {
                        match client
                            .get_transaction_count(&signer.address_hex(), "latest")
                            .await
                        {
                            Ok(current) => {
                                mined_delta = mined_delta.saturating_add(
                                    current.saturating_sub(*start_nonce),
                                );
                            }
                            Err(_) => {}
                        }
                    }
                }

                let accepted = state.rpc_accepted.load(Ordering::Acquire);
                let rejected = state.rpc_rejected.load(Ordering::Acquire);
                let rejected_reasons = state
                    .rejected_reasons
                    .lock()
                    .map(|r| r.clone())
                    .unwrap_or_default();
                // Match means the on-chain nonce delta equals the
                // tracker's included count AND the submission
                // accounting adds up. We only assert delta == included
                // here; runners with known timeout windows may see
                // included < delta because some txs mine after the
                // tracker gave up.
                let ground_truth_match = mined_delta == stats.included;
                Some(BroadcastResult {
                    rpc_accepted: accepted,
                    rpc_rejected: rejected,
                    rejected_reasons,
                    tracker_stats: stats,
                    mined_nonce_delta_total: mined_delta,
                    ground_truth_match,
                    included_tps: 0.0, // filled below
                })
            }
        };

        let duration_secs = start.elapsed().as_secs_f64();
        let signed_ok: u64 = state
            .per_signer_count
            .iter()
            .map(|a| a.load(Ordering::Acquire))
            .sum();
        let signing_errors = state.signing_errors.load(Ordering::Acquire);
        let effective_tps = if duration_secs > 0.0 {
            signed_ok as f64 / duration_secs
        } else {
            0.0
        };
        let per_signer_count = state
            .per_signer_count
            .iter()
            .map(|a| a.load(Ordering::Acquire))
            .collect::<Vec<_>>();
        let sample_txs = state
            .sample_txs
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();

        let broadcast = broadcast_result.map(|mut b| {
            b.included_tps = if duration_secs > 0.0 {
                b.tracker_stats.included as f64 / duration_secs
            } else {
                0.0
            };
            b
        });

        let effective_mix: Vec<(&'static str, u64)> = state
            .class_names
            .iter()
            .zip(state.class_counts.iter())
            .map(|(name, atomic)| (*name, atomic.load(Ordering::Acquire)))
            .collect();

        Ok(RunResult {
            attempted,
            pool_saturated,
            signed_ok,
            signing_errors,
            duration_secs,
            effective_tps,
            per_signer_count,
            sample_txs,
            mode: mode_final,
            broadcast,
            effective_mix,
        })
    }

    /// Preflight: query each signer's current `latest` nonce. Returns
    /// them in pool order so the caller can compute deltas later.
    async fn fetch_starting_nonces(&self, client: &RpcClient) -> Result<Vec<u64>> {
        let mut out = Vec::with_capacity(self.pool.len());
        for i in 0..self.pool.len() {
            let Some(signer) = self.pool.signer(i) else {
                continue;
            };
            let n = client
                .get_transaction_count(&signer.address_hex(), "latest")
                .await?;
            out.push(n);
        }
        Ok(out)
    }
}

impl RunMode {
    fn clone_for_result(&self) -> RunMode {
        match self {
            RunMode::DryRun => RunMode::DryRun,
            RunMode::Broadcast {
                client,
                tracker_options,
                concurrency_cap,
                cooldown_secs,
            } => RunMode::Broadcast {
                client: client.clone(),
                tracker_options: tracker_options.clone(),
                concurrency_cap: *concurrency_cap,
                cooldown_secs: *cooldown_secs,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signers::Signer;
    use crate::workload::mix::{MixEntry, MixedWorkload};
    use crate::workload::transfer::SimpleTransfer;

    fn signer_with_last_byte(b: u8) -> Signer {
        let mut k = [0u8; 32];
        k[31] = b;
        Signer::from_key_bytes(&k).expect("signer")
    }

    fn pool_of(n: u8) -> Arc<SignerPool> {
        let signers = (1..=n).map(signer_with_last_byte).collect::<Vec<_>>();
        let starting = vec![0u64; n as usize];
        Arc::new(SignerPool::new(signers, starting, 64).expect("pool"))
    }

    fn runner(pool: Arc<SignerPool>, target_tps: u64, duration_secs: u64) -> Runner {
        let ctx = Arc::new(WorkloadContext::for_dry_run(40204, 1_000_000_000));
        let workload: Arc<dyn WorkloadClass> = Arc::new(SimpleTransfer::default_bench());
        Runner::new(pool, ctx, workload, RunOptions::for_dry_run(duration_secs, target_tps))
            .expect("runner")
    }

    #[tokio::test]
    async fn dry_run_respects_target_rate() {
        let pool = pool_of(2);
        let r = runner(pool, 50, 1);
        let result = r.run(RunMode::DryRun).await.expect("run");
        assert!(
            result.signed_ok >= 40 && result.signed_ok <= 60,
            "signed_ok = {} (expected ~50)",
            result.signed_ok
        );
        assert_eq!(result.signing_errors, 0);
        assert_eq!(result.pool_saturated, 0);
        assert!(result.broadcast.is_none());
    }

    #[tokio::test]
    async fn sample_cap_is_honored() {
        let pool = pool_of(1);
        let mut r = runner(pool, 200, 1);
        r.options.sample_cap = 5;
        let result = r.run(RunMode::DryRun).await.expect("run");
        assert!(result.sample_txs.len() <= 5);
        assert_eq!(result.sample_txs.len(), 5);
    }

    #[tokio::test]
    async fn per_signer_counts_sum_to_signed_ok() {
        let pool = pool_of(4);
        let r = runner(pool, 100, 1);
        let result = r.run(RunMode::DryRun).await.expect("run");
        let sum: u64 = result.per_signer_count.iter().sum();
        assert_eq!(sum, result.signed_ok);
        for (i, n) in result.per_signer_count.iter().enumerate() {
            assert!(*n > 0, "signer {i} got zero work: {:?}", result.per_signer_count);
        }
    }

    #[tokio::test]
    async fn nonces_are_sequential_per_signer() {
        let pool = pool_of(3);
        let r = runner(pool, 300, 1);
        let result = r.run(RunMode::DryRun).await.expect("run");
        use std::collections::BTreeMap;
        let mut by_sender: BTreeMap<[u8; 20], Vec<u64>> = BTreeMap::new();
        for tx in &result.sample_txs {
            by_sender.entry(tx.sender).or_default().push(tx.nonce);
        }
        for (_sender, nonces) in by_sender {
            let mut sorted = nonces.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, nonces, "nonces not monotonic for a signer");
            let dedup = {
                let mut d = sorted.clone();
                d.dedup();
                d
            };
            assert_eq!(dedup, sorted, "duplicate nonces for a signer");
        }
    }

    #[tokio::test]
    async fn dry_run_records_single_class_effective_mix() {
        let pool = pool_of(1);
        let r = runner(pool, 50, 1);
        let result = r.run(RunMode::DryRun).await.expect("run");
        assert_eq!(result.effective_mix.len(), 1);
        assert_eq!(result.effective_mix[0].0, "simple_transfer");
        assert_eq!(result.effective_mix[0].1, result.signed_ok);
    }

    #[tokio::test]
    async fn dry_run_records_multi_class_effective_mix() {
        // Build a mix of two classes that both work without an
        // address table: two copies of SimpleTransfer with different
        // recipients. The mix semantics (dispatch + counter) are
        // identical regardless of class identity, so this is enough
        // to verify the runner plumbs `effective_mix` correctly.
        let mut other = SimpleTransfer::default_bench();
        other.recipient[19] = 0xaa;
        // Rename the second class via a wrapping newtype so both
        // entries land in distinct slots of `class_roster`.
        struct OtherTransfer(SimpleTransfer);
        impl WorkloadClass for OtherTransfer {
            fn name(&self) -> &'static str {
                "other_transfer"
            }
            fn required_contracts(&self) -> &'static [&'static str] {
                &[]
            }
            fn build(
                &self,
                ctx: &WorkloadContext,
                signer: &Signer,
                nonce: u64,
            ) -> crate::Result<SignedTx> {
                self.0.build(ctx, signer, nonce)
            }
        }

        let mix = MixedWorkload::new(vec![
            MixEntry {
                class: Arc::new(SimpleTransfer::default_bench()),
                weight: 40,
            },
            MixEntry {
                class: Arc::new(OtherTransfer(other)),
                weight: 60,
            },
        ])
        .expect("mix");

        let pool = pool_of(2);
        let ctx = Arc::new(WorkloadContext::for_dry_run(40204, 1_000_000_000));
        let workload: Arc<dyn WorkloadClass> = Arc::new(mix);
        let runner = Runner::new(
            pool,
            ctx,
            workload,
            RunOptions::for_dry_run(1, 200),
        )
        .expect("runner");

        let result = runner.run(RunMode::DryRun).await.expect("run");
        assert_eq!(result.effective_mix.len(), 2);
        let class_names: Vec<&str> =
            result.effective_mix.iter().map(|(n, _)| *n).collect();
        assert!(class_names.contains(&"simple_transfer"));
        assert!(class_names.contains(&"other_transfer"));
        let sum: u64 = result.effective_mix.iter().map(|(_, n)| *n).sum();
        assert_eq!(sum, result.signed_ok);

        // Weight-based expectation: over ~200 txs with weights 40/60,
        // each class gets within a couple of full cycles of its
        // configured ratio.
        let simple = result
            .effective_mix
            .iter()
            .find(|(n, _)| *n == "simple_transfer")
            .expect("simple")
            .1;
        let other = result
            .effective_mix
            .iter()
            .find(|(n, _)| *n == "other_transfer")
            .expect("other")
            .1;
        assert!(other >= simple, "60%% class should have >= 40%% class");
    }

    #[tokio::test]
    async fn rejects_zero_duration() {
        let pool = Arc::new(
            SignerPool::new(vec![signer_with_last_byte(1)], vec![0], 1)
                .expect("pool"),
        );
        let ctx = Arc::new(WorkloadContext::for_dry_run(40204, 1));
        let workload: Arc<dyn WorkloadClass> = Arc::new(SimpleTransfer::default_bench());
        let bad = Runner::new(
            pool,
            ctx,
            workload,
            RunOptions {
                duration_secs: 0,
                target_tps: 10,
                sample_cap: 1,
            },
        );
        assert!(bad.is_err());
    }
}
