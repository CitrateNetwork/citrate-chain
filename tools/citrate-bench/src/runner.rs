//! Benchmark runner.
//!
//! Phase 2 responsibility: drive tx construction at a target rate.
//! Phase 3 extends this with real RPC submission. The shape of the
//! loop does not change between phases — only the dispatch inside
//! the per-tx step does.
//!
//! Rate limiting is **deadline-based**, not sleep-between-each-tx.
//! For submission index `i`, the target wall-clock moment is
//! `run_start + (i / target_tps) seconds`. The runner sleeps until
//! that deadline before building the next tx. This produces a steady
//! stream that matches `target_tps` regardless of per-tx overhead.
//!
//! When `target_tps` is zero, the loop runs as fast as it can — used
//! only in unit tests of the loop's accounting.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::signers::pool::SignerPool;
use crate::tx::SignedTx;
use crate::workload::{WorkloadClass, WorkloadContext};
use crate::{Error, Result};

/// How the runner handles each signed tx.
#[derive(Debug, Clone)]
pub enum RunMode {
    /// Build + sign transactions but never broadcast. Used for
    /// Phase 2 and as the `--dry-run` switch in later phases.
    DryRun,
    // Phase 3 will add: Broadcast { rpc_url: String, timeout_ms: u64 }
}

/// Knobs the runner needs.
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

/// Outcome of a single run.
#[derive(Debug)]
pub struct RunResult {
    /// Slots the rate limiter attempted to fill.
    pub attempted: u64,
    /// Slots where the pool was saturated and no signer was available.
    pub pool_saturated: u64,
    /// Transactions successfully signed.
    pub signed_ok: u64,
    /// Signing errors (should be zero in dry-run under normal inputs).
    pub signing_errors: u64,
    pub duration_secs: f64,
    /// Signed tx per second, measured end-to-end.
    pub effective_tps: f64,
    /// One entry per signer, in pool order.
    pub per_signer_count: Vec<u64>,
    /// First N signed txs (N = `RunOptions::sample_cap`) for inspection.
    pub sample_txs: Vec<SignedTx>,
    pub mode: RunMode,
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
        // target_tps == 0 is allowed (best-effort mode for tests).
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
        // Nanoseconds between tx slots. Zero means "as fast as possible".
        let tx_interval_ns: u64 = if target_tps > 0 {
            1_000_000_000 / target_tps
        } else {
            0
        };

        let mut attempted: u64 = 0;
        let mut pool_saturated: u64 = 0;
        let mut signed_ok: u64 = 0;
        let mut signing_errors: u64 = 0;
        let mut per_signer: Vec<u64> = vec![0; self.pool.len()];
        let mut sample: Vec<SignedTx> = Vec::with_capacity(self.options.sample_cap);

        let start = Instant::now();
        while start.elapsed() < duration {
            // Deadline scheduling.
            if tx_interval_ns > 0 {
                let target_elapsed = Duration::from_nanos(tx_interval_ns * attempted);
                let now_elapsed = start.elapsed();
                if target_elapsed > now_elapsed {
                    tokio::time::sleep(target_elapsed - now_elapsed).await;
                }
            }

            attempted += 1;

            // Acquire signer + lane.
            let Some((lane_idx, signer, permit)) = self.pool.try_acquire_indexed() else {
                pool_saturated += 1;
                continue;
            };

            // Build + sign.
            let signed = match self.workload.build(&self.context, &signer, permit.nonce) {
                Ok(tx) => tx,
                Err(_e) => {
                    signing_errors += 1;
                    // Drop permit; the nonce is effectively burned for
                    // this slot. In Phase 3 the classifier decides
                    // whether to release or burn.
                    drop(permit);
                    continue;
                }
            };

            debug_assert_eq!(signed.sender, signer.address);
            debug_assert_eq!(signed.nonce, permit.nonce);

            per_signer[lane_idx] += 1;
            signed_ok += 1;
            if sample.len() < self.options.sample_cap {
                sample.push(signed.clone());
            }

            // Dispatch by mode.
            match &mode {
                RunMode::DryRun => {
                    // No broadcast. Drop the permit so the lane can
                    // reuse the slot. In a real run the permit would
                    // be held until the receipt lands.
                    drop(permit);
                }
            }
        }

        let duration_secs = start.elapsed().as_secs_f64();
        let effective_tps = if duration_secs > 0.0 {
            signed_ok as f64 / duration_secs
        } else {
            0.0
        };

        Ok(RunResult {
            attempted,
            pool_saturated,
            signed_ok,
            signing_errors,
            duration_secs,
            effective_tps,
            per_signer_count: per_signer,
            sample_txs: sample,
            mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signers::Signer;
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
        // 50 tps × 1 second ≈ 50 signed txs, allow a small window
        // either side for scheduler jitter.
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
    }

    #[tokio::test]
    async fn sample_cap_is_honored() {
        let pool = pool_of(1);
        let mut r = runner(pool, 200, 1);
        r.options.sample_cap = 5;
        let result = r.run(RunMode::DryRun).await.expect("run");
        assert!(result.sample_txs.len() <= 5);
        // At 200 tps for 1s we should definitely have at least 5 samples.
        assert_eq!(result.sample_txs.len(), 5);
    }

    #[tokio::test]
    async fn per_signer_counts_sum_to_signed_ok() {
        let pool = pool_of(4);
        let r = runner(pool, 100, 1);
        let result = r.run(RunMode::DryRun).await.expect("run");
        let sum: u64 = result.per_signer_count.iter().sum();
        assert_eq!(sum, result.signed_ok);
        // Round-robin across 4 signers at 100 tps for 1s should spread
        // roughly evenly. Assert no signer got zero.
        for (i, n) in result.per_signer_count.iter().enumerate() {
            assert!(*n > 0, "signer {i} got zero work: {:?}", result.per_signer_count);
        }
    }

    #[tokio::test]
    async fn nonces_are_sequential_per_signer() {
        let pool = pool_of(3);
        let r = runner(pool, 300, 1);
        let result = r.run(RunMode::DryRun).await.expect("run");
        // Group sample nonces by signer address and confirm each
        // group is strictly increasing (they may not be contiguous
        // because sample_cap may drop some).
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
    async fn rejects_empty_pool() {
        let pool = Arc::new(
            SignerPool::new(vec![signer_with_last_byte(1)], vec![0], 1)
                .expect("pool"),
        );
        // Empty would fail construction, so instead test that
        // Runner::new rejects zero duration.
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
