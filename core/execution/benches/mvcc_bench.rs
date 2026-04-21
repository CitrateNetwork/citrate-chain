//! MVCC commit-coordinator throughput benchmarks.
//!
//! Sprint P950-A-4 WP-A.4.4. Measures the cost of the post-tx MVCC commit
//! path (write-set iteration + tracker bump + global version advance).
//!
//! These numbers establish a baseline for the per-tx overhead of MVCC
//! version tracking. They do NOT measure end-to-end TPS (which is
//! dominated by REVM execution + state I/O, not commit bookkeeping);
//! that benchmark lives in `tests/load/` and is run against a live node.
//!
//! Run with:
//!     cargo bench -p citrate-execution --bench mvcc_bench

use citrate_execution::mvcc::{CommitCoordinator, WriteSet};
use citrate_execution::types::Address;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::thread;

fn addr(n: u64) -> Address {
    let mut a = [0u8; 20];
    a[..8].copy_from_slice(&n.to_be_bytes());
    Address(a)
}

fn make_write_set(n_accounts: usize) -> WriteSet {
    let mut ws = WriteSet::new();
    for i in 0..n_accounts {
        ws.record_write(addr(i as u64));
    }
    ws
}

/// Single commit latency as a function of write-set size.
fn bench_commit_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_writes_serialized");
    for &size in &[1usize, 2, 4, 8, 16, 64, 256] {
        let coord = CommitCoordinator::new();
        let ws = make_write_set(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &ws, |b, ws| {
            b.iter(|| {
                let v = coord.commit_writes_serialized(black_box(ws));
                black_box(v);
            });
        });
    }
    group.finish();
}

/// Sustained throughput over N sequential commits.
fn bench_sustained_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("sustained_commit");
    for &ntxs in &[100usize, 1000, 10_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(ntxs),
            &ntxs,
            |b, &ntxs| {
                b.iter(|| {
                    let coord = CommitCoordinator::new();
                    let mut ws = WriteSet::new();
                    ws.record_write(addr(1));
                    ws.record_write(addr(2));
                    for _ in 0..ntxs {
                        let v = coord.commit_writes_serialized(black_box(&ws));
                        black_box(v);
                    }
                });
            },
        );
    }
    group.finish();
}

/// Version-of lookup latency with a large pre-populated tracker.
fn bench_version_of_lookup(c: &mut Criterion) {
    let coord = CommitCoordinator::new();
    let mut ws = WriteSet::new();
    for i in 0..10_000u64 {
        ws.record_write(addr(i));
    }
    coord.commit_writes_serialized(&ws);

    let tracker = coord.tracker().clone();
    c.bench_function("tracker_version_of_lookup", |b| {
        b.iter(|| {
            let v = tracker.version_of(black_box(&addr(5000)));
            black_box(v);
        });
    });
}

/// Concurrent commit contention: N threads all commit 100 txs each.
fn bench_concurrent_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_commit");
    for &n_threads in &[1usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(n_threads),
            &n_threads,
            |b, &n_threads| {
                b.iter(|| {
                    let coord = Arc::new(CommitCoordinator::new());
                    let handles: Vec<_> = (0..n_threads)
                        .map(|t| {
                            let coord = Arc::clone(&coord);
                            thread::spawn(move || {
                                let mut ws = WriteSet::new();
                                ws.record_write(addr(t as u64));
                                for _ in 0..100 {
                                    coord.commit_writes_serialized(&ws);
                                }
                            })
                        })
                        .collect();
                    for h in handles {
                        h.join().unwrap();
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_commit_throughput,
    bench_sustained_commit,
    bench_version_of_lookup,
    bench_concurrent_commit
);
criterion_main!(benches);
