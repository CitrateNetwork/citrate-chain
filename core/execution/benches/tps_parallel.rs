// citrate_v0.01.1/core/execution/benches/tps_parallel.rs
//
// Sprint P950-A-5 WP-A.5.4 — End-to-end parallel TPS benchmark.
//
// Measures transaction throughput on the journal-routed executor path
// (Sprint P950-A-5 WP-A.5.1→A.5.3) across worker-count scaling. The
// benchmark simulates the workload from the sprint gate: N independent
// senders submitting M transfers each.
//
// Gate: 8-worker throughput ≥ 2× 1-worker throughput on the
// disjoint-senders workload.
//
// This benchmark deliberately bypasses RPC / networking — it exercises
// only the executor's concurrency model. The benchmark-suite (HTTP
// against a live node) in `tests/load` gives the real-world number;
// this bench gives the executor-internal ceiling.

use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature,
    Transaction as ConsensusTransaction, VrfProof,
};
use citrate_execution::{address_utils, types::Address, Executor, StateDB};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use primitive_types::U256;
use std::sync::Arc;
use tokio::runtime::Runtime;

fn make_pk(seed: u32) -> PublicKey {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&seed.to_le_bytes());
    PublicKey::new(bytes)
}

fn make_addr(seed: u32) -> Address {
    address_utils::normalize_address(&make_pk(seed))
}

fn test_block() -> Block {
    BlockBuilder::new()
        .hash(Hash::new([0xEE; 32]))
        .height(1)
        .timestamp(1_700_000_000)
        .blue_score(10)
        .blue_work(1000)
        .vrf_reveal(VrfProof {
            proof: vec![0u8; 80],
            output: Hash::default(),
        })
        .build_unhashed()
}

fn transfer_tx(
    sender_seed: u32,
    recipient_seed: u32,
    nonce: u64,
) -> ConsensusTransaction {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(&sender_seed.to_le_bytes());
    h[4..12].copy_from_slice(&nonce.to_le_bytes());
    ConsensusTransaction {
        hash: Hash::new(h),
        nonce,
        from: make_pk(sender_seed),
        to: Some(make_pk(recipient_seed)),
        value: 1,
        gas_limit: 100_000,
        gas_price: 1,
        data: vec![],
        signature: Signature::new([0u8; 64]),
        tx_type: None,
        ..Default::default()
    }
}

/// Build a fresh executor with N pre-funded senders (disjoint).
fn fresh_executor(n_senders: u32) -> Arc<Executor> {
    let state_db = Arc::new(StateDB::new());
    let executor = Arc::new(Executor::new(state_db));
    for i in 0..n_senders {
        executor.set_balance(&make_addr(i), U256::from(10_000_000_000u64));
    }
    executor
}

fn bench_parallel_tps(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("parallel_tps_disjoint_senders");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(8));

    const TXS_PER_WORKER: u32 = 20;
    const RECIPIENT_OFFSET: u32 = 100_000;

    for &n_workers in &[1u32, 2, 4, 8] {
        let total_txs = n_workers * TXS_PER_WORKER;
        group.throughput(Throughput::Elements(total_txs as u64));
        group.bench_with_input(
            BenchmarkId::new("workers", n_workers),
            &n_workers,
            |b, &n_workers| {
                b.iter_custom(|iters| {
                    let mut total = std::time::Duration::ZERO;
                    for _iter in 0..iters {
                        let executor = fresh_executor(n_workers);
                        let block = test_block();

                        let start = std::time::Instant::now();
                        rt.block_on(async {
                            let mut handles = Vec::new();
                            for sender in 0..n_workers {
                                let exec = Arc::clone(&executor);
                                let block = block.clone();
                                handles.push(tokio::spawn(async move {
                                    for nonce in 0..TXS_PER_WORKER {
                                        let tx = transfer_tx(
                                            sender,
                                            RECIPIENT_OFFSET + sender,
                                            nonce as u64,
                                        );
                                        let _ = exec.execute_transaction(&block, &tx).await;
                                    }
                                }));
                            }
                            for h in handles {
                                let _ = h.await;
                            }
                        });
                        total += start.elapsed();
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

/// APPLES-TO-APPLES COMPARISON: emulates the pre-A.5.3 serialized
/// execution path by wrapping every `execute_transaction` call in an
/// outer tokio::Mutex. Same code path, same workload, same hardware —
/// the only difference is whether the outer lock serializes execution.
///
/// This isolates "what did removing exec_lock buy us?" independent of
/// the absolute throughput number (which is dominated by the in-memory
/// executor ceiling, not representative of real TPS).
fn bench_serialized_emulated(c: &mut Criterion) {
    use tokio::sync::Mutex as AsyncMutex;

    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("serialized_vs_parallel_same_workload");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(8));

    const TXS_PER_WORKER: u32 = 20;
    const RECIPIENT_OFFSET: u32 = 100_000;
    const N_WORKERS: u32 = 8;

    // Variant A: 8 workers serialized behind an outer mutex (emulates
    // the old `exec_lock` serialization)
    group.throughput(Throughput::Elements((N_WORKERS * TXS_PER_WORKER) as u64));
    group.bench_function("A_serialized_emulated_8workers", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _iter in 0..iters {
                let executor = fresh_executor(N_WORKERS);
                let block = test_block();
                let outer = Arc::new(AsyncMutex::new(()));

                let start = std::time::Instant::now();
                rt.block_on(async {
                    let mut handles = Vec::new();
                    for sender in 0..N_WORKERS {
                        let exec = Arc::clone(&executor);
                        let block = block.clone();
                        let outer = Arc::clone(&outer);
                        handles.push(tokio::spawn(async move {
                            for nonce in 0..TXS_PER_WORKER {
                                let tx = transfer_tx(
                                    sender,
                                    RECIPIENT_OFFSET + sender,
                                    nonce as u64,
                                );
                                // Emulate exec_lock: serialize every call
                                let _g = outer.lock().await;
                                let _ = exec.execute_transaction(&block, &tx).await;
                            }
                        }));
                    }
                    for h in handles {
                        let _ = h.await;
                    }
                });
                total += start.elapsed();
            }
            total
        });
    });

    // Variant B: 8 workers, no outer lock (current branch's design)
    group.bench_function("B_parallel_cas_8workers", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _iter in 0..iters {
                let executor = fresh_executor(N_WORKERS);
                let block = test_block();

                let start = std::time::Instant::now();
                rt.block_on(async {
                    let mut handles = Vec::new();
                    for sender in 0..N_WORKERS {
                        let exec = Arc::clone(&executor);
                        let block = block.clone();
                        handles.push(tokio::spawn(async move {
                            for nonce in 0..TXS_PER_WORKER {
                                let tx = transfer_tx(
                                    sender,
                                    RECIPIENT_OFFSET + sender,
                                    nonce as u64,
                                );
                                let _ = exec.execute_transaction(&block, &tx).await;
                            }
                        }));
                    }
                    for h in handles {
                        let _ = h.await;
                    }
                });
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

/// CONTRACT CALL BENCH: deploys a simple SSTORE contract and measures
/// throughput of contract calls that actually execute EVM opcodes.
/// This represents the "complex tx" path — real contract execution
/// with REVM, storage I/O, gas accounting.
///
/// Expected throughput is SUBSTANTIALLY lower than the transfer bench
/// because:
/// - REVM interprets EVM bytecode (stack machine per opcode)
/// - Storage slot read/write is ~20-100× the cost of a single journal
///   balance write
/// - Gas accounting adds per-opcode overhead
fn bench_contract_calls(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("contract_call_disjoint_callers");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(8));

    // Simple contract: SSTORE(0, 0xDEADBEEF). Runtime bytecode only.
    //
    // PUSH32 0xDEADBEEF (padded to 32 bytes)
    // PUSH1  0
    // SSTORE
    // STOP
    let runtime_code = vec![
        0x7f, // PUSH32
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0xde, 0xad, 0xbe, 0xef, // 32-byte literal
        0x60, 0x00, // PUSH1 0
        0x55, // SSTORE
        0x00, // STOP
    ];

    const TXS_PER_WORKER: u32 = 10;
    const N_WORKERS: u32 = 8;
    const CONTRACT_SEED: u32 = 999_999;

    for &n_workers in &[1u32, N_WORKERS] {
        let total_txs = n_workers * TXS_PER_WORKER;
        group.throughput(Throughput::Elements(total_txs as u64));
        group.bench_with_input(
            BenchmarkId::new("workers", n_workers),
            &n_workers,
            |b, &n_workers| {
                b.iter_custom(|iters| {
                    let mut total = std::time::Duration::ZERO;
                    for _iter in 0..iters {
                        let executor = fresh_executor(n_workers);
                        let contract_addr = make_addr(CONTRACT_SEED);
                        executor.set_code(&contract_addr, runtime_code.clone());
                        let block = test_block();

                        let start = std::time::Instant::now();
                        rt.block_on(async {
                            let mut handles = Vec::new();
                            for sender in 0..n_workers {
                                let exec = Arc::clone(&executor);
                                let block = block.clone();
                                handles.push(tokio::spawn(async move {
                                    for nonce in 0..TXS_PER_WORKER {
                                        let mut h = [0u8; 32];
                                        h[0] = 0xC;
                                        h[1..5].copy_from_slice(&sender.to_le_bytes());
                                        h[5..13]
                                            .copy_from_slice(&(nonce as u64).to_le_bytes());
                                        // Non-empty data + non-precompile recipient
                                        // → executor parses as Call
                                        let tx = ConsensusTransaction {
                                            hash: Hash::new(h),
                                            nonce: nonce as u64,
                                            from: make_pk(sender),
                                            to: Some(make_pk(CONTRACT_SEED)),
                                            value: 0,
                                            gas_limit: 100_000,
                                            gas_price: 1,
                                            data: vec![0xAB; 4],
                                            signature: Signature::new([0u8; 64]),
                                            tx_type: None,
                                            ..Default::default()
                                        };
                                        let _ = exec.execute_transaction(&block, &tx).await;
                                    }
                                }));
                            }
                            for h in handles {
                                let _ = h.await;
                            }
                        });
                        total += start.elapsed();
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_parallel_tps,
    bench_serialized_emulated,
    bench_contract_calls
);
criterion_main!(benches);
