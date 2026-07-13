//! WP-A1.2 — Argon2 v2 calibration bench.
//!
//! Measures the wall-clock cost of `KeyManager::create_account` (Argon2id
//! v2 KDF + AES-GCM seal + JSON write) on the target host. Used to
//! validate that the production parameters (m=65536 KiB, t=3, p=4) sit in
//! the [100 ms, 600 ms] target envelope per `docs/security/KDF_POLICY.md`
//! §5.4.
//!
//! Run via `cargo bench -p citrate-wallet-core --bench argon2_calibration`.
//!
//! The hard gate test is `wallet-core/tests/bench_argon2.rs::bench_argon2_within_envelope`
//! — that one runs in CI and fails the build if the envelope is violated.
//! This criterion bench is for *profiling* the params on a new host, not
//! for the CI gate.

// B1.1-F-1: this bench exercises `KeyManager::create_account` (the native
// Argon2 keystore path), so its body is native-only. Under the lean
// `crypto` build a no-op `main` keeps the bench target compiling.
#[cfg(feature = "native")]
use citrate_wallet_core::keys::KeyManager;
#[cfg(feature = "native")]
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "native")]
use std::path::PathBuf;

#[cfg(feature = "native")]
fn fresh_keystore() -> PathBuf {
    std::env::temp_dir().join(format!("citrate_bench_argon2_{}", uuid::Uuid::new_v4()))
}

#[cfg(feature = "native")]
fn bench_argon2_v2_create_account(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2_v2");
    // KDF cost is ~250 ms; we don't need many samples.
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    group.bench_function("create_account_v2", |b| {
        b.iter(|| {
            let path = fresh_keystore();
            let km = KeyManager::new(&path);
            km.create_account("strongpassword12345", "bench")
                .expect("create_account in bench");
        });
    });

    group.finish();
}

#[cfg(feature = "native")]
criterion_group!(benches, bench_argon2_v2_create_account);
#[cfg(feature = "native")]
criterion_main!(benches);

// Lean build: the bench body is native-only; provide a no-op entry point
// so the bench target still compiles under `--no-default-features`.
#[cfg(not(feature = "native"))]
fn main() {}
