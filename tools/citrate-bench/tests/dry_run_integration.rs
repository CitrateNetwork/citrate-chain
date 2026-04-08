//! Integration test: end-to-end dry-run using only the crate's public API.
//!
//! This file lives in `tests/` so it is compiled against `citrate-bench`
//! as an external consumer would — no access to `#[cfg(test)]` helpers,
//! no crate-internal items. If the public API breaks, these tests break
//! first.
//!
//! The test creates a real eth-keystore V3 file with a known passphrase,
//! then runs the crate's full pipeline: `keystore::load_many` →
//! `SignerPool::new` → `Runner::new` → `Runner::run(DryRun)`. No chain
//! is required; the runner only builds and signs transactions.

use std::sync::Arc;

use citrate_bench::address_table::AddressTable;
use citrate_bench::runner::{RunMode, RunOptions, Runner};
use citrate_bench::signers::keystore;
use citrate_bench::signers::pool::SignerPool;
use citrate_bench::workload::classroom::ClassroomTransferStudent;
use citrate_bench::workload::forwarder::ForwarderExecute;
use citrate_bench::workload::inference_router::InferenceRouterRequest;
use citrate_bench::workload::learning_pool::LearningPoolJoin;
use citrate_bench::workload::mix::{MixEntry, MixedWorkload};
use citrate_bench::workload::transfer::SimpleTransfer;
use citrate_bench::workload::wrapped_salt::WrappedSaltTransfer;
use citrate_bench::workload::{WorkloadClass, WorkloadContext};

/// Create `count` eth-keystore V3 files in `dir`, named `bench-01`,
/// `bench-02`, ... all encrypted with `passphrase`. Returns the
/// decrypted private key bytes so the test can independently verify
/// the derived sender addresses.
fn make_keystores(dir: &std::path::Path, count: usize, passphrase: &str) -> Vec<[u8; 32]> {
    use rand::rngs::OsRng;
    let mut keys = Vec::with_capacity(count);
    for i in 1..=count {
        let name = format!("bench-{i:02}");
        let mut rng = OsRng;
        let (raw, filename) = eth_keystore::new(dir, &mut rng, passphrase, Some(&name))
            .expect("new keystore");
        // Defensive: some eth-keystore versions ignore Some(name) and
        // use a uuid instead. Rename if needed.
        let target = dir.join(&name);
        if !target.exists() {
            std::fs::rename(dir.join(&filename), &target).expect("rename keystore");
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        keys.push(k);
    }
    keys
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dry_run_end_to_end_with_real_keystore() {
    let dir = tempfile::tempdir().expect("tempdir");
    let passphrase = "integration-test-passphrase";
    let keys = make_keystores(dir.path(), 3, passphrase);

    // Sanity: derive expected addresses directly from the raw keys
    // via the crate's Signer type, so we can compare against what
    // the dry-run's signed txs report as their sender.
    let expected_addresses: Vec<[u8; 20]> = keys
        .iter()
        .map(|k| {
            citrate_bench::signers::Signer::from_key_bytes(k)
                .expect("signer from raw")
                .address
        })
        .collect();

    // Write passphrase to a file and use the File source (same path
    // the ceremony rehearsal uses via ETH_PASSWORD).
    let pw_file = tempfile::NamedTempFile::new().expect("pw file");
    std::fs::write(pw_file.path(), passphrase).expect("write pw");

    let accounts = vec![
        "bench-01".to_string(),
        "bench-02".to_string(),
        "bench-03".to_string(),
    ];
    let signers = keystore::load_many(
        dir.path(),
        &accounts,
        &keystore::PassphraseSource::File(pw_file.path().to_path_buf()),
    )
    .expect("load_many");
    assert_eq!(signers.len(), 3);

    // Compare addresses loaded via keystore to those derived directly.
    for (i, s) in signers.iter().enumerate() {
        assert_eq!(
            s.address, expected_addresses[i],
            "keystore-loaded address does not match direct derivation for account {i}"
        );
    }

    // Build the pool with identical starting nonces per signer.
    let pool = Arc::new(
        SignerPool::new(signers, vec![100, 200, 300], 64)
            .expect("pool"),
    );
    assert_eq!(pool.len(), 3);

    // Build the workload + context.
    let workload: Arc<dyn WorkloadClass> = Arc::new(SimpleTransfer::default_bench());
    let ctx = Arc::new(WorkloadContext::for_dry_run(40204, 1_000_000_000));

    // Short burst: 100 tps for 1 second.
    let options = RunOptions::for_dry_run(1, 100);
    let runner = Runner::new(pool, ctx, workload, options).expect("runner");
    let result = runner.run(RunMode::DryRun).await.expect("run");

    // --- Assertions ---

    // The rate limiter should have targeted ~100 tx in 1s. Allow
    // scheduler jitter windows.
    assert!(
        result.signed_ok >= 80 && result.signed_ok <= 120,
        "expected ~100 signed txs, got {}",
        result.signed_ok
    );
    assert_eq!(result.signing_errors, 0);
    assert_eq!(result.pool_saturated, 0, "pool should never saturate in dry-run with 64 slots");

    // Per-signer counts must sum to signed_ok.
    let sum: u64 = result.per_signer_count.iter().sum();
    assert_eq!(sum, result.signed_ok);
    // Round-robin across 3 signers → each gets at least one.
    for (i, n) in result.per_signer_count.iter().enumerate() {
        assert!(*n > 0, "signer {i} got zero work");
    }

    // Every sample tx's sender must be one of the three expected
    // addresses — the dry-run never invented or mis-derived a signer.
    for tx in &result.sample_txs {
        assert!(
            expected_addresses.contains(&tx.sender),
            "sample tx from unknown sender {:?}",
            tx.sender
        );
    }

    // Every sample tx's nonce must be >= the lane's starting nonce.
    // Starting nonces were 100, 200, 300 for lanes 0, 1, 2.
    for tx in &result.sample_txs {
        let idx = expected_addresses
            .iter()
            .position(|a| *a == tx.sender)
            .expect("sample sender is one of the three");
        let lane_start = [100, 200, 300][idx];
        assert!(
            tx.nonce >= lane_start,
            "tx nonce {} below lane {idx} start {lane_start}",
            tx.nonce
        );
    }

    // Effective TPS is a smoke check, not a strict assertion — CI
    // runners under load can miss the target. We only assert it is
    // positive and reasonable.
    assert!(
        result.effective_tps > 50.0 && result.effective_tps < 200.0,
        "effective_tps out of expected window: {}",
        result.effective_tps
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dry_run_is_truly_read_only() {
    // A dry-run must never attempt network I/O. We prove this
    // negatively: if we point the runner at a WorkloadContext with
    // no RPC URL and the run succeeds, the code path can't be
    // quietly reaching the network.
    //
    // This is a weak check (we can't easily hook the network here)
    // but combined with the unit tests it covers the invariant
    // sufficiently for Phase 2.

    let dir = tempfile::tempdir().expect("tempdir");
    let _keys = make_keystores(dir.path(), 1, "pw");
    let signers = keystore::load_many(
        dir.path(),
        &["bench-01".to_string()],
        &keystore::PassphraseSource::Literal("pw".to_string()),
    )
    .expect("load_many");

    let pool = Arc::new(SignerPool::new(signers, vec![0], 16).expect("pool"));
    let workload: Arc<dyn WorkloadClass> = Arc::new(SimpleTransfer::default_bench());
    let ctx = Arc::new(WorkloadContext::for_dry_run(40204, 1));
    let options = RunOptions::for_dry_run(1, 20);
    let runner = Runner::new(pool, ctx, workload, options).expect("runner");

    let result = runner.run(RunMode::DryRun).await.expect("run");
    assert!(result.signed_ok > 0);
    assert_eq!(result.signing_errors, 0);
}

/// Phase 4: every contract workload class must round-trip (build,
/// sign, and verify) against a populated address table via the
/// public API. This test does **not** submit anything — it just
/// proves the data source trace holds: "class → address table →
/// contract → signed tx".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dry_run_mix_exercises_every_workload_class() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _keys = make_keystores(dir.path(), 2, "pw");
    let signers = keystore::load_many(
        dir.path(),
        &["bench-01".to_string(), "bench-02".to_string()],
        &keystore::PassphraseSource::Literal("pw".to_string()),
    )
    .expect("load_many");

    let pool = Arc::new(SignerPool::new(signers, vec![0, 0], 32).expect("pool"));

    // Populate the address table with every contract the Phase 4
    // workloads need. Addresses are dummy but shape-valid.
    let json = r#"{
      "chainId": 40204,
      "contracts": [
        { "name": "WrappedSALT",               "address": "0x1111111111111111111111111111111111111111" },
        { "name": "LearningPool",              "address": "0x2222222222222222222222222222222222222222" },
        { "name": "AIInferenceRouterPortable", "address": "0x3333333333333333333333333333333333333333" },
        { "name": "ClassroomClusterV1",        "address": "0x4444444444444444444444444444444444444444" },
        { "name": "Forwarder",                 "address": "0x5555555555555555555555555555555555555555" }
      ]
    }"#;
    let table: AddressTable = serde_json::from_str(json).expect("parse");

    let mix = MixedWorkload::new(vec![
        MixEntry {
            class: Arc::new(SimpleTransfer::default_bench()),
            weight: 1,
        },
        MixEntry {
            class: Arc::new(WrappedSaltTransfer::default_bench()),
            weight: 1,
        },
        MixEntry {
            class: Arc::new(LearningPoolJoin::default_bench()),
            weight: 1,
        },
        MixEntry {
            class: Arc::new(InferenceRouterRequest::default_bench()),
            weight: 1,
        },
        MixEntry {
            class: Arc::new(ClassroomTransferStudent::default_bench()),
            weight: 1,
        },
        MixEntry {
            class: Arc::new(ForwarderExecute::default_bench()),
            weight: 1,
        },
    ])
    .expect("mix");

    let workload: Arc<dyn WorkloadClass> = Arc::new(mix);
    let ctx = Arc::new(
        WorkloadContext::for_dry_run(40204, 1_000_000_000)
            .with_address_table(Arc::new(table)),
    );

    // 200 txs at 400 tps over 0.5s wall-clock (duration_secs=1 but
    // the rate limiter overshoots short windows). With 6 classes at
    // equal weight, each class should get ~1/6 of the total.
    let options = RunOptions::for_dry_run(1, 400);
    let runner = Runner::new(pool, ctx, workload, options).expect("runner");
    let result = runner.run(RunMode::DryRun).await.expect("run");

    assert_eq!(
        result.effective_mix.len(),
        6,
        "expected all six classes in effective_mix, got {:?}",
        result.effective_mix
    );
    // Every class should have at least one sign. With weights
    // (1,1,1,1,1,1) and >= 6 txs (which trivially holds at 400 tps
    // for 1s) the deterministic dispatcher guarantees this.
    for (name, count) in &result.effective_mix {
        assert!(
            *count > 0,
            "class {name} got zero signs (full mix: {:?})",
            result.effective_mix
        );
    }
    // All class counts should sum to signed_ok.
    let sum: u64 = result.effective_mix.iter().map(|(_, n)| *n).sum();
    assert_eq!(sum, result.signed_ok);
    // No signing errors: every class built cleanly against the table.
    assert_eq!(result.signing_errors, 0);
}
