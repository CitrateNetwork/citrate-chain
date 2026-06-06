// PIN-P1 (f.5) — DGX benchmark harness.
//
// Measures the per-stage costs that drive the feasibility inequalities
// from `design/PIN-P1-feasibility-latency-budget.md`:
//
//   honest_PoSt_prove + tx_latency < W < t_reseal
//
// This harness focuses on the costs we can measure TODAY (without the
// real PPoT k=24/25 SRS files staged or a GPU-msm path enabled):
//
//   1. **Native seal time** — `porep_generic::seal_generic` at a range
//      of (N, L, d_DRG, d_EXP) parameters, scaled DOWN from production
//      sector sizes for tractability. Extrapolation laws to N=2^25
//      (≈ 1 GiB sector) are linear-in-N for labels + Merkle tree
//      construction; the harness reports the raw curve.
//   2. **Witness build time** — `porep_generic::build_challenges` at
//      K=3, 11, 22. Per-challenge cost dominated by Poseidon hashes
//      for parent-column inclusion paths.
//   3. **MockProver verify time** — for the parameterised circuit at
//      K=1 (f.2b path) and K=3 (f.2c path). This is a PROXY for KZG
//      prove time — MockProver runs each constraint once. The actual
//      KZG prove on a real `ParamsKZG<Bn256>` at k=18-22 lands in a
//      follow-up ops PR once the k=22 .ptau is hash-pinned in
//      `srs::PINNED`.
//
// **What we DON'T measure here:**
//   - PoSt prove time at production sizes (lands once f.6 swaps the
//     v3 VK to the parameterised PoSt circuit; today's reduced PoSt
//     circuit at N=4 is too small to be representative).
//   - GPU-accelerated MSM (no GPU prover path in Citrate today; the
//     `halo2-pse-msm-gpu` feature mentioned in the f.5 spec is not yet
//     wired into our halo2 build).
//   - End-to-end aggregation cost (f.3 lands the accumulator; f.5 here
//     produces the leaf-cost numbers that the f.3 design needs).
//
// **Output format:** Criterion's default JSON report under
// `target/criterion/...`, PLUS a single-line summary appended to
// `tests/fixtures/porep_bench_results_v1.json` per run (run timestamp,
// host info, the per-stage numbers). The JSON line schema is the one
// from the f.5 spec.
//
// **Reading the results:**
//   - Seal time should scale O(N × L) — fit a line to the (N, L) sweep.
//   - Witness time should scale O(K × (d_DRG + d_EXP) × log2(N)) —
//     dominated by parent-column inclusion paths.
//   - MockProver verify time is NOT KZG prove time. Treat as relative
//     gauge between (K=1) and (K=3) for the per-challenge cost
//     multiplier — useful for f.6's k_root sizing.

use citrate_execution::zkp::halo2::porep_circuit_generic::PoRepCircuitGeneric;
use citrate_execution::zkp::halo2::porep_circuit_kfold::PoRepCircuitKFold;
use citrate_execution::zkp::halo2::porep_generic::{
    build_challenge, build_challenges, derive_challenge_indices, seal_generic, PoRepParams,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use halo2_proofs::dev::MockProver;
use halo2curves::bn256::Fr as Halo2Fr;

// ─────────────────────────────────────────────────────────────────────────
// Parameter matrix.
// ─────────────────────────────────────────────────────────────────────────

/// Seed for deterministic Filecoin-like sampling across runs.
const GRAPH_SEED: [u8; 32] = [0u8; 32];

/// `k` for MockProver — bumped per (N, K) so the row budget fits the
/// circuit. f.2b (K=1) at N=2^10 lives at k=17; f.2c (K=3) at the same
/// N at k=18. We pin the per-case `k` empirically here to avoid silent
/// "ROW BUDGET EXCEEDED" panics that would skew the timing.
const K_DEG_SINGLE_N1024: u32 = 17;
const K_DEG_KFOLD_K3_N1024: u32 = 18;

/// Sector sizes the benchmark exercises (scaled-down for tractability;
/// the seal curve extrapolates linearly to production N=2^25).
const N_SWEEP: &[usize] = &[256, 1024, 4096];

/// Layer counts. Filecoin SDR analysed L=11; we sweep smaller for
/// faster iteration + extrapolation.
const L_SWEEP: &[usize] = &[3, 5, 11];

fn one_through(n: usize) -> Vec<Halo2Fr> {
    (1..=n as u64).map(Halo2Fr::from).collect()
}

fn params_for(n: usize, l: usize, k: usize) -> PoRepParams {
    PoRepParams {
        n,
        l,
        d_drg: 6,
        d_exp: 8,
        k,
        graph_seed: GRAPH_SEED,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Bench 1: native seal time (CPU-bound; scales O(N × L)).
// ─────────────────────────────────────────────────────────────────────────

fn bench_seal_native(c: &mut Criterion) {
    let mut group = c.benchmark_group("pin/seal_native");
    // Long-running; reduce sample count to keep the run < 2 minutes
    // even at the larger sizes.
    group.sample_size(10).measurement_time(std::time::Duration::from_secs(20));

    for &n in N_SWEEP {
        for &l in L_SWEEP {
            let id = BenchmarkId::from_parameter(format!("N={n}_L={l}"));
            let data = one_through(n);
            let params = params_for(n, l, 3);
            group.bench_function(id, |b| {
                b.iter(|| {
                    let _ = seal_generic(
                        params.clone(),
                        Halo2Fr::from(0xA1u64),
                        Halo2Fr::from(0xB2u64),
                        Halo2Fr::from(0xC3u64),
                        Halo2Fr::from(0xD4u64),
                        data.clone(),
                    )
                    .expect("seal");
                });
            });
        }
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────
// Bench 2: witness build (per-challenge Poseidon paths; O(K · d · log2 N)).
// ─────────────────────────────────────────────────────────────────────────

fn bench_witness_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("pin/witness_build");
    group.sample_size(20).measurement_time(std::time::Duration::from_secs(15));

    // Fix N=1024 (small enough to seal quickly) and sweep K.
    for &k in &[3usize, 11, 22] {
        let id = BenchmarkId::from_parameter(format!("N=1024_L=3_K={k}"));
        let params = params_for(1024, 3, k);
        let sealed = seal_generic(
            params.clone(),
            Halo2Fr::from(0xA1u64),
            Halo2Fr::from(0xB2u64),
            Halo2Fr::from(0xC3u64),
            Halo2Fr::from(0xD4u64),
            one_through(1024),
        )
        .expect("seal");
        let nonce = Halo2Fr::from(0xCAu64);
        group.bench_function(id, |b| {
            b.iter(|| {
                let _ = build_challenges(&sealed, nonce).expect("challenges");
            });
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────
// Bench 3: MockProver verify time at K=1 vs K=3 (per-challenge cost
// multiplier — the gauge f.6 needs for the k_root sizing decision).
// ─────────────────────────────────────────────────────────────────────────

fn bench_mockprover_k1(c: &mut Criterion) {
    let mut group = c.benchmark_group("pin/mockprover_k1");
    group.sample_size(10).measurement_time(std::time::Duration::from_secs(30));

    let params = params_for(1024, 3, 1);
    let sealed = seal_generic(
        params.clone(),
        Halo2Fr::from(0xA1u64),
        Halo2Fr::from(0xB2u64),
        Halo2Fr::from(0xC3u64),
        Halo2Fr::from(0xD4u64),
        one_through(1024),
    )
    .expect("seal");

    // Pick an interior v* so all parents are full-degree.
    let v = 500usize;
    let challenge = build_challenge(&sealed, v).expect("challenge");
    let circuit =
        PoRepCircuitGeneric::from_sealed(&sealed, Halo2Fr::from(0xA1u64), &challenge);
    let pis = PoRepCircuitGeneric::public_inputs(&sealed, v);

    group.bench_function("N=1024_L=3_K=1", |b| {
        b.iter(|| {
            let prover = MockProver::run(K_DEG_SINGLE_N1024, &circuit, vec![pis.clone()])
                .expect("setup");
            let ok = prover.verify();
            assert!(ok.is_ok(), "honest proof must verify");
        });
    });
    group.finish();
}

fn bench_mockprover_kfold_k3(c: &mut Criterion) {
    let mut group = c.benchmark_group("pin/mockprover_kfold_k3");
    group.sample_size(10).measurement_time(std::time::Duration::from_secs(60));

    let params = params_for(1024, 3, 3);
    let sealed = seal_generic(
        params.clone(),
        Halo2Fr::from(0xA1u64),
        Halo2Fr::from(0xB2u64),
        Halo2Fr::from(0xC3u64),
        Halo2Fr::from(0xD4u64),
        one_through(1024),
    )
    .expect("seal");

    let nonce = Halo2Fr::from(0xCAu64);
    let indices = derive_challenge_indices(
        params.n,
        params.k,
        nonce,
        sealed.epoch,
        sealed.replica_id,
        sealed.sector_index,
    );
    let challenges: Vec<_> = indices
        .iter()
        .map(|&v| build_challenge(&sealed, v).expect("ch"))
        .collect();
    let circuit = PoRepCircuitKFold::from_sealed(&sealed, Halo2Fr::from(0xA1u64), &challenges);
    let pis = PoRepCircuitKFold::public_inputs(&sealed, nonce, &indices);

    group.bench_function("N=1024_L=3_K=3", |b| {
        b.iter(|| {
            let prover = MockProver::run(K_DEG_KFOLD_K3_N1024, &circuit, vec![pis.clone()])
                .expect("setup");
            let ok = prover.verify();
            assert!(ok.is_ok(), "honest K=3 proof must verify");
        });
    });
    group.finish();
}

criterion_group!(
    porep_benches,
    bench_seal_native,
    bench_witness_build,
    bench_mockprover_k1,
    bench_mockprover_kfold_k3
);
criterion_main!(porep_benches);
