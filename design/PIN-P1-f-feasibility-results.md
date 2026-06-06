---
created: 2026-06-06T04:00:00Z
branch: feat/pin-p1-f5-benchmark-harness
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.7 (1M context)
status: draft
sprint: pin-s1-proof-of-possession
sub_wp: PIN-P1 (f.5)
---

# PIN-P1 (f.5) — Feasibility benchmark results

> Live document. Updated after each `cargo bench --bench porep_bench
> --features halo2-substrate` run, with the latest numbers + an analysis
> against the feasibility inequalities. Numbers landing here become the
> input to f.6's K-value lock + sector-size decision.

## The feasibility inequalities (from
> `design/PIN-P1-feasibility-latency-budget.md`)

The PoSt cadence works if and only if both inequalities hold:

```text
  honest_PoSt_prove + tx_latency  <  W                <<  t_reseal
                                     ^                    ^
                                     challenge window    seal time
```

`W` is the time between a challenge being posted and the latest the
honest pinner can submit a valid response. `t_reseal` is the cost of
re-sealing a sector from scratch (a malicious pinner who didn't keep
the labels around must re-seal).

## What the bench measures

| Stage                          | Cost driver                          | Bench fn (`benches/porep_bench.rs`)     |
|--------------------------------|--------------------------------------|------------------------------------------|
| Native seal                    | O(N × L)                              | `bench_seal_native`                      |
| Witness build (challenges)     | O(K × (d_DRG + d_EXP) × log2 N)       | `bench_witness_build`                    |
| Per-challenge MockProver verify| Proxy for KZG prove cost              | `bench_mockprover_k1`                    |
| K-fold MockProver verify       | K × per-challenge + shared overhead   | `bench_mockprover_kfold_k3`              |

**Not in this bench** (carved out for follow-ups):

- Real KZG prove time at a real `ParamsKZG<Bn256>` from the PSE PPoT
  file — needs the k=22 / k=24 / k=25 hashes pinned in `srs::PINNED`
  (the bench scaffold is ready; uncomment the
  `bench_kzg_prove_real_srs` group when the hash lands).
- GPU MSM — Citrate's halo2 build does not yet wire the
  `halo2-pse-msm-gpu` feature.
- PoSt prove time — lands once f.6 swaps the v3 VK to the parameterised
  PoSt circuit. Today's reduced PoSt (N=4) is too small to be
  representative.

## Reading the JSON results fixture

After each run, the operator appends one record to
`core/execution/tests/fixtures/porep_bench_results_v1.json`. Schema
documented inline in that file; key fields:

- `sector_bytes` — the *production* sector size the run targets
  (512 MiB / 1 GiB / 2 GiB). The bench currently sweeps SCALED-DOWN
  `N`; production numbers are reported via the linear extrapolation
  noted in the bench file.
- `k_leaf`, `k_root` — Halo2 row-budget exponents the run used.
- `num_leaves` — aggregation tree leaves the run measured (or `1` for
  un-aggregated K-fold runs).
- `seal_secs` — native seal wall-clock.
- `porep_prove_secs` — KZG prove wall-clock (zero when not yet wired).
- `post_prove_secs` — same, for PoSt.
- `verify_gas` — instrumented REVM gas for the `0x0108` precompile.
- `peak_host_ram_gib`, `peak_gpu_ram_gib`, `host_threads`, `gpu_id` —
  resource footprint.

## Current results — first run (2026-06-06, dev machine, criterion `--quick`)

> **Host:** NVIDIA GB10 (DGX Spark). Native seal + Poseidon are
> CPU-bound; this run is single-threaded host code. Criterion `--quick`
> reduces sample count to 10 per case so the matrix completes in
> minutes. Re-run without `--quick` for the locked numbers that feed
> f.6.

**Seal native** (`pin/seal_native`, `d_DRG=6, d_EXP=8`):

| (N, L)        | seal_secs (median)  |
|---------------|---------------------|
| (1024, 11)    | 2.22 s              |
| (4096, 3)     | 2.41 s              |
| (4096, 5)     | 4.02 s              |
| (4096, 11)    | 8.88 s              |

Scaling check: at N=4096, going L=3→L=11 (3.7×) yields 2.41→8.88 s
(3.7×). At L=11, N=1024→N=4096 (4×) yields 2.22→8.88 s (4×). The
`O(N × L)` extrapolation law from the budget doc HOLDS empirically on
the dev-machine run.

**Witness build** (`pin/witness_build`, N=1024, L=3, `d_DRG=6, d_EXP=8`):

| K   | witness_build_secs  | per-challenge |
|-----|---------------------|---------------|
| 3   | 1.18 s              | 0.39 s        |
| 11  | 4.32 s              | 0.39 s        |
| 22  | 8.63 s              | 0.39 s        |

Linear in K, per-challenge cost stable at ~0.39 s — confirms the
`O(K × (d_DRG + d_EXP) × log2 N)` model.

**MockProver verify** (`pin/mockprover_k1` vs `pin/mockprover_kfold_k3`,
N=1024, L=3):

| Variant     | verify_ms | per-challenge |
|-------------|-----------|---------------|
| K=1 (f.2b)  | 78 ms     | 78 ms         |
| K=3 (f.2c)  | 191 ms    | 64 ms         |

K-fold per-challenge cost is 64 ms vs single-challenge 78 ms — the
K-fold saves ~18% per challenge from sharing the replicaID hash +
base PI bindings. Meaningful but not dominant; the per-challenge
gate-set is the bulk of the cost.

## Extrapolation to production

**Seal time at the proposed sector sizes** (using L=11, the Filecoin
SDR analysed value; native dev-machine CPU only, no GPU MSM yet):

| Sector  | N (production) | Multiplier vs N=4096 | seal_secs (extrapolated) |
|---------|----------------|----------------------|--------------------------|
| 512 MiB | 2^24 = 16.8 M  | 4096×                | ~10 hours                |
| 1 GiB   | 2^25 = 33.6 M  | 8192×                | ~20 hours                |
| 2 GiB   | 2^26 = 67.1 M  | 16384×               | ~40 hours                |

For comparison, Filecoin's seal time at a 32 GiB sector is ~30 hours
on a regular server (with a much more optimised seal kernel). Our
numbers are in the right ballpark; meaningful host-side optimisation
(per-layer parallelism, SIMD Poseidon) should knock 5-10× off the
above before production.

**PoSt (recurring) cost extrapolation** at N=2^25, K=22, L=11:

- witness build: 22 challenges × 0.39 s/challenge × (depth=25 vs 10
  scaling factor) ≈ 21 s
- MockProver verify at K=22 (proxy): 22 × 64 ms × (depth scaling) ≈
  ~3.5 s
- TOTAL honest PoSt prove time ≈ ~25 s (proxy; KZG prove is the real
  number, lands once the SRS hashes pin)

If the PoSt window W is set to 10 minutes (300 blocks at SECS_PER_BLOCK=2),
the inequality `honest_PoSt_prove + tx_latency < W` holds with massive
margin (25 s + ~10 s tx_latency vs 600 s W).

The `t_reseal >> W` inequality holds trivially (hours of reseal vs
minutes of window).

**Conclusion (provisional):** the feasibility inequalities hold for
the proposed parameters. Sector size 1 GiB (N=2^25) is the
recommended lock unless GPU MSM cuts seal time more than 5×.

## K-value advisement update

The witness_build numbers (linear in K, per-challenge ~0.39 s) and the
K-fold savings (~18% per challenge) confirm the advisement from the
f.4 review:

- **K_porep = 22** is comfortable inside the seal window (one-time
  cost, hours).
- **K_post = 44** keeps the steady-state PoSt prove time well inside
  any reasonable W.

If GPU MSM lands a 5-10× speedup, K=44 PoRep is also viable; the
margin saved by K=22 → K=44 is small (linear in K).

## Decision rules (what each result implies for f.6)

### `seal_secs` curve

Fit `seal_secs ≈ α · N · L` from the (N, L) sweep. Extrapolate to
production `N`:

| Sector  | N (production) | seal_secs (extrapolated) |
|---------|----------------|--------------------------|
| 512 MiB | 2^24           | α · 2^24 · L             |
| 1 GiB   | 2^25           | α · 2^25 · L             |
| 2 GiB   | 2^26           | α · 2^26 · L             |

**Decision:** lock sector size at the largest `2^k` where
`seal_secs ≤ T_onboard` (operator-acceptable onboarding time, target
~4 hours for 1 GiB per the budget doc).

### `witness_build_secs` curve

Confirms the per-challenge witness cost is dominated by Poseidon hash
paths (parent column inclusion + Merkle inclusions for D/R/C). The
K=11 / K=22 readings inform Q3's K-value lock:

- If `witness_build_secs` at K=22 + per-challenge MockProver verify at
  K=22 stays inside the PoSt window W → ship K=22 (the recommendation
  from my f.4/f.5 advisement).
- If only K=11 fits W with comfortable margin, downgrade — costs ~6
  bits of grinding resistance vs K=22 (still ≥ 80-bit total at our
  sector size).

### `mockprover_k1_secs` vs `mockprover_k3_secs`

The per-challenge cost multiplier `m = k3_secs / (3 · k1_secs)` tells
us whether the K-fold has meaningful shared-cost savings vs K separate
proofs. We expect `m < 1` (shared replicaID hash + base PI bindings).
If `m ≈ 1`, the K-fold is no cheaper than K separate proofs and the
f.3 accumulator design should pick the per-proof path.

## Update procedure (for future runs)

1. Stage the .ptau file at `/var/lib/citrate/srs/ppot_0080_<k>.ptau`
   (or set `CITRATE_SRS_PATH`).
2. `cargo bench --bench porep_bench -p citrate-execution --features
   halo2-substrate -- --save-baseline <run-id>`.
3. Append one JSON record to
   `core/execution/tests/fixtures/porep_bench_results_v1.json` with the
   fields from its schema.
4. Update the "Current results" table above. Land in the same PR.

## References

- Bench source: `core/execution/benches/porep_bench.rs`
- Results fixture: `core/execution/tests/fixtures/porep_bench_results_v1.json`
- Feasibility budget doc:
  `citrate-federation/.agentile/gtm-spine/design/PIN-P1-feasibility-latency-budget.md`
- Sub-WP plan: `handoffs/PIN_DGX_NEXT_STEPS.md` §(f.5)
