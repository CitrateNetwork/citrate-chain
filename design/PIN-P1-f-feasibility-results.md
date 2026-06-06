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

## Current results

> **No run captured yet.** First run captures the scaling curve at
> `N ∈ {256, 1024, 4096}, L ∈ {3, 5, 11}, K ∈ {3, 11, 22}`.

| Stage                | N=256, L=3 | N=1024, L=3 | N=4096, L=3 | N=1024, L=5 | N=1024, L=11 |
|----------------------|------------|-------------|-------------|-------------|--------------|
| `seal_secs`          | TBD        | TBD         | TBD         | TBD         | TBD          |
| `witness_build_secs` (K=3) | TBD  | TBD         | TBD         | TBD         | TBD          |
| `mockprover_k1_secs` | TBD        | TBD         | TBD         | TBD         | TBD          |
| `mockprover_k3_secs` | TBD        | TBD         | TBD         | TBD         | TBD          |

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
