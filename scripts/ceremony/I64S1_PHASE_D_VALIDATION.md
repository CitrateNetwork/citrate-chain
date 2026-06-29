---
created: 2026-06-28
branch: feat/i64-s1-phase-d-validation
author: saul (Larry Klosowski)
status: green
gate: g-validation
---

# I64-S1 Phase D — Validation Report (gate `g-validation`)

Consensus-grade validation of the Q16 `i32 → i64` widening across the quintet:
**unit · integration · adversarial · cross-build + benchmark**. Phase D added
**only test code** (`core/execution/tests/q16_i64_adversarial.rs` + the WP-B3
parity goldens) — zero production-code delta, so it introduces no regression
surface of its own; it *validates* the Phase A production change.

## WP-D1 — Unit (covered, re-verified)

| Suite | Result |
|---|---|
| `q16` lib unit (mod/ops/exp + saturation + caps) | 141 passed (debug + **release**) |
| both precompile wire formats (belnap 0x0110 / routing 0x0111 reject + happy-path) | in the 141 above |
| re-frozen cross-platform goldens (`tests/q16_cross_platform_fixtures.rs`) | 8 passed (debug + **release**) |

Zero `.unwrap()` in the new test code (chain rule); `.expect("…")` with context throughout.

## WP-D2 — Integration (covered by WP-B3 + existing on-chain tests)

| Surface | Where it's proven |
|---|---|
| precompile ⇄ kernel round-trip (referee/aggregate, LoRA, patronage) | `core/federated` parity goldens — `e79c5a63` / `9bda1b5b` / `4000-1800-500` (9/9, debug + **release**) |
| `AggregationChallenge` commit → referee recompute → resolve (dispute game) | `contracts/test/AggregationChallenge.t.sol` (AGG-S1) |
| patronage settlement parity vs co-op `PatronageLedger` | kernel `SettlementRow::patronage_units` golden = coop `FederatedSettlement.t.sol::test_coordinator_settles_round` (4000/1800/500) |
| address preservation (additions-only) | `contracts/test/Create2Determinism.t.sol` |

## WP-D3 — Adversarial (NEW — `tests/q16_i64_adversarial.rs`, 13 tests)

The widened deserializers are the consensus attack surface. Targets the surface
the widening *specifically* created (not a re-run of in-module rejects):

| Class | Tests |
|---|---|
| **OLD i32-width buffer fails-closed under i64 decoder** (the load-bearing widening invariant) | `belnap_rejects_old_i32_width_buffer`, `routing_rejects_old_arch_version_1`, `routing_rejects_old_i32_width_body` |
| misalignment ± the widening delta (4 bytes) | `belnap_misaligned_by_widening_delta_rejected` |
| saturation at the NEW i64 bounds (i128 intermediates; overflow-checks on → a wrap would panic) | `belnap_saturation_at_i64_extremes_no_panic`, `q16_ops_saturate_at_i64_bounds` |
| truncation sweep never panics | `belnap_truncation_sweep_never_panics` |
| property fuzz at the executor boundary — arbitrary bytes never panic + deterministic verdict | `belnap_execute_never_panics`, `routing_execute_never_panics`, `belnap_execute_is_deterministic`, `routing_execute_is_deterministic` (512/512 + 2048-case fuzz) |

Result: **13 passed (debug AND release).**

## WP-D4 — Cross-build determinism + kernel parity + benchmark

* **Profile determinism:** the entire i64 surface is green under BOTH `cargo test`
  (debug, overflow-checks on) and `cargo test --release` (the chain's release
  profile, lto + overflow-checks on): adversarial 13/13, q16 unit 141/141,
  fixtures 8/8, parity 9/9. Pure integer math + explicit saturation ⇒ identical
  bytes across profiles (the kernel's Tier-1 H3 contract).
* **Kernel parity:** chain's pinned `citrate-fed-types` rev reproduces nat's
  frozen goldens bit-for-bit (WP-B3).
* **Benchmark (no >10% regression):** executor-ceiling bench `tps_parallel`
  (disjoint-senders) ran clean — single-worker ≈ 57.75 µs/batch, 8-worker
  ≈ 214 µs median, consistent with the CLAUDE.md baseline (321K tx/s @ 1 worker,
  773K @ 8). **This path deliberately excludes precompiles** (`tps_parallel.rs`:
  "non-precompile recipient"), so the Q16 widening cannot regress it; combined
  with Phase D being test-only, there is no regression surface. The full
  live-node `benchmark-suite` run is a ceremony step (runbook §1/close).

## Repro

```bash
# debug
cargo test -p citrate-execution --test q16_i64_adversarial
cargo test -p citrate-execution --test q16_cross_platform_fixtures
cargo test -p citrate-execution --lib q16
cargo test --manifest-path core/federated/Cargo.toml
# release (cross-build determinism)
cargo test -p citrate-execution --release --test q16_i64_adversarial
cargo test -p citrate-execution --release --lib q16
cargo test --release --manifest-path core/federated/Cargo.toml
# benchmark
cargo bench -p citrate-execution --bench tps_parallel
```

## Gate verdict

`g-validation` = **MET**: unit + integration + adversarial + cross-build all
green in both profiles; benchmark shows no regression (and the changed code is
off the measured path). The re-frozen precompile goldens are the new ratchet.
