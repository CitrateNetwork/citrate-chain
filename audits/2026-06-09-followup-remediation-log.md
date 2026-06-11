---
created: 2026-06-11T00:00:00Z
branch: audit/secrem02-chain-blockstore-ct
author: Fable 5 (Claude Code)
sprint: SECREM-02-followup-remediation
status: active
repo: citrate-chain
baseline_test_count: "citrate-storage 203 / citrate-api 244 (package-scoped)"
---

# citrate-chain — SECREM-02 Remediation Log

> Coverage matrix: `citrate-security/planset/2026-06-10-followup-remediation.md`.
> SECREM-01 (the 39 pre-audit findings) has its own log:
> `2026-06-09-SECREM-01-remediation-log.md`. This log covers only the
> SECREM-02 WP 5.6 items.

## Phase 5 — WP 5.6

| Finding | Sev | Red test(s) | Fix (file) | Suite | Mutation | Disposition |
|---|---|---|---|---|---|---|
| FUA-CHAIN-01 | Med | `test_fua_chain_01_concurrent_sibling_puts_keep_all_child_links` (8 racing siblings), `…_height_never_regresses_under_concurrency` (16 racing heights), `…_duplicate_put_does_not_duplicate_child_link` — all FAILED pre-fix (races reproduced 3/3 runs; duplicate deterministic) | `put_block` holds a `put_lock` mutex across the children/height read-modify-writes + batch commit (poison-recovering); children list deduped on re-put — `core/storage/src/chain/block_store.rs` | storage 206 ✓ (+3) | M1 (lock removed) killed 3/3 runs; M2 (dedupe removed) killed | **FIXED** |
| prior 2026-05-31 -006 (non-CT operator-token compare, SECREM-01 coverage gap) | Low | `constant_time_eq_semantics` + source tripwires `operator_token_compare_is_constant_time_source_tripwire`, `api_key_compare_is_constant_time_source_tripwire` | New `server::constant_time_eq` (XOR-accumulate, no early exit); used by `require_operator_auth` (gates emergencyPause/resume/model mutation) and the API-key middleware check — `core/api/src/server.rs`, `core/api/src/rate_limit.rs` | api 247 ✓ (+3) | M3/M4 (revert either compare to `==`) killed by the source tripwires | **FIXED** |

## Notes
- Suites run package-scoped (`-p citrate-storage`, `-p citrate-api`) — both fully
  green, counts up by exactly the new tests. Full-workspace Rule-2 ratchet rides
  the repo's CI.
- Clippy clean on both touched crates (`--all-targets`).
- `put_block` was already serialized in practice by the fsync'd
  `write_batch_sync` commit; the mutex adds one uncontended lock around an
  fsync-dominated path, so the 5K TPS network baseline is unaffected
  (Rule 6). The `benchmark-suite` live-node run is deferred to the next
  chain-freeze ops window (PIL-14) — noted, not skipped silently.
- A timing-leak revert is invisible to behavioural tests, hence the
  source-tripwire pattern (same approach as district-registration 5.7);
  the Phase-8 Semgrep rule will encode the class repo-wide.
- FUA-CHAIN-02/03 (mnemonic zeroization, forge CLI key) are **KEYSAFE K2**
  scope, not this WP.
