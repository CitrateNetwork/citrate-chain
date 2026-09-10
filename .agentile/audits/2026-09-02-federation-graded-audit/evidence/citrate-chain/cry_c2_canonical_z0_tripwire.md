---
created: 2026-09-06T00:00:00Z
branch: prep/rm-q-chain-nonconsensus
author: Codex
status: active
---

# CRY-C2 canonical initial-state tripwire

## Finding

`CRY-C2` identified that the CommD fixed-fold verifier accepted the caller-supplied
Nova initial state without reconstructing it from `num_steps` and `depth`. In the
old path, a proof generated with a non-canonical initial `filled[0]` state verified.

## Red-first reproduction

The isolated parent snapshot was temporarily instrumented only for the witness to
set `z0[0] = Scalar::ONE` while generating the proof. The old verifier then
accepted the proof, causing the rejection assertion to fail:

```text
test cry_c2_forged_initial_state_is_rejected ... FAILED
fold verifier must reject a proof whose initial state is non-canonical
test result: FAILED. 0 passed; 1 failed
```

Command:

```text
cargo test --locked --manifest-path crates/citrate-commd-verify/Cargo.toml --test cry_c2_tripwire
```

The temporary prover mutation was removed before the remediation was committed.

## Green verification

The fixed verifier reconstructs the canonical initial state from `num_steps` and
the explicit `depth`, requires the supplied `z0` to have the exact fixed arity,
and rejects any mismatch before Nova proof decoding/verification:

```text
test cry_c2_forged_initial_state_is_rejected ... ok
test result: ok. 1 passed; 0 failed
```

The fixed test also passed the real compressed proof path with the supplied
initial state mutated at `filled[0]`, and observed
`VerifyError::NonCanonicalInitialState`.

## Scope and release gate

- `canonical_initial_state(num_steps, depth)` enforces nonzero leaves, the
  fixed maximum depth, and the derived leaf-count/depth relationship.
- The circuit derives `is_last` from the fold position and retains the canonical
  depth binding in the public state.
- `0x0130` remains feature-gated and fail-closed by default.
- This is prepared-held for the coordinated reroll; no existing deployment was
  migrated or modified.
