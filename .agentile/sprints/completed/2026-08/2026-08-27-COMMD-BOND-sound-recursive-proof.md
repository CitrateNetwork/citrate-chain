---
created: 2026-08-27T21:50:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: completed
issue: citrate-chain#170
adr: ADR-2026-08-27-pin-commd-bond-zk-challenge
---

# COMMD-BOND — sound the IPFSIncentivesV3 model-owner CommD bond (citrate-chain#170)

Make the model-owner CommD bond **sound**: an honestly-registered bond must be impossible to
grief-slash. Retroactive record of the M1–M4 build (the work was issue-driven; this sprint file is
the operational truth, written at close).

## Source of truth (link, don't copy — Rule 9)
- Issue: citrate-chain#170. Finding: citrate-core `docs/FINDING_PIN_COMMD_BOND_2026-08-26.md`.
- Design: `citrate-federation/.agentile/adrs/ADR-2026-08-27-pin-commd-bond-zk-challenge.md`.
- Spec: `citrate-federation/.agentile/gtm-spine/formal/PINIncentiveV4.tla` (`ChallengeWrongCommD`).

## Why (the defect, verified in source)
`IPFSIncentivesV3.challengeWrongCommD(cid, data, recomputedCommD)` trusted an **arbitrary
caller-supplied** `recomputedCommD` and never recomputed the root from `data`. Passing the
`keccak256(data) == dataHash` identity gate is trivial for a public file, so **anyone could supply any
differing 32 bytes and slash 50% of an honest owner's bond.** This blocked Commons CX-S2.2 (the desktop
pin-bond client): posting real SALT against a grief-slashable bond is a Rule-1 violation.

Three defects: **D1** grief-slashable challenge; **D2** no canonical byte→CommD existed; **D3** deployed
params diverged from the ADR (window 100 vs 302400; MIN_MODEL_BOND 5 vs 55 ether).

## Decision (recorded)
- **D2 = (b)** Citrate-native fr32→Poseidon-BN254 CommD (extends the 0x0108 Poseidon substrate; no
  re-version).
- **D1 = non-interactive RECURSIVE proof.** An impossibility surfaced early: an opaque owner-asserted
  root forces an O(N) recompute to refute, and there is no non-interactive, non-recursive, sound
  challenge at GB scale. Owner chose the recursive path (Nova folding) over the O(log N)-Solidity
  fallback. This authored the ADR first.

## Acceptance / definition of done
- **Invariant:** no `computeCommD(data)` registration is slashable; a genuinely-wrong one is slashable
  exactly once in-window. (Foundry `test_honestRegistration_cannotBeGriefSlashed` + siblings.)
- Cross-impl agreement: `citrate-commd` frozen vectors == the fold/circuit CommD for the same bytes.
- The full prover→verifier pipeline exists and verifies end-to-end; a single VK covers every file size.
- Params fixed (D3); ADR authored; #170 updated.

## Status log (Rule 4 — this file is the truth)
- **M1 foundation (#171):** `crates/citrate-commd` — `compute_comm_d`/`compute_data_commit` (fr32
  31-byte→BN254 pack + Poseidon-BN254 Merkle root; domain-separated sponge `CTZ/dataCommit/v1`), frozen
  v1 vectors, `IncrementalMerkle` + `CommDFold` references, M1b halo2 `commd_step.rs`. Build fix: dropped
  the `bn256-table` halo2curves feature (its build.rs wrote into the read-only registry).
- **M2b (#172):** bellpepper Poseidon-BN254 gadget **bit-identical** to native `poseidon_hash`
  (`permute([0,a,b])[1]`), + incremental-Merkle Nova fold reproducing `compute_comm_d` in-circuit.
  Isolated workspace `crates/citrate-commd-fold` so Nova never unifies with the pinned PSE-halo2/ark-0.4.
- **M2b-cont (#173):** `commD`↔`dataCommit` bound in ONE fold (`CommDBindFoldStep`), the leaf↔identity
  binding the soundness argument rests on. Native `compute_data_commit_streaming` de-risked the sponge
  fold before circuit-izing.
- **M2c (#174):** succinct `CompressedSNARK` (Spartan/HyperKZG) — proof ~11.8 KB (calldata-fits), vk
  ~14.8 MB (baked). Serialize round-trip + bound-to-public-inputs tests.
- **M4 contract (#175):** rewrote `challengeWrongCommD(cid, proof, numSteps, depth, z0)` → verify via
  `IFoldVerifier` + require `dataCommit == reg.dataCommit` + slash iff `trueCommD != reg.commD`; dropped
  `recomputedCommD` + the keccak gate; added `dataCommit` to registration; D3 params. **No-grief
  invariant passes** against a faithful `MockFoldVerifier`.
- **M3 kernel (#176):** `crates/citrate-commd-verify` — node-linkable `verify_fold_proof`. **Dep-link
  validated:** Nova (halo2curves 0.9) coexists with pinned PSE-halo2 (0.7); `citrate-execution
  --features halo2-substrate` builds with Nova present.
- **M3 fixed-arity (#177):** `FixedCommDFoldStep` — constant arity (MAX_DEPTH=40), masks levels ≥ the
  file's depth ⇒ commD == `compute_comm_d` (not re-versioned) with ONE R1CS shape ⇒ **one VK verifies
  every file size** (`one_verifier_key_covers_different_file_sizes`).
- **M3 wiring/tooling (#178):** `bake_vk` (ptau/dev → single VK + blake3) + feature-gated `0x0130`
  precompile (`commd_fold_verify.rs`, ABI decoder always-on + unit-tested; verify + baked VK behind OFF
  `commd-fold-verify`). Default build excludes Nova; feature-ON compiles+links Nova+VK.

## Acceptance check-off
- [x] No-grief invariant proven (contract, Foundry). — `test_honestRegistration_cannotBeGriefSlashed`
- [x] Fold reproduces canonical CommD + dataCommit in-circuit, verified. — M2b/M2b-cont
- [x] Single VK across file sizes. — M3 fixed-arity
- [x] Node-linkable verifier; Nova ⊕ pinned-halo2 coexist. — M3 kernel
- [x] Params D3 in the deploy script; ADR authored; #170 updated.
- [ ] **Trusted-setup ceremony → prod VK** — owner/ops, not code.
- [ ] **Fleet-activate 0x0130 (consensus fork)** — owner/ops.
- [ ] **Redeploy IPFSIncentivesV3 on 40204** + address JSONs — owner/ops, after activation.

## Retrospective

**What went right.** The impossibility was named before any code — an opaque asserted root cannot be
refuted without an O(N) recompute, so the honest path was recursion, and the ADR said so first. Every
hard layer was **de-risked natively before circuit-izing**: the Poseidon reduction (`permute([0,a,b])[1]`),
the streaming Merkle, the streaming sponge, and the masked fixed-depth walk each got a native reference
proven byte-equal to the canonical output *before* a single R1CS constraint was written. That turned the
scariest question ("does the gadget match native to the bit?") into a differential unit test, and the
circuits mostly worked on the first honest attempt.

**The three findings that only surfaced by building it.** (1) The Nova prover **cannot** live in the
consensus workspace (its ark/test-utils stack), but the *verifier* **can** — halo2curves 0.7 and 0.9
coexist; the isolation was about the prover, not the verifier. (2) The variable-`depth` circuit that made
M2 clean is **incompatible with a single baked VK** — the R1CS shape, hence the key, depends on depth.
The fix (a fixed `MAX_DEPTH` walk that masks below-depth levels) preserves `compute_comm_d` exactly, so it
cost no re-version. (3) A GB file is `O(N·MAX_DEPTH)` ≈ 1e9 hashes to prove — correctness is done but
production proving needs GPU/parallel infra, a separate track.

**What I want to remember.** The bug TLA+ could not catch was a *category*, not a transition:
`ChallengeWrongCommD` modeled the money split but never the correctness predicate, so grief and
legitimate slashes were the same state move and conservation held either way. Formal-green is only as
honest as the questions the model poses. Documented in the spec, enforced by the proof — not the state
machine. (See the essay of the same date.)

**Process note.** `cargo fmt -p citrate-execution` reflows the whole crate (a large latent fmt debt);
touching one file there means `rustfmt` *that file only*, never `git add core/execution/` broadly, or the
commit drowns in unrelated churn. Cost one force-push to clean.
