# Proof of Inference — how Citrate verifies that a model actually ran

Citrate answers *"did the committed model produce this output?"* with a **layered
model, not a single mechanism.** There are three verification tiers, and they are not
interchangeable: they differ in trust assumptions, cost, and how far they scale. This
document is the canonical reference — cite it, not any one circuit, when describing
Citrate's proof-of-inference posture.

The most important thing to understand first: **the load-bearing tiers are #1
(determinism) and #2 (TEE attestation). The zero-knowledge tier (#3) is an additive
cryptographic guarantee under active research — it is not, and does not claim to be,
Citrate's primary verification today.**

---

## Tier 1 — Deterministic re-execution (Q16.16 fixed-point) — **primary, live**

Inference on the verifiable path runs in **Q16.16 fixed-point integer arithmetic**, not
floating point. Integer ops with a fixed rounding/scaling rule are exact and
order-stable, so the FMA-order / reduction-order / rounding-mode divergences that make
floating-point ML non-deterministic across GPUs **do not arise**. The result is
bit-identical on any hardware.

- **What it proves:** correctness by *re-computation*. Any validator re-runs the
  inference and compares the input/model/output commitments. The determinism **is** the
  proof — no SNARK, no trusted hardware.
- **Scales to whole models** — you just re-run them; there is no per-parameter proving cost.
- **Trust model:** permissionless-economics (re-execution by independent validators).
- **Status:** live via the Q16 precompiles (`core/execution/src/precompiles/q16/`).
  `inference.rs` runs in **strict mode by default** — the non-deterministic FP path is
  disabled on mainnet.
- **Code:** `core/execution/src/precompiles/q16/`, `core/execution/src/precompiles/inference.rs`.
- **Limitation:** only covers what runs inside the fixed-point precompiles; large GPU
  models that can't be re-run cheaply are Tier 2's job.

## Tier 2 — TEE attestation (CM-08) — **for large / GPU / non-deterministic inference**

For models that cannot be deterministically re-executed on-chain, Citrate's answer is a
**trusted execution environment (TEE)**: prove the inference ran inside an attested
enclave, and anchor the enclave measurement on-chain.

- **What it proves:** the output came from the committed model running in a genuine,
  measured enclave (hardware-rooted attestation), without re-execution.
- **Trust model:** committee/hardware-honesty (the enclave vendor + measurement registry).
- **On-chain anchor:** `TEEAttestationRegistry` (deployed). The inference precompile's
  **attestation gate** admits a non-deterministic run only if it presents a valid quote.
- **Status:** registry deployed; the attestation gate's **Phase-1 default is
  `AlwaysReject`** — so large-model inference is currently *disabled* in strict mode
  rather than *attested*. **CM-08** wires real quote verification. **Requires hardware
  (enclave) connections; target: by mainnet.**
- **Code:** `core/execution/src/precompiles/inference.rs` (gate), `attestation` module,
  `contracts/src/boeing/TEEAttestationRegistry.sol`.

## Tier 3 — Zero-knowledge proof of inference — **research frontier, additive**

A cryptographic proof that a committed model produced a committed output, requiring
**neither re-execution nor trusted hardware** — the strongest guarantee, and the hardest
to build.

- **What it proves (v1):** one Q16.16 linear layer `y = (W·x)>>16 + b`, with the input,
  model, and output bound to public Poseidon commitments via in-circuit copy constraints.
- **Honest scope:** v1 (`RM-M1b`, `CIRCUIT_VERSION_LINEAR_Q16`) ships
  `in_dim=2, out_dim=1` — **the smallest non-trivial layer**, and does not yet enforce
  Q16 saturation in-circuit. This is a **foundation, not a full-model proof.**
- **The honest industry context:** ZK-proving a *real* model end-to-end is an **open
  problem nobody has solved at scale.** Citrate does not claim to have; Tier 3 is a
  deliberate, staged research effort to push that edge, not the thing that secures
  inference today.
- **Trust model:** cryptographic (no re-execution, no hardware) — once it covers a
  meaningful model.
- **Status:** v1 circuit + Halo2-KZG verifier precompile (`0x0108`,
  `verify_inference_proof`). Roadmap (saturation range checks, larger dimensions, layer
  composition + nonlinearities, recursion/folding) is tracked in the **"Proof of
  Inference" GitHub project.**
- **Code:** `core/execution/src/zkp/halo2/circuits.rs`, `chips.rs`; verifier in
  `core/execution/src/precompiles/verify.rs`.

---

## How to read a claim about "proof of inference"

| Question | Answer |
|---|---|
| What verifies inference **today**, at model scale? | Tier 1 (determinism) for the fixed-point path; Tier 2 (TEE) is the intended path for large models, gated until CM-08 lands. |
| Is there a ZK proof of a **full** model? | **No** — Tier 3 v1 proves one small linear layer. Full-model ZK is an unsolved frontier; we are researching it, not claiming it. |
| Is the ZK circuit "Citrate's proof of inference"? | **No.** It is one additive tier. Citing it alone misrepresents the design. |

A reviewer who examines only `zkp/halo2/circuits.rs` and concludes the proof-of-inference
is a toy has read the **ZK tier** correctly but **missed tiers 1 and 2**, which are the
load-bearing mechanisms. This document exists so that scoping is unambiguous.

*Owner: Larry Klosowski · Citrate Network.*
