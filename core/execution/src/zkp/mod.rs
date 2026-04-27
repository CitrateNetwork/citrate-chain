// citrate/core/execution/src/zkp/mod.rs
//
// Zero-knowledge proof substrates.
//
// **Inference verification (production):** lives in `halo2::` —
// Halo2-KZG over BN254. The 0x0108 INFERENCE_PROOF_VERIFY precompile
// dispatches to `halo2::verify_inference_proof`. See ADR-RM-M1b-1.
//
// **Training proofs (legacy Groth16, BLS12-381):** the rest of this
// module — `backend`, `prover`, `verifier`, `circuits`, `types`,
// `mimc`, `poseidon` — supports the gradient/training-round proof
// path. That path is independent of inference verification and has
// its own migration sprint slot (RM-M1c, scoped, not yet active).
//
// **Removed (RM-M1b WP-M1b.5, 2026-04-27):** `inference_proof.rs`
// (Groth16-based InferenceProver/InferenceProof types). The audit at
// `WP_M1B_5_CALLER_AUDIT.md` confirmed zero callers workspace-wide
// before deletion. The Halo2-KZG path in `halo2::` is the sole
// inference-verification substrate going forward.

pub mod backend;
pub mod ceremony;
pub mod circuits;
pub mod halo2;
pub mod mimc;
pub mod poseidon;
pub mod poseidon_bn254;
pub mod prover;
pub mod types;
pub mod verifier;

pub use backend::ZKPBackend;
pub use prover::Prover;
pub use types::{Proof, ProofType, ProvingKey, VerifyingKey, ZKPError};
pub use verifier::Verifier;
