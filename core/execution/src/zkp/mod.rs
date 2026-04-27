// citrate/core/execution/src/zkp/mod.rs
//
// EXPERIMENTAL: Zero-knowledge proof generation and verification.
//
// Current status: Circuit implementations use simplified/placeholder logic:
// - InferenceProofCircuit: configurable neurons/layer, MiMC commitment
// - StateTransitionCircuit: allocates variables but enforces no constraints
// - GradientProofCircuit: constraint checks commented out
// - mimc: MiMC hash (220 rounds, x^3) for R1CS-friendly commitments
//
// Production Groth16 verification is gated behind `zkp_production` feature
// in core/mcp/src/verification.rs. Without that feature, the MCP layer uses
// commitment-based verification instead of Groth16.

pub mod backend;
pub mod ceremony;
pub mod circuits;
pub mod halo2;
pub mod inference_proof;
pub mod mimc;
pub mod poseidon;
pub mod prover;
pub mod types;
pub mod verifier;

pub use backend::ZKPBackend;
pub use prover::Prover;
pub use types::{Proof, ProofType, ProvingKey, VerifyingKey, ZKPError};
pub use verifier::Verifier;
