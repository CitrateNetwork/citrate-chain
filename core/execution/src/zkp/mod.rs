// citrate/core/execution/src/zkp/mod.rs
//
// EXPERIMENTAL: Zero-knowledge proof generation and verification.
//
// Current status: Circuit implementations use simplified/placeholder logic:
// - InferenceProofCircuit: hardcoded 100 neurons/layer, XOR commitment
// - StateTransitionCircuit: allocates variables but enforces no constraints
// - GradientProofCircuit: constraint checks commented out
//
// Production Groth16 verification is gated behind `zkp_production` feature
// in core/mcp/src/verification.rs. Without that feature, the MCP layer uses
// commitment-based verification instead of Groth16.

pub mod backend;
pub mod circuits;
pub mod prover;
pub mod types;
pub mod verifier;

pub use backend::ZKPBackend;
pub use prover::Prover;
pub use types::{Proof, ProvingKey, VerifyingKey, ZKPError};
pub use verifier::Verifier;
