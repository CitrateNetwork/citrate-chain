// citrate/core/execution/src/precompiles/q16/routing.rs
//
// **Routing-model inference precompile (0x0111).**
//
// RM-FL-2: routes a query embedding through a fixed 3-layer MLP and
// returns `(mentor_id, adapter_id, confidence)`. The architecture is
// hardfork-locked at `ARCH_VERSION = 1` with shape:
//   input_dim = 768, hidden_dim = 128, output_dim = 3
//   (canonical params: 115,331 — fits the planset's 100K–500K window).
//
// Forward pass: 3 LinearChip + 2 ReLU + 1 softmax. Q16 saturating
// arithmetic throughout (no floats). Output bit-deterministic on
// every CPU.
//
// **Status (RM-FL-2, WP-2.5 + WP-2.6 — GREEN):**
//   - Types + encode/decode/validate: GREEN.
//   - `forward()`: **LIVE.** Q16 deterministic forward pass —
//     `linear → relu → linear → relu → linear → softmax → argmax`.
//   - `execute()`: precompile entry with gas accounting
//     (`5000 + 4 * params`).
//   - dispatch: wired in `precompiles/mod.rs` at address
//     `0x0000…0111` (Learning page selector 0x11).
//   - Halo2 multi-layer `RoutingCircuit::v1`: **deferred** (per
//     planset risk mitigation §RM-FL-2 — Halo2 multi-layer circuit
//     generalization is the highest-risk WP and overrunning was
//     planned for. 0x0111 ships *without* ZK proof support; ZK
//     follow-up tracked as a carry-forward sub-sprint.)
//   - The 3 `#[ignore = "WP-2.5"]` tests from WP-2.3 are now
//     un-ignored and GREEN.
//
// **Wire format (committed at WP-2.1; subject to property-test pressure):**
//
//   Input bytes (big-endian):
//     arch_version: u32        (4 bytes; rejects mismatch with ARCH_VERSION)
//     input_dim:    u32        (4 bytes; must equal 768)
//     hidden_dim:   u32        (4 bytes; must equal 128)
//     output_dim:   u32        (4 bytes; must equal 3)
//     input:        input_dim * i32     (3072 bytes at canonical shape)
//     W1:           hidden_dim * input_dim * i32     (393_216 at canonical)
//     b1:           hidden_dim * i32                 (512 bytes)
//     W2:           hidden_dim * hidden_dim * i32    (65_536 bytes)
//     b2:           hidden_dim * i32                 (512 bytes)
//     W3:           output_dim * hidden_dim * i32    (1_536 bytes)
//     b3:           output_dim * i32                 (12 bytes)
//   Total at canonical shape: ~464 KB.
//
//   Output bytes (big-endian):
//     mentor_id:    u32       (argmax of softmax over output)
//     adapter_id:   u32       (argmax-derived adapter slot)
//     confidence:   i32       (Q16; max-element of softmax)
//   Total = 12 bytes.
//
// **Caps (DoS protection):**
//   - Strict shape: input_dim == 768, hidden_dim == 128, output_dim == 3
//     (per ARCH_VERSION 1). Any other shape rejected at decode.
//   - MAX_INPUT_BYTES: 1 MiB (cap on the total input length the
//     precompile will ever consider; prevents pathological allocations).
//
// **Determinism guarantee:** every operation uses ONLY i32/i64
// arithmetic via the Q16 substrate. No floats. Verified by tripwire
// `check_routing_quant_q16_only.py` (WP-2.4).
//
// **Architecture lock:** ARCH_VERSION is a `pub const` in this module.
// Changing it requires a hardfork. Verified by tripwire
// `check_routing_arch_locked.py` (WP-2.4).

#![allow(dead_code)] // some helpers exposed for the RM-FL-3 daemon path

use super::ops as q16_ops;
use super::Q16;

// ---------------------------------------------------------------------------
// Architecture-version constant (HARDFORK LOCKED)
// ---------------------------------------------------------------------------

/// Routing-model architecture version. Locked at hardfork. Changing
/// this constant in a non-hardfork release will be caught by the CI
/// tripwire `check_routing_arch_locked.py` (WP-2.4) and by on-chain
/// governance refusing to register a new version without an
/// associated upgrade proposal.
pub const ARCH_VERSION: u32 = 1;

/// Required input dimensionality at ARCH_VERSION 1.
pub const ARCH_V1_INPUT_DIM: u32 = 768;

/// Required hidden dimensionality at ARCH_VERSION 1.
pub const ARCH_V1_HIDDEN_DIM: u32 = 128;

/// Required output dimensionality at ARCH_VERSION 1.
pub const ARCH_V1_OUTPUT_DIM: u32 = 3;

// ---------------------------------------------------------------------------
// Caps
// ---------------------------------------------------------------------------

/// Maximum input length in bytes — covers the canonical shape with
/// margin and rejects pathological inputs at the parse stage.
pub const MAX_INPUT_BYTES: usize = 1 << 20; // 1 MiB

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Routing-model architectural shape. Carried in the wire format
/// header so the precompile can sanity-check before allocating
/// large weight tensors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingShape {
    pub input_dim: u32,
    pub hidden_dim: u32,
    pub output_dim: u32,
}

impl RoutingShape {
    /// Canonical ARCH_VERSION 1 shape. Locked at hardfork.
    pub const V1: RoutingShape = RoutingShape {
        input_dim: ARCH_V1_INPUT_DIM,
        hidden_dim: ARCH_V1_HIDDEN_DIM,
        output_dim: ARCH_V1_OUTPUT_DIM,
    };

    /// Total parameters under this shape: `H*I + H + H*H + H + O*H + O`.
    /// Matches the network: 3 linear layers (W+b each), no skip
    /// connections.
    pub fn params(&self) -> u64 {
        let i = self.input_dim as u64;
        let h = self.hidden_dim as u64;
        let o = self.output_dim as u64;
        h * i + h + h * h + h + o * h + o
    }
}

/// Decoded input. Owning copies of the wire-format slices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingInput {
    pub arch_version: u32,
    pub shape: RoutingShape,
    pub input: Vec<Q16>,
    pub w1: Vec<Q16>,
    pub b1: Vec<Q16>,
    pub w2: Vec<Q16>,
    pub b2: Vec<Q16>,
    pub w3: Vec<Q16>,
    pub b3: Vec<Q16>,
}

/// Forward-pass output: `(mentor_id, adapter_id, confidence)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingOutput {
    pub mentor_id: u32,
    pub adapter_id: u32,
    pub confidence: Q16,
}

/// Decode / validate / forward failures.
///
/// At WP-2.3 there was a `NotImplemented` variant pinning the stub
/// contract; WP-2.5 removed it together with the impl landing.
/// (RM-FL-1 retro item #1 in action: the 3 `#[ignore = "WP-2.5"]`
/// tests in this module are un-ignored at WP-2.5 and become real
/// behavioral assertions, no compile-break churn.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    /// Input shorter than the 16-byte header.
    InputTooShort,
    /// Input length exceeds `MAX_INPUT_BYTES` (DoS guard).
    InputTooLarge,
    /// `arch_version` does not match the chain's `ARCH_VERSION`.
    ArchVersionUnregistered,
    /// Shape doesn't match what `arch_version` requires (e.g. v1 must
    /// have input_dim=768).
    ShapeMismatch,
    /// `dim == 0` for any of input/hidden/output.
    DimZero,
    /// Input length doesn't match the declared `(arch_version, shape)`.
    LengthMismatch,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingError::InputTooShort => write!(f, "input shorter than 16-byte header"),
            RoutingError::InputTooLarge => write!(f, "input exceeds {MAX_INPUT_BYTES} bytes"),
            RoutingError::ArchVersionUnregistered => write!(f, "arch_version unregistered (current: {ARCH_VERSION})"),
            RoutingError::ShapeMismatch => write!(f, "shape mismatch for declared arch_version"),
            RoutingError::DimZero => write!(f, "input/hidden/output dim must be > 0"),
            RoutingError::LengthMismatch => write!(f, "input length does not match declared (arch_version, shape)"),
        }
    }
}

impl std::error::Error for RoutingError {}

// ---------------------------------------------------------------------------
// Header layout
// ---------------------------------------------------------------------------

const HEADER_LEN: usize = 16; // arch_version(4) + 3 dims(4 each)

// ---------------------------------------------------------------------------
// Decode / validate (fully implemented at WP-2.3)
// ---------------------------------------------------------------------------

/// Decode the wire-format input bytes into a `RoutingInput`. Performs
/// length, cap, and arch_version validation; never panics.
pub fn decode(input: &[u8]) -> Result<RoutingInput, RoutingError> {
    if input.len() < HEADER_LEN {
        return Err(RoutingError::InputTooShort);
    }
    if input.len() > MAX_INPUT_BYTES {
        return Err(RoutingError::InputTooLarge);
    }

    let arch_version = u32::from_be_bytes(input[0..4].try_into().expect("4 bytes"));
    let input_dim = u32::from_be_bytes(input[4..8].try_into().expect("4 bytes"));
    let hidden_dim = u32::from_be_bytes(input[8..12].try_into().expect("4 bytes"));
    let output_dim = u32::from_be_bytes(input[12..16].try_into().expect("4 bytes"));

    if input_dim == 0 || hidden_dim == 0 || output_dim == 0 {
        return Err(RoutingError::DimZero);
    }

    // Arch-version check. Currently only ARCH_VERSION 1 is registered.
    // RoutingModelInference.tla::AllInferencesUseRegisteredArch.
    if arch_version != ARCH_VERSION {
        return Err(RoutingError::ArchVersionUnregistered);
    }

    let shape = RoutingShape { input_dim, hidden_dim, output_dim };

    // Shape check for the declared version. v1 requires the canonical
    // shape; future versions plug in here.
    if arch_version == 1 && shape != RoutingShape::V1 {
        return Err(RoutingError::ShapeMismatch);
    }

    // Compute expected body length.
    let i = input_dim as usize;
    let h = hidden_dim as usize;
    let o = output_dim as usize;

    // Compute total Q16 count from the layer dimensions, with checked
    // arithmetic at every step. Pathological dim*dim products can't
    // wrap to a small number that passes the length check.
    let lm = || RoutingError::LengthMismatch;
    let w1_count = h.checked_mul(i).ok_or_else(lm)?;
    let w2_count = h.checked_mul(h).ok_or_else(lm)?;
    let w3_count = o.checked_mul(h).ok_or_else(lm)?;
    let body_q16_count = i
        .checked_add(w1_count).ok_or_else(lm)?
        .checked_add(h).ok_or_else(lm)?           // b1
        .checked_add(w2_count).ok_or_else(lm)?
        .checked_add(h).ok_or_else(lm)?           // b2
        .checked_add(w3_count).ok_or_else(lm)?
        .checked_add(o).ok_or_else(lm)?;          // b3

    let body_bytes = body_q16_count
        .checked_mul(4)
        .ok_or(RoutingError::LengthMismatch)?;
    let expected_total = HEADER_LEN
        .checked_add(body_bytes)
        .ok_or(RoutingError::LengthMismatch)?;

    if input.len() != expected_total {
        return Err(RoutingError::LengthMismatch);
    }

    let mut cursor = HEADER_LEN;

    let input_vec = decode_q16_slice(&input[cursor..cursor + i * 4])
        .ok_or(RoutingError::LengthMismatch)?;
    cursor += i * 4;

    let w1 = decode_q16_slice(&input[cursor..cursor + h * i * 4])
        .ok_or(RoutingError::LengthMismatch)?;
    cursor += h * i * 4;

    let b1 = decode_q16_slice(&input[cursor..cursor + h * 4])
        .ok_or(RoutingError::LengthMismatch)?;
    cursor += h * 4;

    let w2 = decode_q16_slice(&input[cursor..cursor + h * h * 4])
        .ok_or(RoutingError::LengthMismatch)?;
    cursor += h * h * 4;

    let b2 = decode_q16_slice(&input[cursor..cursor + h * 4])
        .ok_or(RoutingError::LengthMismatch)?;
    cursor += h * 4;

    let w3 = decode_q16_slice(&input[cursor..cursor + o * h * 4])
        .ok_or(RoutingError::LengthMismatch)?;
    cursor += o * h * 4;

    let b3 = decode_q16_slice(&input[cursor..cursor + o * 4])
        .ok_or(RoutingError::LengthMismatch)?;
    cursor += o * 4;

    debug_assert_eq!(cursor, input.len());

    Ok(RoutingInput {
        arch_version,
        shape,
        input: input_vec,
        w1,
        b1,
        w2,
        b2,
        w3,
        b3,
    })
}

fn decode_q16_slice(bytes: &[u8]) -> Option<Vec<Q16>> {
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        out.push(Q16::from_raw(i32::from_be_bytes(chunk.try_into().expect("4 bytes"))));
    }
    Some(out)
}

/// Encode a `RoutingOutput` into wire-format bytes (12 bytes total).
pub fn encode_output(output: &RoutingOutput) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&output.mentor_id.to_be_bytes());
    bytes.extend_from_slice(&output.adapter_id.to_be_bytes());
    bytes.extend_from_slice(&output.confidence.0.to_be_bytes());
    bytes
}

/// Validate a programmatically-constructed `RoutingInput` (used by
/// the RM-FL-3 daemon path that decodes from candle weights). `decode`
/// already enforces these on the byte path.
pub fn validate(input: &RoutingInput) -> Result<(), RoutingError> {
    if input.arch_version != ARCH_VERSION {
        return Err(RoutingError::ArchVersionUnregistered);
    }
    if input.shape.input_dim == 0
        || input.shape.hidden_dim == 0
        || input.shape.output_dim == 0
    {
        return Err(RoutingError::DimZero);
    }
    if input.arch_version == 1 && input.shape != RoutingShape::V1 {
        return Err(RoutingError::ShapeMismatch);
    }

    let i = input.shape.input_dim as usize;
    let h = input.shape.hidden_dim as usize;
    let o = input.shape.output_dim as usize;

    if input.input.len() != i {
        return Err(RoutingError::LengthMismatch);
    }
    if input.w1.len() != h * i || input.b1.len() != h {
        return Err(RoutingError::LengthMismatch);
    }
    if input.w2.len() != h * h || input.b2.len() != h {
        return Err(RoutingError::LengthMismatch);
    }
    if input.w3.len() != o * h || input.b3.len() != o {
        return Err(RoutingError::LengthMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Precompile address (Learning page 0x01_01 — selector 0x11)
// ---------------------------------------------------------------------------

/// 20-byte address `0x0000…0111` for routing-model inference. Sits
/// next to Belnap (RM-FL-1's 0x0110) on the Learning page.
pub const ROUTING_INFERENCE: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 0x11,
];

/// Base gas cost (per planset).
const GAS_BASE: u64 = 5_000;
/// Per-parameter gas cost (per planset: `5000 + 4 * params`).
const GAS_PER_PARAM: u64 = 4;

// ---------------------------------------------------------------------------
// Forward pass (WP-2.5 GREEN — Q16 deterministic algorithm)
// ---------------------------------------------------------------------------

/// Run the routing-model forward pass on the decoded input. Returns
/// the (mentor_id, adapter_id, confidence) tuple as wire-format bytes.
///
/// Algorithm (Q16 throughout, no floats):
///
///   l1_pre = W1 · input + b1                  (linear, hidden_dim×input_dim)
///   l1     = ReLU(l1_pre)
///   l2_pre = W2 · l1 + b2                     (linear, hidden_dim×hidden_dim)
///   l2     = ReLU(l2_pre)
///   logits = W3 · l2 + b3                     (linear, output_dim×hidden_dim)
///   probs  = softmax(logits)                  (numerically-stable Q16 softmax)
///   k      = argmax(probs)                    (selected class index)
///
///   mentor_id  = k as u32
///   adapter_id = k as u32                     (v1: same head; future versions
///                                              may decouple via a separate
///                                              output projection)
///   confidence = probs[k]                     (Q16 max-softmax value)
///
/// Determinism: every step uses the Q16 substrate (q16::ops::{linear,
/// relu, softmax}). Verified by tripwire `check_routing_quant_q16_only.py`.
pub fn forward(input: &[u8]) -> Result<Vec<u8>, RoutingError> {
    let decoded = decode(input)?;
    validate(&decoded)?;
    let output = forward_decoded(&decoded);
    Ok(encode_output(&output))
}

/// Inner forward kernel against a decoded `RoutingInput`. Exposed for
/// the RM-FL-3 daemon path (which constructs `RoutingInput` directly
/// from candle weights without round-tripping through bytes).
pub fn forward_decoded(input: &RoutingInput) -> RoutingOutput {
    let i = input.shape.input_dim as usize;
    let h = input.shape.hidden_dim as usize;
    let o = input.shape.output_dim as usize;

    // Layer 1: hidden = ReLU(W1 · input + b1)
    let l1_pre = q16_ops::linear(&input.w1, &input.input, &input.b1, h, i);
    let l1 = q16_ops::relu(&l1_pre);

    // Layer 2: hidden2 = ReLU(W2 · l1 + b2)
    let l2_pre = q16_ops::linear(&input.w2, &l1, &input.b2, h, h);
    let l2 = q16_ops::relu(&l2_pre);

    // Layer 3: logits = W3 · l2 + b3
    let logits = q16_ops::linear(&input.w3, &l2, &input.b3, o, h);

    // Numerically-stable Q16 softmax → argmax.
    let probs = q16_ops::softmax(&logits);
    let (k, conf) = argmax(&probs);

    RoutingOutput {
        mentor_id: k as u32,
        adapter_id: k as u32,
        confidence: conf,
    }
}

/// Argmax over a Q16 vector. Returns `(index, value)`. Empty input
/// returns `(0, Q16::ZERO)` — defensive default; the precompile path
/// guarantees output_dim > 0 via `validate()` so this is unreachable
/// in production.
fn argmax(values: &[Q16]) -> (usize, Q16) {
    if values.is_empty() {
        return (0, Q16::ZERO);
    }
    let mut best_i = 0usize;
    let mut best_v = values[0];
    for (i, v) in values.iter().enumerate().skip(1) {
        if v.0 > best_v.0 {
            best_i = i;
            best_v = *v;
        }
    }
    (best_i, best_v)
}

// ---------------------------------------------------------------------------
// Precompile entry point (called by the dispatcher in `precompiles/mod.rs`)
// ---------------------------------------------------------------------------

/// Precompile entry. Charges gas, then runs `forward()`.
///
/// Gas: `GAS_BASE + GAS_PER_PARAM * params` = `5000 + 4 * params`.
/// At canonical shape (115,331 params) → 465,324 gas. Within the
/// planset's ≤1M-gas-per-inference bar.
///
/// The gas pre-charge uses the *header-declared* shape (rounded to
/// MAX_INPUT_BYTES caps via the byte-length check in decode). A
/// caller can't trick saturating-mul into asking for u64::MAX gas
/// because the body length check rejects oversize inputs at the
/// MAX_INPUT_BYTES boundary first.
pub fn execute(input: &[u8], gas_limit: u64) -> Result<crate::precompiles::PrecompileResult, anyhow::Error> {
    use crate::precompiles::PrecompileResult;

    if gas_limit < GAS_BASE {
        return Err(anyhow::anyhow!(
            "Routing forward: insufficient gas (need {GAS_BASE}, got {gas_limit})"
        ));
    }

    // Compute params from the header so gas accounting is accurate
    // BEFORE doing the full decode + tensor allocation.
    let params_hint = if input.len() >= HEADER_LEN {
        let i = u32::from_be_bytes(input[4..8].try_into().expect("4 bytes")) as u64;
        let h = u32::from_be_bytes(input[8..12].try_into().expect("4 bytes")) as u64;
        let o = u32::from_be_bytes(input[12..16].try_into().expect("4 bytes")) as u64;
        // Same formula as RoutingShape::params(), but in u64 with
        // saturating arithmetic so a malicious header can't overflow.
        h.saturating_mul(i)
            .saturating_add(h)
            .saturating_add(h.saturating_mul(h))
            .saturating_add(h)
            .saturating_add(o.saturating_mul(h))
            .saturating_add(o)
    } else {
        0
    };
    let total_gas = GAS_BASE.saturating_add(GAS_PER_PARAM.saturating_mul(params_hint));
    if gas_limit < total_gas {
        return Err(anyhow::anyhow!(
            "Routing forward: insufficient gas (need {total_gas}, got {gas_limit})"
        ));
    }

    match forward(input) {
        Ok(output) => Ok(PrecompileResult {
            output,
            gas_used: total_gas,
            success: true,
        }),
        Err(e) => Err(anyhow::anyhow!("Routing forward: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a wire-format input bytes blob for a given shape, using
    /// uniform values for input/weights/biases. Test-only.
    fn encode_input_uniform(shape: RoutingShape, value: i32) -> Vec<u8> {
        let i = shape.input_dim as usize;
        let h = shape.hidden_dim as usize;
        let o = shape.output_dim as usize;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ARCH_VERSION.to_be_bytes());
        bytes.extend_from_slice(&shape.input_dim.to_be_bytes());
        bytes.extend_from_slice(&shape.hidden_dim.to_be_bytes());
        bytes.extend_from_slice(&shape.output_dim.to_be_bytes());

        let push = |bytes: &mut Vec<u8>, n: usize, v: i32| {
            for _ in 0..n {
                bytes.extend_from_slice(&v.to_be_bytes());
            }
        };
        push(&mut bytes, i, value);                 // input
        push(&mut bytes, h * i, value);             // W1
        push(&mut bytes, h, value);                 // b1
        push(&mut bytes, h * h, value);             // W2
        push(&mut bytes, h, value);                 // b2
        push(&mut bytes, o * h, value);             // W3
        push(&mut bytes, o, value);                 // b3

        bytes
    }

    /// A tiny test shape that fits in memory comfortably: 4-2-2.
    /// Used everywhere the canonical 768-128-3 shape would be
    /// memory-prohibitive in fast unit tests.
    const TEST_SHAPE: RoutingShape = RoutingShape {
        input_dim: 4,
        hidden_dim: 2,
        output_dim: 2,
    };

    // ====================================================================
    // ROUND 1 — Architecture / shape constants (5 GREEN)
    // ====================================================================

    #[test]
    fn arch_version_locked_at_one() {
        // Wire-format invariant: ARCH_VERSION = 1. If anyone bumps it
        // without a hardfork, the tripwire `check_routing_arch_locked.py`
        // will catch it; this test is the in-tree pin.
        assert_eq!(ARCH_VERSION, 1);
    }

    #[test]
    fn arch_v1_shape_constants_match_spec() {
        // Source: RoutingModelInference.tla::ShapeFixed
        assert_eq!(ARCH_V1_INPUT_DIM, 768);
        assert_eq!(ARCH_V1_HIDDEN_DIM, 128);
        assert_eq!(ARCH_V1_OUTPUT_DIM, 3);
    }

    #[test]
    fn shape_v1_canonical() {
        let s = RoutingShape::V1;
        assert_eq!(s.input_dim, 768);
        assert_eq!(s.hidden_dim, 128);
        assert_eq!(s.output_dim, 3);
    }

    #[test]
    fn shape_params_canonical_in_planset_window() {
        // Planset RM-FL-2 window: 100K–500K params.
        let p = RoutingShape::V1.params();
        assert!(p >= 100_000, "params {} below planset window lower bound", p);
        assert!(p <= 500_000, "params {} above planset window upper bound", p);
        // Exact: 128*768 + 128 + 128*128 + 128 + 3*128 + 3 = 115,331
        assert_eq!(p, 115_331);
    }

    #[test]
    fn shape_params_test_shape() {
        // Tiny 4-2-2 shape: 2*4 + 2 + 2*2 + 2 + 2*2 + 2 = 22 params.
        assert_eq!(TEST_SHAPE.params(), 22);
    }

    // ====================================================================
    // ROUND 2 — Decode / encode (10 GREEN)
    // ====================================================================

    #[test]
    fn decode_too_short_returns_input_too_short() {
        assert_eq!(decode(&[0u8; 4]), Err(RoutingError::InputTooShort));
    }

    #[test]
    fn decode_too_large_returns_input_too_large() {
        let oversize = vec![0u8; MAX_INPUT_BYTES + 1];
        assert_eq!(decode(&oversize), Err(RoutingError::InputTooLarge));
    }

    #[test]
    fn decode_arch_version_zero_rejected() {
        let mut bytes = vec![0u8; HEADER_LEN];
        // arch_version = 0
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes()); // input_dim=1
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes()); // hidden_dim=1
        bytes[12..16].copy_from_slice(&1u32.to_be_bytes()); // output_dim=1
        assert_eq!(decode(&bytes), Err(RoutingError::ArchVersionUnregistered));
    }

    #[test]
    fn decode_arch_version_two_rejected() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&2u32.to_be_bytes()); // arch_version=2 (not registered)
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(decode(&bytes), Err(RoutingError::ArchVersionUnregistered));
    }

    #[test]
    fn decode_dim_zero_rejected() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&ARCH_VERSION.to_be_bytes());
        bytes[4..8].copy_from_slice(&0u32.to_be_bytes()); // input_dim=0
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(decode(&bytes), Err(RoutingError::DimZero));
    }

    #[test]
    fn decode_v1_with_wrong_input_dim_rejected() {
        // v1 requires input_dim=768; declare 256.
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&ARCH_VERSION.to_be_bytes());
        bytes[4..8].copy_from_slice(&256u32.to_be_bytes()); // wrong
        bytes[8..12].copy_from_slice(&128u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(decode(&bytes), Err(RoutingError::ShapeMismatch));
    }

    #[test]
    fn decode_v1_with_wrong_hidden_dim_rejected() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&ARCH_VERSION.to_be_bytes());
        bytes[4..8].copy_from_slice(&768u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&64u32.to_be_bytes()); // wrong
        bytes[12..16].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(decode(&bytes), Err(RoutingError::ShapeMismatch));
    }

    /// Test a non-canonical shape via a synthetic ARCH_VERSION=1 path.
    /// Since v1 requires the canonical shape, any non-canonical shape
    /// at v1 must be rejected. We can't easily test "non-v1 shape
    /// accepted" until v2 is registered — that's a future hardfork.
    #[test]
    fn decode_canonical_shape_passes_decode_to_length_check() {
        // We can't easily build a 464KB canonical input in a unit test
        // without real weights, so this test confirms the shape-check
        // path doesn't reject a canonical-shape header. The body
        // length check still fires (we only built the 16-byte header).
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&ARCH_VERSION.to_be_bytes());
        bytes[4..8].copy_from_slice(&768u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&128u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_be_bytes());
        // Header is canonical-shape but body is empty → LengthMismatch.
        assert_eq!(decode(&bytes), Err(RoutingError::LengthMismatch));
    }

    #[test]
    fn decode_truncated_input_rejected() {
        // Build a valid TEST_SHAPE blob, then truncate one Q16.
        // TEST_SHAPE is non-canonical so it will fail the shape check
        // at v1 (since v1 requires canonical). To exercise the
        // length-mismatch path, we'd need a hypothetical v2 that
        // accepts arbitrary shapes. For now, exercise the truncate
        // path against canonical-header but truncated body.
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&ARCH_VERSION.to_be_bytes());
        bytes[4..8].copy_from_slice(&768u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&128u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_be_bytes());
        // Add some body but short of expected.
        bytes.extend_from_slice(&[0u8; 1024]);
        assert_eq!(decode(&bytes), Err(RoutingError::LengthMismatch));
    }

    #[test]
    fn encode_output_byte_layout() {
        let out = RoutingOutput {
            mentor_id: 7,
            adapter_id: 13,
            confidence: Q16::from_int(1),
        };
        let bytes = encode_output(&out);
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[0..4], &7u32.to_be_bytes());
        assert_eq!(&bytes[4..8], &13u32.to_be_bytes());
        assert_eq!(&bytes[8..12], &Q16::from_int(1).0.to_be_bytes());
    }

    // ====================================================================
    // ROUND 3 — Validate (programmatic-construction path) (4 GREEN)
    // ====================================================================

    fn make_test_input() -> RoutingInput {
        let s = TEST_SHAPE;
        let i = s.input_dim as usize;
        let h = s.hidden_dim as usize;
        let o = s.output_dim as usize;
        RoutingInput {
            arch_version: ARCH_VERSION,
            shape: s,
            input: vec![Q16::from_int(1); i],
            w1: vec![Q16::from_int(0); h * i],
            b1: vec![Q16::from_int(0); h],
            w2: vec![Q16::from_int(0); h * h],
            b2: vec![Q16::from_int(0); h],
            w3: vec![Q16::from_int(0); o * h],
            b3: vec![Q16::from_int(0); o],
        }
    }

    #[test]
    fn validate_rejects_test_shape_at_v1() {
        // Programmatic construction can supply non-canonical shape;
        // v1 still rejects it.
        let input = make_test_input();
        assert_eq!(validate(&input), Err(RoutingError::ShapeMismatch));
    }

    #[test]
    fn validate_rejects_inconsistent_w1_length() {
        let mut input = make_test_input();
        input.w1.pop();
        // shape mismatch fires first because TEST_SHAPE != v1
        assert_eq!(validate(&input), Err(RoutingError::ShapeMismatch));
    }

    #[test]
    fn validate_rejects_arch_version_zero() {
        let mut input = make_test_input();
        input.arch_version = 0;
        assert_eq!(validate(&input), Err(RoutingError::ArchVersionUnregistered));
    }

    #[test]
    fn validate_rejects_dim_zero() {
        let mut input = make_test_input();
        input.shape.input_dim = 0;
        assert_eq!(validate(&input), Err(RoutingError::DimZero));
    }

    // ====================================================================
    // ROUND 4 — forward() stub contract (3 GREEN)
    // ====================================================================
    //
    // These tests exercise the WP-2.3 stub directly. They do NOT
    // depend on the WP-2.5 implementation — they only check that
    // decode + validate run before the stub fires. Per RM-FL-1
    // retro, behavioral tests that DO need real outputs are
    // `#[ignore = "WP-2.5"]` below.

    #[test]
    fn forward_stub_returns_not_implemented_for_canonical_header() {
        // Build a valid header but no body → LengthMismatch fires
        // before the stub.
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&ARCH_VERSION.to_be_bytes());
        bytes[4..8].copy_from_slice(&768u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&128u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(forward(&bytes), Err(RoutingError::LengthMismatch));
    }

    #[test]
    fn forward_stub_validates_arch_version_first() {
        let mut bytes = vec![0u8; HEADER_LEN];
        // arch_version = 99
        bytes[0..4].copy_from_slice(&99u32.to_be_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(forward(&bytes), Err(RoutingError::ArchVersionUnregistered));
    }

    #[test]
    fn forward_stub_rejects_oversize() {
        let oversize = vec![0u8; MAX_INPUT_BYTES + 1];
        assert_eq!(forward(&oversize), Err(RoutingError::InputTooLarge));
    }

    // ====================================================================
    // ROUND 5 — Behavioral tests (gated, GREEN at WP-2.5)
    //
    // RM-FL-1 retro item #1: use #[ignore] instead of compile-break
    // forcing function. These tests describe what forward() MUST do
    // once WP-2.5 lands; running them now produces "ignored", running
    // them at WP-2.5 close produces "passed".
    // ====================================================================

    /// Test-only output decoder (mirror of encode_output's inverse).
    fn parse_output(bytes: &[u8]) -> RoutingOutput {
        assert_eq!(bytes.len(), 12, "output must be 12 bytes");
        let mentor_id = u32::from_be_bytes(bytes[0..4].try_into().expect("4 bytes"));
        let adapter_id = u32::from_be_bytes(bytes[4..8].try_into().expect("4 bytes"));
        let confidence = Q16::from_raw(i32::from_be_bytes(
            bytes[8..12].try_into().expect("4 bytes"),
        ));
        RoutingOutput { mentor_id, adapter_id, confidence }
    }

    /// Build a canonical-shape input directly via `forward_decoded`
    /// (avoids encoding/decoding 464 KB of bytes for unit tests).
    /// All weights and biases set to zero; input set to `input_value`.
    fn make_canonical_input_uniform_input(input_value: i32) -> RoutingInput {
        let s = RoutingShape::V1;
        let i = s.input_dim as usize;
        let h = s.hidden_dim as usize;
        let o = s.output_dim as usize;
        RoutingInput {
            arch_version: ARCH_VERSION,
            shape: s,
            input: vec![Q16::from_raw(input_value); i],
            w1: vec![Q16::ZERO; h * i],
            b1: vec![Q16::ZERO; h],
            w2: vec![Q16::ZERO; h * h],
            b2: vec![Q16::ZERO; h],
            w3: vec![Q16::ZERO; o * h],
            b3: vec![Q16::ZERO; o],
        }
    }

    #[test]
    fn forward_canonical_input_produces_well_formed_output() {
        // Gherkin scenario 1 (happy path) — canonical shape with
        // zero weights produces a well-formed output. With all
        // weights = 0, the network output is a vector of zeros;
        // softmax(zero vec) yields a uniform distribution; argmax
        // returns index 0 by tie-break (the argmax helper picks
        // first on ties).
        let input = make_canonical_input_uniform_input(Q16::ONE.0);
        let out = forward_decoded(&input);
        assert!(
            (out.mentor_id as u32) < input.shape.output_dim,
            "mentor_id {} must be < output_dim {}",
            out.mentor_id, input.shape.output_dim
        );
        assert!(
            (out.adapter_id as u32) < input.shape.output_dim,
            "adapter_id {} must be < output_dim {}",
            out.adapter_id, input.shape.output_dim
        );
        // confidence is a Q16 value in roughly [0, ONE]; with uniform
        // softmax over 3 classes it should be ≈ Q16(0x5555) ≈ 0.333.
        assert!(out.confidence.0 > 0, "confidence must be positive");
        assert!(out.confidence.0 <= Q16::ONE.0, "confidence must be ≤ 1.0");
    }

    #[test]
    fn forward_deterministic_across_runs() {
        // Gherkin scenario "cross-CPU determinism" (in-process leg).
        let input = make_canonical_input_uniform_input(Q16::ONE.0);
        let r1 = forward_decoded(&input);
        let r2 = forward_decoded(&input);
        assert_eq!(r1, r2, "identical inputs must produce identical outputs");
    }

    #[test]
    fn forward_max_magnitude_weights_no_panic() {
        // Gherkin scenario — weight poisoning. Set every weight to
        // i32::MAX or i32::MIN; saturating Q16 throughout must not
        // panic.
        let s = RoutingShape::V1;
        let i = s.input_dim as usize;
        let h = s.hidden_dim as usize;
        let o = s.output_dim as usize;
        let max = Q16::MAX;
        let min = Q16::MIN;
        let alternating = |n: usize| {
            (0..n).map(|k| if k % 2 == 0 { max } else { min }).collect::<Vec<_>>()
        };
        let input = RoutingInput {
            arch_version: ARCH_VERSION,
            shape: s,
            input: alternating(i),
            w1: alternating(h * i),
            b1: alternating(h),
            w2: alternating(h * h),
            b2: alternating(h),
            w3: alternating(o * h),
            b3: alternating(o),
        };
        // Must not panic. Q16 confidence is well-defined.
        let out = forward_decoded(&input);
        let _ = out.confidence; // any value is OK as long as no panic
    }

    // ====================================================================
    // ROUND 7 — execute() entry + gas accounting (4 GREEN, WP-2.6)
    // ====================================================================

    #[test]
    fn execute_below_base_gas_rejects() {
        let input = vec![0u8; HEADER_LEN]; // any input, gas check fires first
        let result = execute(&input, GAS_BASE - 1);
        assert!(result.is_err(), "execute must reject below-base gas");
    }

    #[test]
    fn execute_below_total_gas_rejects() {
        // Build a valid v1 header → params_hint will compute the
        // canonical-shape param count → total_gas ≈ 465K. Pass
        // gas_limit = 100K (above base, below total) → reject.
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&ARCH_VERSION.to_be_bytes());
        bytes[4..8].copy_from_slice(&768u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&128u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_be_bytes());
        let result = execute(&bytes, 100_000);
        assert!(
            result.is_err(),
            "execute must reject gas_limit below total"
        );
    }

    #[test]
    fn execute_below_header_short_input_charges_base_gas_only() {
        // Input shorter than HEADER_LEN → params_hint = 0 → total_gas = GAS_BASE.
        // gas_limit just at GAS_BASE → execute returns the decode error
        // (not a gas error).
        let result = execute(&[0u8; 4], GAS_BASE);
        // forward() returns InputTooShort; execute wraps that.
        assert!(result.is_err());
    }

    #[test]
    fn execute_dim_overflow_clamped_safely() {
        // A malicious header claiming dim = u32::MAX must not overflow
        // the gas pre-charge (saturating_mul prevents this).
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&ARCH_VERSION.to_be_bytes());
        bytes[4..8].copy_from_slice(&u32::MAX.to_be_bytes()); // huge input_dim
        bytes[8..12].copy_from_slice(&u32::MAX.to_be_bytes()); // huge hidden_dim
        bytes[12..16].copy_from_slice(&u32::MAX.to_be_bytes()); // huge output_dim
        // Even with u64::MAX gas_limit, the decode still has to fail
        // (input.len() < expected_total). The gas pre-charge clamps to
        // u64::MAX via saturating_mul; the decode then rejects.
        let result = execute(&bytes, u64::MAX);
        assert!(result.is_err(), "malformed-header overflow must error cleanly");
    }

    // ====================================================================
    // ROUND 8 — Address constant (1 GREEN)
    // ====================================================================

    #[test]
    fn routing_inference_address_byte_layout() {
        // Wire-format invariant: 0x0111 on the Learning page
        // (byte17=0x01, byte18=0x01, byte19=0x11). If anyone changes
        // this, the dispatcher in mod.rs and the routing-arch tripwire
        // break together.
        assert_eq!(ROUTING_INFERENCE[0..17], [0u8; 17]);
        assert_eq!(ROUTING_INFERENCE[17], 0x01);
        assert_eq!(ROUTING_INFERENCE[18], 0x01);
        assert_eq!(ROUTING_INFERENCE[19], 0x11);
    }

    #[test]
    fn forward_decoded_argmax_picks_largest_logit() {
        // Build inputs such that the W3 matrix biases output[1]
        // significantly higher than [0] and [2]. Confirm argmax = 1.
        let s = RoutingShape::V1;
        let i = s.input_dim as usize;
        let h = s.hidden_dim as usize;
        let o = s.output_dim as usize;

        // Trivial network: input = ones, W1 = zeros, b1 = zeros
        // → l1 = ReLU(0) = 0. W2 zeros, b2 zeros → l2 = 0. Then
        // W3 zeros + b3 = [0, ONE, 0] → logits = [0, ONE, 0].
        // softmax([0, ONE, 0]) has max at index 1.
        let mut b3 = vec![Q16::ZERO; o];
        b3[1] = Q16::ONE;

        let input = RoutingInput {
            arch_version: ARCH_VERSION,
            shape: s,
            input: vec![Q16::ONE; i],
            w1: vec![Q16::ZERO; h * i],
            b1: vec![Q16::ZERO; h],
            w2: vec![Q16::ZERO; h * h],
            b2: vec![Q16::ZERO; h],
            w3: vec![Q16::ZERO; o * h],
            b3,
        };
        let out = forward_decoded(&input);
        assert_eq!(out.mentor_id, 1, "argmax should select the slot with the largest logit");
        assert_eq!(out.adapter_id, 1, "v1: adapter_id == mentor_id");
    }

    #[test]
    fn parse_output_round_trips_encoded_output() {
        let original = RoutingOutput {
            mentor_id: 42,
            adapter_id: 7,
            confidence: Q16::from_raw(0x12345678),
        };
        let bytes = encode_output(&original);
        let parsed = parse_output(&bytes);
        assert_eq!(parsed, original);
    }

    // ====================================================================
    // ROUND 9 — In-process determinism sweep (1 GREEN, WP-2.9 sibling)
    //
    // The cargo-fuzz target `fuzz_routing_inference` (added in WP-2.9
    // as `citrate_v0.01.1/fuzz/fuzz_targets/fuzz_routing_inference.rs`)
    // is the canonical 10M-input fuzzer. This test is its in-process
    // sibling: a deterministic 50k-iteration sweep that runs every
    // workspace test invocation. It catches panics on the same input
    // shapes the fuzzer targets — overflow, dim mismatch, version
    // edge cases, truncated/oversize buffers.
    //
    // 50k iterations vs Belnap's 100k — routing has more decode work
    // per iteration (large weight tensor parsing on valid headers),
    // so we cap the count to keep test runtime under ~3s.
    // ====================================================================

    #[test]
    fn deterministic_sweep_50k_no_panic() {
        // Lightweight LCG, deterministic seed (mnemonic ROUTING in
        // hex-clean approximation: 0xR0_07_1N_6 → 0x_07_F0_07_17).
        let mut state: u64 = 0x_07_F0_07_17_DE_AD_BE_EF_u64;
        let next = |s: &mut u64| -> u64 {
            *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *s
        };

        for _ in 0..50_000 {
            // Choose an input length in [0, 8192]. Most randomly-
            // generated headers will fail decode (arch_version
            // mismatch, dim mismatch, length mismatch), exercising
            // the fast-fail paths. A small fraction will land on
            // canonical-header bytes by chance and exercise deeper
            // paths.
            let len = (next(&mut state) % 8193) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push((next(&mut state) & 0xFF) as u8);
            }
            let _ = forward(&bytes);
        }
    }

    // ====================================================================
    // ROUND 6 — Property tests (4 GREEN, mixed coverage)
    // ====================================================================

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config { cases: 256, ..Default::default() })]

        /// `forward()` must NEVER panic on arbitrary input bytes.
        /// DoS-resistance contract — already GREEN at WP-2.3 because
        /// every path returns Result.
        #[test]
        fn proptest_forward_never_panics(bytes: Vec<u8>) {
            let _ = forward(&bytes);
        }

        /// `decode()` is deterministic — same input bytes → same
        /// Result.
        #[test]
        fn proptest_decode_deterministic(bytes: Vec<u8>) {
            let r1 = decode(&bytes);
            let r2 = decode(&bytes);
            proptest::prop_assert_eq!(r1, r2);
        }

        /// `RoutingShape::params()` is monotonic in each dimension
        /// (no overflow surprises in the multiplication path).
        #[test]
        fn proptest_params_monotonic_in_input_dim(
            i in 1u32..=64,
            h in 1u32..=64,
            o in 1u32..=8,
        ) {
            let s_low = RoutingShape { input_dim: i, hidden_dim: h, output_dim: o };
            let s_high = RoutingShape { input_dim: i + 1, hidden_dim: h, output_dim: o };
            proptest::prop_assert!(s_high.params() >= s_low.params());
        }

        /// `encode_output()` always produces 12 bytes.
        #[test]
        fn proptest_encode_output_always_12_bytes(
            mentor in 0u32..u32::MAX,
            adapter in 0u32..u32::MAX,
            conf_raw in i32::MIN..=i32::MAX,
        ) {
            let out = RoutingOutput {
                mentor_id: mentor,
                adapter_id: adapter,
                confidence: Q16::from_raw(conf_raw),
            };
            proptest::prop_assert_eq!(encode_output(&out).len(), 12);
        }
    }
}
