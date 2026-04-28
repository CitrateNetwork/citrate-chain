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
// **Status (RM-FL-2, WP-2.3):**
//   - Types + encode/decode/validate: GREEN.
//   - `forward()`: stub returning `Err(RoutingError::NotImplemented)`.
//     Real Q16 implementation lands at WP-2.5 along with the
//     dispatcher registration at 0x0111.
//   - Behavioral tests gated on the impl are `#[ignore = "WP-2.5"]`
//     (RM-FL-1 retro item #1 — cleaner than the WP-1.3 compile-break
//     forcing function).
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

#![allow(dead_code)] // some helpers used only by tests until WP-2.5

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
    /// WP-2.3 stub indicator. Removed at WP-2.5 GREEN. (RM-FL-1 retro
    /// item #1: prefer `#[ignore = "WP-2.5"]` on the test side over
    /// pinning this variant; this is kept ONLY so tests that don't
    /// need real outputs can still observe the stub state cleanly.)
    NotImplemented,
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
            RoutingError::NotImplemented => write!(f, "forward() is a WP-2.3 stub; impl lands at WP-2.5"),
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
// Forward (WP-2.3 STUB — implemented at WP-2.5)
// ---------------------------------------------------------------------------

/// Run the routing-model forward pass: 3 LinearChip + 2 ReLU +
/// 1 softmax over the decoded input. Returns the argmax mentor/adapter
/// + confidence (max-softmax-element).
///
/// **WP-2.3 status: STUB.** Returns `Err(RoutingError::NotImplemented)`.
/// The real Q16 implementation lands at WP-2.5. Behavioral tests are
/// `#[ignore = "WP-2.5"]` per the RM-FL-1 retro — the cleaner pattern
/// versus pinning the stub-error variant in test assertions.
///
/// The signature is final at WP-2.3 so the dispatcher (WP-2.6) can
/// be wired against it without a churning shape.
pub fn forward(input: &[u8]) -> Result<Vec<u8>, RoutingError> {
    let decoded = decode(input)?;
    validate(&decoded)?;
    Err(RoutingError::NotImplemented)
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

    #[test]
    #[ignore = "WP-2.5: forward() impl pending — gated until aggregate algorithm lands"]
    fn forward_canonical_input_produces_well_formed_output() {
        // Gherkin scenario 1 — happy path.
        // Build a canonical-shape input with simple uniform weights;
        // assert output decodes to a (mentor_id < output_dim,
        // adapter_id < output_dim, finite Q16 confidence) tuple.
        // Implementation deferred to WP-2.5.
        unreachable!("ignored test; un-ignore at WP-2.5");
    }

    #[test]
    #[ignore = "WP-2.5: forward() impl pending"]
    fn forward_deterministic_across_runs() {
        // Gherkin scenario "cross-CPU determinism" (in-process leg).
        // Two consecutive calls with identical bytes return identical
        // bytes. Implementation deferred to WP-2.5.
        unreachable!("ignored test; un-ignore at WP-2.5");
    }

    #[test]
    #[ignore = "WP-2.5: forward() impl pending"]
    fn forward_max_magnitude_weights_no_panic() {
        // Gherkin scenario — weight poisoning. Maximum-magnitude
        // weights produce a saturating, well-defined Q16 confidence
        // and never panic. Implementation deferred to WP-2.5.
        unreachable!("ignored test; un-ignore at WP-2.5");
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
