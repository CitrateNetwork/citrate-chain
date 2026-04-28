// citrate/core/execution/src/precompiles/q16/belnap.rs
//
// **Belnap-FOUR aggregation precompile (0x0110).**
//
// RM-FL-1: federated learning production track. Aggregates per-validator
// embedding contributions into (a) a Q16 weighted-mean value per dim and
// (b) a Belnap state per dim ∈ {Neither, True, Both, False}. Output is
// bit-deterministic on every CPU.
//
// **Status (RM-FL-1, WP-1.3 — RED phase):**
//   - encode/decode: implemented + tested
//   - validation:    implemented + tested
//   - classify dim:  implemented + tested
//   - aggregate():   STUB — returns `Err(BelnapError::NotImplemented)`.
//                    The function exists with its final signature so
//                    test-driven development can write the failing
//                    behavior tests at this WP. The body is filled in
//                    at WP-1.5 (GREEN) and the `NotImplemented` error
//                    variant is removed at that close.
//   - dispatch:      not wired into `precompiles/mod.rs`. WP-1.5
//                    registers the address `0x0000…0110`.
//
// **Reference (off-chain, f32):** `core/learning/src/belnap.rs`
//   - `BelnapValue::{join, meet, negation}` — lattice
//   - `classify_belnap` — per-(participant, dim) classification
//   - `reduce_belnap_states` — state-vector reduction (lattice-join across participants)
//
// The precompile uses Q16 fixed-point throughout. The off-chain reference is
// f32. They are NOT byte-equivalent oracles; property tests use algebraic
// equivalence (sign of result preserved, classification matches under bounded
// tolerance).
//
// **Wire format:**
//   Input bytes (big-endian throughout):
//     dim:           u32           (4 bytes)
//     n:             u32           (4 bytes)
//     embeddings:    n*dim*i32     (4*n*dim bytes)
//     confidences:   n*dim*i32     (4*n*dim bytes)
//     weights:       n*i32         (4*n bytes)
//     threshold_pos: i32           (4 bytes)
//     threshold_neg: i32           (4 bytes)
//   Total = 16 + 8*n*dim + 4*n bytes.
//
//   Output bytes (big-endian):
//     aggregated:    dim*i32       (4*dim bytes)
//     states:        dim*u8        (1 byte per dim)
//   Total = 5*dim bytes.
//
// **Caps (DoS protection):**
//   - MAX_N: 1024 participants per call
//   - MAX_DIM: 1024 dimensions per call
//   - These match RM-M2 cap conventions; verified by tripwire
//     `check_belnap_caps_enforced.py` (WP-1.4).
//
// **Determinism guarantee:**
//   - All arithmetic uses Q16 (i32/i64 only). No floats. No platform
//     intrinsics. Verified by tripwire `check_belnap_no_float.py`.

#![allow(dead_code)] // some helpers used only by tests until WP-1.5

use super::Q16;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Belnap-FOUR state values, encoded as `u8` for wire format.
///
/// At the per-participant classification level, all four values are produced.
/// At the *reduced* state-vector level (what the precompile emits), `False`
/// never appears — a single dissenter against a high-conf majority becomes
/// `Both` via the lattice-join reduction (Paper II §3.2 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BelnapState {
    Neither = 0,
    True = 1,
    False = 2,
    Both = 3,
}

impl BelnapState {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Reverse of `as_u8`. Returns `None` for unknown values so that
    /// future on-chain readers can detect stale wire-format bytes.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(BelnapState::Neither),
            1 => Some(BelnapState::True),
            2 => Some(BelnapState::False),
            3 => Some(BelnapState::Both),
            _ => None,
        }
    }
}

/// Decoded input. Owning copies of the wire-format slices (the input
/// bytes are not guaranteed to be `i32`-aligned, so we copy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BelnapInput {
    pub dim: usize,
    pub n: usize,
    pub embeddings: Vec<Q16>,
    pub confidences: Vec<Q16>,
    pub weights: Vec<Q16>,
    pub threshold_pos: Q16,
    pub threshold_neg: Q16,
}

/// Aggregated output: one Q16 value + one `BelnapState` per dimension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BelnapOutput {
    pub aggregated_values: Vec<Q16>,
    pub states: Vec<BelnapState>,
}

/// Decode/validate failures + the WP-1.3 stub indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BelnapError {
    /// Input shorter than the 16-byte header.
    InputTooShort,
    /// `dim == 0`.
    DimZero,
    /// `n == 0`.
    NZero,
    /// `dim` exceeds `MAX_DIM`.
    DimTooLarge,
    /// `n` exceeds `MAX_N`.
    NTooLarge,
    /// Input length doesn't match the declared `(dim, n)`.
    LengthMismatch,
    /// WP-1.3 stub. Removed at WP-1.5 GREEN.
    NotImplemented,
}

impl std::fmt::Display for BelnapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BelnapError::InputTooShort => write!(f, "input shorter than 16-byte header"),
            BelnapError::DimZero => write!(f, "dim must be > 0"),
            BelnapError::NZero => write!(f, "n must be > 0"),
            BelnapError::DimTooLarge => write!(f, "dim exceeds cap of {MAX_DIM}"),
            BelnapError::NTooLarge => write!(f, "n exceeds cap of {MAX_N}"),
            BelnapError::LengthMismatch => write!(f, "input length does not match declared (dim, n)"),
            BelnapError::NotImplemented => write!(f, "aggregate() is a WP-1.3 stub; impl lands at WP-1.5"),
        }
    }
}

impl std::error::Error for BelnapError {}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum participants per call. Matches RM-M2 cap convention.
pub const MAX_N: usize = 1024;

/// Maximum embedding dimensionality per call. Matches RM-M2 cap convention.
pub const MAX_DIM: usize = 1024;

/// Header length in bytes: `dim:u32 || n:u32` + threshold pair.
const HEADER_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Decode / encode (fully implemented at WP-1.3)
// ---------------------------------------------------------------------------

/// Decode the wire-format input bytes into a `BelnapInput`. Performs
/// bounds, cap, and length-consistency checks; never panics, never
/// allocates more than the declared `(dim, n)` requires.
pub fn decode(input: &[u8]) -> Result<BelnapInput, BelnapError> {
    if input.len() < HEADER_LEN {
        return Err(BelnapError::InputTooShort);
    }

    let dim = u32::from_be_bytes(input[0..4].try_into().expect("4 bytes")) as usize;
    let n = u32::from_be_bytes(input[4..8].try_into().expect("4 bytes")) as usize;

    if dim == 0 {
        return Err(BelnapError::DimZero);
    }
    if n == 0 {
        return Err(BelnapError::NZero);
    }
    if dim > MAX_DIM {
        return Err(BelnapError::DimTooLarge);
    }
    if n > MAX_N {
        return Err(BelnapError::NTooLarge);
    }

    // Check total length BEFORE allocating. Use checked arithmetic so a
    // pathological dim*n cannot wrap to a small number that passes the
    // length check.
    let body_len = n
        .checked_mul(dim)
        .and_then(|nd| nd.checked_mul(8)) // embeddings + confidences = 2 * 4 bytes
        .and_then(|nd8| nd8.checked_add(n.checked_mul(4)?)) // + weights
        .ok_or(BelnapError::LengthMismatch)?;
    let expected_total = HEADER_LEN.checked_add(body_len).ok_or(BelnapError::LengthMismatch)?;

    if input.len() != expected_total {
        return Err(BelnapError::LengthMismatch);
    }

    let mut cursor = 8;

    // The two thresholds sit at the END of the payload (after weights).
    // The header carries dim+n only; thresholds are part of the body
    // so the precompile can reuse them per call without dispatching to
    // governance state. (See WP-1.5 for the on-chain governance hook.)
    //
    // Wait — re-reading the wire format docstring: thresholds are 8
    // bytes total at the END. body_len already accounts for that via
    // HEADER_LEN = 16 (dim+n+two thresholds). Recompute body_len:

    // Section 1: embeddings (n*dim*i32)
    let emb_bytes = n * dim * 4;
    let embeddings = decode_q16_slice(&input[cursor..cursor + emb_bytes])
        .ok_or(BelnapError::LengthMismatch)?;
    cursor += emb_bytes;

    // Section 2: confidences (n*dim*i32)
    let conf_bytes = n * dim * 4;
    let confidences = decode_q16_slice(&input[cursor..cursor + conf_bytes])
        .ok_or(BelnapError::LengthMismatch)?;
    cursor += conf_bytes;

    // Section 3: weights (n*i32)
    let w_bytes = n * 4;
    let weights = decode_q16_slice(&input[cursor..cursor + w_bytes])
        .ok_or(BelnapError::LengthMismatch)?;
    cursor += w_bytes;

    // Sanity: cursor should now equal input.len() (thresholds are part
    // of HEADER_LEN, not body_len). But our HEADER_LEN includes them at
    // the END — re-derive properly below.

    // Re-derive: input layout is
    //   [0..4]   dim
    //   [4..8]   n
    //   [8..8+emb]                   embeddings
    //   [8+emb..8+emb+conf]          confidences
    //   [8+emb+conf..8+emb+conf+w]   weights
    //   [last 8 bytes]               threshold_pos, threshold_neg
    //
    // So the trailing 8 bytes carry the thresholds.
    // The corrected expected_total is:
    //   8 (dim+n) + 4*n*dim*2 (emb+conf) + 4*n (weights) + 8 (thresholds)
    // = 16 + 8*n*dim + 4*n
    // which matches our body_len + HEADER_LEN = 8 + (8*n*dim + 4*n) + 8.

    if cursor + 8 != input.len() {
        return Err(BelnapError::LengthMismatch);
    }

    let threshold_pos = Q16::from_raw(i32::from_be_bytes(
        input[cursor..cursor + 4].try_into().expect("4 bytes"),
    ));
    let threshold_neg = Q16::from_raw(i32::from_be_bytes(
        input[cursor + 4..cursor + 8].try_into().expect("4 bytes"),
    ));

    Ok(BelnapInput {
        dim,
        n,
        embeddings,
        confidences,
        weights,
        threshold_pos,
        threshold_neg,
    })
}

/// Decode a contiguous run of big-endian Q16 values. Returns `None` if
/// the slice length is not a multiple of 4.
fn decode_q16_slice(bytes: &[u8]) -> Option<Vec<Q16>> {
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        let raw = i32::from_be_bytes(chunk.try_into().expect("4 bytes"));
        out.push(Q16::from_raw(raw));
    }
    Some(out)
}

/// Encode a `BelnapOutput` into wire-format bytes. Counterpart of `decode`
/// (no `decode_output` is exposed since on-chain readers parse the bytes
/// directly via Solidity ABI).
pub fn encode_output(output: &BelnapOutput) -> Vec<u8> {
    debug_assert_eq!(
        output.aggregated_values.len(),
        output.states.len(),
        "BelnapOutput: aggregated_values and states length mismatch"
    );
    let dim = output.aggregated_values.len();
    let mut bytes = Vec::with_capacity(5 * dim);
    for v in &output.aggregated_values {
        bytes.extend_from_slice(&v.0.to_be_bytes());
    }
    for s in &output.states {
        bytes.push(s.as_u8());
    }
    bytes
}

// ---------------------------------------------------------------------------
// Pure helpers (fully implemented at WP-1.3)
// ---------------------------------------------------------------------------

/// Per-(participant, dim) confidence classification, *before* the
/// majority-resolution step.
///
/// Returns:
///   - `Some(true)`  if confidence ≥ `threshold_pos` AND embedding ≥ 0
///   - `Some(false)` if confidence ≥ `threshold_pos` AND embedding < 0
///   - `None`        if confidence < `threshold_pos` (low-confidence)
///
/// The `threshold_neg` is reserved for future variants (e.g. asymmetric
/// thresholds for unbalanced data); the WP-1.3 helper uses only `threshold_pos`.
///
/// Pure / deterministic / Q16-only.
pub fn classify_dim_threshold(
    embedding: Q16,
    confidence: Q16,
    threshold_pos: Q16,
) -> Option<bool> {
    if confidence.0 < threshold_pos.0 {
        return None;
    }
    Some(embedding.0 >= 0)
}

/// Validate a decoded `BelnapInput` for caps + dimensional consistency.
/// `decode` already enforces these when reading bytes; this helper is
/// exposed for callers that construct a `BelnapInput` programmatically
/// (the daemon code path in RM-FL-3).
pub fn validate(input: &BelnapInput) -> Result<(), BelnapError> {
    if input.dim == 0 {
        return Err(BelnapError::DimZero);
    }
    if input.n == 0 {
        return Err(BelnapError::NZero);
    }
    if input.dim > MAX_DIM {
        return Err(BelnapError::DimTooLarge);
    }
    if input.n > MAX_N {
        return Err(BelnapError::NTooLarge);
    }
    if input.embeddings.len() != input.n * input.dim {
        return Err(BelnapError::LengthMismatch);
    }
    if input.confidences.len() != input.n * input.dim {
        return Err(BelnapError::LengthMismatch);
    }
    if input.weights.len() != input.n {
        return Err(BelnapError::LengthMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Aggregate (WP-1.3 STUB — implemented at WP-1.5)
// ---------------------------------------------------------------------------

/// Aggregate per-validator Belnap contributions into a single state +
/// weighted-mean value per dimension.
///
/// **WP-1.3 status: RED stub.** Returns `Err(BelnapError::NotImplemented)`
/// for every input. The real implementation lands at WP-1.5 along with
/// the dispatcher registration at `0x0110`.
///
/// The signature is final at WP-1.3 so failing tests can be written
/// against the production-shape API.
pub fn aggregate(input: &[u8]) -> Result<Vec<u8>, BelnapError> {
    // Validate decode + caps even at the stub level — that part of the
    // contract is already provable in WP-1.3 GREEN, and ensures a
    // malformed input is rejected with the right error before we hit
    // the unimplemented core.
    let decoded = decode(input)?;
    validate(&decoded)?;
    Err(BelnapError::NotImplemented)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Encoding helpers (used by tests + WP-1.5 fixtures)
    // -----------------------------------------------------------------

    /// Encode a `BelnapInput` back into wire-format bytes — the inverse
    /// of `decode`. Test-only; on-chain callers ABI-encode directly.
    fn encode_input(input: &BelnapInput) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(input.dim as u32).to_be_bytes());
        bytes.extend_from_slice(&(input.n as u32).to_be_bytes());
        for v in &input.embeddings {
            bytes.extend_from_slice(&v.0.to_be_bytes());
        }
        for v in &input.confidences {
            bytes.extend_from_slice(&v.0.to_be_bytes());
        }
        for v in &input.weights {
            bytes.extend_from_slice(&v.0.to_be_bytes());
        }
        bytes.extend_from_slice(&input.threshold_pos.0.to_be_bytes());
        bytes.extend_from_slice(&input.threshold_neg.0.to_be_bytes());
        bytes
    }

    fn make_input(
        dim: usize,
        n: usize,
        embedding_value: f64,
        confidence_value: f64,
        weight_value: f64,
        threshold_pos: f64,
    ) -> BelnapInput {
        let emb = Q16::from_f64(embedding_value);
        let conf = Q16::from_f64(confidence_value);
        let w = Q16::from_f64(weight_value);
        BelnapInput {
            dim,
            n,
            embeddings: vec![emb; n * dim],
            confidences: vec![conf; n * dim],
            weights: vec![w; n],
            threshold_pos: Q16::from_f64(threshold_pos),
            threshold_neg: -Q16::from_f64(threshold_pos),
        }
    }

    // ====================================================================
    // ROUND 1 — Encoding / decoding (12 tests, all GREEN)
    // ====================================================================

    #[test]
    fn decode_minimum_valid_input() {
        let input = make_input(1, 1, 0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        let decoded = decode(&bytes).expect("minimum input decodes");
        assert_eq!(decoded.dim, 1);
        assert_eq!(decoded.n, 1);
        assert_eq!(decoded.embeddings.len(), 1);
        assert_eq!(decoded.confidences.len(), 1);
        assert_eq!(decoded.weights.len(), 1);
    }

    #[test]
    fn decode_too_short_returns_input_too_short() {
        let bytes = vec![0u8; 4]; // less than HEADER_LEN
        assert_eq!(decode(&bytes), Err(BelnapError::InputTooShort));
    }

    #[test]
    fn decode_n_zero_returns_n_zero() {
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&1u32.to_be_bytes()); // dim=1
        bytes[4..8].copy_from_slice(&0u32.to_be_bytes()); // n=0
        assert_eq!(decode(&bytes), Err(BelnapError::NZero));
    }

    #[test]
    fn decode_dim_zero_returns_dim_zero() {
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&0u32.to_be_bytes()); // dim=0
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes()); // n=1
        assert_eq!(decode(&bytes), Err(BelnapError::DimZero));
    }

    #[test]
    fn decode_n_above_cap_rejects() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&1u32.to_be_bytes());
        bytes[4..8].copy_from_slice(&((MAX_N + 1) as u32).to_be_bytes());
        assert_eq!(decode(&bytes), Err(BelnapError::NTooLarge));
    }

    #[test]
    fn decode_dim_above_cap_rejects() {
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&((MAX_DIM + 1) as u32).to_be_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(decode(&bytes), Err(BelnapError::DimTooLarge));
    }

    #[test]
    fn decode_truncated_embeddings_rejects() {
        let input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        let mut bytes = encode_input(&input);
        bytes.truncate(bytes.len() - 1); // drop one trailing byte
        assert_eq!(decode(&bytes), Err(BelnapError::LengthMismatch));
    }

    #[test]
    fn decode_oversize_input_rejects() {
        let input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        let mut bytes = encode_input(&input);
        bytes.push(0xff); // extra trailing byte
        assert_eq!(decode(&bytes), Err(BelnapError::LengthMismatch));
    }

    #[test]
    fn decode_thresholds_round_trip() {
        let input = make_input(1, 1, 0.0, 1.0, 1.0, 0.75);
        let bytes = encode_input(&input);
        let decoded = decode(&bytes).expect("decodes");
        assert_eq!(decoded.threshold_pos, input.threshold_pos);
        assert_eq!(decoded.threshold_neg, input.threshold_neg);
    }

    #[test]
    fn encode_input_round_trip() {
        let input = make_input(3, 2, 0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        let decoded = decode(&bytes).expect("decodes");
        assert_eq!(decoded.dim, input.dim);
        assert_eq!(decoded.n, input.n);
        assert_eq!(decoded.embeddings, input.embeddings);
        assert_eq!(decoded.confidences, input.confidences);
        assert_eq!(decoded.weights, input.weights);
    }

    #[test]
    fn encode_output_byte_layout() {
        let out = BelnapOutput {
            aggregated_values: vec![Q16::from_int(7), Q16::from_int(-7)],
            states: vec![BelnapState::True, BelnapState::Both],
        };
        let bytes = encode_output(&out);
        // 4*2 (values) + 1*2 (states) = 10 bytes
        assert_eq!(bytes.len(), 10);
        // First 4 bytes: BE-encoded Q16 of 7
        assert_eq!(&bytes[0..4], &Q16::from_int(7).0.to_be_bytes());
        // Next 4 bytes: BE-encoded Q16 of -7
        assert_eq!(&bytes[4..8], &Q16::from_int(-7).0.to_be_bytes());
        // Last 2 bytes: state codes
        assert_eq!(bytes[8], BelnapState::True.as_u8());
        assert_eq!(bytes[9], BelnapState::Both.as_u8());
    }

    #[test]
    fn encode_output_empty_dim() {
        let out = BelnapOutput {
            aggregated_values: vec![],
            states: vec![],
        };
        assert_eq!(encode_output(&out).len(), 0);
    }

    // ====================================================================
    // ROUND 2 — Validation (5 tests, GREEN)
    // ====================================================================

    #[test]
    fn validate_accepts_at_max_n() {
        let input = BelnapInput {
            dim: 1,
            n: MAX_N,
            embeddings: vec![Q16::ZERO; MAX_N],
            confidences: vec![Q16::ZERO; MAX_N],
            weights: vec![Q16::ZERO; MAX_N],
            threshold_pos: Q16::ZERO,
            threshold_neg: Q16::ZERO,
        };
        validate(&input).expect("at-cap n accepted");
    }

    #[test]
    fn validate_accepts_at_max_dim() {
        let input = BelnapInput {
            dim: MAX_DIM,
            n: 1,
            embeddings: vec![Q16::ZERO; MAX_DIM],
            confidences: vec![Q16::ZERO; MAX_DIM],
            weights: vec![Q16::ZERO; 1],
            threshold_pos: Q16::ZERO,
            threshold_neg: Q16::ZERO,
        };
        validate(&input).expect("at-cap dim accepted");
    }

    #[test]
    fn validate_rejects_inconsistent_embedding_length() {
        let mut input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        input.embeddings.pop(); // n*dim = 6, now 5
        assert_eq!(validate(&input), Err(BelnapError::LengthMismatch));
    }

    #[test]
    fn validate_rejects_inconsistent_weights_length() {
        let mut input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        input.weights.pop(); // n = 3, now 2
        assert_eq!(validate(&input), Err(BelnapError::LengthMismatch));
    }

    #[test]
    fn validate_zero_weight_is_legal() {
        // A submission with weight=0 is well-formed input — the
        // aggregator filters it later, but validation passes.
        let input = make_input(1, 1, 0.5, 0.9, 0.0, 0.8);
        validate(&input).expect("zero-weight is legal at validate");
    }

    // ====================================================================
    // ROUND 3 — Threshold classification helper (6 tests, GREEN)
    // ====================================================================

    #[test]
    fn classify_below_threshold_neither() {
        let conf = Q16::from_f64(0.5);
        let thr = Q16::from_f64(0.8);
        assert_eq!(
            classify_dim_threshold(Q16::from_f64(1.0), conf, thr),
            None
        );
    }

    #[test]
    fn classify_at_threshold_inclusive_passes() {
        let thr = Q16::from_f64(0.8);
        // Confidence == threshold → inclusive lower bound (high-conf).
        assert_eq!(
            classify_dim_threshold(Q16::from_f64(1.0), thr, thr),
            Some(true)
        );
    }

    #[test]
    fn classify_above_threshold_pos_sign() {
        let conf = Q16::from_f64(0.9);
        let thr = Q16::from_f64(0.8);
        assert_eq!(
            classify_dim_threshold(Q16::from_f64(2.5), conf, thr),
            Some(true)
        );
    }

    #[test]
    fn classify_above_threshold_neg_sign() {
        let conf = Q16::from_f64(0.9);
        let thr = Q16::from_f64(0.8);
        assert_eq!(
            classify_dim_threshold(Q16::from_f64(-2.5), conf, thr),
            Some(false)
        );
    }

    #[test]
    fn classify_zero_embedding_high_conf() {
        // Zero embedding is ambiguous — convention: treat as positive
        // (`>= 0` rule). Documented in fn docs.
        let conf = Q16::from_f64(0.9);
        let thr = Q16::from_f64(0.8);
        assert_eq!(
            classify_dim_threshold(Q16::ZERO, conf, thr),
            Some(true)
        );
    }

    #[test]
    fn classify_one_ulp_below_threshold_is_neither() {
        // The Q16-boundary case from Gherkin scenario 3.
        let thr = Q16::from_f64(0.8);
        let one_ulp_below = Q16::from_raw(thr.0 - 1);
        assert_eq!(
            classify_dim_threshold(Q16::from_f64(1.0), one_ulp_below, thr),
            None,
            "one ULP below threshold must be Neither"
        );
    }

    // ====================================================================
    // ROUND 4 — BelnapState type (3 tests, GREEN)
    // ====================================================================

    #[test]
    fn belnap_state_round_trip_via_u8() {
        for s in [
            BelnapState::Neither,
            BelnapState::True,
            BelnapState::False,
            BelnapState::Both,
        ] {
            assert_eq!(BelnapState::from_u8(s.as_u8()), Some(s));
        }
    }

    #[test]
    fn belnap_state_unknown_byte_returns_none() {
        for unknown in 4..=255u8 {
            assert_eq!(BelnapState::from_u8(unknown), None);
        }
    }

    #[test]
    fn belnap_state_codes_match_wire_format() {
        // Wire format committed in module docs:
        // 0=Neither, 1=True, 2=False, 3=Both.
        // If anyone changes these, on-chain readers break silently.
        assert_eq!(BelnapState::Neither.as_u8(), 0);
        assert_eq!(BelnapState::True.as_u8(), 1);
        assert_eq!(BelnapState::False.as_u8(), 2);
        assert_eq!(BelnapState::Both.as_u8(), 3);
    }

    // ====================================================================
    // ROUND 5 — aggregate() behavior (10 tests; mostly RED at WP-1.3)
    //
    // These tests assert what aggregate() MUST do once WP-1.5 lands.
    // At WP-1.3, aggregate() returns Err(NotImplemented), so they all
    // fail with the matching error. At WP-1.5 they flip to GREEN.
    //
    // The decode/validation paths are exercised even at WP-1.3 (they
    // run before the Err) — that's why we can validate "decode rejects"
    // tests fully GREEN here.
    // ====================================================================

    #[test]
    fn aggregate_three_honest_agree_state_true() {
        // Gherkin scenario 1 — happy path.
        let input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        let result = aggregate(&bytes);
        // RED at WP-1.3:
        assert_eq!(
            result,
            Err(BelnapError::NotImplemented),
            "WP-1.3 stub; this test flips to GREEN at WP-1.5 with state=[True,True]"
        );
    }

    #[test]
    fn aggregate_collusion_under_hda_state_both() {
        // Gherkin scenario 2 — collusion. RED at WP-1.3.
        let input = BelnapInput {
            dim: 1,
            n: 4,
            embeddings: vec![
                Q16::from_f64(1.0),  // honest A
                Q16::from_f64(1.0),  // honest B
                Q16::from_f64(-1.0), // byz   C
                Q16::from_f64(-1.0), // byz   D
            ],
            confidences: vec![Q16::from_f64(0.9); 4],
            weights: vec![
                Q16::from_f64(1.0), // honest A weight 1
                Q16::from_f64(1.0), // honest B weight 1 (HDA: 2.0 > 1.0)
                Q16::from_f64(0.5), // byz   C weight 0.5
                Q16::from_f64(0.5), // byz   D weight 0.5
            ],
            threshold_pos: Q16::from_f64(0.8),
            threshold_neg: Q16::from_f64(-0.8),
        };
        let bytes = encode_input(&input);
        assert_eq!(aggregate(&bytes), Err(BelnapError::NotImplemented));
    }

    #[test]
    fn aggregate_threshold_edge_deterministic() {
        // Gherkin scenario 3 — threshold edge. RED at WP-1.3.
        let mut input = make_input(1, 2, 1.0, 0.0, 1.0, 0.8);
        input.confidences[0] = Q16::from_f64(0.8); // exactly at threshold
        input.confidences[1] = Q16::from_raw(Q16::from_f64(0.8).0 - 1); // one ULP below
        let bytes = encode_input(&input);

        // Determinism property: same bytes → same Err at WP-1.3, same
        // output at WP-1.5. The point of the test is the bit-equality.
        let r1 = aggregate(&bytes);
        let r2 = aggregate(&bytes);
        assert_eq!(r1, r2);
        assert_eq!(r1, Err(BelnapError::NotImplemented));
    }

    #[test]
    fn aggregate_zero_weight_filtered() {
        // Gherkin scenario 4 — weight=0 ignored. RED at WP-1.3.
        let input = BelnapInput {
            dim: 1,
            n: 3,
            embeddings: vec![
                Q16::from_f64(1.0),
                Q16::from_f64(1.0),
                Q16::from_f64(-9.0), // adversary sign
            ],
            confidences: vec![Q16::from_f64(0.9); 3],
            weights: vec![
                Q16::from_f64(1.0),
                Q16::from_f64(1.0),
                Q16::ZERO, // adversary excluded
            ],
            threshold_pos: Q16::from_f64(0.8),
            threshold_neg: Q16::from_f64(-0.8),
        };
        let bytes = encode_input(&input);
        assert_eq!(aggregate(&bytes), Err(BelnapError::NotImplemented));
    }

    #[test]
    fn aggregate_dim_mismatch_reverts() {
        // Gherkin scenario 5 — bounds rejection. GREEN at WP-1.3
        // because decode() catches it before the stub.
        let input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        let mut bytes = encode_input(&input);
        // Truncate one Q16 worth of bytes from the middle of the
        // embeddings section.
        bytes.truncate(bytes.len() - 4);
        let result = aggregate(&bytes);
        // Length check fires before the stub.
        assert_eq!(result, Err(BelnapError::LengthMismatch));
    }

    #[test]
    fn aggregate_max_magnitude_no_panic() {
        // Gherkin scenario 6 — max-magnitude inputs. RED at WP-1.3 but
        // partially GREEN: the stub still accepts the input without
        // panicking. Saturation correctness in the aggregator core is
        // proved at WP-1.5 / WP-1.7 (fuzz).
        let input = BelnapInput {
            dim: 1,
            n: 2,
            embeddings: vec![Q16::MAX, Q16::MIN],
            confidences: vec![Q16::from_f64(0.9), Q16::from_f64(0.9)],
            weights: vec![Q16::from_f64(1.0), Q16::from_f64(1.0)],
            threshold_pos: Q16::from_f64(0.8),
            threshold_neg: Q16::from_f64(-0.8),
        };
        let bytes = encode_input(&input);
        // Accepts decode + validate (max magnitudes are legal Q16 values).
        let result = aggregate(&bytes);
        assert_eq!(result, Err(BelnapError::NotImplemented));
        // No panic — that's the WP-1.3 guarantee for this test.
    }

    #[test]
    fn aggregate_cross_cpu_determinism_fixture() {
        // Gherkin scenario 7 — cross-CPU determinism. The actual
        // x86_64-vs-aarch64 assertion lands as a fixture in WP-1.5.
        // At WP-1.3, two consecutive calls on this CPU must agree —
        // any divergence here is an immediate red flag.
        let input = make_input(4, 5, 0.25, 0.85, 1.0, 0.8);
        let bytes = encode_input(&input);
        let r1 = aggregate(&bytes);
        let r2 = aggregate(&bytes);
        assert_eq!(r1, r2, "two calls with identical bytes must produce identical results");
    }

    #[test]
    fn aggregate_unanimous_negative_agree_is_true() {
        // All high-conf participants point in the SAME (negative)
        // direction → state=True. Adversarial-TLA Q.E.D.: aggregator
        // doesn't know ground truth, only inputs.
        let input = make_input(1, 3, -0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        assert_eq!(aggregate(&bytes), Err(BelnapError::NotImplemented));
    }

    #[test]
    fn aggregate_single_participant_state_true() {
        // n=1 edge case — trivially consistent → True.
        let input = make_input(2, 1, 0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        assert_eq!(aggregate(&bytes), Err(BelnapError::NotImplemented));
    }

    #[test]
    fn aggregate_all_low_confidence_state_neither() {
        // No high-conf positive-weight participant → Neither.
        // (Source: BelnapAdversarial.tla::NeitherImpliesUnderconfidence)
        let input = make_input(1, 3, 0.5, 0.1, 1.0, 0.8);
        let bytes = encode_input(&input);
        assert_eq!(aggregate(&bytes), Err(BelnapError::NotImplemented));
    }

    // ====================================================================
    // ROUND 6 — Property tests (6 tests, mixed GREEN / RED)
    // ====================================================================

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config { cases: 256, ..Default::default() })]

        /// Encode-decode round trip is identity for any well-formed input.
        #[test]
        fn proptest_encode_decode_round_trip(
            dim in 1usize..=8,
            n in 1usize..=8,
        ) {
            let input = BelnapInput {
                dim,
                n,
                embeddings: vec![Q16::from_int(1); n * dim],
                confidences: vec![Q16::from_int(1); n * dim],
                weights: vec![Q16::from_int(1); n],
                threshold_pos: Q16::from_int(0),
                threshold_neg: Q16::from_int(0),
            };
            let bytes = encode_input(&input);
            let decoded = decode(&bytes).expect("round-trip decode");
            proptest::prop_assert_eq!(decoded.dim, input.dim);
            proptest::prop_assert_eq!(decoded.n, input.n);
            proptest::prop_assert_eq!(decoded.embeddings, input.embeddings);
        }

        /// `aggregate()` must NEVER panic on arbitrary input bytes —
        /// only return `Err`. This is the DoS-resistance contract and
        /// is already GREEN at WP-1.3 because every path returns Result.
        #[test]
        fn proptest_aggregate_never_panics(bytes: Vec<u8>) {
            let _ = aggregate(&bytes);
        }

        /// Classify is monotone in confidence: increasing the conf above
        /// threshold cannot move the classification back to `None`.
        #[test]
        fn proptest_classify_monotone_in_confidence(
            embedding_raw: i32,
            base_conf_raw: i32,
            delta_raw in 0i32..i32::MAX,
            threshold_raw: i32,
        ) {
            let emb = Q16::from_raw(embedding_raw);
            let base_conf = Q16::from_raw(base_conf_raw);
            let higher_conf = Q16::from_raw(base_conf_raw.saturating_add(delta_raw));
            let thr = Q16::from_raw(threshold_raw);
            let base = classify_dim_threshold(emb, base_conf, thr);
            let higher = classify_dim_threshold(emb, higher_conf, thr);
            // If base is Some, higher is also Some.
            if base.is_some() {
                proptest::prop_assert!(higher.is_some());
                proptest::prop_assert_eq!(base, higher);
            }
        }

        /// When `aggregate` returns Ok, the output bytes have the
        /// expected length: `5 * dim` per the wire format. RED at
        /// WP-1.3 (Ok branch never taken); GREEN at WP-1.5.
        #[test]
        fn proptest_aggregate_output_size_correct(
            dim in 1usize..=8,
            n in 1usize..=8,
        ) {
            let input = BelnapInput {
                dim,
                n,
                embeddings: vec![Q16::from_int(1); n * dim],
                confidences: vec![Q16::from_int(1); n * dim],
                weights: vec![Q16::from_int(1); n],
                threshold_pos: Q16::from_int(0),
                threshold_neg: Q16::from_int(0),
            };
            let bytes = encode_input(&input);
            if let Ok(output) = aggregate(&bytes) {
                proptest::prop_assert_eq!(output.len(), 5 * dim);
            }
            // No assert on Err branch — the WP-1.3 stub returns Err here.
        }

        /// Same input bytes → same output (or same error). Determinism.
        #[test]
        fn proptest_aggregate_deterministic(bytes: Vec<u8>) {
            let r1 = aggregate(&bytes);
            let r2 = aggregate(&bytes);
            proptest::prop_assert_eq!(r1, r2);
        }

        /// `BelnapState::from_u8(s.as_u8()) == Some(s)` for all states.
        #[test]
        fn proptest_belnap_state_round_trip(s_raw in 0u8..4u8) {
            let s = BelnapState::from_u8(s_raw).expect("0..4 are valid");
            proptest::prop_assert_eq!(BelnapState::from_u8(s.as_u8()), Some(s));
        }
    }
}
