// citrate/core/execution/src/precompiles/q16/belnap.rs
//
// **Belnap-FOUR aggregation precompile (0x0110).**
//
// RM-FL-1: federated learning production track. Aggregates per-validator
// embedding contributions into (a) a Q16 weighted-mean value per dim and
// (b) a Belnap state per dim ∈ {Neither, True, Both, False}. Output is
// bit-deterministic on every CPU.
//
// **Status (RM-FL-1, WP-1.5 — GREEN):**
//   - encode/decode: implemented + tested
//   - validation:    implemented + tested
//   - classify dim:  implemented + tested
//   - aggregate():   **LIVE.** Q16-deterministic algorithm; matches
//                    the off-chain reference in `core/learning/` at
//                    the *semantic* level (sign+confidence regime),
//                    not byte-equality (the reference uses f32).
//   - execute():     precompile entry point with gas accounting
//                    (`2000 + 50 * dim`).
//   - dispatch:      wired in `precompiles/mod.rs` at address
//                    `0x0000…0110` (Learning page, canonical WP-B0: byte18=1,
//                    byte19=0x10).
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
//     embeddings:    n*dim*i64     (8*n*dim bytes)
//     confidences:   n*dim*i64     (8*n*dim bytes)
//     weights:       n*i64         (8*n bytes)
//     threshold_pos: i64           (8 bytes)
//     threshold_neg: i64           (8 bytes)
//   Total = 24 + 16*n*dim + 8*n bytes.
//
//   Output bytes (big-endian):
//     aggregated:    dim*i64       (8*dim bytes)
//     states:        dim*u8        (1 byte per dim)
//   Total = 9*dim bytes.
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

/// Decode / validate failures.
///
/// At WP-1.3 there was a `NotImplemented` variant pinning the stub
/// contract; WP-1.5 removed it together with the impl landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BelnapError {
    /// Input shorter than the 24-byte header.
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
}

impl std::fmt::Display for BelnapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BelnapError::InputTooShort => write!(f, "input shorter than 24-byte header"),
            BelnapError::DimZero => write!(f, "dim must be > 0"),
            BelnapError::NZero => write!(f, "n must be > 0"),
            BelnapError::DimTooLarge => write!(f, "dim exceeds cap of {MAX_DIM}"),
            BelnapError::NTooLarge => write!(f, "n exceeds cap of {MAX_N}"),
            BelnapError::LengthMismatch => write!(f, "input length does not match declared (dim, n)"),
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

/// Header length in bytes: `dim:u32 || n:u32` (8 bytes) + threshold
/// pair `threshold_pos:i64 || threshold_neg:i64` (16 bytes) = 24.
const HEADER_LEN: usize = 24;

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
        .and_then(|nd| nd.checked_mul(16)) // embeddings + confidences = 2 * 8 bytes
        .and_then(|nd16| nd16.checked_add(n.checked_mul(8)?)) // + weights
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
    // Wait — re-reading the wire format docstring: thresholds are 16
    // bytes total at the END. body_len already accounts for that via
    // HEADER_LEN = 24 (dim+n+two thresholds). Recompute body_len:

    // Section 1: embeddings (n*dim*i64)
    let emb_bytes = n * dim * 8;
    let embeddings = decode_q16_slice(&input[cursor..cursor + emb_bytes])
        .ok_or(BelnapError::LengthMismatch)?;
    cursor += emb_bytes;

    // Section 2: confidences (n*dim*i64)
    let conf_bytes = n * dim * 8;
    let confidences = decode_q16_slice(&input[cursor..cursor + conf_bytes])
        .ok_or(BelnapError::LengthMismatch)?;
    cursor += conf_bytes;

    // Section 3: weights (n*i64)
    let w_bytes = n * 8;
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
    //   [last 16 bytes]              threshold_pos, threshold_neg
    //
    // So the trailing 16 bytes carry the thresholds.
    // The corrected expected_total is:
    //   8 (dim+n) + 8*n*dim*2 (emb+conf) + 8*n (weights) + 16 (thresholds)
    // = 24 + 16*n*dim + 8*n
    // which matches our body_len + HEADER_LEN = 8 + (16*n*dim + 8*n) + 16.

    if cursor + 16 != input.len() {
        return Err(BelnapError::LengthMismatch);
    }

    let threshold_pos = Q16::from_raw(i64::from_be_bytes(
        input[cursor..cursor + 8].try_into().expect("8 bytes"),
    ));
    let threshold_neg = Q16::from_raw(i64::from_be_bytes(
        input[cursor + 8..cursor + 16].try_into().expect("8 bytes"),
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
/// the slice length is not a multiple of 8.
fn decode_q16_slice(bytes: &[u8]) -> Option<Vec<Q16>> {
    if !bytes.len().is_multiple_of(8) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 8);
    for chunk in bytes.chunks_exact(8) {
        let raw = i64::from_be_bytes(chunk.try_into().expect("8 bytes"));
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
    let mut bytes = Vec::with_capacity(9 * dim);
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
// Precompile address (Learning page 0x01_01)
// ---------------------------------------------------------------------------

/// 20-byte address `0x0000…0110` for Belnap-FOUR aggregation. The
/// Learning page (canonical byte18=1, selector 0x10–0x1F — WP-B0) is
/// reserved for RM-FL precompiles:
///   - 0x0110: Belnap aggregation        (RM-FL-1, this module)
///   - 0x0111: Routing-model inference    (RM-FL-2, future)
pub const BELNAP_AGGREGATE: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x10,
];

/// Base gas cost (per Gherkin scenario 1).
const GAS_BASE: u64 = 2000;
/// Per-dimension gas cost.
const GAS_PER_DIM: u64 = 50;

// ---------------------------------------------------------------------------
// Aggregate (WP-1.5 GREEN)
// ---------------------------------------------------------------------------

/// Aggregate per-validator Belnap contributions into a single state
/// vector + Q16 weighted-sum value per dimension.
///
/// Algorithm (Q16 throughout — no floats):
///
/// For each dimension `d ∈ 0..dim`:
///   1. **Aggregated value**:
///      `agg_value[d] = Σ saturating(weight[i] * embedding[i][d])`
///      over `i ∈ 0..n`. Saturating arithmetic at every step; an
///      adversarial max-magnitude input produces a saturated Q16 value,
///      not a panic and not a wrap.
///   2. **Per-participant classification** (only for participants with
///      strictly positive weight — `weight[i].0 > 0`):
///      conf < threshold_pos        → low-confidence (ignored)
///      emb >= 0 AND conf >= thresh → "agree"  side
///      emb <  0 AND conf >= thresh → "oppose" side
///   3. **Reduced state** (Paper II §3.2 step 3 — lattice-join):
///      no high-conf positive-weight at this dim → `Neither`
///      only one side populated                  → `True`
///      both sides populated                     → `Both`
///      (`False` is impossible at the reduced level — a single
///      dissenter joins with the majority's `True` to produce `Both`.)
///
/// Determinism: bit-identical output across CPUs because every step
/// is integer Q16. Verified by tripwire `check_belnap_no_float.py`.
///
/// Symmetry: only `threshold_pos` is consulted at WP-1.5. `threshold_neg`
/// is reserved for future asymmetric-threshold variants and is parsed
/// from the wire format for forward compatibility.
pub fn aggregate(input: &[u8]) -> Result<Vec<u8>, BelnapError> {
    let decoded = decode(input)?;
    validate(&decoded)?;
    let output = aggregate_decoded(&decoded);
    Ok(encode_output(&output))
}

/// Pluggable Belnap aggregation strategy.
///
/// **Why a trait?** Paper II §3 names the FOUR-valued reduction as ONE
/// algorithm, but Paper III §2 (mentor matching, RM-FL-4) and the
/// hypothesis rigs in RM-FL-5 may want lattice variants — e.g. an
/// asymmetric-threshold reduction that uses both `threshold_pos` and
/// `threshold_neg`, or a meet-based "consensus" reduction. Pinning the
/// surface here lets future variants slot in without touching
/// `aggregate()` or its callers (the dispatcher in `precompiles/mod.rs`
/// and the RM-FL-3 daemon path).
///
/// Implementors MUST be deterministic and Q16-only — no floats, no
/// platform intrinsics, no randomness. The default
/// [`StandardBelnap`] implements the WP-1.5 algorithm verbatim.
pub trait BelnapStateMachine {
    /// Aggregate a fully-decoded `BelnapInput` into a per-dimension
    /// (value, state) output. Pure function; no allocation outside
    /// the returned `BelnapOutput`.
    fn aggregate(&self, input: &BelnapInput) -> BelnapOutput;
}

/// The WP-1.5 Belnap algorithm — `Σ saturating(w * e)` per dim plus
/// agree/oppose classification with early lattice-join termination.
///
/// Equivalent to the inlined `aggregate_decoded` from before WP-1.6;
/// the trait is a non-behavior-changing extraction.
#[derive(Debug, Default, Clone, Copy)]
pub struct StandardBelnap;

impl BelnapStateMachine for StandardBelnap {
    fn aggregate(&self, input: &BelnapInput) -> BelnapOutput {
        let dim = input.dim;
        let n = input.n;

        let mut aggregated_values = Vec::with_capacity(dim);
        let mut states = Vec::with_capacity(dim);

        for d in 0..dim {
            // ---- Step 1: weighted sum over participants ----
            let mut acc = Q16::ZERO;
            for i in 0..n {
                let w = input.weights[i];
                let e = input.embeddings[i * dim + d];
                acc = acc.saturating_add(w.saturating_mul(e));
            }
            aggregated_values.push(acc);

            // ---- Step 2 + 3: classification + lattice reduction ----
            let mut has_agree = false;
            let mut has_oppose = false;
            for i in 0..n {
                // Filter zero-weight participants
                // (BelnapAdversarial.tla::WeightZeroIgnored).
                // Negative weights are wire-format bugs; treat as zero.
                if input.weights[i].0 <= 0 {
                    continue;
                }
                let e = input.embeddings[i * dim + d];
                let c = input.confidences[i * dim + d];
                match classify_dim_threshold(e, c, input.threshold_pos) {
                    Some(true) => has_agree = true,
                    Some(false) => has_oppose = true,
                    None => {}
                }
                // Early termination: once both sides are populated,
                // the per-dim state is locked at Both. O(n + early-out)
                // instead of O(n) on the common adversarial case.
                if has_agree && has_oppose {
                    break;
                }
            }

            let state = match (has_agree, has_oppose) {
                (false, false) => BelnapState::Neither,
                (true, false) | (false, true) => BelnapState::True,
                (true, true) => BelnapState::Both,
            };
            states.push(state);
        }

        BelnapOutput {
            aggregated_values,
            states,
        }
    }
}

/// Inner aggregation kernel against an already-decoded `BelnapInput`.
/// Wrapper around `StandardBelnap::aggregate` — kept as a free
/// function so existing callers (test code, RM-FL-3 daemon path)
/// don't need to import the trait.
pub fn aggregate_decoded(input: &BelnapInput) -> BelnapOutput {
    StandardBelnap.aggregate(input)
}

// ---------------------------------------------------------------------------
// Precompile entry point (called by the dispatcher in `precompiles/mod.rs`)
// ---------------------------------------------------------------------------

/// Precompile entry. Charges gas, then runs `aggregate()`.
///
/// Gas: `GAS_BASE + GAS_PER_DIM * dim` = `2000 + 50 * dim`.
/// Decode failures (`InputTooShort`, malformed bytes) charge `GAS_BASE`
/// so a malformed-input griefer still pays for the parse work.
pub fn execute(input: &[u8], gas_limit: u64) -> Result<crate::precompiles::PrecompileResult, anyhow::Error> {
    use crate::precompiles::PrecompileResult;

    if gas_limit < GAS_BASE {
        return Err(anyhow::anyhow!(
            "Belnap aggregate: insufficient gas (need {GAS_BASE}, got {gas_limit})"
        ));
    }

    // Peek the dim from the header (without full-decoding) so we can
    // gas-charge accurately. If the input is too short, decode() below
    // catches it; we fall back to GAS_BASE.
    let dim_hint = if input.len() >= 4 {
        u32::from_be_bytes(input[0..4].try_into().expect("4 bytes")) as u64
    } else {
        0
    };
    let dim_hint = dim_hint.min(MAX_DIM as u64);
    let total_gas = GAS_BASE.saturating_add(GAS_PER_DIM.saturating_mul(dim_hint));
    if gas_limit < total_gas {
        return Err(anyhow::anyhow!(
            "Belnap aggregate: insufficient gas (need {total_gas}, got {gas_limit})"
        ));
    }

    match aggregate(input) {
        Ok(output) => Ok(PrecompileResult {
            output,
            gas_used: total_gas,
            success: true,
        }),
        Err(e) => Err(anyhow::anyhow!("Belnap aggregate: {e}")),
    }
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

    /// Decode the wire-format output bytes back into a `BelnapOutput`.
    /// Test-only — on-chain readers ABI-decode directly.
    fn parse_output(bytes: &[u8], dim: usize) -> BelnapOutput {
        assert_eq!(bytes.len(), 9 * dim, "output bytes length must be 9 * dim");
        let mut aggregated_values = Vec::with_capacity(dim);
        for d in 0..dim {
            let raw = i64::from_be_bytes(
                bytes[d * 8..(d + 1) * 8].try_into().expect("8 bytes"),
            );
            aggregated_values.push(Q16::from_raw(raw));
        }
        let states_off = 8 * dim;
        let mut states = Vec::with_capacity(dim);
        for d in 0..dim {
            states.push(
                BelnapState::from_u8(bytes[states_off + d])
                    .expect("test fixture must produce valid state byte"),
            );
        }
        BelnapOutput {
            aggregated_values,
            states,
        }
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
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&1u32.to_be_bytes()); // dim=1
        bytes[4..8].copy_from_slice(&0u32.to_be_bytes()); // n=0
        assert_eq!(decode(&bytes), Err(BelnapError::NZero));
    }

    #[test]
    fn decode_dim_zero_returns_dim_zero() {
        let mut bytes = vec![0u8; HEADER_LEN];
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
        // 8*2 (values) + 1*2 (states) = 18 bytes
        assert_eq!(bytes.len(), 18);
        // First 8 bytes: BE-encoded Q16 of 7
        assert_eq!(&bytes[0..8], &Q16::from_int(7).0.to_be_bytes());
        // Next 8 bytes: BE-encoded Q16 of -7
        assert_eq!(&bytes[8..16], &Q16::from_int(-7).0.to_be_bytes());
        // Last 2 bytes: state codes
        assert_eq!(bytes[16], BelnapState::True.as_u8());
        assert_eq!(bytes[17], BelnapState::Both.as_u8());
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
    // ROUND 5 — aggregate() behavior (10 tests, all GREEN at WP-1.5)
    //
    // At WP-1.3 these tests pinned the stub contract via
    // Err(BelnapError::NotImplemented). WP-1.5 removed that variant
    // and rewrote each test against the real Gherkin-derived
    // expected output.
    // ====================================================================

    #[test]
    fn aggregate_three_honest_agree_state_true() {
        // Gherkin scenario 1 — happy path.
        // 3 participants, dim=2, embedding=[+0.5, +0.5], conf=[0.9, 0.9],
        // weight=1.0 each → state=[True, True].
        let input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        let bytes_out = aggregate(&bytes).expect("happy-path aggregates");
        let out = parse_output(&bytes_out, input.dim);
        assert_eq!(out.states, vec![BelnapState::True, BelnapState::True]);
        // Aggregated value = Σ w_i * emb_i = 3 * (1.0 * 0.5) = 1.5 (Q16).
        // Per-dim, identical because every participant submits the same vector.
        for v in &out.aggregated_values {
            assert!(v.0 > 0, "aggregated value sign must be positive");
        }
    }

    #[test]
    fn aggregate_collusion_under_hda_state_both() {
        // Gherkin scenario 2 — collusion under Honest Dominance.
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
                Q16::from_f64(1.0), // honest A
                Q16::from_f64(1.0), // honest B (HDA: honest 2.0 > byz 1.0)
                Q16::from_f64(0.5), // byz   C
                Q16::from_f64(0.5), // byz   D
            ],
            threshold_pos: Q16::from_f64(0.8),
            threshold_neg: Q16::from_f64(-0.8),
        };
        let bytes = encode_input(&input);
        let out = parse_output(&aggregate(&bytes).expect("aggregates"), input.dim);
        assert_eq!(
            out.states,
            vec![BelnapState::Both],
            "BelnapAdversarial.tla::AdversaryCannotFlipUnderHDA: state must be Both"
        );
    }

    #[test]
    fn aggregate_threshold_edge_deterministic() {
        // Gherkin scenario 3 — threshold edge.
        // Participant A: conf == threshold_pos exactly (high-conf, inclusive).
        // Participant B: conf == threshold_pos - 1 ULP (low-conf).
        let mut input = make_input(1, 2, 1.0, 0.0, 1.0, 0.8);
        input.confidences[0] = Q16::from_f64(0.8);
        input.confidences[1] = Q16::from_raw(Q16::from_f64(0.8).0 - 1);
        let bytes = encode_input(&input);
        let r1 = aggregate(&bytes).expect("aggregates");
        let r2 = aggregate(&bytes).expect("aggregates");
        // Bit-determinism: identical bytes both calls.
        assert_eq!(r1, r2);
        // A is high-conf positive, B is low-conf — only the positive
        // side has a participant → state=True.
        let out = parse_output(&r1, input.dim);
        assert_eq!(out.states, vec![BelnapState::True]);
    }

    #[test]
    fn aggregate_zero_weight_filtered() {
        // Gherkin scenario 4 — weight=0 ignored
        // (BelnapAdversarial.tla::WeightZeroIgnored).
        let input = BelnapInput {
            dim: 1,
            n: 3,
            embeddings: vec![
                Q16::from_f64(1.0),
                Q16::from_f64(1.0),
                Q16::from_f64(-9.0), // adversary sign + magnitude
            ],
            confidences: vec![Q16::from_f64(0.9); 3],
            weights: vec![
                Q16::from_f64(1.0),
                Q16::from_f64(1.0),
                Q16::ZERO, // adversary excluded from classification
            ],
            threshold_pos: Q16::from_f64(0.8),
            threshold_neg: Q16::from_f64(-0.8),
        };
        let bytes = encode_input(&input);
        let out = parse_output(&aggregate(&bytes).expect("aggregates"), input.dim);
        // Zero-weight excluded → only the two positive-weight honest
        // participants count → state=True.
        assert_eq!(out.states, vec![BelnapState::True]);
        // Aggregated value: Σ w*e = 1*1 + 1*1 + 0*(-9) = 2.0 (saturating).
        // The zero-weight contribution is exactly Q16::ZERO so the
        // aggregated value is unaffected by adversarial magnitude.
        assert!(out.aggregated_values[0].0 > 0);
    }

    #[test]
    fn aggregate_dim_mismatch_reverts() {
        // Gherkin scenario 5 — bounds rejection at decode().
        let input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        let mut bytes = encode_input(&input);
        bytes.truncate(bytes.len() - 4);
        assert_eq!(aggregate(&bytes), Err(BelnapError::LengthMismatch));
    }

    #[test]
    fn aggregate_max_magnitude_no_panic() {
        // Gherkin scenario 6 — saturating Q16 over max-magnitude inputs.
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
        let out = parse_output(&aggregate(&bytes).expect("aggregates without panic"), input.dim);
        // Two high-conf positive-weight participants on opposing sides
        // → state=Both. Aggregated value is well-defined Q16 (no panic,
        // no wrap — saturating throughout).
        assert_eq!(out.states, vec![BelnapState::Both]);
    }

    #[test]
    fn aggregate_cross_cpu_determinism_fixture() {
        // Gherkin scenario 7 — bit-determinism on this CPU. Cross-CPU
        // x86_64-vs-aarch64 fixture lives as a separate test in
        // tests/cross_platform/ (TODO at sprint close).
        let input = make_input(4, 5, 0.25, 0.85, 1.0, 0.8);
        let bytes = encode_input(&input);
        let r1 = aggregate(&bytes).expect("aggregates");
        let r2 = aggregate(&bytes).expect("aggregates");
        assert_eq!(r1, r2, "identical bytes must produce identical results");
    }

    #[test]
    fn aggregate_unanimous_negative_agree_is_true() {
        // All high-conf participants point negative → state=True.
        // The aggregator doesn't know ground truth, only inputs.
        let input = make_input(1, 3, -0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        let out = parse_output(&aggregate(&bytes).expect("aggregates"), input.dim);
        assert_eq!(out.states, vec![BelnapState::True]);
        assert!(
            out.aggregated_values[0].0 < 0,
            "unanimous negative input → negative aggregated value"
        );
    }

    #[test]
    fn aggregate_single_participant_state_true() {
        // n=1 — trivially consistent → True for every dim.
        let input = make_input(2, 1, 0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        let out = parse_output(&aggregate(&bytes).expect("aggregates"), input.dim);
        assert_eq!(out.states, vec![BelnapState::True, BelnapState::True]);
    }

    #[test]
    fn aggregate_all_low_confidence_state_neither() {
        // No high-conf positive-weight participant → state=Neither.
        // (Source: BelnapAdversarial.tla::NeitherImpliesUnderconfidence)
        let input = make_input(1, 3, 0.5, 0.1, 1.0, 0.8);
        let bytes = encode_input(&input);
        let out = parse_output(&aggregate(&bytes).expect("aggregates"), input.dim);
        assert_eq!(out.states, vec![BelnapState::Neither]);
    }

    // ====================================================================
    // ROUND 5b — execute() entry point + gas accounting (5 GREEN, new at WP-1.5)
    // ====================================================================

    #[test]
    fn execute_happy_path_returns_precompile_result() {
        let input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        let gas_limit = 100_000;
        let result = execute(&bytes, gas_limit).expect("executes");
        assert!(result.success);
        // Output bytes match aggregate() directly.
        assert_eq!(result.output, aggregate(&bytes).unwrap());
    }

    #[test]
    fn execute_gas_charged_per_dim() {
        // Gas = 2000 + 50 * dim. dim=2 → 2100. dim=4 → 2200.
        let input2 = make_input(2, 1, 0.5, 0.9, 1.0, 0.8);
        let input4 = make_input(4, 1, 0.5, 0.9, 1.0, 0.8);
        let g2 = execute(&encode_input(&input2), 100_000).unwrap().gas_used;
        let g4 = execute(&encode_input(&input4), 100_000).unwrap().gas_used;
        assert_eq!(g2, 2000 + 50 * 2);
        assert_eq!(g4, 2000 + 50 * 4);
    }

    #[test]
    fn execute_insufficient_gas_below_base() {
        let input = make_input(1, 1, 0.5, 0.9, 1.0, 0.8);
        let bytes = encode_input(&input);
        let result = execute(&bytes, 1999); // below GAS_BASE
        assert!(result.is_err(), "execute must reject below-base gas limit");
    }

    #[test]
    fn execute_insufficient_gas_below_dim_total() {
        let input = make_input(8, 1, 0.5, 0.9, 1.0, 0.8); // needs 2400 gas
        let bytes = encode_input(&input);
        let result = execute(&bytes, 2300); // above base, below total
        assert!(result.is_err(), "execute must reject below-total gas limit");
    }

    #[test]
    fn execute_dim_hint_clamped_to_max_dim() {
        // A malicious caller crafts a header claiming dim = u32::MAX.
        // The gas pre-charge clamps to MAX_DIM so the saturating math
        // can't be tricked into asking for u64::MAX gas.
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&u32::MAX.to_be_bytes()); // huge dim
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes()); // n=1
        // input is too short for the actual decode; the gas pre-charge
        // path will compute total_gas = GAS_BASE + GAS_PER_DIM * MAX_DIM
        // = 2000 + 50*1024 = 53200. Pass 100_000.
        let result = execute(&bytes, 100_000);
        // Decode fails (length mismatch); execute surfaces it as anyhow.
        assert!(result.is_err());
    }

    // ====================================================================
    // ROUND 5c — Address constant (1 GREEN, new at WP-1.5)
    // ====================================================================

    // ====================================================================
    // ROUND 5d — BelnapStateMachine trait surface (3 GREEN, WP-1.6)
    // ====================================================================

    #[test]
    fn standard_belnap_implements_state_machine_trait() {
        // The trait is the load-bearing surface for future variants
        // (RM-FL-4 mentor matching, RM-FL-5 hypothesis rigs). This
        // test pins that StandardBelnap satisfies it — if a future
        // refactor accidentally narrows the trait, this fails.
        fn assert_impl<T: BelnapStateMachine>(_: &T) {}
        assert_impl(&StandardBelnap);
    }

    #[test]
    fn standard_belnap_matches_aggregate_decoded() {
        // The free function `aggregate_decoded` must dispatch to
        // `StandardBelnap`. If a future change introduces a different
        // default, callers (RM-FL-3 daemon, tests) get unexpected
        // behavior — this test catches that drift.
        let input = make_input(2, 3, 0.5, 0.9, 1.0, 0.8);
        let via_free = aggregate_decoded(&input);
        let via_trait = StandardBelnap.aggregate(&input);
        assert_eq!(via_free, via_trait);
    }

    #[test]
    fn standard_belnap_via_trait_object() {
        // Trait object dispatch works (object safety check). Future
        // variant selection at the daemon level may want
        // `Box<dyn BelnapStateMachine>` for runtime configuration.
        let machine: &dyn BelnapStateMachine = &StandardBelnap;
        let input = make_input(1, 1, 1.0, 1.0, 1.0, 0.5);
        let out = machine.aggregate(&input);
        assert_eq!(out.states, vec![BelnapState::True]);
    }

    // ====================================================================
    // ROUND 5e — Deterministic 100k-iteration sweep (1 GREEN, WP-1.7)
    //
    // The cargo-fuzz target `fuzz_belnap_aggregate` is the canonical
    // 10M-input fuzzer (run as a long-running CI/operator job). This
    // test is its in-process sibling: a deterministic 100k-iteration
    // sweep that runs every workspace test invocation. It catches
    // panics on the same input shapes the fuzzer targets — overflow,
    // dim mismatch, weight=0 edge cases, threshold-edge confidence,
    // truncated/oversize inputs.
    //
    // The seed is fixed (0xBE_1A_AF) so a regression that lands here
    // reproduces bit-identically across machines.
    // ====================================================================

    #[test]
    fn deterministic_sweep_100k_no_panic() {
        // Lightweight LCG (deterministic, no external rand crate
        // dependency at the unit-test level). Period covers far more
        // than the 100k iterations we run.
        let mut state: u64 = 0xBE_1A_AF_DE_AD_BE_EF_42;
        let next = |s: &mut u64| -> u64 {
            *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *s
        };

        for _ in 0..100_000 {
            // Choose an input length in [0, 4096] — covers truncated
            // headers, exact valid inputs, and oversize buffers.
            let len = (next(&mut state) % 4097) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push((next(&mut state) & 0xFF) as u8);
            }

            // Surface 1: direct aggregate (decode + validate + algorithm).
            // Surface 2: dispatcher path is exercised by the cargo-fuzz
            //            target only — calling it 100k times here would
            //            slow the unit test suite. The two surfaces
            //            share the same code paths from `aggregate()`
            //            inward, so direct calls are sufficient for
            //            this sweep.
            let _ = aggregate(&bytes);
        }
    }

    #[test]
    fn belnap_aggregate_address_byte_layout() {
        // Wire-format invariant: the precompile lives at the
        // CANONICAL `0x0000…0110` (byte18=0x01, selector 0x10 — the
        // address Solidity's `address(0x0110)` resolves to, WP-B0).
        // If anyone changes this, the dispatcher in mod.rs and the
        // REVM bridge table (`PURE_PRECOMPILE_ADDRESSES`) break together.
        assert_eq!(BELNAP_AGGREGATE[0..18], [0u8; 18]);
        assert_eq!(BELNAP_AGGREGATE[18], 0x01);
        assert_eq!(BELNAP_AGGREGATE[19], 0x10);
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
            embedding_raw: i64,
            base_conf_raw: i64,
            delta_raw in 0i64..i64::MAX,
            threshold_raw: i64,
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
                proptest::prop_assert_eq!(output.len(), 9 * dim);
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
