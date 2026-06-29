// citrate/core/execution/src/precompiles/tensor_format.rs
//
// Canonical binary tensor format v1 — used by every RM-M and later AI
// precompile that accepts or returns tensor-shaped data.
//
// **Stability:** this format is FROZEN. Any incompatible change requires
// a new dtype byte (which is enforced by `Dtype::from_byte` rejecting
// unknown values), or a new precompile address with a new format
// entirely. The frozen guarantee is what makes 0x0107 TENSOR_COMMIT
// commitments stable across versions.
//
// ## Wire format
//
// ```text
// [ 1 byte rank ]
// [ rank × 4 bytes shape (u32, big-endian) ]
// [ 1 byte dtype ]
// [ data bytes ]
// ```
//
// ### Field details
//
// - `rank` — number of dimensions (`0..=4`). Values ≥ 5 are rejected
//   here; per-precompile callers may impose tighter caps (e.g. matmul
//   requires exactly rank 2).
// - `shape` — `rank` u32 values, big-endian, in row-major order. Each
//   dimension must be ≥ 1; zero-dimensional rank-0 tensors carry zero
//   shape entries and one data element. The product of dimensions
//   (the element count) must not exceed `MAX_ELEMENTS`.
// - `dtype` — one byte selector. See `Dtype`. Unknown bytes return
//   `TensorFormatError::UnknownDtype` — this is what makes the format
//   forward-compatible: a new dtype is added by allocating a new
//   selector, and old dtypes never disappear.
// - `data` — `element_count × dtype.byte_size` bytes, laid out
//   row-major (innermost dimension contiguous in memory). For
//   multi-byte dtypes the bytes within an element are big-endian.
//
// ## Caps
//
// The format itself caps:
//
// - `MAX_RANK` = 4 — caller per-call may impose lower (e.g. matmul = 2).
// - `MAX_ELEMENTS` = 65,536 — bounds memory before per-precompile caps
//   apply (256×256 matmul = 65,536; long vectors up to 65,536 = 1024
//   elements × 64 features). Per-precompile dispatchers MUST also
//   validate against their own tighter caps.
//
// These bounds are deliberately conservative and shared across the
// format level; tighter caps live at the dispatcher boundary
// (per-precompile) so the format stays stable as we add new ops.
//
// ## Why no version byte
//
// The dtype byte serves as the version marker per dtype. If we ever
// need a wholesale format change, that is a new precompile address
// with a new format — not a v2 of this one. This avoids the v1/v2
// branching that compounds across every dispatcher.

use thiserror::Error;

/// Hard caps for the format. These are the absolute upper bounds at
/// the format level — per-precompile dispatchers impose tighter
/// per-op caps (and MUST validate them BEFORE any allocation).
pub const MAX_RANK: usize = 4;

/// Element count cap. 2²⁰ = 1,048,576. Sized to accommodate the largest
/// planned RM-M2 per-op cap (ReLU at 1M elements). All other planned
/// ops are well under this — matmul is 256×256 = 65,536, softmax /
/// dot are 1024.
///
/// At the format level, decoding never allocates based on element_count
/// — the data slice is borrowed zero-copy from the input. So the
/// element cap is a sanity check, not a memory guard. The memory guard
/// is `MAX_DATA_BYTES` below, which bounds the worst-case input size
/// across both dtypes.
pub const MAX_ELEMENTS: usize = 1_048_576;

/// Total data-byte cap = 16 MiB. Bounds the worst-case across dtypes:
///
/// - Q16 (8 bytes/elem): 16 MiB / 8 = 2,097,152 elements (more than
///   `MAX_ELEMENTS` allows, so element cap binds first for Q16).
/// - Field32 (32 bytes/elem): 16 MiB / 32 = 524,288 elements (so
///   Field32 is implicitly capped well below the element cap, which
///   is intentional — Field32 is for commitments / Merkle leaves
///   where a 524,288-element call is already absurdly oversized).
///
/// The two caps work together: `MAX_ELEMENTS` says "no precompile
/// will ever need more elements than this," and `MAX_DATA_BYTES` says
/// "no input will ever cross this physical-byte threshold." Either
/// triggering rejects the input.
pub const MAX_DATA_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Tensor element data type.
///
/// Selectors are stable. Adding a new dtype is additive: allocate a new
/// byte (next free is `0x03`), document it here, ship a new precompile
/// or extend an existing one. Old dtype bytes are NEVER reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Dtype {
    /// Q16.16 fixed-point, little-endian i64 (8 bytes on the wire).
    /// 16 fractional bits over an i64 backing (I64-S1 widening), so the
    /// integer part spans ≈ ±1.4 × 10¹⁴, resolution ≈ 1.526 × 10⁻⁵.
    /// Bit-identical across all hardware. Used by RM-M2 deterministic
    /// compute precompiles.
    Q16_16 = 0x01,

    /// 32-byte big-endian field element (BLS12-381 Fr). Used by
    /// commitment / Merkle precompiles where each element is already
    /// a hash digest or a circuit witness value.
    Field32 = 0x02,
}

impl Dtype {
    /// Bytes per element for this dtype.
    pub const fn byte_size(self) -> usize {
        match self {
            Dtype::Q16_16 => 8,
            Dtype::Field32 => 32,
        }
    }

    /// Decode a dtype byte. Unknown bytes are rejected — this is the
    /// forward-compat invariant.
    pub fn from_byte(b: u8) -> Result<Self, TensorFormatError> {
        match b {
            0x01 => Ok(Dtype::Q16_16),
            0x02 => Ok(Dtype::Field32),
            _ => Err(TensorFormatError::UnknownDtype(b)),
        }
    }

    /// Encode as a single byte.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

/// A decoded tensor view — just the structural metadata plus a slice
/// into the original input bytes. Zero-copy. Caller is responsible for
/// the lifetime of `data`.
#[derive(Debug, Clone)]
pub struct TensorView<'a> {
    pub shape: Vec<u32>,
    pub dtype: Dtype,
    pub data: &'a [u8],
}

impl TensorView<'_> {
    /// Total element count. Always ≤ `MAX_ELEMENTS` because `decode`
    /// validates this.
    pub fn element_count(&self) -> usize {
        self.shape.iter().fold(1usize, |acc, &dim| acc * dim as usize)
    }

    /// Total data bytes = element_count × dtype.byte_size.
    pub fn data_byte_count(&self) -> usize {
        self.element_count() * self.dtype.byte_size()
    }
}

/// Errors that arise during decode/encode. All variants are structural —
/// none of them indicate a bug in this module; they indicate malformed
/// caller input.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TensorFormatError {
    #[error("input too short: expected at least {expected} bytes, got {got}")]
    Truncated { expected: usize, got: usize },

    #[error("rank {0} exceeds MAX_RANK ({})", MAX_RANK)]
    RankTooLarge(u8),

    #[error("element count {got} exceeds MAX_ELEMENTS ({})", MAX_ELEMENTS)]
    TooManyElements { got: usize },

    #[error("data byte count {got} exceeds MAX_DATA_BYTES ({})", MAX_DATA_BYTES)]
    TooManyBytes { got: usize },

    #[error("dimension at axis {axis} is zero — all dims must be ≥ 1")]
    ZeroDimension { axis: usize },

    #[error("element count overflows usize during multiplication")]
    ElementCountOverflow,

    #[error("unknown dtype byte 0x{0:02x}")]
    UnknownDtype(u8),

    #[error("trailing bytes: input had {extra} bytes beyond the encoded tensor")]
    TrailingBytes { extra: usize },

    #[error("data length {got} does not match expected {expected} (element_count × dtype.byte_size)")]
    DataLengthMismatch { expected: usize, got: usize },
}

/// Decode a single tensor from the start of `input`. Returns the
/// decoded view AND the number of bytes consumed (so callers can decode
/// concatenated tensors — e.g. matmul takes two).
pub fn decode_one<'a>(input: &'a [u8]) -> Result<(TensorView<'a>, usize), TensorFormatError> {
    if input.is_empty() {
        return Err(TensorFormatError::Truncated { expected: 1, got: 0 });
    }
    let rank = input[0] as usize;
    if rank > MAX_RANK {
        return Err(TensorFormatError::RankTooLarge(input[0]));
    }

    // Header bytes: 1 (rank) + rank × 4 (shape) + 1 (dtype)
    let header_len = 1 + rank * 4 + 1;
    if input.len() < header_len {
        return Err(TensorFormatError::Truncated {
            expected: header_len,
            got: input.len(),
        });
    }

    // Shape: rank × u32 BE.
    let mut shape = Vec::with_capacity(rank);
    let mut element_count: usize = 1;
    for axis in 0..rank {
        let off = 1 + axis * 4;
        let dim_bytes: [u8; 4] = input[off..off + 4]
            .try_into()
            .expect("4 bytes by construction");
        let dim = u32::from_be_bytes(dim_bytes);
        if dim == 0 {
            return Err(TensorFormatError::ZeroDimension { axis });
        }
        shape.push(dim);
        element_count = element_count
            .checked_mul(dim as usize)
            .ok_or(TensorFormatError::ElementCountOverflow)?;
        if element_count > MAX_ELEMENTS {
            return Err(TensorFormatError::TooManyElements { got: element_count });
        }
    }

    let dtype_off = 1 + rank * 4;
    let dtype = Dtype::from_byte(input[dtype_off])?;

    let data_byte_count = element_count
        .checked_mul(dtype.byte_size())
        .ok_or(TensorFormatError::ElementCountOverflow)?;
    if data_byte_count > MAX_DATA_BYTES {
        return Err(TensorFormatError::TooManyBytes {
            got: data_byte_count,
        });
    }

    let data_start = header_len;
    let data_end = data_start
        .checked_add(data_byte_count)
        .ok_or(TensorFormatError::ElementCountOverflow)?;
    if input.len() < data_end {
        return Err(TensorFormatError::Truncated {
            expected: data_end,
            got: input.len(),
        });
    }

    let view = TensorView {
        shape,
        dtype,
        data: &input[data_start..data_end],
    };

    Ok((view, data_end))
}

/// Decode exactly one tensor and reject any trailing bytes. Most
/// single-tensor precompiles (TENSOR_COMMIT, MERKLE_VERIFY_TENSOR) want
/// this; multi-tensor precompiles (matmul) call `decode_one` directly
/// and decode the next tensor from the remaining suffix.
pub fn decode_exact(input: &[u8]) -> Result<TensorView<'_>, TensorFormatError> {
    let (view, consumed) = decode_one(input)?;
    if consumed != input.len() {
        return Err(TensorFormatError::TrailingBytes {
            extra: input.len() - consumed,
        });
    }
    Ok(view)
}

/// Encode a tensor — used by precompile *output* paths (e.g. matmul
/// returns a tensor). Returns owned bytes because the output crosses
/// the precompile boundary.
pub fn encode(shape: &[u32], dtype: Dtype, data: &[u8]) -> Result<Vec<u8>, TensorFormatError> {
    if shape.len() > MAX_RANK {
        return Err(TensorFormatError::RankTooLarge(shape.len() as u8));
    }
    let mut element_count: usize = 1;
    for (axis, &dim) in shape.iter().enumerate() {
        if dim == 0 {
            return Err(TensorFormatError::ZeroDimension { axis });
        }
        element_count = element_count
            .checked_mul(dim as usize)
            .ok_or(TensorFormatError::ElementCountOverflow)?;
        if element_count > MAX_ELEMENTS {
            return Err(TensorFormatError::TooManyElements { got: element_count });
        }
    }
    let expected = element_count
        .checked_mul(dtype.byte_size())
        .ok_or(TensorFormatError::ElementCountOverflow)?;
    if expected > MAX_DATA_BYTES {
        return Err(TensorFormatError::TooManyBytes { got: expected });
    }
    if data.len() != expected {
        return Err(TensorFormatError::DataLengthMismatch {
            expected,
            got: data.len(),
        });
    }

    let mut out = Vec::with_capacity(1 + shape.len() * 4 + 1 + data.len());
    out.push(shape.len() as u8);
    for &dim in shape {
        out.extend_from_slice(&dim.to_be_bytes());
    }
    out.push(dtype.to_byte());
    out.extend_from_slice(data);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_q16_tensor(shape: &[u32], values: &[i64]) -> Vec<u8> {
        let mut data = Vec::with_capacity(values.len() * 8);
        for &v in values {
            data.extend_from_slice(&v.to_le_bytes());
        }
        encode(shape, Dtype::Q16_16, &data).expect("test fixture must encode")
    }

    #[test]
    fn roundtrip_rank_2_q16() {
        let values: Vec<i64> = (1..=6).collect();
        let bytes = build_q16_tensor(&[2, 3], &values);
        let view = decode_exact(&bytes).expect("decode");
        assert_eq!(view.shape, vec![2, 3]);
        assert_eq!(view.dtype, Dtype::Q16_16);
        assert_eq!(view.element_count(), 6);
        assert_eq!(view.data_byte_count(), 48);
        assert_eq!(view.data.len(), 48);
    }

    #[test]
    fn roundtrip_field32() {
        let mut data = Vec::with_capacity(2 * 32);
        for i in 0..2u8 {
            for j in 0..32u8 {
                data.push(i.wrapping_add(j));
            }
        }
        let bytes = encode(&[2], Dtype::Field32, &data).unwrap();
        let view = decode_exact(&bytes).unwrap();
        assert_eq!(view.shape, vec![2]);
        assert_eq!(view.dtype, Dtype::Field32);
        assert_eq!(view.data, &data[..]);
    }

    #[test]
    fn rejects_truncated_header_short() {
        // rank=2 but no shape bytes
        let bytes = vec![2u8];
        let err = decode_exact(&bytes).unwrap_err();
        assert!(matches!(err, TensorFormatError::Truncated { .. }));
    }

    #[test]
    fn rejects_truncated_data() {
        // rank=1 shape=[3] dtype=Q16 but only 8 bytes data instead of 24
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.push(Dtype::Q16_16.to_byte());
        bytes.extend_from_slice(&[0u8; 8]);
        let err = decode_exact(&bytes).unwrap_err();
        assert!(matches!(err, TensorFormatError::Truncated { .. }));
    }

    #[test]
    fn rejects_oversize_rank() {
        let bytes = vec![5u8, 0, 0, 0, 1, 0, 0, 0, 1];
        let err = decode_exact(&bytes).unwrap_err();
        assert!(matches!(err, TensorFormatError::RankTooLarge(5)));
    }

    #[test]
    fn rejects_zero_dim() {
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.push(Dtype::Q16_16.to_byte());
        let err = decode_exact(&bytes).unwrap_err();
        assert!(matches!(err, TensorFormatError::ZeroDimension { axis: 0 }));
    }

    #[test]
    fn rejects_oversize_element_count() {
        // rank=2 shape=[2048,2048] = 4,194,304 elements > MAX_ELEMENTS=1,048,576
        let mut bytes = vec![2u8];
        bytes.extend_from_slice(&2048u32.to_be_bytes());
        bytes.extend_from_slice(&2048u32.to_be_bytes());
        bytes.push(Dtype::Q16_16.to_byte());
        let err = decode_exact(&bytes).unwrap_err();
        assert!(matches!(err, TensorFormatError::TooManyElements { .. }));
    }

    #[test]
    fn rejects_oversize_byte_count_via_field32() {
        // rank=1 shape=[600_000] dtype=Field32 = 600_000 × 32 = 19.2 MiB > 16 MiB.
        // 600_000 < MAX_ELEMENTS=1_048_576, so element cap doesn't catch it.
        // Byte cap must.
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&600_000u32.to_be_bytes());
        bytes.push(Dtype::Field32.to_byte());
        let err = decode_exact(&bytes).unwrap_err();
        assert!(
            matches!(err, TensorFormatError::TooManyBytes { .. }),
            "expected TooManyBytes, got {err:?}"
        );
    }

    #[test]
    fn accepts_max_element_q16_at_format_ceiling() {
        // 1,048,576 Q16 elements = 4 MiB data — under MAX_DATA_BYTES (16 MiB)
        // and exactly at MAX_ELEMENTS. Header decode must succeed.
        // We don't actually allocate 4 MiB here; we just check the header path
        // and that an empty-data slice fails with Truncated (proving the
        // header-side validation passed).
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&1_048_576u32.to_be_bytes());
        bytes.push(Dtype::Q16_16.to_byte());
        // No data — should fail Truncated, not TooManyElements / TooManyBytes.
        let err = decode_one(&bytes).unwrap_err();
        assert!(
            matches!(err, TensorFormatError::Truncated { .. }),
            "expected Truncated (proving caps passed), got {err:?}"
        );
    }

    #[test]
    fn encode_rejects_oversize_byte_count_field32() {
        // 600_000 Field32 elements would be 19.2 MiB — exceeds MAX_DATA_BYTES.
        // Pass empty data; the byte-cap check fires before the
        // length-mismatch check, so we don't actually allocate 19 MiB
        // just to exercise the rejection path.
        let err = encode(&[600_000], Dtype::Field32, &[]).unwrap_err();
        assert!(matches!(err, TensorFormatError::TooManyBytes { .. }));
    }

    #[test]
    fn rejects_unknown_dtype() {
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(0xff); // unknown dtype
        let err = decode_exact(&bytes).unwrap_err();
        assert!(matches!(err, TensorFormatError::UnknownDtype(0xff)));
    }

    #[test]
    fn rejects_trailing_bytes_in_decode_exact() {
        let bytes = build_q16_tensor(&[2], &[1, 2]);
        let mut padded = bytes.clone();
        padded.push(0xff);
        let err = decode_exact(&padded).unwrap_err();
        assert!(matches!(err, TensorFormatError::TrailingBytes { extra: 1 }));
    }

    #[test]
    fn decode_one_consumes_only_first_tensor() {
        // Concatenate two encoded tensors; decode_one should return the
        // first and report the consumed length pointing at the second.
        let a = build_q16_tensor(&[2], &[10, 20]);
        let b = build_q16_tensor(&[3], &[1, 2, 3]);
        let combined: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
        let (view_a, consumed_a) = decode_one(&combined).unwrap();
        assert_eq!(view_a.shape, vec![2]);
        assert_eq!(consumed_a, a.len());
        let (view_b, consumed_b) = decode_one(&combined[consumed_a..]).unwrap();
        assert_eq!(view_b.shape, vec![3]);
        assert_eq!(consumed_b, b.len());
    }

    #[test]
    fn dtype_byte_size_constants() {
        assert_eq!(Dtype::Q16_16.byte_size(), 8);
        assert_eq!(Dtype::Field32.byte_size(), 32);
    }

    #[test]
    fn dtype_roundtrip() {
        for dt in [Dtype::Q16_16, Dtype::Field32] {
            assert_eq!(Dtype::from_byte(dt.to_byte()).unwrap(), dt);
        }
    }

    #[test]
    fn rank_zero_scalar_q16() {
        // rank=0 → shape is empty, element_count=1, single Q16 value.
        let mut bytes = vec![0u8]; // rank 0
        bytes.push(Dtype::Q16_16.to_byte());
        bytes.extend_from_slice(&42i64.to_le_bytes());
        let view = decode_exact(&bytes).unwrap();
        assert_eq!(view.shape, Vec::<u32>::new());
        assert_eq!(view.element_count(), 1);
        assert_eq!(view.data, &42i64.to_le_bytes()[..]);
    }

    #[test]
    fn encode_rejects_data_length_mismatch() {
        // shape=[2,3] = 6 elements; q16 expects 48 bytes but we pass 8.
        let bad = vec![0u8; 8];
        let err = encode(&[2, 3], Dtype::Q16_16, &bad).unwrap_err();
        assert!(matches!(err, TensorFormatError::DataLengthMismatch { expected: 48, got: 8 }));
    }

    // ----- Property-based: roundtrip ALWAYS holds. -----
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config { cases: 1024, ..Default::default() })]

        #[test]
        fn proptest_roundtrip_q16(
            // 1..=4 dims, each 1..=8 — keeps element count well under MAX_ELEMENTS
            shape in proptest::collection::vec(1u32..=8, 1..=4),
        ) {
            let element_count: usize = shape.iter().fold(1usize, |a, &b| a * b as usize);
            let data: Vec<u8> = (0..element_count * 8).map(|i| i as u8).collect();
            let bytes = encode(&shape, Dtype::Q16_16, &data).unwrap();
            let view = decode_exact(&bytes).unwrap();
            proptest::prop_assert_eq!(view.shape, shape);
            proptest::prop_assert_eq!(view.dtype, Dtype::Q16_16);
            proptest::prop_assert_eq!(view.data, &data[..]);
        }

        #[test]
        fn proptest_roundtrip_field32(
            n in 1u32..=8,
        ) {
            let data: Vec<u8> = (0..n as usize * 32).map(|i| (i & 0xff) as u8).collect();
            let bytes = encode(&[n], Dtype::Field32, &data).unwrap();
            let view = decode_exact(&bytes).unwrap();
            proptest::prop_assert_eq!(view.shape, vec![n]);
            proptest::prop_assert_eq!(view.dtype, Dtype::Field32);
            proptest::prop_assert_eq!(view.data, &data[..]);
        }
    }
}
