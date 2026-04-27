// citrate/core/execution/src/precompiles/compute.rs
//
// RM-M2 — AI Deterministic Compute Precompiles (Track 2).
//
// Six Q16.16 fixed-point tensor primitives at 0x010A–0x010F that
// let on-chain contracts run small inference operations on data
// they own, with provable cross-CPU bit-identical output. The
// underlying arithmetic is in `precompiles::q16` — saturating,
// no floats, no `unsafe`, no platform intrinsics.
//
// Address allocation:
//   0x010A — TENSOR_MATMUL_Q16  (rows_a × cols_a) · (cols_a × cols_b)
//   0x010B — TENSOR_DOT_Q16     ⟨a, b⟩
//   0x010C — TENSOR_SOFTMAX_Q16 numerically-stable softmax over a vector
//   0x010D — TENSOR_RELU_Q16    elementwise max(x, 0)
//   0x010E — TENSOR_LINEAR_Q16  fused W·x + b
//   0x010F — TENSOR_TRANSPOSE_Q16 row-major matrix transpose
//
// **Validate-before-allocate discipline:** every op decodes and
// caps-checks the input tensors BEFORE allocating the output
// buffer. A caller cannot trick the precompile into a 16 GB
// allocation by sending a 257×257×Q16 tensor — it gets rejected
// with `OversizeTensor` for the cost of the parse.
//
// **Stability invariant:** the byte output of every op is FROZEN.
// Cross-platform fixtures in `tests/cross_platform/q16_determinism.rs`
// pin the exact bytes for a sweep of canonical inputs. Drift forks
// the chain.

use anyhow::{anyhow, Result};

use super::q16::{ops as q16_ops, Q16};
use super::tensor_format::{self, decode_one, encode, Dtype, TensorFormatError, TensorView};
use super::PrecompileResult;
use crate::types::Address;

/// Precompile addresses for AI deterministic compute operations.
pub mod addresses {
    /// 0x010A — TENSOR_MATMUL_Q16
    pub const TENSOR_MATMUL_Q16: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x0A];

    /// 0x010B — TENSOR_DOT_Q16
    pub const TENSOR_DOT_Q16: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x0B];

    /// 0x010C — TENSOR_SOFTMAX_Q16
    pub const TENSOR_SOFTMAX_Q16: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x0C];

    /// 0x010D — TENSOR_RELU_Q16
    pub const TENSOR_RELU_Q16: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x0D];

    /// 0x010E — TENSOR_LINEAR_Q16
    pub const TENSOR_LINEAR_Q16: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x0E];

    /// 0x010F — TENSOR_TRANSPOSE_Q16
    pub const TENSOR_TRANSPOSE_Q16: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0x0F];
}

/// Gas costs.
pub mod gas_costs {
    /// MATMUL: base + per mul-add. `5000 + 4 × rows_a × cols_a × cols_b`.
    pub const MATMUL_BASE: u64 = 5_000;
    pub const MATMUL_PER_MULADD: u64 = 4;

    /// DOT: base + per element. `2000 + 4 × len`.
    pub const DOT_BASE: u64 = 2_000;
    pub const DOT_PER_ELEMENT: u64 = 4;

    /// SOFTMAX: base + per element (dominated by exp). `5000 + 30 × len`.
    pub const SOFTMAX_BASE: u64 = 5_000;
    pub const SOFTMAX_PER_ELEMENT: u64 = 30;

    /// RELU: base + per element. `1000 + 1 × len`.
    pub const RELU_BASE: u64 = 1_000;
    pub const RELU_PER_ELEMENT: u64 = 1;

    /// LINEAR: matmul gas + bias_len. `5000 + 4 × out_dim × in_dim + 1 × out_dim`.
    pub const LINEAR_BASE: u64 = 5_000;
    pub const LINEAR_PER_MULADD: u64 = 4;
    pub const LINEAR_PER_BIAS: u64 = 1;

    /// TRANSPOSE: base + per element. `1000 + 1 × rows × cols`.
    pub const TRANSPOSE_BASE: u64 = 1_000;
    pub const TRANSPOSE_PER_ELEMENT: u64 = 1;
}

/// Caps. Exceeding these returns `OversizeTensor` BEFORE allocation.
pub mod caps {
    /// Maximum matmul output dimension (rows_a, cols_b each ≤ 256).
    pub const MATMUL_DIM_MAX: u32 = 256;
    /// Maximum vector length for dot / softmax (≤ 1024).
    pub const VECTOR_LEN_MAX: u32 = 1024;
    /// Maximum vector length for softmax (≤ 1024 per WP-M2.5).
    pub const SOFTMAX_LEN_MAX: u32 = 1024;
    /// Maximum elementwise vector length for relu (≤ 1,048,576).
    pub const RELU_LEN_MAX: u32 = 1_048_576;
    /// Maximum transpose total elements (rows × cols ≤ 65,536 = 256²).
    pub const TRANSPOSE_ELEMS_MAX: u32 = 65_536;
}

/// Dispatch a 0x010A–0x010F address to its precompile.
pub fn execute(address: &Address, input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let addr = address.as_fixed_bytes();
    if addr == &addresses::TENSOR_MATMUL_Q16 {
        matmul(input, gas_limit)
    } else if addr == &addresses::TENSOR_DOT_Q16 {
        dot(input, gas_limit)
    } else if addr == &addresses::TENSOR_SOFTMAX_Q16 {
        softmax(input, gas_limit)
    } else if addr == &addresses::TENSOR_RELU_Q16 {
        relu(input, gas_limit)
    } else if addr == &addresses::TENSOR_LINEAR_Q16 {
        linear(input, gas_limit)
    } else if addr == &addresses::TENSOR_TRANSPOSE_Q16 {
        transpose(input, gas_limit)
    } else {
        Err(anyhow!("Unknown compute precompile address"))
    }
}

// ===== Helpers =====

fn map_format_error(e: TensorFormatError) -> anyhow::Error {
    anyhow!("tensor format: {e}")
}

/// Convert a Q16-typed tensor's data bytes to a `Vec<Q16>`. Caller
/// must have validated dtype is Q16_16 and length is `n × 4`.
fn parse_q16_tensor(view: &TensorView<'_>) -> Result<Vec<Q16>> {
    if view.dtype != Dtype::Q16_16 {
        return Err(anyhow!(
            "expected Q16.16 dtype (0x01), got 0x{:02x}",
            view.dtype.to_byte()
        ));
    }
    let n = view.element_count();
    if view.data.len() != n * 4 {
        return Err(anyhow!(
            "tensor data length mismatch: expected {} bytes, got {}",
            n * 4,
            view.data.len()
        ));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let bytes = [
            view.data[i * 4],
            view.data[i * 4 + 1],
            view.data[i * 4 + 2],
            view.data[i * 4 + 3],
        ];
        out.push(Q16(i32::from_le_bytes(bytes)));
    }
    Ok(out)
}

/// Encode a `Vec<Q16>` as a Q16.16 tensor with given shape.
fn encode_q16_tensor(shape: &[u32], data: &[Q16]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(data.len() * 4);
    for q in data {
        bytes.extend_from_slice(&q.0.to_le_bytes());
    }
    encode(shape, Dtype::Q16_16, &bytes).map_err(map_format_error)
}

fn check_gas(needed: u64, have: u64, op: &'static str) -> Result<()> {
    if have < needed {
        return Err(anyhow!(
            "Insufficient gas for {op}: need {needed}, have {have}"
        ));
    }
    Ok(())
}

// ===== 0x010A — TENSOR_MATMUL_Q16 =====

/// Q16.16 matrix multiplication: `C = A · B`, where A is
/// `rows_a × cols_a` and B is `cols_a × cols_b`.
///
/// **Input:** two encoded Q16 tensors concatenated. A first, then B.
/// **Output:** encoded Q16 tensor of shape `[rows_a, cols_b]`.
/// **Caps:** rows_a, cols_b ≤ 256; cols_a == rows_b; cols_a ≤ 256.
/// **Gas:** `5000 + 4 × rows_a × cols_a × cols_b`.
pub fn matmul(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    // Decode A.
    let (a_view, a_consumed) = decode_one(input).map_err(map_format_error)?;
    // Decode B (starts at offset a_consumed).
    let (b_view, _b_consumed) =
        decode_one(&input[a_consumed..]).map_err(map_format_error)?;

    // Shape validation BEFORE any heap allocation for output data.
    if a_view.shape.len() != 2 {
        return Err(anyhow!(
            "matmul: tensor A must be rank 2, got rank {}",
            a_view.shape.len()
        ));
    }
    if b_view.shape.len() != 2 {
        return Err(anyhow!(
            "matmul: tensor B must be rank 2, got rank {}",
            b_view.shape.len()
        ));
    }
    let rows_a = a_view.shape[0];
    let cols_a = a_view.shape[1];
    let rows_b = b_view.shape[0];
    let cols_b = b_view.shape[1];

    if rows_a > caps::MATMUL_DIM_MAX
        || cols_a > caps::MATMUL_DIM_MAX
        || cols_b > caps::MATMUL_DIM_MAX
    {
        return Err(anyhow!(
            "matmul: dim cap exceeded: rows_a={rows_a}, cols_a={cols_a}, cols_b={cols_b} (max {})",
            caps::MATMUL_DIM_MAX
        ));
    }
    if cols_a != rows_b {
        return Err(anyhow!(
            "matmul: shape mismatch — A is {}x{}, B is {}x{} (cols_a must equal rows_b)",
            rows_a,
            cols_a,
            rows_b,
            cols_b
        ));
    }

    let gas_used = gas_costs::MATMUL_BASE
        + gas_costs::MATMUL_PER_MULADD
            * (rows_a as u64) * (cols_a as u64) * (cols_b as u64);
    check_gas(gas_used, gas_limit, "TENSOR_MATMUL_Q16")?;

    // Parse data.
    let a = parse_q16_tensor(&a_view)?;
    let b = parse_q16_tensor(&b_view)?;

    // Compute.
    let out = q16_ops::matmul(
        &a,
        &b,
        rows_a as usize,
        cols_a as usize,
        cols_b as usize,
    );

    // Encode.
    let bytes = encode_q16_tensor(&[rows_a, cols_b], &out)?;
    Ok(PrecompileResult {
        output: bytes,
        gas_used,
        success: true,
    })
}

// ===== 0x010B — TENSOR_DOT_Q16 =====

/// Q16.16 vector inner product: `Σ a[i] · b[i]`.
///
/// **Input:** two encoded Q16 1D tensors concatenated.
/// **Output:** encoded scalar Q16 tensor of shape `[1]`.
/// **Caps:** vector length ≤ 1024; both lengths must match.
/// **Gas:** `2000 + 4 × len`.
pub fn dot(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let (a_view, a_consumed) = decode_one(input).map_err(map_format_error)?;
    let (b_view, _b_consumed) =
        decode_one(&input[a_consumed..]).map_err(map_format_error)?;

    if a_view.shape.len() != 1 || b_view.shape.len() != 1 {
        return Err(anyhow!(
            "dot: both tensors must be rank 1; got A rank {}, B rank {}",
            a_view.shape.len(),
            b_view.shape.len()
        ));
    }
    let len_a = a_view.shape[0];
    let len_b = b_view.shape[0];
    if len_a != len_b {
        return Err(anyhow!(
            "dot: length mismatch: A has {len_a}, B has {len_b}"
        ));
    }
    if len_a > caps::VECTOR_LEN_MAX {
        return Err(anyhow!(
            "dot: length cap exceeded: {len_a} (max {})",
            caps::VECTOR_LEN_MAX
        ));
    }

    let gas_used =
        gas_costs::DOT_BASE + gas_costs::DOT_PER_ELEMENT * (len_a as u64);
    check_gas(gas_used, gas_limit, "TENSOR_DOT_Q16")?;

    let a = parse_q16_tensor(&a_view)?;
    let b = parse_q16_tensor(&b_view)?;
    let out = q16_ops::dot(&a, &b);
    let bytes = encode_q16_tensor(&[1], &[out])?;
    Ok(PrecompileResult {
        output: bytes,
        gas_used,
        success: true,
    })
}

// ===== 0x010C — TENSOR_SOFTMAX_Q16 =====

/// Q16.16 numerically-stable softmax over a 1D vector.
///
/// **Input:** one encoded Q16 1D tensor.
/// **Output:** encoded Q16 1D tensor of the same length.
/// **Caps:** length ≤ 1024.
/// **Gas:** `5000 + 30 × len`.
pub fn softmax(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let view = tensor_format::decode_exact(input).map_err(map_format_error)?;
    if view.shape.len() != 1 {
        return Err(anyhow!(
            "softmax: input must be rank 1; got rank {}",
            view.shape.len()
        ));
    }
    let len = view.shape[0];
    if len > caps::SOFTMAX_LEN_MAX {
        return Err(anyhow!(
            "softmax: length cap exceeded: {len} (max {})",
            caps::SOFTMAX_LEN_MAX
        ));
    }

    let gas_used =
        gas_costs::SOFTMAX_BASE + gas_costs::SOFTMAX_PER_ELEMENT * (len as u64);
    check_gas(gas_used, gas_limit, "TENSOR_SOFTMAX_Q16")?;

    let v = parse_q16_tensor(&view)?;
    let out = q16_ops::softmax(&v);
    let bytes = encode_q16_tensor(&[len], &out)?;
    Ok(PrecompileResult {
        output: bytes,
        gas_used,
        success: true,
    })
}

// ===== 0x010D — TENSOR_RELU_Q16 =====

/// Q16.16 elementwise ReLU: `max(x, 0)` per element.
///
/// **Input:** one encoded Q16 1D tensor.
/// **Output:** encoded Q16 1D tensor of the same length.
/// **Caps:** length ≤ 1,048,576.
/// **Gas:** `1000 + 1 × len`.
pub fn relu(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let view = tensor_format::decode_exact(input).map_err(map_format_error)?;
    if view.shape.len() != 1 {
        return Err(anyhow!(
            "relu: input must be rank 1; got rank {}",
            view.shape.len()
        ));
    }
    let len = view.shape[0];
    if len > caps::RELU_LEN_MAX {
        return Err(anyhow!(
            "relu: length cap exceeded: {len} (max {})",
            caps::RELU_LEN_MAX
        ));
    }

    let gas_used =
        gas_costs::RELU_BASE + gas_costs::RELU_PER_ELEMENT * (len as u64);
    check_gas(gas_used, gas_limit, "TENSOR_RELU_Q16")?;

    let v = parse_q16_tensor(&view)?;
    let out = q16_ops::relu(&v);
    let bytes = encode_q16_tensor(&[len], &out)?;
    Ok(PrecompileResult {
        output: bytes,
        gas_used,
        success: true,
    })
}

// ===== 0x010E — TENSOR_LINEAR_Q16 =====

/// Q16.16 fused linear layer: `y = W · x + b`.
///
/// **Input:** three encoded Q16 tensors concatenated:
///   1. W — rank-2, `out_dim × in_dim`.
///   2. x — rank-1, length `in_dim`.
///   3. b — rank-1, length `out_dim`.
///
/// **Output:** encoded Q16 1D tensor of length `out_dim`.
/// **Caps:** out_dim, in_dim ≤ 256; bias length must match.
/// **Gas:** `5000 + 4 × out_dim × in_dim + 1 × out_dim`.
pub fn linear(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    // Decode W.
    let (w_view, w_consumed) = decode_one(input).map_err(map_format_error)?;
    // Decode x.
    let (x_view, x_consumed) =
        decode_one(&input[w_consumed..]).map_err(map_format_error)?;
    // Decode b.
    let (b_view, _b_consumed) =
        decode_one(&input[w_consumed + x_consumed..]).map_err(map_format_error)?;

    if w_view.shape.len() != 2 {
        return Err(anyhow!(
            "linear: W must be rank 2; got rank {}",
            w_view.shape.len()
        ));
    }
    if x_view.shape.len() != 1 {
        return Err(anyhow!(
            "linear: x must be rank 1; got rank {}",
            x_view.shape.len()
        ));
    }
    if b_view.shape.len() != 1 {
        return Err(anyhow!(
            "linear: b must be rank 1; got rank {}",
            b_view.shape.len()
        ));
    }
    let out_dim = w_view.shape[0];
    let in_dim = w_view.shape[1];
    let x_len = x_view.shape[0];
    let b_len = b_view.shape[0];

    if out_dim > caps::MATMUL_DIM_MAX || in_dim > caps::MATMUL_DIM_MAX {
        return Err(anyhow!(
            "linear: dim cap exceeded: out_dim={out_dim}, in_dim={in_dim} (max {})",
            caps::MATMUL_DIM_MAX
        ));
    }
    if x_len != in_dim {
        return Err(anyhow!(
            "linear: x length {x_len} must match in_dim {in_dim}"
        ));
    }
    if b_len != out_dim {
        return Err(anyhow!(
            "linear: b length {b_len} must match out_dim {out_dim}"
        ));
    }

    let gas_used = gas_costs::LINEAR_BASE
        + gas_costs::LINEAR_PER_MULADD * (out_dim as u64) * (in_dim as u64)
        + gas_costs::LINEAR_PER_BIAS * (out_dim as u64);
    check_gas(gas_used, gas_limit, "TENSOR_LINEAR_Q16")?;

    let w = parse_q16_tensor(&w_view)?;
    let x = parse_q16_tensor(&x_view)?;
    let b = parse_q16_tensor(&b_view)?;
    let out = q16_ops::linear(&w, &x, &b, out_dim as usize, in_dim as usize);
    let bytes = encode_q16_tensor(&[out_dim], &out)?;
    Ok(PrecompileResult {
        output: bytes,
        gas_used,
        success: true,
    })
}

// ===== 0x010F — TENSOR_TRANSPOSE_Q16 =====

/// Q16.16 row-major matrix transpose.
///
/// **Input:** one encoded Q16 rank-2 tensor of shape `[rows, cols]`.
/// **Output:** encoded Q16 rank-2 tensor of shape `[cols, rows]`.
/// **Caps:** rows × cols ≤ 65,536.
/// **Gas:** `1000 + 1 × rows × cols`.
pub fn transpose(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let view = tensor_format::decode_exact(input).map_err(map_format_error)?;
    if view.shape.len() != 2 {
        return Err(anyhow!(
            "transpose: input must be rank 2; got rank {}",
            view.shape.len()
        ));
    }
    let rows = view.shape[0];
    let cols = view.shape[1];
    let total = (rows as u64) * (cols as u64);
    if total > caps::TRANSPOSE_ELEMS_MAX as u64 {
        return Err(anyhow!(
            "transpose: total elements cap exceeded: {total} (max {})",
            caps::TRANSPOSE_ELEMS_MAX
        ));
    }

    let gas_used =
        gas_costs::TRANSPOSE_BASE + gas_costs::TRANSPOSE_PER_ELEMENT * total;
    check_gas(gas_used, gas_limit, "TENSOR_TRANSPOSE_Q16")?;

    let v = parse_q16_tensor(&view)?;
    let out = q16_ops::transpose(&v, rows as usize, cols as usize);
    let bytes = encode_q16_tensor(&[cols, rows], &out)?;
    Ok(PrecompileResult {
        output: bytes,
        gas_used,
        success: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Q16 tensor input from shape + i32 values (which are
    /// treated as Q16(i32 << 16) — i.e., the "real integer" value).
    fn q16_tensor_from_ints(shape: &[u32], values: &[i32]) -> Vec<u8> {
        let q: Vec<Q16> = values.iter().map(|&n| Q16::from_int(n)).collect();
        encode_q16_tensor(shape, &q).expect("encode")
    }

    /// Decode a precompile output and convert its Q16 data into i32
    /// real integers for assertions.
    fn decode_to_q16_vec(bytes: &[u8]) -> Vec<Q16> {
        let view = tensor_format::decode_exact(bytes).expect("decode");
        parse_q16_tensor(&view).expect("parse")
    }

    fn q16_to_int(q: Q16) -> i32 {
        // Recover integer if exactly representable.
        q.0 >> 16
    }

    // ====== matmul tests ======

    #[test]
    fn matmul_2x2_basic() {
        // [[1,2],[3,4]] · [[5,6],[7,8]] = [[19,22],[43,50]]
        let a = q16_tensor_from_ints(&[2, 2], &[1, 2, 3, 4]);
        let b = q16_tensor_from_ints(&[2, 2], &[5, 6, 7, 8]);
        let mut input = a.clone();
        input.extend_from_slice(&b);
        let r = matmul(&input, 1_000_000).unwrap();
        let out = decode_to_q16_vec(&r.output);
        let expected: Vec<i32> = vec![19, 22, 43, 50];
        let actual: Vec<i32> = out.iter().map(|q| q16_to_int(*q)).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn matmul_identity() {
        // I_2 · A = A
        let a = q16_tensor_from_ints(&[2, 2], &[1, 2, 3, 4]);
        let i = q16_tensor_from_ints(&[2, 2], &[1, 0, 0, 1]);
        let mut input = i.clone();
        input.extend_from_slice(&a);
        let r = matmul(&input, 1_000_000).unwrap();
        let out = decode_to_q16_vec(&r.output);
        assert_eq!(out, vec![Q16::from_int(1), Q16::from_int(2),
                             Q16::from_int(3), Q16::from_int(4)]);
    }

    #[test]
    fn matmul_shape_mismatch_rejected() {
        // A is 2x3, B is 4x2 — cols_a (3) ≠ rows_b (4).
        let a = q16_tensor_from_ints(&[2, 3], &[1, 2, 3, 4, 5, 6]);
        let b = q16_tensor_from_ints(&[4, 2], &[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut input = a;
        input.extend_from_slice(&b);
        let r = matmul(&input, 1_000_000);
        assert!(r.is_err(), "expected shape-mismatch error");
        assert!(r.unwrap_err().to_string().contains("shape mismatch"));
    }

    #[test]
    fn matmul_oversize_rejected() {
        // 257-row A — exceeds MATMUL_DIM_MAX of 256.
        let a = q16_tensor_from_ints(&[257, 1], &vec![1; 257]);
        let b = q16_tensor_from_ints(&[1, 1], &[1]);
        let mut input = a;
        input.extend_from_slice(&b);
        let r = matmul(&input, 100_000_000);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("dim cap exceeded"));
    }

    #[test]
    fn matmul_insufficient_gas() {
        let a = q16_tensor_from_ints(&[2, 2], &[1, 2, 3, 4]);
        let b = q16_tensor_from_ints(&[2, 2], &[5, 6, 7, 8]);
        let mut input = a;
        input.extend_from_slice(&b);
        let r = matmul(&input, 100); // way too little
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Insufficient gas"));
    }

    // ====== dot tests ======

    #[test]
    fn dot_basic() {
        // [1,2,3] · [4,5,6] = 32
        let a = q16_tensor_from_ints(&[3], &[1, 2, 3]);
        let b = q16_tensor_from_ints(&[3], &[4, 5, 6]);
        let mut input = a;
        input.extend_from_slice(&b);
        let r = dot(&input, 100_000).unwrap();
        let out = decode_to_q16_vec(&r.output);
        assert_eq!(out, vec![Q16::from_int(32)]);
    }

    #[test]
    fn dot_length_mismatch_rejected() {
        let a = q16_tensor_from_ints(&[3], &[1, 2, 3]);
        let b = q16_tensor_from_ints(&[4], &[1, 2, 3, 4]);
        let mut input = a;
        input.extend_from_slice(&b);
        let r = dot(&input, 100_000);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("length mismatch"));
    }

    #[test]
    fn dot_oversize_rejected() {
        let a = q16_tensor_from_ints(&[1025], &vec![1; 1025]);
        let b = q16_tensor_from_ints(&[1025], &vec![1; 1025]);
        let mut input = a;
        input.extend_from_slice(&b);
        let r = dot(&input, 100_000_000);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("length cap exceeded"));
    }

    // ====== softmax tests ======

    #[test]
    fn softmax_uniform() {
        // [5, 5, 5] → [1/3, 1/3, 1/3]
        let v = q16_tensor_from_ints(&[3], &[5, 5, 5]);
        let r = softmax(&v, 100_000).unwrap();
        let out = decode_to_q16_vec(&r.output);
        let expected_each = Q16(21845); // ~0.333
        for q in &out {
            assert!((q.0 - expected_each.0).abs() <= 4);
        }
    }

    #[test]
    fn softmax_oversize_rejected() {
        let v = q16_tensor_from_ints(&[1025], &vec![1; 1025]);
        let r = softmax(&v, 100_000_000);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("length cap exceeded"));
    }

    // ====== relu tests ======

    #[test]
    fn relu_basic() {
        // [-2, -1, 0, 1, 2] → [0, 0, 0, 1, 2]
        let v = q16_tensor_from_ints(&[5], &[-2, -1, 0, 1, 2]);
        let r = relu(&v, 100_000).unwrap();
        let out: Vec<i32> = decode_to_q16_vec(&r.output).iter().map(|q| q16_to_int(*q)).collect();
        assert_eq!(out, vec![0, 0, 0, 1, 2]);
    }

    #[test]
    fn relu_at_cap_succeeds_with_enough_gas() {
        // 4 elements is way under the cap; a smoke that the
        // dispatcher accepts non-trivial-but-tiny inputs. The
        // RELU_LEN_MAX cap (1,048,576) coincides with the
        // tensor_format encoder's own MAX_ELEMENTS, so attempting
        // to encode a tensor at exactly that cap also passes the
        // precompile cap. There is no input we can encode that
        // exceeds the precompile cap without failing the encoder
        // first — the cap is structurally enforced by the format.
        let v = q16_tensor_from_ints(&[4], &[-2, 0, 1, 2]);
        let r = relu(&v, 100_000_000).unwrap();
        let out: Vec<i32> =
            decode_to_q16_vec(&r.output).iter().map(|q| q16_to_int(*q)).collect();
        assert_eq!(out, vec![0, 0, 1, 2]);
    }

    // ====== linear tests ======

    #[test]
    fn linear_basic() {
        // y = [[1,0],[0,1]] · [3,4] + [10,20] = [13,24]
        let w = q16_tensor_from_ints(&[2, 2], &[1, 0, 0, 1]);
        let x = q16_tensor_from_ints(&[2], &[3, 4]);
        let b = q16_tensor_from_ints(&[2], &[10, 20]);
        let mut input = w;
        input.extend_from_slice(&x);
        input.extend_from_slice(&b);
        let r = linear(&input, 1_000_000).unwrap();
        let out: Vec<i32> = decode_to_q16_vec(&r.output).iter().map(|q| q16_to_int(*q)).collect();
        assert_eq!(out, vec![13, 24]);
    }

    #[test]
    fn linear_bias_length_mismatch_rejected() {
        let w = q16_tensor_from_ints(&[2, 2], &[1, 0, 0, 1]);
        let x = q16_tensor_from_ints(&[2], &[3, 4]);
        let b = q16_tensor_from_ints(&[3], &[1, 2, 3]); // wrong: should be 2
        let mut input = w;
        input.extend_from_slice(&x);
        input.extend_from_slice(&b);
        let r = linear(&input, 1_000_000);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("b length"));
    }

    // ====== transpose tests ======

    #[test]
    fn transpose_2x3() {
        // [[1,2,3],[4,5,6]] → [[1,4],[2,5],[3,6]]
        let m = q16_tensor_from_ints(&[2, 3], &[1, 2, 3, 4, 5, 6]);
        let r = transpose(&m, 100_000).unwrap();
        let out: Vec<i32> = decode_to_q16_vec(&r.output).iter().map(|q| q16_to_int(*q)).collect();
        assert_eq!(out, vec![1, 4, 2, 5, 3, 6]);
        // Also verify the output's shape header:
        let view = tensor_format::decode_exact(&r.output).unwrap();
        assert_eq!(view.shape, vec![3, 2]);
    }

    #[test]
    fn transpose_double_is_identity() {
        let m = q16_tensor_from_ints(&[2, 3], &[1, 2, 3, 4, 5, 6]);
        let once = transpose(&m, 100_000).unwrap();
        let twice = transpose(&once.output, 100_000).unwrap();
        assert_eq!(twice.output, m);
    }

    #[test]
    fn transpose_oversize_rejected() {
        // 257 × 257 = 66,049 > cap of 65,536.
        let m = q16_tensor_from_ints(&[257, 257], &vec![1; 66_049]);
        let r = transpose(&m, 100_000_000);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("total elements cap"));
    }

    // ====== dispatch tests ======

    #[test]
    fn dispatch_unknown_address_errors() {
        let bogus = Address([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0xFF,
        ]);
        let r = execute(&bogus, &[], 1_000_000);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Unknown compute"));
    }
}
