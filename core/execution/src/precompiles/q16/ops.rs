// citrate/core/execution/src/precompiles/q16/ops.rs
//
// Tensor-level Q16.16 operations.
//
// Each function operates on flat slices of `Q16`. Shape
// validation is the caller's responsibility (precompile
// dispatchers in RM-M2 will do it; LinearChip's differential
// test does it via the calling-test plumbing).

use super::Q16;

/// Dot product over Q16 vectors. Returns `Σ a[i] · b[i]` with
/// saturating arithmetic at every step. Caller asserts
/// `a.len() == b.len()`.
pub fn dot(a: &[Q16], b: &[Q16]) -> Q16 {
    debug_assert_eq!(
        a.len(),
        b.len(),
        "Q16 dot: vector length mismatch ({} vs {})",
        a.len(),
        b.len()
    );
    let mut acc = Q16::ZERO;
    for (x, y) in a.iter().zip(b.iter()) {
        acc = acc.saturating_add(x.saturating_mul(*y));
    }
    acc
}

/// Matrix multiplication. `a` is rows_a × cols_a, `b` is
/// cols_a × cols_b, output is rows_a × cols_b. All matrices
/// stored row-major.
///
/// Caller validates shape: `a.len() == rows_a * cols_a`,
/// `b.len() == cols_a * cols_b`. Returns a new Vec of length
/// `rows_a * cols_b`.
pub fn matmul(
    a: &[Q16],
    b: &[Q16],
    rows_a: usize,
    cols_a: usize,
    cols_b: usize,
) -> Vec<Q16> {
    debug_assert_eq!(a.len(), rows_a * cols_a);
    debug_assert_eq!(b.len(), cols_a * cols_b);
    let mut out = vec![Q16::ZERO; rows_a * cols_b];
    for i in 0..rows_a {
        for j in 0..cols_b {
            let mut acc = Q16::ZERO;
            for k in 0..cols_a {
                let aik = a[i * cols_a + k];
                let bkj = b[k * cols_b + j];
                acc = acc.saturating_add(aik.saturating_mul(bkj));
            }
            out[i * cols_b + j] = acc;
        }
    }
    out
}

/// Linear layer: `y = W · x + b` where `W` is `out_dim × in_dim`,
/// `x` is `in_dim`-vector, `b` is `out_dim`-vector. Returns
/// `out_dim`-vector. Saturating throughout.
pub fn linear(
    weights: &[Q16],
    input: &[Q16],
    bias: &[Q16],
    out_dim: usize,
    in_dim: usize,
) -> Vec<Q16> {
    debug_assert_eq!(weights.len(), out_dim * in_dim);
    debug_assert_eq!(input.len(), in_dim);
    debug_assert_eq!(bias.len(), out_dim);
    let mut out = Vec::with_capacity(out_dim);
    for i in 0..out_dim {
        let row = &weights[i * in_dim..(i + 1) * in_dim];
        let mut acc = dot(row, input);
        acc = acc.saturating_add(bias[i]);
        out.push(acc);
    }
    out
}

/// Element-wise ReLU: `max(x, 0)` per element.
pub fn relu(input: &[Q16]) -> Vec<Q16> {
    input
        .iter()
        .map(|&q| if q.0 >= 0 { q } else { Q16::ZERO })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_basic() {
        let a: Vec<Q16> = [1, 2, 3].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = [4, 5, 6].iter().map(|&n| Q16::from_int(n)).collect();
        // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(dot(&a, &b), Q16::from_int(32));
    }

    #[test]
    fn dot_orthogonal() {
        let a: Vec<Q16> = [1, 0, 0].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = [0, 1, 0].iter().map(|&n| Q16::from_int(n)).collect();
        assert_eq!(dot(&a, &b), Q16::ZERO);
    }

    #[test]
    fn matmul_basic_2x2_2x2() {
        // [[1, 2], [3, 4]] × [[5, 6], [7, 8]]
        // = [[1*5+2*7, 1*6+2*8], [3*5+4*7, 3*6+4*8]]
        // = [[19, 22], [43, 50]]
        let a: Vec<Q16> = [1, 2, 3, 4].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = [5, 6, 7, 8].iter().map(|&n| Q16::from_int(n)).collect();
        let out = matmul(&a, &b, 2, 2, 2);
        let expected: Vec<Q16> = [19, 22, 43, 50].iter().map(|&n| Q16::from_int(n)).collect();
        assert_eq!(out, expected);
    }

    #[test]
    fn matmul_identity() {
        // [[1, 2], [3, 4]] × I = [[1, 2], [3, 4]]
        let a: Vec<Q16> = [1, 2, 3, 4].iter().map(|&n| Q16::from_int(n)).collect();
        let i_mat: Vec<Q16> = [1, 0, 0, 1].iter().map(|&n| Q16::from_int(n)).collect();
        assert_eq!(matmul(&a, &i_mat, 2, 2, 2), a);
        assert_eq!(matmul(&i_mat, &a, 2, 2, 2), a);
    }

    #[test]
    fn linear_basic() {
        // y = [[1,0],[0,1]] · [3, 4] + [10, 20] = [13, 24]
        let w: Vec<Q16> = [1, 0, 0, 1].iter().map(|&n| Q16::from_int(n)).collect();
        let x: Vec<Q16> = [3, 4].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = [10, 20].iter().map(|&n| Q16::from_int(n)).collect();
        let y = linear(&w, &x, &b, 2, 2);
        let expected: Vec<Q16> = [13, 24].iter().map(|&n| Q16::from_int(n)).collect();
        assert_eq!(y, expected);
    }

    #[test]
    fn linear_with_negative_input() {
        // y = [[2, -1]] · [3, 5] + [0] = [2*3 + (-1)*5 + 0] = [1]
        let w: Vec<Q16> = [Q16::from_int(2), Q16::from_int(-1)].into();
        let x: Vec<Q16> = [3, 5].iter().map(|&n| Q16::from_int(n)).collect();
        let b: Vec<Q16> = vec![Q16::ZERO];
        let y = linear(&w, &x, &b, 1, 2);
        assert_eq!(y, vec![Q16::from_int(1)]);
    }

    #[test]
    fn relu_basic() {
        let x: Vec<Q16> = [-2, -1, 0, 1, 2].iter().map(|&n| Q16::from_int(n)).collect();
        let y = relu(&x);
        let expected: Vec<Q16> = [0, 0, 0, 1, 2].iter().map(|&n| Q16::from_int(n)).collect();
        assert_eq!(y, expected);
    }
}
