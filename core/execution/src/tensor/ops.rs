// citrate/core/execution/src/tensor/ops.rs

use super::types::{Tensor, TensorError};
use ndarray::{ArrayD, Axis, IxDyn, Zip};

/// `f(a, b)` element-wise with `b` broadcast to `a`'s shape. ndarray's operators
/// panic when broadcasting fails; this returns `IncompatibleShapes` instead.
fn zip_with(
    a: &ArrayD<f32>,
    b: &ArrayD<f32>,
    f: impl Fn(f32, f32) -> f32,
) -> Result<ArrayD<f32>, TensorError> {
    let b = b
        .broadcast(a.raw_dim())
        .ok_or(TensorError::IncompatibleShapes)?;
    Ok(Zip::from(a).and(&b).map_collect(|&x, &y| f(x, y)))
}

/// Tensor operations implementation
pub struct TensorOps;

impl TensorOps {
    /// Element-wise addition
    pub fn add(a: &Tensor, b: &Tensor) -> Result<Tensor, TensorError> {
        if !a.shape.broadcast_compatible(&b.shape) {
            return Err(TensorError::IncompatibleShapes);
        }

        let result = zip_with(&a.data, &b.data, |x, y| x + y)?;
        Ok(Tensor {
            data: result,
            shape: a.shape.clone(),
            requires_grad: a.requires_grad || b.requires_grad,
            grad: None,
        })
    }

    /// Element-wise subtraction
    pub fn sub(a: &Tensor, b: &Tensor) -> Result<Tensor, TensorError> {
        if !a.shape.broadcast_compatible(&b.shape) {
            return Err(TensorError::IncompatibleShapes);
        }

        let result = zip_with(&a.data, &b.data, |x, y| x - y)?;
        Ok(Tensor {
            data: result,
            shape: a.shape.clone(),
            requires_grad: a.requires_grad || b.requires_grad,
            grad: None,
        })
    }

    /// Element-wise multiplication
    pub fn mul(a: &Tensor, b: &Tensor) -> Result<Tensor, TensorError> {
        if !a.shape.broadcast_compatible(&b.shape) {
            return Err(TensorError::IncompatibleShapes);
        }

        let result = zip_with(&a.data, &b.data, |x, y| x * y)?;
        Ok(Tensor {
            data: result,
            shape: a.shape.clone(),
            requires_grad: a.requires_grad || b.requires_grad,
            grad: None,
        })
    }

    /// Element-wise division
    pub fn div(a: &Tensor, b: &Tensor) -> Result<Tensor, TensorError> {
        if !a.shape.broadcast_compatible(&b.shape) {
            return Err(TensorError::IncompatibleShapes);
        }

        // Check for division by zero
        if b.data.iter().any(|&x| x == 0.0) {
            return Err(TensorError::DivisionByZero);
        }

        let result = zip_with(&a.data, &b.data, |x, y| x / y)?;
        Ok(Tensor {
            data: result,
            shape: a.shape.clone(),
            requires_grad: a.requires_grad || b.requires_grad,
            grad: None,
        })
    }

    /// Matrix multiplication
    pub fn matmul(a: &Tensor, b: &Tensor) -> Result<Tensor, TensorError> {
        // Check dimensions are compatible for matrix multiplication
        let a_shape = &a.shape.0;
        let b_shape = &b.shape.0;

        if a_shape.len() < 2 || b_shape.len() < 2 {
            return Err(TensorError::InvalidShape(
                "Tensors must have at least 2 dimensions for matmul".to_string(),
            ));
        }

        // Both have >= 2 dimensions (checked above).
        let (Some(&a_cols), Some(&b_rows)) = (
            a_shape.last(),
            b_shape.get(b_shape.len().saturating_sub(2)),
        ) else {
            return Err(TensorError::IncompatibleShapes);
        };

        if a_cols != b_rows {
            return Err(TensorError::IncompatibleShapes);
        }

        // Perform matrix multiplication using ndarray's dot product
        // This is a simplified version - full implementation would handle batched matmul
        let a_2d = a
            .data
            .view()
            .into_dimensionality::<ndarray::Ix2>()
            .map_err(|_| TensorError::InvalidShape("Cannot convert to 2D".to_string()))?;
        let b_2d = b
            .data
            .view()
            .into_dimensionality::<ndarray::Ix2>()
            .map_err(|_| TensorError::InvalidShape("Cannot convert to 2D".to_string()))?;

        let result_2d = a_2d.dot(&b_2d);
        let result_shape = vec![a_2d.nrows(), b_2d.ncols()];
        let result = ArrayD::from_shape_vec(IxDyn(&result_shape), result_2d.into_raw_vec())
            .map_err(|e| TensorError::InvalidShape(e.to_string()))?;

        Ok(Tensor {
            data: result,
            shape: super::types::TensorShape(result_shape),
            requires_grad: a.requires_grad || b.requires_grad,
            grad: None,
        })
    }

    /// Transpose tensor (swap last two dimensions)
    pub fn transpose(tensor: &Tensor) -> Result<Tensor, TensorError> {
        let shape = &tensor.shape.0;
        if shape.len() < 2 {
            return Err(TensorError::InvalidShape(
                "Tensor must have at least 2 dimensions".to_string(),
            ));
        }

        let mut axes: Vec<usize> = (0..shape.len()).collect();
        let n = axes.len(); // >= 2 (checked above)
        axes.swap(n.saturating_sub(2), n.saturating_sub(1));

        let transposed = tensor.data.view().permuted_axes(axes);
        let mut new_shape = shape.clone();
        new_shape.swap(n.saturating_sub(2), n.saturating_sub(1));

        Ok(Tensor {
            data: transposed.to_owned(),
            shape: super::types::TensorShape(new_shape),
            requires_grad: tensor.requires_grad,
            grad: None,
        })
    }

    /// Apply ReLU activation
    pub fn relu(tensor: &Tensor) -> Tensor {
        let result = tensor.data.mapv(|x| x.max(0.0));
        Tensor {
            data: result,
            shape: tensor.shape.clone(),
            requires_grad: tensor.requires_grad,
            grad: None,
        }
    }

    /// Apply Sigmoid activation
    pub fn sigmoid(tensor: &Tensor) -> Tensor {
        let result = tensor.data.mapv(|x| 1.0 / (1.0 + (-x).exp()));
        Tensor {
            data: result,
            shape: tensor.shape.clone(),
            requires_grad: tensor.requires_grad,
            grad: None,
        }
    }

    /// Apply Tanh activation
    pub fn tanh(tensor: &Tensor) -> Tensor {
        let result = tensor.data.mapv(|x| x.tanh());
        Tensor {
            data: result,
            shape: tensor.shape.clone(),
            requires_grad: tensor.requires_grad,
            grad: None,
        }
    }

    /// Apply Softmax activation along the last axis
    pub fn softmax(tensor: &Tensor) -> Result<Tensor, TensorError> {
        // A 0-dimensional tensor has no last axis.
        let axis = tensor
            .shape
            .0
            .len()
            .checked_sub(1)
            .ok_or_else(|| TensorError::InvalidShape("softmax needs at least 1 dimension".to_string()))?;

        // Compute exp(x - max) for numerical stability
        let max = tensor
            .data
            .fold_axis(Axis(axis), f32::NEG_INFINITY, |&a, &b| a.max(b))
            .insert_axis(Axis(axis));
        let exp_values = zip_with(&tensor.data, &max, |x, m| (x - m).exp())?;

        // Sum along axis
        let sum = exp_values.sum_axis(Axis(axis)).insert_axis(Axis(axis));
        let result = zip_with(&exp_values, &sum, |e, s| e / s)?;

        Ok(Tensor {
            data: result,
            shape: tensor.shape.clone(),
            requires_grad: tensor.requires_grad,
            grad: None,
        })
    }

    /// Sum all elements
    pub fn sum(tensor: &Tensor) -> f32 {
        tensor.data.sum()
    }

    /// Mean of all elements
    pub fn mean(tensor: &Tensor) -> f32 {
        tensor.data.mean().unwrap_or(0.0)
    }

    /// Max element
    pub fn max(tensor: &Tensor) -> f32 {
        tensor.data.fold(f32::NEG_INFINITY, |a, &b| a.max(b))
    }

    /// Min element
    pub fn min(tensor: &Tensor) -> f32 {
        tensor.data.fold(f32::INFINITY, |a, &b| a.min(b))
    }

    /// Compute L2 norm
    pub fn norm(tensor: &Tensor) -> f32 {
        let sum_squares = tensor.data.mapv(|x| x * x).sum();
        sum_squares.sqrt()
    }

    /// Convolution 2D operation (simplified)
    pub fn conv2d(
        input: &Tensor,
        kernel: &Tensor,
        stride: (usize, usize),
        padding: (usize, usize),
    ) -> Result<Tensor, TensorError> {
        // This is a simplified implementation
        // Full implementation would handle multiple channels, batches, etc.

        let input_shape = &input.shape.0;
        let kernel_shape = &kernel.shape.0;

        if input_shape.len() != 4 || kernel_shape.len() != 4 {
            return Err(TensorError::InvalidShape(
                "Conv2d expects 4D tensors (batch, channel, height, width)".to_string(),
            ));
        }

        // Calculate output dimensions
        let &[batch, _, in_h, in_w] = input_shape.as_slice() else {
            return Err(TensorError::IncompatibleShapes);
        };
        let &[out_c, _, k_h, k_w] = kernel_shape.as_slice() else {
            return Err(TensorError::IncompatibleShapes);
        };
        // A kernel larger than the padded input, or a zero stride, has no output.
        let out_dim = |input: usize, pad: usize, k: usize, stride: usize| {
            input
                .checked_add(pad.checked_mul(2)?)?
                .checked_sub(k)?
                .checked_div(stride)?
                .checked_add(1)
        };
        let (Some(out_h), Some(out_w)) = (
            out_dim(in_h, padding.0, k_h, stride.0),
            out_dim(in_w, padding.1, k_w, stride.1),
        ) else {
            return Err(TensorError::IncompatibleShapes);
        };

        let output_shape = vec![batch, out_c, out_h, out_w];

        // Create output tensor (simplified - just zeros for now)
        // Full implementation would perform actual convolution
        Ok(Tensor::zeros(output_shape))
    }

    /// Max pooling 2D
    pub fn maxpool2d(
        input: &Tensor,
        kernel_size: (usize, usize),
        stride: (usize, usize),
    ) -> Result<Tensor, TensorError> {
        let input_shape = &input.shape.0;

        if input_shape.len() != 4 {
            return Err(TensorError::InvalidShape(
                "MaxPool2d expects 4D tensor".to_string(),
            ));
        }

        // Calculate output dimensions
        let &[batch, channels, in_h, in_w] = input_shape.as_slice() else {
            return Err(TensorError::IncompatibleShapes);
        };
        // A window larger than the input, or a zero stride, has no output.
        let out_dim = |input: usize, k: usize, stride: usize| {
            input.checked_sub(k)?.checked_div(stride)?.checked_add(1)
        };
        let (Some(out_h), Some(out_w)) = (
            out_dim(in_h, kernel_size.0, stride.0),
            out_dim(in_w, kernel_size.1, stride.1),
        ) else {
            return Err(TensorError::IncompatibleShapes);
        };

        let output_shape = vec![batch, channels, out_h, out_w];

        // Create output tensor (simplified - just zeros for now)
        // Full implementation would perform actual max pooling
        Ok(Tensor::zeros(output_shape))
    }

    /// Batch normalization
    pub fn batch_norm(
        input: &Tensor,
        gamma: &Tensor,
        beta: &Tensor,
        eps: f32,
    ) -> Result<Tensor, TensorError> {
        // Compute mean and variance along batch dimension
        let mean = Self::mean(input);
        let variance = input
            .data
            .mapv(|x| (x - mean).powi(2))
            .mean()
            .unwrap_or(0.0);

        // Normalize
        let normalized = input.data.mapv(|x| (x - mean) / (variance + eps).sqrt());

        // Scale and shift
        let gamma_b = gamma
            .data
            .broadcast(normalized.raw_dim())
            .ok_or(TensorError::IncompatibleShapes)?;
        let beta_b = beta
            .data
            .broadcast(normalized.raw_dim())
            .ok_or(TensorError::IncompatibleShapes)?;
        let scaled = Zip::from(&normalized)
            .and(&gamma_b)
            .and(&beta_b)
            .map_collect(|&n, &g, &b| n * g + b);

        Ok(Tensor {
            data: scaled,
            shape: input.shape.clone(),
            requires_grad: input.requires_grad || gamma.requires_grad || beta.requires_grad,
            grad: None,
        })
    }

    /// Dropout (for training)
    pub fn dropout(tensor: &Tensor, p: f32, training: bool) -> Tensor {
        if !training || p == 0.0 {
            return tensor.clone();
        }

        use ndarray_rand::rand_distr::Uniform;
        use ndarray_rand::RandomExt;

        let mask = ArrayD::random(tensor.data.raw_dim(), Uniform::new(0.0, 1.0));
        let mask = mask.mapv(|x| if x > p { 1.0 / (1.0 - p) } else { 0.0 });

        // The mask is built with the tensor's own dimensions.
        let data = Zip::from(&tensor.data)
            .and(&mask)
            .map_collect(|&x, &m| x * m);
        Tensor {
            data,
            shape: tensor.shape.clone(),
            requires_grad: tensor.requires_grad,
            grad: None,
        }
    }
}

#[cfg(test)]
mod panic_s1_tests {
    use super::*;

    /// PANIC-S1: shape errors that used to panic (subtraction underflow, zero
    /// stride division, 0-d softmax, ndarray broadcast failure) are now errors.
    #[test]
    fn panic_s1_tensor_shape_errors_do_not_panic() {
        let small = Tensor::zeros(vec![1, 1, 2, 2]);
        let kernel = Tensor::zeros(vec![1, 1, 3, 3]);
        assert!(TensorOps::maxpool2d(&small, (3, 3), (1, 1)).is_err(), "window > input");
        assert!(TensorOps::maxpool2d(&small, (1, 1), (0, 1)).is_err(), "zero stride");
        assert!(TensorOps::conv2d(&small, &kernel, (1, 1), (0, 0)).is_err(), "kernel > input");
        assert!(TensorOps::conv2d(&small, &kernel, (1, 1), (1, 1)).is_ok(), "padding makes it fit");
        assert!(TensorOps::softmax(&Tensor::zeros(vec![])).is_err(), "0-d softmax");
        let a = Tensor::zeros(vec![2, 3]);
        let b = Tensor::zeros(vec![3, 2]);
        assert!(TensorOps::add(&a, &b).is_err());
        let ok = TensorOps::add(&a, &Tensor::zeros(vec![2, 3])).expect("same shape");
        assert_eq!(ok.data.shape(), &[2, 3]);
    }
}
