// citrate/core/execution/src/precompiles/lora.rs
//
// HUP-S7.2 / federation F-2: deterministic LoRA precompiles (agent precompile
// fork, `crate::agent_fork`). Spec: `docs/precompiles/AGENT_PRECOMPILES.md`.
//
//   0x0112 LORA_APPLY  W' = W + (alpha / r) * (B . A)
//   0x0113 LORA_MERGE  dW = sum_i w_i * (alpha_i / r_i) * (B_i . A_i)
//
// Both work on one tile of at most 256 x 256 output elements. A full adapter
// for a large model is many tiles: tile (R, C) of `B . A` is `B[R, :] . A[:, C]`,
// so a contract, a referee or a challenger can recompute any one tile of an
// applied or merged adapter on chain and compare it with a claimed tile (for
// example a federated-learning aggregate under `AggregationChallenge`). Small
// adapters (a routing head, a classifier) fit in one tile and can be applied
// whole.
//
// Arithmetic is the RM-M2 Q16.16 arithmetic (`precompiles::q16`): i64 backing,
// i128 intermediates, saturating at every step, no floats. The order of every
// operation below is part of consensus and FROZEN once the fork activates:
//
//   delta    = q16::ops::matmul(B, A)                         (row-major, k inner)
//   scaled_e = delta_e.saturating_mul(alpha).saturating_div(Q16::from_int(r))
//   APPLY:   out_e = W_e.saturating_add(scaled_e)
//   MERGE:   acc_e = acc_e.saturating_add(scaled_e.saturating_mul(w_i)), i in input order
//
// Input discipline: every tensor is the canonical v1 tensor format with dtype
// Q16_16 (0x01), the input must be consumed exactly (no trailing bytes), and
// every shape and the gas are checked BEFORE any element is parsed or any
// output is allocated.

use anyhow::{anyhow, Result};

use super::q16::{ops as q16_ops, Q16};
use super::tensor_format::{decode_one, encode, Dtype, TensorView};
use super::PrecompileResult;

/// 0x0112 LORA_APPLY.
pub const LORA_APPLY: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x12,
];
/// 0x0113 LORA_MERGE.
pub const LORA_MERGE: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x13,
];

/// Gas schedule. Conservative placeholder values, pending owner sign-off; they
/// price the work at the RM-M2 matmul rate (4 gas per multiply-add) plus a per
/// output element charge for the scale/add steps.
pub mod gas_costs {
    /// LORA_APPLY: `3000 + 4 * d * r * k + 3 * d * k`.
    pub const APPLY_BASE: u64 = 3_000;
    pub const APPLY_PER_MULADD: u64 = 4;
    pub const APPLY_PER_ELEMENT: u64 = 3;

    /// LORA_MERGE: `3000 + sum_i (4 * d * r_i * k + 4 * d * k)`.
    pub const MERGE_BASE: u64 = 3_000;
    pub const MERGE_PER_MULADD: u64 = 4;
    pub const MERGE_PER_ELEMENT: u64 = 4;
}

/// Caps, checked before allocation.
pub mod caps {
    /// Output tile rows / columns (d, k) are each at most 256.
    pub const DIM_MAX: u32 = 256;
    /// LoRA rank r is 1..=64.
    pub const RANK_MAX: u32 = 64;
    /// LORA_MERGE takes 1..=16 adapters.
    pub const MERGE_MAX_ADAPTERS: usize = 16;
}

fn check_gas(needed: u64, have: u64, op: &'static str) -> Result<()> {
    if have < needed {
        return Err(anyhow!(
            "Insufficient gas for {op}: need {needed}, have {have}"
        ));
    }
    Ok(())
}

/// Decode the next tensor at `*offset`, advancing it.
fn next<'a>(input: &'a [u8], offset: &mut usize, what: &str) -> Result<TensorView<'a>> {
    let rest = input
        .get(*offset..)
        .ok_or_else(|| anyhow!("{what}: input truncated"))?;
    let (view, consumed) = decode_one(rest).map_err(|e| anyhow!("{what}: tensor format: {e}"))?;
    *offset = offset
        .checked_add(consumed)
        .ok_or_else(|| anyhow!("{what}: offset overflow"))?;
    if view.dtype != Dtype::Q16_16 {
        return Err(anyhow!(
            "{what}: expected Q16.16 dtype (0x01), got 0x{:02x}",
            view.dtype.to_byte()
        ));
    }
    Ok(view)
}

/// A rank-2 tensor's (rows, cols).
fn matrix(view: &TensorView<'_>, what: &str) -> Result<(u32, u32)> {
    match view.shape.as_slice() {
        [rows, cols] => Ok((*rows, *cols)),
        other => Err(anyhow!("{what}: must be rank 2, got rank {}", other.len())),
    }
}

/// A rank-0 tensor (one element) as a Q16 scalar.
fn scalar(view: &TensorView<'_>, what: &str) -> Result<Q16> {
    if !view.shape.is_empty() {
        return Err(anyhow!(
            "{what}: must be a rank-0 scalar, got rank {}",
            view.shape.len()
        ));
    }
    let bytes: [u8; 8] = view
        .data
        .try_into()
        .map_err(|_| anyhow!("{what}: scalar must be 8 bytes"))?;
    Ok(Q16(i64::from_le_bytes(bytes)))
}

/// Parse a validated Q16 tensor's elements (8-byte little-endian i64 each, the
/// RM-M2 wire form).
fn elements(view: &TensorView<'_>) -> Result<Vec<Q16>> {
    let (chunks, rest) = view.data.as_chunks::<8>();
    if !rest.is_empty() {
        return Err(anyhow!(
            "tensor data is not a whole number of 8-byte elements"
        ));
    }
    let out: Vec<Q16> = chunks.iter().map(|c| Q16(i64::from_le_bytes(*c))).collect();
    if out.len() != view.element_count() {
        return Err(anyhow!("tensor data length does not match its shape"));
    }
    Ok(out)
}

fn encode_q16(shape: &[u32], data: &[Q16]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(data.len() * 8);
    for q in data {
        bytes.extend_from_slice(&q.0.to_le_bytes());
    }
    encode(shape, Dtype::Q16_16, &bytes).map_err(|e| anyhow!("tensor format: {e}"))
}

fn check_rank(r: u32, what: &str) -> Result<()> {
    if r == 0 || r > caps::RANK_MAX {
        return Err(anyhow!(
            "{what}: LoRA rank {r} outside 1..={}",
            caps::RANK_MAX
        ));
    }
    Ok(())
}

fn check_tile(d: u32, k: u32, what: &str) -> Result<()> {
    if d > caps::DIM_MAX || k > caps::DIM_MAX {
        return Err(anyhow!(
            "{what}: tile {d}x{k} exceeds the {max}x{max} cap",
            max = caps::DIM_MAX
        ));
    }
    Ok(())
}

/// `delta . alpha / r` for one adapter, in the frozen order.
fn scaled_delta(b: &[Q16], a: &[Q16], d: u32, r: u32, k: u32, alpha: Q16) -> Vec<Q16> {
    let delta = q16_ops::matmul(b, a, d as usize, r as usize, k as usize);
    // r <= 64, so the conversion to i32 is exact.
    let rank = Q16::from_int(r as i32);
    delta
        .into_iter()
        .map(|e| e.saturating_mul(alpha).saturating_div(rank))
        .collect()
}

/// 0x0112 LORA_APPLY.
///
/// **Input:** `W` (d x k) `||` `B` (d x r) `||` `A` (r x k) `||` `alpha` (rank 0), all
/// Q16.16, nothing after. **Output:** Q16 tensor `[d, k]` = `W + (alpha / r) (B . A)`.
/// **Gas:** `3000 + 4 d r k + 3 d k`.
pub fn apply(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let mut off = 0usize;
    let w = next(input, &mut off, "LORA_APPLY W")?;
    let b = next(input, &mut off, "LORA_APPLY B")?;
    let a = next(input, &mut off, "LORA_APPLY A")?;
    let alpha_v = next(input, &mut off, "LORA_APPLY alpha")?;
    if off != input.len() {
        return Err(anyhow!("LORA_APPLY: {} trailing bytes", input.len() - off));
    }
    let (d, k) = matrix(&w, "LORA_APPLY W")?;
    let (bd, r) = matrix(&b, "LORA_APPLY B")?;
    let (ar, ak) = matrix(&a, "LORA_APPLY A")?;
    check_tile(d, k, "LORA_APPLY")?;
    check_rank(r, "LORA_APPLY")?;
    if bd != d || ar != r || ak != k {
        return Err(anyhow!(
            "LORA_APPLY: shape mismatch, W {d}x{k}, B {bd}x{r}, A {ar}x{ak} \
             (B must be d x r and A r x k)"
        ));
    }
    let alpha = scalar(&alpha_v, "LORA_APPLY alpha")?;

    let (d64, r64, k64) = (u64::from(d), u64::from(r), u64::from(k));
    let gas_used = gas_costs::APPLY_BASE
        + gas_costs::APPLY_PER_MULADD * d64 * r64 * k64
        + gas_costs::APPLY_PER_ELEMENT * d64 * k64;
    check_gas(gas_used, gas_limit, "LORA_APPLY")?;

    let w_e = elements(&w)?;
    let b_e = elements(&b)?;
    let a_e = elements(&a)?;
    let scaled = scaled_delta(&b_e, &a_e, d, r, k, alpha);
    let out: Vec<Q16> = w_e
        .iter()
        .zip(scaled.iter())
        .map(|(we, se)| we.saturating_add(*se))
        .collect();
    Ok(PrecompileResult {
        output: encode_q16(&[d, k], &out)?,
        gas_used,
        success: true,
    })
}

/// 0x0113 LORA_MERGE.
///
/// **Input:** `n` (1 byte, 1..=16) then `n` times `B_i` (d x r_i) `||` `A_i` (r_i x k)
/// `||` `alpha_i` (rank 0) `||` `w_i` (rank 0), all Q16.16, nothing after. Every
/// adapter has the same `d` and `k`; ranks may differ. **Output:** Q16 tensor
/// `[d, k]` = `sum_i w_i (alpha_i / r_i) (B_i . A_i)`.
/// **Gas:** `3000 + sum_i (4 d r_i k + 4 d k)`.
pub fn merge(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    let n = usize::from(
        *input
            .first()
            .ok_or_else(|| anyhow!("LORA_MERGE: empty input"))?,
    );
    if n == 0 || n > caps::MERGE_MAX_ADAPTERS {
        return Err(anyhow!(
            "LORA_MERGE: adapter count {n} outside 1..={}",
            caps::MERGE_MAX_ADAPTERS
        ));
    }
    let mut off = 1usize;
    let mut parts = Vec::with_capacity(n);
    let mut tile: Option<(u32, u32)> = None;
    let mut gas_used = gas_costs::MERGE_BASE;
    for i in 0..n {
        let b = next(input, &mut off, "LORA_MERGE B")?;
        let a = next(input, &mut off, "LORA_MERGE A")?;
        let alpha_v = next(input, &mut off, "LORA_MERGE alpha")?;
        let weight_v = next(input, &mut off, "LORA_MERGE weight")?;
        let (d, r) = matrix(&b, "LORA_MERGE B")?;
        let (ar, k) = matrix(&a, "LORA_MERGE A")?;
        check_tile(d, k, "LORA_MERGE")?;
        check_rank(r, "LORA_MERGE")?;
        if ar != r {
            return Err(anyhow!(
                "LORA_MERGE adapter {i}: B is {d}x{r} but A is {ar}x{k} (A must be r x k)"
            ));
        }
        match tile {
            None => tile = Some((d, k)),
            Some((td, tk)) if td == d && tk == k => {}
            Some((td, tk)) => {
                return Err(anyhow!(
                    "LORA_MERGE adapter {i}: tile {d}x{k} differs from adapter 0's {td}x{tk}"
                ))
            }
        }
        let alpha = scalar(&alpha_v, "LORA_MERGE alpha")?;
        let weight = scalar(&weight_v, "LORA_MERGE weight")?;
        let (d64, r64, k64) = (u64::from(d), u64::from(r), u64::from(k));
        gas_used += gas_costs::MERGE_PER_MULADD * d64 * r64 * k64
            + gas_costs::MERGE_PER_ELEMENT * d64 * k64;
        parts.push((b, a, r, alpha, weight));
    }
    if off != input.len() {
        return Err(anyhow!("LORA_MERGE: {} trailing bytes", input.len() - off));
    }
    let (d, k) = tile.ok_or_else(|| anyhow!("LORA_MERGE: no adapters"))?;
    check_gas(gas_used, gas_limit, "LORA_MERGE")?;

    let mut acc = vec![Q16::ZERO; d as usize * k as usize];
    for (b, a, r, alpha, weight) in &parts {
        let scaled = scaled_delta(&elements(b)?, &elements(a)?, d, *r, k, *alpha);
        for (slot, s) in acc.iter_mut().zip(scaled.iter()) {
            *slot = slot.saturating_add(s.saturating_mul(*weight));
        }
    }
    Ok(PrecompileResult {
        output: encode_q16(&[d, k], &acc)?,
        gas_used,
        success: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(shape: &[u32], vals: &[i32]) -> Vec<u8> {
        let q: Vec<Q16> = vals.iter().map(|v| Q16::from_int(*v)).collect();
        encode_q16(shape, &q).expect("encode")
    }

    fn s(v: i32) -> Vec<u8> {
        t(&[], &[v])
    }

    fn out_vals(out: &[u8]) -> Vec<i64> {
        let (view, _) = decode_one(out).expect("decode output");
        elements(&view)
            .expect("elements")
            .into_iter()
            .map(|q| q.0)
            .collect()
    }

    const ONE: i64 = 1 << 16;

    #[test]
    fn apply_adds_scaled_low_rank_update() {
        // W = 0 (2x2), B = [[1],[2]] (2x1), A = [[3, 4]] (1x2), alpha = 2, r = 1:
        // B.A = [[3,4],[6,8]]; scaled by 2/1 -> [[6,8],[12,16]].
        let input = [
            t(&[2, 2], &[0, 0, 0, 0]),
            t(&[2, 1], &[1, 2]),
            t(&[1, 2], &[3, 4]),
            s(2),
        ]
        .concat();
        let r = apply(&input, 1_000_000).expect("apply");
        assert_eq!(
            out_vals(&r.output),
            vec![6 * ONE, 8 * ONE, 12 * ONE, 16 * ONE]
        );
        assert_eq!(r.gas_used, 3_000 + 4 * 2 * 2 + 3 * 4);
    }

    #[test]
    fn apply_divides_by_rank() {
        // r = 2: B = [[1, 1]] (1x2), A = [[2],[2]] (2x1): B.A = [[4]]; alpha 1, r 2 -> 2; W = 1 -> 3.
        let input = [
            t(&[1, 1], &[1]),
            t(&[1, 2], &[1, 1]),
            t(&[2, 1], &[2, 2]),
            s(1),
        ]
        .concat();
        let r = apply(&input, 1_000_000).expect("apply");
        assert_eq!(out_vals(&r.output), vec![3 * ONE]);
    }

    #[test]
    fn apply_rejects_shape_mismatch_rank_and_trailing_bytes() {
        let good = [
            t(&[2, 2], &[0; 4]),
            t(&[2, 1], &[1, 2]),
            t(&[1, 2], &[3, 4]),
            s(2),
        ]
        .concat();
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(apply(&trailing, 1_000_000).is_err());
        let bad_b = [t(&[3, 1], &[1, 2, 3]), t(&[1, 2], &[3, 4])].concat();
        let input = [t(&[2, 2], &[0; 4]), bad_b, s(2)].concat();
        assert!(apply(&input, 1_000_000).is_err());
        let not_scalar = [
            t(&[2, 2], &[0; 4]),
            t(&[2, 1], &[1, 2]),
            t(&[1, 2], &[3, 4]),
            t(&[1], &[2]),
        ]
        .concat();
        assert!(apply(&not_scalar, 1_000_000).is_err());
    }

    #[test]
    fn tile_cap_is_enforced() {
        // d = 257 exceeds the 256 cap (r = 1, k = 1, so the input stays small).
        let input = [
            t(&[257, 1], &[0; 257]),
            t(&[257, 1], &[0; 257]),
            t(&[1, 1], &[1]),
            s(1),
        ]
        .concat();
        let err = apply(&input, u64::MAX).expect_err("tile cap");
        assert!(err.to_string().contains("cap"), "{err}");
        let at_cap = [
            t(&[256, 1], &[0; 256]),
            t(&[256, 1], &[0; 256]),
            t(&[1, 1], &[1]),
            s(1),
        ]
        .concat();
        assert!(apply(&at_cap, u64::MAX).is_ok());
    }

    #[test]
    fn apply_checks_gas_before_work() {
        let input = [
            t(&[2, 2], &[0; 4]),
            t(&[2, 1], &[1, 2]),
            t(&[1, 2], &[3, 4]),
            s(2),
        ]
        .concat();
        let need = 3_000 + 4 * 2 * 2 + 3 * 4;
        assert!(apply(&input, need - 1).is_err());
        assert!(apply(&input, need).is_ok());
    }

    #[test]
    fn merge_is_weighted_sum_of_scaled_deltas() {
        // Two 1x1-tile adapters. #1: B=[[2]], A=[[3]], alpha 1, w 1 -> 6.
        // #2 (rank 2): B=[[1,1]], A=[[1],[1]] -> 2; alpha 4, r 2 -> 4; w 2 -> 8. Sum 14.
        let input = [
            vec![2u8],
            t(&[1, 1], &[2]),
            t(&[1, 1], &[3]),
            s(1),
            s(1),
            t(&[1, 2], &[1, 1]),
            t(&[2, 1], &[1, 1]),
            s(4),
            s(2),
        ]
        .concat();
        let r = merge(&input, 1_000_000).expect("merge");
        assert_eq!(out_vals(&r.output), vec![14 * ONE]);
        assert_eq!(r.gas_used, 3_000 + (4 + 4) + (4 * 2 + 4));
    }

    #[test]
    fn merge_rejects_count_tile_and_rank_errors() {
        assert!(merge(&[], 1_000_000).is_err());
        assert!(merge(&[0], 1_000_000).is_err());
        assert!(merge(&[17], 1_000_000).is_err());
        let mixed_tile = [
            vec![2u8],
            t(&[1, 1], &[2]),
            t(&[1, 1], &[3]),
            s(1),
            s(1),
            t(&[2, 1], &[1, 1]),
            t(&[1, 1], &[1]),
            s(1),
            s(1),
        ]
        .concat();
        assert!(merge(&mixed_tile, 1_000_000).is_err());
        let rank_65 = [
            vec![1u8],
            t(&[1, 65], &[0; 65]),
            t(&[65, 1], &[0; 65]),
            s(1),
            s(1),
        ]
        .concat();
        assert!(merge(&rank_65, 1_000_000).is_err());
    }

    #[test]
    fn saturates_instead_of_wrapping() {
        let big = Q16(i64::MAX);
        let w = encode_q16(&[1, 1], &[big]).expect("w");
        let input = [w, t(&[1, 1], &[1]), t(&[1, 1], &[1]), s(1)].concat();
        let r = apply(&input, 1_000_000).expect("apply");
        assert_eq!(out_vals(&r.output), vec![i64::MAX]);
    }
}
