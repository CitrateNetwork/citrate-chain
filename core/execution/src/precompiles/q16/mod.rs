// citrate/core/execution/src/precompiles/q16/mod.rs
//
// **Q16.16 fixed-point arithmetic library.**
//
// Hand-rolled, integer-only, saturating, deterministic. Designed
// to be the substrate that RM-M2 deterministic compute precompiles
// (0x010A–0x010F) consume, and that the RM-M1b LinearChip
// differential-tests against.
//
// **Encoding:**
//   - One value = `i32` packed as: high 16 bits = signed integer
//     part, low 16 bits = unsigned fractional part.
//   - Equivalently: stored value × 2¹⁶ = canonical_real_value.
//   - Range: [-32_768.00000, +32_767.99998]
//   - Resolution: ≈ 1.526 × 10⁻⁵ (= 2⁻¹⁶)
//
// **Determinism guarantee:** every operation in this module
// uses ONLY i32 / i64 arithmetic. No floats. No platform-
// dependent intrinsics. No `unsafe`. Bit-identical on any CPU.
//
// **Saturation:** overflow saturates to `Q16::MAX` or `Q16::MIN`,
// never wraps, never panics. This is the standard convention
// for fixed-point math in real-time systems.
//
// **Status (RM-M1b WP-M1b.3 in-flight):** this is the
// FOUNDATIONAL Rust library. RM-M2 will:
//   - wrap selected ops as precompiles at 0x010A–0x010F
//   - add gas pricing per op
//   - author cross-platform fixture tests
//   - author the TLA+ Q16Arithmetic determinism spec
//   - author check_m2_no_float / check_m2_caps_enforced verifiers
//
// We're shipping the LIBRARY in RM-M1b because LinearChip's
// differential test needs it. The precompile dispatcher and
// RM-M2 governance machinery land in their own sprint.

#![allow(dead_code)]

pub mod ops;

/// Q16.16 fixed-point value stored as `i32`. The canonical real-
/// number value is `inner / 2¹⁶`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Q16(pub i32);

const SHIFT: u32 = 16;
const SCALE: i64 = 1 << SHIFT;

impl Q16 {
    pub const MAX: Q16 = Q16(i32::MAX);
    pub const MIN: Q16 = Q16(i32::MIN);
    pub const ZERO: Q16 = Q16(0);
    pub const ONE: Q16 = Q16(1 << SHIFT);

    /// Construct from an integer (no fractional part).
    /// Saturates if `n` exceeds Q16's representable range.
    pub fn from_int(n: i32) -> Q16 {
        match (n as i64).checked_shl(SHIFT) {
            Some(v) if v <= i32::MAX as i64 && v >= i32::MIN as i64 => Q16(v as i32),
            Some(v) if v > i32::MAX as i64 => Q16::MAX,
            Some(_) => Q16::MIN,
            None if n > 0 => Q16::MAX,
            None => Q16::MIN,
        }
    }

    /// Construct from a raw i32 representation. The caller is
    /// responsible for ensuring `raw` is the intended Q16 encoding.
    /// Used for parsing wire-format bytes.
    pub fn from_raw(raw: i32) -> Q16 {
        Q16(raw)
    }

    /// Saturating addition.
    pub fn saturating_add(self, other: Q16) -> Q16 {
        Q16(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction.
    pub fn saturating_sub(self, other: Q16) -> Q16 {
        Q16(self.0.saturating_sub(other.0))
    }

    /// Saturating multiplication.
    /// (a / 2¹⁶) × (b / 2¹⁶) = (a × b) / 2³² → result = (a × b) >> 16
    /// Use i64 intermediate to avoid overflow before shifting.
    pub fn saturating_mul(self, other: Q16) -> Q16 {
        let prod_64: i64 = (self.0 as i64) * (other.0 as i64);
        let shifted: i64 = prod_64 >> SHIFT;
        if shifted > i32::MAX as i64 {
            Q16::MAX
        } else if shifted < i32::MIN as i64 {
            Q16::MIN
        } else {
            Q16(shifted as i32)
        }
    }

    /// Saturating division. Division by zero returns `MAX` or
    /// `MIN` matching the sign of the numerator (no panic).
    pub fn saturating_div(self, other: Q16) -> Q16 {
        if other.0 == 0 {
            return if self.0 >= 0 { Q16::MAX } else { Q16::MIN };
        }
        // (a / 2¹⁶) / (b / 2¹⁶) = a / b. To preserve the Q16
        // scale, compute (a << 16) / b in i64.
        let num_64: i64 = (self.0 as i64) << SHIFT;
        let result: i64 = num_64 / (other.0 as i64);
        if result > i32::MAX as i64 {
            Q16::MAX
        } else if result < i32::MIN as i64 {
            Q16::MIN
        } else {
            Q16(result as i32)
        }
    }

    /// Saturating negation. -i32::MIN saturates to i32::MAX.
    pub fn saturating_neg(self) -> Q16 {
        if self.0 == i32::MIN {
            Q16::MAX
        } else {
            Q16(-self.0)
        }
    }

    /// Convert to `f64` for diagnostics / external comparison.
    /// **NOT used by any precompile or chip path** — purely
    /// human-readable for debugging.
    pub fn to_f64(self) -> f64 {
        (self.0 as f64) / (SCALE as f64)
    }

    /// Construct from `f64` for test fixtures only. Saturates on
    /// overflow. **NOT a deterministic primitive** — different
    /// f64 inputs that round-trip differently can produce
    /// different Q16 outputs. Use `from_int` or `from_raw` in
    /// production paths.
    #[cfg(test)]
    pub fn from_f64(x: f64) -> Q16 {
        let scaled = (x * (SCALE as f64)).round();
        if scaled > i32::MAX as f64 {
            Q16::MAX
        } else if scaled < i32::MIN as f64 {
            Q16::MIN
        } else {
            Q16(scaled as i32)
        }
    }
}

impl std::ops::Add for Q16 {
    type Output = Q16;
    fn add(self, other: Q16) -> Q16 {
        self.saturating_add(other)
    }
}
impl std::ops::Sub for Q16 {
    type Output = Q16;
    fn sub(self, other: Q16) -> Q16 {
        self.saturating_sub(other)
    }
}
impl std::ops::Mul for Q16 {
    type Output = Q16;
    fn mul(self, other: Q16) -> Q16 {
        self.saturating_mul(other)
    }
}
impl std::ops::Div for Q16 {
    type Output = Q16;
    fn div(self, other: Q16) -> Q16 {
        self.saturating_div(other)
    }
}
impl std::ops::Neg for Q16 {
    type Output = Q16;
    fn neg(self) -> Q16 {
        self.saturating_neg()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_is_correct() {
        assert_eq!(Q16::ONE.0, 1 << SHIFT);
        assert!((Q16::ONE.to_f64() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn from_int_roundtrip() {
        for n in [-1, 0, 1, 100, -100, 32767, -32768] {
            let q = Q16::from_int(n);
            assert!((q.to_f64() - n as f64).abs() < 1e-9, "from_int({n})");
        }
    }

    #[test]
    fn from_int_saturates() {
        assert_eq!(Q16::from_int(100_000), Q16::MAX);
        assert_eq!(Q16::from_int(-100_000), Q16::MIN);
    }

    #[test]
    fn add_basic() {
        let a = Q16::from_int(2);
        let b = Q16::from_int(3);
        let c = a + b;
        assert_eq!(c, Q16::from_int(5));
    }

    #[test]
    fn add_saturates_high() {
        let max = Q16::MAX;
        let one = Q16::ONE;
        assert_eq!(max + one, Q16::MAX);
    }

    #[test]
    fn add_saturates_low() {
        let min = Q16::MIN;
        let neg_one = -Q16::ONE;
        assert_eq!(min + neg_one, Q16::MIN);
    }

    #[test]
    fn sub_basic() {
        let a = Q16::from_int(5);
        let b = Q16::from_int(3);
        assert_eq!(a - b, Q16::from_int(2));
    }

    #[test]
    fn mul_basic() {
        let a = Q16::from_int(3);
        let b = Q16::from_int(4);
        assert_eq!(a * b, Q16::from_int(12));
    }

    #[test]
    fn mul_fractional() {
        // 0.5 * 0.5 = 0.25
        let half = Q16::from_f64(0.5);
        assert_eq!((half * half).to_f64(), 0.25);
    }

    #[test]
    fn mul_saturates() {
        let big = Q16::from_int(20_000);
        let big2 = Q16::from_int(20_000);
        // 20k * 20k = 400M which exceeds Q16::MAX (32k.999...)
        assert_eq!(big * big2, Q16::MAX);
    }

    #[test]
    fn mul_negative_saturates_min() {
        let big_pos = Q16::from_int(20_000);
        let big_neg = Q16::from_int(-20_000);
        assert_eq!(big_pos * big_neg, Q16::MIN);
    }

    #[test]
    fn div_basic() {
        let a = Q16::from_int(12);
        let b = Q16::from_int(3);
        assert_eq!(a / b, Q16::from_int(4));
    }

    #[test]
    fn div_by_zero_positive_returns_max() {
        let a = Q16::from_int(5);
        assert_eq!(a / Q16::ZERO, Q16::MAX);
    }

    #[test]
    fn div_by_zero_negative_returns_min() {
        let a = Q16::from_int(-5);
        assert_eq!(a / Q16::ZERO, Q16::MIN);
    }

    #[test]
    fn neg_basic() {
        assert_eq!(-Q16::from_int(5), Q16::from_int(-5));
        assert_eq!(-Q16::ZERO, Q16::ZERO);
        assert_eq!(-Q16::MIN, Q16::MAX); // saturating
    }

    #[test]
    fn associativity_holds_for_safe_ranges() {
        // Saturation breaks strict associativity for overflowing
        // expressions; for safe ranges (|x|, |y|, |z| < 100), it
        // holds. This catches catastrophic bit-level errors in
        // saturating_add etc.
        for a in -100..=100 {
            for b in -100..=100 {
                for c in [-50, 0, 50] {
                    let qa = Q16::from_int(a);
                    let qb = Q16::from_int(b);
                    let qc = Q16::from_int(c);
                    assert_eq!(
                        (qa + qb) + qc,
                        qa + (qb + qc),
                        "add associativity failed at a={a}, b={b}, c={c}"
                    );
                }
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config { cases: 1024, ..Default::default() })]

        #[test]
        fn proptest_add_commutative(a: i32, b: i32) {
            let qa = Q16(a);
            let qb = Q16(b);
            proptest::prop_assert_eq!(qa + qb, qb + qa);
        }

        #[test]
        fn proptest_mul_commutative(a: i32, b: i32) {
            let qa = Q16(a);
            let qb = Q16(b);
            proptest::prop_assert_eq!(qa * qb, qb * qa);
        }

        #[test]
        fn proptest_add_zero_identity(a: i32) {
            let qa = Q16(a);
            proptest::prop_assert_eq!(qa + Q16::ZERO, qa);
            proptest::prop_assert_eq!(Q16::ZERO + qa, qa);
        }

        #[test]
        fn proptest_mul_one_identity(a: i32) {
            let qa = Q16(a);
            proptest::prop_assert_eq!(qa * Q16::ONE, qa);
        }

        #[test]
        fn proptest_no_panic_on_arbitrary_inputs(a: i32, b: i32) {
            let qa = Q16(a);
            let qb = Q16(b);
            // These should never panic regardless of input.
            let _ = qa + qb;
            let _ = qa - qb;
            let _ = qa * qb;
            let _ = qa / qb; // including b=0
            let _ = -qa;
        }
    }
}
