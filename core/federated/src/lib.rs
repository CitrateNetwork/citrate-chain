//! `citrate-federated` — the chain ⇄ kernel Q16 parity seam (I64-S1).
//!
//! The consensus execution layer (`citrate_execution::precompiles::q16::Q16`)
//! and the Tier-1-audited federated/gradient kernel
//! (`citrate_fed_types::Q16`) each carry their own Q16.16 fixed-point type.
//! The I64-S1 unification widened both to an `i64` backing with identical
//! saturating semantics (i128 mul/div intermediates, div-by-zero saturating
//! by numerator sign, SHIFT = 16). This crate's sole job is to PROVE — at
//! the byte level, on a fixed adversarial input vector — that the two agree,
//! so an on-chain precompile result is bit-identical to what the off-chain
//! gradient path computes.
//!
//! This is the WP-A1 acceptance artifact. It is a `dev-dependencies`-only
//! parity harness; nothing here is compiled into the node binary, and the
//! crate is excluded from `default-members` so the kernel git dependency is
//! only fetched when this proof is explicitly run.

// No production surface — the proof lives entirely in the test module.

#[cfg(test)]
mod q16_parity {
    use citrate_execution::precompiles::q16::Q16 as ChainQ16;
    use citrate_fed_types::Q16 as KernelQ16;

    /// A fixed vector of raw `i64` Q16 values spanning the determinism-
    /// relevant edge cases: zero, ±ULP, ±1.0, the OLD i32 real bounds
    /// (±32_768), the i32 raw bounds, values BEYOND i32 (the headroom the
    /// widening buys — e.g. `from_int(50_000)` ≈ 3.28e9 raw), and the i64
    /// extremes that exercise the saturating down-cast.
    const RAW: &[i64] = &[
        0,
        1,
        -1,
        65_536,                       // +1.0
        -65_536,                      // -1.0
        32_767,
        -32_768,
        2_147_483_647,                // i32::MAX raw
        -2_147_483_648,               // i32::MIN raw
        3_276_800_000,                // from_int(50_000) territory (> i32::MAX)
        -3_276_800_000,
        140_737_488_355_328,          // 2^47, real ≈ 2.1e9
        -140_737_488_355_328,
        i64::MAX,
        i64::MIN,
    ];

    fn c(raw: i64) -> ChainQ16 {
        ChainQ16::from_raw(raw)
    }
    fn k(raw: i64) -> KernelQ16 {
        KernelQ16::from_raw(raw)
    }

    /// The raw-byte invariant: `from_raw` round-trips identically in both.
    #[test]
    fn from_raw_roundtrip_parity() {
        for &v in RAW {
            assert_eq!(c(v).0, k(v).raw(), "from_raw/raw parity at {v}");
        }
    }

    #[test]
    fn add_parity() {
        for &a in RAW {
            for &b in RAW {
                assert_eq!(
                    c(a).saturating_add(c(b)).0,
                    k(a).add(k(b)).raw(),
                    "add parity at a={a}, b={b}",
                );
            }
        }
    }

    #[test]
    fn sub_parity() {
        for &a in RAW {
            for &b in RAW {
                assert_eq!(
                    c(a).saturating_sub(c(b)).0,
                    k(a).sub(k(b)).raw(),
                    "sub parity at a={a}, b={b}",
                );
            }
        }
    }

    #[test]
    fn mul_parity() {
        for &a in RAW {
            for &b in RAW {
                assert_eq!(
                    c(a).saturating_mul(c(b)).0,
                    k(a).mul(k(b)).raw(),
                    "mul parity at a={a}, b={b}",
                );
            }
        }
    }

    /// Includes the div-by-zero fail-safe: both must saturate to
    /// `i64::MAX`/`i64::MIN` by the sign of the numerator (no panic).
    #[test]
    fn div_parity() {
        for &a in RAW {
            for &b in RAW {
                assert_eq!(
                    c(a).saturating_div(c(b)).0,
                    k(a).div(k(b)).raw(),
                    "div parity at a={a}, b={b} (incl. div-by-zero)",
                );
            }
        }
    }

    /// The shared constants must coincide bit-for-bit.
    #[test]
    fn constant_parity() {
        assert_eq!(ChainQ16::ZERO.0, KernelQ16::ZERO.raw(), "ZERO parity");
        assert_eq!(ChainQ16::ONE.0, KernelQ16::ONE.raw(), "ONE parity");
    }
}
