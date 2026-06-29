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

/// WP-B3 — frozen consensus-anchor golden guard, pinned at the chain's kernel rev.
///
/// The `q16_parity` module above proves the chain and kernel agree on the Q16
/// *primitives*. This module proves the chain's *pinned* `citrate-fed-types` rev
/// (the exact `rev` in this crate's Cargo.toml) still reproduces nat's frozen
/// consensus digests on the three *composite* surfaces the chain consumes:
///
///   * referee/aggregate  — `aggregate()` trimmed-mean digest  (`e79c5a63…`)
///   * LoRA               — `lora_commitment()` adapter digest  (`9bda1b5b…`)
///   * patronage          — `SettlementRow::patronage_units` units (`4000/1800/500`)
///
/// These are consensus anchors: the on-chain `AggregationChallenge` referee,
/// `LoRAFactory`, and `PatronageLedger` all reconcile against them. nat and the
/// kernel each carry their own copy of these frozen tests; this one is the guard
/// at the *chain's dependency boundary* — if someone bumps the kernel `rev` to a
/// version that drifted any committed-byte path, this fails before the chain ever
/// builds against it. The i64 widening (I64-S1) must not move a single byte here.
#[cfg(test)]
mod golden_surfaces {
    use citrate_execution::precompiles::q16::Q16 as ChainQ16;
    use citrate_fed_types::aggregate::{aggregate, PseudoGradient};
    use citrate_fed_types::lora::{lora_commitment, LoraFactors};
    use citrate_fed_types::settlement::{SettlementRow, BPS_SCALE};
    use citrate_fed_types::Q16 as KernelQ16;

    fn pg(id: &str, coords: &[f32]) -> PseudoGradient {
        PseudoGradient::new(id, coords.iter().map(|&v| KernelQ16::from_f32(v)).collect())
    }

    /// Referee/aggregate surface — identical inputs to
    /// `nat_aggregate::frozen_aggregate_digest` and the kernel's
    /// `frozen_aggregate_digest_matches_nat`.
    #[test]
    fn frozen_aggregate_digest_at_pinned_rev() {
        let g = vec![
            pg("alpha", &[1.0, -2.0, 3.5]),
            pg("beta", &[2.0, -1.0, 3.0]),
            pg("gamma", &[1.5, -1.5, 3.25]),
            pg("delta", &[1.75, -1.25, 3.1]),
        ];
        let r = aggregate(&g, 1, 64, b"frozen-seed-v1").expect("aggregate");
        assert_eq!(
            r.digest, "e79c5a6381c2e761f264d1c64dfdf12016c08ca3494ee909736ec84d00aa59a1",
            "chain-pinned kernel rev drifted the referee/aggregate consensus digest",
        );

        // Chain-Q16 tie: every coordinate the kernel aggregation emits must be
        // representable in the chain's Q16 (the consensus contract — the executor
        // has to hold what the off-chain reduction computes), bit-for-bit.
        for coord in &r.aggregate {
            let raw = coord.raw();
            assert_eq!(
                ChainQ16::from_raw(raw).0,
                raw,
                "aggregate output {raw} not bit-representable in chain Q16",
            );
        }
    }

    /// LoRA surface — the kernel's `sample()` fixture (the `lora_commitment_is_frozen`
    /// golden), re-asserted at the chain's pinned rev.
    #[test]
    fn frozen_lora_commitment_at_pinned_rev() {
        let sample = LoraFactors {
            zone_tag: 3, // ZoneId::PF
            rank: 2,
            dim_out: 4,
            dim_in: 3,
            alpha: 1.0,
            matrix_a: vec![vec![0.3, -0.2, 0.1], vec![-0.3, 0.2, 0.5]],
            matrix_b: vec![
                vec![1.0, 0.0],
                vec![-0.5, 0.5],
                vec![0.25, -0.5],
                vec![0.0, 1.0],
            ],
        };
        assert_eq!(
            lora_commitment(&sample).expect("lora_commitment"),
            "9bda1b5bccb365446d998a71f48c6852a85d1a94657022cd02bc9a3742a6716d",
            "chain-pinned kernel rev drifted the LoRA adapter commitment digest",
        );
    }

    /// Patronage surface — the on-chain `FederatedSettlement.t.sol` golden cases
    /// (`4000 / 1800 / 500`), via the kernel's `SettlementRow` math.
    #[test]
    fn frozen_patronage_units_at_pinned_rev() {
        let cases = [
            (4000.0_f32, 1.0_f32, 4000_u128), // heavy compute, top quality
            (2000.0, 0.9, 1800),              // medium
            (1000.0, 0.5, 500),               // light
        ];
        for (compute, quality, expected) in cases {
            let row = SettlementRow::new(
                "n",
                KernelQ16::from_f32(compute),
                KernelQ16::from_f32(quality),
                Some(3),
                "t",
            );
            assert_eq!(
                row.patronage_units(BPS_SCALE, BPS_SCALE),
                expected,
                "chain-pinned kernel rev drifted patronage units \
                 (compute={compute}, quality={quality})",
            );
        }
    }
}
