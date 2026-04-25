// Audit finding M-04 regression: previously committee selection
// computed each validator's weight as `(stake as f64).sqrt() as u64`.
// `u128 → f64` lossily quantizes for stake > 2^53 (with 18 decimals,
// 0.009 SALT base units already exceeds 2^53). The `f64 → u64` cast
// saturates differently across rustc / LLVM versions for special
// values. Result: committee membership could differ between
// validators running different rustc / LLVM combos, breaking
// finality.
//
// Fix (WP-B4.2): replace with integer sqrt on u128 — exact and
// deterministic on every platform.

use citrate_consensus::checkpoint::{integer_sqrt_u128, CommitteeSelector};
use citrate_consensus::types::{Hash, PublicKey};

/// M-04.1: integer sqrt agrees with f64 sqrt on small values.
#[test]
fn m04_integer_sqrt_matches_f64_for_small_values() {
    for n in [0u128, 1, 4, 9, 16, 100, 256, 1_000, 1_000_000] {
        let int_sqrt = integer_sqrt_u128(n);
        let f64_sqrt = (n as f64).sqrt() as u128;
        assert_eq!(int_sqrt, f64_sqrt, "n={}", n);
    }
}

/// M-04.2: integer sqrt is exact for stakes > 2^53 where f64
/// loses precision. The pre-fix `(stake as f64).sqrt() as u64`
/// would silently produce different values on different platforms.
#[test]
fn m04_integer_sqrt_exact_above_f64_precision() {
    // Stake = (2^60)^2 → exact integer sqrt = 2^60.
    let stake: u128 = 1u128 << 120;
    let expected: u128 = 1u128 << 60;
    let result = integer_sqrt_u128(stake);
    assert_eq!(result, expected);

    // f64 round-trip would lose precision here.
    let f64_result = (stake as f64).sqrt() as u128;
    // f64 sqrt of 2^120 ~ 2^60 but f64 representation may be off.
    // We don't assert the f64 result is wrong; we assert the integer
    // result is right.
    let _ = f64_result;
}

/// M-04.3: integer sqrt is monotonic — `n1 <= n2 ⇒ sqrt(n1) <= sqrt(n2)`.
/// Pre-fix the f64 path could violate monotonicity at edge cases
/// because of double-rounding. This test pins the structural
/// property.
#[test]
fn m04_integer_sqrt_monotonic() {
    let inputs: Vec<u128> = (0..100u128)
        .chain([1u128 << 50, 1u128 << 60, 1u128 << 70, 1u128 << 100, u128::MAX].iter().copied())
        .collect();
    let mut sorted = inputs.clone();
    sorted.sort();
    let sqrts: Vec<u128> = sorted.iter().map(|&n| integer_sqrt_u128(n)).collect();
    for i in 1..sqrts.len() {
        assert!(
            sqrts[i] >= sqrts[i - 1],
            "M-04: sqrt monotonicity violated at index {}: {} -> {}",
            i,
            sqrts[i - 1],
            sqrts[i]
        );
    }
}

/// M-04.4: committee selection at high stake produces a
/// deterministic membership. Two calls with identical inputs MUST
/// agree byte-for-byte. This is the load-bearing property — pre-fix
/// f64 quantization could produce different results on different
/// platforms.
#[test]
fn m04_committee_selection_deterministic_at_high_stake() {
    let validators: Vec<(PublicKey, u128)> = (0..10u8)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            bytes[31] = 0x42;
            // Stake near u128::MAX to push past f64 precision.
            let stake: u128 = u128::MAX / 100 - (i as u128 * 1000);
            (PublicKey::new(bytes), stake)
        })
        .collect();

    let seed = Hash::new([0xAB; 32]);
    let committee_a = CommitteeSelector::select(&validators, 100, &seed, 5);
    let committee_b = CommitteeSelector::select(&validators, 100, &seed, 5);
    assert_eq!(
        committee_a, committee_b,
        "M-04: identical inputs must produce identical committee membership"
    );
    assert_eq!(committee_a.len(), 5);
}

/// M-04.5: integer_sqrt_u128(0) and integer_sqrt_u128(1) return
/// the trivial values. Pin this so a future refactor can't
/// silently break the base cases.
#[test]
fn m04_integer_sqrt_base_cases() {
    assert_eq!(integer_sqrt_u128(0), 0);
    assert_eq!(integer_sqrt_u128(1), 1);
    assert_eq!(integer_sqrt_u128(2), 1);
    assert_eq!(integer_sqrt_u128(3), 1);
    assert_eq!(integer_sqrt_u128(4), 2);
}
