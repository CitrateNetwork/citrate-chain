//! Belnap FOUR-valued logic lattice.
//!
//! Implements Definition 1 from Gradient Papers No. II.
//!
//! The four values form a bilattice with two orderings:
//! - **Knowledge ordering** (≤k): N ≤k {T, F} ≤k B
//! - **Truth ordering** (≤t): F ≤t {N, B} ≤t T

use serde::{Deserialize, Serialize};
use std::fmt;

/// The four Belnap truth values.
///
/// - `True` — Known to be true
/// - `False` — Known to be false
/// - `Both` — Known to be both true and false (paraconsistent)
/// - `Neither` — Unknown / no information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BelnapValue {
    /// Known true.
    True,
    /// Known false.
    False,
    /// Both true and false (paraconsistent).
    Both,
    /// Neither true nor false (unknown).
    Neither,
}

impl BelnapValue {
    /// Lattice join (⊔) under knowledge ordering.
    ///
    /// Combines information: the result knows at least as much as either input.
    pub fn join(self, other: Self) -> Self {
        use BelnapValue::*;
        match (self, other) {
            (Neither, x) | (x, Neither) => x,
            (Both, _) | (_, Both) => Both,
            (True, True) => True,
            (False, False) => False,
            (True, False) | (False, True) => Both,
        }
    }

    /// Lattice meet (⊓) under knowledge ordering.
    ///
    /// Consensus: the result knows only what both inputs agree on.
    pub fn meet(self, other: Self) -> Self {
        use BelnapValue::*;
        match (self, other) {
            (Both, x) | (x, Both) => x,
            (Neither, _) | (_, Neither) => Neither,
            (True, True) => True,
            (False, False) => False,
            (True, False) | (False, True) => Neither,
        }
    }

    /// Negation operator.
    ///
    /// Swaps True ↔ False, preserves Both and Neither.
    pub fn negation(self) -> Self {
        use BelnapValue::*;
        match self {
            True => False,
            False => True,
            Both => Both,
            Neither => Neither,
        }
    }

    /// Knowledge ordering value (for comparison).
    ///
    /// N=0, T=1, F=1, B=2
    pub fn k_level(self) -> u8 {
        use BelnapValue::*;
        match self {
            Neither => 0,
            True | False => 1,
            Both => 2,
        }
    }

    /// Returns true if self ≤k other in the knowledge ordering.
    pub fn k_leq(self, other: Self) -> bool {
        // Knowledge ordering: N ≤k {T,F} ≤k B
        // But T and F are incomparable under ≤k
        use BelnapValue::*;
        match (self, other) {
            (x, y) if x == y => true,
            (Neither, _) => true,
            (_, Both) => true,
            _ => false,
        }
    }

    /// Returns true if self ≤t other in the truth ordering.
    pub fn t_leq(self, other: Self) -> bool {
        // Truth ordering: F ≤t {N,B} ≤t T
        // But N and B are incomparable under ≤t
        use BelnapValue::*;
        match (self, other) {
            (x, y) if x == y => true,
            (False, _) => true,
            (_, True) => true,
            _ => false,
        }
    }
}

impl fmt::Display for BelnapValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BelnapValue::True => write!(f, "T"),
            BelnapValue::False => write!(f, "F"),
            BelnapValue::Both => write!(f, "B"),
            BelnapValue::Neither => write!(f, "N"),
        }
    }
}

impl Default for BelnapValue {
    fn default() -> Self {
        BelnapValue::Neither
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PC-T01: Belnap FOUR values construct correctly
    #[test]
    fn test_belnap_values_construct() {
        let t = BelnapValue::True;
        let f = BelnapValue::False;
        let b = BelnapValue::Both;
        let n = BelnapValue::Neither;

        assert_ne!(t, f);
        assert_ne!(t, b);
        assert_ne!(t, n);
        assert_ne!(f, b);
        assert_ne!(f, n);
        assert_ne!(b, n);
        assert_eq!(BelnapValue::default(), BelnapValue::Neither);
    }

    // PC-T07: Knowledge ordering correct
    #[test]
    fn test_knowledge_ordering() {
        use BelnapValue::*;

        // N ≤k everything
        assert!(Neither.k_leq(Neither));
        assert!(Neither.k_leq(True));
        assert!(Neither.k_leq(False));
        assert!(Neither.k_leq(Both));

        // T and F ≤k B
        assert!(True.k_leq(Both));
        assert!(False.k_leq(Both));

        // T and F are incomparable
        assert!(!True.k_leq(False));
        assert!(!False.k_leq(True));

        // B ≤k only B
        assert!(Both.k_leq(Both));
        assert!(!Both.k_leq(True));
        assert!(!Both.k_leq(False));
        assert!(!Both.k_leq(Neither));
    }

    // PC-T08: Truth ordering correct
    #[test]
    fn test_truth_ordering() {
        use BelnapValue::*;

        // F ≤t everything
        assert!(False.t_leq(False));
        assert!(False.t_leq(Neither));
        assert!(False.t_leq(Both));
        assert!(False.t_leq(True));

        // N and B ≤t T
        assert!(Neither.t_leq(True));
        assert!(Both.t_leq(True));

        // N and B are incomparable
        assert!(!Neither.t_leq(Both));
        assert!(!Both.t_leq(Neither));

        // T ≤t only T
        assert!(True.t_leq(True));
        assert!(!True.t_leq(False));
        assert!(!True.t_leq(Neither));
        assert!(!True.t_leq(Both));
    }

    // Join table verification (all 16 combinations)
    #[test]
    fn test_join_table() {
        use BelnapValue::*;

        // Row T
        assert_eq!(True.join(True), True);
        assert_eq!(True.join(False), Both);
        assert_eq!(True.join(Both), Both);
        assert_eq!(True.join(Neither), True);

        // Row F
        assert_eq!(False.join(True), Both);
        assert_eq!(False.join(False), False);
        assert_eq!(False.join(Both), Both);
        assert_eq!(False.join(Neither), False);

        // Row B
        assert_eq!(Both.join(True), Both);
        assert_eq!(Both.join(False), Both);
        assert_eq!(Both.join(Both), Both);
        assert_eq!(Both.join(Neither), Both);

        // Row N
        assert_eq!(Neither.join(True), True);
        assert_eq!(Neither.join(False), False);
        assert_eq!(Neither.join(Both), Both);
        assert_eq!(Neither.join(Neither), Neither);
    }

    // Meet table verification (all 16 combinations)
    #[test]
    fn test_meet_table() {
        use BelnapValue::*;

        // Row T
        assert_eq!(True.meet(True), True);
        assert_eq!(True.meet(False), Neither);
        assert_eq!(True.meet(Both), True);
        assert_eq!(True.meet(Neither), Neither);

        // Row F
        assert_eq!(False.meet(True), Neither);
        assert_eq!(False.meet(False), False);
        assert_eq!(False.meet(Both), False);
        assert_eq!(False.meet(Neither), Neither);

        // Row B
        assert_eq!(Both.meet(True), True);
        assert_eq!(Both.meet(False), False);
        assert_eq!(Both.meet(Both), Both);
        assert_eq!(Both.meet(Neither), Neither);

        // Row N
        assert_eq!(Neither.meet(True), Neither);
        assert_eq!(Neither.meet(False), Neither);
        assert_eq!(Neither.meet(Both), Neither);
        assert_eq!(Neither.meet(Neither), Neither);
    }

    #[test]
    fn test_negation() {
        use BelnapValue::*;
        assert_eq!(True.negation(), False);
        assert_eq!(False.negation(), True);
        assert_eq!(Both.negation(), Both);
        assert_eq!(Neither.negation(), Neither);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", BelnapValue::True), "T");
        assert_eq!(format!("{}", BelnapValue::False), "F");
        assert_eq!(format!("{}", BelnapValue::Both), "B");
        assert_eq!(format!("{}", BelnapValue::Neither), "N");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_belnap() -> impl Strategy<Value = BelnapValue> {
        prop_oneof![
            Just(BelnapValue::True),
            Just(BelnapValue::False),
            Just(BelnapValue::Both),
            Just(BelnapValue::Neither),
        ]
    }

    // PC-T02: Join commutative
    proptest! {
        #[test]
        fn join_commutative(a in arb_belnap(), b in arb_belnap()) {
            prop_assert_eq!(a.join(b), b.join(a));
        }
    }

    // PC-T03: Join associative
    proptest! {
        #[test]
        fn join_associative(a in arb_belnap(), b in arb_belnap(), c in arb_belnap()) {
            prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        }
    }

    // PC-T04: Join idempotent
    proptest! {
        #[test]
        fn join_idempotent(a in arb_belnap()) {
            prop_assert_eq!(a.join(a), a);
        }
    }

    // PC-T05: Meet commutative
    proptest! {
        #[test]
        fn meet_commutative(a in arb_belnap(), b in arb_belnap()) {
            prop_assert_eq!(a.meet(b), b.meet(a));
        }
    }

    // PC-T06: Meet associative
    proptest! {
        #[test]
        fn meet_associative(a in arb_belnap(), b in arb_belnap(), c in arb_belnap()) {
            prop_assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)));
        }
    }

    // Absorption: a join (a meet b) = a
    proptest! {
        #[test]
        fn absorption_join_meet(a in arb_belnap(), b in arb_belnap()) {
            prop_assert_eq!(a.join(a.meet(b)), a);
        }
    }

    // Absorption: a meet (a join b) = a
    proptest! {
        #[test]
        fn absorption_meet_join(a in arb_belnap(), b in arb_belnap()) {
            prop_assert_eq!(a.meet(a.join(b)), a);
        }
    }

    // Double negation
    proptest! {
        #[test]
        fn double_negation(a in arb_belnap()) {
            prop_assert_eq!(a.negation().negation(), a);
        }
    }
}
