// citrate/core/consensus/src/hardening.rs
//
// PBA-R2 — the single activation height for the pre-bounty block-validity
// hardening (PBA-L1b-001 / -002 / -003, with PBA-L1a-006's import half).
//
// WHY ONE NAMED HEIGHT
//
// Three rules change which blocks are valid:
//
//   * PBA-L1b-001 — every transaction in an imported block must carry a
//     signature that THIS node verifies (never the wire `ecdsa_verified`
//     flag), and its `hash` must be the canonical id of its contents.
//   * PBA-L1b-002 — `tx_root` commits to each transaction's full contents
//     (`types::tx_root_v2`), not to the peer-supplied `tx.hash` field.
//   * PBA-L1b-003 — a block's timestamp may not run more than
//     `MAX_BLOCK_TIMESTAMP_ADVANCE_SECS` past its selected parent's.
//
// A node enforcing any of them while a peer does not disagrees about block
// validity, which is a fork. So all three switch on together, at one height,
// and every node must agree on that height. Blocks below it are judged by the
// old rules forever (re-judging history under a new rule forks just as surely).
//
// DEFAULTS
//
//   * Chain 40204 (every shipped testnet/mainnet profile): UNSET. The rules are
//     off until the owner schedules a height (see `docs/consensus/
//     PBA_HARDENING_ACTIVATION.md`). An upgraded binary changes nothing on
//     40204 by itself.
//   * Dev profiles (`NodeConfig::devnet()`, `node/config/devnet.toml`,
//     `devnet-config.toml`) set `chain.pba_hardening_height = 0`: active from
//     genesis.
//   * Unit tests construct components with an explicit [`PbaHardening`], so
//     both sides of the boundary are exercised.
//
// Genesis (height 0) is never re-judged: [`PbaHardening::active_at`] is false
// for height 0 even when the activation height is 0. Genesis is built locally
// by every node from the same profile, it is never received.

use std::sync::atomic::{AtomicU64, Ordering};

/// Environment override for the activation height, read by the node at start
/// (after the config file). Accepts a decimal height, or `off`/`none` to force
/// the rules off.
///
/// DANGER: a consensus parameter. Two nodes on one chain with different
/// values disagree about block validity. Set it fleet-wide or not at all.
pub const PBA_HARDENING_ENV: &str = "CITRATE_PBA_HARDENING_HEIGHT";

/// Upper bound on how far a block's timestamp may run ahead of its selected
/// parent's (PBA-L1b-003), once the hardening is active.
///
/// Why a parent-relative bound and not only a wall-clock one: a wall-clock
/// check is local policy (two nodes with different clocks disagree), so it
/// cannot be a validity rule. A parent-relative bound is deterministic. It
/// caps how far one proposer can push the chain's clock per block, so a
/// `u64::MAX` timestamp is invalid on every node.
///
/// Liveness after an outage: the producer stamps
/// `clamp(now, parent.ts, parent.ts + MAX)` (see [`producer_timestamp`]), so
/// even after a halt longer than this bound the next block is valid; the
/// chain's clock then catches up by up to this much per block.
pub const MAX_BLOCK_TIMESTAMP_ADVANCE_SECS: u64 = 3_600;

/// Wall-clock future-drift tolerance applied at every block ingress (gossip,
/// sync). The same value gossip has always used. This one is local policy
/// (it depends on the local clock), so it is NOT height-gated: a block
/// rejected for it now is accepted once its time arrives.
pub const MAX_FUTURE_BLOCK_DRIFT_SECS: u64 = 900;

const UNSET: u64 = u64::MAX;

/// Process-wide activation height, set once by the node from config/env
/// before any consensus component is constructed. `UNSET` = rules off.
static PBA_HARDENING_HEIGHT: AtomicU64 = AtomicU64::new(UNSET);

/// Set the process-wide activation height. `None` turns the rules off.
pub fn set_pba_hardening_height(height: Option<u64>) {
    PBA_HARDENING_HEIGHT.store(height.unwrap_or(UNSET), Ordering::SeqCst);
}

/// The process-wide activation height, if one is scheduled.
pub fn pba_hardening_height() -> Option<u64> {
    match PBA_HARDENING_HEIGHT.load(Ordering::SeqCst) {
        UNSET => None,
        h => Some(h),
    }
}

/// Parse an env/config override. `Ok(None)` = rules explicitly off.
pub fn parse_pba_hardening_override(raw: &str) -> Result<Option<u64>, String> {
    let v = raw.trim();
    if v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    match v.parse::<u64>() {
        Ok(UNSET) => Err(format!(
            "{PBA_HARDENING_ENV}={v}: u64::MAX is reserved (use `off`)"
        )),
        Ok(h) => Ok(Some(h)),
        Err(e) => Err(format!(
            "{PBA_HARDENING_ENV}={v}: not a height or `off`: {e}"
        )),
    }
}

/// A component's view of the activation height.
///
/// Components capture it at construction ([`PbaHardening::from_process`]);
/// tests pass an explicit one ([`PbaHardening::at`] / [`PbaHardening::off`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PbaHardening {
    activation: Option<u64>,
}

impl Default for PbaHardening {
    fn default() -> Self {
        Self::from_process()
    }
}

impl PbaHardening {
    /// The process-wide value (see [`set_pba_hardening_height`]).
    pub fn from_process() -> Self {
        Self {
            activation: pba_hardening_height(),
        }
    }

    /// Active from `height` onward.
    pub const fn at(height: u64) -> Self {
        Self {
            activation: Some(height),
        }
    }

    /// Never active.
    pub const fn off() -> Self {
        Self { activation: None }
    }

    pub fn activation_height(&self) -> Option<u64> {
        self.activation
    }

    /// Whether the hardened validity rules apply to a block at `height`.
    /// Genesis (height 0) is never re-judged.
    pub fn active_at(&self, height: u64) -> bool {
        match self.activation {
            Some(a) => height > 0 && height >= a,
            None => false,
        }
    }
}

/// The timestamp an honest producer stamps on a child of a parent with
/// timestamp `parent_ts` (PBA-L1b-003).
///
/// `max(now, parent_ts)` keeps the parent-monotonic rule satisfiable even when
/// the parent is ahead of the local clock (the pre-fix producer stamped `now`
/// and every child of a future-dated tip was rejected: a permanent halt).
/// The upper clamp keeps the result inside the parent-relative bound, so a
/// long outage never leaves the producer unable to build a valid block.
pub fn producer_timestamp(now: u64, parent_ts: u64) -> u64 {
    now.max(parent_ts)
        .min(parent_ts.saturating_add(MAX_BLOCK_TIMESTAMP_ADVANCE_SECS))
}

/// Whether `ts` is acceptable at ingress against the local clock.
pub fn within_future_drift(ts: u64, now: u64) -> bool {
    ts <= now.saturating_add(MAX_FUTURE_BLOCK_DRIFT_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_never_rejudged_and_boundary_is_inclusive() {
        let h = PbaHardening::at(0);
        assert!(!h.active_at(0), "genesis is never re-judged");
        assert!(h.active_at(1));
        let h = PbaHardening::at(100);
        assert!(!h.active_at(99));
        assert!(h.active_at(100));
        assert!(h.active_at(101));
        assert!(!PbaHardening::off().active_at(u64::MAX - 1));
    }

    #[test]
    fn override_parsing() {
        assert_eq!(parse_pba_hardening_override("off"), Ok(None));
        assert_eq!(parse_pba_hardening_override(" NONE "), Ok(None));
        assert_eq!(parse_pba_hardening_override("0"), Ok(Some(0)));
        assert_eq!(parse_pba_hardening_override("123456"), Ok(Some(123_456)));
        assert!(parse_pba_hardening_override("18446744073709551615").is_err());
        assert!(parse_pba_hardening_override("soon").is_err());
    }

    #[test]
    fn producer_timestamp_never_precedes_parent_and_never_exceeds_bound() {
        // Parent in the past: stamp now.
        assert_eq!(producer_timestamp(1_000, 900), 1_000);
        // Parent ahead of our clock (the halt shape): stamp the parent's ts.
        assert_eq!(producer_timestamp(1_000, 5_000), 5_000);
        // Long outage: clamp to the parent-relative bound.
        assert_eq!(
            producer_timestamp(1_000_000, 10),
            10 + MAX_BLOCK_TIMESTAMP_ADVANCE_SECS
        );
        // Exactly at the bound.
        assert_eq!(
            producer_timestamp(10 + MAX_BLOCK_TIMESTAMP_ADVANCE_SECS, 10),
            10 + MAX_BLOCK_TIMESTAMP_ADVANCE_SECS
        );
        // u64::MAX parent: saturates, never panics.
        assert_eq!(producer_timestamp(1_000, u64::MAX), u64::MAX);
    }

    #[test]
    fn future_drift_window() {
        assert!(within_future_drift(1_900, 1_000));
        assert!(!within_future_drift(1_901, 1_000));
        assert!(!within_future_drift(u64::MAX, 1_000));
        assert!(within_future_drift(u64::MAX, u64::MAX));
    }
}
