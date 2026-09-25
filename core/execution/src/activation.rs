// citrate/core/execution/src/activation.rs
//
// R2 hardening activation, as seen from the execution layer.
//
// There is exactly ONE activation store and ONE resolution order, and they live
// in `citrate_consensus::hardening` (the lowest crate that needs them: GhostDag,
// sync and gossip cannot depend on this crate). This module is a thin view onto
// that store so execution-layer rules ask `pba_hardening_active(height)` without
// a second, divergent copy. Never add a separate static here: two stores can
// disagree, and a node whose stores disagree forks at the activation height.
//
// Resolution (see `citrate_consensus::hardening::resolve_pba_hardening_height`):
// the `CITRATE_PBA_HARDENING_HEIGHT` env override (a height, or `off`) when set,
// otherwise `[chain] pba_hardening_height`. The node publishes it once at start
// with `init_pba_hardening_height`. Genesis (height 0) is never re-judged.

pub use citrate_consensus::hardening::{
    init_pba_hardening_height, pba_hardening_height, resolve_pba_hardening_height,
    set_pba_hardening_height, PbaHardening, PBA_HARDENING_ENV,
};

/// Whether the hardening rules apply to a block at `height` under
/// `activation` (pure; tests drive it without the process store).
pub fn active_at(activation: Option<u64>, height: u64) -> bool {
    match activation {
        Some(a) => PbaHardening::at(a).active_at(height),
        None => false,
    }
}

/// Whether the hardening rules apply to a block at `height` on this node.
pub fn pba_hardening_active(height: u64) -> bool {
    PbaHardening::from_process().active_at(height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_never_activates() {
        assert!(!active_at(None, 0));
        assert!(!active_at(None, u64::MAX));
    }

    #[test]
    fn activates_at_and_after_height_genesis_excluded() {
        assert!(!active_at(Some(100), 99));
        assert!(active_at(Some(100), 100));
        assert!(active_at(Some(100), 101));
        assert!(!active_at(Some(0), 0), "genesis is never re-judged");
        assert!(active_at(Some(0), 1));
    }
}
