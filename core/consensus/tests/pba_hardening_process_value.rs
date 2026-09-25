// PBA-R2: the process-wide activation height round-trips and is what
// components capture at construction. Its own test binary (own process) so
// setting the global cannot leak into other tests.

use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::hardening::{
    pba_hardening_height, set_pba_hardening_height, PbaHardening,
};
use citrate_consensus::types::GhostDagParams;
use std::sync::Arc;

#[test]
fn process_value_round_trips_and_is_captured_at_construction() {
    assert_eq!(pba_hardening_height(), None, "unset by default (rules off)");
    assert_eq!(PbaHardening::from_process(), PbaHardening::off());
    assert_eq!(PbaHardening::default(), PbaHardening::off());

    set_pba_hardening_height(Some(1_234));
    assert_eq!(pba_hardening_height(), Some(1_234));
    assert_eq!(PbaHardening::from_process(), PbaHardening::at(1_234));
    let gd = GhostDag::new(
        GhostDagParams::default(),
        Arc::new(DagStore::with_permissive_vrf_for_testing()),
    );
    assert_eq!(gd.pba_hardening(), PbaHardening::at(1_234));
    assert_eq!(gd.pba_hardening().activation_height(), Some(1_234));

    set_pba_hardening_height(Some(0));
    assert_eq!(pba_hardening_height(), Some(0));
    set_pba_hardening_height(None);
    assert_eq!(pba_hardening_height(), None);
}
