// R2: one activation store, one resolution order, honoured by EVERY
// activation-gated path (consensus, network and execution).
//
// A node configured only by `CITRATE_PBA_HARDENING_HEIGHT` must enforce the
// same height on every path as a node configured by `[chain]
// pba_hardening_height`; a path that read a different store (or ignored the
// env override) would disagree at the activation height, which is a fork.
//
// Its own test binary: it mutates the process environment and the process
// store, so nothing else may run in this process concurrently. One #[test].

use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::hardening::{
    init_pba_hardening_height, pba_hardening_height, resolve_pba_hardening_height, PbaHardening,
    PBA_HARDENING_ENV,
};
use citrate_consensus::types::GhostDagParams;
use citrate_execution::{activation, Executor, StateDB};
use citrate_network::{
    GossipConfig, GossipProtocol, PeerManager, PeerManagerConfig, SyncConfig, SyncManager,
};
use std::sync::Arc;

/// Every activation-gated component, constructed as the node constructs it,
/// must report `want`.
fn assert_all_paths(want: PbaHardening, label: &str) {
    let gd = GhostDag::new(
        GhostDagParams::default(),
        Arc::new(DagStore::with_permissive_vrf_for_testing()),
    );
    assert_eq!(
        gd.pba_hardening(),
        want,
        "{label}: GhostDag (timestamp bound)"
    );
    let sync = SyncManager::new(SyncConfig::default());
    assert_eq!(
        sync.pba_hardening(),
        want,
        "{label}: SyncManager (tx_root rule)"
    );
    let gossip = GossipProtocol::new(
        GossipConfig::default(),
        Arc::new(PeerManager::new(PeerManagerConfig::default())),
    );
    assert_eq!(
        gossip.pba_hardening(),
        want,
        "{label}: GossipProtocol (tx_root rule)"
    );
    let exec = Executor::new(Arc::new(StateDB::new()));
    assert_eq!(
        exec.pba_hardening(),
        want,
        "{label}: Executor (import gate)"
    );
    // Execution-layer rules (inference, precompile gating) ask this view.
    for h in [0u64, 1, 6, 7, 8, 1_000_000] {
        assert_eq!(
            activation::pba_hardening_active(h),
            want.active_at(h),
            "{label}: execution::activation at height {h}"
        );
    }
    assert_eq!(activation::pba_hardening_height(), want.activation_height());
}

#[test]
fn env_override_is_honoured_on_every_activation_gated_path() {
    // SAFETY (edition 2021 set_var is safe; kept single-threaded by design).
    std::env::remove_var(PBA_HARDENING_ENV);

    // 1. No env: the config value is used.
    assert_eq!(resolve_pba_hardening_height(Some(42)), Ok(Some(42)));
    assert_eq!(resolve_pba_hardening_height(None), Ok(None));
    init_pba_hardening_height(Some(42)).unwrap();
    assert_all_paths(PbaHardening::at(42), "config only");

    // 2. Env height overrides the config value (a node configured only by env).
    std::env::set_var(PBA_HARDENING_ENV, "7");
    assert_eq!(init_pba_hardening_height(Some(42)), Ok(Some(7)));
    assert_eq!(pba_hardening_height(), Some(7));
    assert_all_paths(PbaHardening::at(7), "env over config");
    assert_eq!(init_pba_hardening_height(None), Ok(Some(7)));
    assert_all_paths(PbaHardening::at(7), "env only");

    // 3. Env `off` overrides a configured height.
    std::env::set_var(PBA_HARDENING_ENV, "off");
    assert_eq!(init_pba_hardening_height(Some(0)), Ok(None));
    assert_all_paths(PbaHardening::off(), "env off over config");

    // 4. An unparseable override is an error and leaves the store untouched.
    std::env::set_var(PBA_HARDENING_ENV, "soon");
    assert!(init_pba_hardening_height(Some(0)).is_err());
    assert_eq!(pba_hardening_height(), None);

    std::env::remove_var(PBA_HARDENING_ENV);
}
