//! r1007 chain parameters (S3-6; docs/consensus/R1007_GENESIS.md): the block-0 constants
//! of the r1007 genesis, keyed by its block-0 hash like the activation table, and equal
//! to the constants the consensus crate actually runs with. A lane that changes one of
//! these constants without the genesis table (or the other way round) fails here.

use citrate_consensus::checkpoint::{CheckpointConfig, DEFAULT_VOTE_DEPTH};
use citrate_consensus::genesis_params::{chain_params_for_genesis, R1007_CHAIN_PARAMS};
use citrate_consensus::ghostdag::MERGE_PARENT_MAX_DEPTH;
use citrate_consensus::hardening::{R1006_GENESIS, R1007_GENESIS, RELEASE_GENESIS};
use citrate_consensus::types::GhostDagParams;

#[test]
fn only_the_r1007_genesis_has_compiled_chain_params() {
    assert_eq!(
        chain_params_for_genesis(40204, &R1007_GENESIS),
        Some(R1007_CHAIN_PARAMS)
    );
    assert_eq!(
        chain_params_for_genesis(40204, &R1006_GENESIS),
        None,
        "r1006 runs the per-node values it always ran"
    );
    assert_eq!(chain_params_for_genesis(40204, &RELEASE_GENESIS[0].1), None);
    assert_eq!(
        chain_params_for_genesis(1337, &R1007_GENESIS),
        None,
        "keyed by (chain id, genesis)"
    );
    assert_eq!(chain_params_for_genesis(40204, &[0x42; 32]), None);
}

#[test]
fn r1007_chain_params_are_the_constants_consensus_runs_with() {
    let p = R1007_CHAIN_PARAMS;
    let g = GhostDagParams::default();
    assert_eq!(p.ghostdag_k, g.k, "k (06 §1.2 D2)");
    assert_eq!(p.max_parents, g.max_parents, "MAX_PARENTS");
    assert_eq!(p.merge_depth, MERGE_PARENT_MAX_DEPTH, "MERGE_DEPTH");
    let cp = CheckpointConfig::default();
    assert_eq!(p.checkpoint_interval, cp.interval, "CHECKPOINT_INTERVAL");
    assert_eq!(p.committee_size, cp.committee_size, "committee size");
    assert_eq!(p.checkpoint_vote_depth, DEFAULT_VOTE_DEPTH, "vote depth D");
    // CV-7a / 06 §4.2 D12: the undo window is the pruning depth, 10,000 chain blocks.
    assert_eq!(p.pruning_depth, 10_000);
    assert_eq!(p.undo_window, p.pruning_depth, "undo window = retention");
    // A checkpoint height is always a possible pruning point (06 G11).
    assert_eq!(p.pruning_depth % p.checkpoint_interval, 0);
    assert!(p.slot_duration_secs >= 1);
    assert!(p.max_future_drift_secs >= p.slot_duration_secs);
    assert!(p.include_gas_limit <= p.accept_gas_limit);
}

/// The rendering is part of the consensus fingerprint (node consensus_manifest), so it is
/// stable, names every field, and moves when any field moves.
#[test]
fn the_rendering_names_every_parameter_and_moves_with_each() {
    let r = R1007_CHAIN_PARAMS.render();
    for name in [
        "slot_duration_secs",
        "max_future_drift_secs",
        "pruning_depth",
        "undo_window",
        "ghostdag_k",
        "max_parents",
        "merge_depth",
        "checkpoint_interval",
        "committee_size",
        "checkpoint_vote_depth",
        "include_gas_limit",
        "accept_gas_limit",
        "validator_activation_height",
    ] {
        assert!(r.contains(&format!("{name}=")), "{name} in {r}");
    }
    assert_eq!(r, R1007_CHAIN_PARAMS.render(), "stable");
    let mut q = R1007_CHAIN_PARAMS;
    q.committee_size += 1;
    assert_ne!(q.render(), r);
    let mut q = R1007_CHAIN_PARAMS;
    q.slot_duration_secs += 1;
    assert_ne!(q.render(), r);
}
