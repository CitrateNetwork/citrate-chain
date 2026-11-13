//! r1007 genesis rule (CV-14, lead decision 2026-11-09): with the MPT state root
//! active from 0, block 0 is rooted under it too. The shared genesis function
//! every node and the GUI call (`initialize_shared_genesis_state`) then commits
//! the standard MPT root of the genesis state, the same root the from-scratch
//! reference gives; with the rule unset (r1005, r1006, legacy devnets) block 0
//! keeps the legacy root it always had.
//!
//! The rule is process-wide, so this binary holds one test.

use citrate_economics::genesis::{initialize_shared_genesis_state, GenesisConfig};
use citrate_execution::executor::Executor;
use citrate_execution::StateDB;
use std::sync::Arc;

fn build(activation: Option<u64>) -> ([u8; 32], Arc<StateDB>) {
    citrate_execution::mpt_state_root::set_mpt_state_root_height(activation);
    let state_db = Arc::new(StateDB::new());
    let executor = Arc::new(Executor::new(state_db.clone()));
    let root = initialize_shared_genesis_state(&executor, &GenesisConfig::default())
        .expect("the default genesis builds");
    (root, state_db)
}

#[test]
fn block_0_is_rooted_under_the_mpt_rule_when_it_is_active_from_0() {
    let (legacy, legacy_db) = build(None);
    assert_eq!(
        legacy_db.root_height(),
        0,
        "genesis is the post-state of block 0"
    );
    assert_eq!(
        legacy,
        *legacy_db.calculate_state_root_at(0).as_bytes(),
        "unset: block 0 keeps the legacy root"
    );

    let (mpt, mpt_db) = build(Some(0));
    assert_eq!(mpt_db.root_height(), 0);
    assert!(
        mpt_db.mpt_rule_active(),
        "the rule applies to block 0 itself"
    );
    assert_eq!(
        mpt,
        *mpt_db.reference_state_root().as_bytes(),
        "block 0's root is the standard MPT root of the genesis state"
    );
    assert_ne!(mpt, legacy, "the two rules give different roots");

    // A later activation leaves block 0 alone.
    let (later, _) = build(Some(10));
    assert_eq!(
        later, legacy,
        "activation 10: block 0 keeps the legacy root"
    );
    citrate_execution::mpt_state_root::set_mpt_state_root_height(None);
}
