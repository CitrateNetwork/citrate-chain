// With the storage-root hardening height PUBLISHED process-wide (a new
// genesis, `Some(0)`), the default entry points a node uses — the executor's
// root after settlement, and a restarted db rooted at its tip — agree after a
// storage delete. Its own test binary: it sets the process-wide height.

use citrate_execution::block_rewards::CANONICAL_BASE_FEE_PER_GAS;
use citrate_execution::storage_root_hardening as srh;
use citrate_execution::types::Address;
use citrate_execution::{Executor, StateDB};
use primitive_types::U256;
use std::sync::Arc;

#[tokio::test]
async fn published_activation_makes_replay_and_restart_agree() {
    srh::set_storage_root_hardening_height(Some(0));
    assert!(srh::storage_root_hardening_active(1));
    assert!(!srh::storage_root_hardening_active(0));

    let gov = Address([0x10; 20]);
    let (a, b, c) = (vec![0u8, 1], vec![0u8, 3, 0], vec![3u8]);

    let db = Arc::new(StateDB::new());
    let exec = Executor::new(db.clone());
    db.accounts.set_balance(gov, U256::one());
    db.set_storage(gov, a.clone(), vec![9]);
    db.set_storage(gov, b.clone(), vec![1]);
    db.set_storage(gov, c.clone(), vec![2]);
    let genesis_root = exec.calculate_state_root();
    db.delete_storage(gov, &a);
    exec.settle_block_rewards(
        1,
        [0u8; 20],
        [0u8; 32],
        CANONICAL_BASE_FEE_PER_GAS,
        &[],
        &[],
        &[],
    )
    .await
    .expect("settle");
    let live_root = exec.calculate_state_root();
    assert_ne!(live_root, genesis_root);

    // The restarted node: same account, surviving slots by insert, rooted at
    // its applied tip (height 1), as node boot does.
    let restarted = StateDB::new();
    restarted.accounts.set_balance(gov, U256::one());
    restarted.set_storage(gov, b, vec![1]);
    restarted.set_storage(gov, c, vec![2]);
    restarted.set_root_height(1);
    assert_eq!(restarted.calculate_state_root(), live_root);

    // Unpublished again, the same state roots by the legacy rule and diverges.
    srh::set_storage_root_hardening_height(None);
    assert_ne!(
        restarted.calculate_state_root(),
        exec.calculate_state_root()
    );
}
