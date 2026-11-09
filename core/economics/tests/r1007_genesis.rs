//! The r1007 genesis (ADR-2026-11-03 CV-2, S3-6; docs/consensus/R1007_GENESIS.md).
//!
//! Owner decisions: r1007 is a new-genesis rehearsal of chain 40204 from the SAME
//! validator set, with TODAY's contract set (the r1006 ceremony state), and grants
//! re-issued by script after genesis. Its block 0 is rooted under the MPT state root
//! rule (CV-14, active from 0, block 0 included).
//!
//! The MPT rule is process-wide, so every test here takes `RULE` first.

use citrate_economics::genesis::{initialize_shared_genesis_state, GenesisConfig};
use citrate_economics::{r1006, r1007};
use citrate_execution::executor::Executor;
use citrate_execution::StateDB;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

static RULE: Mutex<()> = Mutex::new(());

fn rule(activation: Option<u64>) -> MutexGuard<'static, ()> {
    let g = RULE.lock().unwrap_or_else(|p| p.into_inner());
    citrate_execution::mpt_state_root::set_mpt_state_root_height(activation);
    g
}

/// The ceremony step (STATE_ROOT_MPT.md §1 step 3): the rule on from 0, then the shared
/// genesis function, twice over, gives exactly the block 0 this release pins.
#[test]
fn r1007_genesis_hash_is_pinned_and_reproducible_under_the_mpt_rule() {
    let _g = rule(Some(0));
    let cfg = GenesisConfig::r1007().expect("r1007 builds");
    let a = r1007::genesis_block_hash(&cfg).expect("block 0");
    let b = r1007::genesis_block_hash(&GenesisConfig::r1007().expect("r1007")).expect("block 0");
    assert_eq!(a, b, "two builds of the r1007 genesis differ");
    assert_eq!(
        a,
        citrate_consensus::hardening::R1007_GENESIS,
        "R1007_GENESIS is stale: the compiled r1007 profile builds 0x{}",
        hex::encode(a)
    );
    assert_ne!(a, citrate_consensus::hardening::R1006_GENESIS);
    // Block 0's root is the standard MPT root of the genesis state (the from-scratch
    // reference), not the legacy encoding.
    let db = Arc::new(StateDB::new());
    let ex = Arc::new(Executor::with_chain_id(db.clone(), 40204));
    let root = initialize_shared_genesis_state(&ex, &cfg).expect("genesis state");
    assert_eq!(root, *db.reference_state_root().as_bytes());
}

/// A GUI or light node that forgets to publish the rule must not build a different
/// "r1007" block 0: the shared genesis function refuses instead (fail closed).
#[test]
fn r1007_genesis_state_refuses_to_build_without_the_mpt_rule() {
    for activation in [None, Some(1), Some(10)] {
        let _g = rule(activation);
        let cfg = GenesisConfig::r1007().expect("r1007 config");
        let ex = Arc::new(Executor::with_chain_id(Arc::new(StateDB::new()), 40204));
        let e = initialize_shared_genesis_state(&ex, &cfg)
            .expect_err("the r1007 genesis builds only under the MPT rule from 0")
            .to_string();
        assert!(e.contains("MPT state root"), "{activation:?}: {e}");
    }
    // Other geneses are not affected by the guard (r1006 keeps the legacy root).
    let _g = rule(None);
    let ex = Arc::new(Executor::with_chain_id(Arc::new(StateDB::new()), 40204));
    initialize_shared_genesis_state(&ex, &GenesisConfig::r1006().expect("r1006"))
        .expect("r1006 builds without the MPT rule");
}

/// Same contract set and same validator set as r1006 (owner Q-3): every r1006 block-0
/// account is in r1007 byte for byte, except the r1006 genesis note, which r1007 replaces
/// with its own note. So every block-0 contract address, the SBT and the vault included,
/// is the same on r1007 as on r1006.
#[test]
fn r1007_keeps_the_r1006_contract_and_validator_sets() {
    let _g = rule(None);
    let r6 = GenesisConfig::r1006().expect("r1006");
    let r7 = GenesisConfig::r1007().expect("r1007");
    assert_eq!(r7.chain_id, 40204);
    for a in r6
        .accounts
        .iter()
        .filter(|a| a.address != r1006::GENESIS_NOTE_ADDRESS)
    {
        let b = r7
            .accounts
            .iter()
            .find(|x| x.address == a.address)
            .unwrap_or_else(|| panic!("0x{} missing from r1007", hex::encode(a.address.0)));
        assert_eq!(
            (&b.code, &b.storage, b.balance, b.nonce),
            (&a.code, &a.storage, a.balance, a.nonce),
            "0x{}",
            hex::encode(a.address.0)
        );
    }
    assert!(!r7
        .accounts
        .iter()
        .any(|a| a.address == r1006::GENESIS_NOTE_ADDRESS));
    let note = r7
        .accounts
        .iter()
        .find(|a| a.address == r1007::GENESIS_NOTE_ADDRESS)
        .expect("the r1007 note");
    assert_eq!(
        note.storage,
        r1006::solidity_string_slots(r1007::GENESIS_NOTE)
    );
    assert_eq!(r7.accounts.len(), r6.accounts.len());
    let mut seen = HashSet::new();
    assert!(r7.accounts.iter().all(|a| seen.insert(a.address.0)));
    assert_eq!(r7.treasury_address, r6.treasury_address);
    assert_eq!(r7.mining_pool_max, r6.mining_pool_max, "same supply split");
    r7.validate().expect("valid");

    // The producer set the genesis registers, and the registry binding a node enforces.
    assert_eq!(
        r1007::validator_set_binding().expect("binding"),
        r1006::validator_set_binding().expect("binding")
    );
    let (registry, activation) = r1007::validator_set_binding()
        .expect("binding")
        .expect("the r1006 producer set is final, so r1007 compiles the binding");
    assert_eq!(
        activation,
        citrate_consensus::genesis_params::R1007_CHAIN_PARAMS.validator_activation_height
    );
    assert!(r7
        .accounts
        .iter()
        .any(|a| a.address.0 == registry && a.code.as_ref().is_some_and(|c| !c.is_empty())));
    assert!(r1007::readiness().expect("readiness").is_release_ready());
}

#[test]
fn the_r1007_note_is_its_own_and_names_r1007() {
    assert_eq!(
        hex::encode(r1007::GENESIS_NOTE_ADDRESS.0),
        "000000000000000000000000000000c17a7e1007"
    );
    assert!(r1007::GENESIS_NOTE.starts_with("Citrate r1007."));
    assert_ne!(r1007::GENESIS_NOTE, r1006::GENESIS_NOTE);
}
