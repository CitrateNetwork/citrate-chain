// Replay below the storage-root hardening height is byte-identical.
//
// A fixed 12-block history (balances, EVM slots, governance proposals whose
// `PENDING:` record is deleted when applied, artifact records with
// variable-length values, and deletes that leave the legacy trie in a
// history-dependent shape). The GOLDEN roots were recorded by running this
// exact scenario on the code BEFORE the activation height was added (the
// parent commit, `StateDB::calculate_state_root`). Every block below the
// activation height must reproduce them byte for byte, under no activation
// (40204 today) and under a later one. At and after the height the root must instead equal the root of a
// restart rebuild of the same state.

use citrate_execution::types::Address;
use citrate_execution::StateDB;
use primitive_types::U256;

pub const BLOCKS: u64 = 12;

fn precompile(nn: u8) -> Address {
    let mut a = [0u8; 20];
    a[18] = 0x10;
    a[19] = nn;
    Address(a)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn prefixed(tag: &[u8], k: u8) -> Vec<u8> {
    let mut v = tag.to_vec();
    v.extend_from_slice(&[k; 32]);
    v
}

/// Apply block `h` of the scenario to `db`: balances, EVM slots, executor-native
/// governance records, and storage deletes (the governance `PENDING:` delete
/// plus short keys that leave the legacy trie in a non-canonical shape).
pub fn apply_block(db: &StateDB, h: u64) {
    let gov = precompile(0x03);
    let art = precompile(0x02);
    let erc = Address([0xC0; 20]);
    let mut rng = Rng(0x5EED_2026_1026_0001 ^ h.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    if h == 0 {
        for i in 1..=6u8 {
            db.accounts
                .set_balance(Address([i; 20]), U256::from(1_000_000u64 * i as u64));
        }
        // Precompile accounts with a balance, so they are part of the state root.
        db.accounts.set_balance(gov, U256::one());
        db.accounts.set_balance(art, U256::one());
        db.accounts.set_balance(erc, U256::from(7u64));
        db.set_storage(gov, b"ADMIN".to_vec(), vec![0xA1; 20]);
        for s in 0..8u8 {
            db.set_storage(erc, vec![s; 32], vec![s ^ 0x5A; 32]);
        }
        return;
    }
    // Value movement every block.
    let from = Address([(1 + (h % 6)) as u8; 20]);
    let bal = db.accounts.get_balance(&from);
    db.accounts
        .set_balance(from, bal.saturating_sub(U256::from(h)));
    db.accounts.set_balance(Address([0xEE; 20]), U256::from(h));
    // EVM slot writes.
    for _ in 0..3 {
        let s = (rng.next() % 16) as u8;
        db.set_storage(erc, vec![s; 32], vec![(rng.next() & 0xFF) as u8; 32]);
    }
    // Governance: propose at odd heights, apply (delete PENDING) at even heights.
    let k = (h / 2) as u8;
    if h % 2 == 1 {
        db.set_storage(
            gov,
            prefixed(b"PENDING:", k),
            [h.to_le_bytes().to_vec(), b"v".to_vec()].concat(),
        );
    } else {
        db.set_storage(gov, prefixed(b"PARAM:", k), b"v".to_vec());
        db.delete_storage(gov, &prefixed(b"PENDING:", k));
    }
    // Artifact index records with variable-length values.
    db.set_storage(
        art,
        prefixed(b"MODEL_CID:", (h % 3) as u8),
        format!("bafy-{h}").into_bytes(),
    );
    // Short keys over a small alphabet, then a delete, at every third height.
    if h.is_multiple_of(3) {
        let (a, b, c) = (vec![0u8, 1], vec![0u8, 3, 0], vec![3u8]);
        db.set_storage(art, a.clone(), vec![9]);
        db.set_storage(art, b, vec![h as u8]);
        db.set_storage(art, c, vec![2]);
        db.delete_storage(art, &a);
    }
}

const GOLDEN: [&str; BLOCKS as usize] = [
    "c8ab1dce007c99376fdf7e861ea33d9caf0db78032e2e335af6ef412658b2a17",
    "89812a361b2c59f4a83a8a27e08bf7e7e8cd68028c867e235c07a60afdc987c2",
    "9f8c4fbc8a3e2b520ec06df51bd3537c81e7cf199eab99cf5865201bbe3f184b",
    "593947a6029db38771d2627a586de511e4f7098ce46eda8bba3272f3475b7c04",
    "05305c19c585a08beec6379c648808f041b7fc27c9e2833e9a40523b54ab8b19",
    "2820b7cbae5e5effff660ad58557da792112e8dd732d80471bf5569e5e7d2bef",
    "e9b65117cfd21fd588de892a2597937d4457e3ceaf76273bae20c895b4689ead",
    "2b60dae03b637e3cc2bf04348bc2e6d06376c866e5aa46947a3eb1d0371048b8",
    "34ae168006976a45f690f139b8fcb6e2c46bce960902c04b2726586576539a3c",
    "3119b903c45a6fffe7941a9a8ef6764921578139910c54d29469a9082210aec8",
    "849f6b56f7ef5dea741f6c2f118ab7e47b88816ef453c073870376af3b8a6862",
    "f681bc3ce0213333a5d93b6bebc4c92b32d77ed98531577aa42ac11c83097ffe",
];

fn hex_root(db: &StateDB, activation: Option<u64>, h: u64) -> String {
    hex::encode(db.calculate_state_root_with(activation, h).as_bytes())
}

/// The state a restarted node rebuilds: the same accounts, and every slot by
/// insert only.
fn restart_rebuild(db: &StateDB) -> StateDB {
    let snap = db.snapshot();
    let cold = StateDB::new();
    for (addr, acct) in snap.account_entries() {
        cold.accounts.set_account(*addr, acct.clone());
    }
    let mut slots: Vec<(Address, Vec<u8>, Vec<u8>)> = snap
        .storage_map()
        .into_iter()
        .flat_map(|(a, m)| m.into_iter().map(move |(k, v)| (a, k, v)))
        .collect();
    slots.sort_by(|x, y| (x.0 .0, &x.1).cmp(&(y.0 .0, &y.1)));
    for (a, k, v) in slots {
        cold.set_storage(a, k, v);
    }
    cold
}

#[test]
fn no_activation_replays_every_block_to_its_recorded_root() {
    let db = StateDB::new();
    for h in 0..BLOCKS {
        apply_block(&db, h);
        assert_eq!(hex_root(&db, None, h), GOLDEN[h as usize], "block {h}");
        // The default entry point is the same legacy function.
        db.set_root_height(h);
        assert_eq!(
            hex::encode(db.calculate_state_root().as_bytes()),
            GOLDEN[h as usize],
            "block {h} via calculate_state_root"
        );
    }
}

#[test]
fn blocks_below_a_scheduled_activation_replay_to_their_recorded_roots() {
    const ACTIVATION: u64 = 7;
    let db = StateDB::new();
    let mut hardened_differs = false;
    for h in 0..BLOCKS {
        apply_block(&db, h);
        let got = hex_root(&db, Some(ACTIVATION), h);
        if h < ACTIVATION {
            assert_eq!(got, GOLDEN[h as usize], "block {h} below activation");
        } else {
            let cold = restart_rebuild(&db);
            assert_eq!(
                got,
                hex_root(&cold, Some(ACTIVATION), h),
                "block {h}: replay and restart rebuild must agree from the activation"
            );
            hardened_differs |= got != GOLDEN[h as usize];
        }
    }
    // Negative control: the legacy and hardened roots differ on this history,
    // so the equalities above are not vacuous.
    assert!(
        hardened_differs,
        "the scenario must reach a block where the hardened root differs"
    );
}

#[test]
fn a_new_genesis_keeps_its_genesis_root_and_hardens_from_block_one() {
    let db = StateDB::new();
    apply_block(&db, 0);
    assert_eq!(
        hex_root(&db, Some(0), 0),
        GOLDEN[0],
        "genesis is never re-judged"
    );
    for h in 1..BLOCKS {
        apply_block(&db, h);
        let cold = restart_rebuild(&db);
        assert_eq!(
            hex_root(&db, Some(0), h),
            hex_root(&cold, Some(0), h),
            "block {h}"
        );
    }
}

#[test]
fn legacy_root_diverges_between_replay_and_restart_on_this_history() {
    // Shows why the activation height exists: under the legacy rule a node
    // restarted after block 3 (the first short-key delete) folds a different
    // root from the node that executed it.
    let db = StateDB::new();
    for h in 0..=3 {
        apply_block(&db, h);
    }
    let cold = restart_rebuild(&db);
    assert_ne!(hex_root(&db, None, 3), hex_root(&cold, None, 3));
    assert_eq!(hex_root(&db, Some(0), 3), hex_root(&cold, Some(0), 3));
}

/// Block reward settlement, the one step the producer, block import and
/// trusted replay all run after execution and before the root, moves the root
/// height to the block's height, and a revert to a snapshot moves it back.
#[tokio::test]
async fn settlement_sets_the_root_height_and_a_revert_restores_it() {
    use citrate_execution::block_rewards::CANONICAL_BASE_FEE_PER_GAS;
    use citrate_execution::Executor;
    use std::sync::Arc;

    let db = Arc::new(StateDB::new());
    let exec = Executor::new(db.clone());
    assert_eq!(db.root_height(), 0, "genesis until a block is settled");
    let settle = |h: u64| {
        let exec = &exec;
        async move {
            exec.settle_block_rewards(
                h,
                [0u8; 20],
                [0u8; 32],
                CANONICAL_BASE_FEE_PER_GAS,
                &[],
                &[],
                &[],
            )
            .await
            .expect("settle")
        }
    };
    settle(9).await;
    assert_eq!(db.root_height(), 9);
    let at_nine = db.snapshot();
    settle(10).await;
    assert_eq!(db.root_height(), 10);
    db.restore(at_nine);
    assert_eq!(
        db.root_height(),
        9,
        "a revert restores the rule of the restored state"
    );
    // The isolated copy RPC roots from carries the height too.
    assert_eq!(db.isolated_clone().root_height(), 9);
    assert_eq!(
        exec.calculate_state_root(),
        db.calculate_state_root_at(9),
        "the executor roots at the settled height"
    );
}
