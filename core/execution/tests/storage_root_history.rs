// A contract's storage root must be a function of its final slot set only.
//
// A node that executed a slot deletion and a node that rebuilt the same final
// slot set by inserts (restart hydration) must fold the same storage root, and
// therefore compute the same state root, once the address holds an account.

use citrate_execution::types::Address;
use citrate_execution::{StateDB, Trie};
use primitive_types::U256;

/// Deterministic xorshift, so a failure is reproducible.
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
    /// A short key over a small alphabet, so keys share prefixes often.
    fn key(&mut self) -> Vec<u8> {
        let len = 1 + (self.next() % 3) as usize;
        (0..len).map(|_| (self.next() % 4) as u8).collect()
    }
}

#[test]
fn trie_root_ignores_a_removed_key_history() {
    // Minimal case from the review: insert A, B, C then remove A, versus B, C.
    let (a, b, c) = (vec![0u8, 1], vec![0u8, 3, 0], vec![3u8]);
    let mut replayed = Trie::new();
    replayed.insert(a.clone(), vec![9]);
    replayed.insert(b.clone(), vec![1]);
    replayed.insert(c.clone(), vec![2]);
    replayed.remove(&a);
    let mut hydrated = Trie::new();
    hydrated.insert(b, vec![1]);
    hydrated.insert(c, vec![2]);
    assert_eq!(
        replayed.root_hash(),
        hydrated.root_hash(),
        "same key/value set, different root"
    );
}

#[test]
fn trie_root_is_a_function_of_the_final_map_over_random_histories() {
    let mut rng = Rng(0x5EED_CAFE_F00D_0001);
    let mut diverged = 0usize;
    const TRIALS: usize = 500;
    for _ in 0..TRIALS {
        let keys: Vec<Vec<u8>> = (0..4).map(|_| rng.key()).collect();
        let mut replayed = Trie::new();
        for (i, k) in keys.iter().enumerate() {
            replayed.insert(k.clone(), vec![i as u8 + 1]);
        }
        let removed_key = keys[(rng.next() % 4) as usize].clone();
        replayed.remove(&removed_key);

        let mut hydrated = Trie::new();
        let mut final_map: Vec<(Vec<u8>, Vec<u8>)> = replayed.entries_map().into_iter().collect();
        final_map.sort();
        for (k, v) in final_map {
            hydrated.insert(k, v);
        }
        if replayed.root_hash() != hydrated.root_hash() {
            diverged += 1;
        }
    }
    assert_eq!(
        diverged, 0,
        "{diverged} of {TRIALS} histories changed the root"
    );
}

#[test]
fn state_root_after_a_storage_delete_matches_a_restart_rebuild() {
    let gov = Address([0x10; 20]);
    let (a, b, c) = (vec![0u8, 1], vec![0u8, 3, 0], vec![3u8]);

    // The node that executed the block: three writes, then a delete.
    let live = StateDB::new();
    live.accounts.set_balance(gov, U256::one());
    live.set_storage(gov, a.clone(), vec![9]);
    live.set_storage(gov, b.clone(), vec![1]);
    live.set_storage(gov, c.clone(), vec![2]);
    live.delete_storage(gov, &a);

    // The restarted node: the same account and the surviving slots, by insert.
    let restarted = StateDB::new();
    restarted.accounts.set_balance(gov, U256::one());
    restarted.set_storage(gov, b, vec![1]);
    restarted.set_storage(gov, c, vec![2]);

    assert_eq!(
        live.get_storage_root_recomputed(&gov),
        restarted.get_storage_root_recomputed(&gov),
        "storage root depends on delete history"
    );
    assert_eq!(
        live.calculate_state_root(),
        restarted.calculate_state_root(),
        "state root depends on delete history"
    );
}
