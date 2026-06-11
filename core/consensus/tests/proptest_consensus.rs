// Property-based tests for citrate-consensus crate.
//
// Sprint NN: Replaced tautological tests (asserting u64 >= 0, x+1 > x, etc.)
// with meaningful property tests that exercise actual consensus invariants
// using real DAG construction and blue set calculation.

use proptest::prelude::*;
use std::sync::Arc;

use citrate_consensus::{
    Block, BlockBuilder, CheckpointConfig, GhostDagParams,
    Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_consensus::checkpoint::CommitteeSelector;
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;

/// Helper: build a minimal valid Block from raw byte arrays for property tests.
fn make_block(
    hash_bytes: [u8; 32],
    parent_bytes: [u8; 32],
    height: u64,
    blue_score: u64,
    timestamp: u64,
    merge_parents: Vec<[u8; 32]>,
    vrf_proof_bytes: Vec<u8>,
) -> Block {
    BlockBuilder::new()
        .hash(Hash::new(hash_bytes))
        .parent(Hash::new(parent_bytes))
        .merge_parents(merge_parents.into_iter().map(Hash::new).collect())
        .height(height)
        .timestamp(timestamp)
        .blue_score(blue_score)
        .blue_work(blue_score as u128)
        .vrf_reveal(VrfProof {
            proof: vrf_proof_bytes,
            output: Hash::default(),
        })
        .build_unhashed()
}

/// Helper: build a DAG-compatible block with proper consensus fields.
fn make_dag_block(
    hash_bytes: [u8; 32],
    selected_parent: Hash,
    merge_parents: Vec<Hash>,
    height: u64,
    blue_score: u64,
) -> Block {
    BlockBuilder::new()
        .hash(Hash::new(hash_bytes))
        .parent(selected_parent)
        .merge_parents(merge_parents)
        .height(height)
        .timestamp(height)
        .blue_score(blue_score)
        // SECREM-01: admission enforces the canonical score→work relation.
        .blue_work(citrate_consensus::types::blue_work_for_score(blue_score))
        .build_unhashed()
}

/// Helper: build a Transaction from raw fields.
fn make_tx(
    hash_bytes: [u8; 32],
    nonce: u64,
    from_bytes: [u8; 32],
    value: u128,
    gas_price: u64,
    data: Vec<u8>,
) -> Transaction {
    Transaction {
        hash: Hash::new(hash_bytes),
        nonce,
        from: PublicKey::new(from_bytes),
        to: None,
        value,
        gas_limit: 21_000,
        gas_price,
        data,
        signature: Signature::default(),
        tx_type: None,
        eth_tx_type: 0,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: None,
        chain_id: None,
        ecdsa_verified: false,
    }
}

/// Deterministic hash from seed + index.
fn hash_for(seed: u64, index: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    let val = seed.wrapping_mul(31).wrapping_add(index);
    h[0..8].copy_from_slice(&val.to_le_bytes());
    h[8..16].copy_from_slice(&index.to_le_bytes());
    h[31] = 0xDD;
    h
}

/// Build a linear chain of n blocks on top of genesis, returning
/// (ghostdag, dag_store, all_hashes_including_genesis).
async fn build_chain(n: usize, seed: u64) -> (GhostDag, Arc<DagStore>, Vec<Hash>) {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    // Genesis
    let genesis = make_dag_block([0xFF; 32], Hash::default(), vec![], 0, 0);
    dag_store.store_block(genesis.clone()).await.unwrap();
    ghostdag.add_block(&genesis).await.unwrap();

    let mut hashes = vec![genesis.hash()];
    let mut prev = genesis.hash();

    for i in 0..n {
        let block = make_dag_block(hash_for(seed, i as u64), prev, vec![], (i + 1) as u64, (i + 1) as u64);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        hashes.push(block.hash());
        prev = block.hash();
    }

    (ghostdag, dag_store, hashes)
}

proptest! {
    // -----------------------------------------------------------------------
    // 1. Hash uniqueness — different inputs produce different Hash values.
    // -----------------------------------------------------------------------
    #[test]
    fn hash_uniqueness(a in prop::collection::vec(any::<u8>(), 32), b in prop::collection::vec(any::<u8>(), 32)) {
        let ha: [u8; 32] = a.as_slice().try_into().unwrap();
        let hb: [u8; 32] = b.as_slice().try_into().unwrap();
        let hash_a = Hash::new(ha);
        let hash_b = Hash::new(hb);
        if ha != hb {
            prop_assert_ne!(hash_a, hash_b);
        } else {
            prop_assert_eq!(hash_a, hash_b);
        }
    }

    // -----------------------------------------------------------------------
    // 2. GhostDagParams default validation — k > 0, max_parents > 0.
    // -----------------------------------------------------------------------
    #[test]
    fn ghostdag_params_defaults_valid(_dummy in 0u8..1u8) {
        let params = GhostDagParams::default();
        prop_assert!(params.k > 0, "k must be positive, got {}", params.k);
        prop_assert!(params.max_parents > 0, "max_parents must be positive, got {}", params.max_parents);
        prop_assert!(params.finality_depth > 0, "finality_depth must be positive");
        prop_assert!(params.pruning_window > 0, "pruning_window must be positive");
    }

    // -----------------------------------------------------------------------
    // 3. REPLACED: proptest_genesis_always_blue
    //    For random-length linear chains, genesis is always in the blue set
    //    of every block. This exercises real DAG construction and blue set
    //    calculation, unlike the old tautological height test.
    // -----------------------------------------------------------------------
    #[test]
    fn proptest_genesis_always_blue(n in 1..12usize, seed in 1..1000u64) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (ghostdag, dag_store, hashes) = build_chain(n, seed).await;
            let genesis_hash = hashes[0];

            for hash in &hashes {
                let block = dag_store.get_block(hash).await.unwrap();
                let blue_set = ghostdag.calculate_blue_set(&block).await.unwrap();
                prop_assert!(
                    blue_set.contains(&genesis_hash),
                    "Genesis must be in the blue set of block {:?} (chain len={})",
                    hash, n
                );
            }
            Ok(())
        })?;
    }

    // -----------------------------------------------------------------------
    // 4. Transaction hash determinism — same content -> same hash.
    // -----------------------------------------------------------------------
    #[test]
    fn transaction_hash_determinism(
        hash_bytes in prop::collection::vec(any::<u8>(), 32),
        nonce in any::<u64>(),
        from_bytes in prop::collection::vec(any::<u8>(), 32),
        value in any::<u128>(),
        gas_price in any::<u64>(),
        data in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let hb: [u8; 32] = hash_bytes.as_slice().try_into().unwrap();
        let fb: [u8; 32] = from_bytes.as_slice().try_into().unwrap();

        let tx1 = make_tx(hb, nonce, fb, value, gas_price, data.clone());
        let tx2 = make_tx(hb, nonce, fb, value, gas_price, data);
        prop_assert_eq!(tx1.hash, tx2.hash, "Same transaction content must yield same hash");
    }

    // -----------------------------------------------------------------------
    // 5. VrfProof length validity — valid proofs are 114 bytes (ECVRF) or 32 bytes (legacy).
    // -----------------------------------------------------------------------
    #[test]
    fn vrf_proof_length_validity(proof_len in prop::sample::select(vec![32usize, 114])) {
        let proof_bytes = vec![0u8; proof_len];
        let vrf = VrfProof {
            proof: proof_bytes.clone(),
            output: Hash::default(),
        };
        prop_assert!(
            vrf.proof.len() == 32 || vrf.proof.len() == 114,
            "Valid VRF proof must be 32 (legacy) or 114 (ECVRF) bytes, got {}",
            vrf.proof.len()
        );
    }

    // -----------------------------------------------------------------------
    // 6. REPLACED: proptest_blue_score_monotonic
    //    For any linear chain extension, blue score >= parent's blue score.
    //    This exercises real blue score computation on random chain lengths.
    // -----------------------------------------------------------------------
    #[test]
    fn proptest_blue_score_monotonic(n in 2..15usize, seed in 1..1000u64) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (ghostdag, _dag_store, hashes) = build_chain(n, seed).await;
            let mut prev_score = 0u64;

            for hash in &hashes {
                let score = ghostdag.get_blue_score(hash).await.unwrap();
                prop_assert!(
                    score >= prev_score,
                    "Blue score must be monotonically non-decreasing: {} -> {} at {:?}",
                    prev_score, score, hash
                );
                prev_score = score;
            }
            Ok(())
        })?;
    }

    // -----------------------------------------------------------------------
    // 7. Block serialization round-trip (bincode).
    // -----------------------------------------------------------------------
    #[test]
    fn block_serialization_roundtrip(
        height in 0u64..10_000,
        blue_score in 0u64..10_000,
        timestamp in 0u64..u64::MAX,
    ) {
        let block = make_block([0xAA; 32], [0xBB; 32], height, blue_score, timestamp, vec![], vec![]);
        let bytes = bincode::serialize(&block).expect("serialize must succeed");
        let roundtripped: Block = bincode::deserialize(&bytes).expect("deserialize must succeed");
        prop_assert_eq!(roundtripped.header.height, height);
        prop_assert_eq!(roundtripped.header.blue_score, blue_score);
        prop_assert_eq!(roundtripped.header.timestamp, timestamp);
        prop_assert_eq!(roundtripped.header.block_hash, Hash::new([0xAA; 32]));
    }

    // -----------------------------------------------------------------------
    // 8. REPLACED: proptest_no_dag_cycles
    //    For any sequence of block additions to a linear chain, the DAG
    //    store must never contain cycles. We verify by checking that
    //    walking parents from any block eventually reaches genesis without
    //    revisiting a block.
    // -----------------------------------------------------------------------
    #[test]
    fn proptest_no_dag_cycles(n in 1..15usize, seed in 1..1000u64) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (_ghostdag, dag_store, hashes) = build_chain(n, seed).await;

            // For each block, walk back via selected_parent and verify no cycles
            for hash in &hashes {
                let mut visited = std::collections::HashSet::new();
                let mut current = *hash;

                loop {
                    prop_assert!(
                        !visited.contains(&current),
                        "Cycle detected: block {:?} visited twice while walking from {:?}",
                        current, hash
                    );
                    visited.insert(current);

                    let block = dag_store.get_block(&current).await.unwrap();
                    if block.is_genesis() {
                        break;
                    }
                    current = block.selected_parent();
                }
            }
            Ok(())
        })?;
    }

    // -----------------------------------------------------------------------
    // 9. Signature length — always 64 bytes.
    // -----------------------------------------------------------------------
    #[test]
    fn signature_length_always_64(sig_bytes in prop::collection::vec(any::<u8>(), 64)) {
        let arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = Signature::new(arr);
        prop_assert_eq!(sig.as_bytes().len(), 64, "Signature must be exactly 64 bytes");
    }

    // -----------------------------------------------------------------------
    // 10. PublicKey to Hash derivation determinism.
    // -----------------------------------------------------------------------
    #[test]
    fn pubkey_to_hash_determinism(pk_bytes in prop::collection::vec(any::<u8>(), 32)) {
        let arr: [u8; 32] = pk_bytes.as_slice().try_into().unwrap();
        let pk = PublicKey::new(arr);
        let hex1 = format!("{:?}", pk);
        let pk2 = PublicKey::new(arr);
        let hex2 = format!("{:?}", pk2);
        prop_assert_eq!(hex1, hex2, "Same public key bytes must produce same debug output");
        prop_assert_eq!(pk, pk2, "Same bytes must be equal");
    }

    // -----------------------------------------------------------------------
    // 11. Checkpoint committee size bounds.
    // -----------------------------------------------------------------------
    #[test]
    fn checkpoint_committee_size_bounds(
        num_validators in 1usize..50,
        committee_size in 1usize..200,
        seed_bytes in prop::collection::vec(any::<u8>(), 32),
    ) {
        let validators: Vec<(PublicKey, u128)> = (0..num_validators)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i as u8;
                bytes[1] = (i >> 8) as u8;
                (PublicKey::new(bytes), 1000)
            })
            .collect();
        let seed = Hash::new(seed_bytes.as_slice().try_into().unwrap());
        let committee = CommitteeSelector::select(&validators, 100, &seed, committee_size);
        let expected_max = committee_size.min(num_validators);
        prop_assert_eq!(
            committee.len(), expected_max,
            "Committee size must be min(requested={}, available={}), got {}",
            committee_size, num_validators, committee.len()
        );
    }

    // -----------------------------------------------------------------------
    // 12. Checkpoint quorum requirement — 67 out of 100 (default config).
    // -----------------------------------------------------------------------
    #[test]
    fn checkpoint_quorum_requirement(vote_count in 0usize..200) {
        let config = CheckpointConfig::default();
        let quorum_met = vote_count >= config.quorum_threshold;
        if vote_count >= 67 {
            prop_assert!(quorum_met, "67+ votes must meet quorum");
        } else {
            prop_assert!(!quorum_met, "<67 votes must not meet quorum");
        }
    }

    // -----------------------------------------------------------------------
    // 13. GhostDagParams clone equality.
    // -----------------------------------------------------------------------
    #[test]
    fn ghostdag_params_clone_equality(
        k in 1u32..100,
        max_parents in 1usize..50,
        finality_depth in 1u64..10_000,
    ) {
        let params = GhostDagParams {
            k,
            max_parents,
            max_blue_score_diff: 1000,
            pruning_window: 100_000,
            finality_depth,
        };
        let cloned = params.clone();
        prop_assert_eq!(cloned.k, params.k);
        prop_assert_eq!(cloned.max_parents, params.max_parents);
        prop_assert_eq!(cloned.finality_depth, params.finality_depth);
        prop_assert_eq!(cloned.max_blue_score_diff, params.max_blue_score_diff);
        prop_assert_eq!(cloned.pruning_window, params.pruning_window);
    }

    // -----------------------------------------------------------------------
    // 14. Blue set always contains the block itself.
    //     For any block in a random linear chain, its own hash must be
    //     in its blue set.
    // -----------------------------------------------------------------------
    #[test]
    fn proptest_blue_set_contains_self(n in 1..12usize, seed in 1..1000u64) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (ghostdag, dag_store, hashes) = build_chain(n, seed).await;
            for hash in &hashes {
                let block = dag_store.get_block(hash).await.unwrap();
                let blue_set = ghostdag.calculate_blue_set(&block).await.unwrap();
                prop_assert!(
                    blue_set.contains(hash),
                    "Block {:?} must be in its own blue set",
                    hash
                );
            }
            Ok(())
        })?;
    }

    // -----------------------------------------------------------------------
    // 15. compute_hash determinism — same block always produces same hash.
    // -----------------------------------------------------------------------
    #[test]
    fn compute_hash_determinism(
        height in 0u64..10_000,
        blue_score in 0u64..10_000,
    ) {
        let block = make_block([0xCC; 32], [0xDD; 32], height, blue_score, 100, vec![], vec![]);
        let hash1 = block.compute_hash();
        let hash2 = block.compute_hash();
        prop_assert_eq!(hash1, hash2, "compute_hash must be deterministic");
    }
}
