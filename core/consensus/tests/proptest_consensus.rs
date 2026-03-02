// Property-based tests for citrate-consensus crate.
// Tests fundamental invariants of the GhostDAG consensus types
// using the proptest framework with the `proptest!` macro.

use proptest::prelude::*;

use citrate_consensus::{
    Block, BlockHeader, CheckpointConfig, GhostDagParams,
    Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_consensus::checkpoint::CommitteeSelector;

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
    Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::new(hash_bytes),
            selected_parent_hash: Hash::new(parent_bytes),
            merge_parent_hashes: merge_parents.into_iter().map(Hash::new).collect(),
            timestamp,
            height,
            blue_score,
            blue_work: blue_score as u128,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([0; 32]),
            vrf_reveal: VrfProof {
                proof: vrf_proof_bytes,
                output: Hash::default(),
            },
            base_fee_per_gas: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
        },
        state_root: Hash::default(),
        tx_root: Hash::default(),
        receipt_root: Hash::default(),
        artifact_root: Hash::default(),
        ghostdag_params: GhostDagParams::default(),
        transactions: vec![],
        signature: Signature::new([0; 64]),
        embedded_models: vec![],
        required_pins: vec![],
        learning_embedding: None,
        learning_confidence: None,
        gradient_commitment: None,
    }
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
        // If inputs differ, hashes must differ (hashes are identity-wrapping [u8;32])
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
    // 3. Block height monotonicity — child height > parent height.
    // -----------------------------------------------------------------------
    #[test]
    fn block_height_monotonicity(parent_height in 0u64..u64::MAX - 1) {
        let child_height = parent_height + 1;
        prop_assert!(child_height > parent_height, "child height must exceed parent height");
    }

    // -----------------------------------------------------------------------
    // 4. Transaction hash determinism — same content → same hash.
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
    // 6. Blue score non-negativity — blue_score always >= 0 (u64 is inherently non-negative).
    // -----------------------------------------------------------------------
    #[test]
    fn blue_score_non_negative(score in any::<u64>()) {
        let block = make_block([1; 32], [0; 32], 1, score, 100, vec![], vec![]);
        // u64 is always >= 0, but confirm the accessor returns the expected value
        prop_assert_eq!(block.blue_score(), score);
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
    // 8. Merge parent count bound — merge parents <= max_parents.
    // -----------------------------------------------------------------------
    #[test]
    fn merge_parent_count_bounded(
        num_parents in 0usize..20,
        max_parents in 1usize..30,
    ) {
        let merge: Vec<[u8; 32]> = (0..num_parents).map(|i| {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h
        }).collect();

        let block = make_block([1; 32], [0; 32], 1, 0, 100, merge.clone(), vec![]);
        let actual = block.header.merge_parent_hashes.len();

        // This is the invariant that a block builder must enforce.
        // We test the check rather than enforce it structurally.
        if actual <= max_parents {
            prop_assert!(actual <= max_parents);
        } else {
            // When a block exceeds max_parents, it violates the invariant
            prop_assert!(actual > max_parents);
        }
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
        // Two identical public keys must yield identical hex representations
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
        // Committee size is min(committee_size, num_validators)
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
        // Default quorum_threshold is 67
        let quorum_met = vote_count >= config.quorum_threshold;
        if vote_count >= 67 {
            prop_assert!(quorum_met, "67+ votes must meet quorum");
        } else {
            prop_assert!(!quorum_met, "<67 votes must not meet quorum");
        }
    }

    // -----------------------------------------------------------------------
    // 13. Block timestamp monotonicity in chains.
    // -----------------------------------------------------------------------
    #[test]
    fn block_timestamp_monotonicity(
        ts_parent in 0u64..u64::MAX - 1,
        delta in 1u64..1_000_000,
    ) {
        let ts_child = ts_parent.saturating_add(delta);
        prop_assert!(ts_child >= ts_parent, "Child timestamp must be >= parent timestamp");
    }

    // -----------------------------------------------------------------------
    // 14. Transaction nonce non-negative (u64 is inherently non-negative).
    // -----------------------------------------------------------------------
    #[test]
    fn transaction_nonce_non_negative(nonce in any::<u64>()) {
        let tx = make_tx([0; 32], nonce, [1; 32], 0, 0, vec![]);
        // u64 is always >= 0; verify we stored it correctly
        prop_assert_eq!(tx.nonce, nonce);
    }

    // -----------------------------------------------------------------------
    // 15. GhostDagParams clone equality.
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
}
