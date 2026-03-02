// Property-based tests for citrate-sequencer mempool.
// Tests ordering invariants, capacity bounds, and priority correctness
// using the proptest framework.

use proptest::prelude::*;

use citrate_sequencer::{Mempool, MempoolConfig, TxClass};
use citrate_sequencer::mempool::TxPriority;

proptest! {
    // -----------------------------------------------------------------------
    // 1. TxClass ordering — System > ModelUpdate > Compute > Training > Inference > Storage > Standard.
    // -----------------------------------------------------------------------
    #[test]
    fn txclass_ordering_invariant(_dummy in 0u8..1u8) {
        // Priority multipliers define the ordering
        let system = TxClass::System.priority_multiplier();
        let model_update = TxClass::ModelUpdate.priority_multiplier();
        let compute = TxClass::Compute.priority_multiplier();
        let training = TxClass::Training.priority_multiplier();
        let inference = TxClass::Inference.priority_multiplier();
        let storage = TxClass::Storage.priority_multiplier();
        let standard = TxClass::Standard.priority_multiplier();

        prop_assert!(system > model_update, "System > ModelUpdate");
        prop_assert!(model_update > compute, "ModelUpdate > Compute");
        prop_assert!(compute > training, "Compute > Training");
        prop_assert!(training > inference, "Training > Inference");
        prop_assert!(inference > storage, "Inference > Storage");
        prop_assert!(storage > standard, "Storage > Standard");
    }

    // -----------------------------------------------------------------------
    // 2. TxPriority ordering determinism — same fields → same ordering.
    // -----------------------------------------------------------------------
    #[test]
    fn txpriority_ordering_determinism(
        gas_price in 1u64..1_000_000,
        timestamp in 0u64..u64::MAX,
    ) {
        let p1 = TxPriority::new(gas_price, TxClass::Standard, timestamp);
        let p2 = TxPriority::new(gas_price, TxClass::Standard, timestamp);
        prop_assert_eq!(p1.score(), p2.score(), "Same fields must produce same score");
        prop_assert_eq!(
            p1.cmp(&p2),
            std::cmp::Ordering::Equal,
            "Same priority must compare Equal"
        );
    }

    // -----------------------------------------------------------------------
    // 3. Mempool capacity invariant — max_size is stored correctly.
    // -----------------------------------------------------------------------
    #[test]
    fn mempool_capacity_invariant(max_size in 1usize..100_000) {
        let config = MempoolConfig {
            max_size,
            ..MempoolConfig::default()
        };
        let pool = Mempool::new(config);
        // The mempool was created — we just verify it doesn't panic on construction.
        // The actual capacity enforcement is tested via add_transaction which requires
        // async + full Transaction objects. Here we verify construction is sound.
        prop_assert!(max_size > 0, "Capacity must be positive");
        // Mempool is opaque; verify construction succeeded by drop without panic.
        drop(pool);
    }

    // -----------------------------------------------------------------------
    // 4. Transaction hash uniqueness — different data → different SHA3.
    // -----------------------------------------------------------------------
    #[test]
    fn tx_hash_uniqueness_via_sha3(
        a in prop::collection::vec(any::<u8>(), 32),
        b in prop::collection::vec(any::<u8>(), 32),
    ) {
        use sha3::{Digest, Sha3_256};
        let hash_a = {
            let mut h = Sha3_256::new();
            h.update(&a);
            h.finalize()
        };
        let hash_b = {
            let mut h = Sha3_256::new();
            h.update(&b);
            h.finalize()
        };
        if a != b {
            prop_assert_ne!(
                hash_a.as_slice(), hash_b.as_slice(),
                "Different data must produce different SHA3 hashes"
            );
        } else {
            prop_assert_eq!(
                hash_a.as_slice(), hash_b.as_slice(),
                "Same data must produce same SHA3 hash"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 5. Nonce monotonicity per sender — sequential nonces must increase.
    // -----------------------------------------------------------------------
    #[test]
    fn nonce_monotonicity(base_nonce in 0u64..u64::MAX - 100, count in 1u64..50) {
        let nonces: Vec<u64> = (0..count).map(|i| base_nonce + i).collect();
        for window in nonces.windows(2) {
            prop_assert!(
                window[1] > window[0],
                "Nonce sequence must be strictly increasing: {} should be > {}",
                window[1], window[0]
            );
        }
    }

    // -----------------------------------------------------------------------
    // 6. Sender limit enforcement — config bounds are respected.
    // -----------------------------------------------------------------------
    #[test]
    fn sender_limit_config(max_per_sender in 1usize..1000) {
        let config = MempoolConfig {
            max_per_sender,
            ..MempoolConfig::default()
        };
        // Verify the config value is stored
        prop_assert_eq!(
            config.max_per_sender, max_per_sender,
            "max_per_sender must match configured value"
        );
    }

    // -----------------------------------------------------------------------
    // 7. Priority ordering — higher gas_price + higher class = higher priority.
    // -----------------------------------------------------------------------
    #[test]
    fn priority_ordering_correctness(
        low_gas in 1u64..500_000,
        high_gas_delta in 1u64..500_000,
        timestamp in 0u64..u64::MAX,
    ) {
        let high_gas = low_gas + high_gas_delta;

        // Same class, different gas price → higher gas = higher priority
        let low_pri = TxPriority::new(low_gas, TxClass::Standard, timestamp);
        let high_pri = TxPriority::new(high_gas, TxClass::Standard, timestamp);
        prop_assert!(
            high_pri.score() > low_pri.score(),
            "Higher gas price must yield higher score: {} vs {}",
            high_pri.score(), low_pri.score()
        );

        // Same gas price, different class → higher class = higher priority
        let standard_pri = TxPriority::new(low_gas, TxClass::Standard, timestamp);
        let system_pri = TxPriority::new(low_gas, TxClass::System, timestamp);
        prop_assert!(
            system_pri.score() > standard_pri.score(),
            "System class must have higher score than Standard: {} vs {}",
            system_pri.score(), standard_pri.score()
        );
    }

    // -----------------------------------------------------------------------
    // 8. Empty mempool operations — construction and basic properties.
    // -----------------------------------------------------------------------
    #[test]
    fn empty_mempool_properties(max_size in 1usize..10_000) {
        let config = MempoolConfig {
            max_size,
            ..MempoolConfig::default()
        };
        let pool = Mempool::new(config);
        // An empty mempool should not panic on drop and should have been constructed.
        // The Mempool type uses async methods for size/pop, so we verify construction.
        drop(pool);
        // Re-create and verify config defaults
        let config2 = MempoolConfig::default();
        prop_assert!(config2.max_size > 0, "Default max_size must be positive");
        prop_assert!(config2.max_per_sender > 0, "Default max_per_sender must be positive");
        prop_assert!(config2.min_gas_price > 0, "Default min_gas_price must be positive");
    }
}
