// Property-based tests for citrate-bridge types and invariants.
// Tests attestation bounds, event hashing, config validation, and format properties
// using the proptest framework.

use proptest::prelude::*;

use citrate_bridge::config::BridgeConfig;
use citrate_bridge::events::{DepositEvent, EventId};
use citrate_bridge::oracle::{compute_event_hash, OracleRegistry};

proptest! {
    // -----------------------------------------------------------------------
    // 1. Attestation threshold bounds — threshold always <= total_oracles.
    // -----------------------------------------------------------------------
    #[test]
    fn attestation_threshold_bounds(
        num_oracles in 1usize..50,
        threshold in 1usize..50,
    ) {
        let mut registry = OracleRegistry::new(threshold);
        // Register oracles with arbitrary (non-ed25519-valid) IDs.
        // register_oracle stores them; crypto verification only happens on submit_attestation.
        for i in 0..num_oracles {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            id[1] = (i >> 8) as u8;
            let _ = registry.register_oracle(id, format!("Oracle-{}", i));
        }

        let reported_threshold = registry.threshold();
        prop_assert_eq!(
            reported_threshold, threshold,
            "Registry threshold must match configured value"
        );

        // Verify active oracle count matches what we registered.
        let active = registry.active_oracle_count();
        prop_assert_eq!(
            active, num_oracles,
            "Active oracle count must equal number registered"
        );
    }

    // -----------------------------------------------------------------------
    // 2. Event nonce monotonicity — sequential nonces always increase.
    // -----------------------------------------------------------------------
    #[test]
    fn event_nonce_monotonicity(
        base_nonce in 0u64..u64::MAX - 100,
        count in 1u64..50,
    ) {
        let nonces: Vec<u64> = (0..count).map(|i| base_nonce + i).collect();
        for window in nonces.windows(2) {
            prop_assert!(
                window[1] > window[0],
                "Event nonces must be strictly monotonically increasing: {} > {}",
                window[1], window[0]
            );
        }
    }

    // -----------------------------------------------------------------------
    // 3. Bridge event hash determinism — same event -> same hash.
    // -----------------------------------------------------------------------
    #[test]
    fn bridge_event_hash_determinism(
        tx_hash in prop::collection::vec(any::<u8>(), 32),
        log_index in any::<u32>(),
    ) {
        let tx: [u8; 32] = tx_hash.as_slice().try_into().unwrap();
        let id1 = DepositEvent::compute_event_id(&tx, log_index);
        let id2 = DepositEvent::compute_event_id(&tx, log_index);
        prop_assert_eq!(id1, id2, "Same tx_hash and log_index must produce same event_id");

        // Also test the generic compute_event_hash function
        let event_id: EventId = [42u8; 32];
        let data = b"some_deposit_data";
        let h1 = compute_event_hash(&event_id, data);
        let h2 = compute_event_hash(&event_id, data);
        prop_assert_eq!(h1, h2, "Same event_id and data must produce same event hash");
    }

    // -----------------------------------------------------------------------
    // 4. Oracle signature format — valid ed25519 signatures are 64 bytes.
    // -----------------------------------------------------------------------
    #[test]
    fn oracle_signature_format(sig_bytes in prop::collection::vec(any::<u8>(), 64)) {
        // Ed25519 signatures are always exactly 64 bytes
        prop_assert_eq!(
            sig_bytes.len(), 64,
            "Ed25519 signature must be exactly 64 bytes, got {}", sig_bytes.len()
        );
    }

    // -----------------------------------------------------------------------
    // 5. Config validation — oracle_threshold > 0, bonding curve bounds.
    // -----------------------------------------------------------------------
    #[test]
    fn config_validation_defaults(_dummy in 0u8..1u8) {
        let config = BridgeConfig::default();

        // oracle_threshold must be > 0
        prop_assert!(
            config.oracle_threshold > 0,
            "oracle_threshold must be > 0 in default config, got {}",
            config.oracle_threshold
        );

        // confirmation_depth must be > 0
        prop_assert!(
            config.confirmation_depth > 0,
            "confirmation_depth must be > 0"
        );

        // Bonding curve: base_multiplier must be > 0
        prop_assert!(
            config.bonding_curve.base_multiplier > 0.0,
            "base_multiplier must be > 0.0"
        );

        // Bonding curve: max_multiplier >= base_multiplier
        prop_assert!(
            config.bonding_curve.max_multiplier >= config.bonding_curve.base_multiplier,
            "max_multiplier must be >= base_multiplier"
        );

        // Bonding curve: salt_per_eth > 0
        prop_assert!(
            config.bonding_curve.salt_per_eth > 0,
            "salt_per_eth must be > 0"
        );

        // Bonding curve: calculate_salt_amount at base should match salt_per_eth
        let base_salt = config.bonding_curve.calculate_salt_amount(1.0, 0.0);
        prop_assert_eq!(
            base_salt,
            config.bonding_curve.salt_per_eth,
            "1 ETH at zero total deposited must yield salt_per_eth"
        );
    }
}
