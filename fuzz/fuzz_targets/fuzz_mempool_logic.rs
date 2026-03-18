#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};

/// Fuzz target that exercises actual mempool logic (add, get, remove)
/// rather than just deserialization.
///
/// Input format: sequence of (action_byte, payload) records.
/// Each record is: 1 byte action + 8 bytes nonce + 8 bytes gas_price + 1 byte sender_id
///   = 18 bytes per record.
///
/// Actions:
///   0 = add_transaction
///   1 = get_transaction (by hash of last added)
///   2 = remove_transaction (by hash of last added)
///
/// Invariants checked:
///   - No panics on any sequence of operations
///   - Capacity limit respected (mempool never exceeds max_size)
///   - Duplicate transactions rejected
fuzz_target!(|data: &[u8]| {
    const RECORD_SIZE: usize = 18;
    if data.len() < RECORD_SIZE {
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        use citrate_sequencer::{Mempool, MempoolConfig, TxClass};

        let config = MempoolConfig {
            max_size: 32, // Small capacity for faster fuzzing
            max_per_sender: 8,
            min_gas_price: 1, // Very low to allow more inputs through
            tx_expiry_secs: 3600,
            allow_replacement: true,
            replacement_factor: 110,
            require_valid_signature: false, // Disable sig checks for fuzzing
            chain_id: 1337,
        };

        let mempool = Mempool::new(config);

        let mut added_hashes: Vec<Hash> = Vec::new();

        for chunk in data.chunks_exact(RECORD_SIZE) {
            let action = chunk[0] % 3;
            let nonce = u64::from_le_bytes(chunk[1..9].try_into().unwrap());
            let gas_price = u64::from_le_bytes(chunk[9..17].try_into().unwrap());
            let sender_byte = chunk[17];

            match action {
                0 => {
                    // add_transaction
                    let mut sender_bytes = [0u8; 32];
                    sender_bytes[0] = sender_byte.wrapping_add(1); // Ensure non-zero
                    sender_bytes[1] = 0x01; // Ensure non-zero sender
                    let sender = PublicKey::new(sender_bytes);

                    // Build a unique hash from the chunk
                    let mut hash_bytes = [0u8; 32];
                    hash_bytes[..RECORD_SIZE].copy_from_slice(chunk);
                    hash_bytes[31] = added_hashes.len() as u8; // Extra uniqueness
                    let hash = Hash::new(hash_bytes);

                    let gas_price = gas_price.max(1_000_000_000); // Above min

                    let tx = Transaction {
                        hash,
                        nonce,
                        from: sender,
                        to: None,
                        value: 0,
                        gas_limit: 21000,
                        gas_price,
                        data: vec![],
                        signature: Signature::new([0xAA; 64]),
                        tx_type: None,
                        chain_id: Some(1337),
                        ..Default::default()
                    };

                    if mempool.add_transaction(tx, TxClass::Standard).await.is_ok() {
                        added_hashes.push(hash);
                    }
                }
                1 => {
                    // get_transaction
                    if let Some(h) = added_hashes.last() {
                        let _ = mempool.get_transaction(h).await;
                    }
                }
                2 => {
                    // remove_transaction
                    if let Some(h) = added_hashes.pop() {
                        let _ = mempool.remove_transaction(&h).await;
                    }
                }
                _ => unreachable!(),
            }
        }

        // Invariant: mempool size never exceeds max_size (32)
        let stats = mempool.stats().await;
        assert!(
            stats.total_transactions <= 32,
            "Mempool exceeded max_size: {} > 32",
            stats.total_transactions
        );

        // Invariant: no duplicate hashes remain
        let txs = mempool.get_transactions(100).await;
        let mut seen = std::collections::HashSet::new();
        for tx in &txs {
            assert!(
                seen.insert(tx.hash),
                "Duplicate transaction in mempool: {:?}",
                tx.hash
            );
        }
    });
});
