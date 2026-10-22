#![no_main]
//! Fuzz target that exercises actual mempool logic (add, get, remove)
//! rather than just deserialization.
//!
//! Input format: sequence of (action_byte, payload) records.
//! Each record is: 1 byte action + 8 bytes nonce + 8 bytes gas_price + 1 byte sender_id
//!   = 18 bytes per record.
//!
//! Actions:
//!   0 = add_transaction
//!   1 = get_transaction (by hash of last added)
//!   2 = remove_transaction (by hash of last added)
//!
//! Invariants checked:
//!   - No panics on any sequence of operations
//!   - Capacity limit respected (mempool never exceeds max_size)
//!   - Per-sender limit respected (no sender holds more than max_per_sender)
//!   - Duplicate transactions rejected (re-adding an admitted or a removed
//!     transaction fails), and no hash is held twice
//!   - An admitted transaction is retrievable; a removed one is not
//!   - `stats()` agrees with the transaction listing
//!
//! Senders are native ed25519-shaped keys (a non-zero byte past offset 20).
//! A sender whose bytes 20..32 are all zero is EVM-shaped, and the mempool
//! now requires a secp256k1 recovery for those, so an EVM-shaped fuzz sender
//! would be rejected on every add and the harness would exercise nothing.
//! For the same reason each added transaction is a plain transfer (see the
//! `to` field below).
use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use libfuzzer_sys::fuzz_target;

const RECORD_SIZE: usize = 18;
const MAX_SIZE: usize = 32;
const MAX_PER_SENDER: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.len() < RECORD_SIZE {
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("failed to build fuzz runtime: {err}"));

    rt.block_on(async {
        use citrate_sequencer::{Mempool, MempoolConfig, MempoolError, TxClass};

        let config = MempoolConfig {
            max_size: MAX_SIZE, // Small capacity for faster fuzzing
            max_per_sender: MAX_PER_SENDER,
            min_gas_price: 1, // Very low to allow more inputs through
            tx_expiry_secs: 3600,
            allow_replacement: true,
            replacement_factor: 110,
            require_valid_signature: false, // Disable sig checks for fuzzing
            chain_id: 40204,
            // Production default (MempoolConfig::default()).
            max_nonce_gap: 16,
        };

        let mempool = Mempool::new(config);

        let mut added_hashes: Vec<Hash> = Vec::new();

        for chunk in data.chunks_exact(RECORD_SIZE) {
            let action = chunk[0] % 3;
            let Ok(nonce_bytes) = <[u8; 8]>::try_from(&chunk[1..9]) else {
                continue;
            };
            let Ok(gas_price_bytes) = <[u8; 8]>::try_from(&chunk[9..17]) else {
                continue;
            };
            let nonce = u64::from_le_bytes(nonce_bytes);
            let gas_price = u64::from_le_bytes(gas_price_bytes);
            let sender_byte = chunk[17];

            match action {
                0 => {
                    // add_transaction
                    let mut sender_bytes = [0u8; 32];
                    sender_bytes[0] = sender_byte.wrapping_add(1); // Ensure non-zero
                    sender_bytes[1] = 0x01; // Ensure non-zero sender
                    sender_bytes[31] = 0x01; // Native (non-EVM-shaped) sender
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
                        // A plain transfer. Admission now only takes payloads
                        // the executor can parse, and an empty-data tx with
                        // no recipient is not one (it is neither a transfer
                        // nor a deployment), so `to: None` was always rejected.
                        to: Some(PublicKey::new([0x02; 32])),
                        value: 0,
                        gas_limit: 21000,
                        gas_price,
                        data: vec![],
                        signature: Signature::new([0xAA; 64]),
                        tx_type: None,
                        chain_id: Some(40204),
                        ..Default::default()
                    };

                    if mempool
                        .add_transaction(tx.clone(), TxClass::Standard)
                        .await
                        .is_ok()
                    {
                        assert!(
                            mempool.get_transaction(&hash).await.is_some(),
                            "admitted transaction {hash:?} is not retrievable"
                        );
                        // Invariant: an exact re-add is rejected as a duplicate.
                        let again = mempool.add_transaction(tx, TxClass::Standard).await;
                        assert!(
                            matches!(again, Err(MempoolError::DuplicateTransaction(_))),
                            "re-adding admitted transaction {hash:?} was not rejected as a duplicate: {again:?}"
                        );
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
                        if let Some(removed) = mempool.remove_transaction(&h).await {
                            assert!(
                                mempool.get_transaction(&h).await.is_none(),
                                "removed transaction {h:?} is still retrievable"
                            );
                            // Invariant: a removed transaction cannot be re-added.
                            let again =
                                mempool.add_transaction(removed, TxClass::Standard).await;
                            assert!(
                                again.is_err(),
                                "removed transaction {h:?} was re-admitted"
                            );
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        // Invariant: mempool size never exceeds max_size
        let stats = mempool.stats().await;
        assert!(
            stats.total_transactions <= MAX_SIZE,
            "Mempool exceeded max_size: {} > {MAX_SIZE}",
            stats.total_transactions
        );

        // Invariant: no duplicate hashes remain, the listing matches stats,
        // and no sender exceeds max_per_sender.
        let txs = mempool.get_transactions(usize::MAX).await;
        assert_eq!(
            txs.len(),
            stats.total_transactions,
            "stats().total_transactions disagrees with get_transactions()"
        );
        let mut seen = std::collections::HashSet::new();
        let mut per_sender: std::collections::HashMap<PublicKey, usize> =
            std::collections::HashMap::new();
        for tx in &txs {
            assert!(
                seen.insert(tx.hash),
                "Duplicate transaction in mempool: {:?}",
                tx.hash
            );
            let n = per_sender.entry(tx.from).or_insert(0);
            *n += 1;
            assert!(
                *n <= MAX_PER_SENDER,
                "sender {:?} holds more than max_per_sender ({MAX_PER_SENDER}) transactions",
                tx.from
            );
        }
    });
});
