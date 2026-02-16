// Persistence and recovery integration test
//
// Validates that:
// 1. State persists across executor sessions
// 2. Blocks stored to disk survive restart
// 3. Transaction state (balances, nonces) is recoverable

use citrate_consensus::types::*;
use citrate_consensus::GhostDagParams;
use citrate_execution::Executor;
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::sync::Arc;
use tempfile::TempDir;

fn create_test_block(num: u8, height: u64) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = num;
    hash_bytes[1] = (height & 0xFF) as u8;

    Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::new(hash_bytes),
            selected_parent_hash: Hash::default(),
            merge_parent_hashes: vec![],
            timestamp: 1000000 + height * 10,
            height,
            blue_score: height * 10,
            blue_work: (height as u128) * 1000,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([0u8; 32]),
            vrf_reveal: VrfProof {
                proof: vec![0u8; 80],
                output: Hash::default(),
            },
        },
        state_root: Hash::default(),
        tx_root: Hash::default(),
        receipt_root: Hash::default(),
        artifact_root: Hash::default(),
        ghostdag_params: GhostDagParams::default(),
        transactions: vec![],
        signature: Signature::new([0u8; 64]),
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    #[tokio::test]
    async fn test_executor_state_survives_restart() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let addr = citrate_execution::types::Address([1u8; 20]);
        let balance = primitive_types::U256::from(5_000_000);

        // Session 1: create state
        {
            let executor = Executor::new(&path).unwrap();
            executor.set_balance(&addr, balance);
            executor.set_nonce(&addr, 42);
            executor.state_db().commit();
        }

        // Session 2: verify state persisted
        {
            let executor = Executor::new(&path).unwrap();
            assert_eq!(
                executor.get_balance(&addr),
                balance,
                "Balance should persist across restart"
            );
            assert_eq!(
                executor.get_nonce(&addr),
                42,
                "Nonce should persist across restart"
            );
        }
    }

    #[tokio::test]
    async fn test_block_storage_survives_restart() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let blocks: Vec<Block> = (0..10).map(|i| create_test_block(i as u8, i)).collect();

        // Session 1: store blocks
        {
            let config = PruningConfig::default();
            let storage = StorageManager::new(&path, config).unwrap();
            for block in &blocks {
                storage.blocks.put_block(block).unwrap();
            }
        }

        // Session 2: verify blocks persisted
        {
            let config = PruningConfig::default();
            let storage = StorageManager::new(&path, config).unwrap();
            for block in &blocks {
                let retrieved = storage
                    .blocks
                    .get_block(&block.header.block_hash)
                    .unwrap();
                assert!(
                    retrieved.is_some(),
                    "Block at height {} should persist",
                    block.header.height
                );
                let retrieved = retrieved.unwrap();
                assert_eq!(
                    retrieved.header.height, block.header.height,
                    "Block height should match"
                );
            }

            let latest = storage.blocks.get_latest_height().unwrap();
            assert_eq!(latest, 9, "Latest height should be 9 after storing 10 blocks");
        }
    }

    #[tokio::test]
    async fn test_multiple_accounts_persist() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let accounts: Vec<(citrate_execution::types::Address, primitive_types::U256, u64)> = vec![
            (
                citrate_execution::types::Address([0x11; 20]),
                primitive_types::U256::from(100_000),
                1,
            ),
            (
                citrate_execution::types::Address([0x22; 20]),
                primitive_types::U256::from(200_000),
                5,
            ),
            (
                citrate_execution::types::Address([0x33; 20]),
                primitive_types::U256::from(300_000),
                10,
            ),
        ];

        // Session 1: set up accounts
        {
            let executor = Executor::new(&path).unwrap();
            for (addr, balance, nonce) in &accounts {
                executor.set_balance(addr, *balance);
                executor.set_nonce(addr, *nonce);
            }
            executor.state_db().commit();
        }

        // Session 2: verify all accounts
        {
            let executor = Executor::new(&path).unwrap();
            for (addr, expected_balance, expected_nonce) in &accounts {
                assert_eq!(
                    executor.get_balance(addr),
                    *expected_balance,
                    "Balance mismatch for account {:?}",
                    addr
                );
                assert_eq!(
                    executor.get_nonce(addr),
                    *expected_nonce,
                    "Nonce mismatch for account {:?}",
                    addr
                );
            }
        }
    }

    #[tokio::test]
    async fn test_state_modification_across_sessions() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        let addr = citrate_execution::types::Address([0xAA; 20]);

        // Session 1: initial state
        {
            let executor = Executor::new(&path).unwrap();
            executor.set_balance(&addr, primitive_types::U256::from(1000));
            executor.set_nonce(&addr, 0);
            executor.state_db().commit();
        }

        // Session 2: modify state
        {
            let executor = Executor::new(&path).unwrap();
            let current = executor.get_balance(&addr);
            assert_eq!(current, primitive_types::U256::from(1000));

            // Simulate spending
            executor.set_balance(&addr, primitive_types::U256::from(500));
            executor.set_nonce(&addr, 1);
            executor.state_db().commit();
        }

        // Session 3: verify modified state
        {
            let executor = Executor::new(&path).unwrap();
            assert_eq!(
                executor.get_balance(&addr),
                primitive_types::U256::from(500),
                "Modified balance should persist"
            );
            assert_eq!(
                executor.get_nonce(&addr),
                1,
                "Modified nonce should persist"
            );
        }
    }
}
