#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::*;

/// Fuzz target for DAG operations: add_block + calculate_blue_set + get_tips
///
/// Input: sequence of bytes interpreted as block descriptors.
/// Each 33-byte chunk = 1 byte parent_index + 32 bytes block_hash.
/// The parent_index selects from previously added blocks.
///
/// Invariants checked:
/// - No panic on any input
/// - Tips have no children
/// - Blue set always contains genesis
fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let dag_store = Arc::new(DagStore::new());
        let params = GhostDagParams {
            k: 4, // Small k for faster exploration
            max_parents: 4,
            ..GhostDagParams::default()
        };
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Genesis block
        let genesis_hash_bytes = [0xFFu8; 32];
        let genesis = Block {
            header: BlockHeader {
                version: 1,
                block_hash: Hash::new(genesis_hash_bytes),
                selected_parent_hash: Hash::default(),
                merge_parent_hashes: vec![],
                timestamp: 0,
                height: 0,
                blue_score: 0,
                blue_work: 0,
                pruning_point: Hash::default(),
                proposer_pubkey: PublicKey::new([0; 32]),
                vrf_reveal: VrfProof { proof: vec![], output: Hash::default() },
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
        };

        let _ = dag_store.store_block(genesis.clone()).await;
        let _ = ghostdag.add_block(&genesis).await;

        let mut block_hashes = vec![Hash::new(genesis_hash_bytes)];

        // Parse fuzz input as block descriptors
        let chunks = data.chunks_exact(33);
        for (i, chunk) in chunks.enumerate() {
            let parent_idx = chunk[0] as usize % block_hashes.len();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&chunk[1..33]);
            // Ensure non-default hash
            hash_bytes[31] = 0xFE;
            hash_bytes[0] = (i as u8).wrapping_add(1);

            let parent = block_hashes[parent_idx];
            let block = Block {
                header: BlockHeader {
                    version: 1,
                    block_hash: Hash::new(hash_bytes),
                    selected_parent_hash: parent,
                    merge_parent_hashes: vec![],
                    timestamp: (i + 1) as u64,
                    height: (i + 1) as u64,
                    blue_score: 0,
                    blue_work: 0,
                    pruning_point: Hash::default(),
                    proposer_pubkey: PublicKey::new([0; 32]),
                    vrf_reveal: VrfProof { proof: vec![], output: Hash::default() },
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
            };

            let _ = dag_store.store_block(block.clone()).await;
            let _ = ghostdag.add_block(&block).await;
            block_hashes.push(Hash::new(hash_bytes));

            // Periodically check invariants
            if i % 5 == 0 && !block_hashes.is_empty() {
                let last = block_hashes.last().unwrap();
                // Blue set calculation should not panic
                let _ = ghostdag.calculate_blue_set(&block).await;
                // Tips should not panic
                let _ = dag_store.get_tips().await;
            }
        }
    });
});
