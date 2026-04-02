#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_consensus::types::{Block, BlockHeader, GhostDagParams, Hash, PublicKey, Signature, VrfProof};

/// Fuzz target for gossip block validation.
///
/// Constructs a Block from fuzz input and runs it through the gossip
/// protocol's validate_block logic (reimplemented here since the method
/// is private). This exercises all validation checks:
///   - Block size limit
///   - Height validation
///   - Timestamp bounds
///   - Blue score checks
///   - VRF proof presence
///   - Parent hash presence
///   - Hash integrity (verify_hash)
///   - TX root integrity
///   - Signature verification
///
/// Invariants:
///   - No panics on any input
///   - Invalid blocks are rejected gracefully
fuzz_target!(|data: &[u8]| {
    // Need enough bytes to populate block fields
    if data.len() < 96 {
        return;
    }

    // Parse fuzz bytes into block fields
    let mut offset = 0;

    let Ok(version_bytes) = <[u8; 4]>::try_from(&data[offset..offset + 4]) else {
        return;
    };
    let version = u32::from_le_bytes(version_bytes);
    offset += 4;

    let mut block_hash_bytes = [0u8; 32];
    block_hash_bytes.copy_from_slice(&data[offset..offset+32]);
    offset += 32;

    let mut parent_hash_bytes = [0u8; 32];
    parent_hash_bytes.copy_from_slice(&data[offset..offset+32]);
    offset += 32;

    let Ok(timestamp_bytes) = <[u8; 8]>::try_from(&data[offset..offset + 8]) else {
        return;
    };
    let timestamp = u64::from_le_bytes(timestamp_bytes);
    offset += 8;

    let Ok(height_bytes) = <[u8; 8]>::try_from(&data[offset..offset + 8]) else {
        return;
    };
    let height = u64::from_le_bytes(height_bytes);
    offset += 8;

    let Ok(blue_score_bytes) = <[u8; 8]>::try_from(&data[offset..offset + 8]) else {
        return;
    };
    let blue_score = u64::from_le_bytes(blue_score_bytes);
    offset += 8;

    // Remaining bytes used for VRF proof (variable length)
    let vrf_proof_bytes: Vec<u8> = if offset < data.len() {
        data[offset..].to_vec()
    } else {
        vec![]
    };

    let block = BlockBuilder::new()
        .version(version)
        .hash(Hash::new(block_hash_bytes))
        .parent(Hash::new(parent_hash_bytes))
        .timestamp(timestamp)
        .height(height)
        .blue_score(blue_score)
        .vrf_reveal(VrfProof {
            proof: vrf_proof_bytes,
            output: Hash::default(),
        })
        .build_unhashed();

    // Replicate gossip validation checks (the method is private on GossipProtocol,
    // so we exercise the same logic inline).

    let max_message_size: usize = 1024 * 1024; // 1MB

    // 1. BLOCK_OVERSIZED
    let size = bincode::serialize(&block).unwrap_or_default().len();
    if size > max_message_size {
        return; // Rejected: oversized
    }

    // 2. INVALID_HEIGHT
    if block.header.height == 0 && !block.is_genesis() {
        return; // Rejected
    }

    // 3. TIMESTAMP_FUTURE
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if block.header.timestamp > now + 900 {
        return; // Rejected
    }

    // 4. ZERO_BLUE_SCORE
    if block.header.blue_score == 0 && !block.is_genesis() {
        return; // Rejected
    }

    // 5. MISSING_VRF
    if !block.is_genesis() && block.header.vrf_reveal.proof.is_empty() {
        return; // Rejected
    }

    // 6. MISSING_PARENT
    if !block.is_genesis() && block.header.selected_parent_hash == Hash::default() {
        return; // Rejected
    }

    // 7. HASH_MISMATCH — verify_hash should not panic
    let _hash_ok = block.verify_hash();

    // 8. TX_ROOT_MISMATCH — exercise tx root computation
    {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        for tx in &block.transactions {
            hasher.update(tx.hash.as_bytes());
        }
        let _computed = hasher.finalize();
    }

    // 9. INVALID_SIGNATURE — exercise signature verification path (should not panic)
    if !block.is_genesis() {
        let _ = citrate_consensus::crypto::verify_block_signature(&block);
    }
});
