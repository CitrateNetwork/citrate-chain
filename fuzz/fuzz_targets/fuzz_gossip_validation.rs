#![no_main]
//! Fuzz target for gossip block validation.
//!
//! Constructs a Block from fuzz input and runs it through the gossip
//! protocol's real block admission path, `GossipProtocol::handle_new_block`,
//! which calls the private `validate_block`. (Earlier versions of this
//! harness re-implemented the checks inline because `validate_block` is
//! private; that only fuzzed a copy. `handle_new_block` is the public entry
//! every gossiped block takes, so the production checks are now exercised
//! directly.) The checks covered:
//!   - Block size limit
//!   - Height validation
//!   - Timestamp bounds
//!   - Blue score checks
//!   - VRF proof presence
//!   - Proposer public key admissibility
//!   - Parent hash presence
//!   - Hash integrity (verify_hash)
//!   - TX root integrity
//!   - Signature verification
//!   - Genesis identity (only a configured genesis is exempt)
//!
//! Invariants:
//!   - No panics on any input
//!   - Soundness: a block the gossip layer accepts satisfies every check
//!     listed above (evaluated by an independent reference predicate)
//!   - Completeness: a block that satisfies every check is accepted, so a
//!     check that rejects valid blocks is caught too
//!
//! Input layout:
//!   [0]        mode flags (see `MODE_*`), so the fuzzer can produce
//!              correctly hashed and signed blocks and reach the later checks
//!   [1..33]    proposer key seed (or the raw proposer key when not signing)
//!   [33..37]   version (u32 LE)
//!   [37..69]   block hash
//!   [69..101]  selected parent hash
//!   [101..109] timestamp (u64 LE)
//!   [109..117] height (u64 LE)
//!   [117..125] blue score (u64 LE)
//!   [125..]    VRF proof bytes (variable length)
use citrate_consensus::hardening::{PbaHardening, MAX_FUTURE_BLOCK_DRIFT_SECS};
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, VrfProof};
use citrate_network::{GossipConfig, GossipProtocol, PeerId, PeerManager, PeerManagerConfig};
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, OnceLock};

/// Sign the block hash with the key derived from the seed, and use that
/// key's public half as the proposer.
const MODE_SIGN: u8 = 1 << 0;
/// Replace the fuzzed block hash with the block's canonical hash.
const MODE_REHASH: u8 = 1 << 1;
/// Set `tx_root` to the canonical root of the (empty) transaction list.
const MODE_TX_ROOT: u8 = 1 << 2;
/// Configure the gossip layer's genesis hash as this block's hash.
const MODE_GENESIS_CFG: u8 = 1 << 3;
/// Run with the PBA hardening rules active from height 1.
const MODE_HARDENED: u8 = 1 << 4;

const HEADER_LEN: usize = 1 + 32 + 4 + 32 + 32 + 8 + 8 + 8;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|err| panic!("failed to build fuzz runtime: {err}"))
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn le_u64(bytes: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_le_bytes)
}

/// Independent statement of the gossip admission rule (WP-G.3 list plus the
/// proposer-key and genesis-identity rules), evaluated at wall-clock `now`.
fn spec_accepts(
    block: &Block,
    genesis_hash: Option<Hash>,
    max_message_size: usize,
    hardening: PbaHardening,
    now: u64,
) -> bool {
    let header = &block.header;
    let is_genesis = header.height == 0
        && header.selected_parent_hash == Hash::default()
        && header.merge_parent_hashes.is_empty()
        && match genesis_hash {
            Some(h) => header.block_hash == h && block.verify_hash(),
            None => true,
        };

    let size_ok = match bincode::serialize(block) {
        Ok(bytes) => bytes.len() <= max_message_size,
        Err(_) => false,
    };
    let height_ok = header.height != 0 || is_genesis;
    let timestamp_ok = header.timestamp <= now.saturating_add(MAX_FUTURE_BLOCK_DRIFT_SECS);
    let blue_score_ok = header.blue_score != 0 || is_genesis;
    let vrf_ok = is_genesis || !header.vrf_reveal.proof.is_empty();
    let proposer_ok = is_genesis || header.proposer_pubkey.is_admissible();
    let parent_ok = is_genesis || header.selected_parent_hash != Hash::default();
    let hash_ok = block.verify_hash_for(hardening);
    let tx_root_ok = block.tx_root
        == citrate_consensus::tx_auth::tx_root_for_height(
            hardening,
            header.height,
            &block.transactions,
        );
    let signature_ok =
        is_genesis || matches!(citrate_consensus::crypto::verify_block_signature(block), Ok(true));

    size_ok
        && height_ok
        && timestamp_ok
        && blue_score_ok
        && vrf_ok
        && proposer_ok
        && parent_ok
        && hash_ok
        && tx_root_ok
        && signature_ok
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_LEN {
        return;
    }

    let mode = data[0];
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[1..33]);
    let mut offset = 33;

    let Ok(version_bytes) = <[u8; 4]>::try_from(&data[offset..offset + 4]) else {
        return;
    };
    let version = u32::from_le_bytes(version_bytes);
    offset += 4;

    let mut block_hash_bytes = [0u8; 32];
    block_hash_bytes.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let mut parent_hash_bytes = [0u8; 32];
    parent_hash_bytes.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let Some(timestamp) = le_u64(&data[offset..offset + 8]) else {
        return;
    };
    offset += 8;

    let Some(height) = le_u64(&data[offset..offset + 8]) else {
        return;
    };
    offset += 8;

    let Some(blue_score) = le_u64(&data[offset..offset + 8]) else {
        return;
    };
    offset += 8;

    // Remaining bytes used for VRF proof (variable length)
    let vrf_proof_bytes: Vec<u8> = data[offset..].to_vec();

    let hardening = if mode & MODE_HARDENED != 0 {
        PbaHardening::at(1)
    } else {
        PbaHardening::off()
    };

    let signing_key = citrate_consensus::crypto::block_signing_key_from_seed(&seed);
    let proposer = if mode & MODE_SIGN != 0 {
        PublicKey::new(signing_key.verifying_key().to_bytes())
    } else {
        PublicKey::new(seed)
    };

    let mut block = BlockBuilder::new()
        .version(version)
        .hash(Hash::new(block_hash_bytes))
        .parent(Hash::new(parent_hash_bytes))
        .timestamp(timestamp)
        .height(height)
        .blue_score(blue_score)
        .proposer(proposer)
        .vrf_reveal(VrfProof {
            proof: vrf_proof_bytes,
            output: Hash::default(),
        })
        .build_unhashed();

    if mode & MODE_TX_ROOT != 0 {
        block.tx_root =
            citrate_consensus::tx_auth::tx_root_for_height(hardening, height, &block.transactions);
    }
    if mode & MODE_REHASH != 0 {
        block.header.block_hash = block.compute_hash_for(hardening);
    }
    if mode & MODE_SIGN != 0 {
        block.signature =
            citrate_consensus::crypto::sign_block(&block.header.block_hash, &signing_key);
    } else {
        block.signature = Signature::new([0; 64]);
    }

    let config = GossipConfig {
        genesis_hash: (mode & MODE_GENESIS_CFG != 0).then_some(block.header.block_hash),
        ..GossipConfig::default()
    };
    let genesis_hash = config.genesis_hash;
    let max_message_size = config.max_message_size;

    // A fresh protocol per input: its seen-cache would otherwise let a
    // repeated block skip validation.
    let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(config, peer_manager).with_pba_hardening(hardening);
    let from_peer = PeerId::new("fuzz-peer".to_string());

    let now_before = now_secs();
    let accepted = runtime()
        .block_on(gossip.handle_new_block(block.clone(), &from_peer))
        .is_ok();
    let now_after = now_secs();

    if accepted {
        assert!(
            spec_accepts(&block, genesis_hash, max_message_size, hardening, now_after),
            "gossip accepted a block that violates the admission rule: mode={mode:#04x} header={:?}",
            block.header
        );
    } else {
        assert!(
            !spec_accepts(&block, genesis_hash, max_message_size, hardening, now_before),
            "gossip rejected a block that satisfies the admission rule: mode={mode:#04x} header={:?}",
            block.header
        );
    }
});
