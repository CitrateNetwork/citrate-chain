//! `--mode mergeset` (r1007 S3-3b/S3-3c): a recording replayed through the
//! INDEPENDENT reference (`citrate-mergeset-ref`), which recomputes GHOSTDAG,
//! the ordered mergesets, every outcome, settlement and the four commitments
//! from block data alone, and compares them block by block with each chain
//! block's header (state_root, receipt_root, accepted_root, gas_used) and with
//! the node's accepted list recorded from its receipt index.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use citrate_consensus::types::Hash;
use citrate_mergeset_ref::{EvmRules, RefConfig, RefPolicy, Report};
use primitive_types::U256;

use crate::recording::Recording;

/// The reference config a recording describes.
pub fn reference_config(rec: &Recording) -> RefConfig {
    let cfg = &rec.config;
    RefConfig {
        chain_id: cfg.chain_id,
        k: cfg.ghostdag_k,
        genesis_alloc: cfg
            .genesis_alloc
            .iter()
            .map(|(a, b)| (*a, U256::from_big_endian(b)))
            .collect(),
        reward_policy: cfg.reward_policy.as_ref().map(|p| RefPolicy {
            activation_height: p.activation_height,
            registry: p.registry,
            priority_fee_share_bps: p.priority_fee_share_bps,
            block_subsidy: U256::from_big_endian(&p.block_subsidy),
            reward_minter: p.reward_minter,
            staker_of: p.staker_of.iter().copied().collect(),
        }),
        pba_hardening_height: cfg.pba_hardening_height,
        supply_hardening_height: cfg.supply_hardening_height,
        storage_root_hardening_height: cfg.storage_root_hardening_height,
        genesis_code: cfg.genesis_code.clone(),
        evm: EvmRules {
            value_transfer_height: cfg.evm_rules.value_transfer_height,
            create_nonce_fix_height: cfg.evm_rules.create_nonce_fix_height,
            exact_create_code_height: cfg.evm_rules.exact_create_code_height,
        },
    }
}

/// Replay `rec` through the independent reference.
pub fn replay_mergeset(rec: &Recording) -> Result<Report> {
    let cfg = reference_config(rec);
    let chain: Vec<Hash> = rec.chain.iter().map(|e| e.hash).collect();
    let lists: HashMap<Hash, Vec<(Hash, Hash, bool)>> = rec
        .chain
        .iter()
        .filter_map(|e| e.accepted.clone().map(|l| (e.hash, l)))
        .collect();
    let lookup = |h: &Hash| lists.get(h).cloned();
    citrate_mergeset_ref::replay(&cfg, &rec.blocks, &chain, Some(&lookup)).map_err(|e| anyhow!(e))
}
