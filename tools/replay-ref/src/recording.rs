//! The recording: what a node holds, dumped once, replayable anywhere.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use citrate_consensus::types::{Block, Hash};
use serde::{Deserialize, Serialize};

/// File magic, then a little-endian `u32` format version, then the
/// deflate-compressed bincode of [`Recording`].
pub const MAGIC: &[u8; 8] = b"CITRPLAY";

/// Format version of [`Recording`]. 2: blocks carry `accepted_root`, the
/// config the GHOSTDAG K, and chain entries the node's accepted list (r1007
/// S3-3b). 3: the config carries the genesis contract code and the EVM
/// activation rules the node executed under (the mergeset reference runs
/// contract transactions, S3-3c).
pub const FORMAT_VERSION: u32 = 3;

/// One block of the node's applied selected chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    pub height: u64,
    pub hash: Hash,
    /// The state root the node committed for this block
    /// (`StateStore::get_state_root`, written when the node applied it), if
    /// it has one.
    pub committed_root: Option<Hash>,
    /// The node's accepted list for this chain block, from its receipt index
    /// (r1007 S3-3b): (tx hash, including block, status) in execution order.
    /// `None` when the node indexed no receipts under it (a pre-r1007 block,
    /// or genesis).
    pub accepted: Option<Vec<(Hash, Hash, bool)>>,
}

/// The VALIDATOR-S1 §R' reward policy the node settled with
/// (`citrate_execution::block_rewards::EpochRewardPolicy`), as data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedRewardPolicy {
    pub epoch: u64,
    pub snapshot_height: u64,
    pub activation_height: u64,
    pub registry: [u8; 20],
    pub reward_minter: [u8; 20],
    pub priority_fee_share_bps: u64,
    /// Big-endian U256.
    pub block_subsidy: [u8; 32],
    /// (proposer ed25519 key, staker address), sorted.
    pub staker_of: Vec<([u8; 32], [u8; 20])>,
}

impl RecordedRewardPolicy {
    pub fn from_policy(p: &citrate_execution::block_rewards::EpochRewardPolicy) -> Self {
        let mut subsidy = [0u8; 32];
        p.block_subsidy.to_big_endian(&mut subsidy);
        let mut staker_of: Vec<([u8; 32], [u8; 20])> =
            p.staker_of.iter().map(|(k, v)| (*k, *v)).collect();
        staker_of.sort();
        Self {
            epoch: p.epoch,
            snapshot_height: p.snapshot_height,
            activation_height: p.activation_height,
            registry: p.registry,
            reward_minter: p.reward_minter,
            priority_fee_share_bps: p.priority_fee_share_bps,
            block_subsidy: subsidy,
            staker_of,
        }
    }

    pub fn to_policy(&self) -> citrate_execution::block_rewards::EpochRewardPolicy {
        citrate_execution::block_rewards::EpochRewardPolicy {
            epoch: self.epoch,
            snapshot_height: self.snapshot_height,
            activation_height: self.activation_height,
            registry: self.registry,
            reward_minter: self.reward_minter,
            priority_fee_share_bps: self.priority_fee_share_bps,
            block_subsidy: primitive_types::U256::from_big_endian(&self.block_subsidy),
            staker_of: self.staker_of.iter().copied().collect::<HashMap<_, _>>(),
        }
    }
}

/// The execution parameters the node ran with. None of them is stored in the
/// data dir (they are the network profile's), so the recorder takes them from
/// its caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayConfig {
    pub chain_id: u64,
    /// `Executor::set_validator_activation_height`, if the node set one.
    pub validator_activation_height: Option<u64>,
    /// The fixed §R' policy the node settled with. A node that re-materializes
    /// the policy at epoch boundaries (`registry_sync`) is not replayable with
    /// a fixed policy past the first boundary; see the crate docs.
    pub reward_policy: Option<RecordedRewardPolicy>,
    /// PBA block-validity hardening activation (`citrate_consensus::hardening`).
    pub pba_hardening_height: Option<u64>,
    /// Supply hardening activation (`citrate_execution::supply_hardening`).
    pub supply_hardening_height: Option<u64>,
    /// Storage-root hardening activation
    /// (`citrate_execution::storage_root_hardening`). Process-wide in the
    /// executor: `replay` refuses to run when the process value differs.
    pub storage_root_hardening_height: Option<u64>,
    /// Genesis allocation: (address, big-endian U256 balance).
    pub genesis_alloc: Vec<([u8; 20], [u8; 32])>,
    /// GHOSTDAG K the node colored with (`GhostDagParams::k`).
    pub ghostdag_k: u32,
    /// Genesis contract code: (address, runtime bytecode). A data dir does
    /// not say which accounts genesis seeded with code, so the caller does.
    pub genesis_code: Vec<([u8; 20], Vec<u8>)>,
    /// The EVM activation rules the node executed contract transactions
    /// under.
    pub evm_rules: RecordedEvmRules,
}

/// The process-wide EVM activation heights of `citrate_execution` (each one
/// a network-profile value, not stored in a data dir).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedEvmRules {
    /// `executor::value_transfer_activation_height`: from here REVM's balance
    /// changes are authoritative (internal value transfers land).
    pub value_transfer_height: u64,
    /// `executor::create_nonce_fix_activation_height`: from here contract
    /// account nonces REVM computes are persisted (EIP-161).
    pub create_nonce_fix_height: u64,
    /// `exact_code::exact_create_code_height`: from here code created inside
    /// a call is stored as its original bytes, not REVM's padded analysis.
    pub exact_create_code_height: Option<u64>,
}

impl RecordedEvmRules {
    /// The rules of this process.
    pub fn from_process() -> Self {
        Self {
            value_transfer_height: citrate_execution::executor::value_transfer_activation_height(),
            create_nonce_fix_height:
                citrate_execution::executor::create_nonce_fix_activation_height(),
            exact_create_code_height: citrate_execution::exact_code::exact_create_code_height(),
        }
    }
}

impl ReplayConfig {
    /// A config with the process-wide hardening heights of this process.
    pub fn from_process(chain_id: u64) -> Self {
        Self {
            chain_id,
            validator_activation_height: None,
            reward_policy: None,
            pba_hardening_height: citrate_consensus::hardening::pba_hardening_height(),
            supply_hardening_height: citrate_execution::supply_hardening::supply_hardening_height(),
            storage_root_hardening_height:
                citrate_execution::storage_root_hardening::storage_root_hardening_height(),
            genesis_alloc: Vec::new(),
            ghostdag_k: citrate_consensus::ghostdag::GHOSTDAG_K,
            genesis_code: Vec::new(),
            evm_rules: RecordedEvmRules::from_process(),
        }
    }
}

/// A node's DAG and applied chain, as recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recording {
    /// Where it was recorded from (a data dir path or a label).
    pub source: String,
    pub config: ReplayConfig,
    /// The node's durable applied tip.
    pub applied_tip: (Hash, u64),
    /// The applied selected chain, genesis (height 0) first. A chain that does
    /// not reach height 0 (a pruned block store) starts higher.
    pub chain: Vec<ChainEntry>,
    /// Every block the node stores (the whole DAG, chain and off-chain),
    /// ordered by (height, hash).
    pub blocks: Vec<Block>,
}

impl Recording {
    /// The recorded blocks by hash.
    pub fn index(&self) -> HashMap<Hash, &Block> {
        self.blocks
            .iter()
            .map(|b| (b.header.block_hash, b))
            .collect()
    }

    /// The recorded block on the chain at `height`, if recorded.
    pub fn chain_block_mut(&mut self, height: u64) -> Option<&mut Block> {
        let hash = self.chain.iter().find(|e| e.height == height)?.hash;
        self.blocks.iter_mut().find(|b| b.header.block_hash == hash)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let body = bincode::serialize(self).context("encode recording")?;
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&body)?;
        let packed = enc.finish()?;
        let mut out = Vec::with_capacity(packed.len() + 12);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&packed);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let Some(rest) = bytes.strip_prefix(MAGIC.as_slice()) else {
            bail!("not a replay recording (bad magic)");
        };
        let (version, packed) = rest.split_at_checked(4).context("truncated header")?;
        let version = u32::from_le_bytes(version.try_into().context("version")?);
        if version != FORMAT_VERSION {
            bail!("recording format {version}, this tool reads {FORMAT_VERSION}");
        }
        let mut body = Vec::new();
        flate2::read::DeflateDecoder::new(packed)
            .read_to_end(&mut body)
            .context("decompress recording")?;
        bincode::deserialize(&body).context("decode recording")
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_bytes()?).with_context(|| format!("write {}", path.display()))
    }

    pub fn read_from(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(&bytes)
    }
}
