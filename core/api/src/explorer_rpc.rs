// citrate/core/api/src/explorer_rpc.rs
//
// S3-7 (CNV-RPC, planset 02 §3, spec 06 §5): the read-only DAG and chain
// methods the explorer needs. Each method names its data source on its
// function. None of them writes anything or changes consensus or execution;
// a value the node does not hold is returned as `null` with the reason, never
// estimated.
//
//   citrate_getBlocksAtHeight      every stored block at a DAG height
//   citrate_getGhostdagData        the persisted GHOSTDAG record of a block
//   citrate_getSelectedChainChanges selected-chain blocks removed/added since a hash
//   citrate_getAcceptingBlock      which chain block executed a transaction
//   citrate_getFinalityStatus      checkpoint finality as this node holds it
//   eth_getBlockReceipts           every receipt of a block, in one call
//
// "Applied chain" below means the node's executed selected chain: the blocks
// reached by `selected_parent_hash` from the applied tip, served by the
// canonical height index (`BlockStore::get_canonical_block_by_height`).

use crate::finalized_tag::FinalizedTagSource;
use crate::metrics::rpc_request;
use citrate_consensus::types::{Block, BlockHeader, GhostdagData, Hash};
use citrate_execution::types::TransactionReceipt;
use citrate_storage::db::column_families::{CF_DAG_GHOSTDAG, CF_DAG_METADATA};
use citrate_storage::StorageManager;
use jsonrpc_core::{IoHandler, Params};
use serde_json::{json, Value};
use std::sync::Arc;

/// Most chain blocks `citrate_getSelectedChainChanges` adds in one answer.
pub const MAX_CHAIN_CHANGES: u64 = 1_000;

/// Default `limit` of `citrate_getSelectedChainChanges`.
pub const DEFAULT_CHAIN_CHANGES: u64 = 100;

/// Deepest walk from `fromHash` down to the applied chain: the reorg window
/// (`canonical_apply::MAX_REORG_DEPTH` = undo window = 10,000, spec 06 §4.2).
/// A client further off than that has to resync from a chain block.
pub const MAX_CHAIN_CHANGES_WALK: u64 = 10_000;

/// How many chain blocks above a block `citrate_getGhostdagData` searches for
/// the chain block whose mergeset holds it (its colour). A block is merged
/// within the merge depth of its height or never (G5); this bounds the work
/// per request.
pub const MAX_COLOR_SEARCH: u64 = 1_024;

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

fn qty(n: u64) -> String {
    format!("0x{n:x}")
}

fn internal(e: impl std::fmt::Display) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: e.to_string(),
        data: None,
    }
}

fn bad(msg: impl Into<String>) -> jsonrpc_core::Error {
    jsonrpc_core::Error::invalid_params(msg.into())
}

fn params_vec(params: Params) -> Result<Vec<Value>, jsonrpc_core::Error> {
    match params {
        Params::None => Ok(Vec::new()),
        p => p.parse::<Vec<Value>>().map_err(|e| bad(e.to_string())),
    }
}

/// A 32-byte hash parameter.
pub fn parse_hash_param(v: Option<&Value>, what: &str) -> Result<Hash, jsonrpc_core::Error> {
    let s = v
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad(format!("{what} must be a 0x-prefixed 32-byte hex string")))?;
    let h = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(h).map_err(|_| bad(format!("{what} is not hex")))?;
    if bytes.len() != 32 {
        return Err(bad(format!("{what} must be 32 bytes")));
    }
    Hash::try_from_bytes(&bytes).ok_or_else(|| bad(format!("{what} must be 32 bytes")))
}

/// A quantity parameter: a `0x` hex string or a JSON number.
fn parse_u64_param(v: Option<&Value>, what: &str) -> Result<u64, jsonrpc_core::Error> {
    match v {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| bad(format!("{what} must be a non-negative integer"))),
        Some(Value::String(s)) => {
            let h = s
                .strip_prefix("0x")
                .ok_or_else(|| bad(format!("{what} must be 0x-prefixed hex")))?;
            u64::from_str_radix(h, 16).map_err(|_| bad(format!("{what} is not a hex quantity")))
        }
        _ => Err(bad(format!("{what} is required"))),
    }
}

/// The applied (executed) tip. Source: `BlockStore::get_applied_tip`
/// (`CF_METADATA applied_tip`), via `canonical_logs::log_tip`.
fn applied_tip(storage: &StorageManager) -> Result<Option<(Hash, u64)>, jsonrpc_core::Error> {
    crate::canonical_logs::log_tip(storage).map_err(internal)
}

/// Whether `hash` at `height` is on the applied chain. Source: the canonical
/// height index (`CF_METADATA canonical_h:`), only at or below the applied
/// tip (above it there is no executed chain yet).
fn on_applied_chain(
    storage: &StorageManager,
    hash: &Hash,
    height: u64,
    tip: Option<(Hash, u64)>,
) -> Result<bool, jsonrpc_core::Error> {
    let Some((_, tip_height)) = tip else {
        return Ok(false);
    };
    if height > tip_height {
        return Ok(false);
    }
    Ok(storage
        .blocks
        .get_canonical_block_by_height(height)
        .map_err(internal)?
        == Some(*hash))
}

/// The persisted GhostdagData record of `hash` (`CF_DAG_GHOSTDAG`, written by
/// the consensus `DagStore::put_ghostdag_data`, decoded and tag-checked by
/// `dag_store::decode_ghostdag_record`). `None`: absent (the DAG store pruned
/// it, or it was never persisted) or not bound to this hash.
pub fn ghostdag_record(
    storage: &StorageManager,
    hash: &Hash,
) -> Result<Option<GhostdagData>, jsonrpc_core::Error> {
    let raw = storage
        .db
        .get_cf(CF_DAG_GHOSTDAG, hash.as_bytes())
        .map_err(internal)?;
    Ok(raw.and_then(|r| citrate_consensus::dag_store::decode_ghostdag_record(hash, &r)))
}

// ── citrate_getBlocksAtHeight ────────────────────────────────────────────

/// `citrate_getBlocksAtHeight(height)`: every stored block at DAG height
/// `height`, siblings included, ascending by hash.
///
/// Data sources: the sibling height index (`BlockStore::get_blocks_at_height`,
/// `CF_METADATA hsib:`), the stored headers (`CF_HEADERS`), the canonical
/// height index (`isSelectedChain`) and `CF_DAG_GHOSTDAG` (`hasGhostdagRecord`).
pub fn blocks_at_height_json(
    storage: &StorageManager,
    height: u64,
) -> Result<Value, jsonrpc_core::Error> {
    let tip = applied_tip(storage)?;
    let hashes = storage
        .blocks
        .get_blocks_at_height(height)
        .map_err(internal)?;
    let mut out = Vec::with_capacity(hashes.len());
    for hash in hashes {
        let Some(header) = storage.blocks.get_header(&hash).map_err(internal)? else {
            continue;
        };
        let tx_count = storage
            .blocks
            .get_block(&hash)
            .map_err(internal)?
            .map(|b| b.transactions.len());
        out.push(json!({
            "hash": hx(&hash),
            "height": qty(header.height),
            "selectedParent": hx(&header.selected_parent_hash),
            "mergeParents": header.merge_parent_hashes.iter().map(hx).collect::<Vec<_>>(),
            "blueScore": qty(header.blue_score),
            "blueWork": format!("0x{:x}", header.blue_work),
            "timestamp": qty(header.timestamp),
            "transactionCount": tx_count,
            "isSelectedChain": on_applied_chain(storage, &hash, header.height, tip)?,
            "hasGhostdagRecord": ghostdag_record(storage, &hash)?.is_some(),
        }));
    }
    Ok(json!({ "height": qty(height), "blocks": out }))
}

// ── citrate_getGhostdagData ──────────────────────────────────────────────

/// The colour of a block relative to the applied chain: the chain block whose
/// mergeset holds it, found by searching the chain blocks above it.
fn colour_of(
    storage: &StorageManager,
    hash: &Hash,
    header: &BlockHeader,
    tip: Option<(Hash, u64)>,
) -> Result<Value, jsonrpc_core::Error> {
    let Some((_, tip_height)) = tip else {
        return Ok(
            json!({ "color": Value::Null, "mergingChainBlock": Value::Null,
            "blueAnticoneSize": Value::Null, "reason": "no block has executed on this node" }),
        );
    };
    let on_chain = on_applied_chain(storage, hash, header.height, tip)?;
    let start = header.height.saturating_add(1);
    let end = header
        .height
        .saturating_add(MAX_COLOR_SEARCH)
        .min(tip_height);
    let mut h = start;
    while h <= end {
        let Some(chain) = storage
            .blocks
            .get_canonical_block_by_height(h)
            .map_err(internal)?
        else {
            break;
        };
        let Some(record) = ghostdag_record(storage, &chain)? else {
            return Ok(
                json!({ "color": if on_chain { json!("blue") } else { Value::Null },
                "mergingChainBlock": Value::Null, "blueAnticoneSize": Value::Null,
                "reason": format!("the GHOSTDAG record of chain block {} is not held (pruned)", hx(&chain)) }),
            );
        };
        let size = record.blues_anticone_sizes.get(hash).copied();
        if record.mergeset_blues.contains(hash) || record.selected_parent == *hash {
            return Ok(json!({ "color": "blue", "mergingChainBlock": hx(&chain),
                "blueAnticoneSize": size, "reason": Value::Null }));
        }
        if record.mergeset_reds.contains(hash) {
            return Ok(json!({ "color": "red", "mergingChainBlock": hx(&chain),
                "blueAnticoneSize": Value::Null, "reason": Value::Null }));
        }
        h = h.saturating_add(1);
    }
    let reason = if end < header.height.saturating_add(MAX_COLOR_SEARCH) {
        "not merged by the applied chain yet"
    } else {
        "not merged within the colour search depth"
    };
    Ok(
        json!({ "color": if on_chain { json!("blue") } else { Value::Null },
        "mergingChainBlock": Value::Null, "blueAnticoneSize": Value::Null, "reason": reason }),
    )
}

/// `citrate_getGhostdagData(hash)`: the persisted GHOSTDAG record of a block
/// and its colour relative to the applied chain. `null` for a block this node
/// does not store.
///
/// Data sources: `CF_DAG_GHOSTDAG[hash]` (the record the consensus engine
/// persisted at admission, spec G12), `CF_HEADERS` (the committed header
/// fields), and for the colour the records of the applied chain blocks above
/// it (canonical height index). A pruned record gives `recordAvailable: false`
/// and `null` record fields; the committed header fields stay available.
pub fn ghostdag_data_json(
    storage: &StorageManager,
    hash: &Hash,
) -> Result<Value, jsonrpc_core::Error> {
    let Some(header) = storage.blocks.get_header(hash).map_err(internal)? else {
        return Ok(Value::Null);
    };
    let tip = applied_tip(storage)?;
    let record = ghostdag_record(storage, hash)?;
    let colour = colour_of(storage, hash, &header, tip)?;
    let rec = record.as_ref();
    Ok(json!({
        "hash": hx(hash),
        "height": qty(header.height),
        "recordAvailable": rec.is_some(),
        "selectedParent": rec.map(|r| hx(&r.selected_parent)),
        "blueScore": rec.map(|r| qty(r.blue_score)),
        "blueWork": rec.map(|r| format!("0x{:x}", r.blue_work)),
        "mergesetBlues": rec.map(|r| r.mergeset_blues.iter().map(hx).collect::<Vec<_>>()),
        "mergesetReds": rec.map(|r| r.mergeset_reds.iter().map(hx).collect::<Vec<_>>()),
        "bluesAnticoneSizes": rec.map(|r| r.blues_anticone_sizes.iter()
            .map(|(h, n)| (hx(h), json!(n))).collect::<serde_json::Map<_, _>>()),
        "mergeDepthRoot": rec.map(|r| hx(&r.merge_depth_root)),
        // Committed in the header (spec G7): available even when pruned.
        "header": {
            "selectedParent": hx(&header.selected_parent_hash),
            "blueScore": qty(header.blue_score),
            "blueWork": format!("0x{:x}", header.blue_work),
        },
        "isSelectedChain": on_applied_chain(storage, hash, header.height, tip)?,
        "color": colour.get("color").cloned().unwrap_or(Value::Null),
        "mergingChainBlock": colour.get("mergingChainBlock").cloned().unwrap_or(Value::Null),
        "blueAnticoneSize": colour.get("blueAnticoneSize").cloned().unwrap_or(Value::Null),
        "colorReason": colour.get("reason").cloned().unwrap_or(Value::Null),
    }))
}

// ── citrate_getSelectedChainChanges ──────────────────────────────────────

/// `citrate_getSelectedChainChanges(fromHash, limit)`: what changed on the
/// applied chain since a client last saw `fromHash` as a chain block.
///
/// - `removedChainBlockHashes`: the blocks of `fromHash`'s selected-parent
///   chain that are no longer on the applied chain, from `fromHash` down
///   (highest first). Empty when `fromHash` is still on it.
/// - `addedChainBlocks`: applied chain blocks above the common ancestor,
///   ascending, at most `limit` (`more: true` if there are more).
/// - `addedChainBlockHashes`: the same blocks as bare hashes, same order
///   (Kaspa's field name; the explorer's chain-change feed reads it).
///
/// Data sources: `CF_HEADERS` (the selected-parent walk), the canonical height
/// index and the applied tip. The walk from `fromHash` is bounded by
/// [`MAX_CHAIN_CHANGES_WALK`].
pub fn selected_chain_changes_json(
    storage: &StorageManager,
    from: &Hash,
    limit: u64,
) -> Result<Value, jsonrpc_core::Error> {
    let limit = limit.clamp(1, MAX_CHAIN_CHANGES);
    let tip = applied_tip(storage)?.ok_or_else(|| jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::ServerError(-32000),
        message: "no block has executed on this node yet".into(),
        data: None,
    })?;
    let Some(mut header) = storage.blocks.get_header(from).map_err(internal)? else {
        return Err(bad(format!("block {} is not known to this node", hx(from))));
    };
    let mut cursor = *from;
    let mut removed: Vec<String> = Vec::new();
    let mut steps: u64 = 0;
    loop {
        if on_applied_chain(storage, &cursor, header.height, Some(tip))? {
            break;
        }
        if steps >= MAX_CHAIN_CHANGES_WALK || header.height == 0 {
            return Err(jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::ServerError(-32000),
                message: format!(
                    "{} does not reach the applied chain within {} blocks; resync from a \
                     selected-chain block",
                    hx(from),
                    MAX_CHAIN_CHANGES_WALK
                ),
                data: None,
            });
        }
        removed.push(hx(&cursor));
        cursor = header.selected_parent_hash;
        header = storage
            .blocks
            .get_header(&cursor)
            .map_err(internal)?
            .ok_or_else(|| {
                internal(format!(
                    "selected parent {} of a removed block is not stored",
                    hx(&cursor)
                ))
            })?;
        steps = steps.saturating_add(1);
    }
    let common = (cursor, header.height);
    let mut added = Vec::new();
    let mut added_hashes = Vec::new();
    let mut h = common.1.saturating_add(1);
    let last = common.1.saturating_add(limit).min(tip.1);
    while h <= last {
        match storage
            .blocks
            .get_canonical_block_by_height(h)
            .map_err(internal)?
        {
            Some(hash) => {
                added.push(json!({ "hash": hx(&hash), "height": qty(h) }));
                added_hashes.push(hx(&hash));
            }
            None => break,
        }
        h = h.saturating_add(1);
    }
    Ok(json!({
        "removedChainBlockHashes": removed,
        "commonAncestor": { "hash": hx(&common.0), "height": qty(common.1) },
        "addedChainBlocks": added,
        "addedChainBlockHashes": added_hashes,
        "more": last < tip.1,
        "appliedTip": { "hash": hx(&tip.0), "height": qty(tip.1) },
    }))
}

// ── citrate_getAcceptingBlock ────────────────────────────────────────────

/// `citrate_getAcceptingBlock(txHash)` (spec 06 §5.4).
///
/// SEMANTICS ON THIS BASE (before S3-3b mergeset execution): a chain block
/// executes its own transactions, so the accepting block is the including
/// block, and only when that block is on the applied chain. The answer says
/// so in `semantics: "including-chain-block"`. When S3-3b lands, a block's
/// transactions are executed by the next chain block (its child on the
/// selected chain) and this method switches to `semantics: "accepting"`,
/// reading `CF_TX_INCLUSIONS` for the `inclusions` list (every DAG block that
/// carries the tx, with colour and outcome). That index does not exist here,
/// so `inclusions` holds only the block named by the receipt and
/// `inclusionsComplete` is `false`.
///
/// Inclusion `color` / `outcome` use the spec 06 §5.4 vocabulary. On this
/// base the including block is itself a selected-chain block when it executed
/// the tx: `color: "selected_parent"` (a chain block, as the explorer renders
/// it), `outcome: "executed"`. A receipt whose block left the applied chain
/// (a reorg) is `color: "unaccepted"`, `outcome: "pending"`: no chain block
/// has executed the tx.
///
/// Data sources: the receipt store (`CF_RECEIPTS[tx_hash]`: block hash and
/// number), the canonical height index (is that block on the applied chain),
/// `CF_HEADERS` (its DAG height) and `CF_TRANSACTIONS` (`knownTransaction`).
pub fn accepting_block_json(
    storage: &StorageManager,
    tx: &Hash,
) -> Result<Value, jsonrpc_core::Error> {
    let tip = applied_tip(storage)?;
    let receipt = storage.transactions.get_receipt(tx).map_err(internal)?;
    let known = storage.transactions.has_transaction(tx).map_err(internal)?;
    let Some(r) = receipt else {
        return Ok(json!({
            "transactionHash": hx(tx),
            "acceptingBlockHash": Value::Null,
            "acceptingHeight": Value::Null,
            "inclusions": [],
            "inclusionsComplete": false,
            "knownTransaction": known,
            "semantics": "including-chain-block",
        }));
    };
    let accepted = on_applied_chain(storage, &r.block_hash, r.block_number, tip)?;
    let dag_height = storage
        .blocks
        .get_header(&r.block_hash)
        .map_err(internal)?
        .map(|h| qty(h.height));
    Ok(json!({
        "transactionHash": hx(tx),
        "acceptingBlockHash": if accepted { json!(hx(&r.block_hash)) } else { Value::Null },
        "acceptingHeight": if accepted { json!(qty(r.block_number)) } else { Value::Null },
        "inclusions": [{
            "blockHash": hx(&r.block_hash),
            "dagHeight": dag_height,
            "isSelectedChain": accepted,
            "color": if accepted { "selected_parent" } else { "unaccepted" },
            "outcome": if accepted { "executed" } else { "pending" },
            "status": if r.status { "0x1" } else { "0x0" },
        }],
        "inclusionsComplete": false,
        "knownTransaction": known,
        "semantics": "including-chain-block",
    }))
}

// ── citrate_getFinalityStatus ────────────────────────────────────────────

/// Fields of the finality-lane response (`r1007/s3-finality-voting`,
/// fbe06ac6) that this base cannot fill: they come from the v2 vote message
/// (epoch, state root, accepted root) and the stake-weighted quorum, which
/// that branch adds. Reported as `null` and listed in `pendingFinalityLane`.
pub const FINALITY_LANE_FIELDS: &[&str] = &[
    "epoch",
    "stateRoot",
    "acceptedRoot",
    "votedStake",
    "totalStake",
    "quorumStake",
    "pending",
    "halted",
];

/// The highest finalized certificate persisted in `CF_DAG_METADATA`
/// (`checkpoint:{height}`, written by `CheckpointManager` when a checkpoint
/// finalizes), as stored. Keys are decimal, so every `checkpoint:` key is
/// visited (one per checkpoint interval).
fn latest_certificate(
    storage: &StorageManager,
) -> Result<Option<citrate_consensus::checkpoint::Checkpoint>, jsonrpc_core::Error> {
    let prefix = b"checkpoint:";
    let mut best: Option<u64> = None;
    storage
        .db
        .for_each_prefix_key_cf(CF_DAG_METADATA, prefix, |key| {
            let h = key
                .get(prefix.len()..)
                .and_then(|rest| std::str::from_utf8(rest).ok())
                .and_then(|rest| rest.parse::<u64>().ok());
            if let Some(h) = h {
                best = Some(best.map_or(h, |b| b.max(h)));
            }
            Ok(())
        })
        .map_err(internal)?;
    let Some(height) = best else {
        return Ok(None);
    };
    let key = format!("checkpoint:{height}");
    let Some(bytes) = storage
        .db
        .get_cf(CF_DAG_METADATA, key.as_bytes())
        .map_err(internal)?
    else {
        return Ok(None);
    };
    Ok(
        bincode::deserialize::<citrate_consensus::checkpoint::Checkpoint>(&bytes)
            .ok()
            .filter(|cp| {
                cp.height == height
                    && cp.status == citrate_consensus::checkpoint::CheckpointStatus::Finalized
            }),
    )
}

/// `citrate_getFinalityStatus`: checkpoint finality as this node holds it,
/// never a block-depth estimate (CV-8).
///
/// Data sources:
/// - `finalized`: the RPC's finalized-tag source (`FinalizedTagSource`): the
///   verified `(height, hash)` pairs the node's finality floor verifier
///   publishes when enforcement is on, otherwise the height handle (0 =
///   genesis);
/// - `latestCertificate`: the highest `checkpoint:{height}` record in
///   `CF_DAG_METADATA` (committee size, votes collected), as stored;
/// - `votingPinned` / `enforcementPinned`: the compiled switches
///   (`checkpoint_gadget::CHECKPOINT_VOTING_FROM_GENESIS`, on from block 0 on
///   r1007, and `CHECKPOINT_ENFORCEMENT_GENESES`, keyed by chain id and this
///   store's block 0);
/// - `interval`: `CheckpointConfig::default().interval`, `voteDepth`:
///   `checkpoint::DEFAULT_VOTE_DEPTH`.
///
/// Key set shared with the finality lane's handler (`r1007/s3-finality-voting`
/// `finality_status.rs`) and read by citrate-explorer#51: `published` is
/// `true` (this view is read from storage on every call, so one always
/// exists), `voting` is the compiled voting switch, `mode` is `"enforced"` when
/// verified certificates feed the finalized tag and otherwise `null` (this
/// base cannot tell the lane's `legacy` from `observed`), `quorumRule` names
/// the count rule this base's certificates use (`Checkpoint::effective_quorum`),
/// and `finalized.blockHash` repeats `finalized.hash` under the lane's name.
pub fn finality_status_json(
    storage: &StorageManager,
    finalized: &FinalizedTagSource,
    chain_id: u64,
) -> Result<Value, jsonrpc_core::Error> {
    let anchor = finalized.resolve(storage);
    let finalized_hash = match anchor.hash {
        Some(h) => Some(h),
        None => storage
            .blocks
            .get_canonical_block_by_height(anchor.height)
            .map_err(internal)?,
    };
    let source = match finalized {
        FinalizedTagSource::Verified(_) => "verified-certificates",
        FinalizedTagSource::Height(_) => "height-handle",
    };
    let cert = latest_certificate(storage)?;
    let config = citrate_consensus::checkpoint::CheckpointConfig::default();
    let enforced = matches!(finalized, FinalizedTagSource::Verified(_));
    let finalized_hex = finalized_hash.as_ref().map(hx);
    // The enforcement table is keyed by (chain id, genesis): r1006 and r1007
    // share chain id 40204. The genesis is this store's canonical block 0; a
    // store without one is enforced for no chain.
    let genesis = storage
        .blocks
        .get_canonical_block_by_height(0)
        .map_err(internal)?
        .unwrap_or_default();
    let voting = citrate_consensus::checkpoint_gadget::checkpoint_voting_active();
    Ok(json!({
        "published": true,
        "voting": voting,
        "mode": if enforced { json!("enforced") } else { Value::Null },
        "quorumRule": "vote count: Checkpoint::effective_quorum of the committee (not \
                       stake-weighted on this base)",
        "chainId": qty(chain_id),
        "votingPinned": voting,
        "enforcementPinned":
            citrate_consensus::checkpoint_gadget::checkpoint_enforcement_pinned(chain_id, &genesis),
        "enforcement": enforced,
        "finalizedSource": source,
        "finalized": {
            "height": qty(anchor.height),
            "hash": finalized_hex,
            "blockHash": finalized_hex,
        },
        "latestCertificate": cert.map(|cp| json!({
            "height": qty(cp.height),
            "blockHash": hx(&cp.block_hash),
            "committeeSize": cp.committee.len(),
            "voters": cp.votes.len(),
            "quorum": cp.effective_quorum(),
            "epoch": Value::Null,
            "stateRoot": Value::Null,
            "acceptedRoot": Value::Null,
            "votedStake": Value::Null,
            "totalStake": Value::Null,
            "quorumStake": Value::Null,
        })),
        "interval": qty(config.interval),
        "voteDepth": qty(citrate_consensus::checkpoint::DEFAULT_VOTE_DEPTH),
        "pending": Value::Null,
        "halted": Value::Null,
        "pendingFinalityLane": FINALITY_LANE_FIELDS,
        "dataSource": "finalized-tag source; CF_DAG_METADATA checkpoint:{height}; compiled \
                       checkpoint pins",
    }))
}

// ── eth_getBlockReceipts ─────────────────────────────────────────────────

/// The 2048-bit logs bloom of a set of logs (yellow paper §4.3.1: for the
/// address and every topic, three 11-bit indices from keccak256).
pub fn logs_bloom<'a>(
    logs: impl IntoIterator<Item = &'a citrate_execution::types::Log>,
) -> [u8; 256] {
    use sha3::{Digest, Keccak256};
    let mut bloom = [0u8; 256];
    let mut add = |data: &[u8]| {
        let h: [u8; 32] = Keccak256::digest(data).into();
        for i in 0..3usize {
            let hi = h.get(i.saturating_mul(2)).copied().unwrap_or(0);
            let lo = h
                .get(i.saturating_mul(2).saturating_add(1))
                .copied()
                .unwrap_or(0);
            let bit = usize::from(u16::from_be_bytes([hi, lo]) & 2047);
            let byte = 255usize.saturating_sub(bit / 8);
            let mask = 1u8
                .checked_shl(u32::try_from(bit % 8).unwrap_or(0))
                .unwrap_or(0);
            if let Some(b) = bloom.get_mut(byte) {
                *b |= mask;
            }
        }
    };
    for log in logs {
        add(&log.address.0);
        for t in &log.topics {
            add(t.as_bytes());
        }
    }
    bloom
}

/// The EIP receipt objects of `block`, positionally (spec 06 §3.11 fields
/// that exist on this base): `cumulativeGasUsed` is the running sum within
/// the block, `logIndex` the running index within the block, and `logsBloom`
/// is derived from the logs.
///
/// Data source: `CF_RECEIPTS[tx_hash]` for every tx in the stored block body
/// (`CF_BLOCKS`). A receipt missing, or naming another block, is an error
/// (the block was not executed here), never a silently shorter list.
pub fn block_receipts_json(
    storage: &StorageManager,
    block: &Block,
) -> Result<Value, jsonrpc_core::Error> {
    let block_hash = block.header.block_hash;
    let mut out = Vec::with_capacity(block.transactions.len());
    let mut cumulative: u64 = 0;
    let mut log_index: u64 = 0;
    for (i, tx) in block.transactions.iter().enumerate() {
        let r: TransactionReceipt = match storage.transactions.get_receipt(&tx.hash) {
            Ok(Some(r)) if r.block_hash == block_hash => r,
            _ => {
                return Err(crate::canonical_logs::receipts_not_stored_error(
                    "eth_getBlockReceipts",
                    block.header.height,
                    &block_hash,
                    &tx.hash,
                ))
            }
        };
        cumulative = cumulative.saturating_add(r.gas_used);
        let tx_index = qty(u64::try_from(i).unwrap_or(u64::MAX));
        let logs: Vec<Value> = r
            .logs
            .iter()
            .map(|log| {
                let v = json!({
                    "address": format!("0x{}", hex::encode(log.address.0)),
                    "topics": log.topics.iter().map(hx).collect::<Vec<_>>(),
                    "data": format!("0x{}", hex::encode(&log.data)),
                    "blockNumber": qty(r.block_number),
                    "blockHash": hx(&r.block_hash),
                    "transactionHash": hx(&r.tx_hash),
                    "transactionIndex": tx_index.clone(),
                    "logIndex": qty(log_index),
                    "removed": false,
                });
                log_index = log_index.saturating_add(1);
                v
            })
            .collect();
        let contract_address = if r.to.is_none() && r.output.len() == 20 {
            Some(format!("0x{}", hex::encode(&r.output)))
        } else {
            None
        };
        out.push(json!({
            "transactionHash": hx(&r.tx_hash),
            "transactionIndex": tx_index,
            "blockHash": hx(&r.block_hash),
            "blockNumber": qty(r.block_number),
            "from": format!("0x{}", hex::encode(r.from.0)),
            "to": r.to.as_ref().map(|t| format!("0x{}", hex::encode(t.0))),
            "cumulativeGasUsed": qty(cumulative),
            "gasUsed": qty(r.gas_used),
            "contractAddress": contract_address,
            "logs": logs,
            "logsBloom": format!("0x{}", hex::encode(logs_bloom(&r.logs))),
            "status": if r.status { "0x1" } else { "0x0" },
            "type": format!("0x{:x}", r.eth_tx_type),
            "effectiveGasPrice": qty(r.effective_gas_price),
        }));
    }
    Ok(Value::Array(out))
}

/// Resolve the block parameter of `eth_getBlockReceipts`: a number, a tag,
/// a 32-byte hash, or an EIP-1898 object. Only blocks on the applied chain
/// have receipts (spec 06 §5.1); anything else is `None` (`null`).
fn resolve_receipts_block(
    storage: &StorageManager,
    finalized: &FinalizedTagSource,
    v: Option<&Value>,
) -> Result<Option<Hash>, jsonrpc_core::Error> {
    let tip = applied_tip(storage)?;
    let by_number = |n: u64| -> Result<Option<Hash>, jsonrpc_core::Error> {
        match tip {
            Some((_, th)) if n <= th => storage
                .blocks
                .get_canonical_block_by_height(n)
                .map_err(internal),
            _ => Ok(None),
        }
    };
    let s = match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => {
            if let Some(h) = o.get("blockHash") {
                let hash = parse_hash_param(Some(h), "blockHash")?;
                return check_hash(storage, hash, tip);
            }
            match o.get("blockNumber").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => return Err(bad("object needs blockHash or blockNumber")),
            }
        }
        _ => return Err(bad("block number, tag or hash is required")),
    };
    match s.as_str() {
        "latest" | "pending" => Ok(tip.map(|(h, _)| h)),
        "earliest" => by_number(0),
        "finalized" | "safe" => {
            let a = finalized.resolve(storage);
            match a.hash {
                Some(h) => check_hash(storage, h, tip),
                None => by_number(a.height),
            }
        }
        other => {
            let hex = other
                .strip_prefix("0x")
                .ok_or_else(|| bad(format!("invalid block parameter: {other}")))?;
            if hex.len() == 64 {
                let hash = parse_hash_param(Some(&Value::String(other.to_string())), "block hash")?;
                return check_hash(storage, hash, tip);
            }
            let n = u64::from_str_radix(hex, 16)
                .map_err(|_| bad(format!("invalid block parameter: {other}")))?;
            by_number(n)
        }
    }
}

fn check_hash(
    storage: &StorageManager,
    hash: Hash,
    tip: Option<(Hash, u64)>,
) -> Result<Option<Hash>, jsonrpc_core::Error> {
    match storage.blocks.get_header(&hash).map_err(internal)? {
        Some(h) if on_applied_chain(storage, &hash, h.height, tip)? => Ok(Some(hash)),
        _ => Ok(None),
    }
}

/// Register the S3-7 explorer methods. Read-only; called by
/// `eth_rpc::register_eth_methods_with_options`, so every handler that serves
/// `eth_*` serves these too.
pub fn register_explorer_methods(
    io_handler: &mut IoHandler,
    storage: Arc<StorageManager>,
    finalized: FinalizedTagSource,
    chain_id: u64,
) {
    let st = storage.clone();
    io_handler.add_sync_method("citrate_getBlocksAtHeight", move |params: Params| {
        rpc_request("citrate_getBlocksAtHeight");
        let p = params_vec(params)?;
        let height = parse_u64_param(p.first(), "height")?;
        blocks_at_height_json(&st, height)
    });

    let st = storage.clone();
    io_handler.add_sync_method("citrate_getGhostdagData", move |params: Params| {
        rpc_request("citrate_getGhostdagData");
        let p = params_vec(params)?;
        let hash = parse_hash_param(p.first(), "block hash")?;
        ghostdag_data_json(&st, &hash)
    });

    let st = storage.clone();
    io_handler.add_sync_method("citrate_getSelectedChainChanges", move |params: Params| {
        rpc_request("citrate_getSelectedChainChanges");
        let p = params_vec(params)?;
        let from = parse_hash_param(p.first(), "fromHash")?;
        let limit = match p.get(1) {
            None | Some(Value::Null) => DEFAULT_CHAIN_CHANGES,
            v => parse_u64_param(v, "limit")?,
        };
        selected_chain_changes_json(&st, &from, limit)
    });

    let st = storage.clone();
    io_handler.add_sync_method("citrate_getAcceptingBlock", move |params: Params| {
        rpc_request("citrate_getAcceptingBlock");
        let p = params_vec(params)?;
        let tx = parse_hash_param(p.first(), "transaction hash")?;
        accepting_block_json(&st, &tx)
    });

    let st = storage.clone();
    let fin = finalized.clone();
    io_handler.add_sync_method("citrate_getFinalityStatus", move |_params: Params| {
        rpc_request("citrate_getFinalityStatus");
        finality_status_json(&st, &fin, chain_id)
    });

    let st = storage;
    let fin = finalized;
    io_handler.add_sync_method("eth_getBlockReceipts", move |params: Params| {
        rpc_request("eth_getBlockReceipts");
        let p = params_vec(params)?;
        let Some(hash) = resolve_receipts_block(&st, &fin, p.first())? else {
            return Ok(Value::Null);
        };
        let Some(block) = st.blocks.get_block(&hash).map_err(internal)? else {
            return Ok(Value::Null);
        };
        block_receipts_json(&st, &block)
    });
}
