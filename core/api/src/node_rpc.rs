// citrate/core/api/src/node_rpc.rs
//
// Node self-description RPC methods: `web3_clientVersion`, `citrate_nodeIdentity`
// and `citrate_getDagStats` (UI truth contract §9, "RPC honesty").
//
// Every value these methods return is read from a named source (see the
// comment on each field). A value the node does not know is returned as JSON
// `null`, never as a guess or a default: a client that renders `null` as
// "unknown" is telling the truth, a client that renders an estimate is not.

use crate::methods::ChainApi;
use crate::metrics::rpc_request;
use crate::rpc_runtime::block_on;
use citrate_consensus::types::GhostDagParams;
use citrate_storage::StorageManager;
use jsonrpc_core::{IoHandler, Params, Value};
use serde_json::json;
use std::sync::Arc;

/// Version of this API crate (the workspace version, `Cargo.toml`
/// `[workspace.package] version`). Used only when the embedding binary did not
/// supply a [`NodeIdentity`].
pub const API_CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the running node binary is, as the node itself computed it at start-up.
///
/// The node (`node/src/main.rs`) builds this from its build stamp and its
/// resolved consensus activation; the API crate never derives any of these
/// values on its own.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    /// Source: the node crate's `CARGO_PKG_VERSION`
    /// (`node/src/consensus_manifest.rs` `ConsensusManifest::version`).
    pub version: String,
    /// Source: `git rev-parse --short=12 HEAD` at build time (`node/build.rs`,
    /// `CITRATE_GIT_SHA`; `"unknown"` when git was absent).
    pub git_sha: String,
    /// Source: `git status --porcelain --untracked-files=no` non-empty at
    /// build time (`node/build.rs`, `CITRATE_GIT_DIRTY`).
    pub git_dirty: bool,
    /// Source: `ConsensusManifest::fingerprint` (`node/src/consensus_manifest.rs`),
    /// the hash over the consensus-affecting build surface and activation heights.
    pub consensus_fingerprint: String,
    /// Source: `ResolvedActivation::fingerprint(consensus_fingerprint)`
    /// (`core/consensus/src/hardening.rs`), the consensus fingerprint bound to
    /// the chain id and the PBA hardening height this process resolved.
    pub activation_fingerprint: String,
    /// Source: the `GhostDagParams` the node's `GhostDag` instance was built with
    /// (`GhostDag::params()`, `node/src/main.rs`). `None` = not supplied.
    pub ghostdag_params: Option<GhostDagParams>,
}

/// The `web3_clientVersion` string.
///
/// With an identity: `citrate/v<version>-<git_sha>` (plus `-dirty` for a
/// dirty-tree build). Without one, only the version this crate was compiled
/// with is known, so only that is reported.
pub fn client_version(identity: Option<&NodeIdentity>) -> String {
    match identity {
        Some(id) => format!(
            "citrate/v{}-{}{}",
            id.version,
            id.git_sha,
            if id.git_dirty { "-dirty" } else { "" }
        ),
        None => format!("citrate/v{API_CRATE_VERSION}"),
    }
}

fn internal_error(message: String) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message,
        data: None,
    }
}

/// Hash of the block stored at height 0, or `None` when the store has no
/// genesis yet. Source: `BlockStore::get_block_by_height(0)`.
fn genesis_hash(storage: &StorageManager) -> Result<Option<String>, jsonrpc_core::Error> {
    storage
        .blocks
        .get_block_by_height(0)
        .map(|h| h.map(|hash| format!("0x{}", hex::encode(hash.as_bytes()))))
        .map_err(|e| internal_error(format!("genesis lookup failed: {e}")))
}

/// The `citrate_nodeIdentity` result.
pub fn node_identity_json(
    storage: &StorageManager,
    chain_id: u64,
    identity: Option<&NodeIdentity>,
) -> Result<Value, jsonrpc_core::Error> {
    Ok(json!({
        // Source: the node's configured `[chain] chain_id` (same value eth_chainId serves).
        "chainId": format!("0x{chain_id:x}"),
        // Source: BlockStore::get_block_by_height(0); null before genesis is stored.
        "genesisHash": genesis_hash(storage)?,
        // Source: NodeIdentity::consensus_fingerprint (ConsensusManifest); null if not supplied.
        "consensusFingerprint": identity.map(|i| i.consensus_fingerprint.clone()),
        // Source: NodeIdentity::activation_fingerprint (ResolvedActivation); null if not supplied.
        "activationFingerprint": identity.map(|i| i.activation_fingerprint.clone()),
        // Source: NodeIdentity::version (node CARGO_PKG_VERSION), else this crate's version.
        "version": identity.map_or_else(|| API_CRATE_VERSION.to_string(), |i| i.version.clone()),
        // Source: NodeIdentity::git_sha (node/build.rs); null if not supplied.
        "gitSha": identity.map(|i| i.git_sha.clone()),
        // Source: NodeIdentity::git_dirty (node/build.rs); null if not supplied.
        "gitDirty": identity.map(|i| i.git_dirty),
    }))
}

/// The `citrate_getDagStats` result.
///
/// The node does not keep a blue/red classification count or a total block
/// count, so `totalBlocks`, `blueBlocks` and `redBlocks` are `null` (they used
/// to be estimated as height and height x 0.95). `ghostdagParams` are the
/// parameters the running `GhostDag` uses, or `null` if the embedding binary
/// did not supply them.
pub fn dag_stats_json(
    storage: &Arc<StorageManager>,
    ghostdag_params: Option<&GhostDagParams>,
) -> Result<Value, jsonrpc_core::Error> {
    let api = ChainApi::new(storage.clone());
    // Source: BlockStore::get_tips() (blocks with no stored child), via ChainApi.
    let tips = block_on(api.get_tips()).map_err(|e| internal_error(e.to_string()))?;
    // Source: BlockStore::get_latest_height(), via ChainApi.
    let height = block_on(api.get_height()).map_err(|e| internal_error(e.to_string()))?;

    // Source: the stored header of every tip (`BlockHeader::blue_score`). The
    // maximum over all tips, not the first tip's score. null when no tip
    // header is stored.
    let mut max_blue_score: Option<u64> = None;
    for tip in &tips {
        let header = storage
            .blocks
            .get_header(tip)
            .map_err(|e| internal_error(format!("tip header lookup failed: {e}")))?;
        if let Some(h) = header {
            max_blue_score = Some(max_blue_score.map_or(h.blue_score, |m| m.max(h.blue_score)));
        }
    }

    let tips_hex: Vec<String> = tips
        .iter()
        .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
        .collect();

    let params = ghostdag_params.map(|p| {
        json!({
            "k": p.k,
            "maxParents": p.max_parents,
            "maxBlueScoreDiff": p.max_blue_score_diff,
            "pruningWindow": p.pruning_window,
            "finalityDepth": p.finality_depth,
        })
    });

    Ok(json!({
        // Not tracked by the node (no block counter, no blue/red tally).
        "totalBlocks": Value::Null,
        "blueBlocks": Value::Null,
        "redBlocks": Value::Null,
        "tipsCount": tips.len(),
        "maxBlueScore": max_blue_score,
        "currentTips": tips_hex,
        "height": height,
        "ghostdagParams": params,
    }))
}

/// Register `web3_clientVersion`, `citrate_nodeIdentity` and
/// `citrate_getDagStats`. Read-only; none of them touches consensus state.
pub fn register_node_methods(
    io_handler: &mut IoHandler,
    storage: Arc<StorageManager>,
    chain_id: u64,
    identity: Option<Arc<NodeIdentity>>,
) {
    let version = client_version(identity.as_deref());
    io_handler.add_sync_method("web3_clientVersion", move |_params: Params| {
        rpc_request("web3_clientVersion");
        Ok(Value::String(version.clone()))
    });

    let storage_id = storage.clone();
    let identity_id = identity.clone();
    io_handler.add_sync_method("citrate_nodeIdentity", move |_params: Params| {
        rpc_request("citrate_nodeIdentity");
        node_identity_json(&storage_id, chain_id, identity_id.as_deref())
    });

    io_handler.add_sync_method("citrate_getDagStats", move |_params: Params| {
        rpc_request("citrate_getDagStats");
        dag_stats_json(
            &storage,
            identity.as_deref().and_then(|i| i.ghostdag_params.as_ref()),
        )
    });
}
