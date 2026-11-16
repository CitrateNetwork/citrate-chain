//! The recorder: a node's data dir, read-only, into a [`Recording`].
//!
//! Data sources (Rule 7), all in the node's chain database:
//! - every stored block: the keys of `CF_HEADERS` (`BlockStore` writes one per
//!   block), each read whole with `BlockStore::get_block` (`CF_BLOCKS`);
//! - the applied tip: `BlockStore::get_applied_tip` (`CF_METADATA`);
//! - the selected chain: selected-parent links of the stored headers, from the
//!   applied tip down;
//! - the committed root per chain block: `StateStore::get_state_root`
//!   (`CF_STATE`, written by the node when it applied the block);
//! - the accepted list per chain block (r1007 S3-3b): the receipts indexed
//!   under it (`TransactionStore::get_block_transactions` /
//!   `get_receipt`), ordered by their acceptance position.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use citrate_consensus::types::Hash;
use citrate_storage::chain::{BlockStore, TransactionStore};
use citrate_storage::db::column_families::CF_HEADERS;
use citrate_storage::db::RocksDB;
use citrate_storage::state::StateStore;

use crate::recording::{ChainEntry, Recording, ReplayConfig};

/// Record the chain database at `data_dir` (opened read-only, so a running
/// node's directory can be recorded).
pub fn record_data_dir(data_dir: &Path, config: ReplayConfig) -> Result<Recording> {
    let db = Arc::new(
        RocksDB::open_read_only(data_dir)
            .with_context(|| format!("open {} read-only", data_dir.display()))?,
    );
    record_db(&db, config, data_dir.display().to_string())
}

/// Record an open chain database.
pub fn record_db(db: &Arc<RocksDB>, config: ReplayConfig, source: String) -> Result<Recording> {
    let blocks = BlockStore::new(db.clone());
    let state = StateStore::new(db.clone());
    let txs = TransactionStore::new(db.clone());
    let Some(applied_tip) = blocks.get_applied_tip().context("applied tip")? else {
        bail!("the database has no applied tip");
    };

    let mut all = Vec::new();
    for (key, _) in db.iter_cf(CF_HEADERS)? {
        let Some(hash) = Hash::try_from_bytes(key.as_ref()) else {
            continue;
        };
        match blocks.get_block(&hash)? {
            Some(b) => all.push(b),
            None => bail!("header {hash} is stored without its block"),
        }
    }
    all.sort_by(|a, b| {
        (a.header.height, a.header.block_hash.as_bytes())
            .cmp(&(b.header.height, b.header.block_hash.as_bytes()))
    });

    let mut chain = Vec::new();
    let mut cursor = applied_tip.0;
    let mut max_height = applied_tip.1;
    loop {
        let Some(header) = blocks.get_header(&cursor)? else {
            // The genesis sentinel (no stored block at height 0, the parent of
            // height 1 is the zero hash) closes the chain; any other missing
            // header leaves a chain that starts above genesis.
            if cursor == Hash::default() && chain.last().is_some_and(|e: &ChainEntry| e.height == 1)
            {
                chain.push(ChainEntry {
                    height: 0,
                    hash: cursor,
                    committed_root: None,
                    accepted: None,
                });
            }
            break;
        };
        if header.height > max_height {
            bail!(
                "header {cursor} at height {} is not below its child (max {max_height})",
                header.height
            );
        }
        chain.push(ChainEntry {
            height: header.height,
            hash: cursor,
            committed_root: state.get_state_root(&cursor)?,
            accepted: accepted_list(&txs, &cursor)?,
        });
        if header.height == 0 {
            break;
        }
        max_height = header.height - 1;
        cursor = header.selected_parent_hash;
    }
    chain.reverse();
    Ok(Recording {
        source,
        config,
        applied_tip,
        chain,
        blocks: all,
    })
}

/// The node's accepted list for chain block `hash`: every receipt indexed
/// under it that still names it, ordered by its acceptance position. `None`
/// when no receipt is indexed under it, or when a receipt lacks acceptance
/// fields (a pre-r1007 block).
fn accepted_list(txs: &TransactionStore, hash: &Hash) -> Result<Option<Vec<(Hash, Hash, bool)>>> {
    let mut rows = Vec::new();
    for tx in txs.get_block_transactions(hash)? {
        let Some(r) = txs.get_receipt(&tx)? else {
            continue;
        };
        if r.block_hash != *hash {
            continue;
        }
        let Some(a) = r.acceptance else {
            return Ok(None);
        };
        rows.push((a.transaction_index, (tx, a.including_block_hash, r.status)));
    }
    if rows.is_empty() {
        return Ok(None);
    }
    rows.sort_by_key(|(i, _)| *i);
    Ok(Some(rows.into_iter().map(|(_, e)| e).collect()))
}
