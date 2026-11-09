// citrate/node/src/mergeset.rs
//
// r1007 S3-3b (ADR CV-4a, spec 06 §3.1-§3.2): the blocks a chain block C
// accepts, in execution order, with their bodies. Shared by the producer
// (sealing C on the applied tip) and the applicator (applying C on the drain,
// a reorg or a rebuild), so both execute byte-identical member lists.
//
// Data sources: C's GHOSTDAG record (`GhostDag::ghostdag_data`, persisted in
// the `dag_ghostdag` column family by admission, or `compute_ghostdag` for a
// block the producer has not sealed yet), committed header keys and block
// bodies from `StorageManager::blocks`. The BLOCKHASH window (`RecentChain`)
// reads committed headers along selected-parent links.

use citrate_consensus::acceptance::InclusionColor;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::ordering::consensus_ordered_mergeset;
use citrate_consensus::types::{Block, BlockHeader, ForkChoiceKey, GhostdagData, Hash};
use citrate_storage::StorageManager;

/// The accepted blocks of one chain block, in execution order.
pub(crate) type Members = Vec<(Block, InclusionColor)>;

/// The ordered mergeset bodies of the chain block `header` (spec 06 §3.2).
///
/// `data` is C's GHOSTDAG record when the caller has it (the producer).
/// Otherwise it is read through `ghostdag`. A block without merge parents
/// has `Mergeset(C) = {SP(C)}` by definition, so it needs no record and no
/// GHOSTDAG engine. A block whose selected parent is the zero hash accepts
/// nothing. Every miss fails closed: a member list is never guessed.
pub(crate) async fn accepted_members(
    storage: &StorageManager,
    ghostdag: Option<&GhostDag>,
    header: &BlockHeader,
    data: Option<&GhostdagData>,
) -> Result<Members, String> {
    let sp = header.selected_parent_hash;
    if sp == Hash::default() {
        return Ok(Vec::new());
    }
    let owned;
    let data: &GhostdagData = match data {
        Some(d) => d,
        None if header.merge_parent_hashes.is_empty() => {
            owned = GhostdagData::with_selected_parent(sp, Hash::default());
            &owned
        }
        None => {
            let g = ghostdag.ok_or_else(|| {
                format!(
                    "block {} @ {} merges {} block(s) but no GHOSTDAG engine is wired to order \
                     its mergeset",
                    header.block_hash,
                    header.height,
                    header.merge_parent_hashes.len()
                )
            })?;
            owned = g
                .ghostdag_data(&header.block_hash)
                .await
                .map_err(|e| {
                    format!(
                        "GHOSTDAG record of {} @ {} unavailable: {e}",
                        header.block_hash, header.height
                    )
                })?
                .as_ref()
                .clone();
            &owned
        }
    };
    if data.selected_parent != sp {
        return Err(format!(
            "GHOSTDAG record of {} names selected parent {}, its header {}",
            header.block_hash, data.selected_parent, sp
        ));
    }
    let mut bodies: std::collections::HashMap<Hash, Block> = std::collections::HashMap::new();
    for h in data.mergeset_blues.iter().chain(data.mergeset_reds.iter()) {
        let block = storage
            .blocks
            .get_block(h)
            .map_err(|e| format!("could not read accepted block {h}: {e}"))?
            .ok_or_else(|| format!("accepted block {h} of {} is not stored", header.block_hash))?;
        bodies.insert(*h, block);
    }
    let order = consensus_ordered_mergeset(data, |h| {
        bodies.get(h).map(|b| ForkChoiceKey::of_header(&b.header))
    })
    .map_err(|e| format!("mergeset order of {}: {e}", header.block_hash))?;
    let mut out = Vec::with_capacity(order.len());
    for m in order {
        let block = bodies
            .remove(&m.hash)
            .ok_or_else(|| format!("accepted block {} listed twice", m.hash))?;
        out.push((block, m.color));
    }
    Ok(out)
}

/// Borrow `members` as the executor's view.
pub(crate) fn as_accepted(
    members: &Members,
) -> Vec<citrate_execution::acceptance::AcceptedBlock<'_>> {
    members
        .iter()
        .map(
            |(block, color)| citrate_execution::acceptance::AcceptedBlock {
                block,
                color: *color,
            },
        )
        .collect()
}

/// Spec 06 §3.7: BLOCKHASH(n) for the transactions chain block C accepts is
/// the hash of C's selected-chain ancestor at height n, for
/// n ∈ [height(C) − 256, height(C)). The window of the last accepting block
/// is kept so that consecutive chain blocks read one new header each; a
/// block on another branch walks its own selected chain until it meets the
/// kept window (or for all 256 heights).
///
/// Data source: committed headers in `StorageManager::blocks`, followed by
/// `selected_parent_hash`. A missing header inside the window fails closed:
/// the order of execution never runs on a guessed BLOCKHASH.
pub(crate) const BLOCKHASH_WINDOW: u64 = 256;

#[derive(Default)]
pub(crate) struct RecentChain {
    /// A contiguous run of selected-chain blocks, by height.
    window: parking_lot::Mutex<std::collections::BTreeMap<u64, Hash>>,
}

impl RecentChain {
    /// The BLOCKHASH map for an accepting block whose selected parent is
    /// `sp` at `sp_height`.
    pub(crate) fn block_hashes(
        &self,
        storage: &StorageManager,
        sp: Hash,
        sp_height: u64,
    ) -> Result<std::collections::HashMap<u64, [u8; 32]>, String> {
        if sp == Hash::default() {
            return Ok(std::collections::HashMap::new());
        }
        let floor = sp_height.saturating_add(1).saturating_sub(BLOCKHASH_WINDOW);
        let mut window = self.window.lock();
        let mut out: std::collections::BTreeMap<u64, Hash> = std::collections::BTreeMap::new();
        let (mut cursor, mut height) = (sp, sp_height);
        loop {
            if window.get(&height) == Some(&cursor) {
                // The kept run holds this block, so it holds its ancestors
                // too (it was built by the same selected-parent walk).
                let kept_floor = window.keys().next().copied().unwrap_or(height);
                if kept_floor <= floor {
                    for (h, x) in window.range(floor..=height) {
                        out.insert(*h, *x);
                    }
                    break;
                }
            }
            out.insert(height, cursor);
            if height <= floor {
                break;
            }
            let header = storage
                .blocks
                .get_header(&cursor)
                .map_err(|e| format!("BLOCKHASH window: header {cursor}: {e}"))?
                .ok_or_else(|| format!("BLOCKHASH window: header {cursor} is not stored"))?;
            if header.height != height {
                return Err(format!(
                    "BLOCKHASH window: {cursor} is at height {}, expected {height}",
                    header.height
                ));
            }
            if header.selected_parent_hash == Hash::default() {
                break;
            }
            cursor = header.selected_parent_hash;
            height = height.saturating_sub(1);
        }
        *window = out.clone();
        Ok(out.into_iter().map(|(h, x)| (h, *x.as_bytes())).collect())
    }
}

#[cfg(test)]
mod included_window_tests {
    use super::*;
    use citrate_consensus::types::{BlockBuilder, PublicKey, Transaction};
    use citrate_storage::pruning::PruningConfig;
    use std::sync::Arc;

    fn tx(from: u8, nonce: u64) -> Transaction {
        let mut h = [0u8; 32];
        h[0] = from;
        h[1..9].copy_from_slice(&nonce.to_be_bytes());
        Transaction {
            hash: Hash::new(h),
            nonce,
            from: PublicKey::new([from; 32]),
            ..Default::default()
        }
    }

    /// The reader counts only the run contiguous from the committed nonce in
    /// the applied tip's own list: a block holding gap nonces (a dishonest
    /// producer can include any) never widens a sender's window.
    #[test]
    fn included_run_is_contiguous_from_the_committed_nonce() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let reader = included_nonce_reader(storage.clone());
        let me = PublicKey::new([7; 32]);
        assert_eq!(reader(&me, 5), 5, "no applied tip: the committed nonce");
        let tip = BlockBuilder::new()
            .hash(Hash::new([0xA7; 32]))
            .height(4)
            .transactions(vec![tx(7, 5), tx(7, 6), tx(7, 7), tx(7, 40), tx(8, 0)])
            .build_unhashed();
        storage.blocks.put_block(&tip).expect("put");
        storage
            .blocks
            .put_applied_tip(&tip.header.block_hash, 4)
            .expect("tip");
        assert_eq!(
            reader(&me, 5),
            8,
            "5, 6, 7 included: next is 8; 40 is gap junk"
        );
        assert_eq!(reader(&me, 6), 8, "the run starts at the committed nonce");
        assert_eq!(
            reader(&me, 9),
            9,
            "an included run below the committed nonce is ignored"
        );
        assert_eq!(
            reader(&PublicKey::new([9; 32]), 3),
            3,
            "another sender is untouched"
        );
    }
}
