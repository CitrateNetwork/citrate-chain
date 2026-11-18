//! Bounded serving of peer `GetHeaders` / `GetBlocks` requests.
//!
//! SECREM-01 NET-1 (Critical) / NET-2 (High): `count` is attacker-supplied.
//! The pre-fix serve loops in `main.rs` ran `while out.len() < count`, so a
//! request anchored past the local tip (where every height lookup returns
//! `None`) never made progress and spun `h` toward `u64::MAX` — one
//! unauthenticated packet pinned a core in a near-infinite storage-read
//! loop. Every serve path must therefore be bounded by ALL of:
//!
//! 1. a protocol clamp on `count` ([`MAX_HEADERS_PER_REQUEST`] /
//!    [`MAX_BLOCKS_PER_REQUEST`]),
//! 2. the local tip height — never iterate past what we actually have,
//! 3. stop at the first gap in the height index (a gap means no further
//!    contiguous data can be served), and
//! 4. a serialized-size budget under the 1 MiB transport frame cap
//!    (`MAX_FRAME_LEN` in citrate-network), so we never spend CPU building
//!    a response the framing layer is guaranteed to reject.

// PANIC-S1 G2: block production / apply / sync path (T1); panic-free outside tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use citrate_consensus::types::{Block, BlockHeader, Hash};
use citrate_storage::StorageManager;
use tracing::{debug, warn};

/// Protocol maximum headers returned per `GetHeaders` request.
pub const MAX_HEADERS_PER_REQUEST: u32 = 2048;

/// Protocol maximum blocks returned per `GetBlocks` request.
pub const MAX_BLOCKS_PER_REQUEST: u32 = 512;

/// Byte budget of a reply that goes on the wire as ONE message: `Headers`
/// (and finality certificates, `finality_sync`).
///
/// This MUST stay under the Noise per-message limit, NOT the 1 MiB length-frame
/// cap. The transport encrypts every message with a single Noise
/// `write_message`, which hard-fails above `MAX_NOISE_MSG_LEN` (65535 bytes) —
/// so an over-64 KiB message is silently dropped by `encrypt`, the requester
/// never receives it, and a cold node wedges forever re-requesting the same
/// anchor. 60 KiB leaves headroom for the enum/vec wrapper and Noise's 16-byte
/// auth tag: 60 KiB payload + wrapper + tag < 65519 usable plaintext bytes.
pub const MAX_UNSPLIT_RESPONSE_BYTES: u64 = 60 * 1024;

/// What a server built before #477 caps a `Blocks` reply at (the soft budget
/// used to be [`MAX_UNSPLIT_RESPONSE_BYTES`]). The mixed-version sync tests
/// serve with it to stand in for an unpatched peer.
#[cfg(test)]
pub const LEGACY_BLOCKS_RESPONSE_BYTES: u64 = MAX_UNSPLIT_RESPONSE_BYTES;

/// Soft cap on the serialized payload of a `Blocks` reply.
///
/// #477 (cold sync at ~0.1 heights/s on r1007): with a 60 KiB budget a reply
/// on a seven-producer DAG carried four height-groups, one of them the
/// requester's own anchor group, so a round trip gained three heights. Since
/// #476 the serving plane splits every `Blocks` reply with [`chunk_for_noise`]
/// into messages that each fit one Noise message, so the reply no longer has to
/// fit one: the budget is now 1 MiB, the transport's frame cap, and a request
/// for [`MAX_BLOCKS_PER_REQUEST`] blocks is bounded by it (about 17 Noise
/// messages at most). No wire change: a peer that asks for 32 still gets at
/// most 32, and a server built before this keeps its 60 KiB budget
/// ([`LEGACY_BLOCKS_RESPONSE_BYTES`]), so a mixed fleet only differs in how
/// much each reply carries.
///
/// NOTE: this is a SOFT budget. `serve_blocks` deliberately exceeds it for the
/// first height-group above the anchor (the SYNC-S2 forward-progress guarantee)
/// — a response that carries nothing new wedges the requester permanently,
/// which is strictly worse than an oversized one.
///
/// The "no block on 40204 exceeds this" assumption that used to live here was
/// WRONG and is what wedged every cold sync: block `79e46ed2` at height 245
/// carries 8 contract-deploy transactions and serializes to **60,515 bytes**.
/// And on r1007 the height-1553 group (seven one-transaction siblings) is
/// 74,543 bytes, which wedged every fresh node at 1552 until replies were split.
/// A SINGLE block over the Noise cap still cannot be sent; that needs
/// Noise-layer fragmentation (a wire change, scheduled for the point release).
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Split a `Blocks` reply into consecutive batches, each of which serializes as
/// a `NetworkMessage::Blocks` within one Noise message
/// ([`citrate_network::noise::MAX_NOISE_PLAINTEXT_LEN`]).
///
/// r1007 cold-sync wedge (2026-11-14): the reply anchored at height 1552 was
/// 14 blocks and ~75 KB, so Noise refused to encrypt it and no fresh node ever
/// got past 1552. Order is kept, so the requester receives the reply exactly as
/// `serve_blocks` built it, only in several messages. Splitting a height-group
/// across messages is safe: siblings never reference each other (every parent
/// has a strictly lower height), messages to one peer leave in order, and the
/// requester admits each block of a later message after the earlier ones
/// (buffering any whose parents are still en route).
///
/// A block that alone exceeds the cap cannot be sent at all. The reply stops
/// before it (anything after it may depend on it) with a warning; the requester
/// still gets what precedes it. When nothing at all can be sent, one empty
/// batch is returned so the requester's pending request is answered rather than
/// left to time out.
pub fn chunk_for_noise(blocks: Vec<Block>) -> Vec<Vec<Block>> {
    let cap = citrate_network::noise::MAX_NOISE_PLAINTEXT_LEN as u64;
    // The enum tag plus the vec length prefix; each block then adds exactly its
    // own serialized size (bincode encodes a Vec as length + elements).
    let overhead =
        bincode::serialized_size(&citrate_network::NetworkMessage::Blocks { blocks: Vec::new() })
            .unwrap_or(16);
    let mut out: Vec<Vec<Block>> = Vec::new();
    let mut current: Vec<Block> = Vec::new();
    let mut current_bytes = overhead;
    for block in blocks {
        let size = bincode::serialized_size(&block).unwrap_or(u64::MAX);
        if overhead.saturating_add(size) > cap {
            warn!(
                "block-serve: block {} at height {} is {} bytes; no Noise message can carry it, \
                 so the reply stops before it (needs Noise-layer fragmentation)",
                hex::encode(
                    block
                        .header
                        .block_hash
                        .as_bytes()
                        .get(..8)
                        .unwrap_or_default()
                ),
                block.header.height,
                size
            );
            break;
        }
        if !current.is_empty() && current_bytes.saturating_add(size) > cap {
            out.push(std::mem::take(&mut current));
            current_bytes = overhead;
        }
        current_bytes = current_bytes.saturating_add(size);
        current.push(block);
    }
    if !current.is_empty() || out.is_empty() {
        out.push(current);
    }
    out
}

/// Resolve the first height to serve for a request anchor.
///
/// The all-zero hash is the protocol's "from genesis" sentinel. Any other
/// anchor must exist locally; an unknown anchor serves nothing (the peer
/// is on a chain we don't have — iterating heights for it is unbounded
/// work for zero serveable data).
fn resolve_start(storage: &StorageManager, from: &Hash) -> Option<u64> {
    if *from == Hash::new([0u8; 32]) {
        return Some(0);
    }
    match storage.blocks.get_block(from) {
        Ok(Some(anchor)) => anchor.header.height.checked_add(1),
        _ => None,
    }
}

/// Like `resolve_start` but INCLUSIVE of the anchor's own height — used only by
/// `serve_blocks` (not headers).
///
/// Deep-sync merge-parent wedge: a follower's applied tip is the CANONICAL block
/// at height H. The block that extends it, H+1, may MERGE a SIBLING at height H
/// (a parallel tip — routinely created when a producer restart spawns concurrent
/// tips). Serving strictly after the anchor (H+1) never delivered that sibling, so
/// the follower could never admit H+1 (`validate_block_consistency` →
/// `MissingParent`) and wedged FOREVER — the applied tip frozen while it
/// re-imported the same range. Serving from H (inclusive) delivers the anchor's
/// whole height-group, so the merge-parent sibling is available; the follower
/// already holds the canonical anchor and skips it (`has_block`), so the only
/// added delivery is the sibling(s) it actually needs.
fn resolve_start_inclusive(storage: &StorageManager, from: &Hash) -> Option<u64> {
    if *from == Hash::new([0u8; 32]) {
        return Some(0);
    }
    match storage.blocks.get_block(from) {
        Ok(Some(anchor)) => Some(anchor.header.height),
        _ => None,
    }
}

/// The height of a request's anchor, when this node holds it (the zero hash is
/// genesis). A peer anchors its sync requests on its own applied tip (or a
/// window it is filling), so this is that peer's current self-report
/// (`serve_plane`).
pub fn anchor_height(storage: &StorageManager, from: &Hash) -> Option<u64> {
    resolve_start_inclusive(storage, from)
}

/// CV-7b (H6): the dead-branch marker, when this node's applied tip is held on
/// a branch it cannot switch from. Unreadable reads as "no marker": serving
/// stays as it was.
fn dead_branch(storage: &StorageManager) -> Option<citrate_storage::chain::wedge::WedgeRecord> {
    citrate_storage::chain::wedge::read(&storage.db)
        .ok()
        .flatten()
}

/// Walk heights `[start, tip]`, mapping each stored block through `map`,
/// stopping at the item clamp, the first index gap, or the byte budget.
fn collect_bounded<T: serde::Serialize>(
    storage: &StorageManager,
    from: &Hash,
    max_items: u32,
    map: impl Fn(Block) -> T,
) -> Vec<T> {
    let Some(start) = resolve_start(storage, from) else {
        return Vec::new();
    };
    let Ok(tip) = storage.blocks.get_latest_height() else {
        return Vec::new();
    };
    // CV-7b: above the fork point of a dead branch the height index is that
    // branch; it is not served as this node's chain.
    let tip = match dead_branch(storage) {
        Some(w) => tip.min(w.fork_height),
        None => tip,
    };
    let mut out: Vec<T> = Vec::new();
    // One message on the wire (`Headers` is not split): the Noise budget.
    let mut budget = MAX_UNSPLIT_RESPONSE_BYTES;
    let mut h = start;
    while h <= tip && (out.len() as u32) < max_items {
        // A missing height or unreadable block is a gap: nothing
        // contiguous can follow it, so stop rather than scan onward.
        let Ok(Some(hash)) = storage.blocks.get_block_by_height(h) else {
            break;
        };
        let Ok(Some(block)) = storage.blocks.get_block(&hash) else {
            break;
        };
        let item = map(block);
        match bincode::serialized_size(&item) {
            Ok(size) if size <= budget => {
                budget = budget.saturating_sub(size);
                out.push(item);
            }
            // Over budget (or unsizeable): the response is full.
            _ => break,
        }
        let Some(next) = h.checked_add(1) else {
            break;
        };
        h = next;
    }
    out
}

/// Serve a `GetHeaders { from, count }` request, fully bounded.
pub fn serve_headers(storage: &StorageManager, from: &Hash, count: u32) -> Vec<BlockHeader> {
    collect_bounded(storage, from, count.min(MAX_HEADERS_PER_REQUEST), |b| {
        b.header
    })
}

/// Serve a `GetBlocks { from, count }` request, fully bounded and DAG-aware.
///
/// #85 (fresh-node forward-sync wedge): the linear `collect_bounded` walk
/// serves exactly ONE block per height (the last-writer-wins height index),
/// which silently drops the SIBLING blocks a multi-producer GhostDAG creates
/// at each height. A joining node then admits height 1, but height 2's
/// canonical block references a height-1 *sibling* it was never sent, so
/// `validate_block_consistency` fails with "Missing parent at admission" and
/// the node wedges at height 1 — on every architecture.
///
/// The fix serves the DAG in topological (height-ascending) order including
/// ALL siblings at each height, delivered as COMPLETE height-groups: because
/// every parent (selected *and* merge) has a strictly lower height than its
/// child, height-ascending complete-group delivery guarantees the requester
/// already holds all of a block's parents before that block. Never split a
/// height across responses (a later batch's child could reference a sibling
/// this batch left behind) and stop at the first height gap.
///
/// SYNC-S2 (cold-sync wedge, 2026-07-27 — why gate G4 never passed). Two
/// interacting defects made a response carry NOTHING the requester could use,
/// forever. Reproduced against a real fleet store at the exact wedge height:
///
///   height 244 group: 1 block  (7c05130a,   674 B) — the requester's OWN anchor
///   height 245 group: 2 blocks (29883fab,   706 B  +  79e46ed2, 60,515 B, 8 txs)
///
/// 1. `resolve_start_inclusive` makes the walk begin at the ANCHOR's height, so
///    the first group emitted is the anchor itself — a block the requester
///    provably already has. That consumed the "always emit the first group"
///    forward-progress escape hatch, which was keyed on `out.is_empty()`.
/// 2. With `out` non-empty, the height-245 group (61,221 B) was then measured
///    against the remaining budget (61,440 − 674 = 60,766 B) and REJECTED.
///
/// Result: `serve_blocks` returned exactly one block — the anchor — so the
/// requester's applied tip never moved, it re-requested the same anchor, and the
/// server returned the same single block. Observed live on rpc-1 as
/// "Sending 1 blocks" every 2 s while the same peer's `GetHeaders` was answered
/// with a full 64 headers, and on the cold node as "Validated and imported 1/1
/// blocks (height 244-244)" indefinitely.
///
/// Fix: key the forward-progress guarantee on "no group ABOVE the anchor emitted
/// yet" rather than on `out.is_empty()`, so the first group the requester can
/// actually advance on is always sent, budget or no budget. Pinned by
/// `cold_sync_serve_always_delivers_a_block_above_the_anchor` and
/// `forward_progress_survives_a_nonempty_anchor_height_group`.
///
/// The anchor's own block is deliberately INCLUDED in the response — see the
/// comment at the group-gathering loop. SYNC-S3's recovery request depends on it.
pub fn serve_blocks(storage: &StorageManager, from: &Hash, count: u32) -> Vec<Block> {
    serve_blocks_within(storage, from, count, MAX_RESPONSE_BYTES)
}

/// [`serve_blocks`] under a soft byte budget of `max_bytes`. Production serves
/// with [`MAX_RESPONSE_BYTES`]; the mixed-version sync tests serve with
/// [`LEGACY_BLOCKS_RESPONSE_BYTES`] to stand in for a server built before #477.
pub fn serve_blocks_within(
    storage: &StorageManager,
    from: &Hash,
    count: u32,
    max_bytes: u64,
) -> Vec<Block> {
    let max_items = count.min(MAX_BLOCKS_PER_REQUEST);
    // INCLUSIVE of the anchor's height so a merge parent that is a sibling of the
    // anchor is delivered (see resolve_start_inclusive — the deep-sync wedge fix).
    let Some(start) = resolve_start_inclusive(storage, from) else {
        return Vec::new();
    };
    let Ok(tip) = storage.blocks.get_latest_height() else {
        return Vec::new();
    };
    if start > tip {
        return Vec::new();
    }
    // A height-group holds >= 1 block, so more than `max_items` heights can
    // never fit in one response — bound the enumerated window accordingly.
    let end = start.saturating_add(max_items as u64).min(tip);
    let mut rows = match storage.blocks.hashes_in_height_range(start, end) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    // Deterministic, peer-independent order: height asc, then hash asc.
    rows.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.as_bytes().cmp(b.1.as_bytes()))
    });

    // CV-7b: the dead branch's blocks above its fork point are left out (a
    // height whose only member was one is an empty group, not a gap).
    let wedge = dead_branch(storage);
    let mut out: Vec<Block> = Vec::new();
    let mut budget = max_bytes;
    let mut expected = start;
    let mut i = 0usize;
    // Has any height-group ABOVE the anchor been emitted yet? The forward-
    // progress guarantee keys on this (see SYNC-S2 in the fn docs).
    let mut progressed = false;
    while let Some(&(h, _)) = rows.get(i) {
        // Heights must be contiguous from `start`: a gap means nothing further
        // is admissible in order, so stop rather than serve a disconnected tail.
        if h != expected {
            break;
        }
        // Gather the WHOLE sibling group at height `h`.
        let mut group: Vec<Block> = Vec::new();
        let mut group_bytes = 0u64;
        let mut unreadable = false;
        while let Some(&(row_h, hash)) = rows.get(i) {
            if row_h != h {
                break;
            }
            i = i.saturating_add(1);
            if let Some(w) = &wedge {
                if row_h > w.fork_height && row_h <= w.dead_tip_height {
                    let canonical = storage
                        .blocks
                        .get_canonical_block_by_height(row_h)
                        .ok()
                        .flatten();
                    if w.is_dead_block(row_h, &hash, canonical) {
                        continue;
                    }
                }
            }
            // The anchor's own block IS included. It is tempting to strip it —
            // "they anchored on it, so they have it" — but that assumption is
            // false for the SYNC-S3 recovery request, which anchors at a MISSING
            // PARENT precisely because the requester does NOT have it. Stripping
            // the anchor there would withhold the one block the requester needs
            // and leave two producers permanently partitioned. The forward-
            // progress guarantee below is what fixes the SYNC-S2 byte-budget
            // wedge; excluding the anchor was only ever an optimization.
            if let Ok(Some(block)) = storage.blocks.get_block(&hash) {
                let sz = bincode::serialized_size(&block).unwrap_or(u64::MAX);
                group_bytes = group_bytes.saturating_add(sz);
                group.push(block);
            } else {
                // A row we cannot read is a genuine gap: nothing contiguous can
                // follow it in order, so stop rather than serve a broken tail.
                unreadable = true;
            }
        }
        if unreadable {
            break;
        }
        // A height whose only member was the anchor leaves an empty group. That
        // is NOT a gap — the requester needs nothing at that height — so fall
        // through and advance rather than breaking.
        if !group.is_empty() {
            // SYNC-S2 forward-progress guarantee: the first height-group ABOVE
            // the anchor is emitted regardless of the soft byte budget, so every
            // response carries something the requester can actually advance on.
            // Keying this on `out.is_empty()` was the defect — with an inclusive
            // anchor the anchor's own group had already filled `out`.
            let first_progress = h > start && !progressed;
            if !first_progress
                && !out.is_empty()
                && (out.len().saturating_add(group.len()) as u32 > max_items
                    || group_bytes > budget)
            {
                break;
            }
            if group_bytes > max_bytes {
                // Emitted anyway: forward progress beats a permanent wedge. The
                // serving plane splits the reply (`chunk_for_noise`), so it is
                // delivered across several Noise messages.
                debug!(
                    "block-serve: height-{} group is {} bytes, over the {}-byte soft budget; \
                     serving it anyway to guarantee sync progress (the reply is split)",
                    h, group_bytes, max_bytes
                );
            }
            budget = budget.saturating_sub(group_bytes);
            out.extend(group);
            if h > start {
                progressed = true;
            }
        }
        expected = h.saturating_add(1);
    }
    out
}

/// The reply to a `GetAncestor` request (ADR-2026-11-17, ancestor sync).
#[derive(Debug, Clone)]
pub struct AncestorReply {
    /// The highest locator entry on this node's executed chain.
    pub common: Option<(Hash, u64)>,
    /// This node's applied tip (the dead branch's fork point when the applied
    /// tip is held on a dead branch, CV-7b).
    pub tip: (Hash, u64),
    /// `blue_work` of the tip's header (0 when unreadable).
    pub tip_blue_work: u128,
    /// Headers of the executed chain directly above `common`, ascending.
    pub headers: Vec<BlockHeader>,
}

impl AncestorReply {
    pub fn into_message(self) -> citrate_network::NetworkMessage {
        citrate_network::NetworkMessage::Ancestor {
            common: self.common,
            tip: self.tip,
            tip_blue_work: self.tip_blue_work,
            headers: self.headers,
        }
    }
}

/// Serve a `GetAncestor { locator }` request, fully bounded.
///
/// Data source: this node's chain store, read through the canonical height
/// index (`BlockStore::get_canonical_block_by_height`, the executed chain) and
/// `BlockStore::get_header`. Cost: at most `MAX_LOCATOR_HASHES` header reads
/// and index reads to find the common block, then at most
/// `MAX_ANCESTOR_HEADERS` index and header reads, stopping at the applied tip
/// (or a dead branch's fork point), at the first gap, and before the reply
/// would exceed [`MAX_UNSPLIT_RESPONSE_BYTES`] (it is one Noise message).
///
/// The common block is the highest locator entry that this node holds AT ITS
/// HEIGHT ON ITS EXECUTED CHAIN: a block it merely stores (a side block) is not
/// a point from which its own chain continues. Entries are read in any order;
/// the highest wins, so a requester cannot make the server walk further by
/// reordering them.
pub fn serve_ancestor(storage: &StorageManager, locator: &[Hash]) -> AncestorReply {
    use citrate_network::protocol::{MAX_ANCESTOR_HEADERS, MAX_LOCATOR_HASHES};
    let applied = storage
        .blocks
        .get_applied_tip()
        .ok()
        .flatten()
        .unwrap_or((Hash::default(), 0));
    // CV-7b: above a dead branch's fork point the executed chain is that
    // branch; it is not served as this node's chain.
    let (tip, top) = match dead_branch(storage) {
        Some(w) if w.fork_height < applied.1 => ((w.fork_point, w.fork_height), w.fork_height),
        _ => (applied, applied.1),
    };
    let tip_blue_work = storage
        .blocks
        .get_header(&tip.0)
        .ok()
        .flatten()
        .map(|h| h.blue_work)
        .unwrap_or(0);
    let on_chain = |hash: &Hash| -> Option<u64> {
        let header = storage.blocks.get_header(hash).ok().flatten()?;
        let height = header.height;
        if height > top {
            return None;
        }
        let canonical = storage
            .blocks
            .get_canonical_block_by_height(height)
            .ok()
            .flatten()?;
        (canonical == *hash).then_some(height)
    };
    let common = locator
        .iter()
        .take(MAX_LOCATOR_HASHES)
        .filter_map(|h| on_chain(h).map(|height| (*h, height)))
        .max_by_key(|(_, height)| *height);
    let mut headers: Vec<BlockHeader> = Vec::new();
    if let Some((_, from)) = common {
        let mut budget = MAX_UNSPLIT_RESPONSE_BYTES;
        let mut h = from;
        while (headers.len() as u32) < MAX_ANCESTOR_HEADERS {
            let Some(next) = h.checked_add(1) else {
                break;
            };
            if next > top {
                break;
            }
            h = next;
            let Ok(Some(hash)) = storage.blocks.get_canonical_block_by_height(h) else {
                break;
            };
            let Ok(Some(header)) = storage.blocks.get_header(&hash) else {
                break;
            };
            match bincode::serialized_size(&header) {
                Ok(size) if size <= budget => {
                    budget = budget.saturating_sub(size);
                    headers.push(header);
                }
                _ => break,
            }
        }
    }
    AncestorReply {
        common,
        tip,
        tip_blue_work,
        headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{BlockBuilder, PublicKey};
    use citrate_storage::pruning::PruningConfig;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    /// Unique, never-all-zero hash per height (zero is the genesis
    /// request sentinel).
    fn height_hash(height: u64) -> Hash {
        let mut bytes = [7u8; 32];
        bytes[..8].copy_from_slice(&height.to_be_bytes());
        Hash::new(bytes)
    }

    fn test_block(height: u64, parent: Hash) -> Block {
        BlockBuilder::new()
            .hash(height_hash(height))
            .parent(parent)
            .height(height)
            .timestamp(1_000_000 + height)
            .blue_score(height * 10)
            .blue_work(height as u128 * 100)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed()
    }

    /// Storage with a contiguous chain at heights 0..=n-1.
    fn chain_of(n: u64) -> (TempDir, Arc<StorageManager>) {
        let dir = TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let mut parent = Hash::default();
        for h in 0..n {
            let b = test_block(h, parent);
            parent = b.hash();
            storage.blocks.put_block(&b).expect("put_block");
        }
        (dir, storage)
    }

    const ZERO_ANCHOR: [u8; 32] = [0u8; 32];

    /// NET-1 red test: the pre-fix loop never terminated when `count`
    /// exceeded the number of serveable headers (every height past the
    /// tip returns `None`, so `headers.len()` stopped growing while the
    /// loop condition stayed true). Run the serve call on a worker
    /// thread with a hard timeout: against the unpatched logic this
    /// test FAILS by timeout; against the bounded logic it returns
    /// immediately with exactly the available headers.
    #[test]
    fn net1_huge_count_past_tip_returns_promptly() {
        let (_dir, storage) = chain_of(5);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let headers = serve_headers(&storage, &Hash::new(ZERO_ANCHOR), u32::MAX);
            let _ = tx.send(headers);
        });
        let headers = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("NET-1 regression: serve_headers did not return within 5s");
        assert_eq!(headers.len(), 5, "exactly the stored chain, nothing more");
    }

    /// NET-1 red test, hash-anchor branch: anchor at the tip, ask for
    /// more. Pre-fix this spun past the tip forever.
    #[test]
    fn net1_anchor_at_tip_returns_empty_promptly() {
        let (_dir, storage) = chain_of(4);
        let tip_hash = storage
            .blocks
            .get_block_by_height(3)
            .expect("read")
            .expect("tip exists");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let headers = serve_headers(&storage, &tip_hash, 1_000_000);
            let _ = tx.send(headers);
        });
        let headers = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("NET-1 regression: anchored serve did not return within 5s");
        assert!(headers.is_empty(), "nothing exists past the tip");
    }

    /// NET-1: empty storage + zero anchor was the tightest infinite
    /// loop (no height ever resolves). Must return empty, promptly.
    #[test]
    fn net1_empty_storage_returns_empty() {
        let (_dir, storage) = chain_of(0);
        let headers = serve_headers(&storage, &Hash::new(ZERO_ANCHOR), 10);
        assert!(headers.is_empty());
    }

    /// NET-2: `count` is clamped to the protocol maximum even when the chain has
    /// more blocks than the clamp — AND the response never exceeds the byte budget.
    /// The count clamp is an UPPER bound: the byte budget (60 KiB for headers,
    /// 1 MiB for blocks) may bind before the count clamp, so assert `<=` the
    /// protocol max + non-empty forward progress.
    #[test]
    fn net2_count_clamped_to_protocol_max() {
        let n = MAX_HEADERS_PER_REQUEST as u64 + 7;
        let (_dir, storage) = chain_of(n);
        let headers = serve_headers(&storage, &Hash::new(ZERO_ANCHOR), u32::MAX);
        assert!(headers.len() <= MAX_HEADERS_PER_REQUEST as usize);
        assert!(!headers.is_empty(), "serve must make forward progress");
        let blocks = serve_blocks(&storage, &Hash::new(ZERO_ANCHOR), u32::MAX);
        assert!(blocks.len() <= MAX_BLOCKS_PER_REQUEST as usize);
        assert!(!blocks.is_empty(), "serve must make forward progress");
    }

    /// A gap in the height index stops the walk: nothing contiguous can
    /// follow it, and pre-fix the gap is exactly what turned a bounded
    /// scan into an unbounded one.
    #[test]
    fn gap_in_height_index_stops_serving() {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let b0 = test_block(0, Hash::default());
        let b1 = test_block(1, b0.hash());
        // Skip height 2 entirely; store height 3.
        let b3 = test_block(3, Hash::new([9u8; 32]));
        for b in [&b0, &b1, &b3] {
            storage.blocks.put_block(b).expect("put_block");
        }
        let headers = serve_headers(&storage, &Hash::new(ZERO_ANCHOR), 10);
        assert_eq!(headers.len(), 2, "serving stops at the gap before height 3");
        assert_eq!(headers[0].height, 0);
        assert_eq!(headers[1].height, 1);
    }

    /// Unknown anchor hash serves nothing — the alternative is an
    /// unbounded scan for a chain we do not have.
    #[test]
    fn unknown_anchor_serves_nothing() {
        let (_dir, storage) = chain_of(3);
        let headers = serve_headers(&storage, &Hash::new([0xAB; 32]), 10);
        assert!(headers.is_empty());
    }

    /// SYNC-S2 — COLD-SYNC WEDGE (gate G4). Reproduces, to the byte, the shape
    /// harvested from a live fleet store at the height where every fresh node
    /// on chain 40204 stalls:
    ///
    ///   height H   : the requester's own anchor,  674 B
    ///   height H+1 : 706 B canonical  +  60,515 B contract-deploy sibling
    ///
    /// Pre-fix, `serve_blocks` emitted the anchor first (inclusive start), which
    /// consumed the `out.is_empty()` forward-progress escape hatch; the H+1 group
    /// (61,221 B) was then measured against the budget MINUS the anchor
    /// (61,440 − 674 = 60,766 B) and rejected. The response carried exactly one
    /// block — the anchor the requester already had — so its applied tip never
    /// moved and it re-requested the same anchor forever. Observed live as
    /// "Sending 1 blocks" on the server and "Validated and imported 1/1 blocks
    /// (height 244-244)" on the cold node, every 2 seconds, indefinitely.
    ///
    /// INVARIANT: a response anchored at H MUST contain at least one block above
    /// H whenever the server has one. Anything less cannot advance the requester.
    #[test]
    fn cold_sync_serve_always_delivers_a_block_above_the_anchor() {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let genesis = dag_block(1, 0, Hash::default(), vec![]);
        let g = genesis.hash();
        // The anchor: the cold node's applied tip, small and alone at its height.
        let anchor = fat_dag_block(0xA1, 1, g, vec![], 674);
        // The next height: a small canonical block plus a large deploy sibling,
        // together just over the budget that remains once the anchor is counted.
        let next = fat_dag_block(0xC2, 2, anchor.hash(), vec![], 706);
        let deploy = fat_dag_block(0xD2, 2, anchor.hash(), vec![], 60_515);
        for b in [&genesis, &anchor, &next, &deploy] {
            storage.blocks.put_block(b).expect("put_block");
        }

        let served = serve_blocks(&storage, &anchor.hash(), 32);
        let heights: Vec<u64> = served.iter().map(|b| b.header.height).collect();
        assert!(
            heights.iter().any(|h| *h > 1),
            "SYNC-S2 INVARIANT: the response must carry at least one block ABOVE the \
             anchor, else the requester can never advance and re-requests the same \
             anchor forever (the live cold-sync wedge). Got heights {heights:?}"
        );
    }

    /// SYNC-S3 — the recovery request must be answerable.
    ///
    /// When a gossiped block cannot be placed (its parent is missing), the node
    /// asks the sending peer for blocks anchored at that MISSING PARENT — a block
    /// the peer provably holds, since it just sent that block's child. The whole
    /// recovery hinges on the serve returning the anchor ITSELF: the requester
    /// does not have it, which is the entire point of asking.
    ///
    /// This pins that property. It is also why `serve_blocks` must NOT strip the
    /// anchor from the response as a bandwidth optimization — doing so withholds
    /// exactly the block the requester is missing and leaves two producers
    /// permanently partitioned (the 2026-07-27 live split, where one dropped
    /// gossip message desynced two producers for good).
    #[test]
    fn recovery_anchor_at_a_missing_parent_returns_that_block() {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let genesis = dag_block(1, 0, Hash::default(), vec![]);
        let g = genesis.hash();
        let shared = dag_block(0xA1, 1, g, vec![]);
        // The peer's branch: `missing` is the block our node never received; `child`
        // is the one it DID receive and had to defer.
        let missing = dag_block(0xB2, 2, shared.hash(), vec![]);
        let child = dag_block(0xC3, 3, missing.hash(), vec![]);
        for b in [&genesis, &shared, &missing, &child] {
            storage.blocks.put_block(b).expect("put_block");
        }

        let served = serve_blocks(&storage, &missing.hash(), 32);
        let hashes: Vec<Hash> = served.iter().map(|b| b.hash()).collect();
        assert!(
            hashes.contains(&missing.hash()),
            "SYNC-S3 INVARIANT: a request anchored at a missing parent MUST return that \
             block — the requester does not have it, which is why it is asking. Stripping \
             the anchor makes the recovery request unanswerable and partitions the fleet."
        );
        assert!(
            hashes.contains(&child.hash()),
            "and the deferred child's ancestry forward must come with it"
        );
    }

    /// SYNC-S2, second half: the forward-progress guarantee must key on "no group
    /// ABOVE the anchor emitted yet", NOT on `out.is_empty()`. Here the anchor
    /// height carries a genuine SIBLING, so `out` is non-empty by the time the
    /// H+1 group is weighed even after the anchor itself is excluded — and that
    /// group alone exceeds the remaining budget. Keyed on `out.is_empty()` the
    /// serve stalls again; keyed on progress it delivers.
    #[test]
    fn forward_progress_survives_a_nonempty_anchor_height_group() {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let genesis = dag_block(1, 0, Hash::default(), vec![]);
        let g = genesis.hash();
        let anchor = fat_dag_block(0xA1, 1, g, vec![], 700);
        let sibling = fat_dag_block(0xB1, 1, g, vec![], 700); // merge-parent sibling
                                                              // Selects the anchor, merges the sibling — and is itself oversized.
        let big = fat_dag_block(0xC2, 2, anchor.hash(), vec![sibling.hash()], 61_000);
        for b in [&genesis, &anchor, &sibling, &big] {
            storage.blocks.put_block(b).expect("put_block");
        }

        let served = serve_blocks(&storage, &anchor.hash(), 32);
        let hashes: Vec<Hash> = served.iter().map(|b| b.hash()).collect();
        assert!(
            hashes.contains(&sibling.hash()),
            "the anchor-height merge-parent sibling must still be delivered"
        );
        assert!(
            hashes.contains(&big.hash()),
            "SYNC-S2 INVARIANT: the first height-group above the anchor must be served \
             even when it exceeds the remaining soft byte budget — a response the \
             requester cannot advance on wedges it permanently"
        );
    }

    /// Anchored request serves strictly after the anchor.
    #[test]
    fn anchored_request_starts_after_anchor() {
        let (_dir, storage) = chain_of(5);
        let anchor = storage
            .blocks
            .get_block_by_height(1)
            .expect("read")
            .expect("height 1 exists");
        let headers = serve_headers(&storage, &anchor, 10);
        assert_eq!(headers.len(), 3, "heights 2, 3, 4");
        assert_eq!(headers[0].height, 2);
        assert_eq!(headers[2].height, 4);
    }

    /// Like [`dag_block`] but padded with one transaction so the block
    /// serializes to (very close to) `target_bytes` — for exercising the
    /// response byte budget with realistically large contract-deploy blocks.
    fn fat_dag_block(
        id: u8,
        height: u64,
        selected: Hash,
        merges: Vec<Hash>,
        target_bytes: u64,
    ) -> Block {
        use citrate_consensus::types::{Signature, Transaction};
        let mk = |data: Vec<u8>| {
            let tx = Transaction {
                hash: Hash::new([id; 32]),
                nonce: 0,
                from: PublicKey::new([2; 32]),
                to: Some(PublicKey::new([3; 32])),
                value: 0,
                gas_limit: 21_000,
                gas_price: 1_000_000_000,
                data,
                signature: Signature::new([1; 64]),
                tx_type: None,
                chain_id: Some(40204),
                ..Default::default()
            };
            let mut bytes = [id; 32];
            bytes[0] = id;
            BlockBuilder::new()
                .hash(Hash::new(bytes))
                .parent(selected)
                .merge_parents(merges.clone())
                .height(height)
                .timestamp(1_000_000 + height)
                .blue_score(height * 10)
                .blue_work(height as u128 * 100)
                .proposer(PublicKey::new([1; 32]))
                .transactions(vec![tx])
                .build_unhashed()
        };
        // `data` is a Vec<u8> — one serialized byte per element — so a single
        // measurement of the empty-payload block gives the exact padding.
        let base = bincode::serialized_size(&mk(Vec::new())).expect("size");
        let pad = target_bytes.saturating_sub(base) as usize;
        mk(vec![0xABu8; pad])
    }

    /// Build a block with an explicit id-derived hash, a selected parent,
    /// and optional merge parents (for constructing multi-producer DAGs).
    fn dag_block(id: u8, height: u64, selected: Hash, merges: Vec<Hash>) -> Block {
        let mut bytes = [id; 32];
        bytes[0] = id; // ensure never all-zero (genesis sentinel)
        BlockBuilder::new()
            .hash(Hash::new(bytes))
            .parent(selected)
            .merge_parents(merges)
            .height(height)
            .timestamp(1_000_000 + height)
            .blue_score(height * 10)
            .blue_work(height as u128 * 100)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed()
    }

    /// #85 regression: on a multi-producer GhostDAG the serve must deliver
    /// EVERY sibling at each height (a complete height-group) in topological
    /// order — not the single last-writer-wins block. Here height 1 has two
    /// siblings A and B; the height-2 block C selects A and MERGES B. A
    /// requester can only admit C if it already holds BOTH A and B, so the
    /// serve must return A and B (both height 1) before C (height 2).
    #[test]
    fn serves_all_siblings_before_merging_child() {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let genesis = dag_block(1, 0, Hash::default(), vec![]);
        let g = genesis.hash();
        let a1 = dag_block(0xA1, 1, g, vec![]);
        let b1 = dag_block(0xB1, 1, g, vec![]);
        // C selects A1, merges B1 — B1 is a merge-parent the old serve dropped.
        let c2 = dag_block(0xC2, 2, a1.hash(), vec![b1.hash()]);
        for b in [&genesis, &a1, &b1, &c2] {
            storage.blocks.put_block(b).expect("put_block");
        }

        let served = serve_blocks(&storage, &Hash::new(ZERO_ANCHOR), u32::MAX);
        let heights: Vec<u64> = served.iter().map(|b| b.header.height).collect();
        // Both height-1 siblings must be present...
        let hashes: Vec<Hash> = served.iter().map(|b| b.hash()).collect();
        assert!(hashes.contains(&a1.hash()), "sibling A1 must be served");
        assert!(
            hashes.contains(&b1.hash()),
            "sibling B1 (a merge-parent) must be served"
        );
        assert!(hashes.contains(&c2.hash()), "child C2 must be served");
        // ...and every height-1 block must precede the height-2 child.
        let c_idx = served
            .iter()
            .position(|b| b.hash() == c2.hash())
            .expect("C2 present");
        for (idx, h) in heights.iter().enumerate() {
            if *h == 1 {
                assert!(
                    idx < c_idx,
                    "all height-1 siblings must precede the height-2 child"
                );
            }
        }
    }

    /// Deep-sync merge-parent wedge regression. The follower's APPLIED TIP is the
    /// canonical block A1 at height 1. The block that extends it, C2 (height 2),
    /// selects A1 and MERGES B1 — a SIBLING of A1 at height 1 (a parallel tip, as a
    /// producer restart routinely creates). Anchored on A1, the pre-fix serve
    /// started at height 2 and delivered C2 but NOT B1, so the follower could never
    /// admit C2 (`validate_block_consistency` → `MissingParent(B1)`) and wedged
    /// forever — the applied tip frozen while it re-imported the same range (the
    /// live boot3 wedge at height 10108). The serve must deliver B1, the
    /// anchor-height sibling merge-parent.
    #[test]
    fn serve_delivers_anchor_height_sibling_merge_parent() {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let genesis = dag_block(1, 0, Hash::default(), vec![]);
        let g = genesis.hash();
        let a1 = dag_block(0xA1, 1, g, vec![]); // canonical height-1 = follower's applied tip
        let b1 = dag_block(0xB1, 1, g, vec![]); // SIBLING at height 1 (the merge parent)
        let c2 = dag_block(0xC2, 2, a1.hash(), vec![b1.hash()]); // selects A1, MERGES B1
        for b in [&genesis, &a1, &b1, &c2] {
            storage.blocks.put_block(b).expect("put_block");
        }

        // Follower requests from its applied tip A1.
        let served = serve_blocks(&storage, &a1.hash(), u32::MAX);
        let hashes: Vec<Hash> = served.iter().map(|b| b.hash()).collect();

        assert!(
            hashes.contains(&c2.hash()),
            "the extending block C2 must be served"
        );
        assert!(
            hashes.contains(&b1.hash()),
            "the anchor-height sibling B1 (C2's merge parent) MUST be served — pre-fix it was \
             omitted (serve started at anchor+1) and the follower wedged forever"
        );
        // And B1 (height 1) must precede C2 (height 2) so the requester holds it first.
        let b_idx = served
            .iter()
            .position(|b| b.hash() == b1.hash())
            .expect("B1 present");
        let c_idx = served
            .iter()
            .position(|b| b.hash() == c2.hash())
            .expect("C2 present");
        assert!(
            b_idx < c_idx,
            "merge-parent sibling B1 must be served before its child C2"
        );
    }

    /// A height-group is never split across a response: if the item cap lands
    /// mid-height, the whole group is deferred so a later batch's child never
    /// references an unserved sibling.
    #[test]
    fn does_not_split_a_height_group() {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let genesis = dag_block(1, 0, Hash::default(), vec![]);
        let g = genesis.hash();
        // Three siblings at height 1.
        let s = [
            dag_block(0x11, 1, g, vec![]),
            dag_block(0x12, 1, g, vec![]),
            dag_block(0x13, 1, g, vec![]),
        ];
        storage.blocks.put_block(&genesis).expect("put");
        for b in &s {
            storage.blocks.put_block(b).expect("put");
        }
        // genesis(0) is one group, height-1 is a 3-sibling group. Ask for a
        // count that could only fit genesis + part of height 1 — the height-1
        // group must be served whole or not at all.
        let served = serve_blocks(&storage, &Hash::new(ZERO_ANCHOR), 2);
        let h1 = served.iter().filter(|b| b.header.height == 1).count();
        assert!(
            h1 == 0 || h1 == 3,
            "height-1 group served whole or not at all, got {h1}"
        );
    }

    /// The serialized response always fits the byte budget (which sits
    /// under the 1 MiB transport frame cap).
    #[test]
    fn response_fits_byte_budget() {
        let n = MAX_BLOCKS_PER_REQUEST as u64 + 1;
        let (_dir, storage) = chain_of(n);
        let blocks = serve_blocks(&storage, &Hash::new(ZERO_ANCHOR), u32::MAX);
        let total: u64 = blocks
            .iter()
            .map(|b| bincode::serialized_size(b).expect("sizeable"))
            .sum();
        assert!(
            total <= MAX_RESPONSE_BYTES,
            "serialized response {total} exceeds budget {MAX_RESPONSE_BYTES}"
        );
    }

    /// Oversized items truncate the response at the budget boundary
    /// instead of overflowing it: blocks inflated with merge-parent
    /// hashes (~32 KiB each) must stop accumulating before 900 KiB.
    #[test]
    fn byte_budget_truncates_before_frame_cap() {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let mut parent = Hash::default();
        let fat_merges: Vec<Hash> = (0..1024)
            .map(|i| Hash::new([(i % 255) as u8; 32]))
            .collect();
        for h in 0..60u64 {
            let b = BlockBuilder::new()
                .hash(Hash::new([(h + 1) as u8; 32]))
                .parent(parent)
                .merge_parents(fat_merges.clone())
                .height(h)
                .timestamp(1_000_000 + h)
                .blue_score(h * 10)
                .blue_work(h as u128 * 100)
                .proposer(PublicKey::new([1; 32]))
                .build_unhashed();
            parent = b.hash();
            storage.blocks.put_block(&b).expect("put_block");
        }
        let headers = serve_headers(&storage, &Hash::new(ZERO_ANCHOR), u32::MAX);
        assert!(
            !headers.is_empty(),
            "budget must admit at least the first item"
        );
        assert!(
            headers.len() < 60,
            "budget must truncate the response below the full chain"
        );
        let total: u64 = headers
            .iter()
            .map(|h| bincode::serialized_size(h).expect("sizeable"))
            .sum();
        assert!(total <= MAX_UNSPLIT_RESPONSE_BYTES);
    }

    fn blocks_message_bytes(blocks: &[Block]) -> u64 {
        bincode::serialized_size(&citrate_network::NetworkMessage::Blocks {
            blocks: blocks.to_vec(),
        })
        .expect("size")
    }

    /// r1007 height-1553 shape: seven ~10.6 KB siblings (74.5 KB) after seven
    /// small ones. Every batch fits one Noise message, and the batches
    /// concatenate back to the input in order.
    #[test]
    fn chunk_for_noise_splits_an_over_cap_reply_in_order() {
        let g = Hash::new([1; 32]);
        let mut reply: Vec<Block> = (0..7u8)
            .map(|i| dag_block(0x10 + i, 1, g, vec![]))
            .collect();
        let anchor = reply[0].hash();
        reply.extend((0..7u8).map(|i| fat_dag_block(0x20 + i, 2, anchor, vec![], 10_650)));
        let cap = citrate_network::noise::MAX_NOISE_PLAINTEXT_LEN as u64;
        assert!(
            blocks_message_bytes(&reply) > cap,
            "fixture is over the cap"
        );

        let batches = chunk_for_noise(reply.clone());
        assert!(batches.len() > 1, "an over-cap reply must be split");
        for (i, b) in batches.iter().enumerate() {
            assert!(!b.is_empty(), "batch {i} is empty");
            let bytes = blocks_message_bytes(b);
            assert!(bytes <= cap, "batch {i} is {bytes} bytes, over {cap}");
        }
        let flat: Vec<Hash> = batches.iter().flatten().map(|b| b.hash()).collect();
        let want: Vec<Hash> = reply.iter().map(|b| b.hash()).collect();
        assert_eq!(flat, want, "order and contents preserved");
        // The first message must carry something above the anchor height, or the
        // requester scores it as a useless answer.
        assert!(batches[0].iter().any(|b| b.header.height == 2));
    }

    /// A store shaped like r1007: `siblings` blocks per height above genesis,
    /// each height's blocks selecting the previous height's first sibling and
    /// merging the rest; every `fat_every`-th height's first sibling carries a
    /// ~10 KB transaction (the r1007 height-1553 shape).
    fn r1007_shaped_store(top: u64, siblings: u64, fat_every: u64) -> (TempDir, StorageManager) {
        let dir = TempDir::new().expect("tempdir");
        let storage = StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let id = |h: u64, i: u64| {
            let mut bytes = [0x5Au8; 32];
            bytes[..8].copy_from_slice(&h.to_be_bytes());
            bytes[8..16].copy_from_slice(&i.to_be_bytes());
            Hash::new(bytes)
        };
        let genesis = BlockBuilder::new()
            .hash(id(0, 0))
            .parent(Hash::default())
            .height(0)
            .timestamp(1_000_000)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed();
        storage.blocks.put_block(&genesis).expect("put genesis");
        let mut prev: Vec<Hash> = vec![genesis.hash()];
        for h in 1..=top {
            let mut row = Vec::new();
            for i in 0..siblings {
                let data = if i == 0 && h % fat_every == 0 {
                    vec![0xAB; 10_400]
                } else {
                    Vec::new()
                };
                let tx = citrate_consensus::types::Transaction {
                    hash: id(h, 1000 + i),
                    to: Some(PublicKey::new([3; 32])),
                    gas_limit: 21_000,
                    data,
                    chain_id: Some(40204),
                    ..Default::default()
                };
                let b = BlockBuilder::new()
                    .hash(id(h, i))
                    .parent(prev[0])
                    .merge_parents(prev[1..].to_vec())
                    .height(h)
                    .timestamp(1_000_000 + h)
                    .blue_score(h * siblings)
                    .blue_work(u128::from(h * siblings))
                    .proposer(PublicKey::new([1; 32]))
                    .transactions(vec![tx])
                    .build_unhashed();
                storage.blocks.put_block(&b).expect("put");
                row.push(b.hash());
            }
            prev = row;
        }
        (dir, storage)
    }

    /// #477: a full 512-block request on a seven-producer DAG with ~10 KB
    /// blocks is answered whole within the 1 MiB budget, and still goes on the
    /// wire as Noise-sized messages. A server built before #477 (60 KiB) carries
    /// a handful of heights for the same request, which is the round-trip cost
    /// the issue measured (3 new heights per answer).
    #[test]
    fn a_full_request_on_an_r1007_shaped_dag_fits_the_split_budget() {
        let (_dir, storage) = r1007_shaped_store(200, 7, 5);
        let anchor = storage
            .blocks
            .get_block_by_height(10)
            .expect("read")
            .expect("anchor");
        let reply = serve_blocks(&storage, &anchor, MAX_BLOCKS_PER_REQUEST);
        let heights: std::collections::BTreeSet<u64> =
            reply.iter().map(|b| b.header.height).collect();
        assert_eq!(reply.len(), 511, "73 complete seven-block groups");
        assert_eq!(heights.first(), Some(&10), "inclusive of the anchor group");
        assert_eq!(heights.len(), 73);
        let total: u64 = reply
            .iter()
            .map(|b| bincode::serialized_size(b).expect("size"))
            .sum();
        assert!(total <= MAX_RESPONSE_BYTES, "{total} bytes");
        let legacy = serve_blocks_within(
            &storage,
            &anchor,
            MAX_BLOCKS_PER_REQUEST,
            LEGACY_BLOCKS_RESPONSE_BYTES,
        );
        let legacy_heights: std::collections::BTreeSet<u64> =
            legacy.iter().map(|b| b.header.height).collect();
        assert!(
            legacy_heights.len() <= 8,
            "a pre-#477 server carries only a few heights: {}",
            legacy_heights.len()
        );
        // On the wire: every message fits one Noise message, in order.
        let cap = citrate_network::noise::MAX_NOISE_PLAINTEXT_LEN as u64;
        let frames = chunk_for_noise(reply.clone());
        assert!(frames.len() > 1);
        for f in &frames {
            assert!(blocks_message_bytes(f) <= cap);
        }
        let flat: Vec<Hash> = frames.iter().flatten().map(|b| b.hash()).collect();
        let want: Vec<Hash> = reply.iter().map(|b| b.hash()).collect();
        assert_eq!(flat, want);
    }

    /// A requester built before #477 asks for 32 and still gets at most 32
    /// (whole groups), whatever the server's byte budget: mixed-version safe.
    #[test]
    fn a_pre_477_requester_still_gets_at_most_its_count() {
        let (_dir, storage) = r1007_shaped_store(200, 7, 5);
        let anchor = storage
            .blocks
            .get_block_by_height(10)
            .expect("read")
            .expect("anchor");
        let reply = serve_blocks(&storage, &anchor, 32);
        assert_eq!(reply.len(), 28, "four whole seven-block groups");
    }

    /// `Headers` is not split, so its budget stays the Noise one however many
    /// headers are asked for.
    #[test]
    fn a_headers_reply_stays_one_noise_message() {
        let (_dir, storage) = r1007_shaped_store(400, 7, 5);
        let headers = serve_headers(&storage, &Hash::new(ZERO_ANCHOR), MAX_HEADERS_PER_REQUEST);
        assert!(headers.len() > 64, "more than the old 64-header window");
        let bytes = bincode::serialized_size(&citrate_network::NetworkMessage::Headers {
            headers: headers.clone(),
        })
        .expect("size");
        assert!(bytes <= citrate_network::noise::MAX_NOISE_PLAINTEXT_LEN as u64);
    }

    /// A reply already under the cap is sent unchanged, as one message.
    #[test]
    fn chunk_for_noise_leaves_a_small_reply_whole() {
        let g = Hash::new([1; 32]);
        let reply: Vec<Block> = (0..5u8)
            .map(|i| dag_block(0x30 + i, 1, g, vec![]))
            .collect();
        let batches = chunk_for_noise(reply.clone());
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), reply.len());
    }

    /// A single block over the cap can never be sent: the reply stops before
    /// it and keeps what precedes it.
    #[test]
    fn chunk_for_noise_stops_before_a_block_no_message_can_carry() {
        let g = Hash::new([1; 32]);
        let small = dag_block(0x40, 1, g, vec![]);
        let huge = fat_dag_block(0x41, 2, small.hash(), vec![], 70_000);
        let after = dag_block(0x42, 3, huge.hash(), vec![]);
        let batches = chunk_for_noise(vec![small.clone(), huge, after]);
        assert_eq!(batches.len(), 1);
        let hashes: Vec<Hash> = batches[0].iter().map(|b| b.hash()).collect();
        assert_eq!(hashes, vec![small.hash()]);
    }

    /// Nothing sendable still yields one (empty) message, so the requester's
    /// pending request is answered instead of timing out.
    #[test]
    fn chunk_for_noise_answers_an_empty_reply() {
        let lens = |b: Vec<Vec<Block>>| b.iter().map(Vec::len).collect::<Vec<_>>();
        assert_eq!(lens(chunk_for_noise(Vec::new())), vec![0]);
        let g = Hash::new([1; 32]);
        let huge = fat_dag_block(0x50, 1, g, vec![], 70_000);
        assert_eq!(lens(chunk_for_noise(vec![huge])), vec![0]);
    }

    // ---- serve_ancestor (ancestor sync, ADR-2026-11-17) ----

    /// `chain_of(n)` with its tip applied, so the canonical index describes
    /// heights 0..n-1.
    fn applied_chain_of(n: u64) -> (TempDir, Arc<StorageManager>) {
        let (dir, storage) = chain_of(n);
        storage
            .blocks
            .put_applied_tip(&height_hash(n - 1), n - 1)
            .expect("applied tip");
        (dir, storage)
    }

    fn unknown(k: u8) -> Hash {
        Hash::new([0xE0 ^ k; 32])
    }

    #[test]
    fn serve_ancestor_finds_the_highest_locator_entry_on_the_executed_chain() {
        let (_dir, storage) = applied_chain_of(300);
        // Newest first, as a requester on a branch forked at 50 sends it: its
        // own blocks (unknown here), then shared ones. Order is not trusted:
        // the highest held entry wins wherever it sits.
        let locator = vec![
            unknown(1),
            unknown(2),
            height_hash(10),
            height_hash(50),
            height_hash(0),
        ];
        let r = serve_ancestor(&storage, &locator);
        assert_eq!(r.common, Some((height_hash(50), 50)));
        assert_eq!(r.tip, (height_hash(299), 299));
        assert_eq!(r.tip_blue_work, 299 * 100);
        let heights: Vec<u64> = r.headers.iter().map(|h| h.height).collect();
        let want: Vec<u64> =
            (51..51 + u64::from(citrate_network::protocol::MAX_ANCESTOR_HEADERS)).collect();
        assert_eq!(
            heights, want,
            "the executed chain above the common block, capped"
        );
        for w in r.headers.windows(2) {
            assert_eq!(w[1].selected_parent_hash, w[0].block_hash, "one chain");
        }
    }

    #[test]
    fn serve_ancestor_stops_at_the_applied_tip_and_answers_an_unknown_locator_with_none() {
        let (_dir, storage) = applied_chain_of(20);
        let r = serve_ancestor(&storage, &[height_hash(15)]);
        assert_eq!(r.common, Some((height_hash(15), 15)));
        let heights: Vec<u64> = r.headers.iter().map(|h| h.height).collect();
        assert_eq!(heights, vec![16, 17, 18, 19]);
        let r = serve_ancestor(&storage, &[height_hash(19)]);
        assert!(r.headers.is_empty(), "nothing above our own tip");
        let r = serve_ancestor(&storage, &[unknown(1), unknown(2)]);
        assert_eq!(r.common, None);
        assert!(r.headers.is_empty());
        assert_eq!(serve_ancestor(&storage, &[]).common, None);
    }

    /// A block this node merely stores (a side block at a height whose
    /// executed block is another) is not a point its chain continues from.
    #[test]
    fn serve_ancestor_ignores_held_side_blocks() {
        let (_dir, storage) = applied_chain_of(100);
        let mut side = test_block(60, height_hash(59));
        side.header.block_hash = unknown(9);
        storage.blocks.put_block(&side).expect("side block");
        // Re-assert the applied tip so the canonical index describes it.
        storage
            .blocks
            .put_applied_tip(&height_hash(99), 99)
            .expect("applied tip");
        let r = serve_ancestor(&storage, &[unknown(9), height_hash(40)]);
        assert_eq!(r.common, Some((height_hash(40), 40)));
    }

    /// DoS cap: entries past `MAX_LOCATOR_HASHES` are never read.
    #[test]
    fn serve_ancestor_reads_at_most_the_locator_cap() {
        let (_dir, storage) = applied_chain_of(30);
        let cap = citrate_network::protocol::MAX_LOCATOR_HASHES;
        let mut locator: Vec<Hash> = (0..cap).map(|k| unknown(k as u8)).collect();
        locator.push(height_hash(5));
        assert_eq!(serve_ancestor(&storage, &locator).common, None);
        locator.insert(0, height_hash(5));
        assert_eq!(
            serve_ancestor(&storage, &locator).common,
            Some((height_hash(5), 5))
        );
    }

    /// The reply is one message on the wire: it fits the Noise budget.
    #[test]
    fn serve_ancestor_reply_fits_one_noise_message() {
        let (_dir, storage) = applied_chain_of(400);
        let r = serve_ancestor(&storage, &[height_hash(1)]);
        assert!(!r.headers.is_empty());
        let size = bincode::serialized_size(&r.into_message()).expect("size");
        assert!(size <= MAX_UNSPLIT_RESPONSE_BYTES + 256, "{size}");
    }
}
