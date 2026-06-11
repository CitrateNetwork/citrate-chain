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

use citrate_consensus::types::{Block, BlockHeader, Hash};
use citrate_storage::StorageManager;

/// Protocol maximum headers returned per `GetHeaders` request.
pub const MAX_HEADERS_PER_REQUEST: u32 = 2048;

/// Protocol maximum blocks returned per `GetBlocks` request.
pub const MAX_BLOCKS_PER_REQUEST: u32 = 512;

/// Soft cap on the serialized response payload. Kept under the 1 MiB
/// transport frame cap so an over-budget response is truncated here
/// instead of serialized in full and then rejected by the framing layer.
pub const MAX_RESPONSE_BYTES: u64 = 900 * 1024;

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
    let mut out: Vec<T> = Vec::new();
    let mut budget = MAX_RESPONSE_BYTES;
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
                budget -= size;
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

/// Serve a `GetBlocks { from, count }` request, fully bounded.
pub fn serve_blocks(storage: &StorageManager, from: &Hash, count: u32) -> Vec<Block> {
    collect_bounded(storage, from, count.min(MAX_BLOCKS_PER_REQUEST), |b| b)
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
        let storage = Arc::new(
            StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"),
        );
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

    /// NET-2: `count` is clamped to the protocol maximum even when the
    /// chain has more blocks than the clamp.
    #[test]
    fn net2_count_clamped_to_protocol_max() {
        let n = MAX_HEADERS_PER_REQUEST as u64 + 7;
        let (_dir, storage) = chain_of(n);
        let headers = serve_headers(&storage, &Hash::new(ZERO_ANCHOR), u32::MAX);
        assert_eq!(headers.len(), MAX_HEADERS_PER_REQUEST as usize);
        let blocks = serve_blocks(&storage, &Hash::new(ZERO_ANCHOR), u32::MAX);
        assert_eq!(blocks.len(), MAX_BLOCKS_PER_REQUEST as usize);
    }

    /// A gap in the height index stops the walk: nothing contiguous can
    /// follow it, and pre-fix the gap is exactly what turned a bounded
    /// scan into an unbounded one.
    #[test]
    fn gap_in_height_index_stops_serving() {
        let dir = TempDir::new().expect("tempdir");
        let storage =
            StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
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
        let storage =
            StorageManager::new(dir.path(), PruningConfig::default()).expect("storage");
        let mut parent = Hash::default();
        let fat_merges: Vec<Hash> = (0..1024).map(|i| Hash::new([(i % 255) as u8; 32])).collect();
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
        assert!(total <= MAX_RESPONSE_BYTES);
    }
}
