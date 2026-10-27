// citrate/core/api/src/finalized_tag.rs
//
// Source of the `finalized` / `safe` RPC block tags (checkpoint finality,
// docs/consensus/CHECKPOINT_FINALITY_WIRING.md §4.6).
//
// A finalized checkpoint certifies a (height, block_hash) PAIR. The block
// store's height index (`BlockStore::get_block_by_height`) is NOT a canonical
// index: every stored block writes its height key, so the LAST block written at
// a height wins — that can be an uncertified sibling of the certified block. In
// Enforced mode the tags are therefore resolved by the verified pair's HASH, never
// by its height through that index. If the certified block is not in this
// node's store, the previous verified pair is served, else genesis — never a
// sibling at the certified height.

use citrate_consensus::types::Hash;
use citrate_storage::StorageManager;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Verified pairs remembered for the fallback when the newest certified block is
/// not available locally.
pub const MAX_VERIFIED_FINALIZED_PAIRS: usize = 8;

/// Verified finalized `(height, block_hash)` pairs, ascending by height,
/// published by the node's finality floor verifier (Enforced mode) only after
/// the certificate verified AND its hash is this node's canonical block at that
/// height.
#[derive(Debug, Default)]
pub struct VerifiedFinalized {
    pairs: RwLock<VecDeque<(u64, Hash)>>,
}

impl VerifiedFinalized {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a verified pair. Monotone: a pair at or below the newest recorded
    /// height is ignored (a verified height never moves back, and a pair is
    /// never replaced by another hash at the same height). Returns whether it
    /// was recorded.
    pub fn record(&self, height: u64, hash: Hash) -> bool {
        let mut pairs = match self.pairs.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if pairs.back().is_some_and(|(h, _)| *h >= height) {
            return false;
        }
        pairs.push_back((height, hash));
        while pairs.len() > MAX_VERIFIED_FINALIZED_PAIRS {
            if pairs.pop_front().is_none() {
                break;
            }
        }
        true
    }

    /// The newest verified pair, if any.
    pub fn latest(&self) -> Option<(u64, Hash)> {
        self.snapshot().last().copied()
    }

    /// The recorded pairs, ascending by height.
    pub fn snapshot(&self) -> Vec<(u64, Hash)> {
        let pairs = match self.pairs.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        pairs.iter().copied().collect()
    }
}

/// What `finalized` / `safe` resolve to for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedAnchor {
    /// The finalized height (bounds for range reads: logs, filters, fee history).
    pub height: u64,
    /// The certified block, looked up BY HASH for block reads. `None` = resolve
    /// `height` through the height index (genesis, or a height-only source).
    pub hash: Option<Hash>,
}

impl FinalizedAnchor {
    pub const GENESIS: Self = Self {
        height: 0,
        hash: None,
    };
}

/// Where the `finalized` / `safe` tags come from.
#[derive(Debug, Clone)]
pub enum FinalizedTagSource {
    /// A height only, resolved through the height index. Used where no
    /// finalized height is ever raised (no applicator, voting OFF, or voting ON
    /// with enforcement OFF): the handle stays 0 and the tags resolve to
    /// genesis, which has exactly one block.
    Height(Arc<AtomicU64>),
    /// Verified `(height, hash)` pairs (enforcement ON): resolved by hash.
    Verified(Arc<VerifiedFinalized>),
}

impl Default for FinalizedTagSource {
    /// Tags resolve to genesis.
    fn default() -> Self {
        Self::Height(Arc::new(AtomicU64::new(0)))
    }
}

impl From<Arc<AtomicU64>> for FinalizedTagSource {
    fn from(height: Arc<AtomicU64>) -> Self {
        Self::Height(height)
    }
}

impl From<Arc<VerifiedFinalized>> for FinalizedTagSource {
    fn from(pairs: Arc<VerifiedFinalized>) -> Self {
        Self::Verified(pairs)
    }
}

impl FinalizedTagSource {
    /// Resolve against this node's block store: the newest verified pair whose
    /// block is stored here, else genesis.
    pub fn resolve(&self, storage: &StorageManager) -> FinalizedAnchor {
        self.resolve_with(|hash| matches!(storage.blocks.has_block(hash), Ok(true)))
    }

    /// [`Self::resolve`] with an explicit "is this block stored here" check.
    pub fn resolve_with(&self, has_block: impl Fn(&Hash) -> bool) -> FinalizedAnchor {
        match self {
            Self::Height(h) => FinalizedAnchor {
                height: h.load(Ordering::SeqCst),
                hash: None,
            },
            Self::Verified(pairs) => pairs
                .snapshot()
                .into_iter()
                .rev()
                .find(|(_, hash)| has_block(hash))
                .map(|(height, hash)| FinalizedAnchor {
                    height,
                    hash: Some(hash),
                })
                .unwrap_or(FinalizedAnchor::GENESIS),
        }
    }
}

/// Most selected-parent links one finality-bounded range read may follow below
/// the certified block (header point reads, bounded like the 1000-block log
/// window they feed). A range that starts deeper than this below the certified
/// height is refused instead of walked.
pub const FINALIZED_RANGE_MAX_WALK: u64 = 10_000;

/// Why [`range_block_hashes`] could not list a range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeReadError {
    /// The range starts more than [`FINALIZED_RANGE_MAX_WALK`] blocks below the
    /// certified height.
    TooDeep { depth: u64, max: u64 },
    /// A header read failed, or the stored ancestry is malformed.
    Storage(String),
}

impl std::fmt::Display for RangeReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooDeep { depth, max } => write!(
                f,
                "range starts {depth} blocks below the finalized block; a range bounded by \
                 finalized/safe may start at most {max} blocks below it"
            ),
            Self::Storage(e) => write!(f, "{e}"),
        }
    }
}

/// The blocks a log-range read visits for heights `from..=to`, ascending by
/// height, as `(height, block_hash)`.
///
/// `anchor` is `Some` only when a bound of the request came from a finality tag.
/// When it carries the certified hash (Enforced mode), every height in the range
/// at or below the certified height is read from the CERTIFIED CHAIN: the
/// selected-parent chain that ends at the certified block, followed back from it
/// by hash. This is the same definition the finality floor verifier
/// (`CanonicalApplicator::verify_certified_floor`) uses for "the block at height
/// h on this chain", so a log of an uncertified sibling at a finalized height is
/// never returned. A height the chain steps over has no block (no logs), and if
/// an ancestor is not stored here the walk stops (nothing below it is served,
/// never a height-index entry).
///
/// Heights above the certified height, and every height when `anchor` is `None`
/// or carries no hash (Legacy / Observed: genesis only), go through the height
/// index exactly as before (missing heights are skipped).
///
/// Bounded: the walk reads at most `certified_height - from + 1` headers and is
/// refused past [`FINALIZED_RANGE_MAX_WALK`]; callers cap `to - from` as before.
pub fn range_block_hashes(
    storage: &StorageManager,
    anchor: Option<FinalizedAnchor>,
    from: u64,
    to: u64,
) -> Result<Vec<(u64, Hash)>, RangeReadError> {
    let mut out = Vec::new();
    if from > to {
        return Ok(out);
    }
    let mut index_from = Some(from);
    if let Some(FinalizedAnchor {
        height: certified_height,
        hash: Some(certified),
    }) = anchor
    {
        if from <= certified_height {
            let depth = certified_height.saturating_sub(from);
            if depth > FINALIZED_RANGE_MAX_WALK {
                return Err(RangeReadError::TooDeep {
                    depth,
                    max: FINALIZED_RANGE_MAX_WALK,
                });
            }
            let mut chain = certified_chain_desc(storage, certified, certified_height, from, to)?;
            chain.reverse();
            out = chain;
            index_from = certified_height.checked_add(1);
        }
    }
    if let Some(start) = index_from {
        if start <= to {
            for height in start..=to {
                // Heights above the certified height, or no certified hash: the
                // executed chain's block at each height (chain#421).
                if let Ok(Some(hash)) = storage.blocks.get_canonical_block_by_height(height) {
                    out.push((height, hash));
                }
            }
        }
    }
    Ok(out)
}

/// Follow selected-parent links back from `start` (stored at `start_height`),
/// collecting the blocks whose height is in `lo..=hi`, descending.
fn certified_chain_desc(
    storage: &StorageManager,
    start: Hash,
    start_height: u64,
    lo: u64,
    hi: u64,
) -> Result<Vec<(u64, Hash)>, RangeReadError> {
    let mut out = Vec::new();
    let mut cursor = start;
    let mut max_height = start_height;
    // Heights strictly decrease along the walk, so this many reads suffice.
    let mut reads_left = start_height.saturating_sub(lo).saturating_add(1);
    while reads_left > 0 {
        reads_left = reads_left.saturating_sub(1);
        let header = match storage.blocks.get_header(&cursor) {
            Ok(Some(header)) => header,
            // Ancestry not stored here: serve nothing below it.
            Ok(None) => break,
            Err(e) => return Err(RangeReadError::Storage(format!("header {cursor}: {e}"))),
        };
        let h = header.height;
        if h > max_height {
            return Err(RangeReadError::Storage(format!(
                "header {cursor} at height {h} is not below its child (max {max_height})"
            )));
        }
        if h < lo {
            break;
        }
        if h <= hi {
            out.push((h, cursor));
        }
        if h == lo || h == 0 {
            break;
        }
        max_height = h.saturating_sub(1);
        cursor = header.selected_parent_hash;
    }
    Ok(out)
}

/// Whether `tag` is one of the finality tags.
pub fn is_finality_tag(tag: Option<&str>) -> bool {
    matches!(tag, Some("finalized") | Some("safe"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash {
        Hash::new([n; 32])
    }

    #[test]
    fn verified_pairs_are_monotone_and_bounded() {
        let v = VerifiedFinalized::new();
        assert_eq!(v.latest(), None);
        assert!(v.record(4, h(4)));
        assert!(!v.record(4, h(5)), "same height never replaced");
        assert!(!v.record(2, h(2)), "never moves back");
        assert_eq!(v.latest(), Some((4, h(4))));
        for i in 0..20u8 {
            v.record(u64::from(i).saturating_add(10), h(i));
        }
        assert_eq!(v.snapshot().len(), MAX_VERIFIED_FINALIZED_PAIRS);
        assert_eq!(v.latest(), Some((29, h(19))));
    }

    #[test]
    fn verified_source_resolves_by_hash_with_fallback() {
        let v = Arc::new(VerifiedFinalized::new());
        let src = FinalizedTagSource::from(v.clone());
        assert_eq!(src.resolve_with(|_| true), FinalizedAnchor::GENESIS);
        v.record(2, h(2));
        v.record(4, h(4));
        assert_eq!(
            src.resolve_with(|_| true),
            FinalizedAnchor {
                height: 4,
                hash: Some(h(4))
            }
        );
        // Newest certified block not stored here: previous verified pair.
        assert_eq!(
            src.resolve_with(|x| *x != h(4)),
            FinalizedAnchor {
                height: 2,
                hash: Some(h(2))
            }
        );
        // None stored: genesis, never a height-index lookup at 4.
        assert_eq!(src.resolve_with(|_| false), FinalizedAnchor::GENESIS);
    }

    #[test]
    fn height_source_resolves_by_height() {
        let a = Arc::new(AtomicU64::new(7));
        let src = FinalizedTagSource::from(a);
        assert_eq!(
            src.resolve_with(|_| false),
            FinalizedAnchor {
                height: 7,
                hash: None
            }
        );
        assert_eq!(
            FinalizedTagSource::default().resolve_with(|_| true),
            FinalizedAnchor::GENESIS
        );
        assert!(is_finality_tag(Some("finalized")));
        assert!(is_finality_tag(Some("safe")));
        assert!(!is_finality_tag(Some("latest")));
        assert!(!is_finality_tag(None));
    }
}
