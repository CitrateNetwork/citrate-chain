//! Test fixtures only: the G11 pruning point a hand-sealed test block must
//! commit (06_CONSENSUS_SPEC §2 G11, `GhostDag::expected_pruning_point`).
//!
//! Since S3-5 admission checks `header.pruning_point` against the selected
//! chain ancestor at `pp_h(B)`, so a fixture block at height >= PRUNING_DEPTH +
//! CHECKPOINT_INTERVAL (10,050) that leaves it zero is rejected
//! (`PruningPointMismatch`). The fixtures that build chains that long by hand
//! (dag_prune, sync_rejoin) seal it here: `pruning_point(height, parent)` before
//! the hash is computed, `record(&block)` after. The value is derived the same
//! way the producer derives it (SP's committed value between boundaries, the
//! SP chain walk at a boundary), from the blocks the fixture has sealed.
//! Data source: the fixture's own sealed headers, kept in a process-wide map
//! keyed by block hash (hashes are unique across tests, so tests may share it).
use citrate_consensus::ghostdag::pruning_point_height;
use citrate_consensus::types::{Block, Hash};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// hash -> (height, selected parent, committed pruning point)
type Sealed = Mutex<HashMap<Hash, (u64, Hash, Hash)>>;

fn sealed() -> &'static Sealed {
    static SEALED: OnceLock<Sealed> = OnceLock::new();
    SEALED.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The pruning point a block at `height` on `parent` commits. Zero while
/// `pp_h = 0`. A parent the fixtures never sealed (a provisional block used
/// only to compute a reward) yields zero; admission would reject such a block,
/// which is what such a fixture expects anyway.
pub(crate) fn pruning_point(height: u64, parent: Hash) -> Hash {
    let target = pruning_point_height(height);
    if target == 0 {
        return Hash::default();
    }
    let map = sealed().lock().expect("g11 fixture map");
    let Some(&(sp_h, _, sp_pp)) = map.get(&parent) else {
        return Hash::default();
    };
    if pruning_point_height(sp_h) == target {
        return sp_pp;
    }
    let mut cur = parent;
    while let Some(&(h, sp, _)) = map.get(&cur) {
        if h == target {
            return cur;
        }
        if h < target {
            break;
        }
        cur = sp;
    }
    Hash::default()
}

/// Record a sealed fixture block (after its hash is computed).
pub(crate) fn record(b: &Block) {
    sealed().lock().expect("g11 fixture map").insert(
        b.header.block_hash,
        (
            b.header.height,
            b.header.selected_parent_hash,
            b.header.pruning_point,
        ),
    );
}
