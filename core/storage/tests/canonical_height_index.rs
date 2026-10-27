// citrate/core/storage/tests/canonical_height_index.rs
//
// chain#421: a by-number lookup must name the block on the executed
// (selected-parent) chain of the applied tip, at every depth.
//
// `BlockStore::put_block` writes `height -> hash` for EVERY stored block, last
// writer wins, so a sibling written after the executed block at the same height
// (a competing producer's block, a losing fork delivered late, a follower that
// receives a height-group in arbitrary order) takes the entry. These tests drive
// the applied tip through every writer the node uses (the block store's tip
// write, the state store's atomic commit, its atomic reorg commit, and the
// non-atomic fallback) and compare the by-number answer with a walk of
// `selected_parent_hash` links down from the tip.

use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey};
use citrate_execution::executor::{ReceiptIndexBatch, StateStoreTrait};
use citrate_storage::chain::BlockStore;
use citrate_storage::db::{column_families::CF_METADATA, RocksDB};
use citrate_storage::state::StateStore;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::TempDir;

/// Branch tags: 0 = the canonical branch, anything else a competitor.
fn block_hash(branch: u8, height: u64) -> Hash {
    let mut b = [0u8; 32];
    b[0] = 0xC0;
    b[1] = branch;
    b[24..32].copy_from_slice(&height.to_be_bytes());
    Hash::new(b)
}

fn mk(branch: u8, height: u64, parent: Hash) -> Block {
    BlockBuilder::new()
        .hash(block_hash(branch, height))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .blue_score(height)
        .blue_work(u128::from(height))
        .proposer(PublicKey::new([branch.wrapping_add(1); 32]))
        .build_unhashed()
}

struct Node {
    _dir: TempDir,
    path: std::path::PathBuf,
    db: Arc<RocksDB>,
    blocks: BlockStore,
    state: StateStore,
}

impl Node {
    fn fresh() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().to_path_buf();
        let db = Arc::new(RocksDB::open(&path).expect("open"));
        Node {
            blocks: BlockStore::new(db.clone()),
            state: StateStore::new(db.clone()),
            db,
            path,
            _dir: dir,
        }
    }

    /// Close and reopen the same data dir (a node restart).
    fn restart(self) -> Self {
        let Node {
            _dir,
            path,
            db,
            blocks,
            state,
        } = self;
        drop(blocks);
        drop(state);
        drop(db);
        let db = Arc::new(RocksDB::open(&path).expect("reopen"));
        Node {
            blocks: BlockStore::new(db.clone()),
            state: StateStore::new(db.clone()),
            db,
            path,
            _dir,
        }
    }

    fn put(&self, b: &Block) {
        self.blocks.put_block(b).expect("put_block");
    }

    /// Apply through the state store's atomic commit (the normal apply path).
    fn commit_tip(&self, hash: Hash, height: u64) {
        self.state
            .write_state_batch_with_applied_tip(
                &[],
                &[],
                Some((hash, height)),
                &ReceiptIndexBatch::default(),
            )
            .expect("commit");
    }

    /// Apply through the state store's atomic reorg commit.
    fn reorg_tip(&self, hash: Hash, height: u64) {
        self.state
            .write_reorg_batch_sync(
                &[],
                &[],
                &[],
                &[],
                Some((hash, height)),
                &ReceiptIndexBatch::default(),
            )
            .expect("reorg commit");
    }

    fn by_number(&self, h: u64) -> Option<Hash> {
        self.blocks
            .get_canonical_block_by_height(h)
            .expect("by-number read")
    }

    /// The block at every height from the applied tip down to genesis, by
    /// following selected-parent links (what `fleet_agree` walks).
    fn parent_walk(&self) -> Vec<Option<Hash>> {
        let (tip, top) = self
            .blocks
            .get_applied_tip()
            .expect("tip")
            .expect("tip set");
        let mut out = vec![None; top as usize + 1];
        let mut cur = tip;
        let mut h = top;
        loop {
            let header = self
                .blocks
                .get_header(&cur)
                .expect("header")
                .expect("stored");
            assert_eq!(header.height, h);
            out[h as usize] = Some(cur);
            if h == 0 {
                break;
            }
            cur = header.selected_parent_hash;
            h -= 1;
        }
        out
    }

    /// Heights at or below the tip where by-number differs from the parent walk.
    fn mismatches(&self) -> Vec<u64> {
        self.parent_walk()
            .iter()
            .enumerate()
            .filter(|(h, want)| self.by_number(*h as u64) != **want)
            .map(|(h, _)| h as u64)
            .collect()
    }
}

/// Store a linear branch `branch` from `from..=to` on top of `parent`.
fn put_branch(n: &Node, branch: u8, parent: Hash, from: u64, to: u64) -> Vec<Block> {
    let mut out = Vec::new();
    let mut p = parent;
    for h in from..=to {
        let b = mk(branch, h, p);
        n.put(&b);
        p = b.hash();
        out.push(b);
    }
    out
}

/// (a) Two producers race at heights 2 and 3; the executed block is written
/// FIRST and the losing sibling AFTER it, so the stored index names the loser.
#[test]
fn by_number_names_the_executed_block_not_a_later_written_sibling() {
    let n = Node::fresh();
    let a = put_branch(&n, 0, Hash::default(), 0, 4);
    n.commit_tip(a[4].hash(), 4);
    // The competing producer's blocks at 2 and 3 arrive after ours.
    let b2 = mk(1, 2, a[1].hash());
    let b3 = mk(1, 3, b2.hash());
    n.put(&b2);
    n.put(&b3);
    assert_eq!(
        n.by_number(2),
        Some(a[2].hash()),
        "height 2 is the executed block"
    );
    assert_eq!(
        n.by_number(3),
        Some(a[3].hash()),
        "height 3 is the executed block"
    );
    assert_eq!(n.mismatches(), Vec::<u64>::new());
}

/// A reorg rewrites the reverted and the applied range, in both directions, and
/// a tip that moves lower stops naming the abandoned heights.
#[test]
fn reorg_rewrites_the_reverted_and_applied_range() {
    let n = Node::fresh();
    let a = put_branch(&n, 0, Hash::default(), 0, 6);
    // Competitor forks at a[2]; written after A, so the stored index names it at 3..=6.
    let b = put_branch(&n, 1, a[2].hash(), 3, 6);
    n.commit_tip(a[6].hash(), 6);
    assert_eq!(n.mismatches(), Vec::<u64>::new(), "on A");
    for h in 3..=6 {
        assert_eq!(n.by_number(h), Some(a[h as usize].hash()));
    }

    n.reorg_tip(b[3].hash(), 6);
    assert_eq!(n.mismatches(), Vec::<u64>::new(), "reorged to B");
    for h in 3..=6 {
        assert_eq!(n.by_number(h), Some(b[h as usize - 3].hash()));
    }

    n.reorg_tip(a[6].hash(), 6);
    assert_eq!(n.mismatches(), Vec::<u64>::new(), "reorged back to A");
    for h in 3..=6 {
        assert_eq!(n.by_number(h), Some(a[h as usize].hash()));
    }

    // Rewind to a lower tip on the B branch: 0..=4 follow B.
    n.reorg_tip(b[1].hash(), 4);
    assert_eq!(n.mismatches(), Vec::<u64>::new(), "rewound onto B @ 4");
    assert_eq!(n.by_number(3), Some(b[0].hash()));
    assert_eq!(n.by_number(4), Some(b[1].hash()));
}

/// (b) A follower syncing a long range: blocks arrive in height-groups whose
/// order puts a losing sibling after the executed block at many heights, the
/// tip advances in group-commit jumps, and part of the range is applied on a
/// competing branch first and then reorged away. Every height must match the
/// parent walk, thousands of blocks deep.
#[test]
fn follower_sync_through_a_reorged_range_matches_the_parent_walk_everywhere() {
    const TOP: u64 = 3_000;
    let n = Node::fresh();
    let mut canon: Vec<Block> = Vec::new();
    let mut parent = Hash::default();
    for h in 0..=TOP {
        let b = mk(0, h, parent);
        // Losing siblings: before the executed block at some heights, after it
        // at others (the order a height-group can arrive in).
        let sib = (h > 0 && h % 7 == 0).then(|| mk(2, h, canon[h as usize - 1].hash()));
        if h % 2 == 0 {
            if let Some(s) = &sib {
                n.put(s);
            }
            n.put(&b);
        } else {
            n.put(&b);
            if let Some(s) = &sib {
                n.put(s);
            }
        }
        parent = b.hash();
        canon.push(b);
    }
    // A competing branch over 1_500..=1_560 that the follower first applies.
    let comp = put_branch(&n, 3, canon[1_499].hash(), 1_500, 1_560);

    let mut h = 0u64;
    let mut step = 1u64;
    while h < 1_560 {
        h = (h + step).min(1_560);
        step = step % 61 + 1;
        if h < 1_500 {
            n.commit_tip(canon[h as usize].hash(), h);
        } else {
            n.commit_tip(comp[(h - 1_500) as usize].hash(), h);
        }
    }
    assert_eq!(n.mismatches(), Vec::<u64>::new(), "on the competing branch");
    assert_eq!(n.by_number(1_530), Some(comp[30].hash()));

    // Fork choice takes the canonical branch back, then sync resumes.
    n.reorg_tip(canon[1_600].hash(), 1_600);
    let mut h = 1_600u64;
    while h < TOP {
        h = (h + step).min(TOP);
        step = step % 61 + 1;
        n.commit_tip(canon[h as usize].hash(), h);
    }
    let bad = n.mismatches();
    assert!(
        bad.is_empty(),
        "{} height(s) differ from the parent walk, first {:?}",
        bad.len(),
        &bad[..bad.len().min(10)]
    );
    assert_eq!(n.by_number(1_530), Some(canon[1_530].hash()));
}

/// (c) After a restart the answers are unchanged, and a data dir written by a
/// binary without the canonical index (tip set, no index) is served correctly
/// on first read after the upgrade, with no reindex step.
#[test]
fn canonical_answers_survive_restart_and_a_pre_upgrade_store_self_heals() {
    let n = Node::fresh();
    let a = put_branch(&n, 0, Hash::default(), 0, 40);
    let b = put_branch(&n, 1, a[10].hash(), 11, 40);
    n.commit_tip(a[40].hash(), 40);
    let n = n.restart();
    assert_eq!(n.mismatches(), Vec::<u64>::new(), "after restart");
    assert_eq!(n.by_number(20), Some(a[20].hash()));

    // An older binary moves the tip by writing only the tip pointer.
    let mut raw = [0u8; 40];
    raw[..32].copy_from_slice(b[29].hash().as_bytes());
    raw[32..].copy_from_slice(&40u64.to_be_bytes());
    n.db.put_cf(
        CF_METADATA,
        citrate_storage::chain::block_store::APPLIED_TIP_KEY,
        &raw,
    )
    .expect("raw tip write");
    let n = n.restart();
    assert_eq!(
        n.mismatches(),
        Vec::<u64>::new(),
        "tip moved by an older binary"
    );
    assert_eq!(n.by_number(20), Some(b[9].hash()));
}

/// A store whose tip came from a binary that never kept the index at all.
#[test]
fn pre_upgrade_store_without_any_index_is_served_canonically() {
    let n = Node::fresh();
    let a = put_branch(&n, 0, Hash::default(), 0, 30);
    put_branch(&n, 1, a[5].hash(), 6, 30);
    let mut raw = [0u8; 40];
    raw[..32].copy_from_slice(a[30].hash().as_bytes());
    raw[32..].copy_from_slice(&30u64.to_be_bytes());
    n.db.put_cf(
        CF_METADATA,
        citrate_storage::chain::block_store::APPLIED_TIP_KEY,
        &raw,
    )
    .expect("raw tip write");
    let n = n.restart();
    assert_eq!(n.mismatches(), Vec::<u64>::new());
}

/// Every writer of the applied tip leaves the index describing that same tip:
/// it is staged in the same write as the tip, so no crash point separates them.
#[test]
fn every_tip_writer_leaves_the_index_at_the_same_tip() {
    let n = Node::fresh();
    let a = put_branch(&n, 0, Hash::default(), 0, 8);
    let b = put_branch(&n, 1, a[3].hash(), 4, 8);
    let check = |n: &Node, what: &str| {
        let tip = n.blocks.get_applied_tip().expect("tip").expect("set");
        assert_eq!(
            n.blocks.canonical_index_tip().expect("marker"),
            Some(tip),
            "{what}: the index must describe the applied tip"
        );
        assert_eq!(n.mismatches(), Vec::<u64>::new(), "{what}");
    };
    n.blocks.put_applied_tip(&a[8].hash(), 8).expect("tip");
    check(&n, "BlockStore::put_applied_tip");
    n.commit_tip(b[4].hash(), 8);
    check(&n, "write_state_batch_with_applied_tip");
    n.reorg_tip(a[7].hash(), 7);
    check(&n, "write_reorg_batch_sync");
    n.state.put_applied_tip_meta(&b[3].hash(), 7).expect("meta");
    check(&n, "put_applied_tip_meta");
}

/// Above the applied tip nothing has executed: the stored index still answers
/// there (admitted, not yet executed blocks), and a store that has never
/// executed a block keeps the stored index everywhere.
#[test]
fn heights_above_the_applied_tip_keep_the_stored_index() {
    let n = Node::fresh();
    let a = put_branch(&n, 0, Hash::default(), 0, 5);
    assert_eq!(n.by_number(3), Some(a[3].hash()), "no applied tip yet");
    n.commit_tip(a[2].hash(), 2);
    assert_eq!(n.by_number(4), Some(a[4].hash()), "admitted above the tip");
    assert_eq!(n.by_number(9), None);
}

/// A hole in the executed chain's ancestry is reported as absent; it is never
/// filled with whatever sibling the stored index has at that height.
#[test]
fn broken_ancestry_reads_absent_not_as_a_sibling() {
    let n = Node::fresh();
    let g = mk(0, 0, Hash::default());
    let a1 = mk(0, 1, g.hash());
    let a2 = mk(0, 2, a1.hash()); // never stored
    let a3 = mk(0, 3, a2.hash());
    let s2 = mk(1, 2, a1.hash()); // a stored sibling at the hole's height
    for b in [&g, &a1, &s2, &a3] {
        n.put(b);
    }
    n.commit_tip(a3.hash(), 3);
    assert_eq!(n.by_number(3), Some(a3.hash()));
    assert_eq!(n.by_number(2), None, "the hole: unknown, not the sibling");
    assert_eq!(n.by_number(1), None, "below the hole: unknown, not a guess");
    assert_eq!(n.by_number(0), None);
}

/// Readers racing a writer that flips the tip between two branches only ever
/// see a block of one of the two branches, never the later-written sibling.
#[test]
fn concurrent_reads_during_reorgs_never_name_a_sibling() {
    let n = Arc::new(Node::fresh());
    let a = put_branch(&n, 0, Hash::default(), 0, 200);
    let b = put_branch(&n, 1, a[10].hash(), 11, 200);
    // Written last: the stored index names these at 11..=200.
    let c = put_branch(&n, 2, a[10].hash(), 11, 200);
    n.commit_tip(a[200].hash(), 200);
    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..3)
        .map(|r| {
            let (n, a, b, c, stop) = (n.clone(), a.clone(), b.clone(), c.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut seen = 0u64;
                let mut h = 11 + r;
                while !stop.load(Ordering::Relaxed) {
                    let got = n.by_number(h).expect("height at or below the tip");
                    assert_ne!(got, c[h as usize - 11].hash(), "sibling named at {h}");
                    assert!(
                        got == a[h as usize].hash() || got == b[h as usize - 11].hash(),
                        "height {h}: not on either applied branch"
                    );
                    seen += 1;
                    h = 11 + (h + 37) % 190;
                }
                seen
            })
        })
        .collect();
    for i in 0..200 {
        if i % 2 == 0 {
            n.reorg_tip(b[189].hash(), 200);
        } else {
            n.reorg_tip(a[200].hash(), 200);
        }
    }
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        assert!(r.join().expect("reader") > 0);
    }
}
