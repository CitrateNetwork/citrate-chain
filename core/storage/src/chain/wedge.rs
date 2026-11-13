// citrate/core/storage/src/chain/wedge.rs
//
// The durable dead-branch marker (ADR-2026-11-03 CV-7b, root cause H6).
//
// A node whose fork-choice head sits on a branch it cannot switch to (the fork
// point is below its reorg window and its DAG store is pruned, so a rebuild
// from genesis is refused) keeps its applied tip on a branch the network no
// longer extends. Without a record of that, it keeps advertising and serving
// that branch as its current chain, and peers that sync from it inherit it.
//
// The marker is written by the applicator when it refuses the switch and is
// read by everything that presents "this node's chain" to the outside: block
// serving, the advertised head, the producer's seal gate and the `syncState`
// RPC field. It lives in the chain database, so it survives a restart and goes
// away with the chain data on a cold resync.

use crate::db::{column_families::CF_METADATA, RocksDB};
use anyhow::Result;
use citrate_consensus::types::Hash;
use serde::{Deserialize, Serialize};

/// `CF_METADATA` key of the marker. Not height-prefixed (`h` + 8 bytes), so
/// the height-index scans never read it.
const WEDGE_KEY: &[u8] = b"sync_wedge:dead_branch";

/// Why the applied branch is dead, and where it leaves the network's chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WedgeRecord {
    /// The applied tip the node is held on (the dead branch's top).
    pub dead_tip: Hash,
    pub dead_tip_height: u64,
    /// The highest block shared by the dead branch and the fork-choice head.
    pub fork_point: Hash,
    pub fork_height: u64,
    /// The fork-choice head the switch was refused toward.
    pub head: Hash,
    pub head_height: u64,
    /// The refusal, as the applicator logged it.
    pub reason: String,
    /// Unix seconds when the refusal was first recorded.
    pub since_unix: u64,
}

impl WedgeRecord {
    /// Applied blocks the switch would abandon.
    pub fn fork_depth(&self) -> u64 {
        self.dead_tip_height.saturating_sub(self.fork_height)
    }

    /// Whether block `hash` at `height` is on the dead branch above the fork
    /// point, given the applied chain's block at that height
    /// (`canonical_at_height`).
    pub fn is_dead_block(
        &self,
        height: u64,
        hash: &Hash,
        canonical_at_height: Option<Hash>,
    ) -> bool {
        height > self.fork_height
            && height <= self.dead_tip_height
            && canonical_at_height.as_ref() == Some(hash)
    }
}

/// The marker, or `None` when the node is not held on a dead branch. A record
/// that does not decode is reported as an error, never as "not wedged".
pub fn read(db: &RocksDB) -> Result<Option<WedgeRecord>> {
    match db.get_cf(CF_METADATA, WEDGE_KEY)? {
        Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
        None => Ok(None),
    }
}

/// Record the marker durably (fsync'd batch).
pub fn write(db: &RocksDB, record: &WedgeRecord) -> Result<()> {
    let bytes = bincode::serialize(record)?;
    let mut batch = db.batch();
    db.batch_put_cf(&mut batch, CF_METADATA, WEDGE_KEY, &bytes)?;
    db.write_batch_sync(batch)
}

/// Remove the marker durably.
pub fn clear(db: &RocksDB) -> Result<()> {
    let mut batch = db.batch();
    db.batch_delete_cf(&mut batch, CF_METADATA, WEDGE_KEY)?;
    db.write_batch_sync(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn record() -> WedgeRecord {
        WedgeRecord {
            dead_tip: Hash::new([1; 32]),
            dead_tip_height: 5_100,
            fork_point: Hash::new([2; 32]),
            fork_height: 100,
            head: Hash::new([3; 32]),
            head_height: 5_200,
            reason: "refused".into(),
            since_unix: 7,
        }
    }

    #[test]
    fn wedge_marker_survives_reopen_and_clears() {
        let dir = TempDir::new().expect("tempdir");
        {
            let db = RocksDB::open(dir.path()).expect("open");
            assert_eq!(read(&db).expect("read"), None);
            write(&db, &record()).expect("write");
        }
        let db = RocksDB::open(dir.path()).expect("reopen");
        let got = read(&db).expect("read").expect("marker kept across reopen");
        assert_eq!(got, record());
        assert_eq!(got.fork_depth(), 5_000);
        clear(&db).expect("clear");
        assert_eq!(read(&db).expect("read"), None);
    }

    #[test]
    fn dead_block_is_the_applied_chain_above_the_fork_point() {
        let r = record();
        let h = Hash::new([9; 32]);
        assert!(r.is_dead_block(101, &h, Some(h)));
        assert!(r.is_dead_block(5_100, &h, Some(h)));
        assert!(
            !r.is_dead_block(100, &h, Some(h)),
            "the fork point is shared"
        );
        assert!(!r.is_dead_block(5_101, &h, Some(h)));
        assert!(
            !r.is_dead_block(200, &h, Some(Hash::new([8; 32]))),
            "a sibling of the applied chain is not the dead branch"
        );
        assert!(!r.is_dead_block(200, &h, None));
    }
}
