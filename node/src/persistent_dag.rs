// WP-S.1: RocksDB KvStore implementation for persistent DAG storage.

use citrate_consensus::dag_store::{KvOp, KvStore};
use citrate_storage::db::RocksDB;
use std::sync::Arc;

/// Adapter that implements the consensus crate's `KvStore` trait using `citrate_storage::RocksDB`.
pub struct RocksDbKvStore {
    db: Arc<RocksDB>,
}

impl RocksDbKvStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }
}

impl KvStore for RocksDbKvStore {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.db.get_cf(cf, key).map_err(|e| e.to_string())
    }

    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.db.put_cf(cf, key, value).map_err(|e| e.to_string())
    }

    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
        self.db.delete_cf(cf, key).map_err(|e| e.to_string())
    }

    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
        self.db.exists_cf(cf, key).map_err(|e| e.to_string())
    }

    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        self.db
            .iter_cf(cf)
            .map(|iter| iter.map(|(k, v)| (k.to_vec(), v.to_vec())).collect())
            .map_err(|e| e.to_string())
    }

    /// RM-B1 / WP-B1.3 (audit H-04): override the trait default with
    /// a real RocksDB `WriteBatch` so multi-op block-admission writes
    /// commit atomically. A power loss between two ops can no longer
    /// leave the DAG in a partial state.
    ///
    /// REM-2 / WP-H1.3 (audit M-API-01): commit via `write_batch_sync`
    /// so the DAG persistence batch is fsynced. Pre-fix the non-fsync
    /// `write_batch` could leave the DAG state on the OS page cache;
    /// a power loss between RPC ack and OS flush would silently roll
    /// back finalised DAG admissions.
    fn kv_write_batch(&self, ops: &[KvOp]) -> Result<(), String> {
        let mut batch = self.db.batch();
        for op in ops {
            match op {
                KvOp::Put { cf, key, value } => {
                    self.db
                        .batch_put_cf(&mut batch, cf, key, value)
                        .map_err(|e| e.to_string())?;
                }
                KvOp::Delete { cf, key } => {
                    self.db
                        .batch_delete_cf(&mut batch, cf, key)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        self.db.write_batch_sync(batch).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::checkpoint::{CheckpointConfig, CheckpointManager};
    use citrate_consensus::checkpoint_gadget::{FinalityGadget, SignRefusal};
    use citrate_consensus::crypto::Ed25519SigningKey;
    use citrate_consensus::types::{BlockBuilder, Hash, PublicKey};
    use citrate_consensus::vrf::VrfProposerSelector;
    use citrate_consensus::DagStore;

    fn hash(b: u8) -> Hash {
        Hash::new([b; 32])
    }

    /// Validator process over a real RocksDB at `path`; dropping it closes the DB.
    async fn boot(
        path: &std::path::Path,
        keys: &[Ed25519SigningKey],
    ) -> (FinalityGadget, Arc<RocksDB>) {
        let db = Arc::new(RocksDB::open(path).expect("open rocksdb"));
        let kv: Arc<dyn KvStore> = Arc::new(RocksDbKvStore::new(db.clone()));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        // Height 9 parent, then two competing blocks at the boundary height 10.
        let parent = BlockBuilder::new().hash(hash(9)).height(9).build_unhashed();
        dag.store_block(parent).await.expect("store parent");
        for h in [hash(0xA0), hash(0xB0)] {
            let b = BlockBuilder::new()
                .hash(h)
                .height(10)
                .parent(hash(9))
                .build_unhashed();
            dag.store_block(b).await.expect("store boundary block");
        }
        let cfg = CheckpointConfig {
            interval: 2,
            committee_size: 100,
            quorum_threshold: 67,
            chain_id: 40204,
            vote_depth: 3,
        };
        let sel = VrfProposerSelector::new().with_snapshot_schedule(1000, 999);
        let set: Vec<(PublicKey, u128)> = keys
            .iter()
            .map(|k| (PublicKey::new(k.verifying_key().to_bytes()), 32_000u128))
            .collect();
        sel.sync_active_set_at(1, set, 1).await;
        let mgr = Arc::new(CheckpointManager::with_persistence(cfg, dag, kv));
        (
            FinalityGadget::with_switch(mgr, Some(Arc::new(sel)), true),
            db,
        )
    }

    /// PR #321 P2 on the production store: the signing decision is committed with
    /// a synced (fsync'd) RocksDB write before the vote is emitted, survives a
    /// close/reopen of the database, and blocks a different hash at that height.
    #[tokio::test]
    async fn signed_vote_record_is_synced_and_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys: Vec<Ed25519SigningKey> = (1u8..=4)
            .map(|i| Ed25519SigningKey::from_bytes(&[i; 32]))
            .collect();
        let me = keys.first().expect("validator key");
        let seed = hash(0x77);
        {
            let (g, db) = boot(dir.path(), &keys).await;
            let syncs_before = db.write_batch_sync_count();
            let out = g
                .on_buried_checkpoint(10, hash(0xA0), &seed, Some(me))
                .await;
            assert!(out.signed_own_vote);
            assert!(
                db.write_batch_sync_count() > syncs_before,
                "record committed via write_batch_sync"
            );
        }
        // Restart: the DB is closed and reopened; the canonical block at 10 is B.
        let (g, _db) = boot(dir.path(), &keys).await;
        assert_eq!(g.signed_vote_at(10), Some(hash(0xA0)));
        let out = g
            .on_buried_checkpoint(10, hash(0xB0), &seed, Some(me))
            .await;
        assert!(!out.signed_own_vote && out.outbound.is_empty());
        assert_eq!(
            out.sign_refused,
            Some(SignRefusal::Conflicting { signed: hash(0xA0) })
        );
    }
}
