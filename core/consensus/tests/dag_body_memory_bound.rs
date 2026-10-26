// Memory bound for the persistent DAG store's in-memory block map.
//
// A persistent `DagStore` writes every block (header AND transaction bodies)
// through to its KV backend, but it also kept every full block in its in-memory
// `HashMap<Hash, Block>` forever. On a producer under sustained load that is a
// per-transaction retention which is never freed: every included transaction
// stays resident for the life of the process.
//
// The bound: only the most recent `resident_body_cap` blocks keep their bodies
// in memory; older entries keep the header (all DAG / fork-choice code needs)
// and `get_block` reloads the body from the backend, byte-identical.
//
// The test measures the heap with a counting global allocator, so it asserts
// the behaviour (bytes retained per block), not an internal counter. The KV
// backend is file-backed so its bytes are on disk, not on the counted heap.
// This file holds exactly ONE #[test] so no concurrent test pollutes the count.

use citrate_consensus::dag_store::{KvOp, KvStore};
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Transaction};
use citrate_consensus::DagStore;
use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

struct Counting;
static LIVE: AtomicI64 = AtomicI64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as i64 - l.size() as i64, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static A: Counting = Counting;

fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

/// File-backed KV: one file per (cf, key) under a private temp dir.
struct FileKv {
    root: PathBuf,
}

impl FileKv {
    fn path(&self, cf: &str, key: &[u8]) -> PathBuf {
        self.root.join(cf).join(hex::encode(key))
    }
}

impl KvStore for FileKv {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        match std::fs::read(self.path(cf, key)) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let p = self.path(cf, key);
        std::fs::create_dir_all(p.parent().ok_or("no parent")?).map_err(|e| e.to_string())?;
        std::fs::write(p, value).map_err(|e| e.to_string())
    }
    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
        match std::fs::remove_file(self.path(cf, key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
        Ok(self.path(cf, key).exists())
    }
    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let dir = self.root.join(cf);
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.to_string()),
        };
        for ent in rd {
            let ent = ent.map_err(|e| e.to_string())?;
            let name = ent.file_name().to_string_lossy().to_string();
            let key = hex::decode(&name).map_err(|e| e.to_string())?;
            out.push((key, std::fs::read(ent.path()).map_err(|e| e.to_string())?));
        }
        Ok(out)
    }
    fn kv_write_batch(&self, ops: &[KvOp]) -> Result<(), String> {
        for op in ops {
            match op {
                KvOp::Put { cf, key, value } => self.kv_put(cf, key, value)?,
                KvOp::Delete { cf, key } => self.kv_delete(cf, key)?,
            }
        }
        Ok(())
    }
}

const TXS_PER_BLOCK: usize = 40;
const TX_DATA: usize = 200;

fn block(height: u64, parent: Hash) -> Block {
    let mut hb = [0u8; 32];
    hb[..8].copy_from_slice(&height.to_be_bytes());
    hb[31] = 0xB1;
    let txs: Vec<Transaction> = (0..TXS_PER_BLOCK)
        .map(|i| {
            let mut th = [0u8; 32];
            th[..8].copy_from_slice(&height.to_be_bytes());
            th[8..16].copy_from_slice(&(i as u64).to_be_bytes());
            Transaction {
                hash: Hash::new(th),
                nonce: height,
                from: PublicKey::new([7u8; 32]),
                data: vec![(i % 251) as u8; TX_DATA],
                ..Default::default()
            }
        })
        .collect();
    BlockBuilder::new()
        .hash(Hash::new(hb))
        .height(height)
        .parent(parent)
        .transactions(txs)
        .build_unhashed()
}

fn private_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "dgx-dag-body-bound-{}-{}",
        std::process::id(),
        nanos
    ))
}

fn remove_exact(dir: &Path) {
    // Only ever the exact directory this test created.
    if dir
        .file_name()
        .map(|n| n.to_string_lossy().starts_with("dgx-dag-body-bound-"))
        .unwrap_or(false)
    {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn persistent_dag_store_does_not_retain_old_block_bodies() {
    let dir = private_dir();
    std::fs::create_dir_all(&dir).expect("temp dir");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            let kv = Arc::new(FileKv { root: dir.clone() });
            let store = DagStore::persistent_with_strict_vrf(kv, false).expect("store");

            const WARMUP: u64 = 600;
            const MEASURED: u64 = 1_400;
            let mut parent = Hash::default();
            let mut kept = Vec::new();
            for h in 1..=WARMUP {
                let b = block(h, parent);
                parent = b.hash();
                if h == 1 {
                    kept.push(b.clone());
                }
                store.store_block(b).await.expect("store");
            }
            let base = live();
            for h in (WARMUP + 1)..=(WARMUP + MEASURED) {
                let b = block(h, parent);
                parent = b.hash();
                store.store_block(b).await.expect("store");
            }
            let grown = live() - base;
            let per_block = grown / MEASURED as i64;
            let body_bytes = (TXS_PER_BLOCK * TX_DATA) as i64;
            eprintln!(
                "heap grew {grown} B over {MEASURED} blocks = {per_block} B/block \
                 (each body carries >= {body_bytes} B of tx data)"
            );
            // Header + index entries are a few hundred bytes per block. A retained
            // body is >= 8,000 B of tx payload alone. Allow 2 KiB/block.
            assert!(
                per_block < 2_048,
                "DAG store retained {per_block} B per block: old block bodies are kept in memory"
            );

            // The body of an old block still comes back byte-identical.
            let old = &kept[0];
            let got = store.get_block(&old.hash()).await.expect("old block");
            assert_eq!(got.transactions.len(), TXS_PER_BLOCK);
            assert_eq!(
                bincode::serialize(&got).expect("ser"),
                bincode::serialize(old).expect("ser"),
                "a stripped block must reload byte-identical from the backend"
            );
            let at_h = store.get_blocks_at_height(1).await;
            assert_eq!(at_h.len(), 1);
            assert_eq!(at_h[0].transactions.len(), TXS_PER_BLOCK);
        })
    }));
    remove_exact(&dir);
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
