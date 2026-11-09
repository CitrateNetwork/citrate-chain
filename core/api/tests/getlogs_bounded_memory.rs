// eth_getLogs holds one block body at a time, not the whole range.
//
// A counting global allocator measures the peak heap growth of one
// maximum-range query whose address filter matches nothing, over blocks that
// each carry a large transaction payload. Holding every body of the range would
// grow the heap by the sum of the payloads; streaming one block at a time grows
// it by about one block. This file holds a single test so no other test's
// allocations land in the measurement.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use citrate_api::canonical_logs::MAX_LOG_BLOCK_RANGE;
use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_execution::types::{Address, Log, TransactionReceipt};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::Value;
use tempfile::TempDir;

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwards the caller's layout contract to the system allocator.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` was returned by `alloc` above with this `layout`.
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const PAYLOAD: usize = 64 * 1024;

fn hash_of(tag: u8, n: u64) -> Hash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = tag;
    Hash::new(h)
}

#[test]
fn max_range_nonmatching_query_holds_one_block_at_a_time() {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));

    let top = MAX_LOG_BLOCK_RANGE;
    let mut parent = Hash::default();
    for h in 0..=top {
        let t = Transaction {
            hash: hash_of(0x11, h),
            nonce: h,
            from: PublicKey::new([1u8; 32]),
            to: Some(PublicKey::new([2u8; 32])),
            gas_limit: 50_000,
            gas_price: 2_000_000_000,
            signature: Signature::new([7u8; 64]),
            chain_id: Some(40204),
            data: vec![0xAB; PAYLOAD],
            ..Default::default()
        };
        let b = BlockBuilder::new()
            .hash(hash_of(0xA0, h))
            .parent(parent)
            .height(h)
            .timestamp(1_000_000 + h)
            .gas_limit(30_000_000)
            .transactions(vec![t.clone()])
            .build_unhashed();
        storage.blocks.put_block(&b).expect("block");
        let r = TransactionReceipt {
            tx_hash: t.hash,
            block_hash: b.hash(),
            block_number: h,
            from: Address([1u8; 20]),
            to: Some(Address([2u8; 20])),
            gas_used: 30_000,
            status: true,
            logs: vec![Log {
                address: Address([0xC0; 20]),
                topics: vec![hash_of(0x22, h)],
                data: vec![1],
            }],
            output: vec![],
            eth_tx_type: 0,
            effective_gas_price: 2_000_000_000,
            revert_reason: None,
        };
        storage
            .transactions
            .put_receipt(&t.hash, &r)
            .expect("receipt");
        parent = b.hash();
    }
    storage.blocks.put_applied_tip(&parent, top).expect("tip");

    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    register_eth_methods_with_finality(
        &mut io,
        storage.clone(),
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
        Arc::new(AtomicU64::new(0)),
    );
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
        "params": [{
            "fromBlock": "0x0",
            "toBlock": format!("0x{top:x}"),
            "address": format!("0x{}", "dd".repeat(20)),
        }],
    })
    .to_string();

    let base = CURRENT.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let resp = io.handle_request_sync(&req).expect("response");
    let growth = PEAK.load(Ordering::Relaxed).saturating_sub(base);

    let v: Value = serde_json::from_str(&resp).expect("json");
    assert_eq!(v["result"], serde_json::json!([]), "{v}");
    let range_bytes = (top as usize + 1) * PAYLOAD;
    // About one block plus fixed overhead; holding the range would be ~64 MiB.
    assert!(
        growth < 16 * PAYLOAD,
        "peak heap growth {growth} bytes for a range of {range_bytes} payload bytes"
    );
}
