// citrate/core/api/tests/by_number_canonical.rs
//
// chain#421: every RPC method that takes a block NUMBER names the block on the
// executed (selected-parent) chain of the applied tip at that height. Before the
// fix they read the store's height index, which keeps the LAST block stored at a
// height: a sibling stored after the executed block (a competing producer, a
// late fork delivery, a follower's height-group order) was served instead.
//
// The tip is moved with `put_applied_tip`, the write the canonical applicator
// makes when it applies or reorgs.

use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::{json, Value};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tempfile::TempDir;

fn hash_of(tag: u8, n: u64) -> Hash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = tag;
    Hash::new(h)
}

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

fn storage() -> (Arc<StorageManager>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let s = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    (s, tmp)
}

fn io(storage: Arc<StorageManager>) -> jsonrpc_core::IoHandler {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    register_eth_methods_with_finality(
        &mut io,
        storage,
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
        Arc::new(AtomicU64::new(0)),
    );
    io
}

fn call(io: &jsonrpc_core::IoHandler, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let resp = io.handle_request_sync(&req).expect("response");
    let v: Value = serde_json::from_str(&resp).expect("json");
    assert!(v.get("error").is_none(), "{method}: unexpected error: {v}");
    v["result"].clone()
}

/// Store a block on `parent` carrying `txs` transactions (so blocks at the same
/// height are told apart by count too).
fn put(storage: &StorageManager, tag: u8, height: u64, parent: Hash, txs: usize) -> Block {
    let txs = (0..txs)
        .map(|i| Transaction {
            hash: hash_of(tag ^ (0x10 + i as u8), height),
            nonce: i as u64,
            from: PublicKey::new([1u8; 32]),
            to: Some(PublicKey::new([2u8; 32])),
            gas_limit: 50_000,
            gas_price: 2_000_000_000,
            signature: Signature::new([7u8; 64]),
            chain_id: Some(40204),
            ..Default::default()
        })
        .collect();
    let b = BlockBuilder::new()
        .hash(hash_of(tag, height))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .gas_limit(30_000_000)
        .transactions(txs)
        .build_unhashed();
    storage.blocks.put_block(&b).expect("block");
    b
}

fn branch(
    storage: &StorageManager,
    tag: u8,
    parent: Hash,
    from: u64,
    to: u64,
    txs: usize,
) -> Vec<Block> {
    let mut out = Vec::new();
    let mut p = parent;
    for h in from..=to {
        let b = put(storage, tag, h, p, txs);
        p = b.hash();
        out.push(b);
    }
    out
}

fn tip(storage: &StorageManager, b: &Block) {
    storage
        .blocks
        .put_applied_tip(&b.hash(), b.header.height)
        .expect("applied tip");
}

fn block_hash_at(io: &jsonrpc_core::IoHandler, h: u64) -> String {
    call(
        io,
        "eth_getBlockByNumber",
        json!([format!("0x{h:x}"), false]),
    )["hash"]
        .as_str()
        .unwrap_or("null")
        .to_string()
}

/// A competing producer's sibling is stored after the executed block at every
/// height: each by-number method answers with the executed block.
#[test]
fn by_number_methods_name_the_executed_block_not_the_later_sibling() {
    let (s, _t) = storage();
    let a = branch(&s, 0xA0, Hash::default(), 0, 12, 1);
    let b = branch(&s, 0xB0, a[4].hash(), 5, 12, 2); // stored after A
    tip(&s, &a[12]);
    let io = io(s.clone());

    for h in 5..=12u64 {
        assert_eq!(
            block_hash_at(&io, h),
            hx(&a[h as usize].hash()),
            "eth_getBlockByNumber({h})"
        );
        assert_ne!(block_hash_at(&io, h), hx(&b[h as usize - 5].hash()));
    }
    assert_eq!(
        call(&io, "eth_getBlockTransactionCountByNumber", json!(["0x7"])),
        json!("0x1"),
        "the executed block has one tx, the sibling two"
    );
    assert_eq!(
        call(
            &io,
            "eth_getTransactionByBlockNumberAndIndex",
            json!(["0x7", "0x0"])
        )["blockHash"],
        json!(hx(&a[7].hash()))
    );
    // parentHash links of consecutive by-number answers form one chain.
    for h in 1..=12u64 {
        let blk = call(
            &io,
            "eth_getBlockByNumber",
            json!([format!("0x{h:x}"), false]),
        );
        assert_eq!(
            blk["parentHash"].as_str(),
            Some(block_hash_at(&io, h - 1).as_str())
        );
    }
}

/// Thousands of blocks deep, across a reorg away and back: by-number agrees
/// with the parent-link walk from the tip at every height.
#[test]
fn deep_reorg_by_number_matches_the_parent_walk_at_every_height() {
    let (s, _t) = storage();
    let a = branch(&s, 0xA0, Hash::default(), 0, 2_500, 1);
    let b = branch(&s, 0xB0, a[1_000].hash(), 1_001, 2_500, 1); // stored after A
    let io = io(s.clone());

    let walk_matches = |io: &jsonrpc_core::IoHandler, top: u64| -> Vec<u64> {
        let mut bad = Vec::new();
        let mut want = block_hash_at(io, top);
        for h in (0..=top).rev() {
            let blk = call(
                io,
                "eth_getBlockByNumber",
                json!([format!("0x{h:x}"), false]),
            );
            if blk["hash"].as_str() != Some(want.as_str()) {
                bad.push(h);
            }
            want = blk["parentHash"].as_str().unwrap_or_default().to_string();
        }
        bad
    };

    tip(&s, &a[2_500]);
    assert_eq!(walk_matches(&io, 2_500), Vec::<u64>::new(), "on A");
    assert_eq!(block_hash_at(&io, 2_000), hx(&a[2_000].hash()));
    tip(&s, &b[1_499]);
    assert_eq!(block_hash_at(&io, 2_000), hx(&b[999].hash()));
    assert_eq!(walk_matches(&io, 2_500), Vec::<u64>::new(), "on B");
    tip(&s, &a[2_500]);
    assert_eq!(block_hash_at(&io, 2_000), hx(&a[2_000].hash()), "back on A");
}

/// A block filter announces the executed block at each new height.
#[test]
fn block_filter_announces_the_executed_block() {
    let (s, _t) = storage();
    let a = branch(&s, 0xA0, Hash::default(), 0, 2, 1);
    tip(&s, &a[2]);
    let io = io(s.clone());
    let id = call(&io, "eth_newBlockFilter", json!([]));
    let a3 = put(&s, 0xA0, 3, a[2].hash(), 1);
    let a4 = put(&s, 0xA0, 4, a3.hash(), 1);
    put(&s, 0xB0, 3, a[2].hash(), 2); // sibling stored last
    tip(&s, &a4);
    let got = call(&io, "eth_getFilterChanges", json!([id]));
    assert_eq!(got, json!([hx(&a3.hash()), hx(&a4.hash())]));
}
