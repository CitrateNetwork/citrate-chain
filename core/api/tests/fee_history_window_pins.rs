// Pins the `eth_feeHistory` block-window clamp at the registered handler.
//
// The existing bound tests seed fewer than 1024 blocks, so the chain height
// already limits the window and the 1024-block clamp was never reached:
// removing it left them green. Here the chain is taller than the clamp, so
// only the clamp keeps the window at 1024 blocks. Local only: in-process
// handler, temp-dir storage, no network.

use citrate_api::eth_rpc::FEE_HISTORY_MAX_BLOCKS;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{BlockBuilder, Hash};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::sync::Arc;
use tempfile::TempDir;

/// A chain of `n` empty blocks above genesis.
fn storage_with_blocks(n: u64) -> (Arc<StorageManager>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let genesis = BlockBuilder::new()
        .hash(Hash::new([0xEE; 32]))
        .parent(Hash::default())
        .height(0)
        .build_unhashed();
    storage.blocks.put_block(&genesis).expect("genesis");
    let mut parent = genesis.hash();
    for h in 1..=n {
        let mut hb = [0u8; 32];
        hb[..8].copy_from_slice(&h.to_be_bytes());
        hb[31] = 0xAB;
        let b = BlockBuilder::new()
            .hash(Hash::new(hb))
            .parent(parent)
            .height(h)
            .timestamp(1_000_000 + h)
            .gas_limit(30_000_000)
            .base_fee_per_gas(1_000_000_000)
            .build_unhashed();
        storage.blocks.put_block(&b).expect("block");
        parent = b.hash();
    }
    (storage, tmp)
}

fn eth_io(storage: Arc<StorageManager>) -> jsonrpc_core::IoHandler {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage,
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
    );
    io
}

fn fee_history(io: &jsonrpc_core::IoHandler, block_count: &str) -> serde_json::Value {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["{block_count}","latest",[]]}}"#
    );
    serde_json::from_str(&io.handle_request_sync(&req).expect("response")).expect("json")
}

fn window_len(v: &serde_json::Value) -> usize {
    v["result"]["gasUsedRatio"]
        .as_array()
        .unwrap_or_else(|| panic!("gasUsedRatio array in {v}"))
        .len()
}

#[test]
fn fee_history_window_is_clamped_when_the_chain_is_taller_than_the_limit() {
    let max = FEE_HISTORY_MAX_BLOCKS as usize;
    let (storage, _tmp) = storage_with_blocks(FEE_HISTORY_MAX_BLOCKS + 200);
    let io = eth_io(storage);

    for asked in ["0x800", "0x10000", "0xffffffffffffffff"] {
        let v = fee_history(&io, asked);
        assert!(
            v.get("error").is_none(),
            "blockCount {asked} is clamped, not refused: {v}"
        );
        assert_eq!(
            window_len(&v),
            max,
            "blockCount {asked} must be served as a {max}-block window"
        );
        let base_fees = v["result"]["baseFeePerGas"]
            .as_array()
            .expect("baseFeePerGas")
            .len();
        assert!(
            base_fees <= max + 1,
            "baseFeePerGas has {base_fees} entries for blockCount {asked}"
        );
    }
}

#[test]
fn fee_history_window_below_the_limit_is_served_in_full() {
    let (storage, _tmp) = storage_with_blocks(FEE_HISTORY_MAX_BLOCKS + 200);
    let io = eth_io(storage);
    assert_eq!(window_len(&fee_history(&io, "0x10")), 16);
    assert_eq!(
        window_len(&fee_history(&io, "0x400")),
        FEE_HISTORY_MAX_BLOCKS as usize
    );
}
