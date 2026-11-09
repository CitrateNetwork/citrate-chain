// Fixture (rpc-finality-height-index, positive): `finalized` and a log range resolved through
// the height index, which can hold an uncertified sibling. Each marked call must be flagged.
pub fn register(
    io_handler: &mut IoHandler,
    storage: Arc<StorageManager>,
    finalized: Arc<AtomicU64>,
) {
    io_handler.add_sync_method("eth_getBlockByNumber", move |params: Params| {
        let n = match resolve_block_tag(arg(&params, 0).as_str(), 0, finalized.load(SeqCst)) {
            Some(n) => n,
            None => return Err(invalid()),
        };
        let hash = storage.blocks.get_block_by_height(n); // FLAG
        Ok(to_json(hash))
    });

    io_handler.add_sync_method("eth_getLogs", move |params: Params| {
        let (from, to) = range(&params);
        for height in from..=to {
            let found = storage.blocks.get_block_by_height(height); // FLAG
            if let Ok(Some(h)) = found {
                collect(h);
            }
        }
        Ok(Value::Null)
    });
}

fn finalized_block(storage: &StorageManager, finalized_height: u64) -> Option<Hash> {
    let found = storage.blocks.get_block_by_height(finalized_height); // FLAG
    found.ok().flatten()
}

pub fn register_lookup(
    io_handler: &mut IoHandler,
    storage: Arc<StorageManager>,
    finalized: Arc<AtomicU64>,
) {
    io_handler.add_sync_method(
        "eth_getBlockTransactionCountByNumber",
        move |params: Params| {
            let api = ChainApi::new(storage.clone());
            let n = resolve_block_tag(arg(&params, 0).as_str(), 0, finalized.load(SeqCst)); // FLAG
            Ok(count(block_on(api.get_block(BlockId::Number(n?)))))
        },
    );
}
