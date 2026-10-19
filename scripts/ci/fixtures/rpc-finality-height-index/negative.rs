// Fixture (rpc-finality-height-index, negative): finalized resolves by certified hash, logs walk
// the executed chain, and a plain number lookup with no finality logic uses the height index.
// Nothing here may be flagged.
pub fn register(
    io_handler: &mut IoHandler,
    storage: Arc<StorageManager>,
    finalized: FinalizedTagSource,
) {
    io_handler.add_sync_method("eth_getBlockByNumber", move |params: Params| {
        let id = resolve_block_id(arg(&params, 0).as_str(), 0, finalized.resolve(&storage));
        Ok(to_json(storage.blocks.get_block(id)))
    });

    io_handler.add_sync_method("eth_getLogs", move |params: Params| {
        let hashes = range_block_hashes(&storage, &params)?; // executed chain, not the height index
        Ok(collect(hashes))
    });
}

/// A plain height lookup: no tag, no range.
pub fn block_hash_at(storage: &StorageManager, height: u64) -> Option<Hash> {
    storage.blocks.get_block_by_height(height).ok().flatten()
}

#[cfg(test)]
mod tests {
    fn finalized_lookup(storage: &StorageManager, finalized_height: u64) {
        let _ = storage.blocks.get_block_by_height(finalized_height);
    }
}
