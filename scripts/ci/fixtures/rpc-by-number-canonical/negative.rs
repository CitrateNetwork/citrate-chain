// Fixture: by-number reads that follow the executed chain, and the genesis lookup.
fn by_number(storage: &StorageManager, n: u64) -> Option<Hash> {
    storage.blocks.get_canonical_block_by_height(n).ok().flatten()
}

fn genesis(storage: &StorageManager) -> Option<Hash> {
    storage.blocks.get_block_by_height(0).ok().flatten()
}

fn genesis_split(storage: &StorageManager) -> Option<Hash> {
    storage
        .blocks
        .get_block_by_height(0)
        .ok()
        .flatten()
}

// A comment naming get_block_by_height(h) is not a call.
fn described() -> &'static str {
    "get_block_by_height(h) in a string is not a call"
}

#[cfg(test)]
mod tests {
    fn t(storage: &StorageManager) {
        let _ = storage.blocks.get_block_by_height(5);
    }
}
