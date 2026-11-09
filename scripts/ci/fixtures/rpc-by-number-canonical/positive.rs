// Fixture: by-number reads through the STORED height index (last block stored wins).
fn by_number(storage: &StorageManager, n: u64) -> Option<Hash> {
    storage.blocks.get_block_by_height(n).ok().flatten() // FLAG
}

#[rustfmt::skip]
fn range(storage: &StorageManager, from: u64, to: u64) {
    for h in from..=to {
        let _ = storage
            .blocks
            .get_block_by_height(h + 1); // FLAG
    }
}

#[rustfmt::skip]
fn split_argument(storage: &StorageManager, head: u64) {
    let _ = storage.blocks.get_block_by_height( // FLAG
        head,
    );
}

fn latest(storage: &StorageManager, head: u64) {
    let _ = storage.blocks.get_block_by_height(head); // FLAG
}
