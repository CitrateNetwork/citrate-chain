#![no_main]
use libfuzzer_sys::fuzz_target;
use citrate_execution::state::Trie;
use citrate_consensus::types::Hash;

fuzz_target!(|data: &[u8]| {
    // Fuzz state DB key construction and trie operations with arbitrary bytes.
    // Exercises the Merkle Patricia Trie insert/get/remove/root_hash paths
    // to ensure no panics on malformed keys or values.

    if data.len() < 2 {
        return;
    }

    let mut trie = Trie::new();

    // Split fuzz data into key/value pairs and operations
    let mut offset = 0;
    while offset + 2 <= data.len() {
        let key_len = (data[offset] as usize).min(data.len() - offset - 1);
        offset += 1;
        if offset + key_len > data.len() {
            break;
        }
        let key = data[offset..offset + key_len].to_vec();
        offset += key_len;

        // Determine operation from remaining data
        if offset < data.len() {
            let op = data[offset] % 4;
            offset += 1;

            match op {
                0 => {
                    // Insert: use remaining bytes as value
                    let val_len = if offset < data.len() {
                        (data[offset] as usize).min(data.len() - offset - 1)
                    } else {
                        0
                    };
                    if offset + 1 + val_len <= data.len() {
                        offset += 1;
                        let value = data[offset..offset + val_len].to_vec();
                        offset += val_len;
                        trie.insert(key, value);
                    }
                }
                1 => {
                    // Get
                    let _ = trie.get(&key);
                }
                2 => {
                    // Remove
                    trie.remove(&key);
                }
                3 => {
                    // Root hash computation
                    let _: Hash = trie.root_hash();
                }
                _ => {}
            }
        }
    }

    // Always compute final root hash to exercise hashing path
    let _: Hash = trie.root_hash();
});
