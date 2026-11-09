// citrate/core/execution/src/state/mod.rs

// State management module
// Handles account states, caching, and trie operations

pub mod account;
pub mod cache;
pub mod mpt;
pub mod mpt_state;
pub mod slot_map;
pub mod state_db;
pub mod trie;

pub use account::AccountManager;
pub use state_db::{StateDB, StateProof, StateRoot, StateSnapshot, StorageProof, TrieReuse};
pub use trie::{Trie, TrieNode};
