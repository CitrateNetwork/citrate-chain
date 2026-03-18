// citrate/node/src/sync/mod.rs

//! Efficient sync module for GhostDAG blockchain synchronization.
//!
//! This module provides non-recursive, memory-bounded block synchronization
//! that can handle deep chains and large block ranges without stack overflow.

mod efficient_sync;

// Re-exports available if needed:
// pub use efficient_sync::{EfficientSyncManager, ParallelSyncCoordinator, SyncResult};
