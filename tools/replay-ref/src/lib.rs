// citrate/tools/replay-ref/src/lib.rs
//
// Differential replay harness (r1007 S3-3c; spec 06_CONSENSUS_SPEC section 8.3;
// ADR-2026-11-03 CV-4a, CV-14).
//
// Three parts:
//
// 1. `recorder`: reads a node's RocksDB data dir READ-ONLY and dumps every
//    stored block (headers and bodies, the whole DAG), the node's applied
//    selected chain (applied tip down to genesis by selected-parent links) and,
//    per chain block, the state root the node committed for it. Written as one
//    compact file (`Recording::write_to`: bincode, deflate-compressed).
//
// 2. `reference`: an independent replay of the recording. It recomputes the
//    world state from the genesis allocation along the recorded selected chain,
//    with the from-scratch state root (the current semantics: `calculate_state_root`
//    rebuilds the account trie from the full resident state on every call), and
//    compares, block by block, the reference root with the block's header root
//    and with the root the node committed. It shares only the trusted base with
//    the node: block/tx types, the executor (revm, settlement), the reward
//    schedule and the on-disk layout. It never imports the node crate, so the
//    node's apply machinery under test (`canonical_apply`: drain, reorgs, the
//    undo window, restarts, the from-genesis rebuild) is checked against a plain
//    linear replay.
//
// 3. The `replay-diff <recording>` CLI (`src/bin/replay_diff.rs`), which prints
//    the first divergence, and `replay-record` (`src/bin/replay_record.rs`).
//
// Modes. `selected-chain` (`reference::SelectedChain`): a chain block
// executes its own transactions through the node's executor (r1006
// semantics). `mergeset` (`mergeset::replay_mergeset`, r1007 S3-3b): the
// recording goes through the INDEPENDENT reference `citrate-mergeset-ref`,
// which shares no execution code with the node, and is compared on state
// roots, receipt roots, accepted roots, gas and the accepted lists.

pub mod mergeset;
pub mod recorder;
pub mod recording;
pub mod reference;

pub use mergeset::{reference_config, replay_mergeset};
pub use recorder::{record_data_dir, record_db};
pub use recording::{ChainEntry, RecordedRewardPolicy, Recording, ReplayConfig, FORMAT_VERSION};
pub use reference::{
    full_hash, reference_reward_config, replay, Divergence, Field, OrderingMode, Report,
    SelectedChain,
};
