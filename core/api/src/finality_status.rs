// citrate/core/api/src/finality_status.rs
//
// `citrate_getFinalityStatus` (spec 06 §5.5, 02 §3; ADR CV-8): the real
// checkpoint-finality state of this node, never a block-depth estimate.
//
// DATA SOURCE. The node's `CheckpointManager` (core/consensus/src/checkpoint.rs):
// the latest finalized certificate (in memory, else `DAG_METADATA`
// `checkpoint:{height}` in RocksDB) and the pending checkpoints with their
// collected votes; plus the compiled switches (`checkpoint_gadget::
// CHECKPOINT_VOTING_FROM_GENESIS`, `CHECKPOINT_ENFORCEMENT_GENESES`) and the
// finality gadget's safety stop. The node's finality driver reads those on
// every pass and publishes a [`FinalityStatusView`] into the shared
// [`FinalityStatusCell`]; this method serves the last published view. Before
// the first publication it reports `published: false` and no checkpoint,
// never an invented one.

use citrate_consensus::checkpoint::quorum_stake;
use citrate_consensus::types::Hash;
use jsonrpc_core::{IoHandler, Params};
use serde_json::{json, Value};
use std::sync::{Arc, RwLock};

/// RPC method name.
pub const FINALITY_STATUS_METHOD: &str = "citrate_getFinalityStatus";

/// Where the response's data comes from (also returned in the response).
pub const FINALITY_STATUS_SOURCE: &str = "CheckpointManager (finalized certificates in \
    DAG_METADATA checkpoint:{height}, pending checkpoints and votes) and the compiled \
    finality switches, published by the node's finality driver";

/// Most pending checkpoints reported (the lowest heights first).
pub const MAX_PENDING_REPORTED: usize = 16;

/// One checkpoint: finalized, or pending with the votes collected so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointView {
    pub height: u64,
    pub block_hash: Hash,
    /// Snapshot height S(E) of the epoch whose committee votes on it.
    pub epoch: u64,
    pub state_root: Hash,
    pub accepted_root: Hash,
    pub committee_size: usize,
    pub voters: usize,
    pub voted_stake: u128,
    pub total_stake: u128,
}

impl CheckpointView {
    fn to_json(&self) -> Value {
        let quorum = quorum_stake(self.total_stake);
        // Percent of the committee stake that has voted, two decimals.
        let pct = if self.total_stake == 0 {
            0.0
        } else {
            let bp = self
                .voted_stake
                .saturating_mul(10_000)
                .checked_div(self.total_stake)
                .unwrap_or(0);
            (bp as f64) / 100.0
        };
        json!({
            "height": format!("0x{:x}", self.height),
            "blockHash": format!("0x{}", hex::encode(self.block_hash.as_bytes())),
            "epoch": format!("0x{:x}", self.epoch),
            "stateRoot": format!("0x{}", hex::encode(self.state_root.as_bytes())),
            "acceptedRoot": format!("0x{}", hex::encode(self.accepted_root.as_bytes())),
            "committeeSize": self.committee_size,
            "voters": self.voters,
            // u128 stakes as decimal strings (JSON numbers lose precision).
            "votedStake": self.voted_stake.to_string(),
            "totalStake": self.total_stake.to_string(),
            "quorumStake": quorum.to_string(),
            "quorumPct": pct,
            "hasQuorum": self.total_stake > 0 && self.voted_stake >= quorum,
        })
    }
}

/// What the node publishes for the RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityStatusView {
    /// Voting (propose / sign / relay) runs on this node.
    pub voting: bool,
    /// A verified certificate raises the reorg floor (fork-choice filter).
    pub enforcement: bool,
    /// "legacy" | "observed" | "enforced" (node `FloorMode`).
    pub mode: String,
    pub interval: u64,
    pub vote_depth: u64,
    /// The latest finalized checkpoint this node holds.
    pub finalized: Option<CheckpointView>,
    /// Pending checkpoints, ascending by height (at most
    /// [`MAX_PENDING_REPORTED`]).
    pub pending: Vec<CheckpointView>,
    /// The finality safety stop is engaged (gadget halted).
    pub halted: bool,
}

/// The last view the node published.
#[derive(Debug, Default)]
pub struct FinalityStatusCell {
    view: RwLock<Option<FinalityStatusView>>,
}

impl FinalityStatusCell {
    pub fn publish(&self, mut view: FinalityStatusView) {
        view.pending.truncate(MAX_PENDING_REPORTED);
        let mut g = match self.view.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *g = Some(view);
    }

    pub fn latest(&self) -> Option<FinalityStatusView> {
        let g = match self.view.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        g.clone()
    }

    /// The JSON-RPC result.
    pub fn to_json(&self) -> Value {
        match self.latest() {
            None => json!({
                "published": false,
                "finalized": Value::Null,
                "pending": [],
                "dataSource": FINALITY_STATUS_SOURCE,
            }),
            Some(v) => json!({
                "published": true,
                "voting": v.voting,
                "enforcement": v.enforcement,
                "mode": v.mode,
                "halted": v.halted,
                "interval": v.interval,
                "voteDepth": v.vote_depth,
                "quorumRule": "more than 2/3 of the committee stake",
                "finalized": v.finalized.as_ref().map(CheckpointView::to_json),
                "pending": v.pending.iter().map(CheckpointView::to_json).collect::<Vec<_>>(),
                "dataSource": FINALITY_STATUS_SOURCE,
            }),
        }
    }
}

/// Register `citrate_getFinalityStatus` over `cell`.
pub fn register_finality_status(io: &mut IoHandler, cell: Arc<FinalityStatusCell>) {
    io.add_sync_method(FINALITY_STATUS_METHOD, move |_params: Params| {
        Ok(cell.to_json())
    });
}
