//! Compiled chain parameters of a release genesis (r1007, S3-6).
//!
//! The r1007 genesis fixes the block-0 constants of the planset's consensus spec
//! (06 §1.2) and the node-level windows the ADR ties to them (CV-7a: undo window =
//! retention). They are keyed by (chain id, block-0 hash), like
//! [`crate::hardening::GENESIS_ACTIVATIONS`], because r1005, r1006 and r1007 all run
//! chain id 40204. Every value and its source decision is listed in
//! `docs/consensus/R1007_GENESIS.md`.
//!
//! Readers (data source: the compiled table [`GENESIS_CHAIN_PARAMS`]):
//! * the consensus fingerprint (node `consensus_manifest`): the rendering is part of
//!   the v4 genesis binding, so two binaries that disagree on any value print
//!   different fingerprints;
//! * the node start-up (`genesis::check_checkpoint_params`): on a genesis with
//!   compiled params the `[checkpoint]` config may only repeat them;
//! * tripwire tests that pin each value to the constant the code runs with
//!   (`tests/r1007_chain_params.rs`, node `genesis::tests`). A lane that owns one of
//!   these constants (time slots, mergeset execution, finality) binds it to this table
//!   when it is integrated, and its test then reads it from here.

use crate::hardening::R1007_GENESIS;

/// The block-0 chain parameters of one genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisChainParams {
    /// `SLOT_DURATION` (06 §1.2, G9). PENDING OWNER O2: 1 s is r1006's live cadence.
    pub slot_duration_secs: u64,
    /// Ingress future-drift bound for a block's slot (06 G9, reviewer R12).
    pub max_future_drift_secs: u64,
    /// `PRUNING_DEPTH` in chain blocks (06 §1.2; D12).
    pub pruning_depth: u64,
    /// Reorg undo window in chain blocks (CV-7a: equal to the pruning depth).
    pub undo_window: u64,
    /// GHOSTDAG `K` (06 §1.2 D2; conditional on the S1-measured delay, §1.3).
    pub ghostdag_k: u32,
    /// `MAX_PARENTS` (1 selected + up to 9 merge parents).
    pub max_parents: usize,
    /// `MERGE_DEPTH` in heights.
    pub merge_depth: u64,
    /// `CHECKPOINT_INTERVAL` (CV-8).
    pub checkpoint_interval: u64,
    /// Checkpoint committee size (CV-8; with 7 producers the committee is all 7).
    pub committee_size: usize,
    /// Checkpoint vote depth `D` (votes only for a block buried this deep).
    pub checkpoint_vote_depth: u64,
    /// `INCLUDE_GAS_LIMIT` per block (06 D9). PENDING OWNER O5: provisional until S1-2.
    pub include_gas_limit: u64,
    /// `ACCEPT_GAS_LIMIT` per accepting block (06 D9). PENDING OWNER O5.
    pub accept_gas_limit: u64,
    /// Height from which the stake-gated producer set is enforced (start of epoch 1).
    pub validator_activation_height: u64,
}

impl GenesisChainParams {
    /// The stable `name=value` rendering, in field order, joined by `,`. Part of the
    /// consensus fingerprint pre-image for this genesis.
    pub fn render(&self) -> String {
        [
            ("slot_duration_secs", self.slot_duration_secs.to_string()),
            (
                "max_future_drift_secs",
                self.max_future_drift_secs.to_string(),
            ),
            ("pruning_depth", self.pruning_depth.to_string()),
            ("undo_window", self.undo_window.to_string()),
            ("ghostdag_k", self.ghostdag_k.to_string()),
            ("max_parents", self.max_parents.to_string()),
            ("merge_depth", self.merge_depth.to_string()),
            ("checkpoint_interval", self.checkpoint_interval.to_string()),
            ("committee_size", self.committee_size.to_string()),
            (
                "checkpoint_vote_depth",
                self.checkpoint_vote_depth.to_string(),
            ),
            ("include_gas_limit", self.include_gas_limit.to_string()),
            ("accept_gas_limit", self.accept_gas_limit.to_string()),
            (
                "validator_activation_height",
                self.validator_activation_height.to_string(),
            ),
        ]
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
    }
}

/// r1007's block-0 parameters (planset 06 §1.2, ADR CV-7a/CV-8; owner 2026-11-07).
pub const R1007_CHAIN_PARAMS: GenesisChainParams = GenesisChainParams {
    slot_duration_secs: 1,
    max_future_drift_secs: 15,
    pruning_depth: 10_000,
    undo_window: 10_000,
    ghostdag_k: 18,
    max_parents: 10,
    merge_depth: 100,
    checkpoint_interval: 50,
    committee_size: 100,
    checkpoint_vote_depth: 3,
    include_gas_limit: 30_000_000,
    accept_gas_limit: 60_000_000,
    validator_activation_height: 1_000,
};

/// Chain parameters compiled into this release, keyed by (chain id, block-0 hash). The
/// ONLY place a genesis gets them: r1005's and r1006's geneses have no entry and keep
/// their per-node values exactly as before.
pub const GENESIS_CHAIN_PARAMS: &[(u64, [u8; 32], GenesisChainParams)] =
    &[(40204, R1007_GENESIS, R1007_CHAIN_PARAMS)];

/// The compiled chain parameters for a node on `chain_id` whose block 0 is `genesis`,
/// or `None` (any other genesis, or this genesis under another chain id).
pub fn chain_params_for_genesis(chain_id: u64, genesis: &[u8; 32]) -> Option<GenesisChainParams> {
    GENESIS_CHAIN_PARAMS
        .iter()
        .find(|(c, g, _)| *c == chain_id && g == genesis)
        .map(|(_, _, p)| *p)
}

/// The compiled chain parameters for `genesis` on any chain id (the fingerprint, which
/// is keyed by block 0 alone, like `hardening::genesis_activations`).
pub fn genesis_chain_params(genesis: &[u8; 32]) -> Option<GenesisChainParams> {
    GENESIS_CHAIN_PARAMS
        .iter()
        .find(|(_, g, _)| g == genesis)
        .map(|(_, _, p)| *p)
}
