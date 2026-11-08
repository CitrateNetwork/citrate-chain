// citrate/core/consensus/src/slots.rs
//
// r1007 time slots and equivocation (planset 2026-11-03-r1007-v060,
// `06_CONSENSUS_SPEC.md` §1.1 `slot`, G9, G10).
//
// A block's slot is `(timestamp - GENESIS_TIMESTAMP) / SLOT_DURATION`. G9: a
// block's slot is strictly greater than the slot of every parent, and its VRF
// is bound to that slot. G10: two blocks with the same proposer and the same
// slot equivocate, and GHOSTDAG colors the later candidate red.
//
// GENESIS_TIMESTAMP is the timestamp of the chain's genesis block (the slot
// origin). The DAG store learns it when it stores the genesis block and keeps
// it with its metadata, so it is known after a restart and after the genesis
// block itself is pruned.

use crate::types::{BlockHeader, Hash, PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// §1.2 `SLOT_DURATION`, in seconds. Owner question O2 (1, 2 or 5 s) is open;
/// this is the spec default. Final at r1007 genesis: it can never change
/// without a hard fork (spec §11).
pub const SLOT_DURATION_SECS: u64 = 1;

/// G9 ingress policy: a block whose slot is more than this many seconds past
/// the local clock's slot is not admitted now (it is admitted once its slot
/// arrives). Local policy, not a validity rule: it depends on the local clock.
/// The spec proposes 15 s (reviewer R12); it was 900 s before r1007.
pub const MAX_FUTURE_SLOT_DRIFT_SECS: u64 = 15;

/// [`MAX_FUTURE_SLOT_DRIFT_SECS`] in whole slots.
pub const MAX_FUTURE_SLOT_DRIFT_SLOTS: u64 = MAX_FUTURE_SLOT_DRIFT_SECS / SLOT_DURATION_SECS;

const _: () = assert!(SLOT_DURATION_SECS > 0);
const _: () = assert!(MAX_FUTURE_SLOT_DRIFT_SECS % SLOT_DURATION_SECS == 0);
// The parent-relative timestamp bound must be a whole number of slots, so the
// producer's clamp to it lands on a slot boundary.
const _: () = assert!(crate::hardening::MAX_BLOCK_TIMESTAMP_ADVANCE_SECS % SLOT_DURATION_SECS == 0);

/// The slot of a block stamped `timestamp` on a chain whose genesis is stamped
/// `genesis_timestamp`. `None` for a timestamp before genesis (no slot).
pub fn slot_of(timestamp: u64, genesis_timestamp: u64) -> Option<u64> {
    timestamp
        .checked_sub(genesis_timestamp)
        .and_then(|d| d.checked_div(SLOT_DURATION_SECS))
}

/// The first second of `slot`. `None` on overflow.
pub fn slot_start(slot: u64, genesis_timestamp: u64) -> Option<u64> {
    slot.checked_mul(SLOT_DURATION_SECS)
        .and_then(|d| genesis_timestamp.checked_add(d))
}

/// G9 ingress policy: whether a block stamped `timestamp` may be admitted when
/// the local clock reads `now` (seconds). False once its slot is more than
/// [`MAX_FUTURE_SLOT_DRIFT_SLOTS`] past the local clock's slot, and for any
/// block while the local clock is still before genesis.
pub fn within_slot_drift(timestamp: u64, now: u64, genesis_timestamp: u64) -> bool {
    let Some(block_slot) = slot_of(timestamp, genesis_timestamp) else {
        // Before genesis: G9 rejects it anyway; not this policy's call.
        return true;
    };
    match slot_of(now, genesis_timestamp) {
        Some(now_slot) => block_slot <= now_slot.saturating_add(MAX_FUTURE_SLOT_DRIFT_SLOTS),
        None => false,
    }
}

/// G10: whether two headers equivocate (same proposer, same slot, different
/// blocks). Headers whose slot is undefined never equivocate.
pub fn equivocates(a: &BlockHeader, b: &BlockHeader, genesis_timestamp: u64) -> bool {
    a.block_hash != b.block_hash
        && a.proposer_pubkey == b.proposer_pubkey
        && slot_of(a.timestamp, genesis_timestamp).is_some()
        && slot_of(a.timestamp, genesis_timestamp) == slot_of(b.timestamp, genesis_timestamp)
}

/// Evidence that `proposer` signed two different blocks for one slot (G10).
///
/// Recorded durably by the DAG store when the second block is stored, for the
/// slashing path (spec O8: equivocation is colored red AND slashed; slashing
/// itself is not wired here). Self-contained: both signed headers are kept, so
/// the evidence survives pruning of the blocks themselves. Each signature is
/// the proposer's ed25519 signature over its block hash (`crypto::sign_block`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub proposer: PublicKey,
    pub slot: u64,
    /// The block stored first.
    pub first: BlockHeader,
    pub first_signature: Signature,
    /// The block whose storage revealed the equivocation.
    pub second: BlockHeader,
    pub second_signature: Signature,
}

impl EquivocationEvidence {
    /// The two block hashes, first then second.
    pub fn hashes(&self) -> (Hash, Hash) {
        (self.first.block_hash, self.second.block_hash)
    }
}

/// The DAG-metadata key under which the evidence for `(proposer, slot)` is
/// stored: a fixed prefix, the proposer key and the big-endian slot, so a
/// prefix scan returns every record and a proposer's records sort by slot.
pub fn equivocation_evidence_key(proposer: &PublicKey, slot: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(EQUIVOCATION_KEY_PREFIX.len().saturating_add(40));
    key.extend_from_slice(EQUIVOCATION_KEY_PREFIX);
    key.extend_from_slice(proposer.as_bytes());
    key.extend_from_slice(&slot.to_be_bytes());
    key
}

/// Prefix of [`equivocation_evidence_key`].
pub const EQUIVOCATION_KEY_PREFIX: &[u8] = b"equivocation/v1/";

/// DAG-metadata key holding the slot origin (the genesis timestamp), u64 BE.
pub const SLOT_ORIGIN_KEY: &[u8] = b"slot_origin";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_arithmetic() {
        assert_eq!(slot_of(1_000, 1_000), Some(0));
        assert_eq!(slot_of(1_001, 1_000), Some(1 / SLOT_DURATION_SECS));
        assert_eq!(slot_of(999, 1_000), None);
        assert_eq!(slot_start(0, 1_000), Some(1_000));
        assert_eq!(slot_start(u64::MAX, 1), None);
        for s in 0..100u64 {
            let start = slot_start(s, 1_000).unwrap();
            assert_eq!(slot_of(start, 1_000), Some(s));
            assert_eq!(slot_of(start + SLOT_DURATION_SECS - 1, 1_000), Some(s));
        }
    }

    #[test]
    fn drift_is_measured_in_slots_from_the_local_clock() {
        let g = 1_000;
        let now = 2_000;
        let edge = now + MAX_FUTURE_SLOT_DRIFT_SECS;
        assert!(within_slot_drift(edge, now, g));
        assert!(!within_slot_drift(edge + SLOT_DURATION_SECS, now, g));
        assert!(!within_slot_drift(u64::MAX, now, g));
        // A local clock before genesis admits nothing ahead of it.
        assert!(!within_slot_drift(g, g - 1, g));
    }
}
