// node/src/finality_driver.rs
//
// WP-S.3 Stage 1a — feeds the consensus `FinalityGadget` from this node's
// canonical chain (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §3, §4.2–4.3).
//
// Once per second the driver reads the APPLIED tip (the chain this node has
// executed and state-root-verified — `CanonicalApplicator::applied_tip`), walks
// its selected-parent chain down through the block store
// (`StorageManager.blocks.get_header`), and for every checkpoint boundary height
// H that is now buried at least `vote_depth` blocks below the tip (§3: never vote
// at the tip) hands `(H, hash_at_H, header.vrf_reveal.output)` to the gadget,
// which proposes, signs (if this node is a committee member) and replays early
// votes. The resulting votes are broadcast as `NetworkMessage::CheckpointVote`.
//
// Spawned ONLY when the compiled switch (`checkpoint_voting_pinned`) is on for the
// running chain; with it off this module never runs.

// PANIC-S1 G2: runs on the live node; panic-free outside tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use citrate_consensus::checkpoint::CheckpointVote;
use citrate_consensus::checkpoint_gadget::FinalityGadget;
use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::types::Hash;
use citrate_network::peer::PeerManager;
use citrate_network::NetworkMessage;
use citrate_storage::StorageManager;
use tracing::{debug, info, warn};

use crate::canonical_apply::CanonicalApplicator;

/// How many boundary heights one pass may process. Bounds the selected-parent
/// walk after a pause (e.g. a long catch-up): older boundaries are skipped, not
/// queued — a checkpoint is only useful near the tip.
pub const MAX_BOUNDARIES_PER_PASS: u64 = 8;

/// A canonical checkpoint block buried at least `vote_depth` deep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuriedCheckpoint {
    pub height: u64,
    pub hash: Hash,
    /// The block's ECVRF beacon (`header.vrf_reveal.output`): the committee seed.
    pub seed: Hash,
}

/// The header fields the walk needs: (height, selected parent, VRF output).
pub type HeaderView = (u64, Hash, Hash);

/// The highest boundary height buried at least `depth` blocks below `tip_height`
/// (i.e. `<= tip_height - depth`), or `None` if there is none yet. `depth` is
/// clamped to >= 1 so a misconfigured 0 can never vote at the tip.
pub fn highest_buried_boundary(tip_height: u64, interval: u64, depth: u64) -> Option<u64> {
    if interval == 0 {
        return None;
    }
    let buried = tip_height.checked_sub(depth.max(1))?;
    let b = buried.checked_sub(buried.checked_rem(interval)?)?;
    (b > 0).then_some(b)
}

/// Boundary heights in `(after, highest_buried]`, ascending, at most
/// [`MAX_BOUNDARIES_PER_PASS`] of the highest ones.
pub fn boundaries_to_process(after: u64, highest: u64, interval: u64) -> Vec<u64> {
    let mut out = Vec::new();
    if interval == 0 {
        return out;
    }
    let mut h = highest;
    while h > after && h > 0 && (out.len() as u64) < MAX_BOUNDARIES_PER_PASS {
        out.push(h);
        match h.checked_sub(interval) {
            Some(next) => h = next,
            None => break,
        }
    }
    out.reverse();
    out
}

/// Walk the selected-parent chain down from `(tip_hash, tip_height)` and return
/// the canonical block at each height in `wanted`. A wanted height the chain
/// steps over (a selected parent more than one height below its child) is
/// simply absent — there is no canonical block "at" it on this chain, and every
/// node on the same chain skips it identically.
///
/// Data source: `lookup` — in production `StorageManager.blocks.get_header`.
pub fn canonical_at_heights<F>(
    tip_hash: Hash,
    tip_height: u64,
    wanted: &[u64],
    lookup: F,
) -> Result<Vec<BuriedCheckpoint>, String>
where
    F: Fn(&Hash) -> Result<Option<HeaderView>, String>,
{
    let want: BTreeSet<u64> = wanted.iter().copied().collect();
    let Some(&lowest) = want.first() else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    let mut cursor = tip_hash;
    // Each step strictly lowers the height, so this bounds the walk.
    let mut steps_left = tip_height.saturating_sub(lowest).saturating_add(1);
    while steps_left > 0 {
        steps_left = steps_left.saturating_sub(1);
        let Some((height, parent, seed)) = lookup(&cursor)? else {
            return Err(format!("canonical walk: header {cursor} missing"));
        };
        if want.contains(&height) {
            found.push(BuriedCheckpoint {
                height,
                hash: cursor,
                seed,
            });
        }
        if height <= lowest || height == 0 {
            break;
        }
        cursor = parent;
    }
    found.sort_by_key(|c| c.height);
    Ok(found)
}

fn to_message(vote: &CheckpointVote) -> NetworkMessage {
    NetworkMessage::CheckpointVote {
        height: vote.height,
        block_hash: vote.block_hash,
        voter_pubkey: vote.voter.as_bytes().to_vec(),
        signature: vote.signature.as_bytes().to_vec(),
    }
}

/// Broadcast votes the gadget produced (own vote, replayed early votes, relays).
pub async fn broadcast_votes(peers: &PeerManager, votes: &[CheckpointVote]) {
    for vote in votes {
        if let Err(e) = peers.broadcast(&to_message(vote)).await {
            warn!("checkpoint {}: vote broadcast failed: {}", vote.height, e);
        }
    }
}

/// Spawn the driver loop. `signer` is this node's consensus key (`proposer.key`,
/// the pubkey registered in `ValidatorRegistry`); `None` = observer node that
/// proposes and aggregates but never signs.
pub fn spawn(
    gadget: Arc<FinalityGadget>,
    applicator: Arc<CanonicalApplicator>,
    storage: Arc<StorageManager>,
    peers: Arc<PeerManager>,
    signer: Option<Ed25519SigningKey>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = gadget.manager().config().interval;
        let depth = gadget.manager().config().vote_depth.max(1);
        let mut tick = crate::timing::cadence_interval(Duration::from_secs(1));
        // Boundaries already buried when this process started are skipped: this
        // node may have signed them before a restart, and the canonical block at
        // a buried height could in principle differ now. Never risk signing a
        // second hash at a height (equivocation).
        let mut cursor: Option<u64> = None;
        info!(
            "checkpoint finality: producer path ON (interval {}, vote depth {}, signer {})",
            interval,
            depth,
            if signer.is_some() { "present" } else { "none" }
        );
        loop {
            tick.tick().await;
            let tip = applicator.applied_tip().await;
            gadget.observe_tip(tip.height).await;
            let Some(highest) = highest_buried_boundary(tip.height, interval, depth) else {
                cursor.get_or_insert(0);
                continue;
            };
            let after = *cursor.get_or_insert(highest);
            let heights = boundaries_to_process(after, highest, interval);
            if heights.is_empty() {
                continue;
            }
            let walk = canonical_at_heights(tip.hash, tip.height, &heights, |h| {
                storage
                    .blocks
                    .get_header(h)
                    .map(|o| o.map(|hd| (hd.height, hd.selected_parent_hash, hd.vrf_reveal.output)))
                    .map_err(|e| e.to_string())
            });
            let found = match walk {
                Ok(f) => f,
                Err(e) => {
                    // The applied chain's headers are persisted before the tip
                    // advances, so this is an anomaly (e.g. pruned store). Skip this
                    // window rather than wedge on it forever: a missed checkpoint
                    // costs finality latency, never safety.
                    warn!(
                        "checkpoint finality: canonical walk failed, skipping boundaries {:?}: {}",
                        heights, e
                    );
                    cursor = Some(highest);
                    continue;
                }
            };
            for cp in found {
                let out = gadget
                    .on_buried_checkpoint(cp.height, cp.hash, &cp.seed, signer.as_ref())
                    .await;
                if let Some(reason) = &out.skipped {
                    debug!("checkpoint {}: not proposed ({:?})", cp.height, reason);
                }
                broadcast_votes(&peers, &out.outbound).await;
            }
            cursor = Some(highest);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn h(n: u8) -> Hash {
        Hash::new([n; 32])
    }

    #[test]
    fn never_votes_at_the_tip() {
        // depth 3, interval 2: tip 10 => buried 7 => boundary 6.
        assert_eq!(highest_buried_boundary(10, 2, 3), Some(6));
        assert_eq!(highest_buried_boundary(9, 2, 3), Some(6));
        assert_eq!(
            highest_buried_boundary(4, 2, 3),
            None,
            "only height 1 buried"
        );
        // depth 0 is clamped to 1: the tip itself is never a vote target.
        assert_eq!(highest_buried_boundary(10, 2, 0), Some(8));
        assert_eq!(highest_buried_boundary(10, 0, 3), None);
        assert_eq!(highest_buried_boundary(2, 2, 3), None);
    }

    #[test]
    fn boundaries_are_ascending_and_bounded() {
        assert_eq!(boundaries_to_process(4, 10, 2), vec![6, 8, 10]);
        assert_eq!(boundaries_to_process(10, 10, 2), Vec::<u64>::new());
        let many = boundaries_to_process(0, 1000, 2);
        assert_eq!(many.len() as u64, MAX_BOUNDARIES_PER_PASS);
        assert_eq!(many.last().copied(), Some(1000));
        assert_eq!(boundaries_to_process(0, 10, 0), Vec::<u64>::new());
    }

    /// Linear chain 0..=12 (hash n+1 at height n) with a sibling at 6 that is
    /// NOT on the selected-parent chain: the walk returns the canonical block.
    #[test]
    fn walk_returns_canonical_blocks_only() {
        let mut headers: HashMap<Hash, HeaderView> = HashMap::new();
        for n in 0u8..=12 {
            let parent = if n == 0 { Hash::default() } else { h(n) };
            headers.insert(
                h(n.saturating_add(1)),
                (u64::from(n), parent, h(n.saturating_add(100))),
            );
        }
        headers.insert(h(200), (6, h(6), h(201))); // orphan sibling at height 6
        let found = canonical_at_heights(h(13), 12, &[6, 8], |x| Ok(headers.get(x).copied()))
            .expect("walk");
        assert_eq!(
            found,
            vec![
                BuriedCheckpoint {
                    height: 6,
                    hash: h(7),
                    seed: h(106)
                },
                BuriedCheckpoint {
                    height: 8,
                    hash: h(9),
                    seed: h(108)
                },
            ]
        );
    }

    #[test]
    fn walk_errors_on_missing_header_and_skips_stepped_over_heights() {
        let headers: HashMap<Hash, HeaderView> = HashMap::from([
            (h(10), (10, h(7), h(1))),
            (h(7), (7, h(5), h(2))), // selected parent jumps from 10 to 7
            (h(5), (5, h(4), h(3))),
        ]);
        let found = canonical_at_heights(h(10), 10, &[8, 6], |x| Ok(headers.get(x).copied()))
            .expect("walk");
        assert!(found.is_empty(), "8 and 6 are stepped over: {found:?}");
        let err = canonical_at_heights(h(10), 10, &[2], |x| Ok(headers.get(x).copied()));
        assert!(err.is_err(), "missing header at 4 must defer, not guess");
    }

    #[test]
    fn vote_message_round_trips_fields() {
        use citrate_consensus::types::{PublicKey, Signature};
        let v = CheckpointVote {
            height: 42,
            block_hash: h(9),
            voter: PublicKey::new([3; 32]),
            signature: Signature::new([4; 64]),
        };
        match to_message(&v) {
            NetworkMessage::CheckpointVote {
                height,
                block_hash,
                voter_pubkey,
                signature,
            } => {
                assert_eq!(height, 42);
                assert_eq!(block_hash, h(9));
                assert_eq!(voter_pubkey, vec![3u8; 32]);
                assert_eq!(signature, vec![4u8; 64]);
            }
            other => panic!("unexpected message {other:?}"),
        }
    }
}
