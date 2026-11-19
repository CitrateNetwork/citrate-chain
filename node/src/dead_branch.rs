// citrate/node/src/dead_branch.rs
//
// Dead-branch evidence: when a node whose applied branch the network has left
// may record the dead-branch marker (`citrate_storage::chain::wedge`, CV-7b)
// by itself, so the guarded cold resync (`cold_resync.rs`, CV-7c) recovers it.
// ADR: .agentile/adrs/ADR-2026-11-19-dead-branch-evidence.md.
//
// THE CASE (r1007, 2026-11-19). The fleet was recovered onto HEAVY, which
// finalized checkpoint 283,600. Member Core nodes stayed on LIGHT at 274,810:
// LIGHT forked at 105,024, about 170,000 heights below their tip, far below
// the 10,000-height reorg floor, and nobody produces on it any more. The
// applicator never refuses a switch (it never sees HEAVY's ancestry), so it
// records no marker; ancestor sync ends `TooDeep` and only logs. The nodes
// report `catching_up` for ever.
//
// THE RULE. A cold resync throws the chain database away (moved aside, not
// deleted) and syncs from genesis, so no peer may be able to cause one by
// claiming a deep heavier fork. The marker is recorded only when ALL hold:
//
// E1 A header-verified TooDeep: an ancestor episode located the fork exactly
//    (`Outcome::TooDeep { diverged: Some(..) }`): the peer's headers verified
//    from our block at the fork, the first one not on our executed chain is
//    named, the fork is below the reorg floor, and the peer claimed more work
//    than our tip. The I4 TooDeep (the peer lacks our finalized checkpoint)
//    has no `diverged` and never counts.
// E2 Corroboration: at least [`MIN_PEERS`] distinct, currently connected
//    peers gave such a TooDeep within [`EVIDENCE_TTL`], agreeing on the fork
//    block and the first block of the other branch. A later conclusive
//    episode with a peer (it extends our chain, is not heavier, or was
//    fetched) withdraws its TooDeep.
// E3 A finalized certificate from one of those peers that verifies against
//    the committee THIS node derives (`finality_sync::judge_foreign_certificate`)
//    and certifies a block not on our executed chain: above our applied tip,
//    or at or below it with another block there; above the fork. Forging one
//    takes the keys of validators this node materialized from its own chain,
//    holding more than two thirds of the committee's stake.
// E4 Never across finality: the fork is at or above this node's latest
//    finalized checkpoint (a branch that leaves out a block this node holds a
//    finalized certificate for is conflicting finality, never resynced to).
// E5 Our branch has stopped: the newest block of our applied selected chain
//    that this node did not seal is more than [`STALL_SECS`] old by its own
//    timestamp ([`stall_age_secs`]). Read from the chain store, so a restart
//    does not reset it.
// E6 `[recovery] cold_resync = false` records nothing (the verdict is logged).
//
// The marker's reason starts with [`REASON_PREFIX`]; if the applied tip moves
// before the resync fires, the branch was not dead and the marker is cleared
// (`CanonicalApplicator::clear_evidence_dead_branch`). Everything after the
// marker is the existing guarded path: `[recovery] cold_resync_after_secs`,
// the minimum interval, the signed-vote carry, exit non-zero, the supervisor
// restart, and `apply_pending` moving the database aside.

// PANIC-S1 G2: sync path; panic-free outside tests.
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use citrate_consensus::types::Hash;
use tracing::{info, warn};

use crate::ancestor_sync::Outcome;
use crate::finality_sync::ForeignCertificate;

/// Distinct connected peers whose TooDeep must agree (E2).
pub const MIN_PEERS: usize = 2;
/// How long a TooDeep or a certificate counts as evidence. Twice the
/// ancestor-sync TooDeep cooldown (30 min), so a peer's next episode renews
/// its TooDeep before it lapses.
pub const EVIDENCE_TTL: Duration = Duration::from_secs(3_600);
/// How old the newest block of our branch that another node sealed must be
/// (E5).
pub const STALL_SECS: u64 = 1_800;
/// Headers [`stall_age_secs`] walks down the applied chain looking for a
/// block another node sealed.
pub const STALL_WALK_MAX: u64 = 4_096;
/// A certificate request without an answer for this long is abandoned.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// A peer is asked for a certificate at most once per this interval.
pub const PROBE_COOLDOWN: Duration = Duration::from_secs(60);
/// Peers whose TooDeep (or certificate request) is remembered, at most.
pub const MAX_PEERS_TRACKED: usize = 256;
/// The marker reason of a marker this module recorded.
pub const REASON_PREFIX: &str = "dead-branch evidence:";

/// One peer's header-verified TooDeep (E1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeepFork {
    fork: (Hash, u64),
    diverged: Hash,
    at: Instant,
}

/// A verified certificate for a block not on our chain (E3).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Certified {
    height: u64,
    hash: Hash,
    peer: String,
    at: Instant,
}

/// What this node knows of itself when the rule is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local {
    /// The applied tip.
    pub applied: (Hash, u64),
    /// The reorg floor (`ancestor_sync::View::reorg_floor`).
    pub floor: u64,
    /// The highest finalized checkpoint this node holds a certificate for
    /// (`CheckpointManager::latest_finalized_height`, any floor mode).
    pub latest_finalized: u64,
    /// [`stall_age_secs`].
    pub stall_age_secs: u64,
}

/// All of E1 to E5 hold: the marker to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The applied tip the verdict was judged against.
    pub dead_tip: (Hash, u64),
    pub fork: (Hash, u64),
    /// The certified block (the branch the network finalized).
    pub head: (Hash, u64),
    /// The agreeing peers.
    pub peers: Vec<String>,
    pub reason: String,
}

/// The first condition that does not hold (diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// E1/E2: fewer than [`MIN_PEERS`] connected peers agree on a deep fork.
    Corroboration { agreeing: usize },
    /// The agreed fork is no longer below our reorg floor or on our chain.
    NotDeep,
    /// E4: the fork is below a checkpoint this node holds as finalized.
    BelowFinality { fork: u64, finalized: u64 },
    /// E3: no verified certificate from an agreeing peer above the fork.
    Certificate,
    /// E5: our branch was extended less than [`STALL_SECS`] ago.
    NotStalled { age_secs: u64 },
}

/// The evidence collected so far (see the module docs).
#[derive(Debug, Default)]
pub struct DeadBranch {
    deep: HashMap<String, DeepFork>,
    cert: Option<Certified>,
    /// The certificate request in flight: (peer, sent at).
    probe: Option<(String, Instant)>,
    /// peer -> when it was last asked for a certificate.
    probed: HashMap<String, Instant>,
}

impl DeadBranch {
    pub fn new() -> Self {
        Self::default()
    }

    /// An ancestor-sync episode with `peer` ended with `outcome`.
    pub fn note_outcome(&mut self, peer: &str, outcome: &Outcome, now: Instant) {
        match outcome {
            Outcome::TooDeep {
                fork,
                fork_hash,
                diverged: Some(diverged),
                ..
            } => {
                if self.deep.len() >= MAX_PEERS_TRACKED && !self.deep.contains_key(peer) {
                    if let Some(oldest) = self
                        .deep
                        .iter()
                        .min_by_key(|(_, d)| d.at)
                        .map(|(p, _)| p.clone())
                    {
                        self.deep.remove(&oldest);
                    }
                }
                self.deep.insert(
                    peer.to_string(),
                    DeepFork {
                        fork: (*fork_hash, *fork),
                        diverged: *diverged,
                        at: now,
                    },
                );
            }
            // A conclusive answer that is not a deep fork withdraws the peer's
            // TooDeep (and a certificate it served).
            Outcome::Extends
            | Outcome::NotHeavier { .. }
            | Outcome::Fetched { .. }
            | Outcome::Faulty(_) => {
                self.deep.remove(peer);
                if self.cert.as_ref().is_some_and(|c| c.peer == peer) {
                    self.cert = None;
                }
            }
            _ => {}
        }
    }

    /// The peer to ask for its latest finalized certificate now, if any: a
    /// connected peer with a fresh TooDeep, not asked within
    /// [`PROBE_COOLDOWN`], while no fresh certificate is held and no request
    /// is in flight. The request is recorded as in flight.
    pub fn want_probe(&mut self, connected: &[String], now: Instant) -> Option<String> {
        if self.cert.as_ref().is_some_and(|c| fresh(c.at, now)) {
            return None;
        }
        if let Some((_, at)) = &self.probe {
            if now.saturating_duration_since(*at) < PROBE_TIMEOUT {
                return None;
            }
            self.probe = None;
        }
        let pick = connected
            .iter()
            .filter(|p| self.deep.get(*p).is_some_and(|d| fresh(d.at, now)))
            .filter(|p| {
                self.probed
                    .get(*p)
                    .is_none_or(|at| now.saturating_duration_since(*at) >= PROBE_COOLDOWN)
            })
            .min()?
            .clone();
        if self.probed.len() >= MAX_PEERS_TRACKED {
            self.probed
                .retain(|_, at| now.saturating_duration_since(*at) < PROBE_COOLDOWN);
        }
        self.probed.insert(pick.clone(), now);
        self.probe = Some((pick.clone(), now));
        Some(pick)
    }

    /// Whether a `CheckpointCertificate` from `peer` answers the request in
    /// flight; `true` consumes it.
    pub fn accept_probe_answer(&mut self, peer: &str, now: Instant) -> bool {
        let answers = self
            .probe
            .as_ref()
            .is_some_and(|(p, at)| p == peer && now.saturating_duration_since(*at) < PROBE_TIMEOUT);
        if answers {
            self.probe = None;
        }
        answers
    }

    /// The judged answer to a certificate request. Only a verified
    /// certificate for a block not on our chain, from a peer with a TooDeep,
    /// is kept.
    pub fn note_certificate(&mut self, peer: &str, judged: &ForeignCertificate, now: Instant) {
        let (height, hash) = match judged {
            ForeignCertificate::AboveTip { height, hash }
            | ForeignCertificate::Conflicts { height, hash, .. } => (*height, *hash),
            ForeignCertificate::OnOurChain { .. } | ForeignCertificate::Refused(_) => return,
        };
        if !self.deep.contains_key(peer) {
            return;
        }
        self.cert = Some(Certified {
            height,
            hash,
            peer: peer.to_string(),
            at: now,
        });
    }

    /// Judge E1 to E5. `connected` are the peers connected now; `on_chain`
    /// says whether a block is on our executed chain at a height.
    pub fn verdict(
        &self,
        local: &Local,
        connected: &[String],
        on_chain: impl Fn(&Hash, u64) -> bool,
        now: Instant,
    ) -> Result<Verdict, Missing> {
        let connected: HashSet<&str> = connected.iter().map(String::as_str).collect();
        // E1 + E2: group the fresh TooDeeps of connected peers by what they
        // claim; the largest group (ties: the lower fork, then the hash) wins.
        let mut groups: BTreeMap<((u64, Hash), Hash), Vec<&str>> = BTreeMap::new();
        for (peer, d) in &self.deep {
            if fresh(d.at, now) && connected.contains(peer.as_str()) {
                groups
                    .entry(((d.fork.1, d.fork.0), d.diverged))
                    .or_default()
                    .push(peer.as_str());
            }
        }
        let best = groups
            .iter()
            .max_by(|a, b| a.1.len().cmp(&b.1.len()).then_with(|| b.0.cmp(a.0)));
        let Some((((fork_h, fork_hash), _), peers)) = best else {
            return Err(Missing::Corroboration { agreeing: 0 });
        };
        if peers.len() < MIN_PEERS {
            return Err(Missing::Corroboration {
                agreeing: peers.len(),
            });
        }
        let fork = (*fork_hash, *fork_h);
        if fork.1 >= local.floor || !on_chain(&fork.0, fork.1) {
            return Err(Missing::NotDeep);
        }
        // E4.
        if fork.1 < local.latest_finalized {
            return Err(Missing::BelowFinality {
                fork: fork.1,
                finalized: local.latest_finalized,
            });
        }
        // E3: from an agreeing peer, above the fork, not on our chain.
        let cert = self
            .cert
            .as_ref()
            .filter(|c| fresh(c.at, now) && c.height > fork.1 && peers.contains(&c.peer.as_str()))
            .filter(|c| c.height > local.applied.1 || !on_chain(&c.hash, c.height))
            .ok_or(Missing::Certificate)?;
        // E5.
        if local.stall_age_secs < STALL_SECS {
            return Err(Missing::NotStalled {
                age_secs: local.stall_age_secs,
            });
        }
        let mut peers: Vec<String> = peers.iter().map(|p| p.to_string()).collect();
        peers.sort();
        let reason = format!(
            "{REASON_PREFIX} {} peers ({}) agree this branch forked at {} @ {} below the reorg \
             floor {}; the committee finalized {} @ {} on their branch (certificate from {}); \
             this branch was last extended by another node {} s ago",
            peers.len(),
            peers.join(", "),
            fork.0,
            fork.1,
            local.floor,
            cert.hash,
            cert.height,
            cert.peer,
            local.stall_age_secs
        );
        Ok(Verdict {
            dead_tip: local.applied,
            fork,
            head: (cert.hash, cert.height),
            peers,
            reason,
        })
    }
}

fn fresh(at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(at) < EVIDENCE_TTL
}

/// This node's coinbase as v2 headers commit to it (`[mining] coinbase`), or
/// `None` when it has none (a follower seals nothing).
pub fn own_coinbase(coinbase: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(coinbase.trim_start_matches("0x")).ok()?;
    let out: [u8; 20] = bytes.try_into().ok()?;
    out.iter().any(|b| *b != 0).then_some(out)
}

/// The wall clock in unix seconds, for [`run_tick`].
pub fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// E5: seconds since the newest block of this node's applied selected chain
/// that `own` (this node's coinbase, which v2 headers commit to; `None`: it
/// seals nothing) did not seal, by that block's own timestamp. Walks at most [`STALL_WALK_MAX`]
/// headers down from the applied tip; if every one was sealed by this node,
/// the oldest walked is used (the branch has been this node's alone for at
/// least that long). 0 when nothing can be read (never "stalled" on a read
/// error). Data source: `BlockStore::get_applied_tip` and `get_header`.
pub fn stall_age_secs(
    storage: &citrate_storage::StorageManager,
    own: Option<&[u8; 20]>,
    now_secs: u64,
) -> u64 {
    let Ok(Some((mut cursor, _))) = storage.blocks.get_applied_tip() else {
        return 0;
    };
    let mut last_ts = None;
    for _ in 0..STALL_WALK_MAX {
        let Ok(Some(h)) = storage.blocks.get_header(&cursor) else {
            break;
        };
        last_ts = Some(h.timestamp);
        if own != Some(&h.coinbase) || h.height == 0 {
            break;
        }
        cursor = h.selected_parent_hash;
    }
    last_ts.map_or(0, |ts| now_secs.saturating_sub(ts))
}

/// One evaluation, as `start_node` runs it every sync tick: send a
/// certificate request if one is due, clear an evidence marker whose branch
/// moved, and record the marker when the rule holds. `peers` are the
/// connected peers; `enabled` is `[recovery] cold_resync`; `now_secs` is the
/// wall clock in unix seconds (what block timestamps are judged against).
#[allow(clippy::too_many_arguments)]
pub async fn run_tick(
    evidence: &parking_lot::Mutex<DeadBranch>,
    app: &crate::canonical_apply::CanonicalApplicator,
    storage: &citrate_storage::StorageManager,
    manager: &citrate_consensus::checkpoint::CheckpointManager,
    peers: &[std::sync::Arc<citrate_network::peer::Peer>],
    finalized_for_floor: u64,
    own: Option<&[u8; 20]>,
    enabled: bool,
    last_logged: &parking_lot::Mutex<Option<Missing>>,
    now: Instant,
    now_secs: u64,
) -> Option<Verdict> {
    if app.clear_evidence_dead_branch(REASON_PREFIX).await {
        *evidence.lock() = DeadBranch::new();
    }
    if app.wedge().ok().flatten().is_some() {
        return None;
    }
    let mut ids = Vec::with_capacity(peers.len());
    let mut handles = HashMap::with_capacity(peers.len());
    for p in peers {
        if p.is_closed() {
            continue;
        }
        let info = p.info.read().await;
        if info.state != citrate_network::peer::PeerState::Connected {
            continue;
        }
        if info
            .version
            .is_some_and(|v| v.understands_checkpoint_sync())
        {
            handles.insert(info.id.0.clone(), p.clone());
        }
        ids.push(info.id.0.clone());
    }
    let latest_finalized = manager.latest_finalized_height().await;
    let probe = evidence.lock().want_probe(
        &ids.iter()
            .filter(|i| handles.contains_key(*i))
            .cloned()
            .collect::<Vec<_>>(),
        now,
    );
    if let Some(peer) = probe {
        if let Some(h) = handles.get(&peer) {
            // The latest certificate it holds above ours, at any height:
            // `latest_finalized_in_range(above, u64::MAX)` on the server.
            let _ = h
                .send(citrate_network::NetworkMessage::GetCheckpoint {
                    above: latest_finalized,
                    at_or_below: u64::MAX,
                })
                .await;
        }
    }
    let view = crate::ancestor_sync::read_view(storage, finalized_for_floor, false);
    let local = Local {
        applied: view.applied,
        floor: view.reorg_floor(),
        latest_finalized,
        stall_age_secs: stall_age_secs(storage, own, now_secs),
    };
    let applied_height = view.applied.1;
    let verdict = evidence.lock().verdict(
        &local,
        &ids,
        |h, height| {
            height <= applied_height
                && storage
                    .blocks
                    .get_canonical_block_by_height(height)
                    .ok()
                    .flatten()
                    == Some(*h)
        },
        now,
    );
    let v = match verdict {
        Ok(v) => v,
        Err(missing) => {
            let mut last = last_logged.lock();
            // Log a change only, and only once there is some evidence.
            if last.as_ref() != Some(&missing)
                && !matches!(missing, Missing::Corroboration { agreeing: 0 })
            {
                info!("DEADBRANCH evidence incomplete: {missing:?}");
            }
            *last = Some(missing);
            return None;
        }
    };
    if !enabled {
        warn!(
            "DEADBRANCH {} — NOT marked: [recovery] cold_resync = false. Resync this node by hand.",
            v.reason
        );
        return None;
    }
    let recorded = app
        .record_dead_branch_on_evidence(
            v.dead_tip.0,
            crate::canonical_apply::AppliedTip {
                hash: v.fork.0,
                height: v.fork.1,
            },
            v.head.0,
            v.head.1,
            &v.reason,
        )
        .await;
    if recorded {
        warn!(
            "DEADBRANCH marked: {}. The guarded cold resync follows ([recovery] \
             cold_resync_after_secs).",
            v.reason
        );
        Some(v)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash {
        Hash::new([n; 32])
    }

    fn deep(fork: u64, fork_hash: Hash, diverged: Option<Hash>) -> Outcome {
        Outcome::TooDeep {
            fork,
            depth: 170_000,
            floor: 264_810,
            fork_hash,
            diverged,
        }
    }

    /// The r1007 member: LIGHT at 274,810, fork 105,024, HEAVY certificate
    /// 283,600, no LIGHT block for an hour.
    fn member() -> Local {
        Local {
            applied: (h(0xAA), 274_810),
            floor: 264_810,
            latest_finalized: 105_000,
            stall_age_secs: 3_600,
        }
    }

    fn cert(height: u64, hash: Hash) -> ForeignCertificate {
        ForeignCertificate::AboveTip { height, hash }
    }

    fn peers(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    /// Our chain: the fork block at 105,024 and nothing of the other branch.
    fn ours(hash: &Hash, height: u64) -> bool {
        height == 105_024 && *hash == h(0x24)
    }

    fn full(now: Instant) -> DeadBranch {
        let mut d = DeadBranch::new();
        d.note_outcome("boot-1", &deep(105_024, h(0x24), Some(h(0x25))), now);
        d.note_outcome("boot-2", &deep(105_024, h(0x24), Some(h(0x25))), now);
        d.note_certificate("boot-1", &cert(283_600, h(0xC0)), now);
        d
    }

    #[test]
    fn an_honest_deep_split_is_a_verdict() {
        let now = Instant::now();
        let v = full(now)
            .verdict(&member(), &peers(&["boot-1", "boot-2", "x"]), ours, now)
            .expect("all of E1 to E5 hold");
        assert_eq!(v.fork, (h(0x24), 105_024));
        assert_eq!(v.head, (h(0xC0), 283_600));
        assert_eq!(v.dead_tip, member().applied);
        assert_eq!(v.peers, peers(&["boot-1", "boot-2"]));
        assert!(v.reason.starts_with(REASON_PREFIX));
    }

    #[test]
    fn one_lying_peer_is_never_enough() {
        let now = Instant::now();
        let mut d = DeadBranch::new();
        d.note_outcome("liar", &deep(105_024, h(0x24), Some(h(0x25))), now);
        d.note_certificate("liar", &cert(283_600, h(0xC0)), now);
        assert_eq!(
            d.verdict(&member(), &peers(&["liar", "honest"]), ours, now),
            Err(Missing::Corroboration { agreeing: 1 })
        );
        // The same liar again, under its id, is still one peer.
        d.note_outcome("liar", &deep(105_024, h(0x24), Some(h(0x25))), now);
        assert!(d
            .verdict(&member(), &peers(&["liar", "honest"]), ours, now)
            .is_err());
    }

    #[test]
    fn peers_that_disagree_on_the_branch_do_not_corroborate() {
        let now = Instant::now();
        let mut d = DeadBranch::new();
        d.note_outcome("a", &deep(105_024, h(0x24), Some(h(0x25))), now);
        d.note_outcome("b", &deep(105_024, h(0x24), Some(h(0x99))), now);
        d.note_certificate("a", &cert(283_600, h(0xC0)), now);
        assert_eq!(
            d.verdict(&member(), &peers(&["a", "b"]), ours, now),
            Err(Missing::Corroboration { agreeing: 1 })
        );
    }

    #[test]
    fn a_toodeep_without_located_headers_never_counts() {
        // The I4 TooDeep (no `diverged`): no header of the branch was checked.
        let now = Instant::now();
        let mut d = DeadBranch::new();
        d.note_outcome("a", &deep(105_024, h(0x24), None), now);
        d.note_outcome("b", &deep(105_024, h(0x24), None), now);
        d.note_certificate("a", &cert(283_600, h(0xC0)), now);
        assert_eq!(
            d.verdict(&member(), &peers(&["a", "b"]), ours, now),
            Err(Missing::Corroboration { agreeing: 0 })
        );
    }

    #[test]
    fn fabricated_headers_without_a_certificate_never_count() {
        let now = Instant::now();
        let mut d = DeadBranch::new();
        d.note_outcome("a", &deep(105_024, h(0x24), Some(h(0x25))), now);
        d.note_outcome("b", &deep(105_024, h(0x24), Some(h(0x25))), now);
        assert_eq!(
            d.verdict(&member(), &peers(&["a", "b"]), ours, now),
            Err(Missing::Certificate)
        );
        // A certificate that did not verify is refused, not kept.
        d.note_certificate(
            "a",
            &ForeignCertificate::Refused("quorum not reached".into()),
            now,
        );
        assert_eq!(
            d.verdict(&member(), &peers(&["a", "b"]), ours, now),
            Err(Missing::Certificate)
        );
        // A certificate for a block on our own chain is no evidence.
        d.note_certificate(
            "a",
            &ForeignCertificate::OnOurChain { height: 270_000 },
            now,
        );
        assert!(d
            .verdict(&member(), &peers(&["a", "b"]), ours, now)
            .is_err());
    }

    #[test]
    fn a_certificate_from_a_peer_without_a_toodeep_is_not_kept() {
        let now = Instant::now();
        let mut d = DeadBranch::new();
        d.note_outcome("a", &deep(105_024, h(0x24), Some(h(0x25))), now);
        d.note_outcome("b", &deep(105_024, h(0x24), Some(h(0x25))), now);
        d.note_certificate("stranger", &cert(283_600, h(0xC0)), now);
        assert_eq!(
            d.verdict(&member(), &peers(&["a", "b", "stranger"]), ours, now),
            Err(Missing::Certificate)
        );
    }

    #[test]
    fn a_certified_block_on_our_chain_or_below_the_fork_is_no_evidence() {
        let now = Instant::now();
        let mut d = full(now);
        // At or below our tip, and the block we hold there.
        d.note_certificate("boot-1", &cert(105_024, h(0x24)), now);
        assert_eq!(
            d.verdict(&member(), &peers(&["boot-1", "boot-2"]), ours, now),
            Err(Missing::Certificate)
        );
        // Below the fork.
        d.note_certificate("boot-1", &cert(105_000, h(0xC1)), now);
        assert_eq!(
            d.verdict(&member(), &peers(&["boot-1", "boot-2"]), ours, now),
            Err(Missing::Certificate)
        );
        // At or below our tip, another block than ours: a conflict, evidence.
        d.note_certificate(
            "boot-1",
            &ForeignCertificate::Conflicts {
                height: 200_000,
                hash: h(0xC2),
                ours: Some(h(0xC3)),
            },
            now,
        );
        assert!(d
            .verdict(&member(), &peers(&["boot-1", "boot-2"]), ours, now)
            .is_ok());
    }

    #[test]
    fn a_live_branch_is_never_marked() {
        let now = Instant::now();
        let mut local = member();
        local.stall_age_secs = STALL_SECS - 1;
        assert_eq!(
            full(now).verdict(&local, &peers(&["boot-1", "boot-2"]), ours, now),
            Err(Missing::NotStalled {
                age_secs: STALL_SECS - 1
            })
        );
    }

    #[test]
    fn a_fork_below_our_finalized_checkpoint_is_never_resynced_to() {
        let now = Instant::now();
        let mut local = member();
        local.latest_finalized = 105_050;
        assert_eq!(
            full(now).verdict(&local, &peers(&["boot-1", "boot-2"]), ours, now),
            Err(Missing::BelowFinality {
                fork: 105_024,
                finalized: 105_050
            })
        );
    }

    #[test]
    fn a_fork_inside_the_window_or_off_our_chain_is_not_deep() {
        let now = Instant::now();
        let mut local = member();
        local.floor = 100_000;
        assert_eq!(
            full(now).verdict(&local, &peers(&["boot-1", "boot-2"]), ours, now),
            Err(Missing::NotDeep)
        );
        assert_eq!(
            full(now).verdict(&member(), &peers(&["boot-1", "boot-2"]), |_, _| false, now),
            Err(Missing::NotDeep),
            "a fork block not on our chain any more"
        );
    }

    #[test]
    fn disconnected_stale_or_withdrawn_evidence_lapses() {
        let now = Instant::now();
        assert_eq!(
            full(now).verdict(&member(), &peers(&["boot-1"]), ours, now),
            Err(Missing::Corroboration { agreeing: 1 }),
            "boot-2 left"
        );
        let later = now + EVIDENCE_TTL;
        assert_eq!(
            full(now).verdict(&member(), &peers(&["boot-1", "boot-2"]), ours, later),
            Err(Missing::Corroboration { agreeing: 0 }),
            "stale"
        );
        let mut d = full(now);
        d.note_outcome("boot-2", &Outcome::Extends, now);
        assert_eq!(
            d.verdict(&member(), &peers(&["boot-1", "boot-2"]), ours, now),
            Err(Missing::Corroboration { agreeing: 1 }),
            "boot-2 now says our chain is its"
        );
        let mut d = full(now);
        d.note_outcome(
            "boot-1",
            &Outcome::NotHeavier {
                fork: 105_024,
                peer_tip: 1,
            },
            now,
        );
        d.note_outcome("boot-3", &deep(105_024, h(0x24), Some(h(0x25))), now);
        assert_eq!(
            d.verdict(
                &member(),
                &peers(&["boot-1", "boot-2", "boot-3"]),
                ours,
                now
            ),
            Err(Missing::Certificate),
            "the certificate went with boot-1's TooDeep"
        );
    }

    #[test]
    fn certificate_requests_go_to_toodeep_peers_one_at_a_time() {
        let t0 = Instant::now();
        let mut d = DeadBranch::new();
        assert_eq!(
            d.want_probe(&peers(&["a", "b"]), t0),
            None,
            "no TooDeep yet"
        );
        d.note_outcome("b", &deep(105_024, h(0x24), Some(h(0x25))), t0);
        assert_eq!(d.want_probe(&peers(&["a", "b"]), t0), Some("b".into()));
        assert_eq!(d.want_probe(&peers(&["a", "b"]), t0), None, "one in flight");
        assert!(!d.accept_probe_answer("a", t0), "not the peer asked");
        assert!(d.accept_probe_answer("b", t0));
        assert!(!d.accept_probe_answer("b", t0), "consumed");
        // b is cooling; once the cooldown passes it is asked again.
        assert_eq!(d.want_probe(&peers(&["a", "b"]), t0), None);
        let t1 = t0 + PROBE_COOLDOWN;
        assert_eq!(d.want_probe(&peers(&["a", "b"]), t1), Some("b".into()));
        assert!(
            !d.accept_probe_answer("b", t1 + PROBE_TIMEOUT),
            "a late answer is not taken"
        );
        // A fresh certificate stops the requests.
        d.note_certificate("b", &cert(283_600, h(0xC0)), t1);
        assert_eq!(
            d.want_probe(&peers(&["a", "b"]), t1 + PROBE_COOLDOWN + PROBE_TIMEOUT),
            None
        );
    }

    #[test]
    fn the_peer_table_is_bounded() {
        let now = Instant::now();
        let mut d = DeadBranch::new();
        for i in 0..(MAX_PEERS_TRACKED + 10) {
            d.note_outcome(
                &format!("p{i}"),
                &deep(105_024, h(0x24), Some(h(0x25))),
                now + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(d.deep.len(), MAX_PEERS_TRACKED);
        assert!(!d.deep.contains_key("p0"), "the oldest is dropped");
    }

    #[test]
    fn own_coinbase_is_a_non_zero_address_or_none() {
        assert_eq!(own_coinbase(""), None);
        assert_eq!(
            own_coinbase("0000000000000000000000000000000000000000"),
            None
        );
        assert_eq!(own_coinbase("0x1234"), None);
        assert_eq!(
            own_coinbase("0x96b82a070ca2615eef29d8c67b86c21fd0ba474b").map(|c| c[0]),
            Some(0x96)
        );
    }

    #[test]
    fn the_stall_clock_is_the_newest_block_another_node_sealed() {
        use citrate_consensus::types::BlockBuilder;
        use citrate_storage::pruning::PruningConfig;
        let dir = tempfile::TempDir::new().expect("tempdir");
        let s = citrate_storage::StorageManager::new(dir.path(), PruningConfig::default())
            .expect("storage");
        let me = [7u8; 20];
        let other = [8u8; 20];
        let mut parent = Hash::default();
        let mut tip = Hash::default();
        // Heights 0..=9: others' blocks at 1_000 + h; 10..=14 ours.
        for height in 0..15u64 {
            let mut hb = [0u8; 32];
            hb[..8].copy_from_slice(&(height + 1).to_be_bytes());
            let hash = Hash::new(hb);
            let block = BlockBuilder::new()
                .hash(hash)
                .parent(parent)
                .height(height)
                .timestamp(1_000 + height)
                .coinbase(if height >= 10 { me } else { other })
                .build_unhashed();
            s.blocks.put_block(&block).expect("put");
            parent = hash;
            tip = hash;
        }
        s.blocks.put_applied_tip(&tip, 14).expect("tip");
        // A follower: the tip's own age.
        assert_eq!(stall_age_secs(&s, None, 5_000), 5_000 - 1_014);
        // A producer extending its own branch alone: the newest other block.
        assert_eq!(stall_age_secs(&s, Some(&me), 5_000), 5_000 - 1_009);
        // Someone else's key: the tip again.
        assert_eq!(stall_age_secs(&s, Some(&other), 5_000), 5_000 - 1_014);
        // A clock behind the chain never reads as stalled.
        assert_eq!(stall_age_secs(&s, None, 10), 0);
    }
    // ---- Review round 1 of #486: a node that is catching up --------------

    /// The cheapest attack on a node that is catching up (a fresh install, or
    /// any node just after a cold resync): two Sybil peer ids answer TooDeep,
    /// one relays a GENUINE certificate from the honest chain above our tip,
    /// and our applied tip is old. An honest peer ahead of us on our own
    /// chain (an `Extends`) vetoes it: the attack then needs a full eclipse.
    #[test]
    fn an_honest_peer_ahead_on_our_chain_vetoes_a_sybil_verdict() {
        let now = Instant::now();
        let mut d = DeadBranch::new();
        d.note_outcome("sybil-1", &deep(105_024, h(0x24), Some(h(0x25))), now);
        d.note_outcome("sybil-2", &deep(105_024, h(0x24), Some(h(0x25))), now);
        d.note_certificate("sybil-1", &cert(283_600, h(0xC0)), now);
        d.note_outcome("honest", &Outcome::Extends, now);
        let connected = peers(&["sybil-1", "sybil-2", "honest"]);
        assert!(
            d.verdict(&member(), &connected, ours, now).is_err(),
            "a catching-up node with an honest peer ahead of it was marked"
        );
        // The veto lasts while that peer is connected and its answer fresh.
        assert!(d
            .verdict(&member(), &peers(&["sybil-1", "sybil-2"]), ours, now)
            .is_ok());
        assert!(
            d.verdict(&member(), &connected, ours, now + EVIDENCE_TTL)
                .is_err(),
            "stale TooDeeps do not count either"
        );
    }

    /// E3 re-check: a certificate that was above our tip when it was judged,
    /// and whose block our own chain has since applied, is no evidence.
    #[test]
    fn a_certificate_our_chain_has_since_applied_is_no_evidence() {
        let now = Instant::now();
        let d = full(now);
        let local = Local {
            applied: (h(0xAB), 290_000),
            floor: 280_000,
            ..member()
        };
        let on = |hash: &Hash, height: u64| {
            (height == 105_024 && *hash == h(0x24)) || (height == 283_600 && *hash == h(0xC0))
        };
        assert_eq!(
            d.verdict(&local, &peers(&["boot-1", "boot-2"]), on, now),
            Err(Missing::Certificate)
        );
    }

    /// The applicator's guards on an evidence marker: it is recorded only
    /// against the tip and fork the verdict was judged on, kept while the tip
    /// stays, and withdrawn once the tip moves; the cold resync's decision
    /// re-checks the tip itself, so a marker whose tip moved never resyncs.
    #[tokio::test]
    async fn an_evidence_marker_is_withdrawn_when_the_tip_moves_and_never_resyncs() {
        use crate::canonical_apply::tests::{fresh, mk_block, persist, roots, setup_fork};
        use crate::canonical_apply::{AppliedTip, ApplyOutcome, CanonicalApplicator};
        let (exec, storage, dir) = fresh();
        let app = CanonicalApplicator::new(exec, storage.clone());
        let (a1, a2, _b2, _b3) = setup_fork(&app, &storage).await;
        let fork = AppliedTip {
            hash: a1.header.block_hash,
            height: 1,
        };
        let tip = a2.header.block_hash;
        let reason = format!("{REASON_PREFIX} test");
        assert!(
            !app.record_dead_branch_on_evidence(h(0x99), fork, h(0xC0), 400, &reason)
                .await,
            "recorded against a tip that is not the applied tip"
        );
        let off_chain = AppliedTip {
            hash: h(0x98),
            height: 1,
        };
        assert!(
            !app.record_dead_branch_on_evidence(tip, off_chain, h(0xC0), 400, &reason)
                .await,
            "recorded with a fork block not on the applied chain"
        );
        assert_eq!(app.wedge().expect("read"), None);
        assert!(
            app.record_dead_branch_on_evidence(tip, fork, h(0xC0), 400, &reason)
                .await
        );
        let w = app.wedge().expect("read").expect("marked");
        assert_eq!((w.dead_tip, w.fork_height), (tip, 1));
        assert!(
            !app.clear_evidence_dead_branch(REASON_PREFIX).await,
            "kept while the tip stays"
        );
        // A block is applied: the branch was not dead.
        let a3 = mk_block(3, tip, roots(3)[2]);
        persist(&storage, &a3);
        assert!(matches!(
            app.apply_received(&a3).await,
            ApplyOutcome::Applied { .. }
        ));
        let policy = crate::cold_resync::Policy::from(&crate::config::RecoveryConfig::default());
        let decision = crate::cold_resync::evaluate(
            &app,
            &storage,
            None,
            dir.path(),
            policy,
            false,
            &citrate_storage::signed_votes::Binding::default(),
            w.since_unix.saturating_add(policy.after_secs),
        )
        .await
        .expect("evaluate");
        assert_eq!(decision, crate::cold_resync::Decision::NotWedged);
        assert!(!dir.path().join(crate::cold_resync::REQUEST_FILE).exists());
        assert_eq!(app.wedge().expect("read"), None);
    }

    /// `clear_evidence_dead_branch` clears an evidence marker whose tip moved
    /// and nothing else: not while the tip stays, and never a marker the
    /// applicator recorded itself (`RefusePruned`).
    #[tokio::test]
    async fn only_an_evidence_marker_whose_tip_moved_is_cleared() {
        use crate::canonical_apply::tests::{fresh, mk_block, persist, roots, setup_fork};
        use crate::canonical_apply::{AppliedTip, ApplyOutcome, CanonicalApplicator};
        let (exec, storage, _dir) = fresh();
        let app = CanonicalApplicator::new(exec, storage.clone());
        let (a1, a2, _b2, _b3) = setup_fork(&app, &storage).await;
        let fork = AppliedTip {
            hash: a1.header.block_hash,
            height: 1,
        };
        let tip = a2.header.block_hash;
        let reason = format!("{REASON_PREFIX} test");
        assert!(
            app.record_dead_branch_on_evidence(tip, fork, h(0xC0), 400, &reason)
                .await
        );
        assert!(app
            .dead_branch_handle()
            .load(std::sync::atomic::Ordering::SeqCst));
        let a3 = mk_block(3, tip, roots(3)[2]);
        persist(&storage, &a3);
        assert!(matches!(
            app.apply_received(&a3).await,
            ApplyOutcome::Applied { .. }
        ));
        assert!(app.clear_evidence_dead_branch(REASON_PREFIX).await);
        assert_eq!(app.wedge().expect("read"), None);
        assert!(!app
            .dead_branch_handle()
            .load(std::sync::atomic::Ordering::SeqCst));
        // An applicator marker on an old tip is left alone.
        let own = citrate_storage::chain::wedge::WedgeRecord {
            dead_tip: tip,
            dead_tip_height: 2,
            fork_point: fork.hash,
            fork_height: 1,
            head: h(0xC0),
            head_height: 400,
            reason: "RefusePruned".into(),
            since_unix: 1,
        };
        citrate_storage::chain::wedge::write(&storage.db, &own).expect("write");
        assert!(!app.clear_evidence_dead_branch(REASON_PREFIX).await);
        assert_eq!(app.wedge().expect("read"), Some(own));
    }
}
