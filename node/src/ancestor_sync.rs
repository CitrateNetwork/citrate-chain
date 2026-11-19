// citrate/node/src/ancestor_sync.rs
//
// Header-first ancestor sync: rejoin a heavier branch from the most recent
// common ancestor with the peer that holds it.
//
// THE FAILURE (r1007, 2026-11-15 00:28Z, fork at 105,012)
//
// Right after checkpoint 105,000 finalized, missing-parent fetches failed
// (`SYNCRECOVERY gave up ... InFlightCap / Unanswered`) and every producer
// built only on its own blocks. The partitions never re-converged. A node on a
// lighter branch kept receiving the heavier branch's blocks ("Validated and
// imported 32/32 (height 224101-224132)"), stored none of them (each deferred on
// a missing parent), and anchored every request at its OWN applied height,
// which on the other branch is above the fork point, so nothing it was sent
// ever connected. The missing-parent walk stops a few hundred heights down;
// the fork-point bisection costs one full `GetBlocks` round trip per step and
// was steered by advertised heads that relayed gossip inflates. After 63 hours
// the fork was about 120,000 heights deep on every branch.
//
// THE PROTOCOL (ProtocolVersion 1.3, `ANCESTOR_SYNC`; ADR in
// .agentile/adrs/ADR-2026-11-17-ancestor-sync.md)
//
// * `GetAncestor { locator }`: up to `MAX_LOCATOR_HASHES` hashes of this
//   node's executed chain, newest first: the applied tip and the 15 heights
//   below it, then exponentially spaced heights (2, 4, 8, ... below), then the
//   finalized checkpoint and genesis ([`build_locator`]). O(log depth) hashes
//   cover a fork of any depth: 34 hashes reach 120,000 heights.
// * `Ancestor { common, tip, tip_blue_work, headers }`: the highest locator
//   entry the server holds ON ITS EXECUTED CHAIN, the server's applied tip, and
//   up to `MAX_ANCESTOR_HEADERS` headers of its executed chain above `common`
//   (`block_serve::serve_ancestor`). Stateless on the server: the next window
//   is asked with a locator that starts at the last header received.
//
// THE DRIVER ([`AncestorSync`]), one episode at a time, one request in flight:
//
// 1. Locate: on evidence that this node lacks a branch (a deferred block, or
//    a sync target above the applied tip), ask one 1.3 peer whose advertised
//    head this node does not hold. Peers are tried in turn with a per-peer
//    cooldown, so a peer that is merely ahead on our own branch costs one
//    small exchange per cooldown ([`Outcome::Extends`]).
// 2. Headers: every header is checked against the one before it (selected
//    parent link, height + 1, strictly increasing blue score, blue work equal
//    to `blue_work_for_score`, timestamp not in the future) starting from the
//    common block, whose header this node holds ([`verify_headers`]). The true
//    fork point is the last header whose block this node holds. If it is below
//    the reorg floor (the finalized checkpoint, or more than the undo window
//    `MAX_REORG_DEPTH` below the applied tip) the episode ends without
//    fetching a body ([`Outcome::TooDeep`]): that branch cannot be switched to
//    in place, and fetching it would be unbounded work for nothing.
// 3. Work gate: bodies are fetched only once a verified header claims more
//    blue work than this node's applied tip. A branch whose headers up to the
//    peer's tip claim no more work ends the episode with no body fetched
//    ([`Outcome::NotHeavier`]).
// 4. Bodies: `GetBlocks` anchored at the highest header-chain block held (the
//    peer holds it: it is on its executed chain), `BODY_WINDOW` heights at a
//    time. Every block goes through `SyncManager::handle_blocks` and
//    `BlockAdmission::admit`, which recompute the hash, check the signature and
//    eligibility, and recompute GHOSTDAG blue score and work (a header that
//    lied about its work is rejected there, G7). An answer that does not move
//    the header cursor is a stall; `MAX_STALLED_BODY_ANSWERS` end the episode.
//
// NOTHING HERE DECIDES VALIDITY OR FORK CHOICE. The episode only picks what to
// ask for. Fork choice (GHOSTDAG) and the applicator's strictly-heavier and
// finality-floor rules (`canonical_apply`, I4) decide whether the applied tip
// moves. Claimed heights and work only gate fetching; they are never trusted.
//
// BOUNDS. Memory: at most `HEADER_BUFFER_CAP` verified header hashes held per
// episode, one episode, `MAX_COOLDOWN_PEERS` cooldown entries. Bandwidth per
// episode: one request in flight, a locator reply is one Noise message, a body
// window is one `GetBlocks` of `BODY_WINDOW` heights, at most
// `MAX_EPISODE_HEADERS` headers. Resumable: an episode that ends keeps every
// body it stored, so the next episode's locator meets the peer higher up.
//
// MIXED VERSIONS. `GetAncestor` / `Ancestor` are sent only to peers that
// advertised 1.3 (`Peer::send` withholds them from older peers, which would
// fail to decode them and drop the connection). Toward an older peer the
// existing fork-point search (`sync_rejoin`, `GetBlocks` bisection) still runs.

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

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use citrate_consensus::types::{blue_work_for_score, BlockHeader, Hash};
use citrate_network::protocol::{MAX_ANCESTOR_HEADERS, MAX_LOCATOR_HASHES};

/// Heights directly below the applied tip that the locator lists one by one.
pub const LOCATOR_DENSE: u64 = 16;

/// Verified header hashes (with heights, 40 bytes each) an episode holds
/// ahead of the bodies it has: the whole episode cap, under 1 MB.
pub const HEADER_BUFFER_CAP: usize = MAX_EPISODE_HEADERS as usize;

/// Below this many buffered headers (and the peer's tip not reached) the next
/// request is for more headers rather than bodies.
pub const HEADER_LOW_WATER: usize = 1_024;

/// Headers one episode may verify in total. Twice the undo window: the fork
/// point is at most `MAX_REORG_DEPTH` below the applied tip, and a branch that
/// does not overtake this node's work within that many heights above it is
/// not one this episode should keep following (normal sync takes over once
/// fork choice has switched).
pub const MAX_EPISODE_HEADERS: u64 = crate::canonical_apply::MAX_REORG_DEPTH.saturating_mul(2);

/// Heights per body request.
pub const BODY_WINDOW: u32 = 32;

/// A request without its answer for this long ends the episode.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The longest one episode may run, whatever its peer does. An honest deep
/// fetch that needs longer ends with [`Outcome::Budget`] and the next episode
/// resumes from what is held by then (PR #483 review, P1-1: a peer answering
/// each request just inside [`REQUEST_TIMEOUT`] could otherwise hold an
/// episode for the whole header cap).
pub const EPISODE_MAX_DURATION: Duration = Duration::from_secs(120);

/// Requests one episode may make, sent or not (a request the sync manager
/// refused counts: InFlightCap must not hold an episode open).
pub const EPISODE_MAX_ROUNDS: u32 = 512;

/// Resumable budget endings in a row with one peer that did not move the
/// applied tip, before that peer gets the ordinary failure cooldown (review
/// round 2: a peer must not restart episode after episode for free).
pub const MAX_IDLE_BUDGETS: u32 = 2;

/// Requests in a row the sync manager refused before the episode ends.
pub const MAX_UNSENT_ROUNDS: u32 = 4;

/// Body answers in a row that hold no new header-chain block before the
/// episode ends.
pub const MAX_STALLED_BODY_ANSWERS: u32 = 4;

/// Without fresh evidence (a deferred block) for this long, no episode starts
/// unless the sync target is above the applied tip.
pub const EVIDENCE_TTL: Duration = Duration::from_secs(30);

/// A peer is not asked again for this long after an episode with it ended
/// (doubled per consecutive failure, up to [`COOLDOWN_MAX`]).
pub const COOLDOWN_BASE: Duration = Duration::from_secs(30);
/// Cap on a peer's cooldown.
pub const COOLDOWN_MAX: Duration = Duration::from_secs(1_800);
/// A fork below the reorg floor does not go away: the peer is not asked again
/// for this long.
pub const TOO_DEEP_COOLDOWN: Duration = COOLDOWN_MAX;

/// Deliverers of deferred blocks remembered, at most; the oldest is dropped.
pub const MAX_DELIVERERS: usize = 256;

/// Peers with a cooldown recorded, at most; the soonest to expire is dropped.
pub const MAX_COOLDOWN_PEERS: usize = 256;

/// How far in the future (by local wall time) a header's timestamp may be.
pub const MAX_HEADER_FUTURE_SECS: u64 = 15;

/// Why an episode ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The peer's executed chain extends ours (the fork point is our applied
    /// tip): ordinary sync owns that gap.
    Extends,
    /// Every header up to the peer's tip verified and none claims more blue
    /// work than our applied tip: no body was fetched.
    NotHeavier { fork: u64, peer_tip: u64 },
    /// Every verified header's block is held. Fork choice decides.
    Fetched { fork: u64, top: u64 },
    /// The fork point is below the reorg floor (the finalized checkpoint, or
    /// more than the undo window below the applied tip). No body was fetched.
    /// A node stranded on such a fork needs a resync (`dead_branch.rs` decides
    /// when the evidence is strong enough to do it automatically).
    ///
    /// `fork_hash` is the fork point's block. `diverged` is the first header
    /// of the peer's branch that is not on our executed chain, set only when
    /// the episode located the fork exactly and that header verified as the
    /// child of our block at the fork (`verify_headers`); `None` for a fork
    /// below the finalized checkpoint (I4), where no header is checked.
    TooDeep {
        fork: u64,
        depth: u64,
        floor: u64,
        fork_hash: Hash,
        diverged: Option<Hash>,
    },
    /// The peer holds none of our locator on its executed chain.
    NoCommon,
    /// The reply broke the protocol (a common block we never sent, headers
    /// that do not verify, a branch longer than the episode cap).
    Faulty(String),
    /// A request went unanswered for [`REQUEST_TIMEOUT`].
    Timeout,
    /// [`MAX_STALLED_BODY_ANSWERS`] body answers moved nothing.
    Stalled,
    /// The peer's executed chain no longer holds our last header (it reorged).
    PeerMoved,
    /// The episode's time, round or header budget ran out. Resumable: what
    /// was fetched stays stored, so the next episode's locator meets the peer
    /// higher up. Not held against the peer when it delivered bodies.
    Budget { fetched: u64 },
    /// The peer disconnected.
    PeerLeft,
}

impl Outcome {
    /// Whether the outcome counts against the peer (longer cooldown).
    fn is_failure(&self) -> bool {
        matches!(
            self,
            Outcome::Faulty(_)
                | Outcome::Timeout
                | Outcome::Stalled
                | Outcome::NoCommon
                | Outcome::Budget { fetched: 0 }
        )
    }
}

/// Why a run of headers does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderFault {
    /// The header's selected parent is not the header before it.
    Unlinked { height: u64 },
    /// The height is not one above the header before it.
    HeightGap { height: u64 },
    /// The blue score does not increase.
    ScoreNotIncreasing { height: u64 },
    /// `blue_work` is not `blue_work_for_score(blue_score)` (CV-3).
    WorkMismatch { height: u64 },
    /// The timestamp is more than [`MAX_HEADER_FUTURE_SECS`] ahead of local time.
    FromTheFuture { height: u64 },
    /// More headers than one reply may carry.
    TooMany,
}

/// The block a run of headers must continue from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub hash: Hash,
    pub height: u64,
    pub blue_score: u64,
}

/// Check `headers` as one selected-parent chain continuing `prev`. Only what
/// headers alone can prove: the bodies are checked in full on admission.
pub fn verify_headers(
    prev: Link,
    headers: &[BlockHeader],
    now_secs: u64,
) -> Result<(), HeaderFault> {
    if headers.len() > MAX_ANCESTOR_HEADERS as usize {
        return Err(HeaderFault::TooMany);
    }
    let mut prev = prev;
    for h in headers {
        if h.selected_parent_hash != prev.hash {
            return Err(HeaderFault::Unlinked { height: h.height });
        }
        if Some(h.height) != prev.height.checked_add(1) {
            return Err(HeaderFault::HeightGap { height: h.height });
        }
        if h.blue_score <= prev.blue_score {
            return Err(HeaderFault::ScoreNotIncreasing { height: h.height });
        }
        if h.blue_work != blue_work_for_score(h.blue_score) {
            return Err(HeaderFault::WorkMismatch { height: h.height });
        }
        if h.timestamp > now_secs.saturating_add(MAX_HEADER_FUTURE_SECS) {
            return Err(HeaderFault::FromTheFuture { height: h.height });
        }
        prev = Link {
            hash: h.block_hash,
            height: h.height,
            blue_score: h.blue_score,
        };
    }
    Ok(())
}

/// The locator for this node's executed chain: the applied tip and the
/// [`LOCATOR_DENSE`] - 1 heights below it, then heights 2, 4, 8, ... further
/// below, strictly above `floor` (the finalized checkpoint, or genesis), then
/// `floor` and genesis. `lookup(h)` names the executed chain's block at `h`
/// (`sync_rejoin::anchor_at_height`); a height it cannot name is skipped. At
/// most [`MAX_LOCATOR_HASHES`] hashes, no repeats, newest first.
#[cfg(test)]
pub fn build_locator(
    applied: (Hash, u64),
    floor: (Hash, u64),
    genesis: Hash,
    lookup: impl Fn(u64) -> Option<Hash>,
) -> Vec<Hash> {
    build_locator_with_heights(applied, floor, genesis, lookup)
        .into_iter()
        .map(|(h, _)| h)
        .collect()
}

/// The locator for this node's executed chain (see `build_locator`), with the
/// height of each entry (genesis at 0).
pub fn build_locator_with_heights(
    applied: (Hash, u64),
    floor: (Hash, u64),
    genesis: Hash,
    lookup: impl Fn(u64) -> Option<Hash>,
) -> Vec<(Hash, u64)> {
    let budget = MAX_LOCATOR_HASHES.saturating_sub(2);
    let mut out: Vec<(Hash, u64)> = Vec::with_capacity(MAX_LOCATOR_HASHES);
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut push = |h: Hash, height: u64, out: &mut Vec<(Hash, u64)>| {
        if seen.insert(h) {
            out.push((h, height));
        }
    };
    if applied.1 > floor.1 {
        push(applied.0, applied.1, &mut out);
    }
    let mut height = applied.1;
    let mut step: u64 = 1;
    let mut listed: u64 = 1;
    while out.len() < budget {
        let Some(next) = height.checked_sub(step) else {
            break;
        };
        if next <= floor.1 {
            break;
        }
        height = next;
        if let Some(h) = lookup(height) {
            push(h, height, &mut out);
        }
        listed = listed.saturating_add(1);
        if listed >= LOCATOR_DENSE {
            step = step.saturating_mul(2);
        }
    }
    push(floor.0, floor.1, &mut out);
    push(genesis, 0, &mut out);
    out
}

/// The locator that narrows a fork known to lie between our block `lo` (held
/// on the peer's executed chain) and height `hi` (our block there is not):
/// our executed chain's blocks at up to `MAX_LOCATOR_HASHES - 1` evenly
/// spaced heights strictly between them, newest first, then `lo`. The peer's
/// answer names the highest it holds, so each round shrinks the gap about
/// 63-fold (a gap of 130,000 heights is closed in three rounds), and the
/// headers above it then show the first block of its branch.
pub fn refine_locator(
    lo: (Hash, u64),
    hi: u64,
    lookup: impl Fn(u64) -> Option<Hash>,
) -> Vec<(Hash, u64)> {
    let gap = hi.saturating_sub(lo.1).saturating_sub(1);
    let slots = (MAX_LOCATOR_HASHES.saturating_sub(1) as u64).min(gap);
    let mut out: Vec<(Hash, u64)> = Vec::with_capacity(MAX_LOCATOR_HASHES);
    let mut last = hi;
    for i in (1..=slots).rev() {
        // i * (gap + 1) / (slots + 1) is in 1..=gap and strictly increasing in i.
        let off = i
            .saturating_mul(gap.saturating_add(1))
            .checked_div(slots.saturating_add(1))
            .unwrap_or(0);
        let height = lo.1.saturating_add(off);
        if height <= lo.1 || height >= last {
            continue;
        }
        last = height;
        if let Some(h) = lookup(height) {
            out.push((h, height));
        }
    }
    out.push(lo);
    out
}

/// A connected peer as the episode driver sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    /// It advertised `ProtocolVersion::ANCESTOR_SYNC` or later.
    pub speaks: bool,
    /// Its advertised head.
    pub head_hash: Hash,
    pub head_height: u64,
    /// This node stores the block `head_hash` names.
    pub head_held: bool,
}

/// What this node knows of itself when the driver runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View {
    pub applied: (Hash, u64),
    /// `blue_work` of the applied tip's header.
    pub applied_blue_work: u128,
    /// The finalized checkpoint `(hash, height)` (genesis when none).
    pub finalized: (Hash, u64),
    pub genesis: Hash,
    /// The sync target is above the applied tip.
    pub behind: bool,
}

impl View {
    /// The lowest fork point this node can switch from in place: the finalized
    /// checkpoint, and no more than the undo window below the applied tip.
    pub fn reorg_floor(&self) -> u64 {
        self.finalized.1.max(
            self.applied
                .1
                .saturating_sub(crate::canonical_apply::MAX_REORG_DEPTH),
        )
    }
}

/// What the driver asks the sync tick to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `GetAncestor { locator }` to `peer`.
    Locate { peer: String, locator: Vec<Hash> },
    /// `GetBlocks { from }` to `peer`, through `SyncManager::request_blocks`
    /// (its batch, [`BODY_WINDOW`] heights, is the sync manager's).
    Bodies {
        peer: String,
        from: Hash,
        height: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Asked {
    Locate { at: Instant, locator: Vec<Hash> },
    Bodies { at: Instant, anchor: Hash },
}

#[derive(Debug)]
struct Episode {
    peer: String,
    asked: Option<Asked>,
    /// The base locator (our executed chain) of this episode, with heights.
    base: Vec<(Hash, u64)>,
    /// The locator of the request in flight, with heights.
    sent: Vec<(Hash, u64)>,
    /// The lowest height at which a locator entry we sent was NOT on the
    /// peer's executed chain: the fork point is below it.
    upper: Option<u64>,
    /// A fork-point search is due: the fork lies between our block `.0`
    /// (on the peer's chain) and height `.1` ([`refine_locator`]).
    refine: Option<((Hash, u64), u64)>,
    /// The last verified header, the next reply continues from it.
    last: Option<Link>,
    /// The highest header-chain block this node holds: the fork point until
    /// a body above it arrives, then the body cursor.
    held: Option<(Hash, u64)>,
    /// The fork point (fixed once the first header this node lacks is seen).
    fork: Option<(Hash, u64)>,
    /// Verified header hashes above `held`, ascending, whose blocks this node
    /// does not hold yet.
    headers: VecDeque<(Hash, u64)>,
    /// The peer's applied tip as it reported it (a claim).
    peer_tip: (Hash, u64),
    /// The last reply's headers reached the peer's reported tip.
    tip_reached: bool,
    /// A verified header claims more blue work than our applied tip.
    work_ok: bool,
    verified: u64,
    stalled: u32,
    /// When the episode started (its [`EPISODE_MAX_DURATION`] clock).
    started: Instant,
    /// Requests made, sent or not ([`EPISODE_MAX_ROUNDS`]).
    rounds: u32,
    /// Requests in a row the sync manager refused ([`MAX_UNSENT_ROUNDS`]).
    unsent: u32,
    /// Heights the body cursor moved on this episode's own body answers.
    fetched: u64,
    /// The last answer this episode consumed was a body answer: the cursor
    /// catch-up after it ([`AncestorSync::advance`]) counts as fetched.
    body_answered: bool,
    /// This node's applied tip when the episode started.
    start_applied: Hash,
}

/// The episode driver described at the top of this file.
#[derive(Debug, Default)]
pub struct AncestorSync {
    episode: Option<Episode>,
    /// peer -> (not before, consecutive failures).
    cooldown: HashMap<String, (Instant, u32)>,
    /// When a block last deferred on a missing parent.
    evidence_at: Option<Instant>,
    /// Peers that delivered a block that deferred on a missing parent, and
    /// when they last did ([`MAX_DELIVERERS`] at most): the peers most likely
    /// to hold the branch this node lacks. An advertised head says less: a
    /// relayed block raises the relaying peer's head whether or not it holds
    /// that block's branch.
    deliverers: HashMap<String, Instant>,
    /// The peer of the last episode that ended (for its log line).
    last_peer: Option<String>,
    /// Episodes ended, by outcome kind (diagnostics).
    ended: HashMap<&'static str, u64>,
    /// The applied tip as of the last tick.
    applied_now: Hash,
    /// peer -> resumable budget endings in a row that left the applied tip
    /// where the episode found it ([`MAX_IDLE_BUDGETS`]).
    idle_budgets: HashMap<String, u32>,
}

impl AncestorSync {
    pub fn new() -> Self {
        Self::default()
    }

    /// A block `peer` delivered deferred on a missing parent: evidence of a
    /// branch this node lacks, and a candidate to ask (only whether and with
    /// whom an episode may start; it moves nothing else).
    pub fn note_deferred(&mut self, peer: &str, now: Instant) {
        self.evidence_at = Some(now);
        if self.deliverers.len() >= MAX_DELIVERERS && !self.deliverers.contains_key(peer) {
            if let Some(oldest) = self
                .deliverers
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(p, _)| p.clone())
            {
                self.deliverers.remove(&oldest);
            }
        }
        self.deliverers.insert(peer.to_string(), now);
    }

    fn delivered_recently(&self, peer: &str, now: Instant) -> Option<Instant> {
        self.deliverers
            .get(peer)
            .copied()
            .filter(|at| now.saturating_duration_since(*at) < EVIDENCE_TTL)
    }

    /// A body request of the running episode is in flight AND an earlier
    /// body answer of this same episode already had a block admitted. Only
    /// then do the sync tick's own request and the pipeline stand aside.
    /// Locating, header paging and an episode's first body request never do,
    /// however much work the headers claim (PR #483 review rounds 1 to 3: a
    /// peer dripping fabricated headers held the tick aside for 99% of the
    /// time; then 32 peers taking turns, each asked for one body it never
    /// delivered, held it aside for 88%). A peer earns the stand-aside only
    /// by delivering a block admission accepted.
    pub fn owns_sync(&self) -> bool {
        self.episode
            .as_ref()
            .is_some_and(|e| e.fetched > 0 && matches!(e.asked, Some(Asked::Bodies { .. })))
    }

    /// Move the body cursor past every buffered header whose block this node
    /// now holds. A body answer is split under the Noise cap and arrives as
    /// several messages; only the first carries the anchor that
    /// [`Self::on_blocks`] matches, so the cursor catches up with the rest
    /// here, before the next window is asked (otherwise the next window would
    /// ask for most of the last one again).
    pub fn advance(&mut self, holds: impl Fn(&Hash) -> bool) {
        let Some(e) = self.episode.as_mut() else {
            return;
        };
        if e.asked.is_some() {
            return;
        }
        while let Some((hash, height)) = e.headers.front().copied() {
            if !holds(&hash) {
                break;
            }
            // Only blocks this episode's own body answers brought in count as
            // fetched: a block held before (a side block served as the first
            // header) moves the cursor but is no progress (review round 2).
            if e.body_answered {
                let from = e.held.map(|h| h.1).unwrap_or(height);
                e.fetched = e.fetched.saturating_add(height.saturating_sub(from));
                e.stalled = 0;
            }
            e.held = Some((hash, height));
            e.headers.pop_front();
        }
    }

    /// The request to send right after an answer, if the running episode has
    /// one and nothing is in flight: an episode does not wait for the next
    /// sync tick between rounds. Bounded by the same round and time budgets
    /// as the tick (which ends an episode that ran out).
    pub fn next(&mut self, now: Instant) -> Option<Request> {
        let e = self.episode.as_mut()?;
        if e.asked.is_some()
            || e.refine.is_some()
            || e.rounds >= EPISODE_MAX_ROUNDS
            || now.saturating_duration_since(e.started) >= EPISODE_MAX_DURATION
            || (e.fork.is_some() && e.tip_reached && e.headers.is_empty())
        {
            return None;
        }
        Self::next_request(e, now)
    }

    /// The next `limit` buffered header hashes the body cursor waits on.
    pub fn front_headers(&self, limit: usize) -> Vec<Hash> {
        self.episode
            .as_ref()
            .map(|e| e.headers.iter().take(limit).map(|(h, _)| *h).collect())
            .unwrap_or_default()
    }

    /// A one-line state summary (diagnostics, harness failure output).
    pub fn summary(&self) -> String {
        let mut ended: Vec<String> = self.ended.iter().map(|(k, v)| format!("{k}={v}")).collect();
        ended.sort();
        match &self.episode {
            Some(e) => format!(
                "episode(peer={} asked={} fork={:?} held={:?} headers={} work_ok={} tip_reached={} rounds={} fetched={}) ended[{}]",
                e.peer,
                e.asked.is_some(),
                e.fork.map(|f| f.1),
                e.held.map(|h| h.1),
                e.headers.len(),
                e.work_ok,
                e.tip_reached,
                e.rounds,
                e.fetched,
                ended.join(" ")
            ),
            None => format!("idle ended[{}]", ended.join(" ")),
        }
    }

    /// The peer of the last episode that ended.
    pub fn last_peer(&self) -> Option<&str> {
        self.last_peer.as_deref()
    }

    fn cooling(&self, peer: &str, now: Instant) -> bool {
        self.cooldown
            .get(peer)
            .is_some_and(|(until, _)| now < *until)
    }

    fn end(&mut self, outcome: Outcome, now: Instant) -> Option<Outcome> {
        let episode = self.episode.take()?;
        let failures = self
            .cooldown
            .get(&episode.peer)
            .map(|(_, f)| *f)
            .unwrap_or(0);
        let idle = match &outcome {
            Outcome::Budget { fetched } if *fetched > 0 => {
                let streak = self.idle_budgets.entry(episode.peer.clone()).or_insert(0);
                if self.applied_now == episode.start_applied {
                    *streak = streak.saturating_add(1);
                } else {
                    *streak = 0;
                }
                *streak >= MAX_IDLE_BUDGETS
            }
            Outcome::PeerLeft => false,
            _ => {
                self.idle_budgets.remove(&episode.peer);
                false
            }
        };
        if self.idle_budgets.len() > MAX_COOLDOWN_PEERS {
            self.idle_budgets.clear();
        }
        let (wait, failures) = match &outcome {
            Outcome::TooDeep { .. } => (TOO_DEEP_COOLDOWN, failures),
            Outcome::PeerLeft => (Duration::ZERO, failures),
            // Resumable, and the peer delivered: ask it again at once, unless
            // its last budgets in a row left the applied tip where it was.
            Outcome::Budget { fetched } if *fetched > 0 && !idle => (Duration::ZERO, 0),
            Outcome::Budget { fetched } if *fetched > 0 => {
                let shift = failures.min(6);
                (
                    COOLDOWN_BASE
                        .saturating_mul(2u32.saturating_pow(shift))
                        .min(COOLDOWN_MAX),
                    failures.saturating_add(1),
                )
            }
            o if o.is_failure() => {
                let shift = failures.min(6);
                (
                    COOLDOWN_BASE
                        .saturating_mul(2u32.saturating_pow(shift))
                        .min(COOLDOWN_MAX),
                    failures.saturating_add(1),
                )
            }
            Outcome::Fetched { .. } => (COOLDOWN_BASE, 0),
            _ => (COOLDOWN_BASE, failures),
        };
        if self.cooldown.len() >= MAX_COOLDOWN_PEERS && !self.cooldown.contains_key(&episode.peer) {
            if let Some(soonest) = self
                .cooldown
                .iter()
                .min_by_key(|(_, (until, _))| *until)
                .map(|(p, _)| p.clone())
            {
                self.cooldown.remove(&soonest);
            }
        }
        self.last_peer = Some(episode.peer.clone());
        let kind = match &outcome {
            Outcome::Extends => "extends",
            Outcome::NotHeavier { .. } => "not_heavier",
            Outcome::Fetched { .. } => "fetched",
            Outcome::TooDeep { .. } => "too_deep",
            Outcome::NoCommon => "no_common",
            Outcome::Faulty(_) => "faulty",
            Outcome::Timeout => "timeout",
            Outcome::Stalled => "stalled",
            Outcome::PeerMoved => "peer_moved",
            Outcome::PeerLeft => "peer_left",
            Outcome::Budget { .. } => "budget",
        };
        let count = self.ended.entry(kind).or_insert(0);
        *count = count.saturating_add(1);
        if let Outcome::Faulty(why) = &outcome {
            tracing::debug!("ancestor episode faulty: {why}");
        }
        self.cooldown.insert(
            episode.peer,
            (now.checked_add(wait).unwrap_or(now), failures),
        );
        Some(outcome)
    }

    /// One sync tick: the request to send now, if any, and the outcome of an
    /// episode that ended on this tick. `lookup(h)` names the executed chain's
    /// block at height `h` (for the locator).
    pub fn tick(
        &mut self,
        now: Instant,
        view: &View,
        candidates: &[Candidate],
        lookup: impl Fn(u64) -> Option<Hash>,
    ) -> (Option<Request>, Option<Outcome>) {
        self.applied_now = view.applied.0;
        let mut ended = None;
        if let Some(e) = &self.episode {
            if !candidates.iter().any(|c| c.id == e.peer) {
                ended = self.end(Outcome::PeerLeft, now);
            } else {
                let timed_out = match &e.asked {
                    Some(Asked::Locate { at, .. }) | Some(Asked::Bodies { at, .. }) => {
                        now.saturating_duration_since(*at) >= REQUEST_TIMEOUT
                    }
                    None => false,
                };
                if timed_out {
                    ended = self.end(Outcome::Timeout, now);
                } else if e.rounds >= EPISODE_MAX_ROUNDS
                    || now.saturating_duration_since(e.started) >= EPISODE_MAX_DURATION
                {
                    let fetched = e.fetched;
                    ended = self.end(Outcome::Budget { fetched }, now);
                }
            }
        }
        if let Some(e) = self.episode.as_mut() {
            if e.asked.is_some() {
                return (None, ended);
            }
            if let Some((lo, hi)) = e.refine.take() {
                let sent = refine_locator(lo, hi, &lookup);
                let locator: Vec<Hash> = sent.iter().map(|(h, _)| *h).collect();
                e.sent = sent;
                // The answer's common block is one of these: the headers
                // continue from our own copy of it.
                e.last = None;
                e.held = None;
                e.asked = Some(Asked::Locate {
                    at: now,
                    locator: locator.clone(),
                });
                e.rounds = e.rounds.saturating_add(1);
                e.body_answered = false;
                let peer = e.peer.clone();
                return (Some(Request::Locate { peer, locator }), ended);
            }
            if e.fork.is_some() && e.tip_reached && e.headers.is_empty() {
                let fork = e.fork.map(|f| f.1).unwrap_or(0);
                let top = e.held.map(|h| h.1).unwrap_or(0);
                return (None, self.end(Outcome::Fetched { fork, top }, now));
            }
            if let Some(req) = Self::next_request(e, now) {
                return (Some(req), ended);
            }
            // Nothing left to ask and no verdict: the header buffer is full
            // below the work this node already has.
            return (None, self.end(Outcome::Stalled, now));
        }
        let evidence = view.behind
            || self
                .evidence_at
                .is_some_and(|at| now.saturating_duration_since(at) < EVIDENCE_TTL);
        if !evidence {
            return (None, ended);
        }
        // Peers that delivered a deferred block first (most recent first),
        // then peers whose advertised head this node does not hold (highest
        // first).
        let Some(pick) = candidates
            .iter()
            .filter(|c| {
                c.speaks
                    && !self.cooling(&c.id, now)
                    && (self.delivered_recently(&c.id, now).is_some()
                        || (!c.head_held && c.head_hash != view.applied.0))
            })
            .max_by(|a, b| {
                self.delivered_recently(&a.id, now)
                    .cmp(&self.delivered_recently(&b.id, now))
                    .then_with(|| (!a.head_held).cmp(&!b.head_held))
                    .then_with(|| a.head_height.cmp(&b.head_height))
                    .then_with(|| b.id.cmp(&a.id))
            })
        else {
            return (None, ended);
        };
        let base = build_locator_with_heights(view.applied, view.finalized, view.genesis, lookup);
        let locator: Vec<Hash> = base.iter().map(|(h, _)| *h).collect();
        let peer = pick.id.clone();
        self.episode = Some(Episode {
            peer: peer.clone(),
            asked: Some(Asked::Locate {
                at: now,
                locator: locator.clone(),
            }),
            sent: base.clone(),
            base,
            upper: None,
            refine: None,
            last: None,
            held: None,
            fork: None,
            headers: VecDeque::new(),
            peer_tip: (Hash::default(), 0),
            tip_reached: false,
            work_ok: false,
            verified: 0,
            stalled: 0,
            started: now,
            rounds: 1,
            unsent: 0,
            fetched: 0,
            body_answered: false,
            start_applied: view.applied.0,
        });
        (Some(Request::Locate { peer, locator }), ended)
    }

    /// The next request of a running episode with nothing in flight.
    fn next_request(e: &mut Episode, now: Instant) -> Option<Request> {
        let last = e.last?;
        let held = e.held?;
        let want_headers = !e.tip_reached && (!e.work_ok || e.headers.len() < HEADER_LOW_WATER);
        if want_headers && e.headers.len() < HEADER_BUFFER_CAP {
            // Resume from the last verified header; the rest of the base
            // locator lets the peer answer even if it reorged since.
            let mut sent = vec![(last.hash, last.height)];
            sent.extend(
                e.base
                    .iter()
                    .copied()
                    .filter(|(h, _)| *h != last.hash)
                    .take(MAX_LOCATOR_HASHES.saturating_sub(1)),
            );
            let locator: Vec<Hash> = sent.iter().map(|(h, _)| *h).collect();
            e.sent = sent;
            e.asked = Some(Asked::Locate {
                at: now,
                locator: locator.clone(),
            });
            e.rounds = e.rounds.saturating_add(1);
            e.body_answered = false;
            return Some(Request::Locate {
                peer: e.peer.clone(),
                locator,
            });
        }
        if e.work_ok && !e.headers.is_empty() {
            e.asked = Some(Asked::Bodies {
                at: now,
                anchor: held.0,
            });
            e.rounds = e.rounds.saturating_add(1);
            e.body_answered = false;
            return Some(Request::Bodies {
                peer: e.peer.clone(),
                from: held.0,
                height: held.1,
            });
        }
        None
    }

    /// The request could not be sent (the sync manager refused it, e.g. at
    /// its in-flight cap, or the peer is gone): forget it and ask again next
    /// round. It still counted against [`EPISODE_MAX_ROUNDS`], and
    /// [`MAX_UNSENT_ROUNDS`] in a row end the episode, so a refusal can never
    /// hold it open (PR #483 review, P1-1). Returns the outcome when it ends.
    pub fn unsent(&mut self, now: Instant) -> Option<Outcome> {
        let e = self.episode.as_mut()?;
        e.asked = None;
        e.unsent = e.unsent.saturating_add(1);
        if e.unsent >= MAX_UNSENT_ROUNDS {
            return self.end(Outcome::Stalled, now);
        }
        None
    }

    /// An `Ancestor` reply from `peer`. `ours(h, height)` says whether block
    /// `h` is on this node's executed chain at `height`; `own_header(h)`
    /// returns the header of a block this node stores. Returns the outcome when the episode ends.
    #[allow(clippy::too_many_arguments)]
    pub fn on_ancestor(
        &mut self,
        peer: &str,
        common: Option<(Hash, u64)>,
        tip: (Hash, u64),
        tip_blue_work: u128,
        headers: &[BlockHeader],
        view: &View,
        now: Instant,
        now_secs: u64,
        ours: impl Fn(&Hash, u64) -> bool,
        own_header: impl Fn(&Hash) -> Option<BlockHeader>,
    ) -> Option<Outcome> {
        let sent = match self.episode.as_ref() {
            Some(e) if e.peer == peer => match &e.asked {
                Some(Asked::Locate { locator, .. }) => locator.clone(),
                _ => return None,
            },
            // Unsolicited: ignored.
            _ => return None,
        };
        let Some((common_hash, common_height)) = common else {
            return self.end(Outcome::NoCommon, now);
        };
        if !sent.contains(&common_hash) {
            return self.end(
                Outcome::Faulty("the common block is not in the locator sent".into()),
                now,
            );
        }
        let floor = view.reorg_floor();
        // I4: a peer whose executed chain does not hold our finalized
        // checkpoint forks below finality; nothing it serves is ever switched to.
        if common_height < view.finalized.1 {
            return self.end(
                Outcome::TooDeep {
                    fork: common_height,
                    depth: view.applied.1.saturating_sub(common_height),
                    floor,
                    fork_hash: common_hash,
                    diverged: None,
                },
                now,
            );
        }
        // The peer's own tip claims no more work than ours: nothing on its
        // chain can be heavier. A claim, so it only ever saves work: a peer
        // that under-reports only keeps its own branch from being fetched.
        if tip_blue_work <= view.applied_blue_work {
            return self.end(
                Outcome::NotHeavier {
                    fork: common_height,
                    peer_tip: tip.1,
                },
                now,
            );
        }
        let e = self.episode.as_mut()?;
        e.asked = None;
        e.unsent = 0;
        e.peer_tip = tip;
        // Every entry we sent above the common block is off the peer's
        // executed chain (it answers with the highest one on it).
        if let Some(above) = e
            .sent
            .iter()
            .filter(|(_, h)| *h > common_height)
            .map(|(_, h)| *h)
            .min()
        {
            e.upper = Some(e.upper.map_or(above, |u| u.min(above)));
        }
        // The link the headers continue from: our last verified header when
        // the peer still holds it, else (first reply) the common block, whose
        // header this node holds.
        let prev = match e.last {
            Some(last) if last.hash == common_hash => last,
            Some(_) => return self.end(Outcome::PeerMoved, now),
            None => match own_header(&common_hash) {
                Some(h) if h.height == common_height => Link {
                    hash: common_hash,
                    height: common_height,
                    blue_score: h.blue_score,
                },
                _ => {
                    return self.end(
                        Outcome::Faulty("the common block's height is not ours".into()),
                        now,
                    )
                }
            },
        };
        if e.held.is_none() {
            e.held = Some((common_hash, common_height));
        }
        if let Err(fault) = verify_headers(prev, headers, now_secs) {
            return self.end(Outcome::Faulty(format!("{fault:?}")), now);
        }
        e.verified = e.verified.saturating_add(headers.len() as u64);
        if e.verified > MAX_EPISODE_HEADERS {
            let fetched = e.fetched;
            return self.end(Outcome::Budget { fetched }, now);
        }
        for h in headers {
            let hash = h.block_hash;
            if e.fork.is_none() {
                // The fork point is the last header ON OUR EXECUTED CHAIN: a
                // side block this node merely stores (gossip, a walk) would
                // make the fork look shallower than it is (PR #483 review).
                if ours(&hash, h.height) {
                    e.held = Some((hash, h.height));
                    continue;
                }
                // The first header that is not ours: the block before it is
                // the fork point.
                let fork = e.held.unwrap_or((common_hash, common_height));
                if fork.1 < floor {
                    let depth = view.applied.1.saturating_sub(fork.1);
                    return self.end(
                        Outcome::TooDeep {
                            fork: fork.1,
                            depth,
                            floor,
                            fork_hash: fork.0,
                            diverged: Some(hash),
                        },
                        now,
                    );
                }
                e.fork = Some(fork);
            }
            if e.headers.len() >= HEADER_BUFFER_CAP {
                break;
            }
            if h.blue_work > view.applied_blue_work {
                e.work_ok = true;
            }
            e.headers.push_back((hash, h.height));
            e.last = Some(Link {
                hash,
                height: h.height,
                blue_score: h.blue_score,
            });
        }
        if e.fork.is_none() {
            // Every header so far is held: keep the cursor on the last one.
            if let Some(last) = headers.last() {
                e.last = Some(Link {
                    hash: last.block_hash,
                    height: last.height,
                    blue_score: last.blue_score,
                });
            } else if e.last.is_none() {
                e.last = Some(prev);
            }
        }
        let at_tip = e.last.is_some_and(|l| l.hash == tip.0) || headers.is_empty();
        e.tip_reached = at_tip;
        // Every header so far is ours, and the fork lies below `upper`: if all
        // of that range is below the reorg floor the fork is too deep, and
        // paging up to it one window at a time would run out of budget (r1007:
        // a common block ~12,600 against a fork at 105,024, with the floor
        // ~265,000). Narrow the range instead; the headers above the fork
        // point then name the first block of the peer's branch.
        if e.fork.is_none() {
            if let (Some(lo), Some(upper)) = (e.held, e.upper) {
                if !at_tip && upper <= floor && upper > lo.1 {
                    e.refine = Some((lo, upper));
                    e.tip_reached = false;
                    return None;
                }
            }
        }
        if at_tip && e.fork.is_none() {
            // Nothing above what we hold. If what we hold ends at our applied
            // tip the peer's chain extends ours (or is ours).
            return self.end(Outcome::Extends, now);
        }
        if let Some(fork) = e.fork {
            if fork.0 == view.applied.0 {
                return self.end(Outcome::Extends, now);
            }
            // Headers spanning the whole reorg window above the fork without
            // claiming more work than ours: nothing further up is a branch
            // this node should fetch now.
            let above = e
                .last
                .map(|l| l.height)
                .unwrap_or(fork.1)
                .saturating_sub(fork.1);
            if !e.work_ok && above >= crate::canonical_apply::MAX_REORG_DEPTH {
                let peer_tip = tip.1;
                return self.end(
                    Outcome::NotHeavier {
                        fork: fork.1,
                        peer_tip,
                    },
                    now,
                );
            }
            if e.tip_reached && !e.work_ok {
                let peer_tip = tip.1;
                return self.end(
                    Outcome::NotHeavier {
                        fork: fork.1,
                        peer_tip,
                    },
                    now,
                );
            }
        }
        None
    }

    /// A `Blocks` answer from `peer` was admitted. `received` is the answer
    /// as it arrived; `holds(h)` reads this node's store after admission.
    /// Returns the outcome when the episode ends.
    pub fn on_blocks(
        &mut self,
        peer: &str,
        received: &[Hash],
        now: Instant,
        holds: impl Fn(&Hash) -> bool,
    ) -> Option<Outcome> {
        let e = self.episode.as_mut()?;
        let anchor = match &e.asked {
            Some(Asked::Bodies { anchor, .. }) if e.peer == peer => *anchor,
            _ => return None,
        };
        // Only the answer to our request: empty, or carrying our anchor.
        if !received.is_empty() && !received.contains(&anchor) {
            return None;
        }
        e.asked = None;
        e.unsent = 0;
        e.body_answered = true;
        let mut moved = false;
        while let Some((hash, height)) = e.headers.front().copied() {
            if !holds(&hash) {
                break;
            }
            let from = e.held.map(|h| h.1).unwrap_or(height);
            e.fetched = e.fetched.saturating_add(height.saturating_sub(from));
            e.held = Some((hash, height));
            e.headers.pop_front();
            moved = true;
        }
        if moved {
            e.stalled = 0;
        } else {
            e.stalled = e.stalled.saturating_add(1);
            if e.stalled >= MAX_STALLED_BODY_ANSWERS {
                return self.end(Outcome::Stalled, now);
            }
        }
        if e.headers.is_empty() && e.tip_reached {
            let fork = e.fork.map(|f| f.1).unwrap_or(0);
            let top = e.held.map(|h| h.1).unwrap_or(0);
            return self.end(Outcome::Fetched { fork, top }, now);
        }
        None
    }
}

/// This node's [`View`]. Data source: the chain store (`BlockStore::get_applied_tip`,
/// `get_header` for the tip's `blue_work`, `get_canonical_block_by_height` for
/// the finalized checkpoint's and genesis's hashes) and the applicator's
/// finalized-height floor (`CanonicalApplicator::finalized_height_handle`).
pub fn read_view(
    storage: &citrate_storage::StorageManager,
    finalized_height: u64,
    behind: bool,
) -> View {
    let applied = storage
        .blocks
        .get_applied_tip()
        .ok()
        .flatten()
        .unwrap_or((Hash::default(), 0));
    let applied_blue_work = storage
        .blocks
        .get_header(&applied.0)
        .ok()
        .flatten()
        .map(|h| h.blue_work)
        .unwrap_or(0);
    let genesis = storage
        .blocks
        .get_canonical_block_by_height(0)
        .ok()
        .flatten()
        .unwrap_or_default();
    let finalized_hash = storage
        .blocks
        .get_canonical_block_by_height(finalized_height)
        .ok()
        .flatten()
        .unwrap_or(genesis);
    View {
        applied,
        applied_blue_work,
        finalized: (finalized_hash, finalized_height),
        genesis,
        behind,
    }
}

/// The connected peers as [`Candidate`]s, with their handles. A head counts
/// as held only when it is fully admitted (chain store AND DAG,
/// `BlockAdmission::is_fully_admitted`): a block that deferred on a missing
/// parent is stored but not admitted, and is exactly the evidence of a branch
/// this node lacks.
pub async fn candidates(
    peers: &[std::sync::Arc<citrate_network::peer::Peer>],
    admission: &crate::admission::BlockAdmission,
) -> Vec<(Candidate, std::sync::Arc<citrate_network::peer::Peer>)> {
    let mut out = Vec::with_capacity(peers.len());
    for p in peers {
        let info = p.info.read().await;
        if info.state != citrate_network::peer::PeerState::Connected {
            continue;
        }
        let id = info.id.0.clone();
        let speaks = info.version.is_some_and(|v| v.understands_ancestor_sync());
        let head_hash = info.head_hash;
        let head_height = info.head_height;
        drop(info);
        let c = Candidate {
            id,
            speaks,
            head_hash,
            head_height,
            head_held: admission.is_fully_admitted(&head_hash).await,
        };
        out.push((c, p.clone()));
    }
    out
}

/// Of the running episode's next buffered headers, those whose blocks are
/// fully admitted (`BlockAdmission::is_fully_admitted`: a stored block that
/// deferred on a missing parent is not). What the body cursor may move past.
pub async fn admitted_front(
    driver: &parking_lot::Mutex<AncestorSync>,
    admission: &crate::admission::BlockAdmission,
) -> HashSet<Hash> {
    let front = driver.lock().front_headers(ADMITTED_FRONT);
    let mut out = HashSet::with_capacity(front.len());
    for h in front {
        if !admission.is_fully_admitted(&h).await {
            break;
        }
        out.insert(h);
    }
    out
}

/// Buffered headers [`admitted_front`] checks per call: four body windows.
pub const ADMITTED_FRONT: usize = (BODY_WINDOW as usize).saturating_mul(4);

/// One sync tick's ancestor-sync step, as `start_node` runs it: the driver's
/// request for this tick, sent. `GetAncestor` goes straight to the peer
/// (`Peer::send` withholds it from a peer below 1.3); a body window goes
/// through `SyncManager::request_blocks`, so its answer is validated, admitted
/// and timed like any other. Returns the outcome of an episode that ended.
#[allow(clippy::too_many_arguments)]
pub async fn run_tick(
    driver: &parking_lot::Mutex<AncestorSync>,
    storage: &citrate_storage::StorageManager,
    admission: &crate::admission::BlockAdmission,
    sync: &citrate_network::sync::SyncManager,
    peers: &[(Candidate, std::sync::Arc<citrate_network::peer::Peer>)],
    finalized_height: u64,
    behind: bool,
    now: Instant,
) -> Option<Outcome> {
    let view = read_view(storage, finalized_height, behind);
    let cands: Vec<Candidate> = peers.iter().map(|(c, _)| c.clone()).collect();
    let admitted = admitted_front(driver, admission).await;
    driver.lock().advance(|h| admitted.contains(h));
    let (request, ended) = driver.lock().tick(now, &view, &cands, |h| {
        crate::sync_rejoin::anchor_at_height(storage, h)
    });
    if let Some(o) = &ended {
        let (peer, summary) = {
            let d = driver.lock();
            (d.last_peer().unwrap_or("-").to_string(), d.summary())
        };
        log_outcome(&peer, o);
        tracing::debug!("SYNCANCESTOR {summary}");
    }
    let Some(request) = request else {
        return ended;
    };
    let target = match &request {
        Request::Locate { peer, .. } | Request::Bodies { peer, .. } => peer.clone(),
    };
    let Some(handle) = peers
        .iter()
        .find(|(c, _)| c.id == target)
        .map(|(_, p)| p.clone())
    else {
        return driver.lock().unsent(now).or(ended);
    };
    let sent = match request {
        Request::Locate { locator, .. } => {
            tracing::debug!(
                "SYNCANCESTOR locate {} hash(es) from {} @ {} at {}",
                locator.len(),
                view.applied.0,
                view.applied.1,
                target
            );
            handle
                .send(citrate_network::NetworkMessage::GetAncestor { locator })
                .await
                .is_ok()
        }
        Request::Bodies { from, height, .. } => {
            tracing::debug!(
                "SYNCANCESTOR bodies from {} @ {} ({} heights) at {}",
                from,
                height,
                BODY_WINDOW,
                target
            );
            matches!(sync.request_blocks(&handle, from, height).await, Ok(true))
        }
    };
    if !sent {
        if let Some(o) = driver.lock().unsent(now) {
            log_outcome(&target, &o);
        }
    }
    ended
}

/// Send the running episode's next request right after an answer from
/// `peer` (see [`AncestorSync::next`]), so an episode does not wait a sync
/// tick per round. The cursor first catches up with what is stored.
pub async fn send_next(
    driver: &parking_lot::Mutex<AncestorSync>,
    admission: &crate::admission::BlockAdmission,
    sync: &citrate_network::sync::SyncManager,
    peer: Option<std::sync::Arc<citrate_network::peer::Peer>>,
    now: Instant,
) {
    let Some(handle) = peer else {
        return;
    };
    let id = handle.info.read().await.id.0.clone();
    let admitted = admitted_front(driver, admission).await;
    let request = {
        let mut d = driver.lock();
        if d.episode.as_ref().map(|e| e.peer.as_str()) != Some(id.as_str()) {
            return;
        }
        d.advance(|h| admitted.contains(h));
        d.next(now)
    };
    let Some(request) = request else {
        return;
    };
    let sent = match request {
        Request::Locate { locator, .. } => handle
            .send(citrate_network::NetworkMessage::GetAncestor { locator })
            .await
            .is_ok(),
        Request::Bodies { from, height, .. } => {
            matches!(sync.request_blocks(&handle, from, height).await, Ok(true))
        }
    };
    if !sent {
        if let Some(o) = driver.lock().unsent(now) {
            log_outcome(&id, &o);
        }
    }
}

/// An `Ancestor` reply from `peer`, judged against this node's store (see
/// [`AncestorSync::on_ancestor`]; data source as [`read_view`], plus
/// `BlockStore::has_block` / `get_header`).
#[allow(clippy::too_many_arguments)]
pub fn on_reply(
    driver: &parking_lot::Mutex<AncestorSync>,
    storage: &citrate_storage::StorageManager,
    finalized_height: u64,
    peer: &str,
    common: Option<(Hash, u64)>,
    tip: (Hash, u64),
    tip_blue_work: u128,
    headers: &[BlockHeader],
    now: Instant,
) -> Option<Outcome> {
    let view = read_view(storage, finalized_height, false);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let applied_height = view.applied.1;
    let out = driver.lock().on_ancestor(
        peer,
        common,
        tip,
        tip_blue_work,
        headers,
        &view,
        now,
        now_secs,
        // On this node's executed chain: at or below the applied tip, the
        // canonical height index names it.
        |h, height| {
            height <= applied_height
                && storage
                    .blocks
                    .get_canonical_block_by_height(height)
                    .ok()
                    .flatten()
                    == Some(*h)
        },
        |h| storage.blocks.get_header(h).ok().flatten(),
    );
    if let Some(o) = &out {
        log_outcome(peer, o);
    }
    out
}

/// One line per ended episode. A fork below the reorg floor is a warning: the
/// node cannot rejoin that branch in place (operator re-seed).
pub fn log_outcome(peer: &str, outcome: &Outcome) {
    let short = peer.get(..14).unwrap_or(peer);
    match outcome {
        Outcome::TooDeep {
            fork, depth, floor, ..
        } => tracing::warn!(
            "SYNCANCESTOR peer {} is on a branch forked at height {} ({} below our applied tip), \
             below our reorg floor {}: not fetched. This node cannot switch to it in place; if \
             that branch is canonical, re-seed this node's data dir from a node on it",
            short,
            fork,
            depth,
            floor
        ),
        Outcome::Fetched { fork, top } => tracing::info!(
            "SYNCANCESTOR fetched {}'s branch from fork point {} up to {}; fork choice decides",
            short,
            fork,
            top
        ),
        Outcome::Budget { fetched } => tracing::info!(
            "SYNCANCESTOR episode with {} ran out of budget after {} height(s); the next one \
             resumes from there",
            short,
            fetched
        ),
        Outcome::Faulty(why) => {
            tracing::info!(
                "SYNCANCESTOR episode with {} ended: faulty reply ({})",
                short,
                why
            )
        }
        other => tracing::debug!("SYNCANCESTOR episode with {} ended: {:?}", short, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{BlockHeader, PublicKey, VrfProof};

    fn hx(n: u64) -> Hash {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_be_bytes());
        b[31] = 1;
        Hash::new(b)
    }

    /// A branch-tagged hash: branch 0 is the shared chain.
    fn hb(branch: u8, n: u64) -> Hash {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_be_bytes());
        b[30] = branch;
        b[31] = 2;
        Hash::new(b)
    }

    fn header(hash: Hash, parent: Hash, height: u64, blue_score: u64) -> BlockHeader {
        BlockHeader {
            version: 2,
            block_hash: hash,
            selected_parent_hash: parent,
            merge_parent_hashes: vec![],
            timestamp: 1_000 + height,
            height,
            blue_score,
            blue_work: blue_work_for_score(blue_score),
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([1; 32]),
            vrf_reveal: VrfProof {
                proof: vec![],
                output: Hash::default(),
            },
            base_fee_per_gas: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
            coinbase: [0; 20],
        }
    }

    /// A chain of headers on `branch` from `from` (exclusive, a block at
    /// height `from_h` with blue score `from_s`) for `len` heights, blue score
    /// `per` per height.
    fn run(
        branch: u8,
        from: Hash,
        from_h: u64,
        from_s: u64,
        len: u64,
        per: u64,
    ) -> Vec<BlockHeader> {
        let mut out = Vec::new();
        let mut parent = from;
        for k in 1..=len {
            let h = hb(branch, from_h + k);
            out.push(header(h, parent, from_h + k, from_s + per * k));
            parent = h;
        }
        out
    }

    const NOW: u64 = 10_000_000;

    /// Body windows go through `SyncManager::request_blocks`, whose batch is
    /// the window this driver's cursor arithmetic assumes.
    #[test]
    fn the_body_window_is_the_sync_batch() {
        assert_eq!(
            citrate_network::sync::SyncConfig::default().block_batch_size,
            BODY_WINDOW
        );
    }

    #[test]
    fn locator_is_logarithmic_and_ends_at_the_floor_and_genesis() {
        let g = hx(0);
        let floor = (hx(105_000), 105_000);
        let applied = (hx(226_000), 226_000);
        let loc = build_locator(applied, floor, g, |h| Some(hx(h)));
        assert!(loc.len() <= MAX_LOCATOR_HASHES, "{}", loc.len());
        assert_eq!(loc.first(), Some(&applied.0));
        assert_eq!(loc.get(loc.len() - 2), Some(&floor.0));
        assert_eq!(loc.last(), Some(&g));
        // Dense at the top.
        for k in 0..LOCATOR_DENSE {
            assert_eq!(
                loc.get(k as usize),
                Some(&hx(226_000 - k)),
                "dense entry {k}"
            );
        }
        // Then each gap at least doubles, and nothing at or below the floor
        // other than the floor itself.
        let heights: Vec<u64> = loc
            .iter()
            .map(|h| u64::from_be_bytes(h.as_bytes()[..8].try_into().expect("8")))
            .collect();
        let tail: Vec<u64> = heights[..heights.len() - 2].to_vec();
        assert!(tail.iter().all(|h| *h > floor.1));
        let gaps: Vec<u64> = tail.windows(2).map(|w| w[0] - w[1]).collect();
        for w in gaps.windows(2).skip(LOCATOR_DENSE as usize) {
            assert!(w[1] >= w[0], "gaps must not shrink: {gaps:?}");
        }
        // 120,000 heights are covered in well under the cap.
        assert!(loc.len() < 40, "{} hashes for a 121k span", loc.len());
    }

    #[test]
    fn locator_on_a_short_chain_lists_every_height_once() {
        let g = hx(0);
        let loc = build_locator((hx(5), 5), (g, 0), g, |h| Some(hx(h)));
        assert_eq!(loc, vec![hx(5), hx(4), hx(3), hx(2), hx(1), g]);
        // At genesis: genesis only.
        assert_eq!(build_locator((g, 0), (g, 0), g, |_| None), vec![g]);
    }

    #[test]
    fn locator_skips_heights_it_cannot_name_and_is_bounded() {
        let g = hx(0);
        let loc = build_locator((hx(u64::MAX / 2), u64::MAX / 2), (g, 0), g, |h| {
            (h % 2 == 0).then(|| hx(h))
        });
        assert!(loc.len() <= MAX_LOCATOR_HASHES);
        let unique: HashSet<Hash> = loc.iter().copied().collect();
        assert_eq!(unique.len(), loc.len(), "no repeats");
    }

    #[test]
    fn verify_headers_accepts_a_chain_and_names_each_fault() {
        let base = Link {
            hash: hb(0, 100),
            height: 100,
            blue_score: 500,
        };
        let good = run(1, base.hash, 100, 500, 5, 3);
        assert_eq!(verify_headers(base, &good, NOW), Ok(()));
        let mut unlinked = good.clone();
        unlinked[2].selected_parent_hash = hb(9, 1);
        assert_eq!(
            verify_headers(base, &unlinked, NOW),
            Err(HeaderFault::Unlinked { height: 103 })
        );
        let mut gap = good.clone();
        gap[1].height = 105;
        assert_eq!(
            verify_headers(base, &gap, NOW),
            Err(HeaderFault::HeightGap { height: 105 })
        );
        let mut flat = good.clone();
        flat[3].blue_score = flat[2].blue_score;
        flat[3].blue_work = blue_work_for_score(flat[3].blue_score);
        assert_eq!(
            verify_headers(base, &flat, NOW),
            Err(HeaderFault::ScoreNotIncreasing { height: 104 })
        );
        let mut work = good.clone();
        work[0].blue_work = u128::MAX;
        assert_eq!(
            verify_headers(base, &work, NOW),
            Err(HeaderFault::WorkMismatch { height: 101 })
        );
        let mut future = good.clone();
        future[4].timestamp = NOW + MAX_HEADER_FUTURE_SECS + 1;
        assert_eq!(
            verify_headers(base, &future, NOW),
            Err(HeaderFault::FromTheFuture { height: 105 })
        );
        let many = run(
            1,
            base.hash,
            100,
            500,
            u64::from(MAX_ANCESTOR_HEADERS) + 1,
            1,
        );
        assert_eq!(verify_headers(base, &many, NOW), Err(HeaderFault::TooMany));
        // The first header must continue the link itself.
        let wrong_start = run(1, hb(7, 100), 100, 500, 2, 1);
        assert_eq!(
            verify_headers(base, &wrong_start, NOW),
            Err(HeaderFault::Unlinked { height: 101 })
        );
    }

    /// The node under test: a shared chain 0..=fork (branch 0), then its own
    /// branch 1 up to `tip`, blue score `per_own` per height. `finalized` is
    /// its checkpoint.
    struct Me {
        fork: u64,
        tip: u64,
        per_own: u64,
        finalized: u64,
        held: HashSet<Hash>,
    }

    impl Me {
        fn new(fork: u64, tip: u64, per_own: u64, finalized: u64) -> Self {
            let mut held = HashSet::new();
            for h in 0..=fork {
                held.insert(hb(0, h));
            }
            for h in fork + 1..=tip {
                held.insert(hb(1, h));
            }
            Self {
                fork,
                tip,
                per_own,
                finalized,
                held,
            }
        }
        fn hash_at(&self, h: u64) -> Hash {
            if h <= self.fork {
                hb(0, h)
            } else {
                hb(1, h)
            }
        }
        fn score_at(&self, h: u64) -> u64 {
            if h <= self.fork {
                h * 4
            } else {
                self.fork * 4 + (h - self.fork) * self.per_own
            }
        }
        fn view(&self) -> View {
            View {
                applied: (self.hash_at(self.tip), self.tip),
                applied_blue_work: blue_work_for_score(self.score_at(self.tip)),
                finalized: (hb(0, self.finalized), self.finalized),
                genesis: hb(0, 0),
                behind: false,
            }
        }
        fn header(&self, h: &Hash) -> Option<BlockHeader> {
            (0..=self.tip).find(|x| self.hash_at(*x) == *h).map(|x| {
                let parent = if x == 0 {
                    Hash::default()
                } else {
                    self.hash_at(x - 1)
                };
                header(*h, parent, x, self.score_at(x))
            })
        }
    }

    /// A 1.3 peer on branch 2 from the same fork, `len` heights above it,
    /// blue score `per` per height. Answers a locator as `serve_ancestor` does.
    struct Peer {
        fork: u64,
        len: u64,
        per: u64,
        /// What it claims as its tip's work (`None`: the truth).
        claim: Option<u128>,
    }

    impl Peer {
        fn hash_at(&self, h: u64) -> Hash {
            if h <= self.fork {
                hb(0, h)
            } else {
                hb(2, h)
            }
        }
        fn tip(&self) -> (Hash, u64) {
            (self.hash_at(self.fork + self.len), self.fork + self.len)
        }
        fn tip_work(&self) -> u128 {
            self.claim
                .unwrap_or_else(|| blue_work_for_score(self.fork * 4 + self.len * self.per))
        }
        fn chain(&self) -> Vec<BlockHeader> {
            run(
                2,
                hb(0, self.fork),
                self.fork,
                self.fork * 4,
                self.len,
                self.per,
            )
        }
        fn answer(&self, locator: &[Hash]) -> (Option<(Hash, u64)>, Vec<BlockHeader>) {
            let top = self.fork + self.len;
            let common = locator
                .iter()
                .filter_map(|h| (0..=top).find(|x| self.hash_at(*x) == *h).map(|x| (*h, x)))
                .max_by_key(|(_, x)| *x);
            let Some((c, ch)) = common else {
                return (None, vec![]);
            };
            let all = self.chain();
            let mut shared: Vec<BlockHeader> = (ch + 1..=self.fork)
                .map(|x| header(hb(0, x), hb(0, x - 1), x, x * 4))
                .collect();
            shared.extend(all.into_iter().filter(|h| h.height > ch));
            shared.truncate(MAX_ANCESTOR_HEADERS as usize);
            (Some((c, ch)), shared)
        }
        fn candidate(&self) -> Candidate {
            Candidate {
                id: "peer".into(),
                speaks: true,
                head_hash: self.tip().0,
                head_height: self.tip().1,
                head_held: false,
            }
        }
    }

    /// Drive one episode to its end; `admit` says whether a body request
    /// stores the peer's blocks (an honest peer) or not. Returns the outcome
    /// and the number of locate and body requests.
    fn drive(me: &mut Me, peer: &Peer, admit: bool) -> (Option<Outcome>, usize, usize) {
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        a.note_deferred("peer", t0);
        let mut locates = 0;
        let mut bodies = 0;
        for tick in 0..20_000u64 {
            let now = t0 + Duration::from_millis(tick);
            let view = me.view();
            let (req, ended) = a.tick(now, &view, &[peer.candidate()], |h| {
                (h <= me.tip).then(|| me.hash_at(h))
            });
            if ended.is_some() {
                return (ended, locates, bodies);
            }
            match req {
                Some(Request::Locate { locator, .. }) => {
                    locates += 1;
                    let (common, headers) = peer.answer(&locator);
                    let held = me.held.clone();
                    if let Some(o) = a.on_ancestor(
                        "peer",
                        common,
                        peer.tip(),
                        peer.tip_work(),
                        &headers,
                        &view,
                        now,
                        NOW,
                        |h, _| held.contains(h),
                        |h| me.header(h),
                    ) {
                        return (Some(o), locates, bodies);
                    }
                }
                Some(Request::Bodies { from, height, .. }) => {
                    bodies += 1;
                    assert_eq!(
                        Some(from),
                        Some(peer.hash_at(height)),
                        "anchor on the peer's chain"
                    );
                    if admit {
                        for x in height..=height + u64::from(BODY_WINDOW) {
                            if x <= peer.tip().1 {
                                me.held.insert(peer.hash_at(x));
                            }
                        }
                    }
                    let held = me.held.clone();
                    if let Some(o) = a.on_blocks("peer", &[from], now, |h| held.contains(h)) {
                        return (Some(o), locates, bodies);
                    }
                }
                None => {}
            }
        }
        (None, locates, bodies)
    }

    #[test]
    fn a_heavier_branch_is_located_verified_and_fetched() {
        // 600 above a fork at 10,000: past the 512-height walk.
        let mut me = Me::new(10_000, 10_600, 3, 9_000);
        let peer = Peer {
            fork: 10_000,
            len: 600,
            per: 4,
            claim: None,
        };
        let (out, locates, bodies) = drive(&mut me, &peer, true);
        assert_eq!(
            out,
            Some(Outcome::Fetched {
                fork: 10_000,
                top: 10_600
            })
        );
        // One locate finds the common block; the rest page headers, 128 per
        // reply. The locator's spacing puts the common block at most our own
        // depth (600) below the fork, so at most 1,200 headers are paged.
        assert!(
            locates <= 1 + 1_200usize.div_ceil(MAX_ANCESTOR_HEADERS as usize),
            "{locates}"
        );
        assert!(bodies >= 600 / BODY_WINDOW as usize, "{bodies}");
        for h in 10_001..=10_600 {
            assert!(me.held.contains(&peer.hash_at(h)), "height {h} fetched");
        }
    }

    #[test]
    fn a_lighter_branch_is_never_fetched() {
        // The peer's branch is longer but claims less work per height: its
        // tip claims less than our applied tip. Headers only, no body.
        let mut me = Me::new(10_000, 10_300, 4, 9_000);
        let peer = Peer {
            fork: 10_000,
            len: 350,
            per: 3,
            claim: None,
        };
        let (out, locates, bodies) = drive(&mut me, &peer, true);
        assert!(
            matches!(
                out,
                Some(Outcome::NotHeavier {
                    peer_tip: 10_350,
                    ..
                })
            ),
            "{out:?}"
        );
        assert_eq!(locates, 1, "the peer's tip claim ends it at once");
        assert_eq!(bodies, 0, "work is checked before any body is pulled");
    }

    #[test]
    fn a_tip_claim_alone_never_fetches_bodies() {
        // The same lighter branch, but the peer claims an enormous tip work:
        // its headers are paged to its tip, none of them claims more work
        // than ours, and no body is pulled.
        let mut me = Me::new(10_000, 10_300, 4, 9_000);
        let peer = Peer {
            fork: 10_000,
            len: 350,
            per: 3,
            claim: Some(u128::MAX),
        };
        let (out, locates, bodies) = drive(&mut me, &peer, true);
        assert_eq!(
            out,
            Some(Outcome::NotHeavier {
                fork: 10_000,
                peer_tip: 10_350
            })
        );
        assert!(locates > 1, "the headers were paged: {locates}");
        assert_eq!(
            bodies, 0,
            "work is checked on verified headers before bodies"
        );
    }

    #[test]
    fn a_fork_beyond_the_undo_window_is_refused_without_bodies() {
        // r1007 today: forked at 105,012, applied at 226,112, finalized 105,000.
        let mut me = Me::new(105_012, 226_112, 3, 105_000);
        let peer = Peer {
            fork: 105_012,
            len: 121_464,
            per: 4,
            claim: None,
        };
        let (out, locates, bodies) = drive(&mut me, &peer, true);
        assert_eq!(
            out,
            Some(Outcome::TooDeep {
                fork: 105_012,
                depth: 121_100,
                floor: 226_112 - crate::canonical_apply::MAX_REORG_DEPTH,
                fork_hash: hb(0, 105_012),
                diverged: Some(hb(2, 105_013)),
            })
        );
        assert_eq!(bodies, 0);
        assert!(locates <= 2, "found in O(1) round trips: {locates}");
    }

    /// The r1007 member after the recovery: LIGHT applied at 274,810, forked
    /// at 105,024, and NO finalized height in the sync view (Observed mode
    /// never raises the applicator's floor, so the view's finalized height is
    /// 0 on every r1007 node). The locator then reaches down to genesis, the
    /// peer's common block is ~12,650, and paging up to the fork one
    /// 128-header window at a time runs out of the 20,000-header budget
    /// (`Budget { fetched: 0 }`, with a doubling cooldown) on every episode:
    /// the node never learned that its fork is too deep. The fork search
    /// narrows the range instead and locates the fork exactly, with the
    /// first block of the peer's branch named and verified, and no body.
    #[test]
    fn a_fork_far_below_the_floor_is_located_exactly_without_a_finalized_height() {
        let mut me = Me::new(105_024, 274_810, 3, 0);
        let peer = Peer {
            fork: 105_024,
            len: 178_576,
            per: 4,
            claim: None,
        };
        let (out, locates, bodies) = drive(&mut me, &peer, true);
        assert!(
            matches!(
                &out,
                Some(Outcome::TooDeep {
                    fork: 105_024,
                    depth: 169_786,
                    ..
                })
            ),
            "{out:?}"
        );
        let text = format!("{out:?}");
        assert!(
            text.contains(&format!("{:?}", hb(2, 105_025))),
            "the first block of the peer's branch is named: {text}"
        );
        assert_eq!(bodies, 0, "nothing is fetched");
        assert!(
            locates <= 6,
            "located in a handful of round trips: {locates}"
        );
    }

    /// A peer cannot steer the search below what it answered: a common block
    /// that is not in the narrowing locator we sent ends the episode faulty,
    /// with nothing recorded as a deep fork.
    #[test]
    fn a_narrowing_answer_outside_the_locator_is_faulty() {
        let me = Me::new(105_024, 274_810, 3, 0);
        let peer = Peer {
            fork: 105_024,
            len: 178_576,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        a.note_deferred("peer", t0);
        let lookup = |h: u64| (h <= me.tip).then(|| me.hash_at(h));
        let view = me.view();
        let (req, _) = a.tick(t0, &view, &[peer.candidate()], lookup);
        let Some(Request::Locate { locator, .. }) = req else {
            panic!("expected a locate");
        };
        let (common, headers) = peer.answer(&locator);
        let held = me.held.clone();
        assert_eq!(
            a.on_ancestor(
                "peer",
                common,
                peer.tip(),
                peer.tip_work(),
                &headers,
                &view,
                t0,
                NOW,
                |h, _| held.contains(h),
                |h| me.header(h),
            ),
            None,
            "the first answer starts the narrowing"
        );
        let (req, _) = a.tick(t0, &view, &[peer.candidate()], lookup);
        let Some(Request::Locate { locator, .. }) = req else {
            panic!("expected the narrowing locate");
        };
        assert!(locator.len() <= MAX_LOCATOR_HASHES);
        // A lying answer: a common block of ours we did not send this round.
        let bogus = (me.hash_at(50_000), 50_000);
        assert!(!locator.contains(&bogus.0));
        let out = a.on_ancestor(
            "peer",
            Some(bogus),
            peer.tip(),
            peer.tip_work(),
            &[],
            &view,
            t0,
            NOW,
            |h, _| held.contains(h),
            |h| me.header(h),
        );
        assert!(matches!(out, Some(Outcome::Faulty(_))), "{out:?}");
    }

    #[test]
    fn the_narrowing_locator_spans_the_gap_and_ends_at_its_low_end() {
        let lo = (hx(1_000), 1_000);
        let loc = refine_locator(lo, 131_072, |h| Some(hx(h)));
        assert_eq!(loc.len(), MAX_LOCATOR_HASHES);
        assert_eq!(loc.last(), Some(&lo));
        let hs: Vec<u64> = loc.iter().map(|(_, h)| *h).collect();
        assert!(hs.windows(2).all(|w| w[0] > w[1]), "newest first: {hs:?}");
        assert!(hs.iter().all(|h| *h >= 1_000 && *h < 131_072));
        // The largest step is about 1/63 of the gap.
        let step = hs.windows(2).map(|w| w[0] - w[1]).max().expect("steps");
        assert!(step <= 130_072 / 63 + 2, "{step}");
        // A small gap lists every height once; no gap lists only `lo`.
        let small = refine_locator(lo, 1_005, |h| Some(hx(h)));
        assert_eq!(
            small.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
            vec![1_004, 1_003, 1_002, 1_001, 1_000]
        );
        assert_eq!(refine_locator(lo, 1_001, |h| Some(hx(h))), vec![lo]);
    }

    #[test]
    fn a_fork_below_the_finalized_checkpoint_is_refused() {
        // The peer's executed chain does not hold our checkpoint at 950: it
        // forked at 900. Its reply's common block is at 900 < 950.
        let me = Me::new(900, 1_000, 3, 950);
        let peer = Peer {
            fork: 900,
            len: 200,
            per: 9,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let mut view = me.view();
        view.finalized = (me.hash_at(950), 950);
        let (req, _) = a.tick(now, &view, &[peer.candidate()], |h| Some(me.hash_at(h)));
        let Some(Request::Locate { locator, .. }) = req else {
            panic!("expected a locate");
        };
        assert!(
            locator.contains(&me.hash_at(950)),
            "the locator carries the checkpoint"
        );
        // The peer holds nothing of ours above genesis: our checkpoint is on
        // our side of its fork.
        let (common, headers) = peer.answer(&locator);
        assert_eq!(common.map(|c| c.1), Some(0));
        let held = me.held.clone();
        let out = a.on_ancestor(
            "peer",
            common,
            peer.tip(),
            peer.tip_work(),
            &headers,
            &view,
            now,
            NOW,
            |h, _| held.contains(h),
            |h| me.header(h),
        );
        assert!(
            matches!(out, Some(Outcome::TooDeep { fork: 0, .. })),
            "{out:?}"
        );
        assert_eq!(view.reorg_floor(), 950);
    }

    #[test]
    fn a_peer_that_extends_our_chain_is_left_to_ordinary_sync() {
        let mut me = Me::new(500, 500, 4, 0);
        let peer = Peer {
            fork: 500,
            len: 40,
            per: 4,
            claim: None,
        };
        let (out, locates, bodies) = drive(&mut me, &peer, true);
        assert_eq!(out, Some(Outcome::Extends));
        assert_eq!((locates, bodies), (1, 0));
    }

    #[test]
    fn a_reply_naming_a_block_we_never_sent_is_faulty_and_cools_the_peer() {
        let me = Me::new(100, 120, 3, 0);
        let peer = Peer {
            fork: 100,
            len: 50,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let view = me.view();
        let (req, _) = a.tick(now, &view, &[peer.candidate()], |h| Some(me.hash_at(h)));
        assert!(matches!(req, Some(Request::Locate { .. })));
        let held = me.held.clone();
        let out = a.on_ancestor(
            "peer",
            Some((hb(7, 3), 3)),
            peer.tip(),
            peer.tip_work(),
            &[],
            &view,
            now,
            NOW,
            |h, _| held.contains(h),
            |h| me.header(h),
        );
        assert!(matches!(out, Some(Outcome::Faulty(_))), "{out:?}");
        // Cooling: not asked again at once, even with fresh evidence.
        a.note_deferred("peer", now + Duration::from_secs(1));
        let (req, _) = a.tick(
            now + Duration::from_secs(1),
            &view,
            &[peer.candidate()],
            |h| Some(me.hash_at(h)),
        );
        assert_eq!(req, None);
        a.note_deferred("peer", now + COOLDOWN_BASE);
        let (req, _) = a.tick(now + COOLDOWN_BASE, &view, &[peer.candidate()], |h| {
            Some(me.hash_at(h))
        });
        assert!(
            matches!(req, Some(Request::Locate { .. })),
            "asked again after the cooldown"
        );
    }

    #[test]
    fn headers_that_do_not_verify_end_the_episode_before_any_body() {
        let me = Me::new(100, 120, 3, 0);
        let peer = Peer {
            fork: 100,
            len: 50,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let view = me.view();
        let (req, _) = a.tick(now, &view, &[peer.candidate()], |h| Some(me.hash_at(h)));
        let Some(Request::Locate { locator, .. }) = req else {
            panic!("locate");
        };
        let (common, mut headers) = peer.answer(&locator);
        // A forged claim of enormous work.
        let k = headers.len() - 1;
        headers[k].blue_score = u64::MAX / 2;
        let held = me.held.clone();
        let out = a.on_ancestor(
            "peer",
            common,
            peer.tip(),
            peer.tip_work(),
            &headers,
            &view,
            now,
            NOW,
            |h, _| held.contains(h),
            |h| me.header(h),
        );
        assert!(matches!(out, Some(Outcome::Faulty(_))), "{out:?}");
    }

    /// A body answer split into several messages: the cursor catches up with
    /// all of them before the next window, so the next request starts where
    /// the last answer ended, not where its first message ended.
    #[test]
    fn the_cursor_catches_up_with_a_split_answer() {
        let mut me = Me::new(1_000, 1_100, 3, 0);
        let peer = Peer {
            fork: 1_000,
            len: 200,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        a.note_deferred("peer", t0);
        let mut anchors = Vec::new();
        for tick in 0..2_000u64 {
            let now = t0 + Duration::from_millis(tick);
            let view = me.view();
            a.advance(|h| me.held.contains(h));
            let (req, ended) = a.tick(now, &view, &[peer.candidate()], |h| {
                (h <= me.tip).then(|| me.hash_at(h))
            });
            if let Some(o) = ended {
                assert_eq!(
                    o,
                    Outcome::Fetched {
                        fork: 1_000,
                        top: 1_200
                    }
                );
                break;
            }
            match req {
                Some(Request::Locate { locator, .. }) => {
                    let (common, headers) = peer.answer(&locator);
                    let held = me.held.clone();
                    let _ = a.on_ancestor(
                        "peer",
                        common,
                        peer.tip(),
                        peer.tip_work(),
                        &headers,
                        &view,
                        now,
                        NOW,
                        |h, _| held.contains(h),
                        |h| me.header(h),
                    );
                }
                Some(Request::Bodies { from, height, .. }) => {
                    anchors.push(height);
                    // First message: the anchor and 7 heights. It is matched
                    // and the cursor moves to its end.
                    for x in height..=height + 7 {
                        me.held.insert(peer.hash_at(x));
                    }
                    let held = me.held.clone();
                    let _ = a.on_blocks("peer", &[from], now, |h| held.contains(h));
                    // The rest of the answer, in later messages that carry no
                    // anchor: stored, never matched.
                    for x in height + 8..=(height + u64::from(BODY_WINDOW)).min(1_200) {
                        me.held.insert(peer.hash_at(x));
                    }
                }
                None => {}
            }
        }
        assert!(
            anchors
                .windows(2)
                .all(|w| w[1] >= w[0] + u64::from(BODY_WINDOW)),
            "each window starts past the last answer's end: {anchors:?}"
        );
    }

    /// Answer the outstanding locate of `a` with `peer`'s reply.
    fn reply(
        a: &mut AncestorSync,
        me: &Me,
        peer: &Peer,
        locator: &[Hash],
        now: Instant,
    ) -> Option<Outcome> {
        let (common, headers) = peer.answer(locator);
        let held = me.held.clone();
        a.on_ancestor(
            "peer",
            common,
            peer.tip(),
            peer.tip_work(),
            &headers,
            &me.view(),
            now,
            NOW,
            |h, _| held.contains(h),
            |h| me.header(h),
        )
    }

    /// PR #483 review, P1-1: a peer that answers every locate just inside the
    /// request timeout, with headers that never claim more work than ours,
    /// must not hold the sync tick or the pipeline aside at all, and its
    /// episode must end within the episode's time budget.
    #[test]
    fn a_slow_drip_header_peer_never_owns_sync_and_is_bounded() {
        // Our branch is 8,000 deep at 4 blue per height; the peer's 30,000
        // headers at 1 per height never reach our work, though its tip claims
        // the most work there is.
        let me = Me::new(1_000, 9_000, 4, 0);
        let peer = Peer {
            fork: 1_000,
            len: 30_000,
            per: 1,
            claim: Some(u128::MAX),
        };
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        a.note_deferred("peer", t0);
        let drip = REQUEST_TIMEOUT - Duration::from_secs(1);
        let mut pending: Option<(Instant, Vec<Hash>)> = None;
        let mut ended = None;
        for sec in 0..3_600u64 {
            let now = t0 + Duration::from_secs(sec);
            if let Some((due, locator)) = pending.clone() {
                if now >= due {
                    pending = None;
                    if let Some(o) = reply(&mut a, &me, &peer, &locator, now) {
                        ended = Some((sec, o));
                        break;
                    }
                }
            }
            assert!(
                !a.owns_sync(),
                "a header-phase episode stood the sync tick aside at {sec} s"
            );
            let (req, out) = a.tick(now, &me.view(), &[peer.candidate()], |h| {
                Some(me.hash_at(h))
            });
            if let Some(o) = out {
                ended = Some((sec, o));
                break;
            }
            if let Some(Request::Locate { locator, .. }) = req {
                pending = Some((now + drip, locator));
            }
        }
        let (sec, out) = ended.expect("the episode ended");
        assert!(
            sec <= EPISODE_MAX_DURATION.as_secs() + REQUEST_TIMEOUT.as_secs(),
            "ended after {sec} s: {out:?}"
        );
        assert_eq!(out, Outcome::Budget { fetched: 0 });
        // Delivered nothing: held against it (no immediate retry).
        a.note_deferred("peer", t0 + Duration::from_secs(sec));
        let (req, _) = a.tick(
            t0 + Duration::from_secs(sec + 1),
            &me.view(),
            &[peer.candidate()],
            |h| Some(me.hash_at(h)),
        );
        assert_eq!(req, None);
    }

    /// PR #483 review, P1-1: a request the sync manager refuses (InFlightCap)
    /// clears nothing that would let the episode hang: four in a row end it.
    #[test]
    fn refused_requests_end_the_episode() {
        let me = Me::new(1_000, 1_100, 3, 0);
        let peer = Peer {
            fork: 1_000,
            len: 200,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        a.note_deferred("peer", t0);
        let mut ended = None;
        let mut refused = 0;
        for tick in 0..100u64 {
            let now = t0 + Duration::from_millis(tick);
            let (req, out) = a.tick(now, &me.view(), &[peer.candidate()], |h| {
                Some(me.hash_at(h))
            });
            if out.is_some() {
                ended = out;
                break;
            }
            match req {
                Some(Request::Locate { locator, .. }) => {
                    let _ = reply(&mut a, &me, &peer, &locator, now);
                }
                Some(Request::Bodies { .. }) => {
                    refused += 1;
                    if let Some(o) = a.unsent(now) {
                        ended = Some(o);
                        break;
                    }
                }
                None => {}
            }
        }
        assert_eq!(ended, Some(Outcome::Stalled));
        assert_eq!(refused, MAX_UNSENT_ROUNDS);
    }

    /// The common-block check (mutation guard): a reply naming a block this
    /// node does hold, but that was not in the locator it sent, is faulty.
    #[test]
    fn a_held_common_block_not_in_the_locator_is_faulty() {
        let me = Me::new(100, 120, 3, 0);
        let peer = Peer {
            fork: 100,
            len: 50,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let (req, _) = a.tick(now, &me.view(), &[peer.candidate()], |h| {
            Some(me.hash_at(h))
        });
        let Some(Request::Locate { locator, .. }) = req else {
            panic!("locate");
        };
        let ours = hb(0, 5);
        assert!(
            me.held.contains(&ours) && !locator.contains(&ours),
            "fixture"
        );
        let held = me.held.clone();
        let out = a.on_ancestor(
            "peer",
            Some((ours, 5)),
            peer.tip(),
            peer.tip_work(),
            &[],
            &me.view(),
            now,
            NOW,
            |h, _| held.contains(h),
            |h| me.header(h),
        );
        assert!(matches!(out, Some(Outcome::Faulty(_))), "{out:?}");
    }

    /// PR #483 review: side blocks this node stores (from gossip or a walk)
    /// are not its chain. The fork depth is measured from the last header on
    /// its executed chain, so stored side blocks cannot make a fork beyond
    /// the undo window look shallow enough to fetch.
    #[test]
    fn stored_side_blocks_do_not_make_a_deep_fork_look_shallow() {
        let mut me = Me::new(1_000, 11_500, 3, 0);
        let peer = Peer {
            fork: 1_000,
            len: 12_000,
            per: 4,
            claim: None,
        };
        // The peer's branch up to 2,000 is stored here as side blocks.
        for h in 1_001..=2_000 {
            me.held.insert(peer.hash_at(h));
        }
        let fork_h = 1_000u64;
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let mut out = None;
        for round in 0..200u64 {
            let t = now + Duration::from_millis(round);
            let (req, ended) = a.tick(t, &me.view(), &[peer.candidate()], |h| {
                (h <= me.tip).then(|| me.hash_at(h))
            });
            if ended.is_some() {
                out = ended;
                break;
            }
            if let Some(Request::Locate { locator, .. }) = req {
                let (common, headers) = peer.answer(&locator);
                let mine = |h: &Hash, height: u64| *h == me.hash_at(height) && height <= me.tip;
                if let Some(o) = a.on_ancestor(
                    "peer",
                    common,
                    peer.tip(),
                    peer.tip_work(),
                    &headers,
                    &me.view(),
                    t,
                    NOW,
                    mine,
                    |h| me.header(h),
                ) {
                    out = Some(o);
                    break;
                }
            }
        }
        assert!(
            matches!(out, Some(Outcome::TooDeep { fork, .. }) if fork == fork_h),
            "{out:?}"
        );
    }

    /// An honest deep fetch that outlasts the episode budget ends resumable:
    /// no cooldown, so the next episode with the same peer starts at once
    /// from what is held by then.
    #[test]
    fn an_honest_fetch_past_the_budget_resumes() {
        let mut me = Me::new(1_000, 1_100, 3, 0);
        let peer = Peer {
            fork: 1_000,
            len: 30_000,
            per: 4,
            claim: None,
        };
        let (out, _, bodies) = drive(&mut me, &peer, true);
        assert!(
            matches!(out, Some(Outcome::Budget { fetched }) if fetched > 0),
            "{out:?}"
        );
        assert!(bodies > 0);
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let _ = a.tick(now, &me.view(), &[peer.candidate()], |h| {
            Some(me.hash_at(h))
        });
        let _ = a.end(Outcome::Budget { fetched: 10 }, now);
        let (req, _) = a.tick(now, &me.view(), &[peer.candidate()], |h| {
            Some(me.hash_at(h))
        });
        assert!(
            matches!(req, Some(Request::Locate { .. })),
            "no cooldown: {req:?}"
        );
    }

    /// An episode does not wait a sync tick between rounds: right after an
    /// answer, `next` hands out the following request.
    #[test]
    fn the_next_round_follows_an_answer_at_once() {
        let me = Me::new(1_000, 1_100, 3, 0);
        let peer = Peer {
            fork: 1_000,
            len: 600,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let (req, _) = a.tick(now, &me.view(), &[peer.candidate()], |h| {
            Some(me.hash_at(h))
        });
        let Some(Request::Locate { locator, .. }) = req else {
            panic!("locate");
        };
        assert_eq!(a.next(now), None, "one request in flight");
        assert_eq!(reply(&mut a, &me, &peer, &locator, now), None);
        assert!(
            matches!(a.next(now), Some(Request::Locate { .. })),
            "pages on at once"
        );
        assert_eq!(a.next(now), None, "and only one at a time");
    }

    #[test]
    fn a_peer_that_never_delivers_bodies_stalls_out() {
        let mut me = Me::new(1_000, 1_100, 3, 0);
        let peer = Peer {
            fork: 1_000,
            len: 200,
            per: 4,
            claim: None,
        };
        let (out, _, bodies) = drive(&mut me, &peer, false);
        assert_eq!(out, Some(Outcome::Stalled));
        assert_eq!(bodies, MAX_STALLED_BODY_ANSWERS as usize);
    }

    #[test]
    fn a_silent_peer_times_out() {
        let me = Me::new(100, 120, 3, 0);
        let peer = Peer {
            fork: 100,
            len: 50,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let view = me.view();
        let _ = a.tick(now, &view, &[peer.candidate()], |h| Some(me.hash_at(h)));
        let (req, ended) = a.tick(
            now + Duration::from_secs(1),
            &view,
            &[peer.candidate()],
            |h| Some(me.hash_at(h)),
        );
        assert_eq!(
            (req, ended),
            (None, None),
            "one request in flight at a time"
        );
        let (_, ended) = a.tick(now + REQUEST_TIMEOUT, &view, &[peer.candidate()], |h| {
            Some(me.hash_at(h))
        });
        assert_eq!(ended, Some(Outcome::Timeout));
    }

    #[test]
    fn mixed_versions_only_1_3_peers_are_asked() {
        let me = Me::new(100, 120, 3, 0);
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let old = Candidate {
            id: "old".into(),
            speaks: false,
            head_hash: hb(2, 900),
            head_height: 900,
            head_held: false,
        };
        let (req, _) = a.tick(now, &me.view(), std::slice::from_ref(&old), |h| {
            Some(me.hash_at(h))
        });
        assert_eq!(req, None, "a 1.2 peer is never sent GetAncestor");
        let new = Candidate {
            id: "new".into(),
            speaks: true,
            head_hash: hb(2, 130),
            head_height: 130,
            head_held: false,
        };
        let (req, _) = a.tick(now, &me.view(), &[old, new], |h| Some(me.hash_at(h)));
        assert!(
            matches!(req, Some(Request::Locate { ref peer, .. }) if peer == "new"),
            "{req:?}"
        );
    }

    #[test]
    fn no_episode_without_evidence_or_for_a_held_head() {
        let me = Me::new(100, 120, 3, 0);
        let mut a = AncestorSync::new();
        let now = Instant::now();
        let held = Candidate {
            id: "p".into(),
            speaks: true,
            head_hash: hb(1, 110),
            head_height: 110,
            head_held: true,
        };
        let unheld = Candidate {
            head_held: false,
            head_hash: hb(2, 130),
            ..held.clone()
        };
        let (req, _) = a.tick(now, &me.view(), std::slice::from_ref(&unheld), |h| {
            Some(me.hash_at(h))
        });
        assert_eq!(req, None, "no evidence: no episode");
        a.note_deferred("peer", now);
        let (req, _) = a.tick(now, &me.view(), std::slice::from_ref(&held), |h| {
            Some(me.hash_at(h))
        });
        assert_eq!(req, None, "a head we hold is not a branch we lack");
        let (req, _) = a.tick(now + EVIDENCE_TTL, &me.view(), &[unheld], |h| {
            Some(me.hash_at(h))
        });
        assert_eq!(req, None, "evidence expires");
    }

    /// A peer whose advertised head is our own tip (it relayed our block)
    /// but which delivered a block that deferred is still asked: the
    /// deferral says it may hold a branch we lack; its head says nothing.
    #[test]
    fn a_deliverer_is_asked_whatever_its_advertised_head() {
        let me = Me::new(100, 120, 3, 0);
        let mut a = AncestorSync::new();
        let now = Instant::now();
        let relayed = Candidate {
            id: "heavy".into(),
            speaks: true,
            head_hash: me.hash_at(120),
            head_height: 120,
            head_held: true,
        };
        let (req, _) = a.tick(now, &me.view(), std::slice::from_ref(&relayed), |h| {
            Some(me.hash_at(h))
        });
        assert_eq!(req, None, "no evidence from it yet");
        a.note_deferred("heavy", now);
        let (req, _) = a.tick(now, &me.view(), &[relayed], |h| Some(me.hash_at(h)));
        assert!(
            matches!(req, Some(Request::Locate { ref peer, .. }) if peer == "heavy"),
            "{req:?}"
        );
    }

    #[test]
    fn an_episode_whose_peer_left_ends_without_a_penalty() {
        let me = Me::new(100, 120, 3, 0);
        let peer = Peer {
            fork: 100,
            len: 50,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let now = Instant::now();
        a.note_deferred("peer", now);
        let _ = a.tick(now, &me.view(), &[peer.candidate()], |h| {
            Some(me.hash_at(h))
        });
        let (_, ended) = a.tick(now, &me.view(), &[], |h| Some(me.hash_at(h)));
        assert_eq!(ended, Some(Outcome::PeerLeft));
        let (req, _) = a.tick(now, &me.view(), &[peer.candidate()], |h| {
            Some(me.hash_at(h))
        });
        assert!(
            matches!(req, Some(Request::Locate { .. })),
            "no cooldown for a peer that left"
        );
    }

    #[test]
    fn the_cooldown_table_is_bounded() {
        let me = Me::new(100, 120, 3, 0);
        let mut a = AncestorSync::new();
        let now = Instant::now();
        for k in 0..(MAX_COOLDOWN_PEERS + 50) {
            a.note_deferred("peer", now);
            let c = Candidate {
                id: format!("p{k}"),
                speaks: true,
                head_hash: hb(2, 130),
                head_height: 130,
                head_held: false,
            };
            let (req, _) = a.tick(now, &me.view(), std::slice::from_ref(&c), |h| {
                Some(me.hash_at(h))
            });
            assert!(req.is_some());
            let _ = a.tick(now, &me.view(), &[], |h| Some(me.hash_at(h)));
            let _ = a.end(Outcome::Timeout, now);
        }
        assert!(a.cooldown.len() <= MAX_COOLDOWN_PEERS);
    }

    /// PR #483 review round 2, P1-1 (the reviewer's PoC, adapted). One peer
    /// must not be able to hold the sync tick and pipeline aside: it serves a real side block S this node already holds
    /// (fully admitted, not on the executed chain) followed by fabricated,
    /// structurally valid headers claiming huge work, dripping one header per
    /// locate just inside REQUEST_TIMEOUT. `advance` pops S, so every episode
    /// ends `Budget { fetched: 1 }`: zero cooldown, failures reset, and the
    /// next episode with the same peer starts on the same tick.
    #[test]
    fn a_peer_serving_a_held_side_block_and_fake_work_cannot_own_sync() {
        let mut me = Me::new(1_000, 1_100, 3, 0);
        let common = (me.hash_at(1_099), 1_099u64);
        let s_hash = hb(9, 1_100);
        let s_hdr = header(s_hash, common.0, 1_100, me.score_at(1_099) + 1);
        me.held.insert(s_hash);
        let fake = |k: u64| -> BlockHeader {
            let parent = if k == 1 { s_hash } else { hb(8, 1_100 + k - 1) };
            header(hb(8, 1_100 + k), parent, 1_100 + k, 10_000_000 + k)
        };
        let tip = (hb(8, 5_000_000), 5_000_000u64);
        let cand = Candidate {
            id: "peer".into(),
            speaks: true,
            head_hash: tip.0,
            head_height: tip.1,
            head_held: false,
        };
        let answer = |locator: &[Hash]| -> (Option<(Hash, u64)>, Vec<BlockHeader>) {
            if let Some(k) = (1..100_000u64).find(|k| locator.first() == Some(&hb(8, 1_100 + k))) {
                return (Some((hb(8, 1_100 + k), 1_100 + k)), vec![fake(k + 1)]);
            }
            (Some(common), vec![s_hdr.clone(), fake(1)])
        };
        let ours = |h: &Hash, height: u64| height <= 1_100 && *h == me.hash_at(height);
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        let drip = REQUEST_TIMEOUT - Duration::from_secs(1);
        let mut pending: Option<(Instant, Vec<Hash>)> = None;
        let total = 3 * 3_600u64;
        let mut owned = 0u64;
        let mut outcomes: HashMap<String, u64> = HashMap::new();
        for sec in 0..total {
            let now = t0 + Duration::from_secs(sec);
            let view = View {
                behind: true,
                ..me.view()
            };
            if let Some((due, locator)) = pending.clone() {
                if now >= due {
                    pending = None;
                    let (c, hs) = answer(&locator);
                    if let Some(o) =
                        a.on_ancestor("peer", c, tip, u128::MAX, &hs, &view, now, NOW, ours, |h| {
                            me.header(h)
                        })
                    {
                        *outcomes.entry(format!("{o:?}")).or_insert(0) += 1;
                    }
                    let held = me.held.clone();
                    a.advance(|h| held.contains(h));
                    if let Some(Request::Locate { locator, .. }) = a.next(now) {
                        pending = Some((now + drip, locator));
                    }
                }
            }
            let held = me.held.clone();
            a.advance(|h| held.contains(h));
            let (req, ended) = a.tick(now, &view, std::slice::from_ref(&cand), |h| {
                (h <= me.tip).then(|| me.hash_at(h))
            });
            if let Some(o) = ended {
                *outcomes.entry(format!("{o:?}")).or_insert(0) += 1;
                pending = None; // the attacker never answers a stale request
            }
            // main.rs samples owns_sync right after run_tick.
            if a.owns_sync() {
                owned += 1;
            }
            if let Some(Request::Locate { locator, .. }) = req {
                // A new episode's first locate: answered at once.
                let (c, hs) = answer(&locator);
                if let Some(o) =
                    a.on_ancestor("peer", c, tip, u128::MAX, &hs, &view, now, NOW, ours, |h| {
                        me.header(h)
                    })
                {
                    *outcomes.entry(format!("{o:?}")).or_insert(0) += 1;
                }
                let held = me.held.clone();
                a.advance(|h| held.contains(h));
                if let Some(Request::Locate { locator, .. }) = a.next(now) {
                    pending = Some((now + drip, locator));
                }
            }
        }
        eprintln!(
            "owned {owned}/{total} ticks; outcomes {outcomes:?}; {}",
            a.summary()
        );
        assert!(
            owned * 2 < total,
            "one peer held the sync tick and pipeline aside for {owned} of {total} s: {outcomes:?}"
        );
        // Nothing was fetched (S was held before the episode), so every
        // ending is an empty budget and the cooldown doubles: few episodes.
        assert!(
            outcomes
                .keys()
                .all(|k| !k.starts_with("Budget") || k == "Budget { fetched: 0 }"),
            "a held side block counted as fetched: {outcomes:?}"
        );
        let episodes: u64 = outcomes.values().sum();
        assert!(episodes <= 16, "{episodes} episodes in 3 h: {outcomes:?}");
    }

    /// The PoC's peer: a held side block S on our block at 1,099, then one
    /// fabricated high-work header per locate.
    struct Dripper {
        common: (Hash, u64),
        s_hdr: BlockHeader,
    }

    impl Dripper {
        fn new(me: &mut Me) -> Self {
            let common = (me.hash_at(1_099), 1_099u64);
            let s_hash = hb(9, 1_100);
            let s_hdr = header(s_hash, common.0, 1_100, me.score_at(1_099) + 1);
            me.held.insert(s_hash);
            Self { common, s_hdr }
        }
        fn fake(&self, k: u64) -> BlockHeader {
            let parent = if k == 1 {
                self.s_hdr.block_hash
            } else {
                hb(8, 1_100 + k - 1)
            };
            header(hb(8, 1_100 + k), parent, 1_100 + k, 10_000_000 + k)
        }
        fn answer(&self, locator: &[Hash]) -> (Option<(Hash, u64)>, Vec<BlockHeader>) {
            if let Some(k) = (1..100_000u64).find(|k| locator.first() == Some(&hb(8, 1_100 + k))) {
                return (Some((hb(8, 1_100 + k), 1_100 + k)), vec![self.fake(k + 1)]);
            }
            (Some(self.common), vec![self.s_hdr.clone(), self.fake(1)])
        }
        fn tip(&self) -> (Hash, u64) {
            (hb(8, 5_000_000), 5_000_000)
        }
        fn candidate(&self) -> Candidate {
            Candidate {
                id: "peer".into(),
                speaks: true,
                head_hash: self.tip().0,
                head_height: self.tip().1,
                head_held: false,
            }
        }
    }

    /// Review round 2, mutation M2: the round and time guards in `next`
    /// bound a peer that answers every request at once (no tick runs between
    /// rounds, so the tick's own budget check never fires).
    #[test]
    fn a_fast_chaining_peer_is_bounded_by_the_episode_guards() {
        for step in [Duration::from_millis(1), Duration::from_secs(1)] {
            let mut me = Me::new(1_000, 1_100, 3, 0);
            let d = Dripper::new(&mut me);
            let mut a = AncestorSync::new();
            let t0 = Instant::now();
            a.note_deferred("peer", t0);
            let view = View {
                behind: true,
                ..me.view()
            };
            let (req, _) = a.tick(t0, &view, &[d.candidate()], |h| Some(me.hash_at(h)));
            let Some(Request::Locate { mut locator, .. }) = req else {
                panic!("locate");
            };
            let mut rounds = 1u64;
            let ours = |h: &Hash, height: u64| height <= 1_100 && *h == me.hash_at(height);
            for k in 0..100_000u64 {
                let now = t0 + step * u32::try_from(k).expect("k");
                let (c, hs) = d.answer(&locator);
                let _ = a.on_ancestor(
                    "peer",
                    c,
                    d.tip(),
                    u128::MAX,
                    &hs,
                    &view,
                    now,
                    NOW,
                    ours,
                    |h| me.header(h),
                );
                match a.next(now) {
                    Some(Request::Locate { locator: l, .. }) => {
                        locator = l;
                        rounds += 1;
                    }
                    _ => break,
                }
            }
            let cap = u64::from(EPISODE_MAX_ROUNDS)
                .min(EPISODE_MAX_DURATION.as_millis() as u64 / step.as_millis() as u64 + 1);
            assert!(
                rounds <= cap,
                "{rounds} rounds at {step:?} a round (cap {cap})"
            );
        }
    }

    /// Review round 2, mutation M1: an episode that ran out of budget with
    /// nothing fetched backs off like a fault: the cooldown doubles.
    #[test]
    fn an_empty_budget_backs_off_like_a_fault() {
        let me = Me::new(100, 120, 3, 0);
        let peer = Peer {
            fork: 100,
            len: 50,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        let start = |a: &mut AncestorSync, t: Instant| {
            a.note_deferred("peer", t);
            a.tick(t, &me.view(), &[peer.candidate()], |h| Some(me.hash_at(h)))
                .0
        };
        assert!(start(&mut a, t0).is_some());
        assert_eq!(
            a.end(Outcome::Budget { fetched: 0 }, t0),
            Some(Outcome::Budget { fetched: 0 })
        );
        let t1 = t0 + COOLDOWN_BASE;
        assert!(
            start(&mut a, t1).is_some(),
            "the first cooldown is the base"
        );
        let _ = a.end(Outcome::Budget { fetched: 0 }, t1);
        assert_eq!(
            start(&mut a, t1 + COOLDOWN_BASE),
            None,
            "the second empty budget doubles the cooldown"
        );
        assert!(start(&mut a, t1 + COOLDOWN_BASE * 2).is_some());
    }

    /// Review round 2, fix (c): resumable budget endings that leave the
    /// applied tip where it was stop being free after MAX_IDLE_BUDGETS.
    #[test]
    fn idle_budgets_in_a_row_cool_the_peer() {
        let me = Me::new(100, 120, 3, 0);
        let peer = Peer {
            fork: 100,
            len: 50,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        let start = |a: &mut AncestorSync, t: Instant, view: &View| {
            a.note_deferred("peer", t);
            a.tick(t, view, &[peer.candidate()], |h| Some(me.hash_at(h)))
                .0
        };
        let view = me.view();
        for k in 1..MAX_IDLE_BUDGETS {
            assert!(
                start(&mut a, t0, &view).is_some(),
                "budget {k} restarts at once"
            );
            let _ = a.end(Outcome::Budget { fetched: 5 }, t0);
        }
        assert!(start(&mut a, t0, &view).is_some());
        let _ = a.end(Outcome::Budget { fetched: 5 }, t0);
        assert_eq!(
            start(&mut a, t0, &view),
            None,
            "idle budgets cooled the peer"
        );
        // Progress resets it: the applied tip moved during the episode.
        let t1 = t0 + COOLDOWN_BASE * 4;
        assert!(start(&mut a, t1, &view).is_some());
        let moved = View {
            applied: (hb(7, 121), 121),
            ..view
        };
        let _ = a.tick(t1, &moved, &[peer.candidate()], |h| Some(me.hash_at(h)));
        let _ = a.end(Outcome::Budget { fetched: 5 }, t1);
        assert!(
            start(&mut a, t1, &moved).is_some(),
            "a moving tip restarts at once"
        );
    }

    /// Review rounds 2 and 3: only a body request in flight AFTER this
    /// episode's own body answer had a block admitted stands the tick and
    /// pipeline aside; header paging and the first body request never do.
    #[test]
    fn only_a_body_request_after_a_delivered_window_owns_sync() {
        let mut me = Me::new(1_000, 1_100, 3, 0);
        let peer = Peer {
            fork: 1_000,
            len: 600,
            per: 4,
            claim: None,
        };
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        a.note_deferred("peer", t0);
        let mut bodies = 0u32;
        for tick in 0..20_000u64 {
            let now = t0 + Duration::from_millis(tick);
            let view = me.view();
            let (req, ended) = a.tick(now, &view, &[peer.candidate()], |h| {
                (h <= me.tip).then(|| me.hash_at(h))
            });
            if ended.is_some() {
                break;
            }
            match req {
                Some(Request::Locate { locator, .. }) => {
                    assert!(!a.owns_sync(), "a locate in flight");
                    let _ = reply(&mut a, &me, &peer, &locator, now);
                    assert!(!a.owns_sync(), "between header pages");
                }
                Some(Request::Bodies { from, height, .. }) => {
                    bodies += 1;
                    if bodies == 1 {
                        assert!(
                            !a.owns_sync(),
                            "the first body request: nothing delivered yet"
                        );
                    } else {
                        assert!(
                            a.owns_sync(),
                            "a body request after a delivered, admitted window"
                        );
                    }
                    for x in height..=height + u64::from(BODY_WINDOW) {
                        if x <= peer.tip().1 {
                            me.held.insert(peer.hash_at(x));
                        }
                    }
                    let held = me.held.clone();
                    let _ = a.on_blocks("peer", &[from], now, |h| held.contains(h));
                    assert!(!a.owns_sync(), "the body answer is in");
                }
                None => {}
            }
        }
        assert!(bodies > 1);
    }

    /// PR #483 review round 3, P1: K peers taking turns. Each serves a valid
    /// high-work header chain and then never delivers a body. Cooldowns are
    /// per peer but standing the tick aside is node-wide, so a body request
    /// in flight must not stand anything aside until this episode's own body
    /// answer has had a block admitted.
    #[test]
    fn rotating_sybils_with_fabricated_headers_cannot_own_sync() {
        let me = Me::new(1_000, 1_100, 3, 0);
        let peer = Peer {
            fork: 1_000,
            len: 200,
            per: 4,
            claim: None,
        };
        let k = 32usize;
        let ids: Vec<String> = (0..k).map(|i| format!("s{i}")).collect();
        let cands: Vec<Candidate> = ids
            .iter()
            .map(|id| Candidate {
                id: id.clone(),
                ..peer.candidate()
            })
            .collect();
        let mut a = AncestorSync::new();
        let t0 = Instant::now();
        let total = 3_600u64;
        let mut owned = 0u64;
        let mut bodies = 0u64;
        for sec in 0..total {
            let now = t0 + Duration::from_secs(sec);
            for id in &ids {
                a.note_deferred(id, now);
            }
            let view = View {
                behind: true,
                ..me.view()
            };
            let (mut req, _) = a.tick(now, &view, &cands, |h| Some(me.hash_at(h)));
            // Every locate is answered at once; no body ever is.
            while let Some(Request::Locate { peer: who, locator }) = req.clone() {
                let (common, headers) = peer.answer(&locator);
                let held = me.held.clone();
                let out = a.on_ancestor(
                    &who,
                    common,
                    peer.tip(),
                    peer.tip_work(),
                    &headers,
                    &view,
                    now,
                    NOW,
                    |h, _| held.contains(h),
                    |h| me.header(h),
                );
                if out.is_some() {
                    break;
                }
                req = a.next(now);
            }
            if matches!(req, Some(Request::Bodies { .. })) {
                bodies += 1;
            }
            if a.owns_sync() {
                owned += 1;
            }
        }
        eprintln!("sybils: owned {owned}/{total} s, {bodies} body requests");
        assert!(bodies > 0, "fixture: the sybils got to the body phase");
        assert!(
            owned * 100 < total,
            "{k} rotating peers held the sync tick aside for {owned} of {total} s ({bodies} body requests)"
        );
    }
}
