// citrate/core/network/src/sync_ranges.rs
//
// Range scheduler for catch-up block download.
//
// WHY THIS EXISTS
//
// The previous driver anchored every `GetBlocks` at the node's applied tip at
// the moment the request was sent, and retired ALL of a peer's outstanding
// requests whenever any response from that peer was processed. The two
// together meant the node forgot about requests whose answers were still on
// the wire, and kept issuing new ones from nearly the same height. With the
// in-flight cap at 8, about 8 requests covering almost the same 32 heights
// stayed outstanding to ONE peer, and each 32-block answer carried about
// 32 / 8 = 4 blocks the node did not already have. A capacity run measured
// exactly that shape: ~4 new blocks per 32-block response, one peer, ~56
// blocks/min against a tip growing ~30/min, CPU mostly idle.
//
// THE MODEL
//
// Heights above the applied tip are split into non-overlapping ranges of
// `range_len` heights, keyed by their first height. A range is in exactly one
// of three states: unrequested, in flight (to one peer, with a deadline), or
// delivered (validated blocks handed to admission, waiting to be applied).
// Requests are only ever issued for unrequested heights, so two outstanding
// requests never cover the same height.
//
// The wire protocol is unchanged. `GetBlocks { from }` serves from the height
// of `from` inclusive, so a range starting at height `s` is requested with the
// hash of a block at height `s` as its anchor. Those hashes come from
// `GetHeaders`, which the scheduler requests ahead of the applied tip (bounded
// by `lookahead`). The first range above the applied tip can always fall back
// to the applied tip itself as the anchor, which is what the old driver did, so
// a missing or bad header source can slow the pipeline down to the old rate
// but never stall it.
//
// Several ranges are in flight at once, spread over every peer that claims a
// head at or above the range (per-peer and total caps). A range that times
// out, comes back empty, or comes back short is released and re-planned; the
// peer that failed it is avoided for that range while another can serve it.
//
// LINKAGE. Header anchors are claims: a header's hash cannot be recomputed
// without the block body, so an anchor is only confirmed when blocks come
// back. A range counts as delivered only through the blocks that LINK to its
// anchor: the anchor block itself (or a sibling with the same parent), then
// each block whose selected parent is an already linked block. Blocks at the
// right heights that do not link (re-sealed on another parent) deliver
// nothing, so the range is re-planned elsewhere instead of waiting for a
// stall. An answer that contains a range's anchor at ANOTHER height proves the
// anchor wrong: the anchor and every anchor from the same header source are
// dropped, and that source is asked for headers again only when no other peer
// can be. A range that fails twice (any mix of timeouts, empty, non-linking
// answers, from two peers) drops its anchor too, so the first range falls
// back to the applied tip. Header requests that bring nothing new back off.
// Peers whose answers proved a wrong anchor, or whose delivered range never
// applied, are reported in `Plan::misbehaved` for the caller to charge.
//
// BACKOFF. A range that every eligible peer has failed (empty, nothing new,
// non-linking, timed out) is not asked again at once: it waits
// `retry_backoff`, doubling on each further round up to `retry_backoff_max`.
// At the tip, or on a branch no peer serves, every answer brings nothing, and
// without this the request rate is bounded only by the peers' round trip.
//
// NOTHING HERE DECIDES VALIDITY. The scheduler only decides what to ask for and
// from whom. Every block still goes through `SyncManager::handle_blocks`
// (hash, signature, tx_root, timestamp) and then admission and execution,
// exactly as before.

use crate::peer::PeerId;
use citrate_consensus::types::Hash;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

/// Tunables for [`RangeScheduler`].
#[derive(Debug, Clone)]
pub struct RangeConfig {
    /// Heights per range. Matches `SyncConfig::block_batch_size` so a full
    /// response stays inside the transport's per-message budget.
    pub range_len: u64,
    /// Block ranges in flight across all peers.
    pub max_in_flight: usize,
    /// Block ranges in flight to any one peer.
    pub max_in_flight_per_peer: usize,
    /// How long a range (or header request) may stay unanswered before it is
    /// released and re-planned on another peer.
    pub request_timeout: Duration,
    /// How far above the applied tip ranges and header anchors are planned.
    /// Bounds the anchor map and the out-of-order blocks admission has to
    /// buffer while an earlier range is still in flight.
    pub lookahead: u64,
    /// Headers requested per `GetHeaders`.
    pub header_count: u32,
    /// If delivered ranges sit above the applied tip for this long without the
    /// applied tip moving, they are forgotten and re-requested. Covers blocks
    /// that admission later refused or that fell out of its bounded orphan
    /// buffer: the scheduler cannot see either, but it can see that nothing
    /// advanced.
    pub stall_timeout: Duration,
    /// After a header answer that adds no anchor (or a header request that
    /// timed out), wait this long before the next `GetHeaders`.
    pub header_backoff: Duration,
    /// Once every eligible peer has failed a range, wait this long before
    /// asking again; doubles per further round.
    pub retry_backoff: Duration,
    /// Cap on the per-range backoff.
    pub retry_backoff_max: Duration,
}

impl Default for RangeConfig {
    fn default() -> Self {
        Self {
            range_len: 32,
            max_in_flight: 12,
            max_in_flight_per_peer: 4,
            request_timeout: Duration::from_secs(10),
            lookahead: 32 * 16,
            header_count: 128,
            stall_timeout: Duration::from_secs(30),
            header_backoff: Duration::from_secs(1),
            retry_backoff: Duration::from_millis(500),
            retry_backoff_max: Duration::from_secs(8),
        }
    }
}

/// A peer that may be asked for blocks, in the caller's preference order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSlot {
    pub id: PeerId,
    /// The head height the peer advertises. Only a necessary condition: a peer
    /// is never asked for a range that starts above it.
    pub head_height: u64,
    /// Ranges this peer may hold at once; `0` means the configured
    /// `max_in_flight_per_peer`. The caller lowers it for a peer in bad
    /// standing, so overflow from good peers does not pile onto a peer that
    /// has been timing out or answering empty (a silent peer holding a range
    /// near the front stalls apply for a whole timeout).
    pub max_in_flight: usize,
}

impl PeerSlot {
    pub fn new(id: PeerId, head_height: u64) -> Self {
        Self {
            id,
            head_height,
            max_in_flight: 0,
        }
    }
}

/// What the scheduler needs to know about one validated block in a `Blocks`
/// answer: enough to check that it links to the range's anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLink {
    pub height: u64,
    pub hash: Hash,
    /// The block's selected parent.
    pub parent: Hash,
}

/// One request the caller should send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncRequest {
    Headers {
        peer: PeerId,
        from: Hash,
        from_height: u64,
        count: u32,
    },
    Blocks {
        peer: PeerId,
        /// Anchor hash; the server serves from its height inclusive.
        from: Hash,
        /// Height of `from`.
        anchor_height: u64,
        /// First height this range needs (== `anchor_height`, except for the
        /// applied-tip fallback where it is `anchor_height + 1`).
        start: u64,
        /// Last height this range needs.
        end: u64,
        /// Blocks to ask for: covers `anchor_height..=end` and no further, so
        /// the answer cannot spill into the next range.
        count: u32,
    },
}

/// A request that went unanswered past its deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expired {
    pub peer: PeerId,
    /// First height of the expired block range, or the anchor height of an
    /// expired header request.
    pub height: u64,
    pub headers: bool,
}

/// What [`RangeScheduler::plan`] decided this round.
#[derive(Debug, Default)]
pub struct Plan {
    pub requests: Vec<SyncRequest>,
    pub expired: Vec<Expired>,
    /// Peers that, since the last plan, sent a header anchor that a block
    /// answer proved wrong, or delivered a range that never applied. The
    /// caller charges them.
    pub misbehaved: Vec<PeerId>,
}

/// How a `Blocks` response related to what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlocksMatch {
    /// Answered one of our ranges.
    Range {
        start: u64,
        end: u64,
        /// Last height of the contiguous run delivered from `start`
        /// (`start - 1` when nothing usable came back).
        delivered_through: u64,
    },
    /// Not an answer to any range in flight to this peer: an ancestry request,
    /// or a late answer to a range that already timed out and was reassigned.
    Unsolicited,
}

/// Counters, for tests and diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeCounters {
    /// `GetBlocks` issued by the scheduler.
    pub block_requests: u64,
    /// `GetHeaders` issued by the scheduler.
    pub header_requests: u64,
    /// Block requests issued for a height that was already in flight,
    /// delivered, or applied. The scheduler never does this; the counter is
    /// the check.
    pub duplicate_requests: u64,
    /// Block requests for a range that had been requested before (after a
    /// timeout, an empty answer or a short answer).
    pub retries: u64,
    pub timeouts: u64,
    pub empty_responses: u64,
    pub short_responses: u64,
    pub unsolicited_responses: u64,
    /// Ranges anchored on the applied tip because no header anchor was known.
    pub tip_anchored: u64,
    /// Times delivered ranges were forgotten because the applied tip stalled.
    pub stall_resets: u64,
    /// Non-empty answers in which nothing linked to the range's anchor.
    pub unlinked_responses: u64,
    /// Answers that carried a range's anchor at another height.
    pub wrong_anchors: u64,
    /// Times anchors were dropped because a range failed on two peers or an
    /// anchor was proved wrong.
    pub anchor_evictions: u64,
    /// Delivered ranges dropped because admission refused their blocks.
    pub rejected_ranges: u64,
    /// Times a range was held back because every eligible peer had failed it.
    pub backoffs: u64,
}

#[derive(Debug, Clone)]
struct InFlight {
    anchor: Hash,
    anchor_height: u64,
    end: u64,
    peer: PeerId,
    sent_at: Instant,
}

#[derive(Debug, Clone)]
struct HeaderReq {
    peer: PeerId,
    sent_at: Instant,
}

/// See the module docs.
#[derive(Debug)]
pub struct RangeScheduler {
    cfg: RangeConfig,
    applied: u64,
    applied_hash: Hash,
    last_progress: Option<Instant>,
    /// Known block hashes above the applied tip (height -> (hash, source)).
    anchors: BTreeMap<u64, (Hash, PeerId)>,
    /// start -> request.
    in_flight: BTreeMap<u64, InFlight>,
    /// start -> (end, peer that delivered it), validated, linked and handed
    /// to admission, not yet applied.
    delivered: BTreeMap<u64, (u64, PeerId)>,
    /// start -> peers that failed that range.
    avoid: HashMap<u64, Vec<PeerId>>,
    /// start -> (not before, current backoff) for a range every eligible
    /// peer has failed. See `RangeConfig::retry_backoff`.
    retry: HashMap<u64, (Option<Instant>, Duration)>,
    /// Ranges requested at least once (for the retry counter).
    requested_once: BTreeSet<u64>,
    header_req: Option<HeaderReq>,
    header_avoid: Vec<PeerId>,
    /// Header sources whose anchors were proved wrong; asked only when no
    /// other peer can be. Bounded by `MAX_BAD_HEADER_SOURCES`.
    bad_header_sources: Vec<PeerId>,
    /// No `GetHeaders` before this instant (see `RangeConfig::header_backoff`).
    header_retry_at: Option<Instant>,
    /// Peers to report in the next `Plan::misbehaved`.
    misbehaved: Vec<PeerId>,
    counters: RangeCounters,
}

/// Bound on remembered bad header sources (and pending misbehaviour reports).
const MAX_BAD_HEADER_SOURCES: usize = 64;

impl RangeScheduler {
    pub fn new(cfg: RangeConfig) -> Self {
        Self {
            cfg,
            applied: 0,
            applied_hash: Hash::default(),
            last_progress: None,
            anchors: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            delivered: BTreeMap::new(),
            avoid: HashMap::new(),
            retry: HashMap::new(),
            requested_once: BTreeSet::new(),
            header_req: None,
            header_avoid: Vec::new(),
            bad_header_sources: Vec::new(),
            header_retry_at: None,
            misbehaved: Vec::new(),
            counters: RangeCounters::default(),
        }
    }

    pub fn config(&self) -> &RangeConfig {
        &self.cfg
    }

    pub fn counters(&self) -> &RangeCounters {
        &self.counters
    }

    /// Block ranges currently in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Block ranges in flight to `peer`.
    pub fn in_flight_to(&self, peer: &PeerId) -> usize {
        self.in_flight.values().filter(|r| r.peer == *peer).count()
    }

    /// Known header anchors (bounded by `lookahead`).
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    fn window_top(&self) -> u64 {
        self.applied.saturating_add(self.cfg.lookahead)
    }

    /// Advance to the node's applied height, dropping everything at or below it.
    pub fn on_applied(&mut self, applied: u64, applied_hash: Hash, now: Instant) {
        // The applied tip moved DOWN, or sideways to another block at the same
        // height (a fork-choice reorg): every plan above it was made against a
        // chain we are no longer on. Start over from the new tip; whatever is
        // still in flight answers as unsolicited and is admitted normally.
        if applied < self.applied || (applied == self.applied && applied_hash != self.applied_hash)
        {
            self.applied = applied;
            self.applied_hash = applied_hash;
            self.anchors.clear();
            self.in_flight.clear();
            self.delivered.clear();
            self.avoid.clear();
            self.retry.clear();
            self.requested_once.clear();
            self.header_req = None;
            self.last_progress = Some(now);
            return;
        }
        self.applied_hash = applied_hash;
        if self.last_progress.is_none() || applied > self.applied {
            self.last_progress = Some(now);
        }
        if applied <= self.applied {
            return;
        }
        self.applied = applied;
        let keep_from = applied.saturating_add(1);
        self.anchors = self.anchors.split_off(&keep_from);
        // A range that straddles the tip keeps only its unapplied tail.
        self.delivered = std::mem::take(&mut self.delivered)
            .into_iter()
            .filter(|(_, (end, _))| *end > applied)
            .map(|(start, d)| (start.max(keep_from), d))
            .collect();
        self.avoid.retain(|start, _| *start > applied);
        self.retry.retain(|start, _| *start > applied);
        self.requested_once = self.requested_once.split_off(&keep_from);
        // In-flight ranges below the tip are left to resolve (or time out) on
        // their own: their answer is harmless and dropping them here would
        // re-open the same heights to a second request.
    }

    /// True when `height` is in flight or delivered.
    fn covered(&self, height: u64) -> Option<u64> {
        // The range containing `height`, if any, returns its end.
        if let Some(end) = self
            .delivered
            .range(..=height)
            .next_back()
            .and_then(|(_, (end, _))| (*end >= height).then_some(*end))
        {
            return Some(end);
        }
        self.in_flight
            .range(..=height)
            .next_back()
            .and_then(|(_, r)| (r.end >= height).then_some(r.end))
    }

    /// First covered height strictly above `height`, if any.
    fn next_covered_after(&self, height: u64) -> Option<u64> {
        let from = height.saturating_add(1);
        let a = self.delivered.range(from..).next().map(|(s, _)| *s);
        let b = self.in_flight.range(from..).next().map(|(s, _)| *s);
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }

    /// Does `[start, end]` intersect anything in flight, delivered or applied?
    fn overlaps_existing(&self, start: u64, end: u64) -> bool {
        if start <= self.applied {
            return true;
        }
        let mut h = start;
        while h <= end {
            if self.covered(h).is_some() {
                return true;
            }
            match self.next_covered_after(h) {
                Some(n) if n <= end => h = n,
                _ => return false,
            }
        }
        false
    }

    /// Highest `h` such that every height in `applied+1..=h` has an anchor.
    fn anchor_frontier(&self) -> u64 {
        let mut h = self.applied;
        for (height, _) in self.anchors.range(self.applied.saturating_add(1)..) {
            if *height == h.saturating_add(1) {
                h = *height;
            } else {
                break;
            }
        }
        h
    }

    fn expire(&mut self, now: Instant) -> Vec<Expired> {
        let timeout = self.cfg.request_timeout;
        let late: Vec<u64> = self
            .in_flight
            .iter()
            .filter(|(_, r)| now.saturating_duration_since(r.sent_at) > timeout)
            .map(|(s, _)| *s)
            .collect();
        let mut out = Vec::new();
        for start in late {
            if let Some(r) = self.in_flight.remove(&start) {
                self.counters.timeouts = self.counters.timeouts.saturating_add(1);
                self.note_failure(start, &r.peer);
                out.push(Expired {
                    peer: r.peer,
                    height: start,
                    headers: false,
                });
            }
        }
        if let Some(h) = &self.header_req {
            if now.saturating_duration_since(h.sent_at) > timeout {
                let peer = h.peer.clone();
                self.header_req = None;
                self.header_avoid.push(peer.clone());
                self.header_retry_at = now.checked_add(self.cfg.header_backoff);
                out.push(Expired {
                    peer,
                    height: self.anchor_frontier(),
                    headers: true,
                });
            }
        }
        out
    }

    /// Decide what to request now. `peers` is in the caller's preference
    /// order; `applied_hash` is the hash of the applied tip (or the all-zero
    /// genesis sentinel when nothing is applied).
    pub fn plan(
        &mut self,
        now: Instant,
        applied: u64,
        applied_hash: Hash,
        peers: &[PeerSlot],
    ) -> Plan {
        self.on_applied(applied, applied_hash, now);
        let mut plan = Plan {
            expired: self.expire(now),
            ..Plan::default()
        };

        // Stall valve: delivered blocks that never got applied (refused by
        // admission, or evicted from its orphan buffer) are re-requested.
        if !self.delivered.is_empty() {
            if let Some(t) = self.last_progress {
                if now.saturating_duration_since(t) > self.cfg.stall_timeout {
                    // The range at the front is the one that did not apply:
                    // its deliverer is avoided for it and reported.
                    let front = self.applied.saturating_add(1);
                    if let Some((_, peer)) = self.delivered.get(&front).cloned() {
                        self.avoid.entry(front).or_default().push(peer.clone());
                        self.report(peer);
                    }
                    self.delivered.clear();
                    self.anchors.clear();
                    self.counters.stall_resets = self.counters.stall_resets.saturating_add(1);
                    self.last_progress = Some(now);
                }
            }
        }

        // Header anchors, one request at a time, kept `lookahead` ahead.
        let backing_off = self.header_retry_at.is_some_and(|t| now < t);
        if self.header_req.is_none() && !backing_off {
            let frontier = self.anchor_frontier();
            if frontier < self.window_top() {
                let from = if frontier == self.applied {
                    Some(applied_hash)
                } else {
                    self.anchors.get(&frontier).map(|(h, _)| *h)
                };
                let bad = &self.bad_header_sources;
                let eligible = |p: &&PeerSlot, avoid: &[PeerId]| {
                    p.head_height > frontier && !avoid.contains(&p.id)
                };
                let mut pick = peers
                    .iter()
                    .find(|p| eligible(p, &self.header_avoid) && !bad.contains(&p.id));
                if pick.is_none() && !self.header_avoid.is_empty() {
                    self.header_avoid.clear();
                    pick = peers
                        .iter()
                        .find(|p| eligible(p, &[]) && !bad.contains(&p.id));
                }
                // A source that sent a wrong anchor is the last resort.
                if pick.is_none() {
                    pick = peers.iter().find(|p| eligible(p, &[]));
                }
                if let (Some(peer), Some(from)) = (pick, from) {
                    self.header_req = Some(HeaderReq {
                        peer: peer.id.clone(),
                        sent_at: now,
                    });
                    self.counters.header_requests = self.counters.header_requests.saturating_add(1);
                    plan.requests.push(SyncRequest::Headers {
                        peer: peer.id.clone(),
                        from,
                        from_height: frontier,
                        count: self.cfg.header_count,
                    });
                }
            }
        }

        // Block ranges.
        let mut cursor = self.applied.saturating_add(1);
        while self.in_flight.len() < self.cfg.max_in_flight {
            // Skip covered heights.
            while let Some(end) = self.covered(cursor) {
                cursor = end.saturating_add(1);
            }
            let start = cursor;
            if start > self.window_top() {
                break;
            }
            // Anchor: a header hash at `start`, or the applied tip for the
            // first range above it.
            let (from, anchor_height) = match self.anchors.get(&start) {
                Some((h, _)) => (*h, start),
                None if start == self.applied.saturating_add(1) => (applied_hash, self.applied),
                None => break,
            };
            let mut end = anchor_height
                .saturating_add(self.cfg.range_len)
                .saturating_sub(1)
                .max(start);
            if let Some(next) = self.next_covered_after(start) {
                end = end.min(next.saturating_sub(1));
            }
            // Peer: preference order, head at or above `start`, under the
            // per-peer cap, not one that already failed this range.
            let mut pick = None;
            let mut repeat = false;
            for pass in 0..2 {
                let avoid: &[PeerId] = if pass == 0 {
                    self.avoid.get(&start).map(Vec::as_slice).unwrap_or(&[])
                } else {
                    &[]
                };
                pick = peers.iter().find(|p| {
                    let cap = match p.max_in_flight {
                        0 => self.cfg.max_in_flight_per_peer,
                        n => n.min(self.cfg.max_in_flight_per_peer),
                    };
                    p.head_height >= start
                        && !avoid.contains(&p.id)
                        && self.in_flight_to(&p.id) < cap
                });
                if pick.is_some() {
                    repeat = pass == 1;
                    break;
                }
            }
            let Some(peer) = pick else { break };
            // Every eligible peer has already failed this range: back off,
            // and plan nothing above it meanwhile (blocks above a range nobody
            // can serve cannot be applied anyway).
            if repeat && !self.retry_due(start, now) {
                break;
            }

            if self.overlaps_existing(start, end) {
                self.counters.duplicate_requests =
                    self.counters.duplicate_requests.saturating_add(1);
            }
            if !self.requested_once.insert(start) {
                self.counters.retries = self.counters.retries.saturating_add(1);
            }
            if anchor_height < start {
                self.counters.tip_anchored = self.counters.tip_anchored.saturating_add(1);
            }
            self.counters.block_requests = self.counters.block_requests.saturating_add(1);
            let count = u32::try_from(end.saturating_sub(anchor_height).saturating_add(1))
                .unwrap_or(u32::MAX);
            self.in_flight.insert(
                start,
                InFlight {
                    anchor: from,
                    anchor_height,
                    end,
                    peer: peer.id.clone(),
                    sent_at: now,
                },
            );
            plan.requests.push(SyncRequest::Blocks {
                peer: peer.id.clone(),
                from,
                anchor_height,
                start,
                end,
                count,
            });
            cursor = end.saturating_add(1);
        }
        plan.misbehaved = std::mem::take(&mut self.misbehaved);
        plan
    }

    /// May the range at `start`, which every eligible peer has failed, be
    /// asked again now? The first time it is not: a backoff starts (or
    /// doubles, up to the cap). Once the backoff has passed it may, once; the
    /// next failure starts the next, longer backoff.
    fn retry_due(&mut self, start: u64, now: Instant) -> bool {
        let base = self.cfg.retry_backoff;
        let max = self.cfg.retry_backoff_max;
        let entry = self.retry.entry(start).or_insert((None, Duration::ZERO));
        match entry.0 {
            Some(at) if now >= at => {
                entry.0 = None;
                true
            }
            Some(_) => false,
            None => {
                let next = if entry.1.is_zero() {
                    base
                } else {
                    entry.1.saturating_mul(2).min(max)
                };
                *entry = (now.checked_add(next), next);
                self.counters.backoffs = self.counters.backoffs.saturating_add(1);
                false
            }
        }
    }

    /// Queue `peer` for the next `Plan::misbehaved` (bounded, de-duplicated).
    fn report(&mut self, peer: PeerId) {
        if !self.misbehaved.contains(&peer) && self.misbehaved.len() < MAX_BAD_HEADER_SOURCES {
            self.misbehaved.push(peer);
        }
    }

    /// `peer` failed the range at `start` (timeout, empty or non-linking
    /// answer). Once two different peers have failed it, its anchor is the
    /// likelier fault: drop it and every anchor above it, and avoid its
    /// header source, so the anchors are fetched again (or, for the first
    /// range, the applied tip is used).
    fn note_failure(&mut self, start: u64, peer: &PeerId) {
        let failed = self.avoid.entry(start).or_default();
        if !failed.contains(peer) {
            failed.push(peer.clone());
        }
        if failed.len() < 2 {
            return;
        }
        if let Some((_, src)) = self.anchors.get(&start) {
            let src = src.clone();
            if !self.header_avoid.contains(&src) {
                self.header_avoid.push(src);
            }
            let _ = self.anchors.split_off(&start);
            self.counters.anchor_evictions = self.counters.anchor_evictions.saturating_add(1);
        }
    }

    /// An answer proved the anchor `anchor` wrong (that hash is a block at
    /// another height). Drop every anchor `src` gave us and stop preferring
    /// it as a header source.
    fn evict_header_source(&mut self, src: &PeerId) {
        self.anchors.retain(|_, (_, from)| from != src);
        if !self.bad_header_sources.contains(src) {
            if self.bad_header_sources.len() >= MAX_BAD_HEADER_SOURCES {
                self.bad_header_sources.remove(0);
            }
            self.bad_header_sources.push(src.clone());
        }
        self.counters.anchor_evictions = self.counters.anchor_evictions.saturating_add(1);
        self.report(src.clone());
    }

    /// A `Headers` response from `peer`, as `(height, hash)` ascending.
    pub fn on_headers(&mut self, peer: &PeerId, headers: &[(u64, Hash)]) {
        self.on_headers_at(peer, headers, Instant::now());
    }

    /// [`Self::on_headers`] at a given instant (for the backoff).
    pub fn on_headers_at(&mut self, peer: &PeerId, headers: &[(u64, Hash)], now: Instant) {
        let solicited = self.header_req.as_ref().is_some_and(|h| h.peer == *peer);
        if !solicited {
            return;
        }
        self.header_req = None;
        let top = self.window_top();
        let mut added = 0usize;
        for (height, hash) in headers {
            if *height <= self.applied || *height > top {
                continue;
            }
            // First writer wins; a bad anchor is evicted by `on_blocks`, by
            // two failures of its range, or with its whole source.
            self.anchors.entry(*height).or_insert_with(|| {
                added = added.saturating_add(1);
                (*hash, peer.clone())
            });
        }
        if added == 0 {
            self.header_avoid.push(peer.clone());
            self.header_retry_at = now.checked_add(self.cfg.header_backoff);
        } else {
            self.header_avoid.retain(|p| p != peer);
        }
    }

    /// A `Blocks` response from `peer`. `first_height` is the height of the
    /// first block in the response as received (before validation); `blocks`
    /// the blocks that passed validation, in the order received.
    pub fn on_blocks(
        &mut self,
        peer: &PeerId,
        first_height: Option<u64>,
        blocks: &[BlockLink],
    ) -> BlocksMatch {
        // A server answers `GetBlocks` from its anchor's height inclusive, so
        // the answer to a range carries the range's anchor block.
        let by_anchor = self
            .in_flight
            .iter()
            .filter(|(_, r)| r.peer == *peer)
            .find_map(|(s, r)| {
                blocks
                    .iter()
                    .find(|b| b.hash == r.anchor)
                    .map(|b| (*s, b.height != r.anchor_height))
            });
        if let Some((start, true)) = by_anchor {
            // The anchor is a block at another height: the header that gave
            // it was wrong. The peer answered what it was asked; release the
            // range without holding it against the peer.
            self.in_flight.remove(&start);
            self.counters.wrong_anchors = self.counters.wrong_anchors.saturating_add(1);
            if let Some((_, src)) = self.anchors.get(&start).cloned() {
                self.evict_header_source(&src);
            }
            self.counters.unsolicited_responses =
                self.counters.unsolicited_responses.saturating_add(1);
            return BlocksMatch::Unsolicited;
        }
        let start = match (by_anchor, first_height) {
            (Some((start, _)), _) => Some(start),
            // An empty answer carries no height; servers answer in order, so
            // it answers the oldest range in flight to this peer.
            (None, None) => self
                .in_flight
                .iter()
                .filter(|(_, r)| r.peer == *peer)
                .min_by_key(|(_, r)| r.sent_at)
                .map(|(s, _)| *s),
            (None, Some(first)) => self
                .in_flight
                .iter()
                .find(|(_, r)| r.peer == *peer && r.anchor_height == first)
                .or_else(|| {
                    self.in_flight.iter().find(|(_, r)| {
                        r.peer == *peer && r.anchor_height <= first && first <= r.end
                    })
                })
                .map(|(s, _)| *s),
        };
        let Some(start) = start else {
            self.counters.unsolicited_responses =
                self.counters.unsolicited_responses.saturating_add(1);
            return BlocksMatch::Unsolicited;
        };
        let Some(req) = self.in_flight.remove(&start) else {
            return BlocksMatch::Unsolicited;
        };
        let linked = linked_heights(&req, blocks);
        let mut through = start.saturating_sub(1);
        while linked.contains(&through.saturating_add(1)) && through < req.end {
            through = through.saturating_add(1);
        }
        if through >= start {
            self.retry.remove(&start);
            self.delivered.insert(start, (through, peer.clone()));
            if through < req.end {
                self.counters.short_responses = self.counters.short_responses.saturating_add(1);
            }
        } else {
            let in_range = blocks
                .iter()
                .any(|b| b.height >= start && b.height <= req.end);
            if in_range {
                self.counters.unlinked_responses =
                    self.counters.unlinked_responses.saturating_add(1);
            } else {
                self.counters.empty_responses = self.counters.empty_responses.saturating_add(1);
            }
            self.note_failure(start, peer);
        }
        BlocksMatch::Range {
            start,
            end: req.end,
            delivered_through: through,
        }
    }

    /// Admission refused blocks that `peer` delivered for the range starting
    /// at `start`: forget the delivery so the range is asked of someone else,
    /// and report the peer.
    pub fn on_rejected(&mut self, peer: &PeerId, start: u64, end: u64) {
        let hits: Vec<u64> = self
            .delivered
            .range(..=end)
            .filter(|(s, (e, p))| *e >= start && **s <= end && p == peer)
            .map(|(s, _)| *s)
            .collect();
        for s in hits {
            self.delivered.remove(&s);
            self.avoid.entry(s).or_default().push(peer.clone());
            self.counters.rejected_ranges = self.counters.rejected_ranges.saturating_add(1);
            self.report(peer.clone());
        }
    }

    /// A delivery from `peer` for `start..=end` was dropped before admission
    /// (the local admission queue stayed full): forget it so the range is
    /// asked again. Not the peer's fault, so nothing is charged.
    pub fn on_dropped(&mut self, peer: &PeerId, start: u64, end: u64) {
        let hits: Vec<u64> = self
            .delivered
            .range(..=end)
            .filter(|(s, (e, p))| *e >= start && **s <= end && p == peer)
            .map(|(s, _)| *s)
            .collect();
        for s in hits {
            self.delivered.remove(&s);
        }
    }

    /// `peer` is gone (or its send failed): release everything it owed.
    pub fn release_peer(&mut self, peer: &PeerId) {
        let starts: Vec<u64> = self
            .in_flight
            .iter()
            .filter(|(_, r)| r.peer == *peer)
            .map(|(s, _)| *s)
            .collect();
        for s in starts {
            self.in_flight.remove(&s);
            self.note_failure(s, peer);
        }
        if self.header_req.as_ref().is_some_and(|h| h.peer == *peer) {
            self.header_req = None;
            self.header_avoid.push(peer.clone());
        }
    }
}

/// Heights in `blocks` that hold a block linking to `req`'s anchor: the
/// anchor itself, a sibling of it with the same parent, or a block whose
/// selected parent is already linked.
fn linked_heights(req: &InFlight, blocks: &[BlockLink]) -> BTreeSet<u64> {
    let mut sorted: Vec<&BlockLink> = blocks.iter().collect();
    sorted.sort_by_key(|b| b.height);
    let anchor_parent = sorted
        .iter()
        .find(|b| b.hash == req.anchor && b.height == req.anchor_height)
        .map(|b| b.parent);
    let mut linked: std::collections::HashSet<Hash> = std::collections::HashSet::new();
    linked.insert(req.anchor);
    let mut heights = BTreeSet::new();
    for b in sorted {
        let links = b.hash == req.anchor
            || linked.contains(&b.parent)
            || (b.height == req.anchor_height && Some(b.parent) == anchor_parent);
        if links {
            linked.insert(b.hash);
            heights.insert(b.height);
        }
    }
    heights
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u64) -> Hash {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&n.to_be_bytes());
        b[31] = 1;
        Hash::new(b)
    }

    fn pid(s: &str) -> PeerId {
        PeerId(s.to_string())
    }

    fn peers(ids: &[&str], head: u64) -> Vec<PeerSlot> {
        ids.iter().map(|i| PeerSlot::new(pid(i), head)).collect()
    }

    /// A fork-choice reorg that lowers the applied tip (or swaps it for a
    /// sibling at the same height) discards the plan made on the old branch:
    /// the next range is anchored on the NEW tip, so its answer matches.
    #[test]
    fn an_applied_tip_that_moves_down_or_sideways_restarts_the_plan() {
        let mut s = RangeScheduler::new(RangeConfig::default());
        let now = Instant::now();
        let ps = peers(&["a"], 10_000);
        s.plan(now, 100, h(100), &ps);
        s.on_headers(&pid("a"), &headers(101, 300));
        s.plan(now, 100, h(100), &ps);
        assert!(s.in_flight() > 1);

        // Down: tip back to 90 on another branch.
        let other = Hash::new([0xEE; 32]);
        let plan = s.plan(now, 90, other, &ps);
        let b = blocks_of(&plan.requests);
        assert_eq!(b.first().map(|r| (r.1, r.2)), Some((90, 91)));
        assert!(plan.requests.iter().any(|r| matches!(
            r,
            SyncRequest::Blocks { from, .. } if *from == other
        )));
        assert_eq!(s.anchor_count(), 0, "old-branch anchors dropped");
        // The answer to that range matches it.
        let m = s.on_blocks(&pid("a"), Some(90), &chain_on(other, 91, 121));
        assert!(matches!(m, BlocksMatch::Range { start: 91, .. }));

        // Sideways: same height, different hash.
        let sibling = Hash::new([0xDD; 32]);
        let plan = s.plan(now, 90, sibling, &ps);
        assert!(plan.requests.iter().any(|r| matches!(
            r,
            SyncRequest::Blocks { from, start: 91, .. } if *from == sibling
        )));
    }

    #[test]
    fn a_peer_in_bad_standing_holds_at_most_its_own_cap() {
        let mut s = RangeScheduler::new(RangeConfig::default());
        let now = Instant::now();
        let mut ps = peers(&["bad", "good"], 10_000);
        ps[0].max_in_flight = 1;
        s.plan(now, 0, h(0), &ps);
        s.on_headers(&pid("bad"), &headers(1, 512));
        s.plan(now, 0, h(0), &ps);
        assert_eq!(s.in_flight_to(&pid("bad")), 1);
        assert_eq!(
            s.in_flight_to(&pid("good")),
            RangeConfig::default().max_in_flight_per_peer
        );
    }

    /// Blocks `from..=to` of the test chain (`h(n)` on parent `h(n - 1)`).
    fn chain(from: u64, to: u64) -> Vec<BlockLink> {
        (from..=to)
            .map(|n| BlockLink {
                height: n,
                hash: h(n),
                parent: h(n.saturating_sub(1)),
            })
            .collect()
    }

    /// Blocks `from..=to` of another branch, the first on `parent`.
    fn chain_on(parent: Hash, from: u64, to: u64) -> Vec<BlockLink> {
        let mut prev = parent;
        (from..=to)
            .map(|n| {
                let mut b = [0xEEu8; 32];
                b[..8].copy_from_slice(&n.to_be_bytes());
                let link = BlockLink {
                    height: n,
                    hash: Hash::new(b),
                    parent: prev,
                };
                prev = link.hash;
                link
            })
            .collect()
    }

    fn headers(from: u64, to: u64) -> Vec<(u64, Hash)> {
        (from..=to).map(|n| (n, h(n))).collect()
    }

    fn blocks_of(reqs: &[SyncRequest]) -> Vec<(PeerId, u64, u64, u64)> {
        reqs.iter()
            .filter_map(|r| match r {
                SyncRequest::Blocks {
                    peer,
                    anchor_height,
                    start,
                    end,
                    ..
                } => Some((peer.clone(), *anchor_height, *start, *end)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn without_anchors_only_the_tip_anchored_range_is_requested() {
        let mut s = RangeScheduler::new(RangeConfig::default());
        let now = Instant::now();
        let plan = s.plan(now, 100, h(100), &peers(&["a", "b", "c"], 10_000));
        let b = blocks_of(&plan.requests);
        assert_eq!(b, vec![(pid("a"), 100, 101, 131)]);
        assert!(plan.requests.iter().any(|r| matches!(
            r,
            SyncRequest::Headers {
                from_height: 100,
                ..
            }
        )));
        // Planning again before anything answers asks for nothing new.
        let again = s.plan(now, 100, h(100), &peers(&["a", "b", "c"], 10_000));
        assert!(blocks_of(&again.requests).is_empty());
        assert_eq!(s.counters().duplicate_requests, 0);
    }

    #[test]
    fn with_anchors_ranges_are_disjoint_and_spread_over_peers() {
        let cfg = RangeConfig::default();
        let mut s = RangeScheduler::new(cfg.clone());
        let now = Instant::now();
        let ps = peers(&["a", "b", "c"], 10_000);
        s.plan(now, 0, h(0), &ps);
        s.on_headers(&pid("a"), &headers(1, 512));
        let plan = s.plan(now, 0, h(0), &ps);
        let b = blocks_of(&plan.requests);
        // The first range (tip-anchored) is already in flight; the rest fill
        // the window up to the total cap.
        assert_eq!(s.in_flight(), cfg.max_in_flight);
        let mut covered = BTreeSet::new();
        for (_, _, start, end) in &b {
            for x in *start..=*end {
                assert!(covered.insert(x), "height {x} requested twice");
            }
        }
        for p in ["a", "b", "c"] {
            assert!(s.in_flight_to(&pid(p)) <= cfg.max_in_flight_per_peer);
            assert!(s.in_flight_to(&pid(p)) > 0, "peer {p} unused");
        }
        assert_eq!(s.counters().duplicate_requests, 0);
    }

    #[test]
    fn an_empty_answer_moves_the_range_to_another_peer() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 1,
            ..RangeConfig::default()
        });
        let now = Instant::now();
        let ps = peers(&["bad", "good"], 10_000);
        let p1 = blocks_of(&s.plan(now, 0, h(0), &ps).requests);
        assert_eq!(p1[0].0, pid("bad"));
        assert_eq!(
            s.on_blocks(&pid("bad"), None, &[]),
            BlocksMatch::Range {
                start: 1,
                end: 31,
                delivered_through: 0
            }
        );
        let p2 = blocks_of(&s.plan(now, 0, h(0), &ps).requests);
        assert_eq!(p2, vec![(pid("good"), 0, 1, 31)]);
        assert_eq!(s.counters().retries, 1);
        assert_eq!(s.counters().empty_responses, 1);
    }

    #[test]
    fn a_slow_peer_times_out_and_its_range_is_reassigned() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 1,
            request_timeout: Duration::from_secs(5),
            ..RangeConfig::default()
        });
        let t0 = Instant::now();
        let ps = peers(&["slow", "fast"], 10_000);
        s.plan(t0, 0, h(0), &ps);
        let later = t0 + Duration::from_secs(6);
        let plan = s.plan(later, 0, h(0), &ps);
        let blocks_expired: Vec<Expired> = plan
            .expired
            .iter()
            .filter(|e| !e.headers)
            .cloned()
            .collect();
        assert_eq!(
            blocks_expired,
            vec![Expired {
                peer: pid("slow"),
                height: 1,
                headers: false
            }]
        );
        assert_eq!(blocks_of(&plan.requests)[0].0, pid("fast"));
        // The slow peer's late answer is not mistaken for the fast one's.
        assert_eq!(
            s.on_blocks(&pid("slow"), Some(0), &chain(1, 31)),
            BlocksMatch::Unsolicited
        );
        assert_eq!(s.in_flight(), 1);
    }

    #[test]
    fn a_short_answer_re_plans_only_the_missing_tail() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 1,
            ..RangeConfig::default()
        });
        let now = Instant::now();
        let ps = peers(&["a"], 10_000);
        s.plan(now, 0, h(0), &ps);
        s.on_headers(&pid("a"), &headers(1, 200));
        // Answer covers 1..=10 of 1..=31.
        let m = s.on_blocks(&pid("a"), Some(0), &chain(1, 10));
        assert_eq!(
            m,
            BlocksMatch::Range {
                start: 1,
                end: 31,
                delivered_through: 10
            }
        );
        let b = blocks_of(&s.plan(now, 0, h(0), &ps).requests);
        assert_eq!(b, vec![(pid("a"), 11, 11, 42)]);
        assert_eq!(s.counters().duplicate_requests, 0);
    }

    #[test]
    fn a_gap_before_a_covered_range_is_requested_without_spilling_into_it() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 2,
            ..RangeConfig::default()
        });
        let now = Instant::now();
        let ps = peers(&["a", "b"], 10_000);
        s.plan(now, 0, h(0), &ps);
        s.on_headers(&pid("a"), &headers(1, 200));
        s.plan(now, 0, h(0), &ps); // 1..=31 (a), 32..=63 (b)
                                   // a answers 1..=20 only.
        s.on_blocks(&pid("a"), Some(0), &chain(1, 20));
        let reqs = s.plan(now, 0, h(0), &ps).requests;
        let b: Vec<(u64, u64, u64, u32)> = reqs
            .iter()
            .filter_map(|r| match r {
                SyncRequest::Blocks {
                    anchor_height,
                    start,
                    end,
                    count,
                    ..
                } => Some((*anchor_height, *start, *end, *count)),
                _ => None,
            })
            .collect();
        // 21..=31 only, and asked for exactly 11 blocks so the answer cannot
        // run into 32..=63, which b already owns.
        assert_eq!(b, vec![(21, 21, 31, 11)]);
    }

    #[test]
    fn a_peer_is_never_asked_above_its_head() {
        let mut s = RangeScheduler::new(RangeConfig::default());
        let now = Instant::now();
        let ps = vec![
            PeerSlot::new(pid("low"), 40),
            PeerSlot::new(pid("high"), 10_000),
        ];
        s.plan(now, 0, h(0), &ps);
        s.on_headers(&pid("low"), &headers(1, 40));
        let plan = s.plan(now, 0, h(0), &ps);
        for (peer, _, start, _) in blocks_of(&plan.requests) {
            if peer == pid("low") {
                assert!(start <= 40);
            }
        }
    }

    #[test]
    fn anchors_stay_bounded_under_a_header_flood() {
        let cfg = RangeConfig::default();
        let mut s = RangeScheduler::new(cfg.clone());
        let now = Instant::now();
        let ps = peers(&["a"], u64::MAX);
        for round in 0..50u64 {
            s.plan(now, 0, h(0), &ps);
            s.on_headers(&pid("a"), &headers(1 + round * 1000, 1000 + round * 1000));
        }
        assert!(s.anchor_count() as u64 <= cfg.lookahead);
        // Unsolicited headers are ignored outright.
        s.on_headers(&pid("stranger"), &headers(1, 512));
        assert!(s.anchor_count() as u64 <= cfg.lookahead);
    }

    #[test]
    fn delivered_but_never_applied_ranges_are_re_requested_after_a_stall() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 1,
            stall_timeout: Duration::from_secs(30),
            ..RangeConfig::default()
        });
        let t0 = Instant::now();
        let ps = peers(&["a"], 10_000);
        s.plan(t0, 0, h(0), &ps);
        s.on_blocks(&pid("a"), Some(0), &chain(1, 31));
        // Applied tip never moves: after the stall timeout 1..=31 is asked
        // again. The only peer is the one whose delivery stalled, so it is
        // asked after the retry hold.
        let stalled = t0 + Duration::from_secs(31);
        assert!(blocks_of(&s.plan(stalled, 0, h(0), &ps).requests).is_empty());
        assert_eq!(s.counters().stall_resets, 1);
        let b = blocks_of(
            &s.plan(stalled + RangeConfig::default().retry_backoff, 0, h(0), &ps)
                .requests,
        );
        assert_eq!(b, vec![(pid("a"), 0, 1, 31)]);
    }

    #[test]
    fn applied_progress_frees_slots_and_never_re_requests_applied_heights() {
        let mut s = RangeScheduler::new(RangeConfig::default());
        let now = Instant::now();
        let ps = peers(&["a", "b", "c"], 100_000);
        let mut applied = 0u64;
        let mut asked = BTreeSet::new();
        for _ in 0..400 {
            let plan = s.plan(now, applied, h(applied), &ps);
            for r in &plan.requests {
                match r {
                    SyncRequest::Blocks {
                        peer, start, end, ..
                    } => {
                        for x in *start..=*end {
                            assert!(asked.insert(x), "height {x} requested twice");
                        }
                        let first = if *start == applied + 1 && !s.anchors.contains_key(start) {
                            applied
                        } else {
                            *start
                        };
                        s.on_blocks(peer, Some(first), &chain(*start, *end));
                    }
                    SyncRequest::Headers {
                        peer, from_height, ..
                    } => {
                        let top = from_height + 128;
                        s.on_headers(peer, &headers(from_height + 1, top));
                    }
                }
            }
            // Apply everything delivered contiguously.
            while s.covered(applied + 1).is_some() && s.delivered.contains_key(&(applied + 1)) {
                applied = s.delivered.get(&(applied + 1)).map_or(applied, |(e, _)| *e);
            }
        }
        assert!(applied > 5_000, "applied only {applied}");
        assert_eq!(s.counters().duplicate_requests, 0);
        assert_eq!(s.counters().retries, 0);
    }

    fn pending_misbehaved(s: &mut RangeScheduler, now: Instant, ps: &[PeerSlot]) -> Vec<PeerId> {
        let applied = s.applied;
        let hash = s.applied_hash;
        s.plan(now, applied, hash, ps).misbehaved
    }

    /// Blocks at the right heights that do not link to the range's anchor
    /// deliver nothing: the range goes to another peer at once.
    #[test]
    fn a_non_linking_answer_delivers_nothing_and_moves_the_range() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 1,
            ..RangeConfig::default()
        });
        let now = Instant::now();
        let ps = peers(&["forger", "good"], 10_000);
        let p1 = blocks_of(&s.plan(now, 0, h(0), &ps).requests);
        assert_eq!(p1, vec![(pid("forger"), 0, 1, 31)]);
        let fake = Hash::new([0xAB; 32]);
        assert_eq!(
            s.on_blocks(&pid("forger"), Some(1), &chain_on(fake, 1, 31)),
            BlocksMatch::Range {
                start: 1,
                end: 31,
                delivered_through: 0
            }
        );
        assert_eq!(s.counters().unlinked_responses, 1);
        let p2 = blocks_of(&s.plan(now, 0, h(0), &ps).requests);
        assert_eq!(p2, vec![(pid("good"), 0, 1, 31)]);
        // A linking answer is delivered, up to where the links stop.
        let mut answer = chain(0, 20);
        answer.extend(chain_on(fake, 21, 31));
        assert_eq!(
            s.on_blocks(&pid("good"), Some(0), &answer),
            BlocksMatch::Range {
                start: 1,
                end: 31,
                delivered_through: 20
            }
        );
    }

    /// On a multi-producer DAG the anchor's height group carries siblings:
    /// one with the anchor's parent links (and so do its children); one on
    /// another parent does not.
    #[test]
    fn a_sibling_of_the_anchor_links_only_through_the_same_parent() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 2,
            ..RangeConfig::default()
        });
        let now = Instant::now();
        let ps = peers(&["a"], 10_000);
        s.plan(now, 0, h(0), &ps);
        s.on_headers(&pid("a"), &headers(1, 200));
        let b = blocks_of(&s.plan(now, 0, h(0), &ps).requests);
        assert!(b.contains(&(pid("a"), 32, 32, 63)));
        let sibling = BlockLink {
            height: 32,
            hash: Hash::new([0x51; 32]),
            parent: h(31),
        };
        let child = BlockLink {
            height: 33,
            hash: Hash::new([0x52; 32]),
            parent: sibling.hash,
        };
        // Answer: the anchor's sibling and its child only (the anchor block's
        // own line stops at 32).
        let answer = vec![chain(32, 32)[0], sibling, child];
        assert_eq!(
            s.on_blocks(&pid("a"), Some(32), &answer),
            BlocksMatch::Range {
                start: 32,
                end: 63,
                delivered_through: 33
            }
        );
        // The same shape on a parent the anchor does not have links nothing
        // past the anchor itself.
        let mut s2 = RangeScheduler::new(RangeConfig {
            max_in_flight: 2,
            ..RangeConfig::default()
        });
        s2.plan(now, 0, h(0), &ps);
        s2.on_headers(&pid("a"), &headers(1, 200));
        s2.plan(now, 0, h(0), &ps);
        let stranger = BlockLink {
            height: 32,
            hash: Hash::new([0x61; 32]),
            parent: Hash::new([0x60; 32]),
        };
        let its_child = BlockLink {
            height: 33,
            hash: Hash::new([0x62; 32]),
            parent: stranger.hash,
        };
        assert_eq!(
            s2.on_blocks(
                &pid("a"),
                Some(32),
                &[chain(32, 32)[0], stranger, its_child]
            ),
            BlocksMatch::Range {
                start: 32,
                end: 63,
                delivered_through: 32
            }
        );
    }

    /// Headers whose hashes are blocks at other heights: the first block
    /// answer that carries such an anchor at its real height drops every
    /// anchor from that source, reports it, and the next header request goes
    /// to another peer.
    #[test]
    fn an_answer_carrying_the_anchor_at_another_height_drops_that_sources_anchors() {
        let mut s = RangeScheduler::new(RangeConfig::default());
        let now = Instant::now();
        let ps = peers(&["liar", "a"], 10_000);
        s.plan(now, 0, h(0), &ps);
        let lies: Vec<(u64, Hash)> = (1..=512).map(|n| (n, h(n + 100))).collect();
        s.on_headers(&pid("liar"), &lies);
        assert_eq!(s.anchor_count(), 512);
        let b = blocks_of(&s.plan(now, 0, h(0), &ps).requests);
        let (peer, _, start, _) = b
            .iter()
            .find(|(_, a, st, _)| a == st)
            .cloned()
            .expect("a header-anchored range");
        // The server resolved the anchor to its real height and served from
        // there.
        let m = s.on_blocks(&peer, Some(start + 100), &chain(start + 100, start + 131));
        assert_eq!(m, BlocksMatch::Unsolicited);
        assert_eq!(s.counters().wrong_anchors, 1);
        assert_eq!(s.anchor_count(), 0, "every anchor from the liar dropped");
        let plan = s.plan(now, 0, h(0), &ps);
        assert_eq!(plan.misbehaved, vec![pid("liar")]);
        // The range is free again, and headers come from someone else.
        let headers_to: Vec<PeerId> = plan
            .requests
            .iter()
            .filter_map(|r| match r {
                SyncRequest::Headers { peer, .. } => Some(peer.clone()),
                _ => None,
            })
            .collect();
        assert!(!headers_to.contains(&pid("liar")));
        assert_eq!(s.counters().duplicate_requests, 0);
    }

    /// A range that fails on two peers (here a timeout and an empty answer)
    /// drops its anchor, so the first range falls back to the applied tip.
    #[test]
    fn a_range_failing_on_two_peers_drops_its_anchor_and_falls_back_to_the_tip() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 1,
            request_timeout: Duration::from_secs(5),
            ..RangeConfig::default()
        });
        let t0 = Instant::now();
        let ps = peers(&["a", "b", "c"], 10_000);
        // Applied at 10; anchors from 11 up name blocks nobody has.
        s.plan(t0, 10, h(10), &ps);
        s.in_flight.clear();
        let bogus: Vec<(u64, Hash)> = (11..=200).map(|n| (n, Hash::new([n as u8; 32]))).collect();
        s.on_headers(&pid("a"), &bogus);
        let p = blocks_of(&s.plan(t0, 10, h(10), &ps).requests);
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].1, p[0].2), (11, 11), "anchored on the header");
        // First peer times out.
        let t1 = t0 + Duration::from_secs(6);
        let p = blocks_of(&s.plan(t1, 10, h(10), &ps).requests);
        assert_eq!((p[0].1, p[0].2), (11, 11));
        // Second peer answers empty: two peers failed it.
        s.on_blocks(&p[0].0, None, &[]);
        assert_eq!(s.counters().anchor_evictions, 1);
        let p = blocks_of(&s.plan(t1, 10, h(10), &ps).requests);
        assert_eq!((p[0].1, p[0].2), (10, 11), "falls back to the applied tip");
    }

    /// A header answer with nothing new is not followed by another header
    /// request until the backoff has passed.
    #[test]
    fn header_requests_back_off_after_an_answer_with_nothing_new() {
        let cfg = RangeConfig::default();
        let mut s = RangeScheduler::new(cfg.clone());
        let t0 = Instant::now();
        let ps = peers(&["a", "b"], 10_000);
        let count_headers = |plan: &Plan| {
            plan.requests
                .iter()
                .filter(|r| matches!(r, SyncRequest::Headers { .. }))
                .count()
        };
        let p = s.plan(t0, 0, h(0), &ps);
        assert_eq!(count_headers(&p), 1);
        s.on_headers_at(&pid("a"), &[], t0);
        let soon = t0 + cfg.header_backoff / 2;
        assert_eq!(count_headers(&s.plan(soon, 0, h(0), &ps)), 0);
        let later = t0 + cfg.header_backoff + Duration::from_millis(1);
        assert_eq!(count_headers(&s.plan(later, 0, h(0), &ps)), 1);
        assert_eq!(s.counters().header_requests, 2);
    }

    /// When delivered blocks never apply, the deliverer of the front range is
    /// reported and that range goes to another peer.
    #[test]
    fn a_stalled_front_range_reports_its_deliverer_and_moves() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 1,
            stall_timeout: Duration::from_secs(30),
            ..RangeConfig::default()
        });
        let t0 = Instant::now();
        let ps = peers(&["a", "b"], 10_000);
        s.plan(t0, 0, h(0), &ps);
        s.on_blocks(&pid("a"), Some(0), &chain(0, 31));
        let plan = s.plan(t0 + Duration::from_secs(31), 0, h(0), &ps);
        assert_eq!(plan.misbehaved, vec![pid("a")]);
        assert_eq!(blocks_of(&plan.requests), vec![(pid("b"), 0, 1, 31)]);
        assert!(pending_misbehaved(&mut s, t0 + Duration::from_secs(31), &ps).is_empty());
    }

    /// Admission refusing a delivered range frees it for another peer.
    #[test]
    fn a_refused_delivery_is_asked_of_another_peer() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 1,
            ..RangeConfig::default()
        });
        let now = Instant::now();
        let ps = peers(&["a", "b"], 10_000);
        s.plan(now, 0, h(0), &ps);
        s.on_blocks(&pid("a"), Some(0), &chain(0, 31));
        assert!(blocks_of(&s.plan(now, 0, h(0), &ps).requests).is_empty());
        // Another peer's refusal report does not touch a's delivery.
        s.on_rejected(&pid("b"), 1, 31);
        assert_eq!(s.counters().rejected_ranges, 0);
        s.on_rejected(&pid("a"), 1, 31);
        assert_eq!(s.counters().rejected_ranges, 1);
        let plan = s.plan(now, 0, h(0), &ps);
        assert_eq!(plan.misbehaved, vec![pid("a")]);
        assert_eq!(blocks_of(&plan.requests), vec![(pid("b"), 0, 1, 31)]);
    }

    /// A delivery dropped before admission is asked again, of the same peer
    /// if it is still the best, with nothing charged.
    #[test]
    fn a_dropped_delivery_is_asked_again_without_a_charge() {
        let mut s = RangeScheduler::new(RangeConfig {
            max_in_flight: 1,
            ..RangeConfig::default()
        });
        let now = Instant::now();
        let ps = peers(&["a", "b"], 10_000);
        s.plan(now, 0, h(0), &ps);
        s.on_blocks(&pid("a"), Some(0), &chain(0, 31));
        assert!(blocks_of(&s.plan(now, 0, h(0), &ps).requests).is_empty());
        s.on_dropped(&pid("a"), 1, 31);
        let plan = s.plan(now, 0, h(0), &ps);
        assert!(plan.misbehaved.is_empty());
        assert_eq!(blocks_of(&plan.requests), vec![(pid("a"), 0, 1, 31)]);
    }

    /// Once every eligible peer has failed a range it is held back, the hold
    /// doubles each round up to the cap, and nothing above it is planned
    /// meanwhile. A delivery clears it.
    #[test]
    fn a_range_every_peer_failed_backs_off_doubling_to_the_cap() {
        let cfg = RangeConfig::default();
        let mut s = RangeScheduler::new(cfg.clone());
        let t0 = Instant::now();
        let ps = peers(&["a", "b"], 10_000);
        let ms = |n: u64| t0 + Duration::from_millis(n);
        // Both peers answer the tip-anchored range with nothing.
        let p = blocks_of(&s.plan(t0, 0, h(0), &ps).requests);
        assert_eq!(p, vec![(pid("a"), 0, 1, 31)]);
        s.on_blocks(&pid("a"), None, &[]);
        let p = blocks_of(&s.plan(t0, 0, h(0), &ps).requests);
        assert_eq!(p, vec![(pid("b"), 0, 1, 31)]);
        s.on_blocks(&pid("b"), None, &[]);
        // Everyone failed it: held for retry_backoff, then asked once.
        let mut at = 0u64;
        let mut hold = cfg.retry_backoff.as_millis() as u64;
        let cap = cfg.retry_backoff_max.as_millis() as u64;
        for round in 0..8 {
            assert!(
                blocks_of(&s.plan(ms(at), 0, h(0), &ps).requests).is_empty(),
                "round {round}: asked again without a hold"
            );
            assert!(blocks_of(&s.plan(ms(at + hold - 1), 0, h(0), &ps).requests).is_empty());
            let p = blocks_of(&s.plan(ms(at + hold), 0, h(0), &ps).requests);
            assert_eq!(p.len(), 1, "round {round}: one request after the hold");
            s.on_blocks(&p[0].0, None, &[]);
            at += hold;
            hold = (hold * 2).min(cap);
        }
        assert_eq!(hold, cap);
        assert_eq!(s.counters().backoffs, 8);
        // A delivery clears the hold.
        assert!(blocks_of(&s.plan(ms(at), 0, h(0), &ps).requests).is_empty());
        let p = blocks_of(&s.plan(ms(at + cap), 0, h(0), &ps).requests);
        s.on_blocks(&p[0].0, Some(0), &chain(0, 31));
        assert!(!s.retry.contains_key(&1));
    }

    /// Only the range everyone failed is held: a range another peer has not
    /// tried yet is reassigned at once.
    #[test]
    fn a_range_with_an_untried_peer_is_reassigned_without_a_hold() {
        let mut s = RangeScheduler::new(RangeConfig::default());
        let now = Instant::now();
        let ps = peers(&["a", "b", "c"], 10_000);
        s.plan(now, 0, h(0), &ps);
        s.on_blocks(&pid("a"), None, &[]);
        let p = blocks_of(&s.plan(now, 0, h(0), &ps).requests);
        assert_eq!(p.first().map(|r| r.0.clone()), Some(pid("b")));
        assert_eq!(s.counters().backoffs, 0);
    }
}
