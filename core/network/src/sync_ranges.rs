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
}

#[derive(Debug, Clone)]
struct InFlight {
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
    /// start -> end, validated and handed to admission, not yet applied.
    delivered: BTreeMap<u64, u64>,
    /// start -> peers that failed that range.
    avoid: HashMap<u64, Vec<PeerId>>,
    /// Ranges requested at least once (for the retry counter).
    requested_once: BTreeSet<u64>,
    header_req: Option<HeaderReq>,
    header_avoid: Vec<PeerId>,
    counters: RangeCounters,
}

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
            requested_once: BTreeSet::new(),
            header_req: None,
            header_avoid: Vec::new(),
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
            .filter(|(_, end)| *end > applied)
            .map(|(start, end)| (start.max(keep_from), end))
            .collect();
        self.avoid.retain(|start, _| *start > applied);
        self.requested_once = self.requested_once.split_off(&keep_from);
        // In-flight ranges below the tip are left to resolve (or time out) on
        // their own: their answer is harmless and dropping them here would
        // re-open the same heights to a second request.
    }

    /// True when `height` is in flight or delivered.
    fn covered(&self, height: u64) -> Option<u64> {
        // The range containing `height`, if any, returns its end.
        let hit = |m: &BTreeMap<u64, u64>| {
            m.range(..=height)
                .next_back()
                .and_then(|(_, end)| (*end >= height).then_some(*end))
        };
        if let Some(end) = hit(&self.delivered) {
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
                self.avoid.entry(start).or_default().push(r.peer.clone());
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
                    self.delivered.clear();
                    self.anchors.clear();
                    self.counters.stall_resets = self.counters.stall_resets.saturating_add(1);
                    self.last_progress = Some(now);
                }
            }
        }

        // Header anchors, one request at a time, kept `lookahead` ahead.
        if self.header_req.is_none() {
            let frontier = self.anchor_frontier();
            if frontier < self.window_top() {
                let from = if frontier == self.applied {
                    Some(applied_hash)
                } else {
                    self.anchors.get(&frontier).map(|(h, _)| *h)
                };
                let eligible = |p: &&PeerSlot, avoid: &[PeerId]| {
                    p.head_height > frontier && !avoid.contains(&p.id)
                };
                let mut pick = peers.iter().find(|p| eligible(p, &self.header_avoid));
                if pick.is_none() && !self.header_avoid.is_empty() {
                    self.header_avoid.clear();
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
                    break;
                }
            }
            let Some(peer) = pick else { break };

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
        plan
    }

    /// A `Headers` response from `peer`, as `(height, hash)` ascending.
    pub fn on_headers(&mut self, peer: &PeerId, headers: &[(u64, Hash)]) {
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
            // First writer wins; a bad anchor is evicted by `on_blocks`.
            self.anchors.entry(*height).or_insert_with(|| {
                added = added.saturating_add(1);
                (*hash, peer.clone())
            });
        }
        if added == 0 {
            self.header_avoid.push(peer.clone());
        } else {
            self.header_avoid.retain(|p| p != peer);
        }
    }

    /// A `Blocks` response from `peer`. `first_height` is the height of the
    /// first block in the response as received (before validation);
    /// `validated` the heights of the blocks that passed validation.
    pub fn on_blocks(
        &mut self,
        peer: &PeerId,
        first_height: Option<u64>,
        validated: &[u64],
    ) -> BlocksMatch {
        let start = match first_height {
            // An empty answer carries no height; servers answer in order, so
            // it answers the oldest range in flight to this peer.
            None => self
                .in_flight
                .iter()
                .filter(|(_, r)| r.peer == *peer)
                .min_by_key(|(_, r)| r.sent_at)
                .map(|(s, _)| *s),
            Some(first) => self
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
        let have: BTreeSet<u64> = validated.iter().copied().collect();
        let mut through = start.saturating_sub(1);
        while have.contains(&through.saturating_add(1)) && through < req.end {
            through = through.saturating_add(1);
        }
        if through >= start {
            self.delivered.insert(start, through);
            if through < req.end {
                self.counters.short_responses = self.counters.short_responses.saturating_add(1);
            }
        } else {
            self.counters.empty_responses = self.counters.empty_responses.saturating_add(1);
            let failed = self.avoid.entry(start).or_default();
            failed.push(peer.clone());
            // Two different peers could not serve this anchor: it may be a
            // hash nobody else holds. Forget anchors from here up so they are
            // fetched again, preferably from someone else.
            let distinct: BTreeSet<&str> = failed.iter().map(|p| p.0.as_str()).collect();
            if distinct.len() >= 2 {
                if let Some((_, src)) = self.anchors.get(&start) {
                    let src = src.clone();
                    if !self.header_avoid.contains(&src) {
                        self.header_avoid.push(src);
                    }
                }
                let _ = self.anchors.split_off(&start);
            }
        }
        BlocksMatch::Range {
            start,
            end: req.end,
            delivered_through: through,
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
            self.avoid.entry(s).or_default().push(peer.clone());
        }
        if self.header_req.as_ref().is_some_and(|h| h.peer == *peer) {
            self.header_req = None;
            self.header_avoid.push(peer.clone());
        }
    }
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
        let m = s.on_blocks(&pid("a"), Some(90), &(91..=121).collect::<Vec<_>>());
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
        s.plan(now, 0, Hash::default(), &ps);
        s.on_headers(&pid("bad"), &headers(1, 512));
        s.plan(now, 0, Hash::default(), &ps);
        assert_eq!(s.in_flight_to(&pid("bad")), 1);
        assert_eq!(
            s.in_flight_to(&pid("good")),
            RangeConfig::default().max_in_flight_per_peer
        );
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
        s.plan(now, 0, Hash::default(), &ps);
        s.on_headers(&pid("a"), &headers(1, 512));
        let plan = s.plan(now, 0, Hash::default(), &ps);
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
        let p1 = blocks_of(&s.plan(now, 0, Hash::default(), &ps).requests);
        assert_eq!(p1[0].0, pid("bad"));
        assert_eq!(
            s.on_blocks(&pid("bad"), None, &[]),
            BlocksMatch::Range {
                start: 1,
                end: 31,
                delivered_through: 0
            }
        );
        let p2 = blocks_of(&s.plan(now, 0, Hash::default(), &ps).requests);
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
        s.plan(t0, 0, Hash::default(), &ps);
        let later = t0 + Duration::from_secs(6);
        let plan = s.plan(later, 0, Hash::default(), &ps);
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
            s.on_blocks(&pid("slow"), Some(0), &(1..=31).collect::<Vec<_>>()),
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
        s.plan(now, 0, Hash::default(), &ps);
        s.on_headers(&pid("a"), &headers(1, 200));
        // Answer covers 1..=10 of 1..=31.
        let m = s.on_blocks(&pid("a"), Some(0), &(1..=10).collect::<Vec<_>>());
        assert_eq!(
            m,
            BlocksMatch::Range {
                start: 1,
                end: 31,
                delivered_through: 10
            }
        );
        let b = blocks_of(&s.plan(now, 0, Hash::default(), &ps).requests);
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
        s.plan(now, 0, Hash::default(), &ps);
        s.on_headers(&pid("a"), &headers(1, 200));
        s.plan(now, 0, Hash::default(), &ps); // 1..=31 (a), 32..=63 (b)
                                              // a answers 1..=20 only.
        s.on_blocks(&pid("a"), Some(0), &(1..=20).collect::<Vec<_>>());
        let reqs = s.plan(now, 0, Hash::default(), &ps).requests;
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
        s.plan(now, 0, Hash::default(), &ps);
        s.on_headers(&pid("low"), &headers(1, 40));
        let plan = s.plan(now, 0, Hash::default(), &ps);
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
            s.plan(now, 0, Hash::default(), &ps);
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
        s.plan(t0, 0, Hash::default(), &ps);
        s.on_blocks(&pid("a"), Some(0), &(1..=31).collect::<Vec<_>>());
        // Applied tip never moves: after the stall timeout 1..=31 is asked again.
        let b = blocks_of(
            &s.plan(t0 + Duration::from_secs(31), 0, Hash::default(), &ps)
                .requests,
        );
        assert_eq!(b, vec![(pid("a"), 0, 1, 31)]);
        assert_eq!(s.counters().stall_resets, 1);
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
                        s.on_blocks(peer, Some(first), &(*start..=*end).collect::<Vec<_>>());
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
                applied = *s.delivered.get(&(applied + 1)).unwrap_or(&applied);
            }
        }
        assert!(applied > 5_000, "applied only {applied}");
        assert_eq!(s.counters().duplicate_requests, 0);
        assert_eq!(s.counters().retries, 0);
    }
}
