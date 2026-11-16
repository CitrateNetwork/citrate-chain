// citrate/core/network/src/inbound.rs

//! Admission and accounting for inbound messages at
//! [`crate::PeerManager::forward_incoming`].
//!
//! The node drains every peer's messages through one bounded queue, which
//! sheds when full (#149). A shed used to bump one total and nothing else, so
//! it was invisible in logs and said nothing about WHAT was shed. Each shed is
//! now counted by message type and warned about at most once per
//! [`DROP_LOG_WINDOW`], with the number of drops not logged since the last line.
//!
//! Under serving load (r1006, 2026-11-01: one node serving catch-up to six)
//! the queue filled with peers' `GetBlocks`, and the messages that keep the
//! node itself on the chain were shed with them: block gossip, and the answers
//! to its own sync requests (so those timed out and it dropped the peers that
//! answered). [`reserved_lane`] keeps them apart: the last
//! [`RESERVED_SHARE_DIVISOR`]th of the queue is held for `NewBlock` and for
//! `Blocks`/`Headers` answers; everything else is shed once only that part is
//! free.
//!
//! There is deliberately no per-peer rate limit on serve requests here. A
//! request shed without an answer stalls the requester's missing-parent walk
//! (answer-paced: one unanswered step gives up the episode and holds the slot
//! for the 30 s request timeout), which kept partitions from healing in the
//! split-heal harness. Any future limit must answer, not vanish; the harness
//! routes every message through `forward_incoming` so a silent drop fails it.
//!
//! ADR CV-6 (planset H3): when the node sets a serve sink, serve requests
//! ([`serve_request`]) never enter that queue at all. They go to their own
//! lane, answered off the consensus loop under [`ServeQueue`]'s budgets, and
//! what that lane sheds is counted apart from the consensus queue's drops
//! (the stall detector reads only the latter).

use crate::{NetworkMessage, PeerId};
use dashmap::DashMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tracing::warn;

/// At most one drop warning per window; the rest are counted in the next line.
pub const DROP_LOG_WINDOW: Duration = Duration::from_secs(10);

/// The reserved part of the inbound queue is its capacity divided by this.
pub const RESERVED_SHARE_DIVISOR: usize = 8;

/// Messages that may use the reserved part of the inbound queue: block gossip
/// and answers to this node's own sync requests (bounded by its in-flight cap).
pub fn reserved_lane(message: &NetworkMessage) -> bool {
    matches!(
        message,
        NetworkMessage::NewBlock { .. }
            | NetworkMessage::Blocks { .. }
            | NetworkMessage::Headers { .. }
    )
}

/// Peer requests the node answers from storage: they go to the serving lane
/// (ADR CV-6) when one is set, never to the consensus queue.
pub fn serve_request(message: &NetworkMessage) -> bool {
    matches!(
        message,
        NetworkMessage::GetBlocks { .. } | NetworkMessage::GetHeaders { .. }
    )
}

/// Depth of the serve lane between `forward_incoming` and the serving task.
/// The task drains it into a [`ServeQueue`] as fast as requests arrive, so it
/// fills only while that queue is at [`SERVE_PENDING_GLOBAL`].
pub const SERVE_LANE_CAPACITY: usize = 1024;

/// Serve requests one peer may have waiting (besides the one being answered).
/// An honest requester keeps a handful outstanding (the sync tick's pending
/// gate, the missing-parent walk's in-flight cap); a burst of 200 from one
/// walker must still be answered in full (`rcseal_a_burst_...`).
pub const SERVE_PENDING_PER_PEER: usize = 256;

/// Serve requests waiting across all peers.
pub const SERVE_PENDING_GLOBAL: usize = 4096;

/// Whether [`ServeQueue::push`] took a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeAdmit {
    /// Waiting its turn.
    Queued,
    /// The peer already has its cap of requests waiting.
    PeerFull,
    /// The queue holds its global cap.
    GlobalFull,
}

/// The serving plane's budgets: per-peer FIFO queues served round-robin, one
/// request per peer being answered at a time, a cap on what one peer and what
/// all peers may have waiting. Over-budget requests wait; nothing here drops a
/// request it took.
#[derive(Debug)]
pub struct ServeQueue<R> {
    per_peer: usize,
    global: usize,
    waiting: HashMap<PeerId, VecDeque<R>>,
    /// Peers with waiting requests and none being answered, in turn order.
    ready: VecDeque<PeerId>,
    /// Peers with a request being answered.
    answering: HashSet<PeerId>,
    pending: usize,
}

impl<R> ServeQueue<R> {
    pub fn new(per_peer: usize, global: usize) -> Self {
        Self {
            per_peer,
            global,
            waiting: HashMap::new(),
            ready: VecDeque::new(),
            answering: HashSet::new(),
            pending: 0,
        }
    }

    /// Queue `request` from `peer` behind that peer's earlier ones.
    pub fn push(&mut self, peer: PeerId, request: R) -> ServeAdmit {
        if self.pending >= self.global {
            return ServeAdmit::GlobalFull;
        }
        let q = self.waiting.entry(peer.clone()).or_default();
        if q.len() >= self.per_peer {
            return ServeAdmit::PeerFull;
        }
        let was_idle = q.is_empty();
        q.push_back(request);
        self.pending = self.pending.saturating_add(1);
        if was_idle && !self.answering.contains(&peer) {
            self.ready.push_back(peer);
        }
        ServeAdmit::Queued
    }

    /// The next request to answer: the oldest request of the peer whose turn
    /// it is. That peer is then "being answered" until [`Self::done`].
    pub fn take_next(&mut self) -> Option<(PeerId, R)> {
        while let Some(peer) = self.ready.pop_front() {
            let Some(q) = self.waiting.get_mut(&peer) else {
                continue;
            };
            let Some(request) = q.pop_front() else {
                self.waiting.remove(&peer);
                continue;
            };
            if q.is_empty() {
                self.waiting.remove(&peer);
            }
            self.pending = self.pending.saturating_sub(1);
            self.answering.insert(peer.clone());
            return Some((peer, request));
        }
        None
    }

    /// `peer`'s request has been answered; its next one (if any) takes a turn
    /// at the back of the line.
    pub fn done(&mut self, peer: &PeerId) {
        if self.answering.remove(peer) && self.waiting.contains_key(peer) {
            self.ready.push_back(peer.clone());
        }
    }

    /// Requests waiting (not counting those being answered).
    pub fn pending(&self) -> usize {
        self.pending
    }

    /// Whether the queue holds its global cap.
    pub fn is_full(&self) -> bool {
        self.pending >= self.global
    }
}

/// Rate limiter for drop warnings: one line per window, reporting the drops it
/// did not log since the previous line.
#[derive(Debug)]
pub struct DropLog {
    window: Duration,
    last_line: Option<Instant>,
    suppressed: u64,
}

impl DropLog {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            last_line: None,
            suppressed: 0,
        }
    }

    /// One drop at `now`. `Some(n)`: write a line now; `n` drops were not
    /// logged since the previous line. `None`: counted, not logged.
    pub fn admit(&mut self, now: Instant) -> Option<u64> {
        let due = self
            .last_line
            .is_none_or(|t| now.saturating_duration_since(t) >= self.window);
        if due {
            self.last_line = Some(now);
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            None
        }
    }
}

/// Per-type drop counters plus the rate-limited warning.
#[derive(Debug)]
pub struct InboundDrops {
    by_kind: DashMap<&'static str, u64>,
    log: parking_lot::Mutex<DropLog>,
    /// Why these messages are shed, as the warning states it.
    reason: &'static str,
}

impl Default for InboundDrops {
    fn default() -> Self {
        Self::with_reason("inbound queue full")
    }
}

impl InboundDrops {
    /// Counters whose warning gives `reason` for the drops.
    pub fn with_reason(reason: &'static str) -> Self {
        Self {
            by_kind: DashMap::new(),
            log: parking_lot::Mutex::new(DropLog::new(DROP_LOG_WINDOW)),
            reason,
        }
    }

    /// Count one shed message of type `kind` from `peer` and, at most once per
    /// [`DROP_LOG_WINDOW`], warn. Returns whether a line was written.
    pub fn record(&self, kind: &'static str, peer: &PeerId, now: Instant) -> bool {
        {
            let mut n = self.by_kind.entry(kind).or_insert(0);
            *n = n.saturating_add(1);
        }
        let Some(suppressed) = self.log.lock().admit(now) else {
            return false;
        };
        warn!(
            "{}, message dropped: type={} peer={} \
             ({} more dropped since the last report; totals: {})",
            self.reason,
            kind,
            peer.0.get(..14).unwrap_or(&peer.0),
            suppressed,
            self.summary()
        );
        true
    }

    /// Every counter as `(message type, drops)`, sorted by type.
    pub fn by_kind(&self) -> Vec<(&'static str, u64)> {
        let mut rows: Vec<(&'static str, u64)> = self
            .by_kind
            .iter()
            .map(|e| (*e.key(), *e.value()))
            .collect();
        rows.sort_unstable();
        rows
    }

    fn summary(&self) -> String {
        self.by_kind()
            .iter()
            .map(|(k, n)| format!("{k}={n}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RED. The drop warning is rate-limited: the first drop writes a line,
    /// drops inside the window are only counted, and the next line reports how
    /// many were not logged.
    #[test]
    fn drop_warnings_are_rate_limited_and_report_what_they_skipped() {
        let t0 = Instant::now();
        let mut log = DropLog::new(Duration::from_secs(10));
        assert_eq!(log.admit(t0), Some(0), "the first drop is logged");
        for i in 1..=5 {
            assert_eq!(
                log.admit(t0 + Duration::from_millis(i * 100)),
                None,
                "a drop inside the window is counted, not logged"
            );
        }
        assert_eq!(
            log.admit(t0 + Duration::from_secs(11)),
            Some(5),
            "the next line reports the five drops it did not log"
        );
    }

    /// RED. A flood of drops writes one line per window while every drop is
    /// still counted under its type.
    #[test]
    fn a_drop_flood_is_counted_in_full_but_logged_once_per_window() {
        let drops = InboundDrops::default();
        let peer = PeerId::new("flooder".to_string());
        let t0 = Instant::now();
        let lines = (0..1_000u64)
            .filter(|i| drops.record("GetBlocks", &peer, t0 + Duration::from_millis(*i)))
            .count();
        assert_eq!(lines, 1, "one warning inside a 10 s window");
        assert!(drops.record("NewBlock", &peer, t0 + DROP_LOG_WINDOW));
        assert_eq!(drops.by_kind(), vec![("GetBlocks", 1_000), ("NewBlock", 1)]);
    }

    fn p(name: &str) -> PeerId {
        PeerId::new(name.to_string())
    }

    /// Peers take turns: one request each per round, oldest first, and a peer
    /// with a request being answered waits until it is done.
    #[test]
    fn serve_queue_serves_peers_round_robin_one_at_a_time() {
        let mut q = ServeQueue::new(8, 64);
        for i in 0..3 {
            assert_eq!(q.push(p("a"), ("a", i)), ServeAdmit::Queued);
        }
        assert_eq!(q.push(p("b"), ("b", 0)), ServeAdmit::Queued);
        let (pa, ra) = q.take_next().expect("a first");
        assert_eq!(ra, ("a", 0));
        let (pb, rb) = q.take_next().expect("then b");
        assert_eq!(rb, ("b", 0));
        assert!(q.take_next().is_none(), "a is still being answered");
        q.done(&pa);
        q.done(&pb);
        assert_eq!(q.take_next().map(|(_, r)| r), Some(("a", 1)));
        assert!(q.take_next().is_none(), "b has nothing waiting");
        assert_eq!(q.pending(), 1);
    }

    /// The caps: one peer cannot hold more than its share waiting, and the
    /// queue as a whole holds at most its global cap. Neither drops anything
    /// it already took.
    #[test]
    fn serve_queue_enforces_per_peer_and_global_caps() {
        let mut q = ServeQueue::new(2, 3);
        assert_eq!(q.push(p("a"), 0), ServeAdmit::Queued);
        assert_eq!(q.push(p("a"), 1), ServeAdmit::Queued);
        assert_eq!(q.push(p("a"), 2), ServeAdmit::PeerFull);
        assert_eq!(q.push(p("b"), 3), ServeAdmit::Queued);
        assert!(q.is_full());
        assert_eq!(q.push(p("c"), 4), ServeAdmit::GlobalFull);
        let mut got = Vec::new();
        while let Some((peer, r)) = q.take_next() {
            got.push(r);
            q.done(&peer);
        }
        got.sort_unstable();
        assert_eq!(got, vec![0, 1, 3]);
    }

    /// d3562a36: a 200-request burst from one walker must be answered in full;
    /// the per-peer cap sits above it.
    #[test]
    fn serve_queue_takes_a_200_request_burst_from_one_peer() {
        let mut q = ServeQueue::new(SERVE_PENDING_PER_PEER, SERVE_PENDING_GLOBAL);
        for i in 0..200 {
            assert_eq!(q.push(p("walker"), i), ServeAdmit::Queued);
        }
        let mut order = Vec::new();
        while let Some((peer, r)) = q.take_next() {
            order.push(r);
            q.done(&peer);
        }
        assert_eq!(order, (0..200).collect::<Vec<_>>(), "answered in order");
    }
}
