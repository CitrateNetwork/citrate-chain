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
//! answered). Two rules keep them apart:
//! - [`reserved_lane`]: the last [`RESERVED_SHARE_DIVISOR`]th of the queue is
//!   held for `NewBlock` and for `Blocks`/`Headers` answers; everything else
//!   is shed once only that part is free.
//! - [`ServeBudget`]: each peer's serve requests (`GetBlocks`, `GetHeaders`,
//!   `GetBlocksByHeight`) pass at most [`SERVE_REQUEST_BURST`] at once and
//!   [`SERVE_REQUESTS_PER_SEC`] a second after that. Each costs the single
//!   message loop a storage read of up to a full response; an honest peer asks
//!   a few per 2 s sync tick.

use crate::{NetworkMessage, PeerId};
use dashmap::DashMap;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::warn;

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

/// Requests whose answer the node serves from storage on its message loop.
pub fn serve_request(message: &NetworkMessage) -> bool {
    matches!(
        message,
        NetworkMessage::GetBlocks { .. }
            | NetworkMessage::GetHeaders { .. }
            | NetworkMessage::GetBlocksByHeight { .. }
    )
}

/// Serve requests a peer may send at once.
pub const SERVE_REQUEST_BURST: u64 = 16;
/// Serve requests a peer may send per second after its burst.
pub const SERVE_REQUESTS_PER_SEC: u64 = 4;
/// Peers tracked by [`ServeBudget`]; past it the longest-idle one is forgotten.
/// A peer's bucket outlives its connection, so reconnecting does not refill it.
const SERVE_BUDGET_PEERS: usize = 1024;
/// Budget units per request (so refill can be counted in milliseconds).
const UNITS_PER_REQUEST: u64 = 1000;

/// Per-peer token bucket over serve requests.
#[derive(Debug, Default)]
pub struct ServeBudget {
    /// `peer -> (units left, last refill)`.
    buckets: parking_lot::Mutex<HashMap<PeerId, (u64, Instant)>>,
}

impl ServeBudget {
    /// Whether `peer` may send one more serve request at `now` (and spend it).
    pub fn allow(&self, peer: &PeerId, now: Instant) -> bool {
        let full = SERVE_REQUEST_BURST.saturating_mul(UNITS_PER_REQUEST);
        let mut buckets = self.buckets.lock();
        if !buckets.contains_key(peer) && buckets.len() >= SERVE_BUDGET_PEERS {
            if let Some(idle) = buckets
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(p, _)| p.clone())
            {
                buckets.remove(&idle);
            }
        }
        let (units, at) = buckets.entry(peer.clone()).or_insert((full, now));
        let elapsed_ms =
            u64::try_from(now.saturating_duration_since(*at).as_millis()).unwrap_or(u64::MAX);
        *units = units
            .saturating_add(elapsed_ms.saturating_mul(SERVE_REQUESTS_PER_SEC))
            .min(full);
        *at = now;
        if *units >= UNITS_PER_REQUEST {
            *units = units.saturating_sub(UNITS_PER_REQUEST);
            true
        } else {
            false
        }
    }
}

/// At most one drop warning per window; the rest are counted in the next line.
pub const DROP_LOG_WINDOW: Duration = Duration::from_secs(10);

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
    /// Counters whose warning gives `reason` for the drop.
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

    /// The serve budget: a burst of 16, then 4 a second, per peer; an idle
    /// peer refills to the burst and no further.
    #[test]
    fn serve_budget_is_a_per_peer_bucket() {
        let budget = ServeBudget::default();
        let a = PeerId::new("a".to_string());
        let b = PeerId::new("b".to_string());
        let t0 = Instant::now();
        let burst = (0..100).filter(|_| budget.allow(&a, t0)).count();
        assert_eq!(burst, 16, "a burst of 16");
        assert!(budget.allow(&b, t0), "another peer has its own budget");
        let t1 = t0 + Duration::from_secs(1);
        let refill = (0..100).filter(|_| budget.allow(&a, t1)).count();
        assert_eq!(refill, 4, "4 a second after the burst");
        let t2 = t1 + Duration::from_secs(3600);
        let after_idle = (0..100).filter(|_| budget.allow(&a, t2)).count();
        assert_eq!(after_idle, 16, "refills to the burst, not beyond");
    }
}
