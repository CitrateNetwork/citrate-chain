// citrate/core/network/src/sync_pipeline.rs
//
// Pipelined, peer-parallel block download for catch-up sync (#477).
//
// WHY THIS EXISTS
//
// Measured on r1007 (2026-11-14, a member node syncing from genesis with #476
// deployed): 181 answers in 809 s, 173 of them exactly 28 blocks, 21 of those
// new (the anchor's own seven-block height-group came back every time), one
// answer every 3.9 s at p50, and 18 % of the wall time in stalls of over 20 s.
// Validating, admitting and applying one answer took ~40 ms; the node was idle
// over 98 % of the time. The cost was the request cadence: one `GetBlocks` per
// 2 s tick, anchored at the applied tip, to one peer, with a 30 s timeout. A
// cold node closed the gap on the network at about 0.1 heights/s.
//
// THE MODEL
//
// Heights above the applied tip are split into WINDOWS of consecutive heights.
// A window is unassigned or owned by one peer; two in-flight requests never
// cover the same height. Up to `max_in_flight` windows are in flight across
// all peers (at most `max_in_flight_per_peer` to one), lowest window first,
// each to the peer expected to finish it soonest (delivered blocks per second
// over its recent answers, divided by what it already holds). The next window
// is issued when an answer arrives, not on the next 2 s tick; the tick is the
// backstop.
//
// NO WIRE CHANGE. `GetBlocks { from, count }` serves from the height of `from`
// INCLUSIVE, so a window `[lo, hi]` is requested with the hash of a block at
// height `lo - 1` as its anchor. Those hashes come from each peer's own header
// chain (`GetHeaders`, requested only while the peer's header window is short
// of the lookahead), or from the applied tip for the first window, or from a
// block an answer already delivered at that height. A window is only ever
// anchored on a hash that peer itself claimed or that we hold, so a peer that
// lies about its headers only wastes its own windows. Only the first window
// re-sends the requester's own height-group (the applied tip's); every later
// window's anchor group is the top of the window below it, which the requester
// does not hold yet.
//
// ANSWERS ARE ATTRIBUTED BY ORDER. A server answers one peer's requests one at
// a time, in order (`serve_plane`), and since #476 one `Blocks` answer may span
// several messages, sent back to back. So every request sent to a peer — the
// pipeline's, the missing-parent walk's, the legacy tick's, and `GetHeaders` —
// is kept in that peer's FIFO. A `Blocks` message either continues the answer
// being received (it starts at that answer's last height or the next one) or
// starts the answer to a later entry (it starts at that entry's anchor height);
// entries skipped over were shed by the server and are released. The answer
// that is being received ends when the next answer (or a `Headers` reply)
// starts, or when it goes quiet for the peer's timeout.
//
// A window whose answer ended short (a server built before #477 caps a reply
// at 60 KiB, a few heights) keeps its remainder as a new window, and the peer's
// reply capacity is learned so its next windows are sized to what it carries.
//
// OUT-OF-ORDER ANSWERS ARE HELD HERE, NOT IN ADMISSION. Blocks of a window
// above the contiguous FRONTIER (every height from the applied tip up to it has
// been received) wait in a bounded reorder buffer and go to admission once the
// windows below them have arrived. So admission sees blocks in height order,
// its orphan buffer is not re-scanned for every message, and the missing-parent
// walk is not asked for parents that are simply still in flight.
//
// TIMEOUTS ADAPT. A peer's timeout is `clamp(4 x p95 service latency, 3 s,
// 30 s)` (10 s before the first sample), doubled per consecutive timeout. On
// expiry every window the peer held goes back to the pool, the one at its front
// marked as failed by it, and the caller is told so it can charge the peer.
//
// HEADER AGREEMENT. A peer's header chain is checked against the blocks the
// answers deliver: a header at a height whose complete group arrived, and which
// is not in that group, contradicts the peer's chain (it is on another branch
// above that height, or it lies). Its headers from there up are dropped; after
// `max_strikes` in a row it gets no windows for `exclusion` and the windows it
// held are re-planned elsewhere.
//
// A STALL VALVE. If the applied tip does not move for `stall_timeout` while
// blocks are held, the held blocks go to admission as they are (its orphan
// buffer and the missing-parent walk take over) and the plan restarts from the
// applied tip.
//
// SECURITY HOOK. Which peers may be asked at all is the caller's decision
// (`PipelinePeer::admissible`). Never choosing a sync peer far behind us is
// being implemented in a private advisory; it plugs in there.
//
// NOTHING HERE DECIDES VALIDITY. The pipeline only decides what to ask for,
// from whom, and when blocks go to admission. Every block still passes
// `SyncManager::handle_blocks` (hash, signature, tx_root, timestamp) before it
// reaches the pipeline, and admission and execution after it.
//
// Credit: the range-scheduler model (non-overlapping ranges, anchors from
// headers, retry elsewhere) is from #402 (`sync_ranges.rs`, 2026-10-26), which
// predates #476's split replies and the r1007 serving plane.

use crate::peer::PeerId;
use citrate_consensus::types::{Block, Hash};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Tunables for [`BlockPipeline`].
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Block windows in flight across all peers.
    pub max_in_flight: usize,
    /// Block windows in flight to any one peer.
    pub max_in_flight_per_peer: usize,
    /// Blocks asked for per window request (the server's clamp is 512 and its
    /// byte budget bounds the reply).
    pub request_count: u32,
    /// Heights per window.
    pub window_heights: u64,
    /// How far above the applied tip windows and header chains are planned.
    pub lookahead_heights: u64,
    /// Headers asked for per `GetHeaders` (the server's byte budget bounds it).
    pub header_count: u32,
    /// The pipeline runs while the sync target is more than this many heights
    /// above the applied tip. Below it the legacy tick keeps a node at the tip.
    pub engage_gap: u64,
    /// Timeout bounds and the timeout before a peer has any latency sample.
    pub min_timeout: Duration,
    pub max_timeout: Duration,
    pub initial_timeout: Duration,
    /// Applied tip unmoved this long with blocks held: flush and re-plan.
    pub stall_timeout: Duration,
    /// Reorder-buffer byte budget. Over it, only the window at the frontier is
    /// planned.
    pub max_buffered_bytes: usize,
    /// Consecutive header contradictions before a peer is excluded.
    pub max_strikes: u32,
    /// How long an excluded peer gets no windows.
    pub exclusion: Duration,
    /// Wait after an empty `Headers` answer before asking that peer again.
    pub header_backoff: Duration,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 8,
            max_in_flight_per_peer: 4,
            request_count: 512,
            window_heights: 64,
            lookahead_heights: 512,
            header_count: 2048,
            engage_gap: 64,
            min_timeout: Duration::from_secs(3),
            max_timeout: Duration::from_secs(30),
            initial_timeout: Duration::from_secs(10),
            stall_timeout: Duration::from_secs(30),
            max_buffered_bytes: 32 * 1024 * 1024,
            max_strikes: 3,
            exclusion: Duration::from_secs(60),
            header_backoff: Duration::from_secs(2),
        }
    }
}

/// A connected peer as the caller sees it this round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelinePeer {
    pub id: PeerId,
    /// The head it advertises: a necessary condition only (a window starting
    /// above it is never assigned to it).
    pub head_height: u64,
    /// The caller's verdict that this peer may be asked at all (the hook the
    /// far-behind-peer advisory plugs into).
    pub admissible: bool,
}

/// One request the caller should send now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineRequest {
    Blocks {
        peer: PeerId,
        /// Anchor; the server serves from its height inclusive.
        anchor: Hash,
        anchor_height: u64,
        count: u32,
        /// The window this answers.
        lo: u64,
        hi: u64,
    },
    Headers {
        peer: PeerId,
        from: Hash,
        from_height: u64,
        count: u32,
    },
}

impl PipelineRequest {
    pub fn peer(&self) -> &PeerId {
        match self {
            Self::Blocks { peer, .. } | Self::Headers { peer, .. } => peer,
        }
    }
}

/// What a `Blocks` message was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    /// An answer (or part of one) to a pipeline window.
    Window { lo: u64, hi: u64 },
    /// An answer to a `GetBlocks` the pipeline did not plan (missing-parent
    /// walk, legacy tick).
    Other,
    /// Not an answer to anything outstanding to this peer.
    Unsolicited,
}

/// The pipeline's verdict on one `Blocks` message.
#[derive(Debug, Default)]
pub struct BlocksOutcome {
    pub attribution: Option<Attribution>,
    /// Blocks to hand to admission now, height-ascending. For a non-pipeline
    /// message: the message's validated blocks, unchanged.
    pub release: Vec<Block>,
    /// Blocks of this message not seen before by the pipeline.
    pub new_blocks: usize,
}

impl BlocksOutcome {
    pub fn is_pipeline(&self) -> bool {
        matches!(self.attribution, Some(Attribution::Window { .. }))
    }
}

/// What [`BlockPipeline::poll`] found.
#[derive(Debug, Default)]
pub struct PollOutcome {
    /// Peers whose oldest outstanding request went unanswered for their timeout.
    pub timed_out: Vec<PeerId>,
    /// Held blocks released by the stall valve (admit them as usual).
    pub flushed: Vec<Block>,
}

/// Per-peer figures for logs and status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerFigures {
    pub id: PeerId,
    pub in_flight: usize,
    /// Delivered new blocks per second (0 before the first answer).
    pub blocks_per_sec: u64,
    pub timeout_ms: u64,
    pub header_top: u64,
    pub excluded: bool,
}

/// Counters for logs and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipelineStats {
    pub windows_in_flight: usize,
    pub windows_requested: u64,
    pub headers_requested: u64,
    pub timeouts: u64,
    pub reassigned: u64,
    pub contradictions: u64,
    pub stall_flushes: u64,
    /// Window requests sent while another in-flight window covered one of the
    /// same heights. Zero by construction; counted so a test can prove it.
    pub overlapping_requests: u64,
    pub buffered_blocks: usize,
    pub buffered_bytes: usize,
    pub frontier: u64,
    pub delivered_blocks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EntryKind {
    Window {
        lo: u64,
        hi: u64,
        anchor_height: u64,
        count: u32,
    },
    Other {
        anchor_height: u64,
    },
    Headers {
        from: Hash,
        from_height: u64,
    },
}

#[derive(Debug, Clone)]
struct Entry {
    kind: EntryKind,
    sent_at: Instant,
    /// A message of its answer has arrived.
    started: bool,
    /// Highest height its answer carried so far, and the hash of the last
    /// block of its last message (a reply is sorted by height, then hash).
    last_height: u64,
    last_hash: Option<Hash>,
    /// When its answer's service began (sent, or the previous answer ended).
    service_from: Instant,
    blocks: usize,
    new_blocks: usize,
}

impl Entry {
    fn anchor_height(&self) -> Option<u64> {
        match self.kind {
            EntryKind::Window { anchor_height, .. } | EntryKind::Other { anchor_height } => {
                Some(anchor_height)
            }
            EntryKind::Headers { .. } => None,
        }
    }
}

#[derive(Debug)]
struct PeerSlot {
    head_height: u64,
    admissible: bool,
    /// This peer's claimed header chain above the applied tip.
    headers: BTreeMap<u64, Hash>,
    fifo: VecDeque<Entry>,
    /// When the last answer message from this peer arrived.
    last_message_at: Option<Instant>,
    /// Service latency samples (first message of an answer).
    samples: VecDeque<Duration>,
    /// Consecutive timeouts since its last answer.
    backoff: u32,
    /// Delivered new blocks per second x 1000 (EMA); `None` before any answer.
    rate_milli: Option<u64>,
    /// Heights one answer carries, when an answer ended short of its window
    /// for lack of budget (a server built before #477).
    capacity_heights: Option<u64>,
    strikes: u32,
    excluded_until: Option<Instant>,
    header_backoff_until: Option<Instant>,
}

impl PeerSlot {
    fn new() -> Self {
        Self {
            head_height: 0,
            admissible: false,
            headers: BTreeMap::new(),
            fifo: VecDeque::new(),
            last_message_at: None,
            samples: VecDeque::new(),
            backoff: 0,
            rate_milli: None,
            capacity_heights: None,
            strikes: 0,
            excluded_until: None,
            header_backoff_until: None,
        }
    }

    fn windows_in_flight(&self) -> usize {
        self.fifo
            .iter()
            .filter(|e| matches!(e.kind, EntryKind::Window { .. }))
            .count()
    }

    fn headers_in_flight(&self) -> bool {
        self.fifo
            .iter()
            .any(|e| matches!(e.kind, EntryKind::Headers { .. }))
    }

    fn excluded(&self, now: Instant) -> bool {
        self.excluded_until.is_some_and(|t| now < t)
    }

    fn header_top(&self) -> Option<(u64, Hash)> {
        self.headers.iter().next_back().map(|(h, x)| (*h, *x))
    }
}

/// Samples kept per peer for the p95.
const MAX_SAMPLES: usize = 32;
/// Header entries kept per peer.
const MAX_HEADERS_PER_PEER: usize = 4096;
/// Prior delivered-blocks rate for a peer never asked: optimistic, so every
/// peer gets tried.
const PRIOR_RATE_MILLI: u64 = 1_000_000_000;

#[derive(Debug, Clone)]
struct Window {
    hi: u64,
    owner: Option<PeerId>,
    failed: Vec<PeerId>,
    attempts: u32,
    retry_at: Option<Instant>,
}

/// The pipelined downloader. Pure state: no I/O, no clock of its own (every
/// call takes `now`), so it is driven the same way by the node and by tests.
#[derive(Debug)]
pub struct BlockPipeline {
    config: PipelineConfig,
    applied: (Hash, u64),
    target: u64,
    allowed: bool,
    /// Windows by first height.
    windows: BTreeMap<u64, Window>,
    /// Highest height a window has been created for.
    planned_to: u64,
    peers: HashMap<PeerId, PeerSlot>,
    /// Hashes received at each height above the applied tip.
    received: BTreeMap<u64, HashSet<Hash>>,
    /// Every height from the applied tip up to here has been received.
    frontier: u64,
    /// Blocks above the frontier, waiting for the windows below them.
    buffer: BTreeMap<u64, Vec<Block>>,
    buffered_bytes: usize,
    /// Most blocks seen at one height (sizes `count`).
    max_siblings: u64,
    last_progress: Instant,
    stats: PipelineStats,
}

fn block_bytes(b: &Block) -> usize {
    usize::try_from(bincode::serialized_size(b).unwrap_or(u64::MAX)).unwrap_or(usize::MAX)
}

impl BlockPipeline {
    pub fn new(config: PipelineConfig, now: Instant) -> Self {
        Self {
            config,
            applied: (Hash::default(), 0),
            target: 0,
            allowed: true,
            windows: BTreeMap::new(),
            planned_to: 0,
            peers: HashMap::new(),
            received: BTreeMap::new(),
            frontier: 0,
            buffer: BTreeMap::new(),
            buffered_bytes: 0,
            max_siblings: 0,
            last_progress: now,
            stats: PipelineStats::default(),
        }
    }

    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }

    /// Raise the sync target (never lowers it).
    pub fn set_target(&mut self, target: u64) {
        self.target = self.target.max(target);
    }

    /// The node's applied tip. Everything at or below it is forgotten; a tip
    /// that moved down (a reorg) restarts the plan from it.
    pub fn observe_applied(&mut self, applied: (Hash, u64), now: Instant) {
        let (_, old) = self.applied;
        let height = applied.1;
        if height > old {
            self.last_progress = now;
        }
        self.applied = applied;
        if height < old {
            self.restart_plan();
        }
        // Prune what is at or below the tip.
        let keep_above = height.saturating_add(1);
        self.received = self.received.split_off(&keep_above);
        let below: Vec<u64> = self.buffer.range(..keep_above).map(|(h, _)| *h).collect();
        for h in below {
            if let Some(bs) = self.buffer.remove(&h) {
                self.buffered_bytes = self
                    .buffered_bytes
                    .saturating_sub(bs.iter().map(block_bytes).sum());
            }
        }
        for slot in self.peers.values_mut() {
            slot.headers = slot.headers.split_off(&keep_above);
        }
        // Windows wholly at or below the tip are done; an unowned window that
        // straddles it starts above it.
        let mut adjusted: BTreeMap<u64, Window> = BTreeMap::new();
        for (lo, w) in std::mem::take(&mut self.windows) {
            if w.hi <= height {
                continue;
            }
            if lo <= height && w.owner.is_none() {
                adjusted.insert(keep_above, w);
            } else {
                adjusted.insert(lo, w);
            }
        }
        self.windows = adjusted;
        self.planned_to = self.planned_to.max(height);
        self.frontier = self.frontier.max(height);
        self.advance_frontier();
    }

    /// Whether the pipeline is doing the downloading (the legacy tick stands
    /// down while it is).
    pub fn active(&self) -> bool {
        if !self.allowed {
            return false;
        }
        let gap = self.target.saturating_sub(self.applied.1);
        gap > self.config.engage_gap
            || (gap > 0 && (self.in_flight_total() > 0 || !self.buffer.is_empty()))
    }

    pub fn frontier(&self) -> u64 {
        self.frontier
    }

    pub fn stats(&self) -> PipelineStats {
        let mut s = self.stats.clone();
        s.windows_in_flight = self.peers.values().map(PeerSlot::windows_in_flight).sum();
        s.buffered_blocks = self.buffer.values().map(Vec::len).sum();
        s.buffered_bytes = self.buffered_bytes;
        s.frontier = self.frontier;
        s
    }

    pub fn peer_figures(&self, now: Instant) -> Vec<PeerFigures> {
        let mut out: Vec<PeerFigures> = self
            .peers
            .iter()
            .map(|(id, slot)| PeerFigures {
                id: id.clone(),
                in_flight: slot.windows_in_flight(),
                blocks_per_sec: slot.rate_milli.unwrap_or(0).checked_div(1000).unwrap_or(0),
                timeout_ms: u64::try_from(self.timeout_for(slot).as_millis()).unwrap_or(u64::MAX),
                header_top: slot.header_top().map(|(h, _)| h).unwrap_or(0),
                excluded: slot.excluded(now),
            })
            .collect();
        out.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        out
    }

    /// Every height `lo..=hi` that some in-flight window covers (tests).
    pub fn in_flight_windows(&self) -> Vec<(PeerId, u64, u64)> {
        let mut out = Vec::new();
        for (id, slot) in &self.peers {
            for e in &slot.fifo {
                if let EntryKind::Window { lo, hi, .. } = e.kind {
                    out.push((id.clone(), lo, hi));
                }
            }
        }
        out.sort_by_key(|(_, lo, _)| *lo);
        out
    }

    fn timeout_for(&self, slot: &PeerSlot) -> Duration {
        let base = if slot.samples.is_empty() {
            self.config.initial_timeout
        } else {
            let mut v: Vec<Duration> = slot.samples.iter().copied().collect();
            v.sort();
            // p95 index, rounded up, within bounds.
            let n = v.len();
            let idx = n
                .saturating_mul(95)
                .div_ceil(100)
                .saturating_sub(1)
                .min(n.saturating_sub(1));
            let p95 = v.get(idx).copied().unwrap_or(self.config.initial_timeout);
            p95.saturating_mul(4)
                .clamp(self.config.min_timeout, self.config.max_timeout)
        };
        let factor = 1u32.checked_shl(slot.backoff.min(5)).unwrap_or(32);
        base.saturating_mul(factor).min(self.config.max_timeout)
    }

    fn restart_plan(&mut self) {
        self.windows.clear();
        self.received.clear();
        self.planned_to = self.applied.1;
        self.frontier = self.applied.1;
        for slot in self.peers.values_mut() {
            slot.headers.clear();
            // Outstanding window answers are now answers to nothing: keep the
            // entries (order) but stop crediting them to windows.
            for e in slot.fifo.iter_mut() {
                if let EntryKind::Window { anchor_height, .. } = e.kind {
                    e.kind = EntryKind::Other { anchor_height };
                }
            }
        }
    }

    fn release_window(&mut self, lo: u64, failed_by: Option<&PeerId>, now: Instant) {
        if let Some(w) = self.windows.get_mut(&lo) {
            w.owner = None;
            if let Some(p) = failed_by {
                if !w.failed.contains(p) {
                    w.failed.push(p.clone());
                }
                w.attempts = w.attempts.saturating_add(1);
                // From the second failure on, back off (500 ms doubling to 8 s).
                if w.attempts >= 2 {
                    let ms = 500u64
                        .saturating_mul(1u64 << w.attempts.saturating_sub(2).min(4))
                        .min(8_000);
                    w.retry_at = now.checked_add(Duration::from_millis(ms));
                }
            }
            self.stats.reassigned = self.stats.reassigned.saturating_add(1);
        }
    }

    /// Release every window `peer` holds and forget its outstanding requests.
    fn drop_outstanding(&mut self, peer: &PeerId, front_failed: bool, now: Instant) {
        let Some(slot) = self.peers.get_mut(peer) else {
            return;
        };
        let entries: Vec<Entry> = slot.fifo.drain(..).collect();
        // The first window in its queue is the one it failed to answer.
        let mut first = true;
        for e in entries {
            if let EntryKind::Window { lo, .. } = e.kind {
                let failed = front_failed && first;
                self.release_window(lo, failed.then_some(peer), now);
                first = false;
            }
        }
    }

    /// A peer that is gone: its windows go back to the pool.
    pub fn peer_gone(&mut self, peer: &PeerId, now: Instant) {
        self.drop_outstanding(peer, false, now);
        self.peers.remove(peer);
    }

    /// A send to `peer` failed: as if it timed out at once.
    pub fn send_failed(&mut self, peer: &PeerId, now: Instant) {
        self.drop_outstanding(peer, true, now);
        if let Some(slot) = self.peers.get_mut(peer) {
            slot.backoff = slot.backoff.saturating_add(1);
        }
    }

    /// A `GetBlocks` the pipeline did not plan was sent to `peer`.
    pub fn note_other_blocks_request(&mut self, peer: &PeerId, anchor_height: u64, now: Instant) {
        let slot = self.peers.entry(peer.clone()).or_insert_with(PeerSlot::new);
        slot.fifo.push_back(Entry {
            kind: EntryKind::Other { anchor_height },
            sent_at: now,
            started: false,
            last_height: anchor_height,
            last_hash: None,
            service_from: now,
            blocks: 0,
            new_blocks: 0,
        });
    }

    /// A `GetHeaders` the pipeline did not plan was sent to `peer`.
    pub fn note_headers_request(
        &mut self,
        peer: &PeerId,
        from: Hash,
        from_height: u64,
        now: Instant,
    ) {
        let slot = self.peers.entry(peer.clone()).or_insert_with(PeerSlot::new);
        slot.fifo.push_back(Entry {
            kind: EntryKind::Headers { from, from_height },
            sent_at: now,
            started: false,
            last_height: from_height,
            last_hash: None,
            service_from: now,
            blocks: 0,
            new_blocks: 0,
        });
    }

    /// The anchor for a window starting at `lo` when asking `peer`.
    fn anchor_for(&self, slot: &PeerSlot, lo: u64) -> Option<(Hash, u64)> {
        let at = lo.checked_sub(1)?;
        if at == self.applied.1 {
            return Some((self.applied.0, at));
        }
        if at < self.applied.1 {
            return None;
        }
        if let Some(h) = slot.headers.get(&at) {
            return Some((*h, at));
        }
        self.received
            .get(&at)
            .and_then(|set| set.iter().min_by_key(|h| *h.as_bytes()).copied())
            .map(|h| (h, at))
    }

    /// Plan requests for this round. `peers` is every connected peer;
    /// `allowed` is false while the node is not following its own tip (a
    /// fork-point search is running), in which case nothing is planned.
    ///
    /// Every returned request is recorded as sent; call [`Self::send_failed`]
    /// for one that could not be.
    pub fn plan(
        &mut self,
        now: Instant,
        peers: &[PipelinePeer],
        allowed: bool,
    ) -> Vec<PipelineRequest> {
        self.allowed = allowed;
        // Peers that disconnected.
        let present: HashSet<&PeerId> = peers.iter().map(|p| &p.id).collect();
        let gone: Vec<PeerId> = self
            .peers
            .keys()
            .filter(|id| !present.contains(id))
            .cloned()
            .collect();
        for id in gone {
            self.peer_gone(&id, now);
        }
        for p in peers {
            let slot = self.peers.entry(p.id.clone()).or_insert_with(PeerSlot::new);
            slot.head_height = p.head_height;
            slot.admissible = p.admissible;
        }
        let mut out = Vec::new();
        if !self.active() {
            return out;
        }
        self.extend_windows();
        // Headers first: a peer answers in order, and a header reply is small,
        // so the anchors for the next windows arrive before the first window's
        // blocks do.
        self.plan_headers(now, &mut out);
        self.assign_windows(now, &mut out);
        out
    }

    fn lookahead_top(&self) -> u64 {
        self.target
            .min(self.applied.1.saturating_add(self.config.lookahead_heights))
    }

    fn extend_windows(&mut self) {
        let top = self.lookahead_top();
        let k = self.config.window_heights.max(1);
        while self.planned_to < top {
            let lo = self.planned_to.saturating_add(1);
            let hi = lo.saturating_add(k.saturating_sub(1)).min(top);
            self.windows.insert(
                lo,
                Window {
                    hi,
                    owner: None,
                    failed: Vec::new(),
                    attempts: 0,
                    retry_at: None,
                },
            );
            self.planned_to = hi;
        }
    }

    /// First height of `lo..=hi` not received yet (`None`: all received).
    fn first_missing(&self, lo: u64, hi: u64) -> Option<u64> {
        let mut h = lo;
        while h <= hi {
            if !self.received.contains_key(&h) {
                return Some(h);
            }
            h = h.checked_add(1)?;
        }
        None
    }

    fn in_flight_total(&self) -> usize {
        self.peers.values().map(PeerSlot::windows_in_flight).sum()
    }

    fn assign_windows(&mut self, now: Instant, out: &mut Vec<PipelineRequest>) {
        let over_budget = self.buffered_bytes > self.config.max_buffered_bytes;
        let los: Vec<u64> = self.windows.keys().copied().collect();
        for lo in los {
            if self.in_flight_total() >= self.config.max_in_flight {
                break;
            }
            let Some(w) = self.windows.get(&lo).cloned() else {
                continue;
            };
            if w.owner.is_some() || w.retry_at.is_some_and(|t| now < t) {
                continue;
            }
            // Over the buffer budget only the gap at the frontier is filled.
            if over_budget && lo > self.frontier.saturating_add(1) {
                break;
            }
            // Drop what other answers already delivered.
            let start = match self.first_missing(lo, w.hi) {
                Some(s) => s,
                None => {
                    self.windows.remove(&lo);
                    continue;
                }
            };
            let lo = if start > lo {
                self.windows.remove(&lo);
                self.windows.insert(start, w.clone());
                start
            } else {
                lo
            };
            let Some((peer, anchor, anchor_height)) = self.choose_peer(lo, &w, now) else {
                continue;
            };
            // Size the window to what the peer's answers carry.
            let mut hi = w.hi;
            if let Some(cap) = self.peers.get(&peer).and_then(|s| s.capacity_heights) {
                let cut = lo.saturating_add(cap.max(1)).saturating_sub(1);
                if cut < hi {
                    let rest = Window {
                        hi,
                        owner: None,
                        failed: w.failed.clone(),
                        attempts: w.attempts,
                        retry_at: None,
                    };
                    self.windows.insert(cut.saturating_add(1), rest);
                    hi = cut;
                }
            }
            if let Some(win) = self.windows.get_mut(&lo) {
                win.hi = hi;
                win.owner = Some(peer.clone());
            }
            let heights = hi.saturating_sub(anchor_height).saturating_add(1);
            let per_height = if self.max_siblings == 0 {
                u64::from(self.config.request_count)
            } else {
                self.max_siblings
            };
            let count = u32::try_from(
                heights
                    .saturating_mul(per_height)
                    .min(u64::from(self.config.request_count)),
            )
            .unwrap_or(self.config.request_count)
            .max(1);
            let overlaps = self
                .in_flight_windows()
                .iter()
                .any(|(_, l, h)| *l <= hi && lo <= *h);
            if overlaps {
                self.stats.overlapping_requests = self.stats.overlapping_requests.saturating_add(1);
            }
            if let Some(slot) = self.peers.get_mut(&peer) {
                slot.fifo.push_back(Entry {
                    kind: EntryKind::Window {
                        lo,
                        hi,
                        anchor_height,
                        count,
                    },
                    sent_at: now,
                    started: false,
                    last_height: anchor_height,
                    last_hash: None,
                    service_from: now,
                    blocks: 0,
                    new_blocks: 0,
                });
            }
            self.stats.windows_requested = self.stats.windows_requested.saturating_add(1);
            out.push(PipelineRequest::Blocks {
                peer,
                anchor,
                anchor_height,
                count,
                lo,
                hi,
            });
        }
    }

    /// The peer expected to finish window `lo` soonest, with its anchor.
    fn choose_peer(&self, lo: u64, w: &Window, now: Instant) -> Option<(PeerId, Hash, u64)> {
        let mut best: Option<(u64, PeerId, Hash, u64)> = None;
        let mut fallback: Option<(u64, PeerId, Hash, u64)> = None;
        for (id, slot) in &self.peers {
            if !slot.admissible
                || slot.excluded(now)
                || slot.head_height < lo
                || slot.windows_in_flight() >= self.config.max_in_flight_per_peer
            {
                continue;
            }
            let Some((anchor, anchor_height)) = self.anchor_for(slot, lo) else {
                continue;
            };
            let rate = slot.rate_milli.unwrap_or(PRIOR_RATE_MILLI);
            let load = u64::try_from(slot.windows_in_flight())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            // A peer that just timed out is asked last until it answers again.
            let score = rate.checked_div(load).unwrap_or(0) >> slot.backoff.min(16);
            let cand = (score, id.clone(), anchor, anchor_height);
            let better = |cur: &Option<(u64, PeerId, Hash, u64)>| match cur {
                None => true,
                Some((s, cid, _, _)) => score > *s || (score == *s && id.0 < cid.0),
            };
            if w.failed.contains(id) {
                if better(&fallback) {
                    fallback = Some(cand);
                }
            } else if better(&best) {
                best = Some(cand);
            }
        }
        best.or(fallback).map(|(_, p, a, h)| (p, a, h))
    }

    fn plan_headers(&mut self, now: Instant, out: &mut Vec<PipelineRequest>) {
        let want_top = self
            .lookahead_top()
            .saturating_add(self.config.window_heights);
        let applied = self.applied;
        let count = self.config.header_count;
        let mut sent = 0u64;
        let mut ids: Vec<PeerId> = self.peers.keys().cloned().collect();
        ids.sort_by(|a, b| a.0.cmp(&b.0));
        for id in ids {
            let Some(slot) = self.peers.get_mut(&id) else {
                continue;
            };
            if !slot.admissible
                || slot.excluded(now)
                || slot.headers_in_flight()
                || slot.header_backoff_until.is_some_and(|t| now < t)
            {
                continue;
            }
            let (from_height, from) = match slot.header_top() {
                Some((h, x)) if h > applied.1 => (h, x),
                _ => (applied.1, applied.0),
            };
            if from_height >= want_top.min(slot.head_height) {
                continue;
            }
            slot.fifo.push_back(Entry {
                kind: EntryKind::Headers { from, from_height },
                sent_at: now,
                started: false,
                last_height: from_height,
                last_hash: None,
                service_from: now,
                blocks: 0,
                new_blocks: 0,
            });
            sent = sent.saturating_add(1);
            out.push(PipelineRequest::Headers {
                peer: id,
                from,
                from_height,
                count,
            });
        }
        self.stats.headers_requested = self.stats.headers_requested.saturating_add(sent);
    }

    fn sample(slot: &mut PeerSlot, d: Duration) {
        slot.samples.push_back(d);
        while slot.samples.len() > MAX_SAMPLES {
            slot.samples.pop_front();
        }
    }

    /// The answer at the front of `peer`'s FIFO is over.
    fn complete_front(&mut self, peer: &PeerId, now: Instant) {
        let Some(slot) = self.peers.get_mut(peer) else {
            return;
        };
        let Some(e) = slot.fifo.pop_front() else {
            return;
        };
        let end = slot.last_message_at.unwrap_or(now);
        if let Some(next) = slot.fifo.front_mut() {
            next.service_from = next.sent_at.max(end);
        }
        let EntryKind::Window {
            lo,
            hi,
            anchor_height,
            count,
        } = e.kind
        else {
            return;
        };
        if !e.started {
            // Shed by the server, or never answered: back to the pool.
            self.release_window(lo, Some(peer), now);
            return;
        }
        // Rate: new blocks over the service time of this answer.
        let took_ms = u64::try_from(end.saturating_duration_since(e.service_from).as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let sample = u64::try_from(e.new_blocks)
            .unwrap_or(u64::MAX)
            .saturating_mul(1_000_000)
            .checked_div(took_ms)
            .unwrap_or(0);
        if let Some(slot) = self.peers.get_mut(peer) {
            slot.rate_milli = Some(match slot.rate_milli {
                None => sample,
                Some(r) => r.saturating_add(sample).checked_div(2).unwrap_or(sample),
            });
            // Capacity: an answer that ended short of its window without
            // reaching its block count was cut by the server's byte budget.
            let reached = e.last_height;
            let count_bound = u64::try_from(e.blocks)
                .unwrap_or(u64::MAX)
                .saturating_mul(10)
                >= u64::from(count).saturating_mul(9);
            if reached < hi && e.blocks > 0 && !count_bound {
                let carried = reached.saturating_sub(anchor_height).max(1);
                slot.capacity_heights = Some(match slot.capacity_heights {
                    Some(c) => c.min(carried).max(1),
                    None => carried,
                });
            } else if reached >= hi {
                // It carried the whole window: probe larger ones again.
                let full = self.config.window_heights;
                slot.capacity_heights = slot
                    .capacity_heights
                    .map(|c| c.saturating_mul(2))
                    .filter(|c| *c < full);
            }
        }
        // Header agreement over the heights this answer completed.
        let from = anchor_height.max(self.applied.1.saturating_add(1));
        self.check_headers(from, e.last_height, now);
        // The window: done, or its remainder goes back to the pool.
        match self.first_missing(lo, hi) {
            None => {
                self.windows.remove(&lo);
                if let Some(slot) = self.peers.get_mut(peer) {
                    slot.strikes = 0;
                }
            }
            Some(missing) => {
                let delivered_nothing = missing == lo;
                if let Some(mut w) = self.windows.remove(&lo) {
                    w.owner = None;
                    if delivered_nothing {
                        if !w.failed.contains(peer) {
                            w.failed.push(peer.clone());
                        }
                        w.attempts = w.attempts.saturating_add(1);
                        if w.attempts >= 2 {
                            let ms = 500u64
                                .saturating_mul(1u64 << w.attempts.saturating_sub(2).min(4))
                                .min(8_000);
                            w.retry_at = now.checked_add(Duration::from_millis(ms));
                        }
                    }
                    self.windows.insert(missing, w);
                }
            }
        }
    }

    /// Headers that complete groups contradict, from `from` to `to`.
    fn check_headers(&mut self, from: u64, to: u64, now: Instant) {
        if to < from {
            return;
        }
        let mut contradicted: Vec<(PeerId, u64)> = Vec::new();
        for (id, slot) in &self.peers {
            for (h, hash) in slot.headers.range(from..=to) {
                if let Some(set) = self.received.get(h) {
                    if !set.contains(hash) {
                        contradicted.push((id.clone(), *h));
                        break;
                    }
                }
            }
        }
        for (id, h) in contradicted {
            self.stats.contradictions = self.stats.contradictions.saturating_add(1);
            let exclude = {
                let Some(slot) = self.peers.get_mut(&id) else {
                    continue;
                };
                slot.headers = {
                    let mut keep = std::mem::take(&mut slot.headers);
                    let _dropped = keep.split_off(&h);
                    keep
                };
                slot.strikes = slot.strikes.saturating_add(1);
                if slot.strikes >= self.config.max_strikes {
                    slot.strikes = 0;
                    slot.excluded_until = now.checked_add(self.config.exclusion);
                    true
                } else {
                    false
                }
            };
            if exclude {
                self.drop_outstanding(&id, false, now);
            }
        }
    }

    /// Does entry `e` start with a message whose first height is `first`?
    fn starts(e: &Entry, first: Option<u64>) -> bool {
        match (e.anchor_height(), first) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(a), Some(f)) => f == a || Some(f) == a.checked_add(1),
        }
    }

    /// Is a message starting at `first` the next part of `front`'s answer?
    ///
    /// A reply is sorted by height, then hash, and split only between blocks.
    /// So a continuation starts either at the next height, or at the same
    /// height with a higher hash (a height-group split across messages). A
    /// message that starts at the anchor height of the next request with a
    /// hash at or below the last one is the start of that next answer: its
    /// anchor group re-sends the top of the window below it.
    fn continues(front: &Entry, next_anchor: Option<u64>, first: (u64, Hash)) -> bool {
        let (f, fh) = first;
        if f == front.last_height {
            return front
                .last_hash
                .is_some_and(|lh| fh.as_bytes() > lh.as_bytes());
        }
        Some(f) == front.last_height.checked_add(1) && next_anchor != Some(f)
    }

    /// Which outstanding request a `Blocks` message from `peer` answers, and
    /// whether that answer is over with this message (an empty answer is one
    /// message).
    fn attribute(
        &mut self,
        peer: &PeerId,
        first: Option<(u64, Hash)>,
        last: Option<(u64, Hash)>,
        now: Instant,
    ) -> (Attribution, bool) {
        let Some(slot) = self.peers.get_mut(peer) else {
            return (Attribution::Unsolicited, false);
        };
        let kind_of = |e: &Entry| match e.kind {
            EntryKind::Window { lo, hi, .. } => Attribution::Window { lo, hi },
            _ => Attribution::Other,
        };
        // 1) A continuation of the answer being received.
        let mut front_ended = false;
        if let Some(front) = slot.fifo.front() {
            if front.started && front.anchor_height().is_some() {
                let next_anchor = slot.fifo.iter().skip(1).find_map(Entry::anchor_height);
                if first.is_some_and(|f| Self::continues(front, next_anchor, f)) {
                    let attribution = kind_of(front);
                    if let (Some(e), Some((lh, lx))) = (slot.fifo.front_mut(), last) {
                        if lh >= e.last_height {
                            e.last_height = lh;
                            e.last_hash = Some(lx);
                        }
                    }
                    slot.last_message_at = Some(now);
                    slot.backoff = 0;
                    return (attribution, false);
                }
                front_ended = true;
            }
        }
        if front_ended {
            self.complete_front(peer, now);
        }
        // 2) The start of the answer to a later entry.
        let first_height = first.map(|(h, _)| h);
        let idx = match self.peers.get(peer) {
            Some(slot) => slot.fifo.iter().position(|e| Self::starts(e, first_height)),
            None => None,
        };
        let Some(idx) = idx else {
            return (Attribution::Unsolicited, false);
        };
        // Entries skipped over were shed by the server (or their answers lost).
        for _ in 0..idx {
            self.complete_front(peer, now);
        }
        let Some(slot) = self.peers.get_mut(peer) else {
            return (Attribution::Unsolicited, false);
        };
        let prev_end = slot.last_message_at;
        let Some(e) = slot.fifo.front_mut() else {
            return (Attribution::Unsolicited, false);
        };
        let service_from = e.sent_at.max(prev_end.unwrap_or(e.sent_at));
        e.service_from = service_from;
        e.started = true;
        if let Some((lh, lx)) = last {
            e.last_height = e.last_height.max(lh);
            e.last_hash = Some(lx);
        }
        let attribution = kind_of(e);
        Self::sample(slot, now.saturating_duration_since(service_from));
        slot.last_message_at = Some(now);
        slot.backoff = 0;
        (attribution, first.is_none())
    }

    /// Advance the frontier over received heights.
    fn advance_frontier(&mut self) {
        loop {
            let Some(next) = self.frontier.checked_add(1) else {
                return;
            };
            if self.received.contains_key(&next) {
                self.frontier = next;
            } else {
                return;
            }
        }
    }

    /// Held blocks at or below the frontier, height-ascending.
    fn take_releasable(&mut self) -> Vec<Block> {
        let Some(above) = self.frontier.checked_add(1) else {
            return Vec::new();
        };
        let rest = self.buffer.split_off(&above);
        let ready = std::mem::replace(&mut self.buffer, rest);
        let mut out = Vec::new();
        for (_, bs) in ready {
            self.buffered_bytes = self
                .buffered_bytes
                .saturating_sub(bs.iter().map(block_bytes).sum());
            out.extend(bs);
        }
        out
    }

    /// A `Blocks` message from `peer`: `raw` is the (height, hash) of the
    /// first and the last block of the message as received (before
    /// validation; `None`: empty), `validated` the blocks of it that passed
    /// `handle_blocks`.
    pub fn on_blocks(
        &mut self,
        peer: &PeerId,
        raw: Option<((u64, Hash), (u64, Hash))>,
        validated: Vec<Block>,
        now: Instant,
    ) -> BlocksOutcome {
        let (first, last) = match raw {
            Some((f, l)) => (Some(f), Some(l)),
            None => (None, None),
        };
        let (attribution, ended) = self.attribute(peer, first, last, now);
        let Attribution::Window { .. } = attribution else {
            if ended {
                self.complete_front(peer, now);
            }
            return BlocksOutcome {
                attribution: Some(attribution),
                release: validated,
                new_blocks: 0,
            };
        };
        let applied = self.applied.1;
        let mut new_blocks = 0usize;
        let mut immediate = Vec::new();
        let total = validated.len();
        for b in validated {
            let h = b.header.height;
            if h <= applied {
                immediate.push(b);
                continue;
            }
            let fresh = self
                .received
                .entry(h)
                .or_default()
                .insert(b.header.block_hash);
            if !fresh {
                continue;
            }
            new_blocks = new_blocks.saturating_add(1);
            let per_height = u64::try_from(self.received.get(&h).map(HashSet::len).unwrap_or(0))
                .unwrap_or(u64::MAX);
            self.max_siblings = self.max_siblings.max(per_height);
            self.buffered_bytes = self.buffered_bytes.saturating_add(block_bytes(&b));
            self.buffer.entry(h).or_default().push(b);
        }
        self.stats.delivered_blocks = self
            .stats
            .delivered_blocks
            .saturating_add(u64::try_from(new_blocks).unwrap_or(u64::MAX));
        if let Some(front) = self.peers.get_mut(peer).and_then(|s| s.fifo.front_mut()) {
            front.blocks = front.blocks.saturating_add(total);
            front.new_blocks = front.new_blocks.saturating_add(new_blocks);
        }
        if ended {
            self.complete_front(peer, now);
        }
        self.advance_frontier();
        immediate.extend(self.take_releasable());
        BlocksOutcome {
            attribution: Some(attribution),
            release: immediate,
            new_blocks,
        }
    }

    /// A `Headers` message from `peer` (`(height, hash)` per header, as sent).
    pub fn on_headers(&mut self, peer: &PeerId, headers: &[(u64, Hash)], now: Instant) {
        let Some(slot) = self.peers.get_mut(peer) else {
            return;
        };
        let Some(idx) = slot
            .fifo
            .iter()
            .position(|e| matches!(e.kind, EntryKind::Headers { .. }))
        else {
            return;
        };
        // Every answer before it is over.
        for _ in 0..idx {
            self.complete_front(peer, now);
        }
        let applied = self.applied;
        let received_at =
            |this: &Self, h: u64, x: &Hash| this.received.get(&h).is_some_and(|s| s.contains(x));
        let Some(slot) = self.peers.get_mut(peer) else {
            return;
        };
        let prev_end = slot.last_message_at;
        let Some(e) = slot.fifo.pop_front() else {
            return;
        };
        let service_from = e.sent_at.max(prev_end.unwrap_or(e.sent_at));
        Self::sample(slot, now.saturating_duration_since(service_from));
        slot.last_message_at = Some(now);
        slot.backoff = 0;
        if let Some(next) = slot.fifo.front_mut() {
            next.service_from = next.sent_at.max(now);
        }
        let EntryKind::Headers { from, from_height } = e.kind else {
            return;
        };
        if headers.is_empty() {
            slot.header_backoff_until = now.checked_add(self.config.header_backoff);
            return;
        }
        // Contiguous from the anchor, or not a chain we can use.
        let contiguous = headers.iter().enumerate().all(|(i, (h, _))| {
            u64::try_from(i)
                .ok()
                .and_then(|i| from_height.checked_add(i))
                .and_then(|x| x.checked_add(1))
                == Some(*h)
        });
        if !contiguous {
            return;
        }
        // The anchor must be one we know this peer stands on: the applied tip,
        // its own previous header, or a block an answer delivered.
        let slot_ref = self.peers.get(peer);
        let anchored = from_height <= applied.1
            || slot_ref.is_some_and(|s| s.headers.get(&from_height) == Some(&from))
            || received_at(self, from_height, &from);
        if !anchored {
            return;
        }
        let Some(slot) = self.peers.get_mut(peer) else {
            return;
        };
        let first = from_height.saturating_add(1);
        let _replaced = slot.headers.split_off(&first);
        for (h, x) in headers {
            if *h > applied.1 && slot.headers.len() < MAX_HEADERS_PER_PEER {
                slot.headers.insert(*h, *x);
            }
        }
        // A header that arrives after its group must agree with it too.
        let last = headers.last().map(|(h, _)| *h).unwrap_or(first);
        self.check_headers(
            first.max(applied.1.saturating_add(1)),
            last.min(self.frontier),
            now,
        );
    }

    /// Timeouts and the stall valve.
    pub fn poll(&mut self, now: Instant) -> PollOutcome {
        let mut out = PollOutcome::default();
        let ids: Vec<PeerId> = self.peers.keys().cloned().collect();
        for id in ids {
            while let Some(slot) = self.peers.get(&id) {
                let Some(front) = slot.fifo.front() else {
                    break;
                };
                let since = front
                    .sent_at
                    .max(slot.last_message_at.unwrap_or(front.sent_at));
                let deadline = since.checked_add(self.timeout_for(slot)).unwrap_or(since);
                if now < deadline {
                    break;
                }
                if front.started {
                    // The answer went quiet: it is over.
                    self.complete_front(&id, now);
                    continue;
                }
                if !matches!(front.kind, EntryKind::Window { .. }) && slot.windows_in_flight() == 0
                {
                    // Someone else's request (walk, legacy tick, headers) with
                    // nothing of ours behind it: the legacy timeout handles it.
                    if let Some(s) = self.peers.get_mut(&id) {
                        s.fifo.pop_front();
                        if let Some(next) = s.fifo.front_mut() {
                            next.service_from = now;
                        }
                    }
                    continue;
                }
                // Unanswered: every window it holds goes back to the pool.
                self.stats.timeouts = self.stats.timeouts.saturating_add(1);
                self.drop_outstanding(&id, true, now);
                if let Some(s) = self.peers.get_mut(&id) {
                    s.backoff = s.backoff.saturating_add(1);
                }
                out.timed_out.push(id.clone());
                break;
            }
        }
        // Stall valve.
        if !self.buffer.is_empty()
            && now.saturating_duration_since(self.last_progress) > self.config.stall_timeout
        {
            self.stats.stall_flushes = self.stats.stall_flushes.saturating_add(1);
            let all = std::mem::take(&mut self.buffer);
            self.buffered_bytes = 0;
            for (_, bs) in all {
                out.flushed.extend(bs);
            }
            self.restart_plan();
            self.last_progress = now;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{BlockBuilder, PublicKey};

    fn pid(s: &str) -> PeerId {
        PeerId::new(s.to_string())
    }

    fn hash(h: u64, i: u64) -> Hash {
        let mut b = [0x77u8; 32];
        b[..8].copy_from_slice(&h.to_be_bytes());
        b[8..16].copy_from_slice(&i.to_be_bytes());
        Hash::new(b)
    }

    fn block(h: u64, i: u64) -> Block {
        BlockBuilder::new()
            .hash(hash(h, i))
            .parent(hash(h.saturating_sub(1), 0))
            .height(h)
            .timestamp(1_000 + h)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed()
    }

    /// Seven siblings at each height in `from..=to`.
    fn groups(from: u64, to: u64) -> Vec<Block> {
        (from..=to)
            .flat_map(|h| (0..7).map(move |i| block(h, i)))
            .collect()
    }

    /// The (height, hash) of a message's first and last block.
    fn raw_of(bs: &[Block]) -> Option<((u64, Hash), (u64, Hash))> {
        let f = bs.first()?;
        let l = bs.last()?;
        Some((
            (f.header.height, f.header.block_hash),
            (l.header.height, l.header.block_hash),
        ))
    }

    fn peer(id: &str, head: u64) -> PipelinePeer {
        PipelinePeer {
            id: pid(id),
            head_height: head,
            admissible: true,
        }
    }

    fn headers(from: u64, to: u64) -> Vec<(u64, Hash)> {
        (from..=to).map(|h| (h, hash(h, 0))).collect()
    }

    fn pipeline(now: Instant) -> BlockPipeline {
        let mut p = BlockPipeline::new(PipelineConfig::default(), now);
        p.observe_applied((hash(0, 0), 0), now);
        p.set_target(10_000);
        p
    }

    fn blocks_of(reqs: &[PipelineRequest]) -> Vec<(PeerId, u64, u64, u64)> {
        reqs.iter()
            .filter_map(|r| match r {
                PipelineRequest::Blocks {
                    peer,
                    anchor_height,
                    lo,
                    hi,
                    ..
                } => Some((peer.clone(), *anchor_height, *lo, *hi)),
                _ => None,
            })
            .collect()
    }

    /// Answer a header request from `p` with its headers up to `to`.
    fn feed_headers(pl: &mut BlockPipeline, reqs: &[PipelineRequest], to: u64, now: Instant) {
        for r in reqs {
            if let PipelineRequest::Headers {
                peer, from_height, ..
            } = r
            {
                pl.on_headers(peer, &headers(from_height + 1, to), now);
            }
        }
    }

    /// Answer window `lo..=hi` (anchored at `lo - 1`) from `p`, in `chunks`
    /// messages.
    fn answer(
        pl: &mut BlockPipeline,
        p: &PeerId,
        lo: u64,
        hi: u64,
        chunks: usize,
        now: Instant,
    ) -> BlocksOutcome {
        let all = groups(lo - 1, hi);
        let per = all.len().div_ceil(chunks);
        let mut out = BlocksOutcome::default();
        for c in all.chunks(per) {
            let o = pl.on_blocks(p, raw_of(c), c.to_vec(), now);
            out.attribution = o.attribution;
            out.new_blocks += o.new_blocks;
            out.release.extend(o.release);
        }
        out
    }

    #[test]
    fn nothing_is_planned_within_the_engage_gap_or_while_not_allowed() {
        let now = Instant::now();
        let mut pl = BlockPipeline::new(PipelineConfig::default(), now);
        pl.observe_applied((hash(100, 0), 100), now);
        pl.set_target(150);
        assert!(pl.plan(now, &[peer("a", 150)], true).is_empty());
        pl.set_target(5_000);
        assert!(pl.plan(now, &[peer("a", 5_000)], false).is_empty());
        assert!(!pl.plan(now, &[peer("a", 5_000)], true).is_empty());
    }

    #[test]
    fn the_first_window_anchors_on_the_applied_tip_and_headers_open_the_rest() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000), peer("b", 10_000), peer("c", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        let b = blocks_of(&reqs);
        // Without headers only the applied tip can anchor: one window.
        assert_eq!(b.len(), 1);
        assert_eq!((b[0].1, b[0].2, b[0].3), (0, 1, 64));
        // Every admissible peer is asked for headers.
        let heads = reqs
            .iter()
            .filter(|r| matches!(r, PipelineRequest::Headers { .. }))
            .count();
        assert_eq!(heads, 3);
        feed_headers(&mut pl, &reqs, 600, now);
        let reqs = pl.plan(now, &peers, true);
        let b = blocks_of(&reqs);
        // Seven more windows (8 in flight in total), each anchored one height
        // below itself, on that peer's own header.
        assert_eq!(b.len(), 7);
        for (_, anchor, lo, _) in &b {
            assert_eq!(*anchor + 1, *lo);
        }
        assert_eq!(pl.stats().windows_in_flight, 8);
    }

    #[test]
    fn windows_in_flight_never_overlap_and_spread_across_peers() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000), peer("b", 10_000), peer("c", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        feed_headers(&mut pl, &reqs, 600, now);
        let _ = pl.plan(now, &peers, true);
        let w = pl.in_flight_windows();
        for pair in w.windows(2) {
            assert!(pair[0].2 < pair[1].1, "overlap: {pair:?}");
        }
        let owners: HashSet<&PeerId> = w.iter().map(|(p, _, _)| p).collect();
        assert_eq!(owners.len(), 3, "spread across every peer: {w:?}");
        for p in &peers {
            assert!(w.iter().filter(|(o, _, _)| *o == p.id).count() <= 4);
        }
        assert_eq!(pl.stats().overlapping_requests, 0);
    }

    #[test]
    fn a_peer_whose_head_is_below_a_window_gets_no_window() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("low", 20), peer("high", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        let b = blocks_of(&reqs);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].0, pid("high"));
    }

    #[test]
    fn an_inadmissible_peer_is_never_asked() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let mut bad = peer("bad", 10_000);
        bad.admissible = false;
        let reqs = pl.plan(now, &[bad], true);
        assert!(reqs.is_empty());
    }

    #[test]
    fn answers_issue_the_next_window_and_release_in_height_order() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000), peer("b", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        feed_headers(&mut pl, &reqs, 600, now);
        let _ = pl.plan(now, &peers, true);
        let w = pl.in_flight_windows();
        // Answer the SECOND window first: its blocks are held.
        let (p2, lo2, hi2) = w[1].clone();
        let o = answer(&mut pl, &p2, lo2, hi2, 5, now);
        assert!(o.is_pipeline());
        assert!(o.new_blocks > 0);
        assert!(o.release.is_empty(), "held until the window below arrives");
        // Then the first: both release, in height order.
        let (p1, lo1, hi1) = w[0].clone();
        let o = answer(&mut pl, &p1, lo1, hi1, 3, now);
        assert!(!o.release.is_empty());
        let hs: Vec<u64> = o.release.iter().map(|b| b.header.height).collect();
        let mut sorted = hs.clone();
        sorted.sort();
        assert_eq!(hs, sorted);
        assert!(hs.contains(&hi2));
        assert_eq!(pl.frontier(), hi2);
    }

    #[test]
    fn a_split_answer_is_one_answer() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        feed_headers(&mut pl, &reqs, 600, now);
        let _ = pl.plan(now, &peers, true);
        let w = pl.in_flight_windows();
        assert_eq!(w.len(), 4, "per-peer cap");
        // Seventeen messages for the first window, then the second's first.
        let (p, lo, hi) = w[0].clone();
        let _ = answer(&mut pl, &p, lo, hi, 17, now);
        assert_eq!(pl.in_flight_windows().len(), 4, "still receiving");
        let (_, lo2, hi2) = w[1].clone();
        let first = groups(lo2 - 1, lo2 + 2);
        let o = pl.on_blocks(&p, raw_of(&first), first.clone(), now);
        assert_eq!(
            o.attribution,
            Some(Attribution::Window { lo: lo2, hi: hi2 })
        );
        // The first window is complete and gone.
        assert!(pl.in_flight_windows().iter().all(|(_, l, _)| *l != lo));
    }

    #[test]
    fn a_short_answer_keeps_its_remainder_and_learns_the_peers_capacity() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("old", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        feed_headers(&mut pl, &reqs, 600, now);
        let _ = pl.plan(now, &peers, true);
        let w = pl.in_flight_windows();
        let (p, lo, _) = w[0].clone();
        // A pre-#477 server: four heights (28 blocks) then the next answer.
        let short = groups(lo - 1, lo + 3);
        let _ = pl.on_blocks(&p, raw_of(&short), short.clone(), now);
        let (_, lo2, _) = w[1].clone();
        let next = groups(lo2 - 1, lo2);
        let _ = pl.on_blocks(&p, raw_of(&next), next.clone(), now);
        // The remainder of the first window is a window again, unowned.
        let next = pl.plan(now, &peers, true);
        let b = blocks_of(&next);
        assert!(
            b.iter().any(|(_, _, l, h)| *l == lo + 4 && *h - *l < 8),
            "remainder re-planned at the learned size: {b:?}"
        );
    }

    #[test]
    fn a_timed_out_window_is_reassigned_to_another_peer() {
        let t0 = Instant::now();
        let mut pl = pipeline(t0);
        let peers = [peer("a", 10_000), peer("b", 10_000)];
        let reqs = pl.plan(t0, &peers, true);
        // Only b answers its headers; a stays silent from here on.
        for r in &reqs {
            if let PipelineRequest::Headers {
                peer, from_height, ..
            } = r
            {
                if peer.0 == "b" {
                    pl.on_headers(peer, &headers(from_height + 1, 600), t0);
                }
            }
        }
        let first = blocks_of(&reqs)[0].clone();
        assert_eq!(first.0, pid("a"), "tie broken on id");
        // Before the initial timeout, nothing moves.
        let early = pl.poll(t0 + Duration::from_secs(5));
        assert!(early.timed_out.is_empty());
        let t1 = t0 + Duration::from_secs(11);
        let out = pl.poll(t1);
        assert_eq!(out.timed_out, vec![pid("a")]);
        let again = blocks_of(&pl.plan(t1, &peers, true));
        assert!(
            again
                .iter()
                .any(|(p, _, lo, _)| *p == pid("b") && *lo == first.2),
            "window {} goes to b: {again:?}",
            first.2
        );
        assert!(pl.stats().timeouts >= 1 && pl.stats().reassigned >= 1);
    }

    #[test]
    fn the_timeout_adapts_to_the_peers_latency() {
        let t0 = Instant::now();
        let mut pl = pipeline(t0);
        let peers = [peer("a", 10_000)];
        let mut now = t0;
        // Ten fast answers (50 ms each).
        for _ in 0..10 {
            let reqs = pl.plan(now, &peers, true);
            feed_headers(&mut pl, &reqs, 5_000, now);
            for (p, _, lo, hi) in blocks_of(&reqs) {
                now += Duration::from_millis(50);
                let _ = answer(&mut pl, &p, lo, hi, 1, now);
            }
            pl.observe_applied((hash(pl.frontier(), 0), pl.frontier()), now);
        }
        let fig = &pl.peer_figures(now)[0];
        assert_eq!(fig.timeout_ms, 3_000, "4 x p95 clamped to the 3 s floor");
        assert!(fig.blocks_per_sec > 0);
    }

    #[test]
    fn an_answer_skipping_a_shed_request_releases_it() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        feed_headers(&mut pl, &reqs, 600, now);
        let _ = pl.plan(now, &peers, true);
        let w = pl.in_flight_windows();
        // The answer to the SECOND request arrives first: the first was shed.
        let (p, lo2, hi2) = w[1].clone();
        let _ = answer(&mut pl, &p, lo2, hi2, 1, now);
        let w_after = pl.in_flight_windows();
        assert!(
            w_after.iter().all(|(_, l, _)| *l != w[0].1),
            "shed window released"
        );
        let next = blocks_of(&pl.plan(now, &peers, true));
        assert!(
            next.iter().any(|(_, _, l, _)| *l == w[0].1),
            "and re-planned"
        );
    }

    #[test]
    fn a_peer_whose_headers_contradict_delivered_blocks_gets_no_windows() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("honest", 10_000), peer("fork", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        for r in &reqs {
            if let PipelineRequest::Headers {
                peer, from_height, ..
            } = r
            {
                // `fork` claims a different chain from height 1 up.
                let hs: Vec<(u64, Hash)> = if peer.0 == "fork" {
                    (from_height + 1..=600).map(|h| (h, hash(h, 99))).collect()
                } else {
                    headers(from_height + 1, 600)
                };
                pl.on_headers(peer, &hs, now);
            }
        }
        let mut now = now;
        // Honest answers arrive; each time fork's headers are re-requested and
        // contradicted again.
        for round in 0..6 {
            now += Duration::from_millis(100);
            let reqs = pl.plan(now, &peers, true);
            for r in &reqs {
                if let PipelineRequest::Headers {
                    peer, from_height, ..
                } = r
                {
                    let hs: Vec<(u64, Hash)> = if peer.0 == "fork" {
                        (from_height + 1..=600).map(|h| (h, hash(h, 99))).collect()
                    } else {
                        headers(from_height + 1, 600)
                    };
                    pl.on_headers(peer, &hs, now);
                }
            }
            for (p, lo, hi) in pl.in_flight_windows() {
                if p.0 == "honest" {
                    let _ = answer(&mut pl, &p, lo, hi, 2, now);
                }
            }
            let _ = round;
        }
        assert!(pl.stats().contradictions >= 3);
        let figs = pl.peer_figures(now);
        let fork = figs.iter().find(|f| f.id.0 == "fork").expect("fork");
        assert!(fork.excluded, "excluded after repeated contradictions");
        let next = blocks_of(&pl.plan(now, &peers, true));
        assert!(next.iter().all(|(p, _, _, _)| p.0 != "fork"));
    }

    #[test]
    fn answers_to_other_requests_pass_through_untouched() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000)];
        let _ = pl.plan(now, &peers, true);
        let p = pid("a");
        pl.note_other_blocks_request(&p, 3_000, now);
        // The pipeline's window (anchored at 0) answers first, then the walk's.
        let _ = answer(&mut pl, &p, 1, 64, 2, now);
        let walk = groups(3_000, 3_001);
        let o = pl.on_blocks(&p, raw_of(&walk), walk.clone(), now);
        assert_eq!(o.attribution, Some(Attribution::Other));
        assert_eq!(o.release.len(), walk.len());
        // A message nobody asked for.
        let z = groups(9, 9);
        let o = pl.on_blocks(&pid("z"), raw_of(&z), z.clone(), now);
        assert_eq!(o.attribution, Some(Attribution::Unsolicited));
    }

    #[test]
    fn an_empty_answer_releases_the_window_to_another_peer() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000), peer("b", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        let (p, _, lo, _) = blocks_of(&reqs)[0].clone();
        let o = pl.on_blocks(&p, None, Vec::new(), now);
        assert!(o.is_pipeline());
        let next = blocks_of(&pl.plan(now, &peers, true));
        let again = next
            .iter()
            .find(|(_, _, l, _)| *l == lo)
            .expect("re-planned");
        assert_ne!(again.0, p, "another peer first");
    }

    #[test]
    fn the_stall_valve_flushes_held_blocks_and_restarts() {
        let t0 = Instant::now();
        let mut pl = pipeline(t0);
        let peers = [peer("a", 10_000), peer("b", 10_000)];
        let reqs = pl.plan(t0, &peers, true);
        feed_headers(&mut pl, &reqs, 600, t0);
        let _ = pl.plan(t0, &peers, true);
        let w = pl.in_flight_windows();
        let (p, lo, hi) = w[2].clone();
        let _ = answer(&mut pl, &p, lo, hi, 1, t0);
        assert!(pl.stats().buffered_blocks > 0);
        let out = pl.poll(t0 + Duration::from_secs(31));
        assert!(!out.flushed.is_empty());
        assert_eq!(pl.stats().buffered_blocks, 0);
        assert_eq!(pl.stats().stall_flushes, 1);
    }

    #[test]
    fn the_buffer_budget_limits_planning_to_the_frontier_gap() {
        let t0 = Instant::now();
        let config = PipelineConfig {
            max_buffered_bytes: 1,
            ..PipelineConfig::default()
        };
        let mut pl = BlockPipeline::new(config, t0);
        pl.observe_applied((hash(0, 0), 0), t0);
        pl.set_target(10_000);
        let peers = [peer("a", 10_000), peer("b", 10_000)];
        let reqs = pl.plan(t0, &peers, true);
        feed_headers(&mut pl, &reqs, 600, t0);
        let _ = pl.plan(t0, &peers, true);
        let w = pl.in_flight_windows();
        // b answers its first window, above the frontier: held, over budget.
        let (p, lo, hi) = w
            .iter()
            .rev()
            .find(|(o, _, _)| o.0 == "b")
            .cloned()
            .expect("b holds a window");
        let _ = answer(&mut pl, &p, lo, hi, 1, t0);
        assert!(pl.stats().buffered_bytes > 1);
        // a goes silent and times out: its windows go back to the pool, but
        // only the one at the frontier gap may be planned again.
        let t1 = t0 + Duration::from_secs(11);
        let _ = pl.poll(t1);
        let again = blocks_of(&pl.plan(t1, &peers, true));
        assert!(!again.is_empty());
        for (_, _, l, _) in &again {
            assert!(*l <= pl.frontier() + 1, "window {l} above the gap");
        }
    }

    #[test]
    fn a_reorg_below_the_plan_restarts_it() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000)];
        let _ = pl.plan(now, &peers, true);
        let p = pid("a");
        let _ = answer(&mut pl, &p, 1, 64, 1, now);
        pl.observe_applied((hash(64, 0), 64), now);
        pl.observe_applied((hash(40, 3), 40), now);
        assert_eq!(pl.frontier(), 40);
        let b = blocks_of(&pl.plan(now, &peers, true));
        assert!(b.iter().any(|(_, a, lo, _)| *a == 40 && *lo == 41));
    }

    /// Many rounds of random answer orders and losses: no two in-flight
    /// windows ever overlap, and every height up to the target is delivered.
    #[test]
    fn randomized_rounds_keep_windows_disjoint_and_reach_the_target() {
        let t0 = Instant::now();
        // Engaged to the last height (by default the legacy tick takes the
        // last `engage_gap` heights).
        let config = PipelineConfig {
            engage_gap: 0,
            ..PipelineConfig::default()
        };
        let mut pl = BlockPipeline::new(config, t0);
        pl.observe_applied((hash(0, 0), 0), t0);
        let target = 3_000;
        pl.set_target(target);
        let peers = [peer("a", target), peer("b", target), peer("c", target)];
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut now = t0;
        let mut applied = 0u64;
        for _ in 0..40_000 {
            now += Duration::from_millis(50);
            let reqs = pl.plan(now, &peers, true);
            feed_headers(&mut pl, &reqs, target, now);
            let w = pl.in_flight_windows();
            for pair in w.windows(2) {
                assert!(pair[0].2 < pair[1].1, "overlap: {pair:?}");
            }
            // Answer one random peer's front request, sometimes short, rarely lost.
            if let Some((p, lo, hi)) = w.get((rnd() as usize) % w.len().max(1)).cloned() {
                if let Some((fp, flo, fhi)) = w.iter().find(|(x, _, _)| *x == p).cloned() {
                    let _ = (lo, hi);
                    match rnd() % 10 {
                        0 => {}
                        1 => {
                            let top = (flo + 2).min(fhi);
                            let part = groups(flo - 1, top);
                            let _ = pl.on_blocks(&fp, raw_of(&part), part.clone(), now);
                        }
                        _ => {
                            let o = answer(&mut pl, &fp, flo, fhi, 3, now);
                            let _ = o;
                        }
                    }
                }
            }
            let _ = pl.poll(now);
            if pl.frontier() > applied {
                applied = pl.frontier();
                pl.observe_applied((hash(applied, 0), applied), now);
            }
            if applied >= target {
                break;
            }
        }
        if applied != target {
            eprintln!("windows: {:?}", pl.windows);
            for (id, slot) in &pl.peers {
                eprintln!(
                    "{}: fifo={:?} headers_top={:?} cap={:?} excl={:?}",
                    id.0,
                    slot.fifo
                        .iter()
                        .map(|e| (&e.kind, e.started, e.last_height))
                        .collect::<Vec<_>>(),
                    slot.header_top().map(|(h, _)| h),
                    slot.capacity_heights,
                    slot.excluded_until.is_some()
                );
            }
        }
        assert_eq!(applied, target, "{:?}", pl.stats());
        assert_eq!(pl.stats().overlapping_requests, 0);
    }
}
