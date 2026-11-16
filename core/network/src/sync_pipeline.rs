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
    /// Hard caps on what the reorder buffer holds, checked as each block
    /// arrives. The same bounds as admission's orphan buffer
    /// (`admission::MAX_ORPHAN_BLOCKS` / `MAX_ORPHAN_BYTES` in citrate-node).
    pub max_held_blocks: usize,
    pub max_held_bytes: usize,
    /// Strikes (an answer inconsistent with the peer's own headers, blocks
    /// that do not chain from the window's anchor, or a chain that does not
    /// connect to ours) before a peer is excluded.
    pub max_strikes: u32,
    /// How long an excluded peer gets no windows.
    pub exclusion: Duration,
    /// Wait after an empty `Headers` answer before asking that peer again.
    pub header_backoff: Duration,
    /// How long the pipeline stands aside when deliveries fork at our applied
    /// tip, so the tick's fork-point search can heal the node.
    pub stand_down: Duration,
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
            max_held_blocks: 20_000,
            max_held_bytes: 64 * 1024 * 1024,
            max_strikes: 3,
            exclusion: Duration::from_secs(60),
            header_backoff: Duration::from_secs(2),
            stand_down: Duration::from_secs(60),
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
    /// Deliveries dropped because their chain did not connect to ours.
    pub unconnected: u64,
    /// Peers tried later for a delivery provably off our chain.
    pub unconnected_deprioritized: u64,
    /// Times the pipeline stood aside for the fork-point search.
    pub stood_down: u64,
    /// Blocks not held because the reorder buffer was at its caps.
    pub held_cap_drops: u64,
    /// Heights asked for again because an answer left a block of them out.
    pub refills: u64,
    /// Held blocks evicted to make room for others (from a holder over its
    /// share).
    pub held_evictions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EntryKind {
    Window {
        lo: u64,
        hi: u64,
        anchor: Hash,
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
    /// What this answer has linked so far (window entries only).
    link: Link,
}

/// The blocks one window answer has linked to its anchor.
#[derive(Debug, Clone, Default)]
struct Link {
    /// The anchor and every block taken in from this answer.
    chain: HashSet<Hash>,
    /// Blocks at the anchor's height other than the anchor: taken in once a
    /// block above references them.
    anchor_group: Vec<Block>,
    /// Blocks taken in.
    accepted: usize,
    /// Blocks in the window's range that did not chain from the anchor.
    unlinked: usize,
    /// Blocks taken in whose selected parent this answer left out.
    gaps: usize,
}

/// Blocks per answer whose selected parent the answer left out.
const MAX_GAPS: usize = 8;

/// Heights of verified history kept below the applied tip, so a height an
/// answer left incomplete can still be asked for again after the tip passed
/// it (the tip can move a whole lookahead between two answers).
const REFILL_DEPTH: u64 = 512;

/// Anchor-height siblings kept per answer while their children arrive.
const MAX_ANCHOR_GROUP: usize = 64;
/// Blocks one answer may bring in beyond its request's `count` (the server
/// emits whole height-groups).
const ANSWER_SLACK: usize = 64;

/// A block in the reorder buffer.
#[derive(Debug, Clone)]
struct Held {
    block: Block,
    bytes: usize,
    /// Who delivered it, for which window.
    peer: PeerId,
    win_lo: u64,
    win_hi: u64,
    /// It chains to the applied tip through verified blocks.
    verified: bool,
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
    /// Times it has been excluded: each exclusion lasts twice the last.
    exclusions: u32,
    /// Asked only when no one else can be, until then: its delivery was off
    /// our chain. Never an exclusion: it stays askable.
    demoted_until: Option<Instant>,
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
            exclusions: 0,
            demoted_until: None,
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
    /// Asks again for a height that is already received but incomplete (a
    /// block above references a block of it that never came).
    refill: bool,
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
    /// Verified hashes at each height from the applied tip up: blocks whose
    /// chain connects to the applied tip. Only these advance the frontier,
    /// are released, and are what headers are checked against.
    received: BTreeMap<u64, HashSet<Hash>>,
    /// The same hashes, for parent lookups.
    verified: HashSet<Hash>,
    /// Every height from the applied tip up to here has been received.
    frontier: u64,
    /// Blocks above the frontier, waiting for the windows below them.
    buffer: BTreeMap<u64, Vec<Held>>,
    buffered_bytes: usize,
    buffered_count: usize,
    /// A delivery forked at our applied tip (see `settle`).
    off_branch: bool,
    /// Peers whose deliveries fork at our applied tip.
    fork_votes: HashSet<PeerId>,
    /// The pipeline stands aside until then (or until the applied tip moves).
    stand_down_until: Option<Instant>,
    /// Heights asked for again (once each) because a block above references
    /// a block of them that was never delivered.
    refilled: HashSet<u64>,
    /// Who delivered the released blocks of each height above the applied
    /// tip: charged if the node then cannot apply that height.
    released_by: BTreeMap<u64, Vec<PeerId>>,
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
            verified: HashSet::new(),
            frontier: 0,
            buffer: BTreeMap::new(),
            buffered_bytes: 0,
            buffered_count: 0,
            refilled: HashSet::new(),
            released_by: BTreeMap::new(),
            off_branch: false,
            fork_votes: HashSet::new(),
            stand_down_until: None,
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
        let (old_hash, old) = self.applied;
        let height = applied.1;
        if applied.0 != old_hash {
            // The tip moved (healed or advanced): plan again.
            self.off_branch = false;
            self.fork_votes.clear();
            self.stand_down_until = None;
        }
        if height > old {
            self.last_progress = now;
        }
        self.applied = applied;
        if height < old {
            self.restart_plan();
        }
        // Prune what is below the tip; the tip's own height stays, seeded
        // with the tip, as the root every verified chain connects to.
        let keep_above = height.saturating_add(1);
        self.received = self
            .received
            .split_off(&height.saturating_sub(REFILL_DEPTH));
        self.received.entry(height).or_default().insert(applied.0);
        self.verified = self.received.values().flatten().copied().collect();
        let below: Vec<u64> = self.buffer.range(..keep_above).map(|(h, _)| *h).collect();
        for h in below {
            if let Some(bs) = self.buffer.remove(&h) {
                self.forget_held(&bs);
            }
        }
        for slot in self.peers.values_mut() {
            slot.headers = slot.headers.split_off(&keep_above);
        }
        self.released_by = self.released_by.split_off(&keep_above);
        let floor = height.saturating_sub(REFILL_DEPTH);
        self.refilled.retain(|h| *h > floor);
        // Windows wholly at or below the tip are done; an unowned window that
        // straddles it starts above it.
        let mut adjusted: BTreeMap<u64, Window> = BTreeMap::new();
        for (lo, w) in std::mem::take(&mut self.windows) {
            if w.refill && w.hi > height.saturating_sub(REFILL_DEPTH) {
                adjusted.insert(lo, w);
                continue;
            }
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
        if !self.allowed || self.stand_down_until.is_some() {
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
        s.buffered_blocks = self.buffered_count;
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

    /// Each peer's outstanding window requests in the order they were sent,
    /// which is the order a server answers them in (tests).
    #[cfg(test)]
    fn fifo_windows(&self) -> Vec<(PeerId, u64, u64)> {
        let mut ids: Vec<&PeerId> = self.peers.keys().collect();
        ids.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out = Vec::new();
        for id in ids {
            if let Some(slot) = self.peers.get(id) {
                for e in &slot.fifo {
                    if let EntryKind::Window { lo, hi, .. } = e.kind {
                        out.push((id.clone(), lo, hi));
                    }
                }
            }
        }
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
        // 2^backoff, capped at 32 (a lookup, no shift).
        const FACTOR: [u32; 6] = [1, 2, 4, 8, 16, 32];
        let idx = usize::try_from(slot.backoff).unwrap_or(usize::MAX);
        let factor = FACTOR.get(idx).copied().unwrap_or(32);
        base.saturating_mul(factor).min(self.config.max_timeout)
    }

    fn forget_held(&mut self, held: &[Held]) {
        self.buffered_bytes = self
            .buffered_bytes
            .saturating_sub(held.iter().map(|h| h.bytes).sum());
        self.buffered_count = self.buffered_count.saturating_sub(held.len());
    }

    fn restart_plan(&mut self) {
        self.windows.clear();
        self.released_by.clear();
        self.refilled.clear();
        // Nothing above the tip stays verified: it is all asked again.
        let _above = self.received.split_off(&self.applied.1.saturating_add(1));
        self.received
            .entry(self.applied.1)
            .or_default()
            .insert(self.applied.0);
        self.verified = self.received.values().flatten().copied().collect();
        self.planned_to = self.applied.1;
        self.frontier = self.applied.1;
        for slot in self.peers.values_mut() {
            slot.headers.clear();
            // Outstanding window answers stay window answers: what they bring
            // is still checked (range, anchor, verification) and held, never
            // passed on unchecked; their windows are simply gone.
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
        // A departed peer's evidence of a fork no longer counts.
        self.fork_votes.remove(peer);
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
            link: Link::default(),
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
            link: Link::default(),
        });
    }

    /// The anchor for a window starting at `lo` when asking `peer`.
    fn anchor_for(&self, slot: &PeerSlot, lo: u64) -> Option<(Hash, u64)> {
        let at = lo.checked_sub(1)?;
        if at == self.applied.1 {
            return Some((self.applied.0, at));
        }
        if at < self.applied.1.saturating_sub(REFILL_DEPTH) {
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
        if self.stand_down_until.is_some_and(|t| now >= t) {
            self.stand_down_until = None;
            self.off_branch = false;
            self.fork_votes.clear();
            self.restart_plan();
            self.last_progress = now;
        }
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
            let turned = slot.admissible && !p.admissible;
            slot.head_height = p.head_height;
            slot.admissible = p.admissible;
            if turned {
                // No longer to be asked: what it holds goes back to the pool,
                // and its fork vote no longer counts.
                self.drop_outstanding(&p.id, false, now);
                self.fork_votes.remove(&p.id);
            }
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
                    refill: false,
                },
            );
            self.planned_to = hi;
        }
    }

    /// First height of `lo..=hi` neither verified nor held (`None`: all
    /// delivered, possibly still waiting for the windows below).
    fn first_missing(&self, lo: u64, hi: u64) -> Option<u64> {
        // At or below the applied tip is done.
        let mut h = lo.max(self.applied.1.saturating_add(1));
        while h <= hi {
            if !self.received.contains_key(&h) && !self.buffer.contains_key(&h) {
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
            // Drop what other answers already delivered (a refill asks again
            // for a height that is received but incomplete).
            let start = match if w.refill {
                Some(lo)
            } else {
                self.first_missing(lo, w.hi)
            } {
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
                        refill: false,
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
            // A refill deliberately asks again for one height an answer
            // already passed; anything else must not overlap.
            let overlaps = !w.refill
                && self
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
                        anchor,
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
                    link: Link::default(),
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
            let demoted = slot.demoted_until.is_some_and(|t| now < t);
            if w.failed.contains(id) || demoted {
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
                link: Link::default(),
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
            ..
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
        self.check_headers(from, e.last_height.min(self.frontier));
        // The deliverer's own consistency: blocks in its window that did not
        // chain from its anchor, or its own headers missing from what it
        // delivered, are charged to it.
        // Only complete groups: the answer's last height may have been cut.
        let top = e.last_height.min(hi).saturating_sub(1);
        let own_mismatch = top >= lo
            && self.peers.get(peer).is_some_and(|slot| {
                slot.headers
                    .range(lo..=top)
                    .any(|(_, x)| !e.link.chain.contains(x))
            });
        if e.link.unlinked > 0 || own_mismatch {
            self.strike(peer, now);
        }
        // The window: done, or its remainder goes back to the pool.
        match self.first_missing(lo, hi) {
            None => {
                self.windows.remove(&lo);
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

    /// Headers the verified blocks from `from` to `to` contradict are
    /// dropped from that height up (the peer is asked again from below). A
    /// disagreement alone charges no one: which side is wrong is not known
    /// from it. Strikes go only to the peer that delivered blocks: see
    /// [`Self::settle`] and [`Self::complete_front`].
    fn check_headers(&mut self, from: u64, to: u64) {
        if to < from {
            return;
        }
        for slot in self.peers.values_mut() {
            let mut cut: Option<u64> = None;
            for (h, hash) in slot.headers.range(from..=to) {
                if let Some(set) = self.received.get(h) {
                    if !set.contains(hash) {
                        cut = Some(*h);
                        break;
                    }
                }
            }
            if let Some(h) = cut {
                self.stats.contradictions = self.stats.contradictions.saturating_add(1);
                let _dropped = slot.headers.split_off(&h);
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
        // A window's answer ends at the window's top: nothing above it is
        // part of it.
        if let EntryKind::Window { hi, .. } = front.kind {
            if f > hi {
                return false;
            }
        }
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

    /// Verified held blocks at or below the frontier, height-ascending.
    /// Unverified ones stay held until their parent comes or `settle` drops
    /// them.
    fn take_releasable(&mut self) -> Vec<Block> {
        let Some(above) = self.frontier.checked_add(1) else {
            return Vec::new();
        };
        let rest = self.buffer.split_off(&above);
        let ready = std::mem::replace(&mut self.buffer, rest);
        let mut out = Vec::new();
        for (h, bs) in ready {
            let (go, stay): (Vec<Held>, Vec<Held>) = bs.into_iter().partition(|x| x.verified);
            self.forget_held(&go);
            for x in go {
                let by = self.released_by.entry(h).or_default();
                if !by.contains(&x.peer) {
                    by.push(x.peer.clone());
                }
                out.push(x.block);
            }
            if !stay.is_empty() {
                self.buffer.insert(h, stay);
            }
        }
        out
    }

    /// Mark held blocks verified, lowest height first: a block is verified
    /// when its selected parent is a verified block one height below (the
    /// applied tip is verified). A verified block whose merge parent is
    /// neither verified nor held asks for its parent's height again
    /// ([`Self::refill`]): the answer that carried that height left a block
    /// out. Then advance the frontier over verified heights.
    fn verify_held(&mut self) {
        let mut want: Vec<u64> = Vec::new();
        let heights: Vec<u64> = self.buffer.keys().copied().collect();
        for h in heights {
            let Some(below) = h.checked_sub(1) else {
                continue;
            };
            let mut newly: Vec<Hash> = Vec::new();
            if let Some(held) = self.buffer.get_mut(&h) {
                for x in held.iter_mut().filter(|x| !x.verified) {
                    let hdr = &x.block.header;
                    let linked = self
                        .received
                        .get(&below)
                        .is_some_and(|set| set.contains(&hdr.selected_parent_hash));
                    if linked {
                        x.verified = true;
                        newly.push(hdr.block_hash);
                        for m in &hdr.merge_parent_hashes {
                            if !self.verified.contains(m) {
                                want.push(below);
                            }
                        }
                    }
                }
            }
            for x in newly {
                self.verified.insert(x);
                self.received.entry(h).or_default().insert(x);
            }
        }
        // A merge parent may be held unverified (it is checked in its own
        // height's pass); only heights none of whose held blocks match count.
        want.sort_unstable();
        want.dedup();
        for h in want {
            self.refill(h);
        }
        self.advance_frontier();
    }

    /// Ask once more for height `h` (received but incomplete), unless it was
    /// asked for again already or is at or below the applied tip.
    fn refill(&mut self, h: u64) {
        if h <= self.applied.1.saturating_sub(REFILL_DEPTH) || self.refilled.contains(&h) {
            return;
        }
        // Asking again needs an anchor one height below on our chain; without
        // one the height counts as asked (so `settle` can decide).
        let anchorable = h
            .checked_sub(1)
            .is_some_and(|a| a == self.applied.1 || self.received.contains_key(&a));
        if !anchorable {
            // Held there and not verified yet: ask once it is.
            let held_below = h
                .checked_sub(1)
                .is_some_and(|a| self.buffer.contains_key(&a));
            if !held_below {
                self.refilled.insert(h);
            }
            return;
        }
        // A window not yet asked, or an answer not yet past `h`, may still
        // deliver it: ask later.
        let unasked = self
            .windows
            .iter()
            .any(|(lo, w)| *lo <= h && h <= w.hi && w.owner.is_none());
        let pending = self.peers.values().flat_map(|s| s.fifo.iter()).any(|e| {
            matches!(e.kind, EntryKind::Window { lo, hi, .. } if lo <= h && h <= hi)
                && (!e.started || e.last_height <= h)
        });
        if unasked || pending {
            return;
        }
        self.refilled.insert(h);
        self.stats.refills = self.stats.refills.saturating_add(1);
        self.windows.insert(
            h,
            Window {
                hi: h,
                owner: None,
                failed: Vec::new(),
                attempts: 0,
                retry_at: None,
                refill: true,
            },
        );
    }

    /// Is a refill of `h` asked for and not yet answered?
    fn refill_pending(&self, h: u64) -> bool {
        self.refilled.contains(&h) && self.windows.get(&h).is_some_and(|w| w.refill)
    }

    /// Held blocks whose selected parent is missing, at or just above the
    /// frontier once nothing in flight can still deliver it. The first time,
    /// the parent's height is asked for again (an answer cut mid-group, or a
    /// sibling left out). If that does not bring it, the blocks cannot connect
    /// to our chain: they are dropped and their window goes back to the pool,
    /// with that peer tried last, and tried later in general when this is
    /// provable (the parent's height is verified and final and was already
    /// asked for again). That is never a strike: off our applied branch is
    /// not off the network's, and during a split an honest peer serves the
    /// heavier sibling branch. When the fork is at our applied tip itself, the
    /// pipeline stands aside (`stand_down`) so the tick's fork-point search
    /// heals the node. The stall valve charges a delivery that was released
    /// (so connected to our chain) and never applied.
    fn settle(&mut self, now: Instant) {
        let Some(next) = self.frontier.checked_add(1) else {
            return;
        };
        let in_flight: Vec<(u64, u64)> = self
            .peers
            .values()
            .flat_map(|s| s.fifo.iter())
            .filter_map(|e| match e.kind {
                // An answer already past a height has delivered all of it it
                // will.
                EntryKind::Window { lo, hi, .. } if !e.started || e.last_height <= hi => {
                    Some((lo.max(if e.started { e.last_height } else { lo }), hi))
                }
                _ => None,
            })
            .collect();
        let covered_in_flight = |h: u64| in_flight.iter().any(|(lo, hi)| *lo <= h && h <= *hi);
        let mut stuck: Vec<(u64, PeerId, u64, u64)> = Vec::new();
        for (h, held) in self.buffer.range(..=next) {
            let Some(below) = h.checked_sub(1) else {
                continue;
            };
            if *h == next && covered_in_flight(below) {
                continue;
            }
            let held_below: HashSet<Hash> = self
                .buffer
                .get(&below)
                .map(|v| v.iter().map(|y| y.block.header.block_hash).collect())
                .unwrap_or_default();
            for x in held.iter().filter(|x| !x.verified) {
                // Waiting on a held parent that is itself waiting: only the
                // lowest missing block is asked for.
                if held_below.contains(&x.block.header.selected_parent_hash) {
                    continue;
                }
                stuck.push((below, x.peer.clone(), x.win_lo, x.win_hi));
            }
        }
        let frontier = self.frontier;
        let mut drop: Vec<(PeerId, u64, u64)> = Vec::new();
        let mut proven: Vec<PeerId> = Vec::new();
        for (below, peer, win_lo, win_hi) in stuck {
            if !self.refilled.contains(&below) {
                self.refill(below);
            } else if !self.refill_pending(below) && !covered_in_flight(below) {
                // Provably off our chain: its parent's height is verified and
                // final (at or below the frontier, nothing in flight for it)
                // and was asked for once more, and the parent is not there.
                if below <= frontier && !proven.contains(&peer) {
                    proven.push(peer.clone());
                }
                // Its chain forks at our applied tip: the network extends a
                // branch other than ours. That is the fork-point search's
                // job (sync_rejoin, on the tick's path), not the pipeline's.
                // Only when nothing extends our tip: no verified block above it
                // and nothing in flight or planned that could bring one.
                let next_tip = self.applied.1.saturating_add(1);
                if below == self.applied.1
                    && !self.received.contains_key(&next_tip)
                    && !covered_in_flight(next_tip)
                    && !self
                        .windows
                        .iter()
                        .any(|(lo, w)| *lo <= next_tip && next_tip <= w.hi && w.owner.is_none())
                {
                    self.fork_votes.insert(peer.clone());
                }
                let key = (peer, win_lo, win_hi);
                if !drop.contains(&key) {
                    drop.push(key);
                }
            }
        }
        // Off OUR chain is not proof of a bad peer: during a split an honest
        // peer serves the heavier sibling branch. So it is only tried later
        // (its rate quartered, and for `stand_down` asked only when no one
        // else can be), never struck or excluded for this.
        for p in &proven {
            self.stats.unconnected_deprioritized =
                self.stats.unconnected_deprioritized.saturating_add(1);
            if let Some(slot) = self.peers.get_mut(p) {
                slot.rate_milli = Some(slot.rate_milli.unwrap_or(PRIOR_RATE_MILLI) / 4);
                slot.demoted_until = now.checked_add(self.config.stand_down);
            }
        }
        // More than half of the peers that may be asked deliver a branch
        // forking at our tip: one peer alone cannot make the pipeline stand
        // aside.
        let askable = self.peers.values().filter(|s| s.admissible).count();
        if self.fork_votes.len().saturating_mul(2) > askable {
            self.off_branch = true;
        }
        if self.off_branch && self.stand_down_until.is_none() {
            self.stats.stood_down = self.stats.stood_down.saturating_add(1);
            self.stand_down_until = now.checked_add(self.config.stand_down);
            // Time standing aside is not a stall of the pipeline's making.
            self.last_progress = now;
        }
        for (peer, win_lo, win_hi) in drop {
            let mut emptied: Vec<u64> = Vec::new();
            for (h, held) in self.buffer.range_mut(win_lo..=win_hi) {
                let (gone, keep): (Vec<Held>, Vec<Held>) = std::mem::take(held)
                    .into_iter()
                    .partition(|x| !x.verified && x.peer == peer && x.win_lo == win_lo);
                self.buffered_bytes = self
                    .buffered_bytes
                    .saturating_sub(gone.iter().map(|x| x.bytes).sum());
                self.buffered_count = self.buffered_count.saturating_sub(gone.len());
                *held = keep;
                if held.is_empty() {
                    emptied.push(*h);
                }
            }
            for h in emptied {
                self.buffer.remove(&h);
            }
            self.stats.unconnected = self.stats.unconnected.saturating_add(1);
            if let Some(start) = self.first_missing(win_lo.max(next), win_hi) {
                self.plan_gap(start, win_hi, &peer);
            }
        }
    }

    /// Put `start..=hi` (what a dropped delivery uncovered) back in the pool,
    /// trimmed so it overlaps no window already planned, with `failed_by`
    /// tried last.
    fn plan_gap(&mut self, start: u64, hi: u64, failed_by: &PeerId) {
        let covered = self
            .windows
            .range(..=start)
            .next_back()
            .is_some_and(|(_, w)| start <= w.hi);
        if covered {
            return;
        }
        let next_lo = self
            .windows
            .range(start.saturating_add(1)..)
            .next()
            .map(|(lo, _)| *lo);
        let hi = match next_lo {
            Some(n) => hi.min(n.saturating_sub(1)),
            None => hi,
        }
        .max(start);
        self.windows.insert(
            start,
            Window {
                hi,
                owner: None,
                failed: vec![failed_by.clone()],
                attempts: 1,
                retry_at: None,
                refill: false,
            },
        );
    }

    fn over_caps(&self, bytes: usize) -> bool {
        self.buffered_count >= self.config.max_held_blocks
            || self.buffered_bytes.saturating_add(bytes) > self.config.max_held_bytes
    }

    /// Unverified blocks and bytes each peer holds in the buffer.
    fn holdings(&self) -> HashMap<PeerId, (usize, usize)> {
        let mut out: HashMap<PeerId, (usize, usize)> = HashMap::new();
        for x in self.buffer.values().flatten().filter(|x| !x.verified) {
            let e = out.entry(x.peer.clone()).or_insert((0, 0));
            e.0 = e.0.saturating_add(1);
            e.1 = e.1.saturating_add(x.bytes);
        }
        out
    }

    /// One peer's fair share of the buffer: its caps split over the peers
    /// that may be asked.
    fn share(&self) -> (usize, usize) {
        let n = self.peers.values().filter(|s| s.admissible).count().max(1);
        (
            self.config.max_held_blocks.checked_div(n).unwrap_or(0),
            self.config.max_held_bytes.checked_div(n).unwrap_or(0),
        )
    }

    /// Room for one more block of `bytes` at height `h` from `peer`. While
    /// the buffer is at its caps, the unverified block farthest above the
    /// frontier of the heaviest holder over its share is evicted (its window
    /// goes back to the pool with that peer tried last), provided it lies
    /// above `h` or belongs to another peer. If no room can be made, the
    /// block is refused. Nobody is charged for volume: eviction bounds the
    /// memory, and an honest peer's blocks can be over its share only because
    /// they wait behind a slow peer's gap. A delivery that never connects is
    /// dropped by `settle`, and one that was released and never applied is
    /// charged by the stall valve.
    fn make_room(&mut self, peer: &PeerId, h: u64, bytes: usize) -> bool {
        let (share_blocks, share_bytes) = self.share();
        while self.over_caps(bytes) {
            let holdings = self.holdings();
            let heavy = holdings
                .iter()
                .filter(|(_, (n, b))| *n > share_blocks || *b > share_bytes)
                .max_by(|a, b| a.1 .0.cmp(&b.1 .0).then_with(|| b.0 .0.cmp(&a.0 .0)))
                .map(|(p, _)| p.clone());
            let victim = heavy.and_then(|hp| {
                self.buffer
                    .iter()
                    .rev()
                    .flat_map(|(vh, v)| v.iter().enumerate().map(move |(i, x)| (*vh, i, x)))
                    .find(|(_, _, x)| !x.verified && x.peer == hp)
                    .map(|(vh, i, x)| (vh, i, x.peer.clone(), x.win_lo, x.win_hi))
            });
            let Some((vh, i, vp, win_lo, win_hi)) = victim else {
                break;
            };
            if vp == *peer && vh <= h {
                break;
            }
            if let Some(v) = self.buffer.get_mut(&vh) {
                if i < v.len() {
                    let gone = v.remove(i);
                    self.buffered_bytes = self.buffered_bytes.saturating_sub(gone.bytes);
                    self.buffered_count = self.buffered_count.saturating_sub(1);
                }
                if v.is_empty() {
                    self.buffer.remove(&vh);
                }
            }
            self.stats.held_evictions = self.stats.held_evictions.saturating_add(1);
            // What the eviction uncovered is asked for again, elsewhere first.
            if let Some(start) = self.first_missing(vh, win_hi.max(vh)) {
                self.plan_gap(start, win_hi.max(start), &vp);
            }
            let _ = win_lo;
        }
        !self.over_caps(bytes)
    }

    /// One strike against `peer`; at `max_strikes` it is excluded for a while
    /// and its windows go back to the pool.
    fn strike(&mut self, peer: &PeerId, now: Instant) {
        let exclude = match self.peers.get_mut(peer) {
            Some(slot) => {
                slot.strikes = slot.strikes.saturating_add(1);
                if slot.strikes >= self.config.max_strikes {
                    slot.strikes = 0;
                    // 1, 2, 4, ... 32 x `exclusion` (a lookup, no shift).
                    const FACTOR: [u32; 6] = [1, 2, 4, 8, 16, 32];
                    let idx = usize::try_from(slot.exclusions).unwrap_or(usize::MAX);
                    let factor = FACTOR.get(idx).copied().unwrap_or(32);
                    slot.exclusions = slot.exclusions.saturating_add(1);
                    slot.excluded_until =
                        now.checked_add(self.config.exclusion.saturating_mul(factor));
                    true
                } else {
                    false
                }
            }
            None => false,
        };
        if exclude {
            self.drop_outstanding(peer, false, now);
        }
    }

    /// Take in one block of a window answer from `peer`, if it belongs: in
    /// `[anchor height, hi]`, chaining from the anchor (or referencing an
    /// anchor-height sibling, which is then taken in too), within the
    /// request's allowance and the buffer's caps. Returns how many blocks
    /// were new.
    fn take_in(&mut self, peer: &PeerId, b: Block, out_now: &mut Vec<Block>) -> usize {
        let Some(slot) = self.peers.get_mut(peer) else {
            return 0;
        };
        let Some(e) = slot.fifo.front_mut() else {
            return 0;
        };
        let EntryKind::Window {
            lo,
            hi,
            anchor,
            anchor_height,
            count,
        } = e.kind
        else {
            return 0;
        };
        let h = b.header.height;
        if h < anchor_height || h > hi {
            return 0;
        }
        if e.link.chain.is_empty() {
            e.link.chain.insert(anchor);
        }
        let allowance = usize::try_from(count)
            .unwrap_or(usize::MAX)
            .saturating_add(ANSWER_SLACK);
        if e.link.accepted >= allowance {
            return 0;
        }
        let mut take: Vec<Block> = Vec::new();
        let mut gap: Option<u64> = None;
        if h == anchor_height {
            if b.header.block_hash == anchor {
                take.push(b);
            } else if e.link.anchor_group.len() < MAX_ANCHOR_GROUP {
                e.link.anchor_group.push(b);
            }
        } else {
            let hdr = &b.header;
            let parents: Vec<Hash> = std::iter::once(hdr.selected_parent_hash)
                .chain(hdr.merge_parent_hashes.iter().copied())
                .collect();
            let mut linked = parents.iter().any(|p| e.link.chain.contains(p));
            // Anchor-height siblings it references are taken in with it.
            let (refd, rest): (Vec<Block>, Vec<Block>) = std::mem::take(&mut e.link.anchor_group)
                .into_iter()
                .partition(|g| parents.contains(&g.header.block_hash));
            e.link.anchor_group = rest;
            if !refd.is_empty() {
                linked = true;
                take.extend(refd);
            }
            if linked {
                take.push(b);
            } else if e.link.gaps < MAX_GAPS {
                // Its selected parent, one height below inside this answer,
                // was left out (an answer cut mid-group, or a sibling
                // omitted): taken in, unverified, and that height is asked
                // for again. A few per answer; more is not an honest answer.
                e.link.gaps = e.link.gaps.saturating_add(1);
                gap = h.checked_sub(1);
                take.push(b);
            } else {
                e.link.unlinked = e.link.unlinked.saturating_add(1);
            }
        }
        let applied = self.applied.1;
        let mut fresh = 0usize;
        for b in take {
            let Some(e) = self.peers.get_mut(peer).and_then(|s| s.fifo.front_mut()) else {
                break;
            };
            e.link.chain.insert(b.header.block_hash);
            e.link.accepted = e.link.accepted.saturating_add(1);
            let bh = b.header.height;
            if bh <= applied {
                // At or below the tip (a refill, or the anchor group): only a
                // block on our verified chain goes to admission, at once.
                let hdr = &b.header;
                let on_chain = bh.checked_sub(1).is_some_and(|below| {
                    self.received
                        .get(&below)
                        .is_some_and(|set| set.contains(&hdr.selected_parent_hash))
                });
                if on_chain && self.verified.insert(hdr.block_hash) {
                    self.received.entry(bh).or_default().insert(hdr.block_hash);
                    fresh = fresh.saturating_add(1);
                    out_now.push(b);
                }
                continue;
            }
            let hash = b.header.block_hash;
            let known = self.verified.contains(&hash)
                || self
                    .buffer
                    .get(&bh)
                    .is_some_and(|v| v.iter().any(|x| x.block.header.block_hash == hash));
            if known {
                continue;
            }
            let bytes = block_bytes(&b);
            if !self.make_room(peer, bh, bytes) {
                self.stats.held_cap_drops = self.stats.held_cap_drops.saturating_add(1);
                continue;
            }
            self.buffered_bytes = self.buffered_bytes.saturating_add(bytes);
            self.buffered_count = self.buffered_count.saturating_add(1);
            let siblings = self.buffer.entry(bh).or_default();
            siblings.push(Held {
                block: b,
                bytes,
                peer: peer.clone(),
                win_lo: lo,
                win_hi: hi,
                verified: false,
            });
            let per_height = u64::try_from(siblings.len()).unwrap_or(u64::MAX);
            self.max_siblings = self.max_siblings.max(per_height);
            fresh = fresh.saturating_add(1);
        }
        if let Some(below) = gap {
            self.refill(below);
        }
        fresh
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
        let mut new_blocks = 0usize;
        let total = validated.len();
        let mut immediate = Vec::new();
        for b in validated {
            new_blocks = new_blocks.saturating_add(self.take_in(peer, b, &mut immediate));
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
        self.verify_held();
        self.settle(now);
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
        );
    }

    /// Timeouts and the stall valve.
    pub fn poll(&mut self, now: Instant) -> PollOutcome {
        let mut out = PollOutcome::default();
        // Settle what is held even when no answer is arriving (a refill or a
        // re-plan may be all that is left to do).
        self.verify_held();
        self.settle(now);
        out.flushed.extend(self.take_releasable());
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
        // Stall valve: the pipeline runs and the applied tip has not moved
        // for `stall_timeout`, whether or not anything is held. What was
        // released at the next height did not apply: its deliverers are
        // charged and tried last, and the plan restarts from the tip.
        if self.active()
            && now.saturating_duration_since(self.last_progress) > self.config.stall_timeout
        {
            self.stats.stall_flushes = self.stats.stall_flushes.saturating_add(1);
            let next = self.applied.1.saturating_add(1);
            let suspects = self.released_by.get(&next).cloned().unwrap_or_default();
            let all = std::mem::take(&mut self.buffer);
            self.buffered_bytes = 0;
            self.buffered_count = 0;
            for (_, bs) in all {
                out.flushed
                    .extend(bs.into_iter().filter(|h| h.verified).map(|h| h.block));
            }
            self.restart_plan();
            for p in &suspects {
                self.strike(p, now);
            }
            self.extend_windows();
            if let Some(w) = self.windows.get_mut(&next) {
                w.failed = suspects;
            }
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
    fn headers_that_disagree_with_delivered_blocks_are_dropped_without_charging_anyone() {
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
        for round in 0..300 {
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
            // `fork` never answers: its windows time out and go to `honest`.
            let _ = pl.poll(now);
            let _ = round;
        }
        // The disagreeing headers are dropped each time they come back; a
        // disagreement alone charges no one (the peer delivered nothing).
        assert!(pl.stats().contradictions >= 3);
        for f in pl.peer_figures(now) {
            assert!(!f.excluded, "{} excluded", f.id.0);
        }
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
        // What is held never connected (the window below never came): it is
        // dropped, not handed to admission, and the plan restarts.
        assert!(out.flushed.is_empty());
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

    fn block_on(h: u64, id: u64, parent: Hash) -> Block {
        BlockBuilder::new()
            .hash(hash(h, id))
            .parent(parent)
            .height(h)
            .timestamp(1_000 + h)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed()
    }

    /// An answer may only bring in blocks of the window it answers, that
    /// chain from its anchor, and no more of them than the request allows:
    /// continuing past the window, blocks that do not link, and an oversized
    /// sibling set are all left out.
    #[test]
    fn an_answer_only_brings_in_linked_blocks_of_its_own_window() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        let (p, _, lo, hi) = blocks_of(&reqs)[0].clone();
        assert_eq!((lo, hi), (1, 64));
        let mut released: Vec<Block> = Vec::new();
        // The window itself, then the same answer "continuing" to 2,000.
        let mut all = groups(0, 64);
        all.extend(groups(65, 2_000));
        for c in all.chunks(200) {
            let o = pl.on_blocks(&p, raw_of(c), c.to_vec(), now);
            // A message that is no pipeline answer goes the legacy way
            // (admission and its bounded orphan buffer), not into the pipeline.
            if o.is_pipeline() {
                released.extend(o.release);
            }
        }
        assert!(
            released.iter().all(|b| b.header.height <= hi),
            "a block above the window was taken in"
        );
        assert!(pl.frontier() <= hi);
        assert_eq!(pl.stats().buffered_blocks, 0);
        // A second window: blocks that do not chain from its anchor, and
        // hundreds of linked siblings per height, are not all held.
        feed_headers(&mut pl, &reqs, 600, now);
        let _ = pl.plan(now, &peers, true);
        let (p2, lo2, hi2) = pl.in_flight_windows()[0].clone();
        assert!(lo2 > hi, "the next window");
        let mut flood: Vec<Block> = vec![block_on(lo2 - 1, 0, hash(lo2 - 2, 0))];
        for h in lo2..=hi2 {
            let parent = if h == lo2 {
                hash(h - 1, 0)
            } else {
                hash(h - 1, 1_000)
            };
            for i in 0..400 {
                flood.push(block_on(h, 1_000 + i, parent));
            }
            flood.push(block_on(h, 9_999, Hash::new([0xEE; 32])));
        }
        for c in flood.chunks(500) {
            let _ = pl.on_blocks(&p2, raw_of(c), c.to_vec(), now);
        }
        let held = pl.stats().buffered_blocks;
        assert!(held <= 512 + 64, "one answer held {held} blocks");
    }

    /// A peer that answers its windows with a chain that does not connect to
    /// ours (and claims headers for it) cannot have honest peers excluded or
    /// its blocks released: disagreement is charged to the peer that
    /// delivered the blocks, and heights count as received only on a chain
    /// that connects to the applied tip.
    #[test]
    fn header_disagreement_is_charged_to_the_peer_that_delivered_the_blocks() {
        let t0 = Instant::now();
        let config = PipelineConfig {
            engage_gap: 0,
            ..PipelineConfig::default()
        };
        let mut pl = BlockPipeline::new(config, t0);
        pl.observe_applied((hash(0, 0), 0), t0);
        let target = 600;
        pl.set_target(target);
        let peers = [peer("a", target), peer("b", target), peer("m", target)];
        let fake = |from: u64, to: u64| -> Vec<Block> {
            (from..=to)
                .flat_map(|h| {
                    (0..7).map(move |i| block_on(h, 90 + i, hash(h.saturating_sub(1), 90)))
                })
                .collect()
        };
        let mut now = t0;
        let mut applied = 0u64;
        for _ in 0..8_000 {
            now += Duration::from_millis(50);
            let reqs = pl.plan(now, &peers, true);
            for r in &reqs {
                if let PipelineRequest::Headers {
                    peer, from_height, ..
                } = r
                {
                    let hs: Vec<(u64, Hash)> = if peer.0 == "m" {
                        (from_height + 1..=target)
                            .map(|h| (h, hash(h, 90)))
                            .collect()
                    } else {
                        headers(from_height + 1, target)
                    };
                    pl.on_headers(peer, &hs, now);
                }
            }
            for (p, lo, hi) in pl.fifo_windows() {
                let answer = if p.0 == "m" {
                    fake(lo - 1, hi)
                } else {
                    groups(lo - 1, hi)
                };
                let o = pl.on_blocks(&p, raw_of(&answer), answer.clone(), now);
                // Messages that answer nothing the pipeline asked (a peer's
                // late answers after it was dropped) go the legacy way.
                if !o.is_pipeline() {
                    continue;
                }
                for b in &o.release {
                    assert!(
                        b.header.block_hash.as_bytes()[8..16] < 90u64.to_be_bytes()[..],
                        "a block off our chain was released at {} (from {}, window {lo}..{hi}, parent {:?})",
                        b.header.height,
                        p.0,
                        &b.header.selected_parent_hash.as_bytes()[..16]
                    );
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
        let figs = pl.peer_figures(now);
        for honest in ["a", "b"] {
            let f = figs.iter().find(|f| f.id.0 == honest).expect("peer");
            assert!(
                !f.excluded,
                "honest peer {honest} excluded: {:?}",
                pl.stats()
            );
        }
        assert_eq!(applied, target, "{:?}", pl.stats());
    }

    /// An answer that carries only the anchor's own height-group (nothing of
    /// the window) ends cleanly when the next answer starts.
    #[test]
    fn an_answer_of_only_the_anchor_group_ends_without_panicking() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let peers = [peer("a", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        feed_headers(&mut pl, &reqs, 600, now);
        let _ = pl.plan(now, &peers, true);
        let w = pl.in_flight_windows();
        let (p, lo, _) = w[0].clone();
        let (_, lo2, hi2) = w[1].clone();
        let anchor_only = groups(lo - 1, lo - 1);
        let _ = pl.on_blocks(&p, raw_of(&anchor_only), anchor_only.clone(), now);
        let next = groups(lo2 - 1, hi2);
        let o = pl.on_blocks(&p, raw_of(&next), next.clone(), now);
        assert!(o.is_pipeline());
    }

    /// A DAG where sibling `i` at each height selects sibling `i` below it
    /// (so a missing sibling leaves its child's selected parent missing).
    fn strand(h: u64, i: u64) -> Block {
        let parent = if h == 1 { hash(0, 0) } else { hash(h - 1, i) };
        block_on(h, i, parent)
    }

    fn strands(from: u64, to: u64, skip: &[(u64, u64)]) -> Vec<Block> {
        (from..=to)
            .flat_map(|h| (0..7).map(move |i| (h, i)))
            .filter(|k| !skip.contains(k))
            .map(|(h, i)| if h == 0 { block(0, i) } else { strand(h, i) })
            .collect()
    }

    /// Drive `pl` with honest peers answering every in-flight window from
    /// `serve` (lo, hi) -> blocks, the node applying a height once a block of
    /// it is released. Returns every released hash.
    fn drive_until(
        pl: &mut BlockPipeline,
        peers: &[PipelinePeer],
        target: u64,
        rounds: usize,
        mut serve: impl FnMut(&PeerId, u64, u64) -> Vec<Block>,
        mut applies: impl FnMut(&Block) -> bool,
    ) -> (HashSet<Hash>, u64) {
        let mut now = Instant::now();
        let mut released: HashSet<Hash> = HashSet::new();
        let mut by_height: BTreeMap<u64, Hash> = BTreeMap::new();
        let mut applied = 0u64;
        for _ in 0..rounds {
            now += Duration::from_millis(50);
            let reqs = pl.plan(now, peers, true);
            feed_headers(pl, &reqs, target, now);
            for (p, lo, hi) in pl.fifo_windows() {
                let answer = serve(&p, lo, hi);
                let o = pl.on_blocks(&p, raw_of(&answer), answer.clone(), now);
                if !o.is_pipeline() {
                    continue;
                }
                for b in o.release {
                    if applies(&b) {
                        by_height
                            .entry(b.header.height)
                            .or_insert(b.header.block_hash);
                    }
                    released.insert(b.header.block_hash);
                }
            }
            for b in pl.poll(now).flushed {
                if applies(&b) {
                    by_height
                        .entry(b.header.height)
                        .or_insert(b.header.block_hash);
                }
                released.insert(b.header.block_hash);
            }
            while by_height.contains_key(&(applied + 1)) {
                applied += 1;
            }
            pl.observe_applied((hash(applied, 0), applied), now);
            if applied >= target {
                break;
            }
        }
        (released, applied)
    }

    fn engaged(target: u64) -> BlockPipeline {
        let now = Instant::now();
        let config = PipelineConfig {
            engage_gap: 0,
            ..PipelineConfig::default()
        };
        let mut pl = BlockPipeline::new(config, now);
        pl.observe_applied((hash(0, 0), 0), now);
        pl.set_target(target);
        pl
    }

    /// A peer answers its windows with blocks of its own that chain onto
    /// ours (so they look connected) but never apply. Nothing marks those
    /// heights as done for good: the node, stuck, re-plans and gets them
    /// from someone else.
    #[test]
    fn blocks_that_never_apply_are_asked_for_again_elsewhere() {
        let target = 300;
        let mut pl = engaged(target);
        let peers = [peer("f", target), peer("h", target)];
        let (_, applied) = drive_until(
            &mut pl,
            &peers,
            target,
            40_000,
            |p, lo, hi| {
                if p.0 == "f" {
                    let mut v = groups(lo - 1, lo - 1);
                    v.extend((lo..=hi).map(|h| {
                        let parent = if h == lo {
                            hash(lo - 1, 0)
                        } else {
                            hash(h - 1, 50)
                        };
                        block_on(h, 50, parent)
                    }));
                    v
                } else {
                    groups(lo - 1, hi)
                }
            },
            |b| b.header.block_hash.as_bytes()[8..16] < 50u64.to_be_bytes()[..],
        );
        assert_eq!(applied, target, "{:?}", pl.stats());
    }

    /// An answer cut in the middle of a height-group (a full outbound queue
    /// drops the rest), and an answer that leaves one sibling out: the
    /// missing blocks are asked for again, and every block is released.
    #[test]
    fn a_cut_group_and_an_omitted_sibling_are_asked_for_again() {
        let target = 1_200;
        for skip in [
            // The rest of the group at 64, the top of the first window.
            vec![(64, 4), (64, 5), (64, 6)],
            // One sibling in the middle of a window.
            vec![(100, 6)],
        ] {
            let mut pl = engaged(target);
            let peers = [peer("a", target), peer("b", target)];
            let mut served_once: HashSet<(u64, u64)> = HashSet::new();
            let (released, applied) = drive_until(
                &mut pl,
                &peers,
                target,
                20_000,
                |_, lo, hi| {
                    // The first answer covering a cut height is short of it;
                    // later answers are whole.
                    let cut: Vec<(u64, u64)> = skip
                        .iter()
                        .copied()
                        .filter(|(h, _)| {
                            lo <= *h + 1 && *h <= hi && !served_once.contains(&(*h, 0))
                        })
                        .collect();
                    for (h, _) in &cut {
                        served_once.insert((*h, 0));
                    }
                    strands(lo - 1, hi, &cut)
                },
                |_| true,
            );
            assert_eq!(applied, target, "{skip:?}: {:?}", pl.stats());
            for (h, i) in &skip {
                assert!(
                    released.contains(&hash(*h, *i)),
                    "{skip:?}: block ({h}, {i}) never released: {:?}",
                    pl.stats()
                );
            }
        }
    }

    /// Everything delivered was released but the applied tip does not move:
    /// the stall valve re-plans even with nothing held.
    #[test]
    fn the_stall_valve_fires_with_an_empty_buffer() {
        let t0 = Instant::now();
        let mut pl = pipeline(t0);
        let peers = [peer("a", 10_000)];
        let reqs = pl.plan(t0, &peers, true);
        let (p, _, lo, hi) = blocks_of(&reqs)[0].clone();
        let answer = groups(lo - 1, hi);
        let o = pl.on_blocks(&p, raw_of(&answer), answer.clone(), t0);
        assert!(!o.release.is_empty());
        assert_eq!(pl.stats().buffered_blocks, 0);
        let _ = pl.poll(t0 + Duration::from_secs(31));
        assert_eq!(pl.stats().stall_flushes, 1);
        let again = blocks_of(&pl.plan(t0 + Duration::from_secs(31), &peers, true));
        assert!(
            again.iter().any(|(_, a, l, _)| *a == 0 && *l == 1),
            "{again:?}"
        );
    }

    /// At its caps the reorder buffer takes nothing more, and the answer that
    /// brought the excess is counted.
    #[test]
    fn the_reorder_buffer_takes_nothing_past_its_caps() {
        let now = Instant::now();
        let config = PipelineConfig {
            max_held_blocks: 50,
            ..PipelineConfig::default()
        };
        let mut pl = BlockPipeline::new(config, now);
        pl.observe_applied((hash(0, 0), 0), now);
        pl.set_target(10_000);
        let peers = [peer("a", 10_000), peer("b", 10_000)];
        let reqs = pl.plan(now, &peers, true);
        feed_headers(&mut pl, &reqs, 600, now);
        let _ = pl.plan(now, &peers, true);
        // Answer every window but the first: all of it waits, unverified.
        for (p, lo, hi) in pl.fifo_windows() {
            if lo == 1 {
                continue;
            }
            let a = groups(lo - 1, hi);
            let _ = pl.on_blocks(&p, raw_of(&a), a.clone(), now);
        }
        assert!(pl.stats().buffered_blocks <= 50, "{:?}", pl.stats());
        assert!(pl.stats().held_cap_drops > 0);
    }

    /// A peer fills the reorder buffer with blocks that never connect: its
    /// blocks are the ones evicted, it is charged only through `settle` (its
    /// deliveries provably never connect), the honest peer answering the
    /// frontier windows is never charged or excluded, and the node reaches
    /// the target.
    #[test]
    fn a_full_buffer_is_charged_to_the_peer_that_filled_it() {
        let t0 = Instant::now();
        let config = PipelineConfig {
            engage_gap: 0,
            window_heights: 8,
            lookahead_heights: 256,
            max_held_blocks: 600,
            ..PipelineConfig::default()
        };
        let mut pl = BlockPipeline::new(config, t0);
        pl.observe_applied((hash(0, 0), 0), t0);
        let target = 400;
        pl.set_target(target);
        let peers = [peer("b", target), peer("z", target)];
        let mut now = t0;
        let mut applied = 0u64;
        for _ in 0..4_000 {
            now += Duration::from_millis(50);
            let reqs = pl.plan(now, &peers, true);
            for r in &reqs {
                if let PipelineRequest::Headers {
                    peer, from_height, ..
                } = r
                {
                    let hs: Vec<(u64, Hash)> = if peer.0 == "z" {
                        (from_height + 1..=target)
                            .map(|h| (h, hash(h, 90)))
                            .collect()
                    } else {
                        headers(from_height + 1, target)
                    };
                    pl.on_headers(peer, &hs, now);
                }
            }
            for (p, lo, hi) in pl.fifo_windows() {
                let answer: Vec<Block> = if p.0 == "z" {
                    (lo - 1..=hi)
                        .flat_map(|h| {
                            (0..7).map(move |i| block_on(h, 90 + i, hash(h.saturating_sub(1), 90)))
                        })
                        .collect()
                } else {
                    groups(lo - 1, hi)
                };
                let o = pl.on_blocks(&p, raw_of(&answer), answer.clone(), now);
                if p.0 == "b" {
                    let strikes = pl.peers.get(&p).map(|s| s.strikes).unwrap_or(0);
                    assert_eq!(strikes, 0, "honest b charged: {:?}", pl.stats());
                }
                let _ = o;
            }
            let _ = pl.poll(now);
            let b = pl.peers.get(&pid("b")).expect("b");
            assert!(!b.excluded(now), "honest b excluded: {:?}", pl.stats());
            if pl.frontier() > applied {
                applied = pl.frontier();
                pl.observe_applied((hash(applied, 0), applied), now);
            }
            if applied >= target {
                break;
            }
        }
        assert_eq!(applied, target, "{:?}", pl.stats());
        assert!(
            pl.stats().held_evictions > 0,
            "the buffer filled: {:?}",
            pl.stats()
        );
        assert!(
            pl.stats().unconnected_deprioritized > 0,
            "z tried later via settle"
        );
        assert_eq!(pl.stats().overlapping_requests, 0);
    }

    /// At a fresh start with many peers and the frontier window stalled on a
    /// slow peer, honest peers whose answers wait behind it go over their
    /// share of a full buffer. They are evicted from, never struck.
    #[test]
    fn honest_peers_over_their_share_behind_a_stalled_frontier_are_never_struck() {
        let t0 = Instant::now();
        let config = PipelineConfig {
            engage_gap: 0,
            window_heights: 8,
            lookahead_heights: 256,
            max_in_flight: 32,
            max_held_blocks: 300,
            ..PipelineConfig::default()
        };
        let mut pl = BlockPipeline::new(config, t0);
        pl.observe_applied((hash(0, 0), 0), t0);
        let target = 256;
        pl.set_target(target);
        // "a" sorts first and takes the frontier window; it never answers.
        let mut peers = vec![peer("a", target)];
        peers.extend((0..20).map(|i| peer(&format!("p{i:02}"), target)));
        let mut now = t0;
        // Well inside the slow peer's timeout: the frontier stays stalled.
        for _ in 0..150 {
            now += Duration::from_millis(50);
            let reqs = pl.plan(now, &peers, true);
            feed_headers(&mut pl, &reqs, target, now);
            for (p, lo, hi) in pl.fifo_windows() {
                if p.0 == "a" {
                    continue;
                }
                let answer = groups(lo - 1, hi);
                let _ = pl.on_blocks(&p, raw_of(&answer), answer.clone(), now);
            }
            let _ = pl.poll(now);
            for (id, slot) in &pl.peers {
                assert_eq!(slot.strikes, 0, "{} struck: {:?}", id.0, pl.stats());
                assert!(!slot.excluded(now), "{} excluded", id.0);
            }
        }
        assert!(
            pl.stats().held_evictions > 0,
            "the buffer filled: {:?}",
            pl.stats()
        );
        assert!(pl.stats().buffered_blocks <= 300);
    }

    /// A split: our applied tip is on a lighter branch, and the only peer
    /// serves the heavier one, whose blocks never connect to our tip. That
    /// peer is never struck or excluded, and the pipeline steps aside so the
    /// fork-point search (the tick's rejoin path) can heal the node.
    #[test]
    fn a_peer_serving_the_heavier_branch_is_never_excluded_and_the_pipeline_steps_aside() {
        let t0 = Instant::now();
        let config = PipelineConfig {
            engage_gap: 0,
            ..PipelineConfig::default()
        };
        let mut pl = BlockPipeline::new(config, t0);
        // Our tip: height 10 of branch "50" (the network's is branch "0").
        pl.observe_applied((hash(10, 50), 10), t0);
        let target = 400;
        pl.set_target(target);
        let peers = [peer("h", target)];
        let mut now = t0;
        let mut stepped_aside = false;
        for _ in 0..2_000 {
            now += Duration::from_millis(50);
            let reqs = pl.plan(now, &peers, true);
            feed_headers(&mut pl, &reqs, target, now);
            for (p, lo, hi) in pl.fifo_windows() {
                let answer = groups(lo - 1, hi);
                let _ = pl.on_blocks(&p, raw_of(&answer), answer.clone(), now);
            }
            let _ = pl.poll(now);
            let h = pl.peers.get(&pid("h")).expect("h");
            assert_eq!(
                h.strikes,
                0,
                "the heavier branch's peer struck: {:?}",
                pl.stats()
            );
            assert!(!h.excluded(now), "the heavier branch's peer excluded");
            if !pl.active() {
                stepped_aside = true;
                break;
            }
        }
        assert!(
            stepped_aside,
            "the pipeline kept the node off the rejoin path: {:?}",
            pl.stats()
        );
    }

    /// Our tip on a lighter branch, `forks` of `peers` serving the heavier
    /// one (the rest silent), driven until the pipeline steps aside or
    /// `rounds` pass. Returns whether it stepped aside, and the time.
    fn split_rounds(
        pl: &mut BlockPipeline,
        peers: &[PipelinePeer],
        forks: &[&str],
        t0: Instant,
        rounds: usize,
    ) -> (bool, Instant) {
        let mut now = t0;
        for _ in 0..rounds {
            now += Duration::from_millis(50);
            let reqs = pl.plan(now, peers, true);
            feed_headers(pl, &reqs, 400, now);
            for (p, lo, hi) in pl.fifo_windows() {
                if forks.contains(&p.0.as_str()) {
                    let answer = groups(lo - 1, hi);
                    let _ = pl.on_blocks(&p, raw_of(&answer), answer.clone(), now);
                }
            }
            let _ = pl.poll(now);
            if !pl.active() {
                return (true, now);
            }
        }
        (false, now)
    }

    fn split_pipeline(t0: Instant) -> BlockPipeline {
        let config = PipelineConfig {
            engage_gap: 0,
            ..PipelineConfig::default()
        };
        let mut pl = BlockPipeline::new(config, t0);
        pl.observe_applied((hash(10, 50), 10), t0);
        pl.set_target(400);
        pl
    }

    /// One peer of three serving a branch that forks at our tip cannot make
    /// the pipeline stand aside.
    #[test]
    fn a_minority_cannot_make_the_pipeline_stand_aside() {
        let t0 = Instant::now();
        let mut pl = split_pipeline(t0);
        let peers = [peer("f", 400), peer("x", 400), peer("y", 400)];
        // Well inside the silent peers' timeouts.
        let (stepped, _) = split_rounds(&mut pl, &peers, &["f"], t0, 150);
        assert!(!stepped, "{:?}", pl.stats());
        assert_eq!(pl.stats().stood_down, 0);
    }

    /// After standing aside the pipeline resumes: when the applied tip moves
    /// (the node healed), and after `stand_down` if it did not.
    #[test]
    fn the_pipeline_resumes_after_standing_aside() {
        let t0 = Instant::now();
        let peers = [peer("h", 400)];
        // The tip moves.
        let mut pl = split_pipeline(t0);
        let (stepped, now) = split_rounds(&mut pl, &peers, &["h"], t0, 2_000);
        assert!(stepped);
        pl.observe_applied((hash(11, 0), 11), now);
        assert!(pl.active(), "resumes when the tip moves");
        assert!(!blocks_of(&pl.plan(now, &peers, true)).is_empty());
        // The tip does not move: back after `stand_down`.
        let mut pl = split_pipeline(t0);
        let (stepped, now) = split_rounds(&mut pl, &peers, &["h"], t0, 2_000);
        assert!(stepped);
        let later = now + Duration::from_secs(61);
        let _ = pl.plan(later, &peers, true);
        assert!(pl.active(), "resumes after stand_down");
    }

    /// A peer that disconnects takes its fork vote with it.
    #[test]
    fn a_disconnected_peers_fork_vote_is_dropped() {
        let t0 = Instant::now();
        let mut pl = split_pipeline(t0);
        let peers = [peer("f", 400), peer("g", 400), peer("x", 400)];
        let (stepped, now) = split_rounds(&mut pl, &peers, &["f"], t0, 150);
        assert!(!stepped);
        assert_eq!(pl.fork_votes.len(), 1, "f voted");
        // f leaves: its vote goes with it.
        let rest = [peer("g", 400), peer("x", 400)];
        let _ = pl.plan(now + Duration::from_millis(50), &rest, true);
        assert!(pl.fork_votes.is_empty(), "{:?}", pl.fork_votes);
    }

    /// A peer that turns inadmissible loses the windows it held.
    #[test]
    fn a_peer_that_turns_inadmissible_loses_its_windows() {
        let now = Instant::now();
        let mut pl = pipeline(now);
        let _ = pl.plan(now, &[peer("a", 10_000)], true);
        assert_eq!(pl.in_flight_windows().len(), 1);
        let mut a = peer("a", 10_000);
        a.admissible = false;
        let _ = pl.plan(now, &[a, peer("b", 10_000)], true);
        let w = pl.in_flight_windows();
        assert!(w.iter().all(|(p, _, _)| p.0 != "a"), "{w:?}");
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
