// citrate/core/network/src/peer.rs

// Peer connection and management
use crate::{NetworkError, NetworkMessage, ProtocolVersion};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use citrate_consensus::types::Hash;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, RwLock};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, info, warn};

/// Unique peer identifier
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn random() -> Self {
        Self(format!("peer_{}", rand::random::<u64>()))
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Peer connection state
#[derive(Debug, Clone, PartialEq)]
pub enum PeerState {
    Connecting,
    Handshaking,
    Connected,
    Disconnecting,
    Disconnected,
}

/// Peer connection direction
#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Information about a peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub state: PeerState,
    pub direction: Direction,
    pub version: Option<ProtocolVersion>,
    pub head_height: u64,
    pub head_hash: Hash,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub score: i32,
    /// Consecutive messages dropped because this peer's send queue was full.
    ///
    /// Reset to 0 on every successful queue. A sustained non-zero value is the
    /// signal that the peer has stopped reading its socket — see
    /// [`Peer::send`] and [`Peer::SEND_DROPS_BEFORE_CLOSE`].
    pub send_drops: u32,
}

impl PeerInfo {
    pub fn new(id: PeerId, addr: SocketAddr, direction: Direction) -> Self {
        let now = Instant::now();
        Self {
            id,
            addr,
            state: PeerState::Connecting,
            direction,
            version: None,
            head_height: 0,
            head_hash: Hash::default(),
            connected_at: now,
            last_seen: now,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            score: 0,
            send_drops: 0,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }
}

/// Individual peer connection
pub struct Peer {
    pub info: Arc<RwLock<PeerInfo>>,
    pub send_tx: mpsc::Sender<NetworkMessage>,
    pub recv_tx: mpsc::Receiver<NetworkMessage>,
    /// Connection-close signal for the reader/writer tasks that own this
    /// connection's socket halves (see [`Peer::close`]).
    shutdown: Arc<Notify>,
    /// Latched close flag. `Notify` only wakes tasks that are already parked,
    /// so a task that is between awaits when `close()` fires would miss the
    /// notification — it re-checks this instead. Latched, never cleared: a
    /// closed connection is never reopened, a new one is built.
    closed: Arc<AtomicBool>,
}

impl Peer {
    pub fn new(
        info: PeerInfo,
        send_tx: mpsc::Sender<NetworkMessage>,
        recv_tx: mpsc::Receiver<NetworkMessage>,
    ) -> Self {
        Self {
            info: Arc::new(RwLock::new(info)),
            send_tx,
            recv_tx,
            shutdown: Arc::new(Notify::new()),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Tell this connection's reader and writer tasks to stop, which drops the
    /// socket halves they own and actually closes the TCP connection.
    ///
    /// WHY THIS EXISTS (fleet incident 2026-07-29). `PeerManager::add_peer`
    /// dedups by `peer_id`: a reconnecting peer replaces the map entry. But
    /// replacing the entry only dropped the OLD `Arc<Peer>` — it never touched
    /// the old connection's tasks, which kept running and kept owning their
    /// socket. Every reconnect therefore leaked one live TCP connection.
    ///
    /// boot1 accumulated **25 established connections on :30303** that way. The
    /// damage is not the socket count, it is that `send_to_peers` resolves a
    /// peer id to exactly ONE `Peer`, so responses were queued onto a connection
    /// whose TCP was half-open and silently discarded. rpc-1 logged
    /// `Sending 32 blocks` while boot1 received nothing and sat frozen at height
    /// 72,057 for twenty minutes — a follower that looked healthy from both ends
    /// while exchanging nothing. `send_to_peers` also discards the send result
    /// at the call site, so nothing surfaced the failure.
    ///
    /// Idempotent: calling it twice is harmless.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // `notify_waiters` (not `notify_one`) — both the reader and the writer
        // of this connection are parked on it and BOTH must stop. `notify_one`
        // would wake exactly one and leave the other holding its half open.
        self.shutdown.notify_waiters();
    }

    /// True once [`Peer::close`] has been called on this connection.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Handles for this connection's owning tasks to park on. Returns the
    /// latched flag alongside the notify so a task can close the miss-window:
    /// check the flag, then park.
    pub fn shutdown_handles(&self) -> (Arc<Notify>, Arc<AtomicBool>) {
        (self.shutdown.clone(), self.closed.clone())
    }

    /// Consecutive full-queue drops before the connection is closed as a
    /// non-consumer. One full queue is congestion; [`SEND_DROPS_BEFORE_CLOSE`]
    /// in a row is a peer that has stopped reading and will never catch up.
    pub const SEND_DROPS_BEFORE_CLOSE: u32 = 64;

    /// Queue `message` for this peer. **Never blocks.**
    ///
    /// #149 — THE FLEET DEADLOCK. THIS FUNCTION USED TO `.await` A BOUNDED
    /// `mpsc::Sender` (capacity 256), AND THAT SINGLE `.await` DEADLOCKED THE
    /// WHOLE NETWORK. Do not reintroduce it.
    ///
    /// The chain, observed end to end on chain 40204 on 2026-07-31:
    ///
    ///   1. A peer stops reading its socket. The writer task parks forever in
    ///      `sink.send(...).await` — TCP window closed, no RST, no timeout.
    ///      (rpc-1 -> boot1 sat at Send-Q 535,288 bytes.)
    ///   2. That peer's `send_tx` (256) fills, because nothing drains it.
    ///   3. Any shared task that sends to that ONE peer blocks forever here.
    ///      The node has exactly ONE inbound message loop, and it sends
    ///      responses inline, so it blocks — and it is also the only thing
    ///      draining the global inbound channel.
    ///   4. The inbound channel (512) fills. Every peer's reader task then
    ///      blocks in `PeerManager::forward_incoming`, so the node stops
    ///      reading EVERY socket. (rpc-1 <- boot1 sat at Recv-Q 681,922 bytes.)
    ///
    /// The node then serves nobody, forever, while looking healthy from every
    /// angle: no panic, no task exit, systemd `active`, `NRestarts=0`, peers
    /// connected, JSON-RPC answering, producer still minting blocks. Because no
    /// task ever ENDS, the #147 watchdog cannot see it either — that watchdog
    /// catches a dead loop, and this one is merely hung.
    ///
    /// It is also mutual and self-sustaining: the peer that stopped reading did
    /// so because it was in the same state. Two wedged nodes hold each other
    /// there, which is why restarting one never fixed it and why the fleet froze
    /// at three DIFFERENT heights rather than one.
    ///
    /// So: a peer's send queue is a bounded buffer, and a full buffer means that
    /// peer is not keeping up. The only safe response is to SHED the message and
    /// eventually drop the peer. Blocking a shared task on one slow peer trades a
    /// dropped gossip frame — which is re-requested on the next 2s sync tick —
    /// for a network-wide halt. Every caller here is a shared task (the message
    /// loop, gossip broadcast, block/tx propagation, the AI handler, the producer),
    /// so there is no call site where blocking is the right answer.
    pub async fn send(&self, message: NetworkMessage) -> Result<(), NetworkError> {
        match self.send_tx.try_send(message) {
            Ok(()) => {
                let mut info = self.info.write().await;
                info.messages_sent += 1;
                info.update_last_seen();
                info.send_drops = 0;
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                let drops = {
                    let mut info = self.info.write().await;
                    info.send_drops = info.send_drops.saturating_add(1);
                    info.send_drops
                };
                if drops >= Self::SEND_DROPS_BEFORE_CLOSE {
                    // Not congestion — this peer has stopped consuming. Close the
                    // connection so its socket halves are released and it can
                    // re-handshake clean, rather than holding a queue nobody drains.
                    warn!(
                        "Peer send queue full {} times consecutively — closing connection (peer is not reading)",
                        drops
                    );
                    self.close();
                }
                Err(NetworkError::ConnectionFailed(format!(
                    "peer send queue full ({} consecutive drops)",
                    drops
                )))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // #151 — A CLOSED CHANNEL MEANS THIS PEER IS A CORPSE. SAY SO.
                //
                // The writer task owns the receiving half, so a closed channel means
                // that task is gone: the connection died. The `Peer` object, however,
                // is still sitting in the `PeerManager` with its advertised head
                // intact — and the sync selector picks on advertised head. So it kept
                // choosing this peer, every send failed, the caller discarded the
                // error, and because a failed send never records a pending request,
                // NO TIMEOUT WAS EVER OBSERVED. The penalty box (#136) is driven
                // entirely by timeouts, so it never fired: never de-preferred, never
                // dropped, never re-handshaked. The node retried a corpse forever.
                //
                // Reproduced on chain 40204 by interrupting a syncing node's network
                // for 150s: it came back with 4 peers, a correct target, an anchor
                // every peer held — and sat at `ph=0 pb=0 req_headers=false
                // req_blocks=false` every 2s indefinitely.
                //
                // Latching `close()` here makes the corpse self-identifying, so
                // `is_closed()` is a reliable liveness test for callers that must
                // stop selecting it. Idempotent.
                self.close();
                Err(NetworkError::ConnectionFailed(
                    "peer connection is closed".to_string(),
                ))
            }
        }
    }

    pub async fn disconnect(&self, reason: String) -> Result<(), NetworkError> {
        self.send(NetworkMessage::Disconnect { reason }).await?;

        let mut info = self.info.write().await;
        info.state = PeerState::Disconnected;

        Ok(())
    }
}

/// Peer manager for handling multiple connections
type IncomingTx = mpsc::Sender<(PeerId, NetworkMessage)>;

pub struct PeerManager {
    config: PeerManagerConfig,
    peers: Arc<DashMap<PeerId, Arc<Peer>>>,
    /// Map of banned addresses to ban expiry time.
    banned_peers: Arc<DashMap<SocketAddr, Instant>>,
    /// SECREM-01 NET-4(b): map of banned IPs to ban expiry time.
    /// A SocketAddr-keyed ban is trivially evaded by reconnecting
    /// from a different source port, so bans are also recorded
    /// per-IP and `is_banned` consults this map.
    banned_ips: Arc<DashMap<IpAddr, Instant>>,
    /// SECREM-01 NET-4(b): map of banned peer IDs to ban expiry
    /// time. Where the peer's identity is known at ban time, the
    /// ban follows the identity even if the peer changes IPs.
    banned_peer_ids: Arc<DashMap<PeerId, Instant>>,
    stats: Arc<RwLock<PeerStats>>,
    pub(crate) incoming: Arc<RwLock<Option<IncomingTx>>>,
    /// Inbound messages shed because the message loop was behind (#149).
    pub(crate) inbound_drops: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
pub struct PeerManagerConfig {
    pub max_peers: usize,
    pub max_inbound: usize,
    pub max_outbound: usize,
    pub peer_timeout: Duration,
    pub ban_duration: Duration,
    pub score_threshold: i32,
}

impl Default for PeerManagerConfig {
    fn default() -> Self {
        Self {
            max_peers: 50,
            max_inbound: 30,
            max_outbound: 20,
            peer_timeout: Duration::from_secs(120),
            ban_duration: Duration::from_secs(3600),
            score_threshold: -100,
        }
    }
}

#[derive(Debug, Default)]
struct PeerStats {
    total_connected: usize,
    inbound_count: usize,
    outbound_count: usize,
}

impl PeerManager {
    pub fn new(config: PeerManagerConfig) -> Self {
        Self {
            config,
            peers: Arc::new(DashMap::new()),
            banned_peers: Arc::new(DashMap::new()),
            // SECREM-01 NET-4(b): IP-level and identity-level ban maps
            banned_ips: Arc::new(DashMap::new()),
            banned_peer_ids: Arc::new(DashMap::new()),
            stats: Arc::new(RwLock::new(PeerStats::default())),
            incoming: Arc::new(RwLock::new(None)),
            inbound_drops: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Set incoming message sink
    pub async fn set_incoming(&self, tx: mpsc::Sender<(PeerId, NetworkMessage)>) {
        *self.incoming.write().await = Some(tx);
    }

    /// Forward a received message to the configured incoming sink, if any.
    ///
    /// #149 — link 4 of the fleet deadlock. This used to `.await` the bounded
    /// (512) inbound channel. Every peer has its own reader task, and each one
    /// calls this, so once the single message loop stalled and stopped draining
    /// that channel, EVERY reader parked here — and the node stopped reading
    /// every socket it had. That is why rpc-1 sat with 681,922 bytes unread from
    /// boot1: not a slow link, a node that had stopped calling `read`.
    ///
    /// Shedding is the correct behaviour: a full inbound queue means the node is
    /// already behind on the messages it has, and blocking the reader converts
    /// local overload into a network-wide halt. Sync requests are re-issued on
    /// the 2s tick and gossip is redundant by construction, so a dropped message
    /// costs a round trip. Blocking cost the entire fleet thirty hours.
    pub async fn forward_incoming(&self, peer_id: PeerId, message: NetworkMessage) {
        if let Some(tx) = self.incoming.read().await.clone() {
            if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send((peer_id, message)) {
                self.inbound_drops.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Total inbound messages shed because the message loop was behind (#149).
    ///
    /// A rising count is genuine backpressure and is survivable. A count that
    /// rises without bound means the loop is not draining at all — which is the
    /// deadlock this counter exists to make visible instead of silent.
    pub fn inbound_drops(&self) -> u64 {
        self.inbound_drops.load(Ordering::Relaxed)
    }

    /// Get max peers configuration
    pub fn max_peers(&self) -> usize {
        self.config.max_peers
    }

    /// Connect to a peer
    pub async fn connect_to_peer(
        &self,
        peer_id: PeerId,
        addr: SocketAddr,
    ) -> Result<(), NetworkError> {
        // Check if already connected
        if self.peers.contains_key(&peer_id) {
            return Ok(());
        }

        // Check if banned
        if self.is_banned(&addr).await {
            return Err(NetworkError::ConnectionFailed("Peer is banned".to_string()));
        }

        // Create channels for communication
        let (send_tx, _send_rx) = mpsc::channel(100);
        let (_recv_tx, recv_rx) = mpsc::channel(100);

        // Create peer info and peer
        let info = PeerInfo::new(peer_id.clone(), addr, Direction::Outbound);
        let peer = Arc::new(Peer::new(info, send_tx, recv_rx));

        // Add the peer
        self.add_peer(peer).await?;

        info!("Initiated connection to peer: {} at {}", peer_id, addr);
        Ok(())
    }

    /// Add a new peer
    // LOCK ORDERING: acquires Peer.info (read) + stats (read), drops both, then stats (write) — Level 1
    pub async fn add_peer(&self, peer: Arc<Peer>) -> Result<(), NetworkError> {
        let (peer_id, direction, addr) = {
            let info = peer.info.read().await;
            (info.id.clone(), info.direction.clone(), info.addr)
        };

        // SECREM-01 NET-4(b): enforce identity- and IP-level bans at
        // the single choke point both inbound (transport handshake)
        // and outbound (connect_to_peer) paths go through.
        if self.is_peer_id_banned(&peer_id).await {
            return Err(NetworkError::ConnectionFailed(
                "Peer identity is banned".to_string(),
            ));
        }
        if self.is_banned(&addr).await {
            return Err(NetworkError::ConnectionFailed(
                "Peer address is banned".to_string(),
            ));
        }

        // Reconnect / duplicate-id guard (inbound_count leak fix). The same peer
        // reconnecting re-enters here with the SAME peer_id. `self.peers.insert`
        // below silently OVERWRITES the old map entry, but the counter increment
        // still fired — so every reconnect (and broken-pipe churn causes many)
        // leaked one inbound/outbound slot until the node wrongly reported
        // "Max inbound peers reached" with only a handful of real connections and
        // rejected ALL new followers (observed fleet-wide). Evict the stale entry's
        // accounting FIRST so re-adding the same id is net-zero, and so a prior
        // connection whose teardown never ran (e.g. a break without remove_peer) is
        // reconciled on the next connect rather than leaking forever.
        if let Some((_, old)) = self.peers.remove(&peer_id) {
            // CONNECTION DEDUP. Evicting the map entry is not enough: the old
            // connection's reader and writer tasks own the socket halves and
            // keep running, so the TCP connection stays ESTABLISHED with nothing
            // routing to it. Those orphans accumulated to 25 sockets on boot1,
            // and — because `send_to_peers` resolves an id to exactly ONE peer —
            // block responses were queued onto a half-open one and silently
            // dropped. Close it explicitly; see `Peer::close`.
            // Guard: only close if this really is a DIFFERENT connection. If a
            // caller ever re-adds the same `Arc<Peer>` (idempotent re-register),
            // closing here would tear down the very connection being added.
            if !Arc::ptr_eq(&old, &peer) {
                old.close();
            }
            let old_dir = { old.info.read().await.direction.clone() };
            let mut stats = self.stats.write().await;
            stats.total_connected = stats.total_connected.saturating_sub(1);
            match old_dir {
                Direction::Inbound => {
                    stats.inbound_count = stats.inbound_count.saturating_sub(1)
                }
                Direction::Outbound => {
                    stats.outbound_count = stats.outbound_count.saturating_sub(1)
                }
            }
            debug!("Closed superseded connection for reconnecting peer {}", peer_id);
        }

        // Check limits (the reconnecting peer is now NOT double-counted against them).
        {
            let stats = self.stats.read().await;
            if stats.total_connected >= self.config.max_peers {
                return Err(NetworkError::ConnectionFailed(
                    "Max peers reached".to_string(),
                ));
            }
            match direction {
                Direction::Inbound if stats.inbound_count >= self.config.max_inbound => {
                    return Err(NetworkError::ConnectionFailed(
                        "Max inbound peers reached".to_string(),
                    ));
                }
                Direction::Outbound if stats.outbound_count >= self.config.max_outbound => {
                    return Err(NetworkError::ConnectionFailed(
                        "Max outbound peers reached".to_string(),
                    ));
                }
                _ => {}
            }
        }

        // Add peer
        self.peers.insert(peer_id.clone(), peer);

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_connected += 1;
        match direction {
            Direction::Inbound => stats.inbound_count += 1,
            Direction::Outbound => stats.outbound_count += 1,
        }

        info!("Added peer: {}", peer_id);
        Ok(())
    }

    /// Remove a peer
    // LOCK ORDERING: acquires Peer.info (read) then PeerManager.stats (write) — Level 1
    pub async fn remove_peer(&self, peer_id: &PeerId) -> Option<Arc<Peer>> {
        let peer = self.peers.remove(peer_id).map(|(_, p)| p);

        if let Some(ref p) = peer {
            // Drop the SOCKET, not just the map entry. Without this a dropped
            // peer keeps its TCP connection ESTABLISHED, and the sync tick's
            // drop-and-re-handshake escalation then adds a fresh connection on
            // every cycle while the dead one lingers — a connection leak driven
            // by the very mechanism meant to recover the peer.
            p.close();
            let info = p.info.read().await;
            let mut stats = self.stats.write().await;
            stats.total_connected = stats.total_connected.saturating_sub(1);
            match info.direction {
                Direction::Inbound => stats.inbound_count = stats.inbound_count.saturating_sub(1),
                Direction::Outbound => {
                    stats.outbound_count = stats.outbound_count.saturating_sub(1)
                }
            }

            info!("Removed peer: {}", peer_id);
        }

        peer
    }

    /// Remove a peer ONLY if the currently-mapped instance is `current` (same Arc).
    ///
    /// A reconnect replaces the map entry with a fresh `Peer` (see `add_peer`). The
    /// OLD connection's reader/writer tasks live on briefly and, when they finally
    /// error, call into the disconnect path — which, using the plain `remove_peer`,
    /// would evict the FRESH reconnected peer by id, churning a node down toward 0
    /// peers (observed: a follower that dropped to 0 peers and never recovered). This
    /// identity check makes a stale teardown a no-op so only the connection that owns
    /// the current mapping can remove it. Returns true if it removed.
    pub async fn remove_peer_if_current(&self, peer_id: &PeerId, current: &Arc<Peer>) -> bool {
        let is_current = self
            .peers
            .get(peer_id)
            .map(|p| Arc::ptr_eq(p.value(), current))
            .unwrap_or(false);
        if is_current {
            self.remove_peer(peer_id).await;
            true
        } else {
            false
        }
    }

    /// Get a peer by ID
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<Arc<Peer>> {
        self.peers.get(peer_id).map(|p| p.clone())
    }

    /// Get all connected peers
    pub fn get_all_peers(&self) -> Vec<Arc<Peer>> {
        self.peers.iter().map(|p| p.value().clone()).collect()
    }

    /// Get peer count by direction.
    ///
    /// Returns `(total, inbound, outbound)` where `total` is the live
    /// size of the peer map (ground truth). `inbound` and `outbound`
    /// come from the stats counter, which may drift by 1–2 during
    /// churn but converges back to the map size on the next
    /// add/remove cycle.
    ///
    /// Why this matters: `stats.total_connected` used to be the
    /// source of truth, but on a reconnecting-peer workload we
    /// observed the counter growing to 34 while the peer map had
    /// exactly 1 entry. Root cause is any code path that inserts a
    /// peer into the map without going through `add_peer()`, or a
    /// crash between `add_peer()` and subsequent `remove_peer()`.
    /// Rather than audit every `self.peers.insert` site, we trust
    /// the map for `total`.
    pub async fn get_peer_counts(&self) -> (usize, usize, usize) {
        let stats = self.stats.read().await;
        (
            self.peers.len(),
            stats.inbound_count,
            stats.outbound_count,
        )
    }

    /// Ban a peer for the configured ban duration.
    ///
    /// SECREM-01 NET-4(b): in addition to the legacy SocketAddr ban,
    /// the IP is banned so the peer cannot evade the ban by simply
    /// reconnecting from a different source port.
    pub async fn ban_peer(&self, addr: SocketAddr) {
        let expires = Instant::now() + self.config.ban_duration;
        self.banned_peers.insert(addr, expires);
        self.banned_ips.insert(addr.ip(), expires);
        warn!("Banned peer {} until {:?} ({:?} from now)", addr, expires, self.config.ban_duration);
    }

    /// Ban a peer by identity AND address/IP.
    ///
    /// SECREM-01 NET-4(b): when the peer's identity is known at ban
    /// time, record the ban against the peer ID as well so it
    /// follows the identity across IP changes. Prefer this over
    /// `ban_peer` whenever a PeerId is available.
    pub async fn ban_peer_with_id(&self, peer_id: &PeerId, addr: SocketAddr) {
        let expires = Instant::now() + self.config.ban_duration;
        self.banned_peer_ids.insert(peer_id.clone(), expires);
        self.ban_peer(addr).await;
        warn!("Banned peer identity {} until {:?}", peer_id, expires);
    }

    /// Check if an address is currently banned (expired bans are removed).
    pub async fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(entry) = self.banned_peers.get(addr) {
            if Instant::now() < *entry.value() {
                return true;
            }
            // Ban expired — remove it
            drop(entry);
            self.banned_peers.remove(addr);
        }
        // SECREM-01 NET-4(b): also enforce IP-level bans, so a new
        // source port on a banned IP is still rejected.
        if let Some(entry) = self.banned_ips.get(&addr.ip()) {
            if Instant::now() < *entry.value() {
                return true;
            }
            drop(entry);
            self.banned_ips.remove(&addr.ip());
        }
        false
    }

    /// Check if a peer identity is currently banned (expired bans are removed).
    /// SECREM-01 NET-4(b).
    pub async fn is_peer_id_banned(&self, peer_id: &PeerId) -> bool {
        if let Some(entry) = self.banned_peer_ids.get(peer_id) {
            if Instant::now() < *entry.value() {
                return true;
            }
            drop(entry);
            self.banned_peer_ids.remove(peer_id);
        }
        false
    }

    /// Remove expired bans (call periodically from maintenance loop).
    pub fn cleanup_expired_bans(&self) {
        let now = Instant::now();
        self.banned_peers.retain(|_addr, expires| now < *expires);
        // SECREM-01 NET-4(b)/NET-3: prune the IP and peer-ID ban maps too
        self.banned_ips.retain(|_ip, expires| now < *expires);
        self.banned_peer_ids.retain(|_id, expires| now < *expires);
    }

    /// Update peer score
    pub async fn update_peer_score(&self, peer_id: &PeerId, delta: i32) {
        if let Some(peer) = self.get_peer(peer_id) {
            let mut info = peer.info.write().await;
            info.score += delta;

            // Ban if score too low
            if info.score < self.config.score_threshold {
                drop(info);
                // SECREM-01 NET-4(b): identity is known here — ban
                // peer ID and IP together so the ban survives both
                // port changes and IP changes.
                let addr = peer.info.read().await.addr;
                self.ban_peer_with_id(peer_id, addr).await;
                self.remove_peer(peer_id).await;
            }
        }
    }

    /// Clean up stale peers
    pub async fn cleanup_stale_peers(&self) {
        let stale_peers: Vec<PeerId> = {
            let mut stale = Vec::new();
            for peer in self.peers.iter() {
                let info = peer.value().info.read().await;
                if info.is_stale(self.config.peer_timeout) {
                    stale.push(info.id.clone());
                }
            }
            stale
        };

        for peer_id in stale_peers {
            debug!("Removing stale peer: {}", peer_id);
            self.remove_peer(&peer_id).await;
        }
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast(&self, message: &NetworkMessage) -> Result<(), NetworkError> {
        let peers = self.get_all_peers();
        let mut send_count = 0;

        for peer in peers {
            if (peer.send(message.clone()).await).is_ok() {
                send_count += 1;
            }
        }

        debug!("Broadcasted message to {} peers", send_count);
        Ok(())
    }

    /// Send message to specific peers
    pub async fn send_to_peers(
        &self,
        peer_ids: &[PeerId],
        message: &NetworkMessage,
    ) -> Result<(), NetworkError> {
        for peer_id in peer_ids {
            if let Some(peer) = self.get_peer(peer_id) {
                peer.send(message.clone()).await?;
            }
        }
        Ok(())
    }

    /// Start a TCP listener for inbound peer connections.
    ///
    /// SECREM-01 NET-6: this is the LEGACY PLAINTEXT P2P path — the
    /// handshake here is unencrypted and trusts a self-asserted `PeerId`
    /// (unlike the production `NetworkTransport`, which performs a Noise
    /// handshake binding identity to a key). The node binary does NOT use
    /// it (it wires `NetworkTransport`). It is fail-closed: it refuses to
    /// run unless `CITRATE_ALLOW_PLAINTEXT_P2P=1` is set, so it can never
    /// be accidentally exposed in production.
    pub async fn start_listener(
        self: &Arc<Self>,
        listen_addr: SocketAddr,
        network_id: u32,
        genesis_hash: Hash,
        head_height: u64,
        head_hash: Hash,
    ) -> Result<(), NetworkError> {
        guard_plaintext_p2p("start_listener")?;
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(NetworkError::Io)?;
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let pm = this.clone();
                        let g = genesis_hash;
                        tokio::spawn(async move {
                            if let Err(e) = handle_incoming(
                                stream,
                                addr,
                                pm,
                                network_id,
                                g,
                                head_height,
                                head_hash,
                            )
                            .await
                            {
                                warn!("Inbound connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Accept error: {}", e);
                        break;
                    }
                }
            }
        });
        info!("Listening for peers on {}", listen_addr);
        Ok(())
    }

    /// Dial a remote peer and perform handshake.
    ///
    /// SECREM-01 NET-6: legacy plaintext path (see `start_listener`) —
    /// fail-closed behind `CITRATE_ALLOW_PLAINTEXT_P2P=1`.
    pub async fn connect_bootnode_real(
        self: Arc<Self>,
        peer_id_hint: Option<PeerId>,
        addr: SocketAddr,
        network_id: u32,
        genesis_hash: Hash,
        head_height: u64,
        head_hash: Hash,
    ) -> Result<(), NetworkError> {
        guard_plaintext_p2p("connect_bootnode_real")?;
        let stream = TcpStream::connect(addr).await.map_err(NetworkError::Io)?;
        let peer_id = peer_id_hint.unwrap_or_else(PeerId::random);
        perform_handshake_outbound(
            self,
            stream,
            addr,
            peer_id,
            network_id,
            genesis_hash,
            head_height,
            head_hash,
        )
        .await
    }
}

async fn handle_incoming(
    stream: TcpStream,
    addr: SocketAddr,
    pm: Arc<PeerManager>,
    network_id: u32,
    local_genesis_hash: Hash,
    head_height: u64,
    head_hash: Hash,
) -> Result<(), NetworkError> {
    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
    // Expect Hello
    let bytes = framed
        .next()
        .await
        .ok_or_else(|| NetworkError::ProtocolError("EOF before hello".into()))
        .map_err(|_| NetworkError::ProtocolError("Stream closed".into()))??;
    let hello: NetworkMessage = bincode::deserialize(&bytes)
        .map_err(|e| NetworkError::DecodeError(format!("handshake decode: {}", e)))?;
    let (peer_id_str, ver, net_ok, genesis_ok) = match hello {
        NetworkMessage::Hello {
            version,
            network_id: nid,
            genesis_hash: remote_genesis,
            peer_id,
            ..
        } => (
            peer_id,
            version,
            nid == network_id,
            remote_genesis == local_genesis_hash,  // GenesisBinding invariant (P2PPeerHandshake.tla)
        ),
        _ => return Err(NetworkError::ProtocolError("Expected Hello".into())),
    };
    if !ver.is_compatible(&ProtocolVersion::CURRENT) || !net_ok || !genesis_ok {
        let reason = if !ver.is_compatible(&ProtocolVersion::CURRENT) {
            "incompatible protocol version"
        } else if !net_ok {
            "network ID mismatch"
        } else {
            "genesis hash mismatch (different chain)"
        };
        tracing::warn!("Rejecting peer {}: {}", addr, reason);
        let _ = send_msg(
            &mut framed,
            &NetworkMessage::Disconnect {
                reason: reason.into(),
            },
        )
        .await;
        return Err(NetworkError::ProtocolError(reason.into()));
    }
    // Register peer
    let peer_id = PeerId::new(peer_id_str);
    // Channels for app-level messaging
    let (send_tx, mut send_rx) = mpsc::channel(256);
    let (recv_tx_app, recv_rx) = mpsc::channel(256);
    let info = PeerInfo::new(peer_id.clone(), addr, Direction::Inbound);
    let peer = Arc::new(Peer::new(info, send_tx.clone(), recv_rx));
    pm.add_peer(peer.clone()).await?;
    // Reply HelloAck
    let ack = NetworkMessage::HelloAck {
        version: ProtocolVersion::CURRENT,
        head_height,
        head_hash,
        peer_id: peer_id.0.clone(),
    };
    send_msg(&mut framed, &ack).await?;
    // Split framed into sink and stream
    let (mut sink, mut stream) = framed.split();
    let writer = tokio::spawn(async move {
        while let Some(msg) = send_rx.recv().await {
            if send_msg_sink(&mut sink, &msg).await.is_err() {
                break;
            }
        }
    });
    // Reader
    while let Some(frame) = stream.next().await {
        let bytes = match frame {
            Ok(b) => b,
            Err(_) => break,
        };
        if let Ok(msg) = NetworkMessage::decode_inbound(&bytes) { // SECURITY: C-01 network-variant sanitize at decode
            // Basic responses
            match msg {
                NetworkMessage::Ping { nonce } => {
                    let _ = send_tx.send(NetworkMessage::Pong { nonce }).await;
                }
                other => {
                    // publish to global incoming
                    if let Some(tx) = pm.incoming.read().await.clone() {
                        let _ = tx.send((peer_id.clone(), other.clone())).await;
                    }
                    let _ = recv_tx_app.send(other).await;
                }
            }
            let mut inf = peer.info.write().await;
            inf.messages_received += 1;
            inf.update_last_seen();
        } else {
            break;
        }
    }
    writer.abort();
    pm.remove_peer(&peer_id).await;
    Ok(())
}

/// SECREM-01 NET-6: fail-closed gate for the legacy plaintext P2P path.
/// The Noise-encrypted `NetworkTransport` is the production transport;
/// the plaintext `PeerManager` listener/dialer is opt-in only. Returns
/// `Err` unless `CITRATE_ALLOW_PLAINTEXT_P2P=1`. Exempt under `cfg(test)`
/// so the existing handshake unit tests still exercise the code.
fn guard_plaintext_p2p(entry: &str) -> Result<(), NetworkError> {
    if cfg!(test) {
        return Ok(());
    }
    match std::env::var("CITRATE_ALLOW_PLAINTEXT_P2P").as_deref() {
        Ok("1") => {
            warn!(
                "SECREM-01 NET-6: plaintext P2P path '{}' enabled via \
                 CITRATE_ALLOW_PLAINTEXT_P2P=1 — handshake is UNENCRYPTED \
                 and trusts a self-asserted PeerId. Production must use \
                 NetworkTransport (Noise).",
                entry
            );
            Ok(())
        }
        _ => Err(NetworkError::ProtocolError(format!(
            "plaintext P2P path '{}' is disabled (SECREM-01 NET-6); the node \
             uses the Noise NetworkTransport. Set CITRATE_ALLOW_PLAINTEXT_P2P=1 \
             only for a trusted local/test network.",
            entry
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
async fn perform_handshake_outbound(
    pm: Arc<PeerManager>,
    stream: TcpStream,
    addr: SocketAddr,
    peer_id: PeerId,
    network_id: u32,
    genesis_hash: Hash,
    head_height: u64,
    head_hash: Hash,
) -> Result<(), NetworkError> {
    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
    // Send Hello
    let hello = NetworkMessage::Hello {
        version: ProtocolVersion::CURRENT,
        network_id,
        genesis_hash,
        head_height,
        head_hash,
        peer_id: peer_id.0.clone(),
    };
    send_msg(&mut framed, &hello).await?;
    // Expect Ack
    let bytes = framed
        .next()
        .await
        .ok_or_else(|| NetworkError::ProtocolError("EOF before ack".into()))
        .map_err(|_| NetworkError::ProtocolError("Stream closed".into()))??;
    let ack: NetworkMessage = bincode::deserialize(&bytes)
        .map_err(|e| NetworkError::DecodeError(format!("ack decode: {}", e)))?;
    match ack {
        NetworkMessage::HelloAck { version, .. }
            if version.is_compatible(&ProtocolVersion::CURRENT) => {}
        _ => {
            return Err(NetworkError::ProtocolError("invalid ack".into()));
        }
    }
    // Register peer and spawn IO
    let (send_tx, mut send_rx) = mpsc::channel(256);
    let (_recv_tx, recv_rx) = mpsc::channel(256);
    let info = PeerInfo::new(peer_id.clone(), addr, Direction::Outbound);
    let peer = Arc::new(Peer::new(info, send_tx.clone(), recv_rx));
    pm.add_peer(peer.clone()).await?;
    let (mut sink, mut stream) = framed.split();
    let writer = tokio::spawn(async move {
        while let Some(msg) = send_rx.recv().await {
            if let Err(_e) = send_msg_sink(&mut sink, &msg).await {
                break;
            }
        }
    });
    let pm2 = pm.clone();
    tokio::spawn(async move {
        while let Some(frame) = stream.next().await {
            if let Ok(bytes) = frame {
                if let Ok(msg) = NetworkMessage::decode_inbound(&bytes) { // SECURITY: C-01 network-variant sanitize at decode
                    if let Some(tx) = pm2.incoming.read().await.clone() {
                        let _ = tx.send((peer_id.clone(), msg)).await;
                    }
                }
            } else {
                break;
            }
        }
        writer.abort();
    });
    info!("Connected to bootnode {}", addr);
    Ok(())
}

async fn send_msg(
    framed: &mut Framed<TcpStream, LengthDelimitedCodec>,
    msg: &NetworkMessage,
) -> Result<(), NetworkError> {
    let bytes = bincode::serialize(msg).map_err(|e| NetworkError::DecodeError(e.to_string()))?;
    framed.send(bytes.into()).await.map_err(NetworkError::Io)
}

async fn send_msg_sink<S>(sink: &mut S, msg: &NetworkMessage) -> Result<(), NetworkError>
where
    S: futures::Sink<bytes::Bytes, Error = std::io::Error> + Unpin,
{
    let bytes = bincode::serialize(msg).map_err(|e| NetworkError::DecodeError(e.to_string()))?;
    sink.send(bytes.into()).await.map_err(NetworkError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_with_id(id: &str, addr: &str, direction: Direction) -> Arc<Peer> {
        let (send_tx, recv_rx) = mpsc::channel(10);
        let info = PeerInfo::new(
            PeerId::new(id.to_string()),
            addr.parse().expect("valid addr"),
            direction,
        );
        Arc::new(Peer::new(info, send_tx, recv_rx))
    }

    /// A peer whose writer never drains — i.e. one that has stopped reading its
    /// socket. `cap` is the send-queue depth; the receiver is held so the channel
    /// stays OPEN (a closed channel is a different, already-handled case).
    fn peer_with_stuck_writer(id: &str, cap: usize) -> (Arc<Peer>, mpsc::Receiver<NetworkMessage>) {
        let (send_tx, _never_drained) = mpsc::channel(cap);
        let (_unused_tx, recv_rx) = mpsc::channel(1);
        let info = PeerInfo::new(
            PeerId::new(id.to_string()),
            "10.0.0.1:30303".parse().expect("valid addr"),
            Direction::Outbound,
        );
        (Arc::new(Peer::new(info, send_tx, recv_rx)), _never_drained)
    }

    fn ping() -> NetworkMessage {
        NetworkMessage::GetPeers
    }

    /// RED TEST — #149, the fleet deadlock, at its root.
    ///
    /// `Peer::send` used to `.await` a bounded (256) `mpsc::Sender`. When a peer
    /// stops reading its socket, its writer task parks forever in `sink.send`, so
    /// nothing drains that queue, so this `.await` never returns. Every caller is
    /// a SHARED task — the single inbound message loop, gossip broadcast, block
    /// and tx propagation, the AI handler, the producer — so one wedged peer
    /// froze the entire node, and then the entire fleet.
    ///
    /// The bound is the whole point of the test: it must return, and it must
    /// return an ERROR, so callers learn the peer is not keeping up instead of
    /// silently waiting on it. Timed, because the failure mode is "hangs forever"
    /// and an unbounded test would hang the suite rather than fail it.
    #[tokio::test]
    async fn send_to_a_peer_that_stopped_reading_returns_instead_of_blocking() {
        let (peer, _held_open) = peer_with_stuck_writer("wedged", 4);

        // Fill the queue. Nothing drains it, exactly like a parked writer.
        for _ in 0..4 {
            peer.send(ping()).await.expect("queue has room");
        }

        // The send that would have blocked forever.
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), peer.send(ping())).await;
        let res = res.expect(
            "send MUST NOT block on a full queue — that single await deadlocked chain 40204",
        );
        assert!(
            res.is_err(),
            "a shed message must be reported to the caller, not silently swallowed"
        );
        assert_eq!(
            peer.info.read().await.send_drops,
            1,
            "the drop is counted so a peer that never drains can be closed"
        );
    }

    /// A peer that is merely congested must recover: one successful queue clears
    /// the counter, so transient fullness never accumulates toward a close.
    #[tokio::test]
    async fn a_successful_send_clears_the_drop_counter() {
        let (send_tx, mut rx) = mpsc::channel(1);
        let (_unused_tx, recv_rx) = mpsc::channel(1);
        let info = PeerInfo::new(
            PeerId::new("congested".to_string()),
            "10.0.0.2:30303".parse().expect("valid addr"),
            Direction::Outbound,
        );
        let peer = Peer::new(info, send_tx, recv_rx);

        // Every send is time-bounded: if the non-blocking contract regresses,
        // these HANG rather than fail, and a hung test wedges CI instead of
        // reporting a bug. Verified: against the pre-fix `.await` this test ran
        // past 60s with no verdict.
        let send = |m| tokio::time::timeout(std::time::Duration::from_secs(2), peer.send(m));
        send(ping()).await.expect("must not block").expect("first fits");
        assert!(
            send(ping()).await.expect("must not block").is_err(),
            "second is shed"
        );
        assert_eq!(peer.info.read().await.send_drops, 1);

        // The writer drains one frame — the peer is reading again.
        rx.recv().await.expect("drained");
        send(ping()).await.expect("must not block").expect("room again");
        assert_eq!(
            peer.info.read().await.send_drops,
            0,
            "congestion must not accumulate toward a close once the peer recovers"
        );
    }

    /// A peer that never drains is not congested, it is gone. After
    /// `SEND_DROPS_BEFORE_CLOSE` consecutive drops the connection is closed so
    /// its socket halves are released and it can re-handshake clean, rather than
    /// being kept forever as a peer that consumes nothing.
    #[tokio::test]
    async fn a_peer_that_never_drains_is_eventually_closed() {
        let (peer, _held_open) = peer_with_stuck_writer("dead", 1);
        // Time-bounded for the same reason as above: a regression must FAIL the
        // suite, not hang it.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            peer.send(ping()).await.expect("first fits");
            for _ in 0..Peer::SEND_DROPS_BEFORE_CLOSE {
                let _ = peer.send(ping()).await;
            }
        })
        .await
        .expect("send must never block — see send_to_a_peer_that_stopped_reading");
        assert!(
            peer.is_closed(),
            "a peer that has shed {} consecutive messages has stopped reading and must be dropped",
            Peer::SEND_DROPS_BEFORE_CLOSE
        );
    }

    /// RED TEST — #151, the post-blip corpse loop, reproduced live on chain 40204
    /// by interrupting a syncing node's network for 150 seconds.
    ///
    /// The connection dies, so the writer task (which owns the receiving half) is
    /// gone and the channel is CLOSED. But the `Peer` object stays in the
    /// `PeerManager` carrying its last advertised head, and the sync selector
    /// picks on advertised head — so it kept choosing this peer. Every send
    /// failed; the caller discarded the error; a failed send records no pending
    /// request, so no timeout was ever observed; and the penalty box (#136) is
    /// driven entirely by timeouts, so it never de-preferred or dropped it.
    ///
    /// Observed: `ph=0 pb=0 req_headers=false req_blocks=false` every 2s
    /// indefinitely, with four peers connected and a correct sync target.
    ///
    /// The peer must therefore mark ITSELF closed, so callers have a reliable
    /// liveness test and can evict it instead of retrying a corpse forever.
    #[tokio::test]
    async fn a_send_to_a_closed_channel_marks_the_peer_closed() {
        let (send_tx, rx) = mpsc::channel(8);
        let (_unused_tx, recv_rx) = mpsc::channel(1);
        let info = PeerInfo::new(
            PeerId::new("corpse".to_string()),
            "10.0.0.9:30303".parse().expect("valid addr"),
            Direction::Outbound,
        );
        let peer = Peer::new(info, send_tx, recv_rx);

        // The writer task owns the receiver. Its death closes the channel.
        drop(rx);
        assert!(!peer.is_closed(), "not closed until we discover the dead channel");

        let res = tokio::time::timeout(std::time::Duration::from_secs(2), peer.send(ping()))
            .await
            .expect("send must not block on a closed channel");
        assert!(res.is_err(), "a send to a dead connection must fail");
        assert!(
            peer.is_closed(),
            "the peer must mark itself closed so the sync driver can evict it — \
             without this it keeps winning selection on a stale advertised head and \
             every request evaporates with no timeout to trigger the penalty box"
        );
    }

    /// RED TEST — #149 link 4. `forward_incoming` used to `.await` the bounded
    /// inbound channel. Every peer has its own reader task calling this, so once
    /// the message loop stopped draining, EVERY reader parked here and the node
    /// stopped reading every socket it had (rpc-1 held 681,922 unread bytes from
    /// boot1). It must shed and count instead, so readers keep servicing sockets.
    #[tokio::test]
    async fn forward_incoming_sheds_instead_of_blocking_the_reader() {
        let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let (tx, _rx_held_open) = mpsc::channel(1);
        pm.set_incoming(tx).await;

        pm.forward_incoming(PeerId::new("p".into()), ping()).await;
        assert_eq!(pm.inbound_drops(), 0, "the first message fits");

        // The loop is not draining. This is the call that used to park forever.
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            pm.forward_incoming(PeerId::new("p".into()), ping()),
        )
        .await;
        res.expect(
            "forward_incoming MUST NOT block a peer's reader task — that is how a stalled loop \
             became a node that stopped reading every socket",
        );
        assert_eq!(
            pm.inbound_drops(),
            1,
            "shed messages are counted so the stall detector can see a loop that is not draining"
        );
    }

    /// CONNECTION DEDUP (fleet incident 2026-07-29).
    ///
    /// `add_peer` already deduped the MAP by peer id — a reconnect replaced the
    /// entry. What it never did was close the connection it replaced, so the old
    /// reader/writer tasks kept their socket halves and the TCP connection stayed
    /// ESTABLISHED with nothing routing to it. boot1 accumulated 25 such sockets,
    /// and since `send_to_peers` resolves an id to exactly ONE peer, block
    /// responses were queued onto a half-open one and silently discarded: rpc-1
    /// logged "Sending 32 blocks" while boot1 sat frozen at 72,057 for 20 minutes.
    #[tokio::test]
    async fn reconnect_closes_the_superseded_connection() {
        let manager = PeerManager::new(PeerManagerConfig::default());

        let first = peer_with_id("noise_abc", "10.0.0.1:30303", Direction::Inbound);
        manager.add_peer(first.clone()).await.expect("first add");
        assert!(!first.is_closed(), "a live connection starts open");

        // Same identity reconnects — a fresh socket, same peer id.
        let second = peer_with_id("noise_abc", "10.0.0.1:44444", Direction::Inbound);
        manager.add_peer(second.clone()).await.expect("reconnect");

        assert!(
            first.is_closed(),
            "the superseded connection MUST be closed — leaving it open is the \
             orphaned-socket leak, and it is the one `send_to_peers` may still \
             resolve to while the peer receives nothing"
        );
        assert!(!second.is_closed(), "the live connection stays open");
        assert_eq!(manager.get_peer_counts().await.0, 1, "still exactly one peer");
    }

    /// Re-registering the SAME connection must not tear it down. Without the
    /// `Arc::ptr_eq` guard, an idempotent re-add would close the very socket it
    /// is registering — turning a no-op into a disconnect.
    #[tokio::test]
    async fn re_adding_the_same_connection_does_not_close_it() {
        let manager = PeerManager::new(PeerManagerConfig::default());
        let peer = peer_with_id("noise_same", "10.0.0.9:30303", Direction::Inbound);

        manager.add_peer(peer.clone()).await.expect("first add");
        manager.add_peer(peer.clone()).await.expect("re-add");

        assert!(
            !peer.is_closed(),
            "re-adding the same Arc must be a no-op, not a self-inflicted close"
        );
        assert_eq!(manager.get_peer_counts().await.0, 1);
    }

    /// Dropping a peer must drop its SOCKET, not just the map entry. The sync
    /// tick drops a peer after repeated timeouts so it re-handshakes; if the old
    /// connection survives that, the recovery mechanism itself leaks a socket per
    /// cycle.
    #[tokio::test]
    async fn dropping_a_peer_closes_its_connection() {
        let manager = PeerManager::new(PeerManagerConfig::default());
        let peer = peer_with_id("noise_xyz", "10.0.0.2:30303", Direction::Outbound);
        manager.add_peer(peer.clone()).await.expect("add");

        let removed = manager.remove_peer(&PeerId::new("noise_xyz".to_string())).await;
        assert!(removed.is_some());
        assert!(peer.is_closed(), "remove_peer must close the connection");
    }

    /// The close signal must actually wake a task parked on it — the reader and
    /// writer both park, so `notify_waiters` (not `notify_one`) is required or
    /// one of the two halves is left holding the socket open forever.
    #[tokio::test]
    async fn close_wakes_every_parked_owner() {
        let peer = peer_with_id("noise_park", "10.0.0.3:30303", Direction::Inbound);
        let (shutdown_a, _) = peer.shutdown_handles();
        let (shutdown_b, _) = peer.shutdown_handles();

        let a = tokio::spawn(async move { shutdown_a.notified().await });
        let b = tokio::spawn(async move { shutdown_b.notified().await });
        // Let both register before signalling.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        peer.close();

        let both = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let _ = a.await;
            let _ = b.await;
        })
        .await;
        assert!(
            both.is_ok(),
            "both socket-owning tasks must wake — notify_one would strand one half"
        );
    }

    /// A task that is mid-iteration when `close()` fires misses the notify
    /// entirely, so the latched flag is what guarantees it still stops. Without
    /// it the fix works only when the timing happens to be favourable.
    #[tokio::test]
    async fn close_is_observable_after_the_fact_via_the_latched_flag() {
        let peer = peer_with_id("noise_latch", "10.0.0.4:30303", Direction::Inbound);
        let (_, closed) = peer.shutdown_handles();

        // Nobody is parked: this notification wakes no one.
        peer.close();

        assert!(
            closed.load(Ordering::SeqCst),
            "a task that parks AFTER the close must still see it — otherwise the \
             writer blocks on recv() forever and the socket never closes"
        );
        assert!(peer.is_closed());
        peer.close(); // idempotent
        assert!(peer.is_closed());
    }

    /// SECREM-01 NET-4(b): banning a SocketAddr must ban the whole
    /// IP — reconnecting from a different source port stays banned.
    #[tokio::test]
    async fn test_ban_applies_to_ip_not_just_port() {
        let manager = PeerManager::new(PeerManagerConfig::default());

        let addr: SocketAddr = "10.1.2.3:30303".parse().expect("valid addr");
        manager.ban_peer(addr).await;

        // Exact addr banned
        assert!(manager.is_banned(&addr).await);
        // Same IP, different port — still banned
        let other_port: SocketAddr = "10.1.2.3:40404".parse().expect("valid addr");
        assert!(
            manager.is_banned(&other_port).await,
            "ban must apply to the IP, not just the source port"
        );
        // Different IP — not banned
        let other_ip: SocketAddr = "10.1.2.4:30303".parse().expect("valid addr");
        assert!(!manager.is_banned(&other_ip).await);
    }

    /// SECREM-01 NET-4(b): ban_peer_with_id bans identity AND IP;
    /// a banned identity is rejected by add_peer even from a fresh IP.
    #[tokio::test]
    async fn test_ban_peer_with_id_follows_identity() {
        let manager = PeerManager::new(PeerManagerConfig::default());

        let peer_id = PeerId::new("noise_attacker".to_string());
        let addr: SocketAddr = "10.9.9.9:30303".parse().expect("valid addr");
        manager.ban_peer_with_id(&peer_id, addr).await;

        assert!(manager.is_peer_id_banned(&peer_id).await);
        assert!(manager.is_banned(&addr).await);

        // Same identity reconnecting from a brand-new IP must be
        // rejected at add_peer.
        let (send_tx, recv_rx) = mpsc::channel(10);
        let fresh_addr: SocketAddr = "192.0.2.55:30303".parse().expect("valid addr");
        let peer = Arc::new(Peer::new(
            PeerInfo::new(peer_id.clone(), fresh_addr, Direction::Inbound),
            send_tx,
            recv_rx,
        ));
        assert!(
            manager.add_peer(peer).await.is_err(),
            "banned identity must be rejected regardless of IP"
        );

        // A different identity from the banned IP must also be rejected.
        let (send_tx2, recv_rx2) = mpsc::channel(10);
        let banned_ip_addr: SocketAddr = "10.9.9.9:55555".parse().expect("valid addr");
        let peer2 = Arc::new(Peer::new(
            PeerInfo::new(PeerId::random(), banned_ip_addr, Direction::Inbound),
            send_tx2,
            recv_rx2,
        ));
        assert!(
            manager.add_peer(peer2).await.is_err(),
            "banned IP must be rejected regardless of identity"
        );
    }

    /// SECREM-01 NET-3/NET-4(b): cleanup_expired_bans prunes all
    /// three ban maps once bans expire.
    #[tokio::test]
    async fn test_cleanup_expired_bans_prunes_all_maps() {
        let config = PeerManagerConfig {
            ban_duration: Duration::from_millis(10),
            ..Default::default()
        };
        let manager = PeerManager::new(config);

        let peer_id = PeerId::new("short_ban".to_string());
        let addr: SocketAddr = "10.4.4.4:30303".parse().expect("valid addr");
        manager.ban_peer_with_id(&peer_id, addr).await;

        assert!(manager.is_banned(&addr).await);
        assert!(manager.is_peer_id_banned(&peer_id).await);

        tokio::time::sleep(Duration::from_millis(30)).await;
        manager.cleanup_expired_bans();

        assert_eq!(manager.banned_peers.len(), 0, "SocketAddr bans must be pruned");
        assert_eq!(manager.banned_ips.len(), 0, "IP bans must be pruned");
        assert_eq!(manager.banned_peer_ids.len(), 0, "peer-ID bans must be pruned");
        assert!(!manager.is_banned(&addr).await);
        assert!(!manager.is_peer_id_banned(&peer_id).await);
    }

    #[tokio::test]
    async fn test_peer_manager_limits() {
        let config = PeerManagerConfig {
            max_peers: 2,
            max_inbound: 1,
            max_outbound: 1,
            ..Default::default()
        };

        let manager = PeerManager::new(config);

        // Create mock peers
        let (send_tx1, recv_rx1) = mpsc::channel(10);
        let (send_tx2, recv_rx2) = mpsc::channel(10);
        let (send_tx3, recv_rx3) = mpsc::channel(10);

        let peer1 = Arc::new(Peer::new(
            PeerInfo::new(
                PeerId::random(),
                "127.0.0.1:8001".parse().unwrap(),
                Direction::Inbound,
            ),
            send_tx1,
            recv_rx1,
        ));

        let peer2 = Arc::new(Peer::new(
            PeerInfo::new(
                PeerId::random(),
                "127.0.0.1:8002".parse().unwrap(),
                Direction::Outbound,
            ),
            send_tx2,
            recv_rx2,
        ));

        let peer3 = Arc::new(Peer::new(
            PeerInfo::new(
                PeerId::random(),
                "127.0.0.1:8003".parse().unwrap(),
                Direction::Inbound,
            ),
            send_tx3,
            recv_rx3,
        ));

        // Add first two peers - should succeed
        assert!(manager.add_peer(peer1).await.is_ok());
        assert!(manager.add_peer(peer2).await.is_ok());

        // Try to add third peer - should fail (max peers reached)
        assert!(manager.add_peer(peer3).await.is_err());

        let (total, inbound, outbound) = manager.get_peer_counts().await;
        assert_eq!(total, 2);
        assert_eq!(inbound, 1);
        assert_eq!(outbound, 1);
    }

    #[tokio::test]
    async fn test_reconnect_same_id_does_not_leak_inbound_count() {
        // Regression (fleet follower lockout): the same peer reconnecting re-enters
        // add_peer with the SAME peer_id. self.peers.insert silently overwrote the
        // map entry, but the counter still incremented — so every reconnect leaked
        // an inbound slot until the node reported "Max inbound peers reached" with
        // only a handful of real connections and rejected ALL new followers.
        let config = PeerManagerConfig {
            max_peers: 10,
            max_inbound: 2,
            max_outbound: 5,
            ..Default::default()
        };
        let manager = PeerManager::new(config);
        let pid = PeerId::random();

        // One connect + four reconnects of the SAME id (broken-pipe churn).
        for i in 0..5u16 {
            let (tx, rx) = mpsc::channel(10);
            let addr = format!("127.0.0.1:90{:02}", i).parse().expect("addr");
            let peer = Arc::new(Peer::new(
                PeerInfo::new(pid.clone(), addr, Direction::Inbound),
                tx,
                rx,
            ));
            assert!(
                manager.add_peer(peer).await.is_ok(),
                "reconnect {i} must be accepted (replaces, not adds) — pre-fix the 3rd leaked past max_inbound and was rejected"
            );
        }
        let (total, inbound, outbound) = manager.get_peer_counts().await;
        assert_eq!(inbound, 1, "five connects of one peer_id must count as one inbound, not leak");
        assert_eq!(total, 1);
        assert_eq!(outbound, 0);

        // The inbound budget (2) is NOT consumed by the reconnect churn: a DISTINCT
        // inbound peer still fits (pre-fix this wrongly hit "max inbound").
        let (tx, rx) = mpsc::channel(10);
        let other = Arc::new(Peer::new(
            PeerInfo::new(
                PeerId::random(),
                "127.0.0.1:9100".parse().expect("addr"),
                Direction::Inbound,
            ),
            tx,
            rx,
        ));
        assert!(
            manager.add_peer(other).await.is_ok(),
            "a distinct inbound peer must still fit after reconnect churn"
        );
        let (_, inbound2, _) = manager.get_peer_counts().await;
        assert_eq!(inbound2, 2);
    }

    #[tokio::test]
    async fn test_remove_peer_if_current_is_identity_aware() {
        // Regression (teardown race → peer starvation): after a reconnect the map
        // holds the FRESH peer, but the OLD connection's teardown fires later and,
        // with a plain remove_peer, would evict the fresh one — churning a node down
        // to 0 peers. remove_peer_if_current makes a stale teardown a no-op.
        let manager = PeerManager::new(PeerManagerConfig::default());
        let pid = PeerId::random();

        let (tx, rx) = mpsc::channel(10);
        let live = Arc::new(Peer::new(
            PeerInfo::new(pid.clone(), "127.0.0.1:9001".parse().expect("addr"), Direction::Inbound),
            tx,
            rx,
        ));
        manager.add_peer(live.clone()).await.expect("add");

        // A DIFFERENT instance with the same id (a stale connection's handle) must
        // NOT evict the mapped peer.
        let (tx2, rx2) = mpsc::channel(10);
        let stale = Arc::new(Peer::new(
            PeerInfo::new(pid.clone(), "127.0.0.1:9002".parse().expect("addr"), Direction::Inbound),
            tx2,
            rx2,
        ));
        assert!(
            !manager.remove_peer_if_current(&pid, &stale).await,
            "a stale (different) instance must not evict the live peer"
        );
        assert!(manager.get_peer(&pid).is_some(), "live peer must remain");

        // The owning instance removes it.
        assert!(
            manager.remove_peer_if_current(&pid, &live).await,
            "the current instance removes"
        );
        assert!(manager.get_peer(&pid).is_none());
    }

    #[tokio::test]
    async fn test_peer_scoring_and_ban() {
        let config = PeerManagerConfig {
            score_threshold: -10,
            ..Default::default()
        };

        let manager = PeerManager::new(config);

        let (send_tx, recv_rx) = mpsc::channel(10);
        let peer_id = PeerId::random();
        let addr = "127.0.0.1:8001".parse().unwrap();

        let peer = Arc::new(Peer::new(
            PeerInfo::new(peer_id.clone(), addr, Direction::Inbound),
            send_tx,
            recv_rx,
        ));

        manager.add_peer(peer).await.unwrap();

        // Decrease score below threshold
        manager.update_peer_score(&peer_id, -15).await;

        // Peer should be removed and banned
        assert!(manager.get_peer(&peer_id).is_none());
        assert!(manager.is_banned(&addr).await);
    }
}
