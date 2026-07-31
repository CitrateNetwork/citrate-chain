// citrate/core/network/src/discovery.rs

// Peer discovery service
use crate::{
    peer::{PeerId, PeerManager},
    protocol::PeerAddress,
    NetworkError,
};
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,

    /// Maximum peers to discover
    pub max_peers: usize,

    /// Discovery interval
    pub discovery_interval: Duration,

    /// Peer exchange size
    pub peer_exchange_size: usize,

    /// Peer expiry time
    pub peer_expiry: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: Vec::new(),
            max_peers: 100,
            discovery_interval: Duration::from_secs(30),
            peer_exchange_size: 10,
            peer_expiry: Duration::from_secs(3600),
        }
    }
}

/// SECREM-01 NET-4(a): maximum outbound peers selected per subnet
/// group — /24 for IPv4, /48 for IPv6. Free Sybil identities are
/// cheap but address space inside one subnet is (comparatively)
/// not, so capping per-group selection raises the cost of eclipsing
/// a node: an attacker must control addresses across many distinct
/// subnets instead of spinning up hundreds of identities on one
/// host or one rented /24.
pub const MAX_PEERS_PER_SUBNET_GROUP: usize = 3;

/// SECREM-01 NET-4(a): subnet-diversity group key for an IP.
///
/// IPv4 addresses group by /24 (first 3 octets); IPv6 by /48 (first
/// 6 bytes). The leading tag byte (4 or 6) keeps the two families
/// in disjoint key spaces.
pub fn subnet_group(ip: &IpAddr) -> [u8; 7] {
    let mut key = [0u8; 7];
    match ip {
        IpAddr::V4(v4) => {
            key[0] = 4;
            key[1..4].copy_from_slice(&v4.octets()[..3]);
        }
        IpAddr::V6(v6) => {
            key[0] = 6;
            key[1..7].copy_from_slice(&v6.octets()[..6]);
        }
    }
    key
}

/// SECREM-01 NET-4(a): pure subnet-cap selection filter.
///
/// `candidates` is an ordered list of `(addr, exempt)` pairs —
/// `exempt = true` (bootstrap peers) bypasses the cap but still
/// counts against its group so non-exempt peers in the same subnet
/// are squeezed out first. `existing` (already-connected peers) is
/// counted against each group before any candidate is admitted.
///
/// Returns the indices of accepted candidates, preserving order.
pub fn filter_by_subnet_cap(
    candidates: &[(SocketAddr, bool)],
    existing: &[SocketAddr],
    cap: usize,
) -> Vec<usize> {
    let mut counts: HashMap<[u8; 7], usize> = HashMap::new();
    for addr in existing {
        *counts.entry(subnet_group(&addr.ip())).or_insert(0) += 1;
    }

    let mut accepted = Vec::with_capacity(candidates.len());
    for (i, (addr, exempt)) in candidates.iter().enumerate() {
        let count = counts.entry(subnet_group(&addr.ip())).or_insert(0);
        if *exempt || *count < cap {
            *count += 1;
            accepted.push(i);
        }
    }
    accepted
}

/// Known peer information
#[derive(Debug, Clone)]
struct KnownPeer {
    id: String,
    addr: SocketAddr,
    last_seen: u64,
    score: i32,
    attempts: u32,
    /// A-10/B-6: Protected bootstrap nodes are never expired and are
    /// always retried on every discovery tick, even after N failures.
    is_bootstrap: bool,
}

/// Peer discovery service
pub struct Discovery {
    config: DiscoveryConfig,
    known_peers: Arc<DashMap<String, KnownPeer>>,
    connected_peers: Arc<RwLock<HashSet<String>>>,
    peer_manager: Arc<PeerManager>,
}

impl Discovery {
    pub fn new(config: DiscoveryConfig, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            config,
            known_peers: Arc::new(DashMap::new()),
            connected_peers: Arc::new(RwLock::new(HashSet::new())),
            peer_manager,
        }
    }

    /// Initialize with bootstrap nodes.
    ///
    /// Parses every supported bootstrap address format and resolves hostnames
    /// via DNS through the shared [`crate::bootnode::resolve_bootnode`] helper:
    ///   - `ip:port` (e.g., `203.0.113.10:30303`)
    ///   - `hostname:port` (e.g., `boot1.citrate.ai:30303`)
    ///   - `noise_<hex>@<host>:port` (trusted identity — host resolved, addr used)
    ///   - `peer_id@<host>:port` (non-noise identity — host resolved)
    ///
    /// Both literal IPs and hostnames are resolved to concrete SocketAddrs and
    /// added to the discovery known_peers set, so a fresh node with the baked
    /// hostname-based `testnet-beta.toml` populates discovery correctly.
    pub async fn init(&self) -> Result<(), NetworkError> {
        let mut added = 0usize;
        for node in &self.config.bootstrap_nodes {
            if let Some((_, addr)) = crate::bootnode::resolve_bootnode(node).await {
                self.add_bootstrap_peer(format!("bootstrap_{}", node), addr).await;
                added += 1;
            } else {
                warn!("Could not resolve bootstrap node: {}", node);
            }
        }

        info!(
            "Initialized discovery with {} bootstrap nodes ({} resolved as protected, {} unresolved)",
            self.config.bootstrap_nodes.len(),
            added,
            self.config.bootstrap_nodes.len() - added,
        );
        Ok(())
    }

    /// Add a discovered peer (non-bootstrap).
    pub async fn add_peer(&self, id: String, addr: SocketAddr, score: i32) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let peer = KnownPeer {
            id: id.clone(),
            addr,
            last_seen: now,
            score,
            attempts: 0,
            is_bootstrap: false,
        };

        self.known_peers.insert(id, peer);
        debug!("Added peer to discovery: {}", addr);
    }

    /// Add a protected bootstrap peer.
    /// Bootstrap peers are never expired and are always retried, even after
    /// repeated connection failures. This is what makes multi-bootnode
    /// failover work: if bootnode A goes offline, the node keeps trying
    /// bootnodes B and C on every discovery tick.
    async fn add_bootstrap_peer(&self, id: String, addr: SocketAddr) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let peer = KnownPeer {
            id: id.clone(),
            addr,
            last_seen: now,
            score: 100, // High score — always try bootstraps first
            attempts: 0,
            is_bootstrap: true,
        };

        self.known_peers.insert(id, peer);
        info!("Added protected bootstrap peer to discovery: {}", addr);
    }

    /// Mark peer as connected.
    ///
    /// BOOKKEEPING ONLY — nothing routes off this set any more, and no dial
    /// decision may be made from it. See [`Discovery::mark_disconnected`].
    pub async fn mark_connected(&self, peer_id: &str) {
        self.connected_peers
            .write()
            .await
            .insert(peer_id.to_string());
    }

    /// Mark peer as disconnected.
    ///
    /// #146 — READ THIS BEFORE MAKING ANY DECISION FROM `connected_peers`.
    ///
    /// This is called from tests and nowhere else: production adds to the set
    /// (`main.rs` discovery loop) and never removes from it, because peers are
    /// dropped by the PEER MANAGER, which has no handle on `Discovery`. The set
    /// is therefore a monotonically growing record of "was dialed once", not of
    /// "is connected now".
    ///
    /// `find_peers` used to gate re-dials on it, with a `peer_count < 3` escape
    /// bolted on for the 0-peer case. On the 40204 fleet a cold-syncing node
    /// dropped the SEQUENCER after five sync timeouts (main.rs
    /// drop-and-re-handshake), leaving exactly the three discovery-only
    /// bootnodes — so `3 < 3` was false, the stale set still claimed the
    /// sequencer was connected, and the one peer holding blocks above ~91k was
    /// never dialed again. The node then synced to the bootnodes' frozen tips
    /// and idled ~36k short of the head, serving inbound requests and asking
    /// nobody for anything. Restarting cleared the process-local state and
    /// bought exactly one more batch.
    ///
    /// `find_peers` now asks the peer manager instead. Keep it that way: any
    /// threshold on a set that cannot shrink is a latch, and the escape hatch
    /// only moves where it bites.
    pub async fn mark_disconnected(&self, peer_id: &str) {
        self.connected_peers.write().await.remove(peer_id);
    }

    /// Get peers for exchange
    ///
    /// WP-H.3: Outgoing peer exchange always sends score=0 to prevent leaking
    /// internal scoring heuristics to remote peers.
    pub async fn get_peers_for_exchange(&self) -> Vec<PeerAddress> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let connected = self.connected_peers.read().await;

        let mut peers: Vec<PeerAddress> = self
            .known_peers
            .iter()
            .filter(|p| {
                !connected.contains(&p.value().id)
                    && (now - p.value().last_seen) < self.config.peer_expiry.as_secs()
            })
            .take(self.config.peer_exchange_size)
            .map(|p| PeerAddress {
                id: p.value().id.clone(),
                addr: p.value().addr.to_string(),
                last_seen: p.value().last_seen,
                score: 0, // Never leak internal scores
            })
            .collect();

        peers.sort_by_key(|p| std::cmp::Reverse(p.score));
        peers.truncate(self.config.peer_exchange_size);

        peers
    }

    /// Handle peer exchange
    ///
    /// WP-H.3: Remote-provided scores are IGNORED. An attacker could inject
    /// peers with score=100 via peer exchange to get priority in `find_peers()`,
    /// enabling eclipse attacks. All remotely-discovered peers start at score 0
    /// and earn score only through successful local interactions.
    pub async fn handle_peer_exchange(&self, peers: Vec<PeerAddress>) {
        const INITIAL_DISCOVERED_SCORE: i32 = 0;

        for peer in peers {
            if let Ok(addr) = peer.addr.parse::<SocketAddr>() {
                // Skip if already connected or banned
                if self.connected_peers.read().await.contains(&peer.id) {
                    continue;
                }

                if self.peer_manager.is_banned(&addr).await {
                    continue;
                }

                // Ignore remote-provided score — use neutral initial score
                self.add_peer(peer.id, addr, INITIAL_DISCOVERED_SCORE).await;
            }
        }
    }

    /// Find new peers to connect to
    // LOCK ORDERING: takes Peer.info read locks, then get_peer_counts() -> stats
    // (read). Safe: both are read locks; no write contention in this path.
    // SECREM-01 NET-4(a): Peer.info read locks are taken first so lock
    // acquisition stays one-directional.
    pub async fn find_peers(&self) -> Vec<(String, SocketAddr)> {
        // SECREM-01 NET-4(a): snapshot the addresses of currently connected
        // peers so existing connections count against each subnet group's cap
        // during selection.
        //
        // #146: this snapshot is ALSO the "is it connected?" test below. The
        // peer manager is the only source of truth for that question; the
        // `connected_peers` set is a write-only shadow copy (see
        // `mark_disconnected`) and using it here is what stranded live nodes.
        let existing_addrs: Vec<SocketAddr> = {
            let mut addrs = Vec::new();
            for peer in self.peer_manager.get_all_peers() {
                addrs.push(peer.info.read().await.addr);
            }
            addrs
        };
        let is_connected = |addr: &SocketAddr| existing_addrs.contains(addr);

        let (current_peers, _, _) = self.peer_manager.get_peer_counts().await;

        if current_peers >= self.config.max_peers {
            return Vec::new();
        }

        let needed = self.config.max_peers - current_peers;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // A-10/B-6: Bootstrap peers are exempt from attempts cap and expiry —
        // they are always retried so multi-bootnode failover works.
        let mut candidates: Vec<_> = self
            .known_peers
            .iter()
            .filter(|p| {
                let peer = p.value();
                if peer.is_bootstrap {
                    // A bootstrap we do not currently hold a connection to is
                    // ALWAYS re-offered. Nothing else may veto that: a bootstrap
                    // is the node's trust root and, on this fleet, the sequencer
                    // is one — see the module note on the 91k stall.
                    return !is_connected(&peer.addr);
                }
                if is_connected(&peer.addr) {
                    return false;
                }
                peer.attempts < 3
                    && (now - peer.last_seen) < self.config.peer_expiry.as_secs()
            })
            .map(|p| p.value().clone())
            .collect();

        // Sort by score and attempts
        candidates.sort_by(|a, b| b.score.cmp(&a.score).then(a.attempts.cmp(&b.attempts)));

        // SECREM-01 NET-4(a): enforce subnet diversity — cap
        // selection per /24 (IPv4) / /48 (IPv6) group, counting
        // already-connected peers first. Bootstrap peers are exempt
        // (A-10/B-6 failover guarantee) but still occupy their
        // group's budget.
        let keyed: Vec<(SocketAddr, bool)> = candidates
            .iter()
            .map(|p| (p.addr, p.is_bootstrap))
            .collect();
        let accepted =
            filter_by_subnet_cap(&keyed, &existing_addrs, MAX_PEERS_PER_SUBNET_GROUP);

        accepted
            .into_iter()
            .take(needed)
            .map(|i| (candidates[i].id.clone(), candidates[i].addr))
            .collect()
    }

    /// Update peer attempts
    pub async fn update_attempts(&self, peer_id: &str, success: bool) {
        if let Some(mut peer) = self.known_peers.get_mut(peer_id) {
            if success {
                peer.attempts = 0;
                peer.score = (peer.score + 10).min(100);
            } else {
                peer.attempts += 1;
                peer.score = (peer.score - 5).max(-100);
            }
        }
    }

    /// Clean up expired peers.
    /// A-10/B-6: Protected bootstrap peers are never expired.
    pub async fn cleanup_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expired: Vec<String> = self
            .known_peers
            .iter()
            .filter(|p| {
                !p.value().is_bootstrap
                    && (now - p.value().last_seen) > self.config.peer_expiry.as_secs()
            })
            .map(|p| p.key().clone())
            .collect();

        for id in expired {
            self.known_peers.remove(&id);
            debug!("Removed expired peer: {}", id);
        }
    }

    /// A-10: Diagnostics — return count of protected bootstrap peers currently known.
    pub async fn bootstrap_peer_count(&self) -> usize {
        self.known_peers.iter().filter(|p| p.value().is_bootstrap).count()
    }

    /// A-10: Diagnostics — return count of currently connected bootstrap peers.
    ///
    /// Counted from the PEER MANAGER, not `connected_peers`: the latter is a
    /// write-only shadow set (see [`Discovery::mark_disconnected`]) and reading
    /// it here reported bootstraps as connected long after they were dropped.
    pub async fn connected_bootstrap_count(&self) -> usize {
        let mut connected_addrs: Vec<SocketAddr> = Vec::new();
        for peer in self.peer_manager.get_all_peers() {
            connected_addrs.push(peer.info.read().await.addr);
        }
        self.known_peers
            .iter()
            .filter(|p| p.value().is_bootstrap && connected_addrs.contains(&p.value().addr))
            .count()
    }

    /// Run discovery loop
    pub async fn run(&self) {
        let mut interval = time::interval(self.config.discovery_interval);

        loop {
            interval.tick().await;

            // Clean up expired peers
            self.cleanup_expired().await;

            // Find new peers to connect to
            let candidates = self.find_peers().await;

            if !candidates.is_empty() {
                info!("Discovery found {} potential peers", candidates.len());

                // Initiate connections to candidates
                for (id, addr) in candidates {
                    debug!("Attempting to connect to: {} ({})", id, addr);

                    match self
                        .peer_manager
                        .connect_to_peer(PeerId::new(id.clone()), addr)
                        .await
                    {
                        Ok(_) => {
                            info!("Successfully initiated connection to {}", id);
                            self.mark_connected(&id).await;
                            self.update_attempts(&id, true).await;
                        }
                        Err(e) => {
                            debug!("Failed to connect to {}: {}", id, e);
                            self.update_attempts(&id, false).await;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{Direction, Peer, PeerInfo, PeerManagerConfig, PeerState};

    // SECREM-01 NET-4(a): /24 grouping for IPv4, /48 for IPv6,
    // disjoint key spaces between families.
    #[test]
    fn test_subnet_group_keys() {
        let a: IpAddr = "10.1.2.3".parse().expect("valid ip");
        let b: IpAddr = "10.1.2.250".parse().expect("valid ip");
        let c: IpAddr = "10.1.3.3".parse().expect("valid ip");
        assert_eq!(subnet_group(&a), subnet_group(&b), "same /24 must group together");
        assert_ne!(subnet_group(&a), subnet_group(&c), "different /24 must not group");

        let v6a: IpAddr = "2001:db8:aaaa:1::1".parse().expect("valid ip");
        let v6b: IpAddr = "2001:db8:aaaa:2::9".parse().expect("valid ip");
        let v6c: IpAddr = "2001:db8:bbbb:1::1".parse().expect("valid ip");
        assert_eq!(subnet_group(&v6a), subnet_group(&v6b), "same /48 must group together");
        assert_ne!(subnet_group(&v6a), subnet_group(&v6c), "different /48 must not group");

        // v4 and v6 keys never collide (tag byte differs)
        assert_ne!(subnet_group(&a)[0], subnet_group(&v6a)[0]);
    }

    // SECREM-01 NET-4(a): cap enforcement — at most `cap` accepted
    // per group, order preserved, other groups unaffected.
    #[test]
    fn test_filter_by_subnet_cap_caps_per_group() {
        let mk = |s: &str| -> SocketAddr { s.parse().expect("valid addr") };
        let candidates = vec![
            (mk("10.0.0.1:30303"), false),
            (mk("10.0.0.2:30303"), false),
            (mk("10.0.0.3:30303"), false),
            (mk("10.0.0.4:30303"), false), // 4th in same /24 — dropped
            (mk("192.168.5.1:30303"), false), // different /24 — kept
            (mk("10.0.0.5:30303"), false), // 5th in same /24 — dropped
        ];
        let accepted = filter_by_subnet_cap(&candidates, &[], 3);
        assert_eq!(accepted, vec![0, 1, 2, 4]);
    }

    // SECREM-01 NET-4(a): already-connected peers consume their
    // group's budget before any candidate is admitted.
    #[test]
    fn test_filter_by_subnet_cap_counts_existing_connections() {
        let mk = |s: &str| -> SocketAddr { s.parse().expect("valid addr") };
        let existing = vec![mk("10.0.0.10:30303"), mk("10.0.0.11:30303")];
        let candidates = vec![
            (mk("10.0.0.1:30303"), false), // 3rd in group — kept
            (mk("10.0.0.2:30303"), false), // 4th in group — dropped
            (mk("172.16.0.1:30303"), false), // fresh group — kept
        ];
        let accepted = filter_by_subnet_cap(&candidates, &existing, 3);
        assert_eq!(accepted, vec![0, 2]);
    }

    // SECREM-01 NET-4(a): bootstrap (exempt) candidates bypass the
    // cap but still consume group budget.
    #[test]
    fn test_filter_by_subnet_cap_bootstrap_exempt_but_counted() {
        let mk = |s: &str| -> SocketAddr { s.parse().expect("valid addr") };
        let candidates = vec![
            (mk("10.0.0.1:30301"), true),
            (mk("10.0.0.2:30302"), true),
            (mk("10.0.0.3:30303"), true),
            (mk("10.0.0.4:30304"), true), // exempt: kept despite >cap
            (mk("10.0.0.5:30305"), false), // non-exempt, group full — dropped
        ];
        let accepted = filter_by_subnet_cap(&candidates, &[], 3);
        assert_eq!(accepted, vec![0, 1, 2, 3]);
    }

    #[tokio::test]
    async fn test_discovery_bootstrap() {
        let config = DiscoveryConfig {
            bootstrap_nodes: vec!["127.0.0.1:8001".to_string(), "127.0.0.1:8002".to_string()],
            ..Default::default()
        };

        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager);

        discovery.init().await.unwrap();

        assert_eq!(discovery.known_peers.len(), 2);
    }

    // A-10/B-6: Bootstrap nodes with identity prefixes are parsed correctly
    #[tokio::test]
    async fn test_bootstrap_identity_prefix_parsed() {
        let config = DiscoveryConfig {
            bootstrap_nodes: vec![
                "noise_abc123@127.0.0.1:30303".to_string(),
                "peer_xyz@127.0.0.1:30304".to_string(),
                "127.0.0.1:30305".to_string(),
            ],
            ..Default::default()
        };

        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager);

        discovery.init().await.unwrap();

        // All 3 should be added as bootstrap peers (identity prefixes stripped)
        assert_eq!(discovery.known_peers.len(), 3);
        assert_eq!(discovery.bootstrap_peer_count().await, 3);
    }

    // A-10/B-6: Bootstrap nodes survive attempt cap (always retryable)
    #[tokio::test]
    async fn test_bootstrap_survives_attempt_cap() {
        let config = DiscoveryConfig {
            bootstrap_nodes: vec!["127.0.0.1:30303".to_string()],
            max_peers: 10,
            ..Default::default()
        };

        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager);
        discovery.init().await.unwrap();

        // Simulate 10 failed attempts — way above the normal attempts<3 cap
        for _ in 0..10 {
            discovery.update_attempts("bootstrap_127.0.0.1:30303", false).await;
        }

        // find_peers should STILL return the bootstrap node because is_bootstrap=true
        let candidates = discovery.find_peers().await;
        assert!(!candidates.is_empty(), "Bootstrap peer must remain in candidates after 10 failed attempts");
        assert_eq!(candidates[0].0, "bootstrap_127.0.0.1:30303");
    }

    /// Register `addr` in the peer manager as a live, connected peer, the way
    /// the transport does after a handshake. Used by the re-dial tests to make
    /// "how many peers do we actually hold" the real thing rather than a mock.
    async fn connect_fake_peer(peer_manager: &Arc<PeerManager>, id: &str, addr: &str) {
        let addr: SocketAddr = addr.parse().expect("valid addr");
        let mut info = PeerInfo::new(PeerId::new(id.to_string()), addr, Direction::Outbound);
        info.state = PeerState::Connected;
        let (to_wire_tx, _to_wire_rx) = tokio::sync::mpsc::channel(8);
        let (_from_wire_tx, from_wire_rx) = tokio::sync::mpsc::channel(8);
        peer_manager
            .add_peer(Arc::new(Peer::new(info, to_wire_tx, from_wire_rx)))
            .await
            .expect("add_peer succeeds for an unbanned peer");
    }

    #[tokio::test]
    async fn test_starved_node_redials_bootstrap_despite_stale_connected_set() {
        // Regression: mark_disconnected is never called in production, so a dropped
        // bootstrap stayed in `connected_peers` forever and find_peers skipped it — a
        // node that lost all peers never re-dialed and stayed isolated (observed:
        // boot3 stuck at 0 peers).
        let config = DiscoveryConfig {
            bootstrap_nodes: vec!["127.0.0.1:30303".to_string()],
            max_peers: 10,
            ..Default::default()
        };
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager);
        discovery.init().await.unwrap();

        // The connection dropped, but the set was never cleaned: it is still "connected"
        // while the REAL peer manager holds 0 peers.
        discovery.mark_connected("bootstrap_127.0.0.1:30303").await;

        let candidates = discovery.find_peers().await;
        assert!(
            candidates
                .iter()
                .any(|(id, _)| id.as_str() == "bootstrap_127.0.0.1:30303"),
            "a peer-starved node must re-dial its bootstrap even when it is stale-marked connected"
        );
    }

    /// RED TEST — the live 40204 stall (#146), reproduced at its exact shape.
    ///
    /// A cold-syncing node holds all four fleet bootstraps. Sync requests to the
    /// SEQUENCER time out five times (its early responses are the largest), so
    /// `main.rs` drops it — logging "will re-handshake" — leaving exactly the
    /// three discovery-only bootnodes, which cannot advance anyone past their own
    /// frozen tips.
    ///
    /// Pre-fix, two conditions had to BOTH hold for the promised re-handshake:
    /// `peer_count < 3` (false: it is exactly 3) or absence from the stale
    /// `connected_peers` set (false: it is never cleaned). Neither held, so the
    /// only peer on the network holding blocks above ~91k was never dialed again
    /// and the node idled ~36k short of the tip until it was restarted — which
    /// bought exactly one more batch before the same five timeouts recurred.
    ///
    /// The count is deliberately pinned at THREE because that is where the old
    /// `< 3` escape hatch stops firing. A fix that merely widens the threshold
    /// (`< 4`) relocates the latch to a four-bootnode fleet instead of removing
    /// it — the same mistake the sync-peer penalty box made with its [3,5) dead
    /// band (see node/src/sync_peer.rs, defect D2).
    #[tokio::test]
    async fn a_dropped_bootstrap_is_redialed_even_with_three_useless_peers_left() {
        let config = DiscoveryConfig {
            bootstrap_nodes: vec![
                "127.0.0.1:30301".to_string(), // boot1
                "127.0.0.1:30302".to_string(), // boot2
                "127.0.0.1:30303".to_string(), // boot3
                "127.0.0.1:30304".to_string(), // the sequencer
            ],
            max_peers: 50,
            ..Default::default()
        };
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager.clone());
        discovery.init().await.expect("bootstraps resolve");

        // All four were dialed at boot, so all four are in the shadow set forever.
        for port in [30301, 30302, 30303, 30304] {
            discovery
                .mark_connected(&format!("bootstrap_127.0.0.1:{}", port))
                .await;
        }
        // Three are still connected; the sequencer was dropped by the sync tick.
        for (i, port) in [30301u16, 30302, 30303].iter().enumerate() {
            connect_fake_peer(
                &peer_manager,
                &format!("boot{}", i + 1),
                &format!("127.0.0.1:{}", port),
            )
            .await;
        }
        let (held, _, _) = peer_manager.get_peer_counts().await;
        assert_eq!(held, 3, "exactly the count the old `< 3` escape does not cover");

        let candidates = discovery.find_peers().await;
        assert!(
            candidates
                .iter()
                .any(|(id, _)| id.as_str() == "bootstrap_127.0.0.1:30304"),
            "the dropped sequencer must be re-offered for dial — it is the only peer \
             that can advance us, and 'will re-handshake' has to be true"
        );
        // And the three we already hold are not re-dialed: the fix must not turn
        // every discovery tick into a redundant reconnect storm.
        for port in [30301, 30302, 30303] {
            let id = format!("bootstrap_127.0.0.1:{}", port);
            assert!(
                !candidates.iter().any(|(c, _)| *c == id),
                "{} is connected and must not be re-dialed",
                id
            );
        }
    }

    /// The same guarantee at full strength: connectivity is judged from the peer
    /// manager, so a bootstrap we hold NO connection to is offered no matter how
    /// many other peers are up. Pinned at a well-peered count so no future
    /// starvation threshold can be reintroduced without failing here.
    #[tokio::test]
    async fn a_bootstrap_we_do_not_hold_is_redialed_even_when_well_peered() {
        let config = DiscoveryConfig {
            bootstrap_nodes: vec!["127.0.0.1:30304".to_string()],
            max_peers: 50,
            ..Default::default()
        };
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager.clone());
        discovery.init().await.expect("bootstraps resolve");
        discovery.mark_connected("bootstrap_127.0.0.1:30304").await;

        // Ten healthy non-bootstrap peers, spread across subnets so the /24 cap
        // does not do the work the assertion is meant to test.
        for i in 0..10u16 {
            connect_fake_peer(
                &peer_manager,
                &format!("gossip{}", i),
                &format!("10.0.{}.5:30303", i),
            )
            .await;
        }

        let candidates = discovery.find_peers().await;
        assert!(
            candidates
                .iter()
                .any(|(id, _)| id.as_str() == "bootstrap_127.0.0.1:30304"),
            "a bootstrap with no live connection is always re-offered — being \
             well-peered is not evidence that the peer we need is among them"
        );
    }

    /// Diagnostics must not inherit the lie either: a bootstrap that was dialed
    /// once and later dropped is NOT a connected bootstrap.
    #[tokio::test]
    async fn connected_bootstrap_count_reflects_the_peer_manager_not_the_shadow_set() {
        let config = DiscoveryConfig {
            bootstrap_nodes: vec!["127.0.0.1:30301".to_string(), "127.0.0.1:30302".to_string()],
            max_peers: 50,
            ..Default::default()
        };
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager.clone());
        discovery.init().await.expect("bootstraps resolve");

        discovery.mark_connected("bootstrap_127.0.0.1:30301").await;
        discovery.mark_connected("bootstrap_127.0.0.1:30302").await;
        connect_fake_peer(&peer_manager, "boot1", "127.0.0.1:30301").await;

        assert_eq!(
            discovery.connected_bootstrap_count().await,
            1,
            "only the bootstrap the peer manager actually holds counts as connected"
        );
    }

    // A-10/B-6: Bootstrap nodes are never expired by cleanup_expired
    #[tokio::test]
    async fn test_bootstrap_not_expired() {
        let config = DiscoveryConfig {
            bootstrap_nodes: vec!["127.0.0.1:30303".to_string()],
            peer_expiry: Duration::from_secs(1),
            ..Default::default()
        };

        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager);
        discovery.init().await.unwrap();

        assert_eq!(discovery.known_peers.len(), 1);

        // Add a non-bootstrap peer that will immediately be eligible for expiry
        discovery
            .add_peer("regular".to_string(), "127.0.0.1:9999".parse().unwrap(), 50)
            .await;

        // Manually age the regular peer
        if let Some(mut p) = discovery.known_peers.get_mut("regular") {
            p.last_seen = 0; // Ancient
        }

        // Manually age the bootstrap peer too
        if let Some(mut p) = discovery.known_peers.get_mut("bootstrap_127.0.0.1:30303") {
            p.last_seen = 0;
        }

        discovery.cleanup_expired().await;

        // Bootstrap peer must survive; regular peer must be removed
        assert_eq!(discovery.bootstrap_peer_count().await, 1, "Bootstrap peer must not be expired");
        assert!(!discovery.known_peers.contains_key("regular"), "Regular peer must be expired");
    }

    // A-10 diagnostics: bootstrap_peer_count + connected_bootstrap_count
    #[tokio::test]
    async fn test_bootstrap_diagnostics() {
        let config = DiscoveryConfig {
            bootstrap_nodes: vec![
                "127.0.0.1:30301".to_string(),
                "127.0.0.1:30302".to_string(),
                "127.0.0.1:30303".to_string(),
            ],
            ..Default::default()
        };

        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager.clone());
        discovery.init().await.unwrap();

        assert_eq!(discovery.bootstrap_peer_count().await, 3);
        assert_eq!(discovery.connected_bootstrap_count().await, 0);

        // #146: "connected" now means the PEER MANAGER holds the connection.
        // This test used to drive the count with `mark_connected` alone, which
        // is exactly the shadow-set reading that let a dropped sequencer keep
        // reporting itself connected — so it is driven through real peers now.
        connect_fake_peer(&peer_manager, "boot1", "127.0.0.1:30301").await;
        assert_eq!(discovery.connected_bootstrap_count().await, 1);

        connect_fake_peer(&peer_manager, "boot2", "127.0.0.1:30302").await;
        assert_eq!(discovery.connected_bootstrap_count().await, 2);

        // The first goes down. `mark_disconnected` is NOT called (production
        // never calls it) — the count must fall anyway.
        peer_manager.remove_peer(&PeerId::new("boot1".to_string())).await;
        assert_eq!(
            discovery.connected_bootstrap_count().await,
            1,
            "a dropped bootstrap stops counting as connected without any \
             bookkeeping call, because the peer manager is the source of truth"
        );
        assert_eq!(discovery.bootstrap_peer_count().await, 3, "Total bootstrap count stays at 3");
    }

    #[tokio::test]
    async fn test_peer_exchange() {
        let config = DiscoveryConfig::default();
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let discovery = Discovery::new(config, peer_manager);

        // Add some peers
        discovery
            .add_peer("peer1".to_string(), "127.0.0.1:8001".parse().unwrap(), 50)
            .await;
        discovery
            .add_peer("peer2".to_string(), "127.0.0.1:8002".parse().unwrap(), 75)
            .await;
        discovery
            .add_peer("peer3".to_string(), "127.0.0.1:8003".parse().unwrap(), 25)
            .await;

        // Mark one as connected
        discovery.mark_connected("peer1").await;

        let peers = discovery.get_peers_for_exchange().await;

        // Should only return non-connected peers (order is non-deterministic since
        // scores are zeroed in get_peers_for_exchange to prevent leaking internal state)
        assert_eq!(peers.len(), 2);
        let mut peer_ids: Vec<&str> = peers.iter().map(|p| p.id.as_str()).collect();
        peer_ids.sort();
        assert_eq!(peer_ids, vec!["peer2", "peer3"]);
    }
}
