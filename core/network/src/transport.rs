// citrate/core/network/src/transport.rs
//
// TCP transport with optional Noise_XX encryption for peer-to-peer communication.
// When a NoiseKeypair is provided, all connections perform a Noise handshake first,
// then run the application Hello/HelloAck over the encrypted channel.

use crate::noise::{self, NoiseKeypair};
use crate::peer::{Direction, Peer, PeerId, PeerInfo, PeerManager};
use crate::protocol::{NetworkMessage, ProtocolVersion};
use crate::NetworkError;
use bincode;
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use citrate_consensus::types::Hash;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, info, warn};

/// Parameters sent during handshake.
#[derive(Debug, Clone)]
pub struct HandshakeParams {
    pub network_id: u32,
    pub genesis_hash: Hash,
    /// LIVE head (height, hash), shared with the node and read FRESH at every
    /// handshake. Previously this was a static (height, hash) snapshot captured
    /// at transport construction — i.e. genesis (height 0) for a node that boots
    /// fresh. A producer therefore advertised head 0 forever, so no follower's
    /// Hello/HelloAck sync-trigger ever fired and no one ever synced. The node
    /// updates this via `HandshakeParams::head` as its applied tip advances.
    pub head: Arc<tokio::sync::RwLock<(u64, Hash)>>,
}

impl HandshakeParams {
    /// Read the current advertised head (height, hash).
    pub async fn current_head(&self) -> (u64, Hash) {
        *self.head.read().await
    }
}

/// TCP-based transport with optional Noise encryption and length-delimited frames.
pub struct NetworkTransport {
    peer_manager: Arc<PeerManager>,
    local_id: PeerId,
    params: HandshakeParams,
    noise_keypair: Option<Arc<NoiseKeypair>>,
    /// Allowed peer Noise public keys (hex-encoded).
    /// When non-empty, only peers whose Noise public key hex is in this set can connect.
    /// When empty, all peers are allowed (open mode).
    allowed_peers: Arc<HashSet<String>>,
}

const MAX_FRAME_LEN: usize = 1024 * 1024; // 1MB

impl NetworkTransport {
    pub fn new(peer_manager: Arc<PeerManager>, local_id: PeerId, params: HandshakeParams) -> Self {
        Self {
            peer_manager,
            local_id,
            params,
            noise_keypair: None,
            allowed_peers: Arc::new(HashSet::new()),
        }
    }

    /// Set the peer whitelist. Only peers whose Noise public key hex is in this set
    /// will be allowed to connect. Empty set means open mode.
    pub fn with_allowed_peers(mut self, peers: Vec<String>) -> Self {
        if !peers.is_empty() {
            info!("P2P peer whitelist enabled: {} allowed keys", peers.len());
        }
        self.allowed_peers = Arc::new(peers.into_iter().collect());
        self
    }

    /// Enable Noise_XX encrypted transport.
    pub fn with_noise(mut self, keypair: NoiseKeypair) -> Self {
        info!(
            "Noise encryption enabled (pubkey={}...)",
            &keypair.public_key_hex()[..16]
        );
        self.noise_keypair = Some(Arc::new(keypair));
        self
    }

    /// Start an async TCP listener and accept inbound peers
    pub async fn start_listener(&self, addr: SocketAddr) -> Result<(), NetworkError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| NetworkError::TransportError(format!("bind {}: {}", addr, e)))?;
        info!("P2P listener on {}", addr);

        let pm = self.peer_manager.clone();
        let local_id = self.local_id.clone();
        let params = self.params.clone();
        let noise_kp = self.noise_keypair.clone();
        let allowed = self.allowed_peers.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, remote)) => {
                        // PT-11: Reject inbound connections before Noise handshake
                        // when at capacity, preventing CPU-expensive handshake flooding
                        let (total, _inbound, _outbound) = pm.get_peer_counts().await;
                        if total >= pm.max_peers() {
                            debug!("Rejecting inbound from {} — at capacity ({}/{})",
                                   remote, total, pm.max_peers());
                            drop(stream);
                            continue;
                        }

                        let pm = pm.clone();
                        let local_id = local_id.clone();
                        let params = params.clone();
                        let noise_kp = noise_kp.clone();
                        let allowed = allowed.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_inbound(stream, remote, pm, local_id, params, noise_kp, allowed)
                                    .await
                            {
                                warn!("inbound error from {}: {}", remote, e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("listener accept error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Dial an outbound peer
    pub async fn connect_to(&self, addr: SocketAddr) -> Result<(), NetworkError> {
        self.connect_to_inner(addr, None).await
    }

    /// Dial an outbound peer and verify its Noise identity matches `expected_id`.
    ///
    /// WP-H.2: Bootnode trust root enforcement. When a bootnode declares its
    /// Noise public key (e.g. `noise_<hex>@ip:port`), we verify the remote's
    /// Noise static key produces the expected PeerId. This prevents DNS/IP
    /// hijack attacks from impersonating trusted bootnodes.
    pub async fn connect_to_trusted(&self, addr: SocketAddr, expected_id: PeerId) -> Result<(), NetworkError> {
        self.connect_to_inner(addr, Some(expected_id)).await
    }

    async fn connect_to_inner(&self, addr: SocketAddr, expected_id: Option<PeerId>) -> Result<(), NetworkError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| NetworkError::TransportError(format!("connect {}: {}", addr, e)))?;
        let pm = self.peer_manager.clone();
        let local_id = self.local_id.clone();
        let params = self.params.clone();
        let noise_kp = self.noise_keypair.clone();
        let allowed = self.allowed_peers.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_outbound(stream, addr, pm, local_id, params, noise_kp, expected_id, allowed).await
            {
                warn!("outbound error to {}: {}", addr, e);
            }
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Inbound connection handler
// ---------------------------------------------------------------------------

async fn handle_inbound(
    mut stream: TcpStream,
    addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
    local_id: PeerId,
    params: HandshakeParams,
    noise_keypair: Option<Arc<NoiseKeypair>>,
    allowed_peers: Arc<HashSet<String>>,
) -> Result<(), NetworkError> {
    // Noise handshake (if enabled)
    let noise_session = if let Some(ref kp) = noise_keypair {
        Some(noise::handshake_responder(&mut stream, kp).await?)
    } else {
        None
    };

    // Sprint 03: Peer whitelist check — reject non-whitelisted peers after Noise handshake.
    if !allowed_peers.is_empty() {
        if let Some(ref ns) = noise_session {
            let remote_hex = hex::encode(ns.remote_public_key());
            if !allowed_peers.contains(&remote_hex) {
                warn!(
                    "PEER_WHITELIST_REJECTED inbound from {} (noise_key={}...)",
                    addr, &remote_hex[..16]
                );
                return Err(NetworkError::ProtocolError(
                    "peer not in allowed_peers whitelist".into(),
                ));
            }
            debug!("Peer whitelist check passed for {}", &remote_hex[..16]);
        } else {
            warn!("Peer whitelist configured but Noise is disabled — rejecting {}", addr);
            return Err(NetworkError::ProtocolError(
                "peer whitelist requires Noise encryption".into(),
            ));
        }
    }

    let noise_session = noise_session.map(Arc::new);

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec();
    let framed = Framed::new(stream, codec);
    let (mut sink, mut stream_rx) = framed.split();

    // Expect Hello from remote (decrypt if noise enabled)
    let hello_bytes = match stream_rx.next().await {
        Some(Ok(bytes)) => {
            if let Some(ref ns) = noise_session {
                BytesMut::from(ns.decrypt(&bytes)?.as_slice())
            } else {
                bytes
            }
        }
        Some(Err(e)) => return Err(NetworkError::TransportError(format!("read: {}", e))),
        None => return Err(NetworkError::TransportError("eof".into())),
    };

    let hello: NetworkMessage = bincode::deserialize(&hello_bytes)
        .map_err(|e| NetworkError::ProtocolError(format!("decode: {}", e)))?;

    let (remote_id, remote_head_height, remote_head_hash) = match hello {
        NetworkMessage::Hello {
            version,
            network_id,
            genesis_hash,
            head_height,
            head_hash,
            peer_id,
        } => {
            if !version.is_compatible(&ProtocolVersion::CURRENT) {
                return Err(NetworkError::ProtocolError("incompatible version".into()));
            }
            if network_id != params.network_id || genesis_hash != params.genesis_hash {
                return Err(NetworkError::ProtocolError("network mismatch".into()));
            }
            // WP-H.1: Verify claimed peer_id matches Noise static key identity.
            // Without this check, an attacker can claim any peer_id in their Hello
            // message while the Noise handshake proves a completely different key.
            let verified_id = if let Some(ref ns) = noise_session {
                let expected = ns.expected_remote_peer_id();
                let claimed = PeerId::new(peer_id);
                if claimed != expected {
                    warn!(
                        "IDENTITY_MISMATCH from {}: claimed={}, noise_key={}",
                        addr, claimed, expected
                    );
                    return Err(NetworkError::ProtocolError(
                        "peer_id does not match Noise static key".into(),
                    ));
                }
                expected
            } else {
                PeerId::new(peer_id)
            };
            (verified_id, head_height, head_hash)
        }
        _ => return Err(NetworkError::ProtocolError("expected Hello".into())),
    };

    // Send HelloAck (encrypt if noise enabled) — advertise our LIVE head.
    let (adv_height, adv_hash) = params.current_head().await;
    let ack = NetworkMessage::HelloAck {
        version: ProtocolVersion::CURRENT,
        head_height: adv_height,
        head_hash: adv_hash,
        peer_id: local_id.0.clone(),
    };
    let ser = bincode::serialize(&ack)
        .map_err(|e| NetworkError::ProtocolError(format!("encode: {}", e)))?;
    let payload = if let Some(ref ns) = noise_session {
        ns.encrypt(&ser)?
    } else {
        ser
    };
    sink.send(bytes::Bytes::from(payload))
        .await
        .map_err(|e| NetworkError::TransportError(format!("write: {}", e)))?;

    // Create peer channels
    let (to_wire_tx, mut to_wire_rx) = mpsc::channel::<NetworkMessage>(256);
    let (_from_wire_tx, from_wire_rx) = mpsc::channel::<NetworkMessage>(256);

    let mut info = PeerInfo::new(remote_id.clone(), addr, Direction::Inbound);
    info.state = super::peer::PeerState::Connected;
    info.head_height = remote_head_height;
    info.head_hash = remote_head_hash;
    let peer = Arc::new(Peer::new(info, to_wire_tx.clone(), from_wire_rx));
    peer_manager.add_peer(peer.clone()).await?;

    let encrypted = noise_session.is_some();
    info!(
        "Inbound peer connected: {} from {} (encrypted={})",
        remote_id, addr, encrypted
    );

    // Writer: forward messages from send queue to wire
    let noise_w = noise_session.clone();
    tokio::spawn(async move {
        while let Some(msg) = to_wire_rx.recv().await {
            match bincode::serialize(&msg) {
                Ok(ser) => {
                    let payload = if let Some(ref ns) = noise_w {
                        match ns.encrypt(&ser) {
                            Ok(ct) => ct,
                            Err(e) => {
                                warn!("encrypt failed: {}", e);
                                break;
                            }
                        }
                    } else {
                        ser
                    };
                    if let Err(e) = sink.send(bytes::Bytes::from(payload)).await {
                        warn!("send to {} failed: {}", addr, e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("encode failed: {}", e);
                    break;
                }
            }
        }
    });

    // Reader loop with rate limiting
    let noise_r = noise_session;
    let mut msg_count = 0u32;
    let mut window_start = std::time::Instant::now();
    const MAX_MSGS_PER_SEC: u32 = 200;
    while let Some(frame) = stream_rx.next().await {
        if window_start.elapsed() > std::time::Duration::from_secs(1) {
            window_start = std::time::Instant::now();
            msg_count = 0;
        }
        msg_count += 1;
        if msg_count > MAX_MSGS_PER_SEC {
            warn!("rate limit exceeded from {} — closing", addr);
            peer_manager.remove_peer_if_current(&remote_id, &peer).await;
            break;
        }
        match frame {
            Ok(bytes) => {
                let plaintext = if let Some(ref ns) = noise_r {
                    match ns.decrypt(&bytes) {
                        Ok(pt) => pt,
                        Err(e) => {
                            warn!("decrypt failed from {}: {}", addr, e);
                            peer_manager.remove_peer_if_current(&remote_id, &peer).await;
                            break;
                        }
                    }
                } else {
                    bytes.to_vec()
                };
                // SECURITY (C-01 network variant): decode_inbound strips any
                // peer-asserted `ecdsa_verified` flag at the deserialization
                // boundary, so a gossiped tx can never claim a verification
                // this node did not perform.
                match NetworkMessage::decode_inbound(&plaintext) {
                    Ok(msg) => {
                        peer_manager
                            .forward_incoming(remote_id.clone(), msg)
                            .await;
                    }
                    Err(e) => {
                        // Was: break WITHOUT remove_peer — the peer stayed registered
                        // and counted after a decode failure, leaking an inbound slot
                        // (every other exit from this loop de-registers). De-register.
                        warn!("decode failed from {}: {}", addr, e);
                        peer_manager.remove_peer_if_current(&remote_id, &peer).await;
                        break;
                    }
                }
            }
            Err(e) => {
                debug!("peer {} closed: {}", remote_id, e);
                peer_manager.remove_peer_if_current(&remote_id, &peer).await;
                break;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Outbound connection handler
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_outbound(
    mut stream: TcpStream,
    addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
    local_id: PeerId,
    params: HandshakeParams,
    noise_keypair: Option<Arc<NoiseKeypair>>,
    expected_id: Option<PeerId>,
    allowed_peers: Arc<HashSet<String>>,
) -> Result<(), NetworkError> {
    // Noise handshake (if enabled)
    let noise_session = if let Some(ref kp) = noise_keypair {
        Some(noise::handshake_initiator(&mut stream, kp).await?)
    } else {
        None
    };

    // Sprint 03: Peer whitelist check for outbound connections too.
    if !allowed_peers.is_empty() {
        if let Some(ref ns) = noise_session {
            let remote_hex = hex::encode(ns.remote_public_key());
            if !allowed_peers.contains(&remote_hex) {
                warn!(
                    "PEER_WHITELIST_REJECTED outbound to {} (noise_key={}...)",
                    addr, &remote_hex[..16]
                );
                return Err(NetworkError::ProtocolError(
                    "peer not in allowed_peers whitelist".into(),
                ));
            }
        }
    }

    let noise_session = noise_session.map(Arc::new);

    // WP-H.2: Bootnode trust root enforcement.
    // If an expected_id was provided (e.g. from `noise_<hex>@ip:port` bootnode config),
    // verify the remote Noise static key produces that PeerId. This catches DNS/IP
    // hijack attacks where an attacker redirects traffic to their own Noise key.
    if let Some(ref expected) = expected_id {
        if let Some(ref ns) = noise_session {
            let actual = ns.expected_remote_peer_id();
            if &actual != expected {
                warn!(
                    "BOOTNODE_TRUST_VIOLATION at {}: expected={}, actual={}",
                    addr, expected, actual
                );
                return Err(NetworkError::ProtocolError(
                    "bootnode Noise key does not match expected trust root".into(),
                ));
            }
            info!("Bootnode trust root verified for {}", addr);
        } else {
            warn!(
                "Bootnode trust root configured for {} but Noise is disabled — cannot verify",
                addr
            );
        }
    }

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec();
    let framed = Framed::new(stream, codec);
    let (mut sink, mut stream_rx) = framed.split();

    // Send Hello (encrypt if noise enabled) — advertise our LIVE head.
    let (adv_height, adv_hash) = params.current_head().await;
    let hello = NetworkMessage::Hello {
        version: ProtocolVersion::CURRENT,
        network_id: params.network_id,
        genesis_hash: params.genesis_hash,
        head_height: adv_height,
        head_hash: adv_hash,
        peer_id: local_id.0.clone(),
    };
    let ser = bincode::serialize(&hello)
        .map_err(|e| NetworkError::ProtocolError(format!("encode: {}", e)))?;
    let payload = if let Some(ref ns) = noise_session {
        ns.encrypt(&ser)?
    } else {
        ser
    };
    sink.send(bytes::Bytes::from(payload))
        .await
        .map_err(|e| NetworkError::TransportError(format!("write: {}", e)))?;

    // Expect HelloAck (decrypt if noise enabled)
    let ack_bytes = match stream_rx.next().await {
        Some(Ok(bytes)) => {
            if let Some(ref ns) = noise_session {
                BytesMut::from(ns.decrypt(&bytes)?.as_slice())
            } else {
                bytes
            }
        }
        Some(Err(e)) => return Err(NetworkError::TransportError(format!("read: {}", e))),
        None => return Err(NetworkError::TransportError("eof".into())),
    };

    let ack: NetworkMessage = bincode::deserialize(&ack_bytes)
        .map_err(|e| NetworkError::ProtocolError(format!("decode: {}", e)))?;

    if let NetworkMessage::HelloAck {
        version,
        peer_id,
        head_height,
        head_hash,
    } = ack
    {
        if !version.is_compatible(&ProtocolVersion::CURRENT) {
            return Err(NetworkError::ProtocolError("incompatible ack".into()));
        }
        // WP-H.1: Verify claimed peer_id matches Noise static key identity.
        // Without this check, a MITM could impersonate a bootnode by claiming
        // its peer_id in the HelloAck while holding a different Noise key.
        let remote_id = if let Some(ref ns) = noise_session {
            let expected = ns.expected_remote_peer_id();
            if !peer_id.is_empty() {
                let claimed = PeerId::new(peer_id);
                if claimed != expected {
                    warn!(
                        "IDENTITY_MISMATCH from {}: claimed={}, noise_key={}",
                        addr, claimed, expected
                    );
                    return Err(NetworkError::ProtocolError(
                        "peer_id does not match Noise static key".into(),
                    ));
                }
            }
            expected
        } else if peer_id.is_empty() {
            PeerId::new(format!("tcp_{}", addr))
        } else {
            PeerId::new(peer_id)
        };
        // Create peer channels
        let (to_wire_tx, mut to_wire_rx) = mpsc::channel::<NetworkMessage>(256);
        let (_from_wire_tx, from_wire_rx) = mpsc::channel::<NetworkMessage>(256);
        let mut info = PeerInfo::new(remote_id.clone(), addr, Direction::Outbound);
        info.state = super::peer::PeerState::Connected;
        info.head_height = head_height;
        info.head_hash = head_hash;
        let peer = Arc::new(Peer::new(info, to_wire_tx.clone(), from_wire_rx));
        peer_manager.add_peer(peer.clone()).await?;

        let encrypted = noise_session.is_some();
        info!(
            "Outbound peer connected: {} at {} (encrypted={})",
            remote_id, addr, encrypted
        );

        // Writer task
        let noise_w = noise_session.clone();
        tokio::spawn(async move {
            while let Some(msg) = to_wire_rx.recv().await {
                match bincode::serialize(&msg) {
                    Ok(ser) => {
                        let payload = if let Some(ref ns) = noise_w {
                            match ns.encrypt(&ser) {
                                Ok(ct) => ct,
                                Err(e) => {
                                    warn!("encrypt failed: {}", e);
                                    break;
                                }
                            }
                        } else {
                            ser
                        };
                        if let Err(e) = sink.send(bytes::Bytes::from(payload)).await {
                            warn!("send to {} failed: {}", addr, e);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("encode failed: {}", e);
                        break;
                    }
                }
            }
        });

        // Reader loop with rate limiting
        let noise_r = noise_session;
        let mut msg_count = 0u32;
        let mut window_start = std::time::Instant::now();
        const MAX_MSGS_PER_SEC: u32 = 200;
        while let Some(frame) = stream_rx.next().await {
            if window_start.elapsed() > std::time::Duration::from_secs(1) {
                window_start = std::time::Instant::now();
                msg_count = 0;
            }
            msg_count += 1;
            if msg_count > MAX_MSGS_PER_SEC {
                warn!("rate limit exceeded from {} — closing", addr);
                peer_manager.remove_peer_if_current(&remote_id, &peer).await;
                break;
            }
            match frame {
                Ok(bytes) => {
                    let plaintext = if let Some(ref ns) = noise_r {
                        match ns.decrypt(&bytes) {
                            Ok(pt) => pt,
                            Err(e) => {
                                warn!("decrypt failed from {}: {}", addr, e);
                                peer_manager.remove_peer_if_current(&remote_id, &peer).await;
                                break;
                            }
                        }
                    } else {
                        bytes.to_vec()
                    };
                    // SECURITY (C-01 network variant): sanitize at decode.
                    match NetworkMessage::decode_inbound(&plaintext) {
                        Ok(msg) => {
                            peer_manager
                                .forward_incoming(remote_id.clone(), msg)
                                .await;
                        }
                        Err(e) => {
                            // de-register on decode failure (was a bare break →
                            // leaked an outbound slot; see the inbound path).
                            warn!("decode failed from {}: {}", addr, e);
                            peer_manager.remove_peer_if_current(&remote_id, &peer).await;
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("peer {} closed: {}", remote_id, e);
                    peer_manager.remove_peer_if_current(&remote_id, &peer).await;
                    break;
                }
            }
        }
        Ok(())
    } else {
        Err(NetworkError::ProtocolError("expected HelloAck".into()))
    }
}

// helper functions removed in favor of split-based loops
