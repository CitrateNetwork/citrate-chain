// citrate/core/network/src/transport.rs
//
// TCP transport with optional Noise_XX encryption for peer-to-peer communication.
// When a NoiseKeypair is provided, all connections perform a Noise handshake first,
// then run the application Hello/HelloAck over the encrypted channel.

use crate::noise::{self, NoiseKeypair, NoiseSession};
use crate::peer::{Direction, Peer, PeerId, PeerInfo, PeerManager};
use crate::protocol::{NetworkMessage, ProtocolVersion};
use crate::NetworkError;
use bincode;
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use citrate_consensus::types::Hash;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, warn};

/// Parameters sent during handshake
#[derive(Debug, Clone)]
pub struct HandshakeParams {
    pub network_id: u32,
    pub genesis_hash: Hash,
    pub head_height: u64,
    pub head_hash: Hash,
}

/// TCP-based transport with optional Noise encryption and length-delimited frames.
pub struct NetworkTransport {
    peer_manager: Arc<PeerManager>,
    local_id: PeerId,
    params: HandshakeParams,
    noise_keypair: Option<Arc<NoiseKeypair>>,
}

const MAX_FRAME_LEN: usize = 1024 * 1024; // 1MB

impl NetworkTransport {
    pub fn new(peer_manager: Arc<PeerManager>, local_id: PeerId, params: HandshakeParams) -> Self {
        Self {
            peer_manager,
            local_id,
            params,
            noise_keypair: None,
        }
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

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, remote)) => {
                        let pm = pm.clone();
                        let local_id = local_id.clone();
                        let params = params.clone();
                        let noise_kp = noise_kp.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_inbound(stream, remote, pm, local_id, params, noise_kp)
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
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| NetworkError::TransportError(format!("connect {}: {}", addr, e)))?;
        let pm = self.peer_manager.clone();
        let local_id = self.local_id.clone();
        let params = self.params.clone();
        let noise_kp = self.noise_keypair.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_outbound(stream, addr, pm, local_id, params, noise_kp).await
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
) -> Result<(), NetworkError> {
    // Noise handshake (if enabled)
    let noise_session = if let Some(ref kp) = noise_keypair {
        Some(noise::handshake_responder(&mut stream, kp).await?)
    } else {
        None
    };

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
            (PeerId::new(peer_id), head_height, head_hash)
        }
        _ => return Err(NetworkError::ProtocolError("expected Hello".into())),
    };

    // Send HelloAck (encrypt if noise enabled)
    let ack = NetworkMessage::HelloAck {
        version: ProtocolVersion::CURRENT,
        head_height: params.head_height,
        head_hash: params.head_hash,
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
            peer_manager.remove_peer(&remote_id).await;
            break;
        }
        match frame {
            Ok(bytes) => {
                let plaintext = if let Some(ref ns) = noise_r {
                    match ns.decrypt(&bytes) {
                        Ok(pt) => pt,
                        Err(e) => {
                            warn!("decrypt failed from {}: {}", addr, e);
                            peer_manager.remove_peer(&remote_id).await;
                            break;
                        }
                    }
                } else {
                    bytes.to_vec()
                };
                match bincode::deserialize::<NetworkMessage>(&plaintext) {
                    Ok(msg) => {
                        peer_manager
                            .forward_incoming(remote_id.clone(), msg)
                            .await;
                    }
                    Err(e) => {
                        warn!("decode failed from {}: {}", addr, e);
                        break;
                    }
                }
            }
            Err(e) => {
                debug!("peer {} closed: {}", remote_id, e);
                peer_manager.remove_peer(&remote_id).await;
                break;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Outbound connection handler
// ---------------------------------------------------------------------------

async fn handle_outbound(
    mut stream: TcpStream,
    addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
    local_id: PeerId,
    params: HandshakeParams,
    noise_keypair: Option<Arc<NoiseKeypair>>,
) -> Result<(), NetworkError> {
    // Noise handshake (if enabled)
    let noise_session = if let Some(ref kp) = noise_keypair {
        Some(noise::handshake_initiator(&mut stream, kp).await?)
    } else {
        None
    };

    let noise_session = noise_session.map(Arc::new);

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME_LEN)
        .new_codec();
    let framed = Framed::new(stream, codec);
    let (mut sink, mut stream_rx) = framed.split();

    // Send Hello (encrypt if noise enabled)
    let hello = NetworkMessage::Hello {
        version: ProtocolVersion::CURRENT,
        network_id: params.network_id,
        genesis_hash: params.genesis_hash,
        head_height: params.head_height,
        head_hash: params.head_hash,
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
        let rid = if peer_id.is_empty() {
            format!("tcp_{}", addr)
        } else {
            peer_id
        };
        let remote_id = PeerId::new(rid);
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
                peer_manager.remove_peer(&remote_id).await;
                break;
            }
            match frame {
                Ok(bytes) => {
                    let plaintext = if let Some(ref ns) = noise_r {
                        match ns.decrypt(&bytes) {
                            Ok(pt) => pt,
                            Err(e) => {
                                warn!("decrypt failed from {}: {}", addr, e);
                                peer_manager.remove_peer(&remote_id).await;
                                break;
                            }
                        }
                    } else {
                        bytes.to_vec()
                    };
                    match bincode::deserialize::<NetworkMessage>(&plaintext) {
                        Ok(msg) => {
                            peer_manager
                                .forward_incoming(remote_id.clone(), msg)
                                .await;
                        }
                        Err(e) => {
                            warn!("decode failed from {}: {}", addr, e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("peer {} closed: {}", remote_id, e);
                    peer_manager.remove_peer(&remote_id).await;
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
