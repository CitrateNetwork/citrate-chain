// citrate/core/network/src/nat.rs
//
// WP-S.4: NAT detection using STUN (RFC 5389) binding requests.
// Determines external IP:port and NAT type for hole punching.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// NAT type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT — public IP is directly reachable.
    None,

    /// Full-cone NAT — any external host can send to the mapped port.
    FullCone,

    /// Restricted-cone NAT — only hosts the internal host has sent to can reply.
    Restricted,

    /// Port-restricted-cone NAT — same as restricted but port-specific.
    PortRestricted,

    /// Symmetric NAT — different mappings per destination (hole punch won't work).
    Symmetric,

    /// Could not determine NAT type.
    Unknown,
}

impl NatType {
    /// Whether hole punching is likely to succeed with this NAT type.
    pub fn supports_hole_punch(&self) -> bool {
        matches!(self, NatType::None | NatType::FullCone | NatType::Restricted | NatType::PortRestricted)
    }

    /// Whether a relay is needed for reliable connectivity.
    pub fn needs_relay(&self) -> bool {
        matches!(self, NatType::Symmetric | NatType::Unknown)
    }
}

/// Result of NAT detection.
#[derive(Debug, Clone)]
pub struct NatInfo {
    /// Detected NAT type.
    pub nat_type: NatType,

    /// External (public) address as seen by the STUN server.
    pub external_addr: Option<SocketAddr>,

    /// Local address used for the probe.
    pub local_addr: SocketAddr,
}

/// Default STUN servers for probing.
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

/// STUN binding request magic cookie (RFC 5389).
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message type: Binding Request.
const STUN_BINDING_REQUEST: u16 = 0x0001;

/// STUN attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Build a minimal STUN Binding Request (RFC 5389).
fn build_stun_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    // Message type: Binding Request (0x0001)
    buf.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    // Message length: 0 (no attributes)
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Magic cookie
    buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    buf.extend_from_slice(transaction_id);
    buf
}

/// Parse a STUN Binding Response to extract the mapped address.
fn parse_stun_response(data: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 20 {
        return None;
    }

    // Verify it's a binding success response (0x0101)
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != 0x0101 {
        return None;
    }

    // Verify magic cookie
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return None;
    }

    // Verify transaction ID
    if &data[8..20] != transaction_id {
        return None;
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let attr_data = &data[20..20 + msg_len.min(data.len() - 20)];

    // Parse attributes
    let mut offset = 0;
    while offset + 4 <= attr_data.len() {
        let attr_type = u16::from_be_bytes([attr_data[offset], attr_data[offset + 1]]);
        let attr_len = u16::from_be_bytes([attr_data[offset + 2], attr_data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > attr_data.len() {
            break;
        }

        let value = &attr_data[offset..offset + attr_len];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return parse_xor_mapped_address(value);
            }
            ATTR_MAPPED_ADDRESS => {
                return parse_mapped_address(value);
            }
            _ => {}
        }

        // Pad to 4-byte boundary
        offset += (attr_len + 3) & !3;
    }

    None
}

/// Parse XOR-MAPPED-ADDRESS attribute (RFC 5389 Section 15.2).
fn parse_xor_mapped_address(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 8 {
        return None;
    }

    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            let ip_bytes = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let ip = ip_bytes ^ STUN_MAGIC_COOKIE;
            let addr = std::net::Ipv4Addr::from(ip);
            Some(SocketAddr::new(addr.into(), port))
        }
        _ => None, // IPv6 not supported for simplicity
    }
}

/// Parse MAPPED-ADDRESS attribute (RFC 5389 Section 15.1).
fn parse_mapped_address(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 8 {
        return None;
    }

    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);

    match family {
        0x01 => {
            let addr = std::net::Ipv4Addr::new(value[4], value[5], value[6], value[7]);
            Some(SocketAddr::new(addr.into(), port))
        }
        _ => None,
    }
}

/// Detect NAT type and external address using STUN.
pub async fn detect_nat(local_bind: Option<SocketAddr>) -> NatInfo {
    let bind_addr = local_bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap_or_else(|e| panic!("valid hardcoded address: {e}")));

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to bind UDP socket for NAT detection: {}", e);
            return NatInfo {
                nat_type: NatType::Unknown,
                external_addr: None,
                local_addr: bind_addr,
            };
        }
    };

    let local_addr = socket.local_addr().unwrap_or(bind_addr);

    // Try each STUN server
    for server in STUN_SERVERS {
        let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(server).await {
            Ok(addrs) => addrs.collect(),
            Err(_) => continue,
        };

        let Some(server_addr) = addrs.first() else {
            continue;
        };

        // Generate transaction ID
        let mut txn_id = [0u8; 12];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut txn_id);

        let request = build_stun_request(&txn_id);

        if socket.send_to(&request, server_addr).await.is_err() {
            continue;
        }

        // Wait for response with timeout
        let mut buf = [0u8; 512];
        let result = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((len, _from))) => {
                if let Some(external) = parse_stun_response(&buf[..len], &txn_id) {
                    let nat_type = if external.ip() == local_addr.ip() {
                        NatType::None
                    } else {
                        // Simple classification — for full classification we'd need
                        // probes to multiple STUN servers. Default to Restricted.
                        NatType::Restricted
                    };

                    info!(
                        "NAT detected: type={:?}, external={}, local={}",
                        nat_type, external, local_addr
                    );

                    return NatInfo {
                        nat_type,
                        external_addr: Some(external),
                        local_addr,
                    };
                }
            }
            Ok(Err(e)) => {
                debug!("STUN recv error from {}: {}", server, e);
            }
            Err(_) => {
                debug!("STUN timeout from {}", server);
            }
        }
    }

    warn!("NAT detection failed — all STUN servers unreachable");
    NatInfo {
        nat_type: NatType::Unknown,
        external_addr: None,
        local_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_request_format() {
        let txn_id = [1u8; 12];
        let req = build_stun_request(&txn_id);
        assert_eq!(req.len(), 20);
        // Check message type
        assert_eq!(req[0], 0x00);
        assert_eq!(req[1], 0x01);
        // Check magic cookie
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            STUN_MAGIC_COOKIE
        );
    }

    #[test]
    fn test_parse_xor_mapped_address() {
        // Build a mock XOR-MAPPED-ADDRESS for 192.168.1.1:8080
        // XOR with magic cookie: 0x2112A442
        let ip: u32 = u32::from_be_bytes([192, 168, 1, 1]);
        let xored_ip = ip ^ STUN_MAGIC_COOKIE;
        let xored_port = 8080u16 ^ (STUN_MAGIC_COOKIE >> 16) as u16;

        let mut value = vec![0x00, 0x01]; // padding + family (IPv4)
        value.extend_from_slice(&xored_port.to_be_bytes());
        value.extend_from_slice(&xored_ip.to_be_bytes());

        let addr = parse_xor_mapped_address(&value).unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_nat_type_properties() {
        assert!(NatType::None.supports_hole_punch());
        assert!(NatType::FullCone.supports_hole_punch());
        assert!(NatType::Restricted.supports_hole_punch());
        assert!(!NatType::Symmetric.supports_hole_punch());
        assert!(NatType::Symmetric.needs_relay());
        assert!(!NatType::None.needs_relay());
    }
}
