//! Bootnode address parsing and DNS resolution.
//!
//! Bootnode strings take the form `[<identity>@]host:port`, where the optional
//! `<identity>` is a `noise_<hex>` trust root (or any peer id) and `host` may be
//! either a literal IP (`142.93.50.217`) or a DNS hostname (`boot1.citrate.ai`).
//!
//! This is the **single shared resolver**. The node daemon, the discovery
//! subsystem, and every embedded-node GUI route bootnode strings through it, so
//! hostname bootnodes connect identically everywhere. Previously each call site
//! parsed addresses with `SocketAddr::parse`, which only accepts literal IPs —
//! the baked `testnet-beta.toml` ships hostnames, so a fresh node got zero
//! peers out of the box.

use crate::peer::PeerId;
use std::net::SocketAddr;

/// Split a bootnode string into its optional identity and the `host:port`
/// remainder. Does not touch DNS — purely string work.
pub fn split_bootnode(s: &str) -> (Option<PeerId>, &str) {
    match s.split_once('@') {
        Some((pid, rest)) => (Some(PeerId::new(pid.trim().to_string())), rest.trim()),
        None => (None, s.trim()),
    }
}

/// Resolve a bootnode string `[<identity>@]host:port` to a concrete socket
/// address, performing DNS resolution when `host` is a hostname rather than a
/// literal IP. Returns the declared identity (if any) alongside the resolved
/// address, or `None` if the address can be neither parsed nor resolved.
///
/// When a hostname resolves to multiple addresses (A + AAAA, round-robin, …)
/// the first is used — matching the prior literal-IP behaviour of a single
/// dial target per bootnode entry.
pub async fn resolve_bootnode(s: &str) -> Option<(Option<PeerId>, SocketAddr)> {
    let (peer_id, host_port) = split_bootnode(s);
    let addr = match host_port.parse::<SocketAddr>() {
        Ok(addr) => addr,
        // Not a literal IP — treat as hostname:port and resolve via DNS.
        Err(_) => tokio::net::lookup_host(host_port).await.ok()?.next()?,
    };
    Some((peer_id, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_noise_identity_from_host() {
        let (pid, host) = split_bootnode("noise_abc123@boot1.citrate.ai:30303");
        assert_eq!(pid.map(|p| p.0), Some("noise_abc123".to_string()));
        assert_eq!(host, "boot1.citrate.ai:30303");
    }

    #[test]
    fn splits_bare_address_without_identity() {
        let (pid, host) = split_bootnode("142.93.50.217:30303");
        assert!(pid.is_none());
        assert_eq!(host, "142.93.50.217:30303");
    }

    #[tokio::test]
    async fn resolves_literal_ip_without_dns() {
        let (pid, addr) =
            resolve_bootnode("noise_f356@142.93.50.217:30303").await.expect("literal IP resolves");
        assert_eq!(pid.map(|p| p.0), Some("noise_f356".to_string()));
        assert_eq!(addr.to_string(), "142.93.50.217:30303");
    }

    #[tokio::test]
    async fn resolves_loopback_hostname() {
        // `localhost` is always resolvable without network egress.
        let (_, addr) = resolve_bootnode("localhost:30303").await.expect("localhost resolves");
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 30303);
    }

    #[tokio::test]
    async fn unresolvable_host_returns_none() {
        assert!(resolve_bootnode("nonexistent.invalid:30303").await.is_none());
    }
}
