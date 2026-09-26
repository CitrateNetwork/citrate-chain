//! Fail-closed startup guards for dangerous node configurations (PBA-R2).
//!
//! Each guard is a pure function over the resolved configuration so the refusal
//! logic is unit-tested without booting a node. `main` calls them before any
//! listener is bound or the producer starts.
//!
//! * PBA-L1a-007 — a production build refuses to mine with
//!   `CITRATE_REQUIRE_VALID_SIGNATURE` disabling mempool signature checks.
//! * PBA-L1a-008 — `rpc.trusted_proxies` is accepted only with a
//!   loopback-bound RPC (behind the proxy).
//! * PBA-L1a-012 — `rpc.allow_eth_send_transaction = true` is accepted only
//!   with a loopback RPC or the local devnet genesis profile (`"default"`).
//! * PBA-L1a-024 — the metrics server binds loopback by default and is
//!   disabled on an unparsable address.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

/// Parse a boolean-ish env value (`1/true/yes/on`, `0/false/no/off`).
fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// PBA-L1a-007: resolve whether the mempool verifies transaction signatures.
///
/// `env` is `CITRATE_REQUIRE_VALID_SIGNATURE`; `devnet_build` is the `devnet`
/// cargo feature. An unrecognised value fails closed (verification ON).
/// Disabling verification is refused outright when the node mines, unless the
/// binary is a devnet build.
pub fn resolve_require_valid_signature(
    env: Option<&str>,
    mining: bool,
    devnet_build: bool,
) -> Result<bool, String> {
    let require = env.and_then(parse_bool).unwrap_or(!devnet_build);
    if !require && mining && !devnet_build {
        return Err(
            "refusing to start: CITRATE_REQUIRE_VALID_SIGNATURE disables transaction \
             signature verification, and this node mines (--mine / mining.enabled). \
             A mining node requires signature checks (PBA-L1a-007). Unset the variable."
                .to_string(),
        );
    }
    Ok(require)
}

/// PBA-L1a-008 / PBA-L1a-012: RPC exposure policy (trusted proxies and
/// unsigned sends require a loopback bind).
pub fn check_rpc_exposure(
    rpc_enabled: bool,
    listen_addr: &SocketAddr,
    allow_eth_send_transaction: bool,
    trusted_proxies: &[IpAddr],
    genesis_profile: Option<&str>,
) -> Result<(), String> {
    if !rpc_enabled {
        return Ok(());
    }
    let loopback = listen_addr.ip().is_loopback();
    if !trusted_proxies.is_empty() && !loopback {
        return Err(format!(
            "refusing to start: rpc.trusted_proxies is set but RPC listens on {listen_addr}. \
             Forwarding headers are only trusted behind a loopback-bound RPC \
             (PBA-L1a-008). Bind RPC to \
             127.0.0.1 behind the proxy, or clear trusted_proxies."
        ));
    }
    if allow_eth_send_transaction && !loopback && genesis_profile != Some("default") {
        return Err(format!(
            "refusing to start: rpc.allow_eth_send_transaction = true requires a loopback RPC \
             (listening on {listen_addr}) outside the local devnet genesis profile \
             (PBA-L1a-012). Bind RPC to 127.0.0.1 or set allow_eth_send_transaction = false."
        ));
    }
    Ok(())
}

/// PBA-L1a-024: the metrics listen address. Defaults to loopback; an
/// unparsable `CITRATE_METRICS_ADDR` disables the metrics server (`None`)
/// instead of silently binding every interface.
pub fn resolve_metrics_addr(env: Option<&str>) -> Option<SocketAddr> {
    match env {
        None => Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9100))),
        Some(s) => s.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test literal is a socket address")
    }

    // ---- PBA-L1a-007 -------------------------------------------------------

    #[test]
    fn l1a_007_mining_with_signature_checks_disabled_is_refused() {
        for v in ["0", "false", "no", "off", "OFF"] {
            let err = resolve_require_valid_signature(Some(v), true, false)
                .expect_err("production mining node must refuse disabled signature checks");
            assert!(err.contains("PBA-L1a-007"), "{err}");
        }
    }

    #[test]
    fn l1a_007_non_mining_or_devnet_build_may_disable() {
        assert_eq!(
            resolve_require_valid_signature(Some("0"), false, false),
            Ok(false)
        );
        assert_eq!(
            resolve_require_valid_signature(Some("0"), true, true),
            Ok(false)
        );
    }

    #[test]
    fn l1a_007_default_and_garbage_fail_closed() {
        assert_eq!(resolve_require_valid_signature(None, true, false), Ok(true));
        assert_eq!(
            resolve_require_valid_signature(Some("maybe"), true, false),
            Ok(true)
        );
        assert_eq!(
            resolve_require_valid_signature(Some("1"), true, false),
            Ok(true)
        );
        // an explicit "on" wins over the devnet default (off)
        for v in ["1", "true", "yes", "on"] {
            assert_eq!(
                resolve_require_valid_signature(Some(v), false, true),
                Ok(true)
            );
        }
        // devnet build keeps its historical default (off) only when unset
        assert_eq!(
            resolve_require_valid_signature(None, false, true),
            Ok(false)
        );
    }

    // ---- PBA-L1a-008 / -012 ------------------------------------------------

    #[test]
    fn l1a_008_trusted_proxies_on_public_bind_is_refused() {
        let proxies = ["127.0.0.1".parse().expect("ip")];
        let err = check_rpc_exposure(true, &addr("0.0.0.0:8545"), false, &proxies, None)
            .expect_err("public bind + trusted proxies must be refused");
        assert!(err.contains("PBA-L1a-008"), "{err}");
        assert!(check_rpc_exposure(true, &addr("127.0.0.1:8545"), false, &proxies, None).is_ok());
    }

    #[test]
    fn l1a_012_public_unsigned_send_is_refused_outside_devnet() {
        for profile in [
            None,
            Some("team_testnet"),
            Some("testnet_beta"),
            Some("mainnet"),
        ] {
            let err = check_rpc_exposure(true, &addr("0.0.0.0:8545"), true, &[], profile)
                .expect_err("public eth_sendTransaction must be refused");
            assert!(err.contains("PBA-L1a-012"), "{err}");
        }
        // loopback, devnet profile, disabled RPC, or send off: allowed
        assert!(check_rpc_exposure(true, &addr("127.0.0.1:8545"), true, &[], None).is_ok());
        assert!(
            check_rpc_exposure(true, &addr("0.0.0.0:8545"), true, &[], Some("default")).is_ok()
        );
        assert!(check_rpc_exposure(false, &addr("0.0.0.0:8545"), true, &[], None).is_ok());
        assert!(check_rpc_exposure(true, &addr("0.0.0.0:8545"), false, &[], None).is_ok());
    }

    /// The shipped team-testnet profile must pass the guard (it used to ship
    /// 0.0.0.0 RPC + unsigned send on chain 40204).
    #[test]
    fn l1a_012_shipped_team_testnet_profile_is_safe() {
        let raw = include_str!("../config/team-testnet.toml");
        let cfg: crate::config::NodeConfig = toml::from_str(raw).expect("team-testnet.toml parses");
        check_rpc_exposure(
            cfg.rpc.enabled,
            &cfg.rpc.listen_addr,
            cfg.rpc.allow_eth_send_transaction,
            &cfg.rpc.trusted_proxies,
            cfg.chain.genesis_profile.as_deref(),
        )
        .expect("team-testnet.toml must not expose unsigned send publicly");
    }

    // ---- PBA-L1a-024 -------------------------------------------------------

    #[test]
    fn l1a_024_metrics_default_is_loopback_and_bad_addr_disables() {
        let d = resolve_metrics_addr(None).expect("default");
        assert!(
            d.ip().is_loopback(),
            "default metrics bind must be loopback, got {d}"
        );
        assert_eq!(d.port(), 9100);
        assert_eq!(resolve_metrics_addr(Some("not-an-addr")), None);
        assert_eq!(
            resolve_metrics_addr(Some("127.0.0.1:9200")),
            Some(addr("127.0.0.1:9200"))
        );
    }
}
