//! HUP-S6.5 / federation F-5: faucet readiness (`GET /ready`).
//!
//! `/health` answers whether the process is up. `/ready` answers whether a drip could succeed
//! right now, which is what the desktop app and an operator's monitor need:
//!
//! - the RPC answers `eth_chainId` with the configured chain id;
//! - the faucet account's balance (`eth_getBalance` at `latest`) covers one drip plus its gas.
//!
//! Data sources (Rule 7): `eth_chainId` and `eth_getBalance(faucet_address, "latest")` on
//! `CITRATE_RPC_URL`.
//!
//! `/ready` is public, so the probe result is cached for [`CACHE_TTL`]: however often it is
//! called, the faucet makes at most two RPC calls per TTL.

use primitive_types::U256;
use serde::Serialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a probe result is reused.
pub const CACHE_TTL: Duration = Duration::from_secs(15);
/// RPC timeout for each probe call.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// What `/ready` reports.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Readiness {
    pub ready: bool,
    pub rpc_reachable: bool,
    pub chain_id: Option<u64>,
    pub chain_id_matches: bool,
    /// `None` when the balance could not be read.
    pub balance_sufficient: Option<bool>,
    /// Why the faucet is not ready, in plain words. `None` when ready.
    pub reason: Option<String>,
    /// Unix seconds of the probe.
    pub checked_at: u64,
}

/// Parse a JSON-RPC quantity (`0x…`) as U256.
pub fn parse_quantity(v: &serde_json::Value) -> Option<U256> {
    let s = v.as_str()?.strip_prefix("0x")?;
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    U256::from_str_radix(s, 16).ok()
}

/// Combine the two reads into a verdict (pure, so the rules are testable without a node).
pub fn assess(
    chain_id: Result<u64, String>,
    expected_chain_id: u64,
    balance: Result<U256, String>,
    min_balance_wei: u128,
    now: u64,
) -> Readiness {
    match chain_id {
        Err(e) => Readiness {
            ready: false,
            rpc_reachable: false,
            chain_id: None,
            chain_id_matches: false,
            balance_sufficient: None,
            reason: Some(format!("the chain RPC is not answering ({e})")),
            checked_at: now,
        },
        Ok(id) if id != expected_chain_id => Readiness {
            ready: false,
            rpc_reachable: true,
            chain_id: Some(id),
            chain_id_matches: false,
            balance_sufficient: None,
            reason: Some(format!(
                "the chain RPC reports chain id {id}, expected {expected_chain_id}"
            )),
            checked_at: now,
        },
        Ok(id) => match balance {
            Err(e) => Readiness {
                ready: false,
                rpc_reachable: true,
                chain_id: Some(id),
                chain_id_matches: true,
                balance_sufficient: None,
                reason: Some(format!("the faucet balance could not be read ({e})")),
                checked_at: now,
            },
            Ok(b) => {
                let enough = b >= U256::from(min_balance_wei);
                Readiness {
                    ready: enough,
                    rpc_reachable: true,
                    chain_id: Some(id),
                    chain_id_matches: true,
                    balance_sufficient: Some(enough),
                    reason: (!enough)
                        .then(|| "the faucet account cannot cover another drip".to_string()),
                    checked_at: now,
                }
            }
        },
    }
}

async fn rpc_value(
    client: &reqwest::Client,
    rpc_url: &str,
    api_key: Option<&str>,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let mut req = client
        .post(rpc_url)
        .timeout(PROBE_TIMEOUT)
        .json(&serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}));
    if let Some(k) = api_key {
        req = req.header("X-API-Key", k);
    }
    let resp = req.send().await.map_err(|e| format!("{method}: {e}"))?;
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("{method}: unreadable reply ({e})"))?;
    if let Some(err) = json.get("error") {
        return Err(format!("{method}: {err}"));
    }
    json.get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: no result"))
}

/// Run the probe against the RPC.
pub async fn probe(
    client: &reqwest::Client,
    rpc_url: &str,
    api_key: Option<&str>,
    expected_chain_id: u64,
    faucet_address_hex: &str,
    min_balance_wei: u128,
    now: u64,
) -> Readiness {
    let chain_id = rpc_value(
        client,
        rpc_url,
        api_key,
        "eth_chainId",
        serde_json::json!([]),
    )
    .await
    .and_then(|v| {
        parse_quantity(&v)
            .filter(|q| *q <= U256::from(u64::MAX))
            .map(|q| q.as_u64())
            .ok_or_else(|| "eth_chainId: malformed".to_string())
    });
    let balance = if chain_id.is_ok() {
        rpc_value(
            client,
            rpc_url,
            api_key,
            "eth_getBalance",
            serde_json::json!([faucet_address_hex, "latest"]),
        )
        .await
        .and_then(|v| parse_quantity(&v).ok_or_else(|| "eth_getBalance: malformed".to_string()))
    } else {
        Err("not read".to_string())
    };
    assess(chain_id, expected_chain_id, balance, min_balance_wei, now)
}

/// A TTL cache around [`probe`].
#[derive(Default)]
pub struct ReadinessCache {
    last: Mutex<Option<(Instant, Readiness)>>,
}

impl ReadinessCache {
    /// The cached result, if it is younger than `ttl`.
    pub fn fresh(&self, ttl: Duration) -> Option<Readiness> {
        let g = self.last.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref()
            .filter(|(at, _)| at.elapsed() < ttl)
            .map(|(_, r)| r.clone())
    }

    /// Store a new result.
    pub fn store(&self, r: Readiness) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), r));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u128 = 10_000_000_000_000_000_000 + 21_000 * 1_000_000_000;

    #[test]
    fn quantity_parsing() {
        assert_eq!(
            parse_quantity(&serde_json::json!("0x9d0c")),
            Some(U256::from(40204u64))
        );
        assert_eq!(parse_quantity(&serde_json::json!("0x")), None);
        assert_eq!(parse_quantity(&serde_json::json!("9d0c")), None);
        assert_eq!(parse_quantity(&serde_json::json!(5)), None);
        assert_eq!(
            parse_quantity(&serde_json::json!(format!("0x{}", "f".repeat(65)))),
            None
        );
    }

    #[test]
    fn ready_only_when_chain_matches_and_balance_covers_a_drip() {
        let ok = assess(Ok(40204), 40204, Ok(U256::from(MIN)), MIN, 7);
        assert!(ok.ready);
        assert_eq!(ok.reason, None);
        assert_eq!(ok.balance_sufficient, Some(true));

        let low = assess(Ok(40204), 40204, Ok(U256::from(MIN - 1)), MIN, 7);
        assert!(!low.ready);
        assert_eq!(low.balance_sufficient, Some(false));
        assert!(low.reason.as_deref().unwrap_or("").contains("cannot cover"));

        let wrong = assess(Ok(1), 40204, Ok(U256::from(MIN)), MIN, 7);
        assert!(!wrong.ready && wrong.rpc_reachable && !wrong.chain_id_matches);

        let down = assess(Err("refused".into()), 40204, Err("not read".into()), MIN, 7);
        assert!(!down.ready && !down.rpc_reachable);
        assert_eq!(down.balance_sufficient, None);

        let unread = assess(Ok(40204), 40204, Err("boom".into()), MIN, 7);
        assert!(!unread.ready && unread.rpc_reachable && unread.balance_sufficient.is_none());
    }

    #[tokio::test]
    async fn probe_against_a_dead_rpc_reports_unreachable() {
        let client = reqwest::Client::new();
        let r = probe(&client, "http://127.0.0.1:9", None, 40204, "0x00", MIN, 1).await;
        assert!(!r.ready);
        assert!(!r.rpc_reachable);
    }

    #[test]
    fn cache_respects_ttl() {
        let c = ReadinessCache::default();
        assert!(c.fresh(CACHE_TTL).is_none());
        let r = assess(Ok(40204), 40204, Ok(U256::from(MIN)), MIN, 1);
        c.store(r.clone());
        assert_eq!(c.fresh(CACHE_TTL), Some(r));
        assert!(c.fresh(Duration::from_secs(0)).is_none());
    }
}
