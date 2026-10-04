//! HUP-S6.5 / federation F-5: an optional server-side membership check (faucet ADR O-2,
//! pending owner sign-off).
//!
//! When the operator sets `FAUCET_MEMBER_SBT` to the membership SBT contract on this chain, the
//! faucet drips only to an address that holds at least one membership token. The check is one
//! read-only `eth_call` of the ERC-721 `balanceOf(address)` on the faucet's own RPC.
//!
//! Data source (Rule 7): `CitrateMemberSBT.balanceOf(recipient)` via `eth_call` at `latest` on
//! `CITRATE_RPC_URL`. A revoked membership burns the token, so it reads 0. Quarantine and term
//! expiry keep the token; whether they should also block the drip is part of O-2.
//!
//! **Off unless the operator sets it.** Unset means no membership check, exactly as before.
//! **Fails closed.** When the check is on and the RPC cannot answer, the drip is refused with a
//! clear reason; it never falls back to "allow".

use primitive_types::U256;

/// `balanceOf(address)`.
pub const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

/// Parse `FAUCET_MEMBER_SBT`. Unset or blank: `Ok(None)` (check off). Anything other than a
/// non-zero `0x` 20-byte address is a startup error.
pub fn parse_sbt_env(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let hex_part = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("FAUCET_MEMBER_SBT must be a 0x address, got {s:?}"))?;
    if hex_part.len() != 40 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "FAUCET_MEMBER_SBT must be a 20-byte 0x address, got {s:?}"
        ));
    }
    if hex_part.bytes().all(|b| b == b'0') {
        return Err("FAUCET_MEMBER_SBT must not be the zero address".to_string());
    }
    Ok(Some(format!("0x{}", hex_part.to_ascii_lowercase())))
}

/// ABI calldata for `balanceOf(recipient)`.
pub fn balance_of_calldata(recipient: &[u8; 20]) -> String {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&BALANCE_OF_SELECTOR);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(recipient);
    format!("0x{}", hex::encode(data))
}

/// Read a `uint256` return word: `true` when it is non-zero. An empty or short result (no code
/// at the address, or a revert the node reported as empty) is an error, not "not a member".
pub fn parse_nonzero_word(result_hex: &str) -> Result<bool, String> {
    let h = result_hex
        .strip_prefix("0x")
        .ok_or_else(|| "membership check: malformed eth_call result".to_string())?;
    if h.len() < 64 {
        return Err(
            "membership check: the membership contract returned no balance (is FAUCET_MEMBER_SBT right?)"
                .to_string(),
        );
    }
    let word = U256::from_str_radix(&h[..64], 16)
        .map_err(|_| "membership check: malformed eth_call result".to_string())?;
    Ok(!word.is_zero())
}

/// `true` when `recipient` holds at least one token of `sbt`. Every failure is an `Err` so the
/// caller can refuse (fail closed).
pub async fn holds_member_sbt(
    client: &reqwest::Client,
    rpc_url: &str,
    api_key: Option<&str>,
    sbt: &str,
    recipient: &[u8; 20],
) -> Result<bool, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": sbt, "data": balance_of_calldata(recipient)}, "latest"],
        "id": 1
    });
    let mut req = client
        .post(rpc_url)
        .timeout(std::time::Duration::from_secs(10))
        .json(&body);
    if let Some(k) = api_key {
        req = req.header("X-API-Key", k);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("membership check: RPC unreachable ({e})"))?;
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("membership check: unreadable RPC reply ({e})"))?;
    if let Some(err) = json.get("error") {
        return Err(format!("membership check: RPC error {err}"));
    }
    let result = json
        .get("result")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "membership check: RPC reply has no result".to_string())?;
    parse_nonzero_word(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parsing_is_strict() {
        assert_eq!(parse_sbt_env(None).expect("ok"), None);
        assert_eq!(parse_sbt_env(Some(" ")).expect("ok"), None);
        let a = format!("0x{}", "Ab".repeat(20));
        assert_eq!(
            parse_sbt_env(Some(&a)).expect("ok"),
            Some(format!("0x{}", "ab".repeat(20)))
        );
        for bad in [
            "ab".repeat(20),
            format!("0x{}", "ab".repeat(19)),
            format!("0x{}", "zz".repeat(20)),
            format!("0x{}", "00".repeat(20)),
        ] {
            assert!(parse_sbt_env(Some(&bad)).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn calldata_is_selector_plus_padded_address() {
        let data = balance_of_calldata(&[0x11; 20]);
        assert_eq!(data.len(), 2 + 8 + 64);
        assert!(data.starts_with("0x70a08231"));
        assert!(data.ends_with(&"11".repeat(20)));
        assert_eq!(&data[10..34], "0".repeat(24));
    }

    #[test]
    fn result_word_parsing() {
        let zero = format!("0x{}", "0".repeat(64));
        let one = format!("0x{}1", "0".repeat(63));
        assert!(!parse_nonzero_word(&zero).expect("zero"));
        assert!(parse_nonzero_word(&one).expect("one"));
        assert!(
            parse_nonzero_word("0x").is_err(),
            "empty result is not 'not a member'"
        );
        assert!(parse_nonzero_word("nothex").is_err());
        assert!(parse_nonzero_word(&format!("0x{}", "g".repeat(64))).is_err());
    }

    #[tokio::test]
    async fn unreachable_rpc_is_an_error_not_a_pass() {
        let client = reqwest::Client::new();
        let r = holds_member_sbt(
            &client,
            "http://127.0.0.1:9",
            None,
            "0x1111111111111111111111111111111111111111",
            &[0x22; 20],
        )
        .await;
        assert!(r.is_err());
    }
}
