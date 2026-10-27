// citrate/core/api/src/state_tag.rs
//
// The block tag of an account-STATE read (`eth_call`, `eth_estimateGas`,
// `eth_getBalance`, `eth_getCode`, `eth_getStorageAt`, `eth_getTransactionCount`).
//
// WHAT THE NODE CAN SERVE
//
// The state store holds one state: the post-state of the executed head (the
// applied tip the canonical applicator persists). There is no state-at-height
// read. Before chain#425 these methods accepted any block tag and answered from
// that one state, so a call "at block N" below the head silently returned the
// head's state labelled as block N's.
//
// RULE (fail closed)
//
// A tag is served only when it names the executed head's state:
//   * absent, `latest`, `pending`: served (the head's state; `pending` keeps
//     its existing meaning, e.g. the mempool nonce in eth_getTransactionCount);
//   * `finalized` / `safe`: left to the finality guard
//     (`eth_rpc::require_serviceable_finality_tag`), which already refuses them
//     unless the finalized block IS the executed head;
//   * a block number, `earliest`, a 32-byte block hash, or an EIP-1898 object
//     (`{"blockNumber": …}` / `{"blockHash": …}`): served only when it resolves
//     to the executed head itself. Below the head the read is refused with
//     [`HISTORICAL_STATE_CODE`]; above it (not executed yet on this node), or a
//     hash that is not the head, likewise.
//   * anything else is an invalid-params error (it used to read as `latest`).
//
// The head is read once per request, before the state read. A block applied
// between the check and the read can make the answer one block newer than the
// tag, the same window a `latest` read has.

use citrate_consensus::types::Hash;
use citrate_storage::StorageManager;
use serde_json::{json, Value};

/// JSON-RPC error code for a state read at a block other than the executed
/// head (the "server error" range; geth answers missing state with -32000 too).
pub const HISTORICAL_STATE_CODE: i64 = -32000;

/// Prefix of every refusal message, so clients can match it.
pub const HISTORICAL_STATE_MESSAGE: &str = "historical state not available on this node";

/// A state-read block tag, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateTag {
    /// absent, `latest`, `pending`, `finalized`, `safe`: no pinned block.
    Unpinned,
    /// A block number (`earliest` is 0).
    Number(u64),
    /// A block hash.
    Hash(Hash),
}

/// Parse the block-tag parameter of a state read.
pub fn parse_state_tag(tag: Option<&Value>) -> Result<StateTag, jsonrpc_core::Error> {
    let bad =
        |what: &str| jsonrpc_core::Error::invalid_params(format!("invalid block tag: {what}"));
    match tag {
        None | Some(Value::Null) => Ok(StateTag::Unpinned),
        Some(Value::String(s)) => parse_tag_str(s).ok_or_else(|| bad(s)),
        Some(Value::Object(o)) => {
            if let Some(h) = o.get("blockHash") {
                let s = h
                    .as_str()
                    .ok_or_else(|| bad("blockHash must be a string"))?;
                return parse_hash(s)
                    .map(StateTag::Hash)
                    .ok_or_else(|| bad("blockHash must be 32 bytes of hex"));
            }
            if let Some(n) = o.get("blockNumber") {
                let s = n
                    .as_str()
                    .ok_or_else(|| bad("blockNumber must be a string"))?;
                return parse_tag_str(s).ok_or_else(|| bad(s));
            }
            Err(bad("object needs blockHash or blockNumber"))
        }
        Some(other) => Err(bad(&other.to_string())),
    }
}

fn parse_tag_str(s: &str) -> Option<StateTag> {
    match s {
        "latest" | "pending" | "finalized" | "safe" => Some(StateTag::Unpinned),
        "earliest" => Some(StateTag::Number(0)),
        _ => {
            let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
            if hex.len() == 64 {
                return parse_hash(s).map(StateTag::Hash);
            }
            if hex.is_empty() {
                return None;
            }
            u64::from_str_radix(hex, 16).ok().map(StateTag::Number)
        }
    }
}

fn parse_hash(s: &str) -> Option<Hash> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    let bytes = hex::decode(hex).ok()?;
    Hash::try_from_bytes(&bytes).filter(|_| bytes.len() == 32)
}

fn refuse(detail: String, data: Value) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::ServerError(HISTORICAL_STATE_CODE),
        message: format!(
            "{HISTORICAL_STATE_MESSAGE}: {detail}; this node serves account state at its \
             executed head only (use \"latest\")"
        ),
        data: Some(data),
    }
}

/// Refuse a state read whose block tag does not name the executed head (see
/// the module doc). `Ok(())` means the read may proceed against the node's
/// current state.
pub fn require_executed_head_state(
    tag: Option<&Value>,
    storage: &StorageManager,
) -> Result<(), jsonrpc_core::Error> {
    let pinned = parse_state_tag(tag)?;
    if pinned == StateTag::Unpinned {
        return Ok(());
    }
    let head = crate::canonical_logs::log_tip(storage).map_err(|e| jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: format!("executed head unavailable: {e}"),
        data: None,
    })?;
    let Some((head_hash, head_height)) = head else {
        return Err(refuse(
            "no block has executed on this node yet".to_string(),
            json!({ "executedHead": null }),
        ));
    };
    let head_json = json!({
        "number": format!("0x{head_height:x}"),
        "hash": format!("0x{}", hex::encode(head_hash.as_bytes())),
    });
    match pinned {
        StateTag::Unpinned => Ok(()),
        StateTag::Number(n) if n == head_height => Ok(()),
        StateTag::Number(n) if n < head_height => Err(refuse(
            format!("block {n} is below the executed head {head_height}"),
            json!({ "requested": format!("0x{n:x}"), "executedHead": head_json }),
        )),
        StateTag::Number(n) => Err(refuse(
            format!("block {n} has not executed on this node (executed head {head_height})"),
            json!({ "requested": format!("0x{n:x}"), "executedHead": head_json }),
        )),
        StateTag::Hash(h) if h == head_hash => Ok(()),
        StateTag::Hash(h) => {
            let detail = match storage.blocks.get_header(&h).ok().flatten() {
                Some(header) => format!(
                    "block {h} at height {} is not the executed head {head_height}",
                    header.height
                ),
                None => format!("block {h} is not known to this node"),
            };
            Err(refuse(
                detail,
                json!({
                    "requested": format!("0x{}", hex::encode(h.as_bytes())),
                    "executedHead": head_json,
                }),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_tag_form() {
        let h = format!("0x{}", "ab".repeat(32));
        let hash = parse_hash(&h).expect("hash");
        for (tag, want) in [
            (json!(null), StateTag::Unpinned),
            (json!("latest"), StateTag::Unpinned),
            (json!("pending"), StateTag::Unpinned),
            (json!("finalized"), StateTag::Unpinned),
            (json!("safe"), StateTag::Unpinned),
            (json!("earliest"), StateTag::Number(0)),
            (json!("0x0"), StateTag::Number(0)),
            (json!("0x1f"), StateTag::Number(31)),
            (json!(h.clone()), StateTag::Hash(hash)),
            (json!({"blockHash": h.clone()}), StateTag::Hash(hash)),
            (
                json!({"blockHash": h.clone(), "requireCanonical": true}),
                StateTag::Hash(hash),
            ),
            (json!({"blockNumber": "0x7"}), StateTag::Number(7)),
            (json!({"blockNumber": "latest"}), StateTag::Unpinned),
        ] {
            assert_eq!(parse_state_tag(Some(&tag)).expect("parses"), want, "{tag}");
        }
        assert_eq!(parse_state_tag(None).expect("absent"), StateTag::Unpinned);
    }

    #[test]
    fn rejects_malformed_tags_instead_of_reading_latest() {
        for tag in [
            json!("blah"),
            json!("0x"),
            json!("0xzz"),
            json!("12"),
            json!(12),
            json!(true),
            json!({}),
            json!({"blockHash": "0x1234"}),
            json!({"blockNumber": 5}),
            json!(format!("0x{}", "f".repeat(17))),
        ] {
            let e = parse_state_tag(Some(&tag)).expect_err("must not parse");
            assert_eq!(e.code, jsonrpc_core::ErrorCode::InvalidParams, "{tag}");
        }
    }
}
