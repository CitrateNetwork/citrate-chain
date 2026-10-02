//! Where the fork's pre-state comes from.
//!
//! * [`ForkState::Rpc`] reads accounts, code, storage and block hashes lazily from a JSON-RPC
//!   endpoint (chain 40204 itself, or a local anvil fork of it) at ONE pinned block, so every
//!   read sees the same snapshot. Data source: `eth_getBalance`, `eth_getTransactionCount`,
//!   `eth_getCode`, `eth_getStorageAt` and `eth_getBlockByNumber` at that block number. Only
//!   read methods are ever called: the fork never sends, signs or holds a key.
//! * [`ForkState::Empty`] starts from no accounts at all (offline runs and tests).
//!
//! Writes made by the dry run stay in revm's in-memory `CacheDB` on top of this and are
//! dropped when the process exits.
use std::time::Duration;

use revm::primitives::{
    keccak256, AccountInfo, Address, Bytecode, Bytes, B256, KECCAK_EMPTY, U256,
};
use revm::DatabaseRef;
use serde_json::{json, Value};

/// How long one JSON-RPC request may take.
const RPC_TIMEOUT: Duration = Duration::from_secs(20);
/// The largest JSON-RPC response body accepted (a contract's code is at most 24 KiB; a block
/// header is small). Larger answers are refused.
const MAX_RPC_BODY: usize = 4 * 1024 * 1024;

/// A fork error: what failed, in words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkError(pub String);

impl std::fmt::Display for ForkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ForkError {}

fn err(s: impl Into<String>) -> ForkError {
    ForkError(s.into())
}

/// A JSON-RPC endpoint read at one block.
pub struct RpcState {
    url: String,
    block: u64,
    client: reqwest::blocking::Client,
}

/// The block the fork runs on top of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkBlock {
    pub number: u64,
    pub timestamp: u64,
    pub hash: Option<B256>,
    pub coinbase: Address,
}

/// Checks the endpoint is `http://` or `https://` and carries no user-info (credentials
/// would end up in the report).
pub fn validate_rpc_url(url: &str) -> Result<(), ForkError> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| err("the RPC URL must start with http:// or https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(err("the RPC URL has no host"));
    }
    if authority.contains('@') {
        return Err(err("the RPC URL must not carry credentials (user@host)"));
    }
    Ok(())
}

/// The scheme and host of an RPC URL, for the report (no path or query, which may hold keys).
pub fn redacted_origin(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => return String::new(),
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    format!("{scheme}://{host}")
}

fn parse_quantity(v: &Value, what: &str) -> Result<u64, ForkError> {
    let s = v
        .as_str()
        .ok_or_else(|| err(format!("{what}: expected a hex quantity")))?;
    let t = s
        .strip_prefix("0x")
        .ok_or_else(|| err(format!("{what}: expected 0x-prefixed hex, got {s}")))?;
    u64::from_str_radix(t, 16).map_err(|e| err(format!("{what}: {e}")))
}

fn parse_u256(v: &Value, what: &str) -> Result<U256, ForkError> {
    let s = v
        .as_str()
        .ok_or_else(|| err(format!("{what}: expected a hex quantity")))?;
    let t = s
        .strip_prefix("0x")
        .ok_or_else(|| err(format!("{what}: expected 0x-prefixed hex, got {s}")))?;
    if t.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(t, 16).map_err(|e| err(format!("{what}: {e}")))
}

fn parse_data(v: &Value, what: &str) -> Result<Vec<u8>, ForkError> {
    let s = v
        .as_str()
        .ok_or_else(|| err(format!("{what}: expected hex data")))?;
    let t = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(t).map_err(|e| err(format!("{what}: {e}")))
}

fn parse_b256(v: &Value, what: &str) -> Result<B256, ForkError> {
    let b = parse_data(v, what)?;
    if b.len() != 32 {
        return Err(err(format!("{what}: expected 32 bytes, got {}", b.len())));
    }
    Ok(B256::from_slice(&b))
}

impl RpcState {
    /// Connects to `url` and pins `block` (or the endpoint's latest block when `None`).
    /// Returns the state, the endpoint's chain id and the pinned block.
    pub fn connect(url: &str, block: Option<u64>) -> Result<(Self, u64, ForkBlock), ForkError> {
        validate_rpc_url(url)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(RPC_TIMEOUT)
            .build()
            .map_err(|e| err(format!("http client: {e}")))?;
        let mut st = RpcState {
            url: url.to_string(),
            block: 0,
            client,
        };
        let chain_id = parse_quantity(&st.call("eth_chainId", json!([]))?, "eth_chainId")?;
        let number = match block {
            Some(n) => n,
            None => parse_quantity(&st.call("eth_blockNumber", json!([]))?, "eth_blockNumber")?,
        };
        st.block = number;
        let header = st.block_header(number)?;
        Ok((st, chain_id, header))
    }

    fn tag(&self) -> String {
        format!("0x{:x}", self.block)
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ForkError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .map_err(|e| err(format!("{method}: {e}")))?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .map_err(|e| err(format!("{method}: reading the response: {e}")))?;
        if bytes.len() > MAX_RPC_BODY {
            return Err(err(format!(
                "{method}: response larger than {MAX_RPC_BODY} bytes"
            )));
        }
        if !status.is_success() {
            return Err(err(format!("{method}: HTTP {status}")));
        }
        let v: Value =
            serde_json::from_slice(&bytes).map_err(|e| err(format!("{method}: not JSON: {e}")))?;
        if let Some(e) = v.get("error") {
            return Err(err(format!("{method}: {e}")));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| err(format!("{method}: no result")))
    }

    fn block_header(&self, number: u64) -> Result<ForkBlock, ForkError> {
        let b = self.call(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), false]),
        )?;
        if b.is_null() {
            return Err(err(format!(
                "block {number} does not exist on the endpoint"
            )));
        }
        let coinbase = match b.get("miner") {
            Some(m) => {
                let raw = parse_data(m, "block miner")?;
                if raw.len() != 20 {
                    return Err(err("block miner: expected 20 bytes"));
                }
                Address::from_slice(&raw)
            }
            None => Address::ZERO,
        };
        Ok(ForkBlock {
            number,
            timestamp: parse_quantity(
                b.get("timestamp").unwrap_or(&Value::Null),
                "block timestamp",
            )?,
            hash: match b.get("hash") {
                Some(h) if !h.is_null() => Some(parse_b256(h, "block hash")?),
                _ => None,
            },
            coinbase,
        })
    }
}

/// The fork's pre-state.
pub enum ForkState {
    Empty,
    Rpc(RpcState),
}

impl DatabaseRef for ForkState {
    type Error = ForkError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let st = match self {
            ForkState::Empty => return Ok(None),
            ForkState::Rpc(st) => st,
        };
        let a = format!("{address:#x}");
        let balance = parse_u256(
            &st.call("eth_getBalance", json!([a, st.tag()]))?,
            "eth_getBalance",
        )?;
        let nonce = parse_quantity(
            &st.call("eth_getTransactionCount", json!([a, st.tag()]))?,
            "eth_getTransactionCount",
        )?;
        let code = parse_data(
            &st.call("eth_getCode", json!([a, st.tag()]))?,
            "eth_getCode",
        )?;
        let (code_hash, bytecode) = if code.is_empty() {
            (KECCAK_EMPTY, None)
        } else {
            (keccak256(&code), Some(Bytecode::new_raw(Bytes::from(code))))
        };
        Ok(Some(AccountInfo {
            balance,
            nonce,
            code_hash,
            code: bytecode,
        }))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        // `basic_ref` always returns the code with the account, so revm's cache holds every
        // code hash it can ask about. A miss means the cache lost track: refuse, never guess.
        Err(err(format!(
            "code for hash {code_hash} was not loaded with its account"
        )))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let st = match self {
            ForkState::Empty => return Ok(U256::ZERO),
            ForkState::Rpc(st) => st,
        };
        parse_u256(
            &st.call(
                "eth_getStorageAt",
                json!([format!("{address:#x}"), format!("{index:#x}"), st.tag()]),
            )?,
            "eth_getStorageAt",
        )
    }

    fn block_hash_ref(&self, number: U256) -> Result<B256, Self::Error> {
        match self {
            // No chain: the same placeholder revm's EmptyDB uses (keccak of the number).
            ForkState::Empty => Ok(keccak256(number.to_string().as_bytes())),
            ForkState::Rpc(st) => {
                let n: u64 = number
                    .try_into()
                    .map_err(|_| err("BLOCKHASH: number out of range"))?;
                st.block_header(n)?
                    .hash
                    .ok_or_else(|| err(format!("block {n} has no hash")))
            }
        }
    }
}
