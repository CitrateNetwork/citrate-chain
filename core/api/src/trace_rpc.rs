// citrate/core/api/src/trace_rpc.rs
//
// S3-7 (CNV-RPC): transaction tracing and the contract-creator lookup the
// explorer needs for internal transactions and factory-created contracts.
//
//   debug_traceTransaction(txHash, {tracer})      callTracer | prestateTracer
//   debug_traceCall(call, blockTag, {tracer})     callTracer | prestateTracer
//   debug_traceBlockByNumber(n, {tracer})         callTracer, every tx of a block
//   debug_traceBlockByHash(hash, {tracer})        callTracer, every tx of a block
//   ots_getContractCreator(address)               { hash, creator }
//
// HOW A TRANSACTION IS TRACED
//
// The transaction's receipt names the block that executed it; that block must
// be on the applied chain. Its parent's state is rebuilt from the undo
// records and verified against the parent's committed state root
// (`historical_state::HistoricalStates::state_at`). A throwaway executor over
// that state (`Executor::replay_executor`: its own state, its own MVCC
// coordinator, a store that discards writes) re-executes the block's
// transactions in block order with the block's EVM context (coinbase, VRF
// prevrandao), the way `Executor::apply_block` does, with an observe-only REVM
// inspector attached (`citrate_execution::trace`). Every replayed receipt must
// match the stored one (status and gas used); a replay that diverges is
// refused, never reported.
//
// SEMANTICS CHANGE AT S3-3b (mergeset execution): today a chain block executes
// its own transactions on its selected parent's state. Under S3-3b the
// accepting chain block executes its mergeset's transactions in mergeset
// order (spec 06 §3.2). The replay here then has to follow the accepting
// block's execution list instead of the including block's body; the trace
// output shape does not change.
//
// Nothing here can change the node: the replay executor shares no state, no
// coordinator and no writable store with it, and the inspector only records
// (`core/execution/tests/trace_inspector_neutral.rs`,
// `core/api/tests/explorer_methods.rs::tracing_changes_no_state`).

use crate::historical_state::{
    creation_of, resolve_state_read, Creation, HistoricalStates, ReplayStore, StateRead,
};
use crate::metrics::rpc_request;
use crate::rpc_runtime::block_on;
use crate::state_tag::StateTagPolicy;
use citrate_consensus::types::{Block, Hash, PublicKey, Signature, Transaction};
use citrate_execution::address_utils::normalize_address;
use citrate_execution::state::StateSnapshot;
use citrate_execution::trace::{new_call_tracer, CallFrame, FrameKind, Touched};
use citrate_execution::types::{Address, TransactionReceipt};
use citrate_execution::Executor;
use citrate_storage::StorageManager;
use jsonrpc_core::{IoHandler, Params};
use primitive_types::U256;
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// Method-budget units for `debug_traceTransaction` and `debug_traceCall`
/// (charged by `rpc_limits::RpcLimits`, see `rpc_limits::heavy_method_cost`).
pub const TRACE_COST: u32 = 100;

/// Method-budget units for `ots_getContractCreator` (a walk of the undo
/// window plus a traced replay of one block).
pub const CREATOR_LOOKUP_COST: u32 = 200;

/// Wall-clock bound on one trace or creator lookup.
pub const TRACE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Gas limit of a `debug_traceCall` without `gas` (the `eth_call` default).
const DEFAULT_CALL_GAS: u64 = 1_000_000;

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

fn addr_hex(a: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

fn qty(n: u64) -> String {
    format!("0x{n:x}")
}

fn word_qty(w: &[u8; 32]) -> String {
    format!("0x{:x}", U256::from_big_endian(w))
}

fn server_error(message: String) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::ServerError(-32000),
        message,
        data: None,
    }
}

fn internal(e: impl std::fmt::Display) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: e.to_string(),
        data: None,
    }
}

fn bad(msg: impl Into<String>) -> jsonrpc_core::Error {
    jsonrpc_core::Error::invalid_params(msg.into())
}

/// Which tracer, and its options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tracer {
    Call { only_top_call: bool, with_log: bool },
    Prestate,
}

/// Parse the tracer options object (`{ "tracer": …, "tracerConfig": … }`).
pub fn parse_tracer(v: Option<&Value>) -> Result<Tracer, jsonrpc_core::Error> {
    let unsupported = || {
        bad(
            "tracer must be \"callTracer\" or \"prestateTracer\" (no other tracer, and no \
             struct logger, is served)",
        )
    };
    let Some(Value::Object(o)) = v else {
        return Err(unsupported());
    };
    let cfg = o.get("tracerConfig").and_then(|c| c.as_object());
    let flag = |k: &str| {
        cfg.and_then(|c| c.get(k))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    match o.get("tracer").and_then(|t| t.as_str()) {
        Some("callTracer") => Ok(Tracer::Call {
            only_top_call: flag("onlyTopCall"),
            with_log: flag("withLog"),
        }),
        Some("prestateTracer") => {
            if flag("diffMode") {
                return Err(bad("prestateTracer diffMode is not served"));
            }
            Ok(Tracer::Prestate)
        }
        _ => Err(unsupported()),
    }
}

fn u128_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    if let Some(tail) = w.get_mut(16..32) {
        tail.copy_from_slice(&v.to_be_bytes());
    }
    w
}

/// The top-level frame of a transaction: REVM's frame when REVM ran (with
/// the transaction's own gas limit, the gas the executor charged and the
/// transaction's value), else one built from the transaction and its receipt
/// (a native transfer or a Citrate AI operation, which REVM never sees).
pub fn top_frame(
    tx: &Transaction,
    receipt: &TransactionReceipt,
    roots: Vec<CallFrame>,
) -> CallFrame {
    let from = normalize_address(&tx.from).0;
    let to = tx.to.as_ref().map(|t| normalize_address(t).0);
    let failed_reason = || {
        receipt
            .revert_reason
            .clone()
            .unwrap_or_else(|| "execution failed".to_string())
    };
    let mut roots = roots.into_iter();
    let mut top = match roots.next() {
        Some(mut f) => {
            f.from = from;
            if f.to.is_none() && !f.kind.is_create() {
                f.to = to;
            }
            f
        }
        None => CallFrame {
            kind: if to.is_some() {
                FrameKind::Call
            } else {
                FrameKind::Create
            },
            from,
            to: match to {
                Some(t) => Some(t),
                None if receipt.status && receipt.output.len() == 20 => {
                    let mut a = [0u8; 20];
                    a.copy_from_slice(&receipt.output);
                    Some(a)
                }
                None => None,
            },
            value: None,
            gas: 0,
            gas_used: 0,
            input: tx.data.clone(),
            output: receipt.output.clone(),
            error: None,
            revert_reason: None,
            logs: Vec::new(),
            calls: Vec::new(),
        },
    };
    // More than one REVM invocation for one transaction: keep them, in order,
    // under the top frame.
    top.calls.extend(roots);
    top.gas = tx.gas_limit;
    top.gas_used = receipt.gas_used;
    top.value = Some(u128_word(tx.value));
    if !receipt.status && top.error.is_none() {
        top.error = Some(failed_reason());
    }
    top
}

/// geth's `callTracer` JSON for a frame tree.
pub fn frame_json(f: &CallFrame, only_top_call: bool, with_log: bool) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), json!(f.kind.as_str()));
    m.insert("from".into(), json!(addr_hex(&f.from)));
    m.insert(
        "to".into(),
        f.to.as_ref().map_or(Value::Null, |t| json!(addr_hex(t))),
    );
    if let Some(v) = &f.value {
        m.insert("value".into(), json!(word_qty(v)));
    }
    m.insert("gas".into(), json!(qty(f.gas)));
    m.insert("gasUsed".into(), json!(qty(f.gas_used)));
    m.insert(
        "input".into(),
        json!(format!("0x{}", hex::encode(&f.input))),
    );
    m.insert(
        "output".into(),
        json!(format!("0x{}", hex::encode(&f.output))),
    );
    if let Some(e) = &f.error {
        m.insert("error".into(), json!(e));
    }
    if let Some(r) = &f.revert_reason {
        m.insert("revertReason".into(), json!(r));
    }
    if with_log && !f.logs.is_empty() {
        m.insert(
            "logs".into(),
            Value::Array(
                f.logs
                    .iter()
                    .map(|l| {
                        json!({
                            "address": addr_hex(&l.address),
                            "topics": l.topics.iter()
                                .map(|t| format!("0x{}", hex::encode(t))).collect::<Vec<_>>(),
                            "data": format!("0x{}", hex::encode(&l.data)),
                        })
                    })
                    .collect(),
            ),
        );
    }
    if !only_top_call && !f.calls.is_empty() {
        m.insert(
            "calls".into(),
            Value::Array(
                f.calls
                    .iter()
                    .map(|c| frame_json(c, false, with_log))
                    .collect(),
            ),
        );
    }
    Value::Object(m)
}

/// geth's `prestateTracer` (non-diff) JSON: every touched account as it was
/// before the transaction, from `pre` (the replay state before it).
pub fn prestate_json(
    storage: &StorageManager,
    pre: &StateSnapshot,
    touched: &Touched,
    extra: &[[u8; 20]],
) -> Result<Value, jsonrpc_core::Error> {
    let db = citrate_execution::StateDB::new();
    db.restore(pre.clone());
    let mut accounts: std::collections::BTreeSet<[u8; 20]> = touched.accounts.clone();
    accounts.extend(extra.iter().copied());
    let mut out = Map::new();
    for a in accounts {
        let addr = Address(a);
        if !db.accounts.exists(&addr) && !touched.slots.contains_key(&a) {
            continue;
        }
        let acct = db.accounts.get_account(&addr);
        let mut m = Map::new();
        m.insert("balance".into(), json!(format!("0x{:x}", acct.balance)));
        if acct.nonce > 0 {
            m.insert("nonce".into(), json!(acct.nonce));
        }
        if acct.code_hash != Hash::default() {
            let code = match db.get_code(&acct.code_hash) {
                Some(c) => Some(c),
                None => storage.state.get_code(&acct.code_hash).map_err(internal)?,
            };
            if let Some(code) = code {
                m.insert("code".into(), json!(format!("0x{}", hex::encode(code))));
            }
        }
        if let Some(slots) = touched.slots.get(&a) {
            let mut st = Map::new();
            for slot in slots {
                let v = db.get_storage(&addr, slot.as_slice()).unwrap_or_default();
                let tail = v.get(v.len().saturating_sub(32)..).unwrap_or_default();
                let mut word = vec![0u8; 32usize.saturating_sub(tail.len())];
                word.extend_from_slice(tail);
                st.insert(
                    format!("0x{}", hex::encode(slot)),
                    json!(format!("0x{}", hex::encode(word))),
                );
            }
            if !st.is_empty() {
                m.insert("storage".into(), Value::Object(st));
            }
        }
        out.insert(addr_hex(&a), Value::Object(m));
    }
    Ok(Value::Object(out))
}

/// One replayed transaction.
pub struct ReplayedTx {
    pub tx: Transaction,
    pub receipt: TransactionReceipt,
    /// The REVM frames it produced (empty for a native operation).
    pub roots: Vec<CallFrame>,
    pub touched: Touched,
    /// The replay state before it (only for the transaction asked for).
    pub pre: Option<StateSnapshot>,
}

/// Re-execute `block`'s transactions `0..=upto` on its parent's verified
/// state, traced, checking each against its stored receipt (see the module
/// doc). `want_pre` captures the state before that one transaction.
pub async fn replay_block(
    storage: &Arc<StorageManager>,
    executor: &Executor,
    historical: &HistoricalStates,
    block: &Block,
    upto: usize,
    want_pre: Option<usize>,
) -> Result<Vec<ReplayedTx>, jsonrpc_core::Error> {
    let height = block.header.height;
    let parent_height = height
        .checked_sub(1)
        .ok_or_else(|| server_error("genesis has no transactions to trace".into()))?;
    let parent = (block.header.selected_parent_hash, parent_height);
    let tracer = new_call_tracer();
    let replay = historical
        .executor_at(storage, executor, parent)?
        .with_call_tracer(tracer.clone());
    // The EVM context `Executor::apply_block` executes the block's
    // transactions in.
    replay.set_block_context(citrate_execution::revm_adapter::BlockContext {
        coinbase: block.header.coinbase,
        prevrandao: *block.header.vrf_reveal.output.as_bytes(),
        block_hashes: std::collections::HashMap::new(),
    });
    let mut out = Vec::new();
    for (j, tx) in block.transactions.iter().enumerate() {
        if j > upto {
            break;
        }
        let pre = (want_pre == Some(j)).then(|| replay.state_snapshot());
        tracer.lock().take();
        let got = replay.execute_transaction(block, tx).await.map_err(|e| {
            server_error(format!(
                "replay of transaction {} (index {j}) of block {} failed: {e}",
                hx(&tx.hash),
                hx(&block.header.block_hash)
            ))
        })?;
        let stored = storage
            .transactions
            .get_receipt(&tx.hash)
            .map_err(internal)?
            .filter(|r| r.block_hash == block.header.block_hash)
            .ok_or_else(|| {
                server_error(format!(
                    "transaction {} has no stored receipt for block {}",
                    hx(&tx.hash),
                    hx(&block.header.block_hash)
                ))
            })?;
        if got.status != stored.status || got.gas_used != stored.gas_used {
            return Err(server_error(format!(
                "the replay of transaction {} diverged from its stored receipt (status {} gas {} \
                 vs stored status {} gas {}); not traced",
                hx(&tx.hash),
                got.status,
                got.gas_used,
                stored.status,
                stored.gas_used
            )));
        }
        let (roots, touched) = tracer.lock().take();
        out.push(ReplayedTx {
            tx: tx.clone(),
            receipt: stored,
            roots,
            touched,
            pre,
        });
    }
    Ok(out)
}

/// The block that executed `tx_hash`, checked to be on the applied chain, and
/// the transaction's index in it. Source: `CF_RECEIPTS`, the canonical height
/// index, `CF_BLOCKS`.
fn executed_location(
    storage: &StorageManager,
    tx_hash: &Hash,
) -> Result<(Block, usize), jsonrpc_core::Error> {
    let receipt = storage
        .transactions
        .get_receipt(tx_hash)
        .map_err(internal)?
        .ok_or_else(|| server_error(format!("transaction {} has no receipt", hx(tx_hash))))?;
    let canonical = storage
        .blocks
        .get_canonical_block_by_height(receipt.block_number)
        .map_err(internal)?;
    if canonical != Some(receipt.block_hash) {
        return Err(server_error(format!(
            "the block {} that executed {} is not on the applied chain",
            hx(&receipt.block_hash),
            hx(tx_hash)
        )));
    }
    let block = storage
        .blocks
        .get_block(&receipt.block_hash)
        .map_err(internal)?
        .ok_or_else(|| server_error(format!("block {} is not stored", hx(&receipt.block_hash))))?;
    let idx = block
        .transactions
        .iter()
        .position(|t| t.hash == *tx_hash)
        .ok_or_else(|| {
            server_error(format!(
                "block {} does not carry {}",
                hx(&receipt.block_hash),
                hx(tx_hash)
            ))
        })?;
    Ok((block, idx))
}

fn with_timeout<T>(
    fut: impl std::future::Future<Output = Result<T, jsonrpc_core::Error>>,
) -> Result<T, jsonrpc_core::Error> {
    match block_on(tokio::time::timeout(TRACE_TIMEOUT, fut)) {
        Ok(r) => r,
        Err(_) => Err(server_error(format!(
            "trace exceeded the {}s deadline",
            TRACE_TIMEOUT.as_secs()
        ))),
    }
}

/// The applied-chain block a `debug_traceBlockByNumber` parameter names: a
/// number (hex or JSON), `latest` / `pending` (the applied tip) or
/// `earliest`. Source: the applied tip and the canonical height index.
fn block_by_number_param(
    storage: &StorageManager,
    v: Option<&Value>,
) -> Result<Hash, jsonrpc_core::Error> {
    let tip = storage
        .blocks
        .get_applied_tip()
        .map_err(internal)?
        .ok_or_else(|| server_error("no block has executed on this node yet".into()))?;
    let n = match v {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| bad("block number must be a non-negative integer"))?,
        Some(Value::String(s)) => match s.as_str() {
            "latest" | "pending" => tip.1,
            "earliest" => 0,
            other => {
                let hex = other
                    .strip_prefix("0x")
                    .ok_or_else(|| bad(format!("invalid block number: {other}")))?;
                u64::from_str_radix(hex, 16)
                    .map_err(|_| bad(format!("invalid block number: {other}")))?
            }
        },
        _ => return Err(bad("block number or tag is required")),
    };
    if n > tip.1 {
        return Err(server_error(format!(
            "block {n} is above the applied head {}",
            tip.1
        )));
    }
    storage
        .blocks
        .get_canonical_block_by_height(n)
        .map_err(internal)?
        .ok_or_else(|| server_error(format!("no applied-chain block at height {n}")))
}

/// `debug_traceBlockByNumber` / `debug_traceBlockByHash` (02 §3 bulk
/// internal-tx indexing): every transaction of one applied-chain block,
/// traced by one replay of the block (`replay_block` over the whole body,
/// receipts checked as for a single trace), as geth's
/// `[{txHash, result}]`. `callTracer` only: a per-block `prestateTracer`
/// would need one state snapshot per transaction, and is refused (-32602).
///
/// Data sources: the block from `CF_BLOCKS` (checked on the applied chain by
/// the canonical height index), its parent's verified state (undo records),
/// and `CF_RECEIPTS` for each replayed transaction. Bounded by one block's
/// body and [`TRACE_TIMEOUT`].
pub fn trace_block(
    storage: &Arc<StorageManager>,
    executor: &Executor,
    historical: &HistoricalStates,
    block_hash: &Hash,
    tracer: Tracer,
) -> Result<Value, jsonrpc_core::Error> {
    let Tracer::Call {
        only_top_call,
        with_log,
    } = tracer
    else {
        return Err(bad(
            "only callTracer is served for a whole block; trace one transaction with \
             debug_traceTransaction for prestateTracer",
        ));
    };
    let header = storage
        .blocks
        .get_header(block_hash)
        .map_err(internal)?
        .ok_or_else(|| server_error(format!("block {} is not stored", hx(block_hash))))?;
    let canonical = storage
        .blocks
        .get_canonical_block_by_height(header.height)
        .map_err(internal)?;
    if canonical != Some(*block_hash) {
        return Err(server_error(format!(
            "block {} is not on the applied chain",
            hx(block_hash)
        )));
    }
    let block = storage
        .blocks
        .get_block(block_hash)
        .map_err(internal)?
        .ok_or_else(|| server_error(format!("block {} is not stored", hx(block_hash))))?;
    let Some(last) = block.transactions.len().checked_sub(1) else {
        return Ok(Value::Array(Vec::new()));
    };
    let replayed = with_timeout(replay_block(
        storage, executor, historical, &block, last, None,
    ))?;
    Ok(Value::Array(
        replayed
            .into_iter()
            .map(|t| {
                let hash = hx(&t.tx.hash);
                json!({
                    "txHash": hash,
                    "result": frame_json(
                        &top_frame(&t.tx, &t.receipt, t.roots),
                        only_top_call,
                        with_log,
                    ),
                })
            })
            .collect(),
    ))
}

/// `debug_traceTransaction`.
pub fn trace_transaction(
    storage: &Arc<StorageManager>,
    executor: &Executor,
    historical: &HistoricalStates,
    tx_hash: &Hash,
    tracer: Tracer,
) -> Result<Value, jsonrpc_core::Error> {
    let (block, idx) = executed_location(storage, tx_hash)?;
    let want_pre = matches!(tracer, Tracer::Prestate).then_some(idx);
    let mut replayed = with_timeout(replay_block(
        storage, executor, historical, &block, idx, want_pre,
    ))?;
    let t = replayed
        .pop()
        .ok_or_else(|| internal("replay returned no transaction"))?;
    match tracer {
        Tracer::Call {
            only_top_call,
            with_log,
        } => Ok(frame_json(
            &top_frame(&t.tx, &t.receipt, t.roots),
            only_top_call,
            with_log,
        )),
        Tracer::Prestate => {
            let pre = t
                .pre
                .as_ref()
                .ok_or_else(|| internal("replay kept no pre-state"))?;
            let mut extra = vec![normalize_address(&t.tx.from).0, block.header.coinbase];
            if let Some(to) = &t.tx.to {
                extra.push(normalize_address(to).0);
            }
            prestate_json(storage, pre, &t.touched, &extra)
        }
    }
}

fn parse_addr(v: Option<&Value>, what: &str) -> Result<[u8; 20], jsonrpc_core::Error> {
    let s = v
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad(format!("{what} must be a 0x-prefixed 20-byte hex string")))?;
    let b = hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|_| bad(format!("{what} is not hex")))?;
    <[u8; 20]>::try_from(b.as_slice()).map_err(|_| bad(format!("{what} must be 20 bytes")))
}

fn parse_qty_u128(
    v: Option<&Value>,
    what: &str,
    default: u128,
) -> Result<u128, jsonrpc_core::Error> {
    match v.and_then(|v| v.as_str()) {
        None => Ok(default),
        Some(s) => {
            let s = s.trim();
            match s.strip_prefix("0x") {
                Some(h) if !h.is_empty() => u128::from_str_radix(h, 16),
                Some(_) => Ok(0),
                None => s.parse::<u128>(),
            }
            .map_err(|_| bad(format!("invalid {what}: {s}")))
        }
    }
}

/// The pseudo-transaction of a `debug_traceCall` call object (the fields
/// `eth_call` reads: from, to, data/input, value, gas, gasPrice). `to` may be
/// absent (a create).
fn call_tx(
    obj: &Map<String, Value>,
    nonce_of: impl Fn(&Address) -> u64,
) -> Result<Transaction, jsonrpc_core::Error> {
    let embed = |a: [u8; 20]| {
        let mut b = [0u8; 32];
        if let Some(head) = b.get_mut(..20) {
            head.copy_from_slice(&a);
        }
        PublicKey::new(b)
    };
    let from = match obj.get("from") {
        Some(v) => parse_addr(Some(v), "from")?,
        None => [0u8; 20],
    };
    let to = match obj.get("to") {
        None | Some(Value::Null) => None,
        Some(v) => Some(parse_addr(Some(v), "to")?),
    };
    let data = match obj
        .get("data")
        .or_else(|| obj.get("input"))
        .and_then(|v| v.as_str())
    {
        Some(d) => {
            hex::decode(d.trim().trim_start_matches("0x")).map_err(|_| bad("invalid data hex"))?
        }
        None => Vec::new(),
    };
    let value = parse_qty_u128(obj.get("value"), "value", 0)?;
    let gas = u64::try_from(parse_qty_u128(
        obj.get("gas"),
        "gas",
        u128::from(DEFAULT_CALL_GAS),
    )?)
    .map_err(|_| bad("gas too large"))?;
    crate::eth_rpc::enforce_rpc_gas_cap(gas)?;
    let gas_price = u64::try_from(parse_qty_u128(obj.get("gasPrice"), "gasPrice", 1)?)
        .map_err(|_| bad("gasPrice too large"))?;
    let from_pk = embed(from);
    let mut tx = Transaction {
        hash: Hash::default(),
        nonce: nonce_of(&Address(from)),
        from: from_pk,
        to: to.map(embed),
        value,
        gas_limit: gas,
        gas_price,
        data,
        signature: Signature::new([0u8; 64]),
        tx_type: None,
        ..Default::default()
    };
    tx.determine_type();
    Ok(tx)
}

/// `debug_traceCall(callObject, blockTag, {tracer})`: simulate on the state
/// the tag names (the executed head, or a verified historical state), traced.
/// The simulation is `eth_call`'s (sender funded for the call, nothing
/// committed).
pub fn trace_call(
    storage: &Arc<StorageManager>,
    executor: &Executor,
    historical: &HistoricalStates,
    policy: StateTagPolicy,
    params: &[Value],
) -> Result<Value, jsonrpc_core::Error> {
    let obj = match params.first() {
        Some(Value::Object(o)) => o.clone(),
        _ => return Err(bad("call object is required")),
    };
    let tracer = parse_tracer(params.get(2))?;
    let read = resolve_state_read(params.get(1), storage, policy)?;
    let (state, store, height, timestamp) = match read {
        StateRead::At { hash, height } => {
            let snap = historical.state_at(storage, executor, (hash, height))?;
            let ts = storage
                .blocks
                .get_header(&hash)
                .map_err(internal)?
                .map(|h| h.timestamp)
                .unwrap_or_default();
            (snap, ReplayStore::code_only(storage.clone()), height, ts)
        }
        StateRead::Head => {
            let (_, h) = crate::canonical_logs::log_tip(storage)
                .map_err(internal)?
                .unwrap_or((Hash::default(), 0));
            let ts = storage
                .blocks
                .get_canonical_block_by_height(h)
                .ok()
                .flatten()
                .and_then(|b| storage.blocks.get_header(&b).ok().flatten())
                .map(|hd| hd.timestamp)
                .unwrap_or_default();
            (
                executor.state_snapshot(),
                ReplayStore::head(storage.clone()),
                h,
                ts,
            )
        }
    };
    let call_tracer = new_call_tracer();
    let replay = executor
        .replay_executor(state.clone(), Some(Arc::new(store)))
        .with_call_tracer(call_tracer.clone());
    let tx = call_tx(&obj, |a| replay.get_canonical_account(a).nonce)?;
    let blk = citrate_consensus::types::BlockBuilder::new()
        .base_fee_per_gas(1_000_000_000)
        .height(height)
        .timestamp(timestamp)
        .build_unhashed();
    let receipt = with_timeout(async {
        replay
            .simulate_transaction(&blk, &tx)
            .await
            .map_err(|e| server_error(format!("debug_traceCall failed: {e}")))
    })?;
    let (roots, touched) = call_tracer.lock().take();
    match tracer {
        Tracer::Call {
            only_top_call,
            with_log,
        } => Ok(frame_json(
            &top_frame(&tx, &receipt, roots),
            only_top_call,
            with_log,
        )),
        Tracer::Prestate => {
            let mut extra = vec![normalize_address(&tx.from).0];
            if let Some(to) = &tx.to {
                extra.push(normalize_address(to).0);
            }
            prestate_json(storage, &state, &touched, &extra)
        }
    }
}

/// `ots_getContractCreator(address)`: the transaction that created the code
/// `address` holds at the executed head, and the account that created it (an
/// EOA for a top-level deploy, the factory for an internal CREATE/CREATE2).
/// `null` for an account without code.
///
/// Data sources: the flat store at the durable tip (`CF_ACCOUNTS`: has code?),
/// the undo records (the creating block, `historical_state::creation_of`), and
/// a traced replay of that block (which transaction, which creator). Refused
/// when the creation is older than the undo window.
pub fn contract_creator(
    storage: &Arc<StorageManager>,
    executor: &Executor,
    historical: &HistoricalStates,
    address: [u8; 20],
) -> Result<Value, jsonrpc_core::Error> {
    let addr = Address(address);
    let has_code = storage
        .state
        .get_account(&addr)
        .map_err(internal)?
        .is_some_and(|a| a.code_hash != Hash::default());
    if !has_code {
        return Ok(Value::Null);
    }
    let (hash, _height) = match creation_of(storage, &addr)? {
        Creation::Genesis => {
            return Ok(json!({ "hash": Value::Null, "creator": Value::Null, "genesis": true }))
        }
        Creation::Block { hash, height } => (hash, height),
    };
    let block = storage
        .blocks
        .get_block(&hash)
        .map_err(internal)?
        .ok_or_else(|| server_error(format!("block {} is not stored", hx(&hash))))?;
    let last = block.transactions.len().saturating_sub(1);
    let replayed = with_timeout(replay_block(
        storage, executor, historical, &block, last, None,
    ))?;
    for t in replayed {
        let top = top_frame(&t.tx, &t.receipt, t.roots);
        let mut frames = Vec::new();
        top.walk(&mut frames);
        if let Some(f) = frames
            .iter()
            .find(|f| f.kind.is_create() && f.error.is_none() && f.to == Some(address))
        {
            return Ok(json!({
                "hash": hx(&t.tx.hash),
                "creator": addr_hex(&f.from),
                "blockHash": hx(&hash),
                "blockNumber": qty(block.header.height),
            }));
        }
    }
    Err(server_error(format!(
        "block {} gave {} its code, but no transaction of it created it (a system operation)",
        hx(&hash),
        addr_hex(&address)
    )))
}

/// Register `debug_traceTransaction`, `debug_traceCall`,
/// `debug_traceBlockByNumber`, `debug_traceBlockByHash` and
/// `ots_getContractCreator`. Read-only. Their method budget is charged by the
/// request middleware (`rpc_limits::heavy_method_cost`).
pub fn register_trace_methods(
    io_handler: &mut IoHandler,
    storage: Arc<StorageManager>,
    executor: Arc<Executor>,
    historical: Arc<HistoricalStates>,
    policy: StateTagPolicy,
) {
    let (st, ex, hs) = (storage.clone(), executor.clone(), historical.clone());
    io_handler.add_sync_method("debug_traceTransaction", move |params: Params| {
        rpc_request("debug_traceTransaction");
        let p: Vec<Value> = params
            .parse()
            .map_err(|e: jsonrpc_core::Error| bad(e.message))?;
        let tx = crate::explorer_rpc::parse_hash_param(p.first(), "transaction hash")?;
        let tracer = parse_tracer(p.get(1))?;
        trace_transaction(&st, &ex, &hs, &tx, tracer)
    });

    let (st, ex, hs) = (storage.clone(), executor.clone(), historical.clone());
    io_handler.add_sync_method("debug_traceCall", move |params: Params| {
        rpc_request("debug_traceCall");
        let p: Vec<Value> = params
            .parse()
            .map_err(|e: jsonrpc_core::Error| bad(e.message))?;
        trace_call(&st, &ex, &hs, policy, &p)
    });

    let (st, ex, hs) = (storage.clone(), executor.clone(), historical.clone());
    io_handler.add_sync_method("debug_traceBlockByNumber", move |params: Params| {
        rpc_request("debug_traceBlockByNumber");
        let p: Vec<Value> = params
            .parse()
            .map_err(|e: jsonrpc_core::Error| bad(e.message))?;
        let tracer = parse_tracer(p.get(1))?;
        let hash = block_by_number_param(&st, p.first())?;
        trace_block(&st, &ex, &hs, &hash, tracer)
    });

    let (st, ex, hs) = (storage.clone(), executor.clone(), historical.clone());
    io_handler.add_sync_method("debug_traceBlockByHash", move |params: Params| {
        rpc_request("debug_traceBlockByHash");
        let p: Vec<Value> = params
            .parse()
            .map_err(|e: jsonrpc_core::Error| bad(e.message))?;
        let tracer = parse_tracer(p.get(1))?;
        let hash = crate::explorer_rpc::parse_hash_param(p.first(), "block hash")?;
        trace_block(&st, &ex, &hs, &hash, tracer)
    });

    let (st, ex, hs) = (storage, executor, historical);
    io_handler.add_sync_method("ots_getContractCreator", move |params: Params| {
        rpc_request("ots_getContractCreator");
        let p: Vec<Value> = params
            .parse()
            .map_err(|e: jsonrpc_core::Error| bad(e.message))?;
        let a = parse_addr(p.first(), "address")?;
        contract_creator(&st, &ex, &hs, a)
    });
}
