// citrate/core/execution/src/trace.rs
//
// S3-7 (CNV-RPC): an observe-only REVM inspector for the RPC tracers
// (`debug_traceTransaction` / `debug_traceCall` with `callTracer` and
// `prestateTracer`, and the contract-creator lookup).
//
// WHAT IT CAN AND CANNOT CHANGE
//
// The inspector only records. Every hook returns `None` (no override of a
// call or create) or the outcome it was given, unchanged, and it never
// touches the interpreter, the journaled state or the database. REVM runs the
// same instructions with the same gas with or without it, so the state, the
// receipts and the state root of a traced execution are those of an untraced
// one. `core/execution/tests/trace_inspector_neutral.rs` checks that by
// executing the same transactions with and without a tracer and comparing the
// state roots and receipts.
//
// WHERE IT IS ATTACHED
//
// Only an executor built by `Executor::replay_executor(..).with_call_tracer(..)`
// carries a tracer. The node's consensus executor never does: its
// `call_tracer` is `None` and the REVM entry points take the untraced branch,
// which builds the EVM exactly as before this module existed.
//
// DATA SOURCE: the REVM interpreter of the replayed (or simulated)
// transaction, through the `revm::Inspector` hooks.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use revm::interpreter::{
    CallInputs, CallOutcome, CallScheme, CallValue, CreateInputs, CreateOutcome, InstructionResult,
    Interpreter,
};
use revm::primitives::{Address as RevmAddress, CreateScheme, Log as RevmLog, U256 as RevmU256};
use revm::{Database, EvmContext, Inspector};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The kind of a call frame, named as geth's `callTracer` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Call,
    CallCode,
    DelegateCall,
    StaticCall,
    Create,
    Create2,
    SelfDestruct,
}

impl FrameKind {
    /// The `type` string of geth's `callTracer`.
    pub fn as_str(&self) -> &'static str {
        match self {
            FrameKind::Call => "CALL",
            FrameKind::CallCode => "CALLCODE",
            FrameKind::DelegateCall => "DELEGATECALL",
            FrameKind::StaticCall => "STATICCALL",
            FrameKind::Create => "CREATE",
            FrameKind::Create2 => "CREATE2",
            FrameKind::SelfDestruct => "SELFDESTRUCT",
        }
    }

    /// CREATE or CREATE2.
    pub fn is_create(&self) -> bool {
        matches!(self, FrameKind::Create | FrameKind::Create2)
    }
}

/// One log emitted inside a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceLog {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// One call frame, with its subcalls in execution order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFrame {
    pub kind: FrameKind,
    pub from: [u8; 20],
    /// The callee, or the created contract (`None` for a create that failed).
    pub to: Option<[u8; 20]>,
    /// Big-endian value; `None` where geth omits it (DELEGATECALL, STATICCALL).
    pub value: Option<[u8; 32]>,
    pub gas: u64,
    pub gas_used: u64,
    /// Calldata, or init code for a create.
    pub input: Vec<u8>,
    /// Return data, or the deployed runtime code for a create.
    pub output: Vec<u8>,
    pub error: Option<String>,
    /// The `Error(string)` reason of a revert, when the output decodes as one.
    pub revert_reason: Option<String>,
    pub logs: Vec<TraceLog>,
    pub calls: Vec<CallFrame>,
}

impl CallFrame {
    /// Every frame of this tree, depth first, this one included.
    pub fn walk<'a>(&'a self, out: &mut Vec<&'a CallFrame>) {
        out.push(self);
        for c in &self.calls {
            c.walk(out);
        }
    }
}

/// What a traced execution touched, for `prestateTracer`: every account a
/// frame named (caller or callee), every account an account-reading opcode
/// named (BALANCE, EXTCODESIZE, EXTCODECOPY, EXTCODEHASH), and every storage
/// slot an SLOAD or SSTORE named, per contract.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Touched {
    pub accounts: BTreeSet<[u8; 20]>,
    pub slots: BTreeMap<[u8; 20], BTreeSet<[u8; 32]>>,
}

/// The recorder. Attach it with `Executor::with_call_tracer`.
#[derive(Debug, Default)]
pub struct CallTracer {
    /// Frames entered and not yet returned (innermost last).
    stack: Vec<CallFrame>,
    /// Completed top-level frames, one per REVM invocation, in order.
    roots: Vec<CallFrame>,
    touched: Touched,
}

/// Shared handle to a tracer (the executor holds one clone, the RPC another).
pub type CallTraceHandle = Arc<parking_lot::Mutex<CallTracer>>;

/// A fresh, empty tracer handle.
pub fn new_call_tracer() -> CallTraceHandle {
    Arc::new(parking_lot::Mutex::new(CallTracer::default()))
}

fn addr20(a: &RevmAddress) -> [u8; 20] {
    a.0 .0
}

fn word(v: &RevmU256) -> [u8; 32] {
    v.to_be_bytes::<32>()
}

/// The `Error(string)` reason of revert data (selector 0x08c379a0), if any.
pub fn decode_revert_reason(output: &[u8]) -> Option<String> {
    let rest = output.strip_prefix(&[0x08, 0xc3, 0x79, 0xa0])?;
    // offset (32) ‖ length (32) ‖ bytes
    let len_word = rest.get(32..64)?;
    let len_bytes = len_word.get(24..32)?;
    let len = usize::try_from(u64::from_be_bytes(len_bytes.try_into().ok()?)).ok()?;
    let end = 64usize.checked_add(len)?;
    let bytes = rest.get(64..end)?;
    String::from_utf8(bytes.to_vec()).ok()
}

fn error_of(result: InstructionResult, output: &[u8]) -> (Option<String>, Option<String>) {
    if result.is_ok() {
        return (None, None);
    }
    if result.is_revert() {
        return (
            Some("execution reverted".to_string()),
            decode_revert_reason(output),
        );
    }
    (Some(format!("{result:?}")), None)
}

impl CallTracer {
    /// The completed top-level frames, in order. A transaction executed
    /// through REVM leaves one; a native transfer or a Citrate AI operation
    /// leaves none (REVM did not run).
    pub fn roots(&self) -> &[CallFrame] {
        &self.roots
    }

    /// What the traced execution touched.
    pub fn touched(&self) -> &Touched {
        &self.touched
    }

    /// Forget what the current attempt recorded. The executor calls this
    /// before every attempt of a transaction (`Executor::execute_transaction`
    /// retries an MVCC-aborted attempt, re-running REVM), so a trace holds
    /// the frames of the attempt that committed only.
    pub fn begin_attempt(&mut self) {
        self.stack.clear();
        self.roots.clear();
        self.touched = Touched::default();
    }

    /// Take the recording and leave the tracer empty.
    pub fn take(&mut self) -> (Vec<CallFrame>, Touched) {
        self.stack.clear();
        (
            std::mem::take(&mut self.roots),
            std::mem::take(&mut self.touched),
        )
    }

    fn enter(&mut self, frame: CallFrame) {
        self.touched.accounts.insert(frame.from);
        if let Some(to) = frame.to {
            self.touched.accounts.insert(to);
        }
        self.stack.push(frame);
    }

    fn leave(&mut self, finish: impl FnOnce(&mut CallFrame)) {
        let Some(mut frame) = self.stack.pop() else {
            return;
        };
        finish(&mut frame);
        if let Some(to) = frame.to {
            self.touched.accounts.insert(to);
        }
        match self.stack.last_mut() {
            Some(parent) => parent.calls.push(frame),
            None => self.roots.push(frame),
        }
    }
}

impl<DB: Database> Inspector<DB> for CallTracer {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        let op = interp.current_opcode();
        match op {
            // SLOAD, SSTORE: the slot is on top of the stack.
            0x54 | 0x55 => {
                if let Ok(key) = interp.stack().peek(0) {
                    let contract = addr20(&interp.contract.target_address);
                    self.touched.accounts.insert(contract);
                    self.touched
                        .slots
                        .entry(contract)
                        .or_default()
                        .insert(word(&key));
                }
            }
            // BALANCE, EXTCODESIZE, EXTCODECOPY, EXTCODEHASH: the address is
            // on top of the stack.
            0x31 | 0x3b | 0x3c | 0x3f => {
                if let Ok(a) = interp.stack().peek(0) {
                    let w = word(&a);
                    let mut addr = [0u8; 20];
                    if let Some(tail) = w.get(12..32) {
                        addr.copy_from_slice(tail);
                        self.touched.accounts.insert(addr);
                    }
                }
            }
            _ => {}
        }
    }

    fn log(&mut self, _context: &mut EvmContext<DB>, log: &RevmLog) {
        if let Some(frame) = self.stack.last_mut() {
            frame.logs.push(TraceLog {
                address: addr20(&log.address),
                topics: log.data.topics().iter().map(|t| t.0).collect(),
                data: log.data.data.to_vec(),
            });
        }
    }

    fn call(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        let kind = match inputs.scheme {
            CallScheme::Call => FrameKind::Call,
            CallScheme::CallCode => FrameKind::CallCode,
            CallScheme::DelegateCall => FrameKind::DelegateCall,
            CallScheme::StaticCall => FrameKind::StaticCall,
        };
        let value = match (&inputs.value, kind) {
            (_, FrameKind::DelegateCall | FrameKind::StaticCall) => None,
            (CallValue::Transfer(v), _) | (CallValue::Apparent(v), _) => Some(word(v)),
        };
        self.enter(CallFrame {
            kind,
            from: addr20(&inputs.caller),
            to: Some(addr20(&inputs.target_address)),
            value,
            gas: inputs.gas_limit,
            gas_used: 0,
            input: inputs.input.to_vec(),
            output: Vec::new(),
            error: None,
            revert_reason: None,
            logs: Vec::new(),
            calls: Vec::new(),
        });
        None
    }

    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        let gas_used = inputs
            .gas_limit
            .saturating_sub(outcome.result.gas.remaining());
        let output = outcome.result.output.to_vec();
        let (error, reason) = error_of(outcome.result.result, &output);
        self.leave(|f| {
            f.gas_used = gas_used;
            f.output = output;
            f.error = error;
            f.revert_reason = reason;
        });
        outcome
    }

    fn create(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        let kind = match inputs.scheme {
            CreateScheme::Create => FrameKind::Create,
            CreateScheme::Create2 { .. } => FrameKind::Create2,
        };
        self.enter(CallFrame {
            kind,
            from: addr20(&inputs.caller),
            to: None,
            value: Some(word(&inputs.value)),
            gas: inputs.gas_limit,
            gas_used: 0,
            input: inputs.init_code.to_vec(),
            output: Vec::new(),
            error: None,
            revert_reason: None,
            logs: Vec::new(),
            calls: Vec::new(),
        });
        None
    }

    fn create_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        let gas_used = inputs
            .gas_limit
            .saturating_sub(outcome.result.gas.remaining());
        let output = outcome.result.output.to_vec();
        let (error, reason) = error_of(outcome.result.result, &output);
        let created = if error.is_none() {
            outcome.address.as_ref().map(addr20)
        } else {
            None
        };
        self.leave(|f| {
            f.to = created;
            f.gas_used = gas_used;
            f.output = output;
            f.error = error;
            f.revert_reason = reason;
        });
        outcome
    }

    fn selfdestruct(&mut self, contract: RevmAddress, target: RevmAddress, value: RevmU256) {
        let frame = CallFrame {
            kind: FrameKind::SelfDestruct,
            from: addr20(&contract),
            to: Some(addr20(&target)),
            value: Some(word(&value)),
            gas: 0,
            gas_used: 0,
            input: Vec::new(),
            output: Vec::new(),
            error: None,
            revert_reason: None,
            logs: Vec::new(),
            calls: Vec::new(),
        };
        self.touched.accounts.insert(frame.from);
        if let Some(to) = frame.to {
            self.touched.accounts.insert(to);
        }
        match self.stack.last_mut() {
            Some(parent) => parent.calls.push(frame),
            None => self.roots.push(frame),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_an_error_string_revert() {
        // Error("no")
        let mut data = vec![0x08, 0xc3, 0x79, 0xa0];
        let mut off = [0u8; 32];
        off[31] = 0x20;
        data.extend_from_slice(&off);
        let mut len = [0u8; 32];
        len[31] = 2;
        data.extend_from_slice(&len);
        let mut s = [0u8; 32];
        s[0] = b'n';
        s[1] = b'o';
        data.extend_from_slice(&s);
        assert_eq!(decode_revert_reason(&data).as_deref(), Some("no"));
        assert_eq!(decode_revert_reason(&[0x08, 0xc3]), None);
        assert_eq!(decode_revert_reason(&[]), None);
    }
}
