// citrate/core/execution/tests/code_storage_conformance.rs
//
// Tripwire: Citrate's code storage against REVM's reference database.
//
// The same transactions run twice under one EVM configuration (CANCUN, zero
// gas price): once over `revm::InMemoryDB` (REVM's reference
// `DatabaseCommit`, the storage semantics anvil and every revm-based client
// share) and once over Citrate's `StateDBAdapter` + `StateDB`. After each
// transaction, every account the reference knows must have the same code bytes
// and the same code hash in Citrate's state.
//
// Any future change to how `commit` derives the bytes it stores (another
// Bytecode accessor, a new analysis mode, a REVM upgrade that changes the
// padding) shows up here as a byte-level diff against the reference.
//
// Negative control: the same comparison with the legacy (padded) rule MUST
// report a mismatch, which proves the comparator sees the difference it
// guards against.

use citrate_execution::revm_adapter::StateDBAdapter;
use citrate_execution::types::Address;
use citrate_execution::StateDB;
use revm::primitives::{
    keccak256, AccountInfo, Address as RAddr, Bytecode, Bytes, ExecutionResult, SpecId, TransactTo,
    KECCAK_EMPTY, U256 as RU256,
};
use revm::{Database, DatabaseCommit, Evm, InMemoryDB};
use std::sync::Arc;

const CALLER: [u8; 20] = [0xCA; 20];
const FACTORY: [u8; 20] = [0xFA; 20];

/// Factory runtime. Calldata = `mode || init code`; mode 2 = CREATE2 (salt 0),
/// mode 3 = CREATE2 then CALL the child, otherwise CREATE. Returns the address.
fn factory_runtime() -> Vec<u8> {
    let mut c = vec![
        0x36, 0x60, 0x01, 0x90, 0x03, // n = calldatasize - 1
        0x80, 0x60, 0x01, 0x5f, 0x37, // calldatacopy(0, 1, n)
        0x5f, 0x35, 0x60, 0xf8, 0x1c, // mode
        0x80, 0x60, 0x01, 0x10, // mode > 1 ? (1 < mode)
        0x60, 0x00, 0x57, // JUMPI create2       (patched @20)
        0x50, 0x5f, 0x5f, 0xf0, // pop mode; create(0, 0, n)
        0x60, 0x00, 0x56, // JUMP ret            (patched @27)
    ];
    let create2 = c.len();
    // [mode, n] -> swap -> [n, mode]; create2(0, 0, n, 0) -> [addr, mode]
    c.extend_from_slice(&[0x5b, 0x90, 0x5f, 0x90, 0x5f, 0x5f, 0xf5]);
    // if mode == 3: call(gas, addr, 0, 0, 0, 0, 0), keep addr
    c.extend_from_slice(&[0x90, 0x60, 0x03, 0x14]); // [mode==3, addr]
    let jcall = c.len() + 1;
    c.extend_from_slice(&[0x60, 0x00, 0x57]); // JUMPI call (patched)
    let jret2 = c.len() + 1;
    c.extend_from_slice(&[0x60, 0x00, 0x56]); // JUMP ret (patched)
    let call = c.len();
    c.extend_from_slice(&[
        0x5b, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x85, 0x5a, 0xf1, 0x50, // call, pop success
    ]);
    let ret = c.len();
    c.extend_from_slice(&[0x5b, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
    c[20] = create2 as u8;
    c[27] = ret as u8;
    c[jcall] = call as u8;
    c[jret2] = ret as u8;
    c
}

fn init_for(runtime: &[u8]) -> Vec<u8> {
    let len = u8::try_from(runtime.len()).expect("short runtime");
    let mut c = vec![0x60, len, 0x80, 0x60, 0x09, 0x5f, 0x39, 0x5f, 0xf3];
    c.extend_from_slice(runtime);
    c
}

fn mode(m: u8, init: &[u8]) -> Vec<u8> {
    let mut d = vec![m];
    d.extend_from_slice(init);
    d
}

/// Runtimes under test, each created through the factory.
fn cases() -> Vec<(&'static str, u8, Vec<u8>)> {
    let ret42 = vec![0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];
    let mut truncated_push = ret42.clone();
    truncated_push.extend_from_slice(&[0x5b, 0x7f, 0xaa]);
    // Code that legitimately ends in 33 zero bytes must keep them: the exact
    // rule stores what the init code returned, it does not trim.
    let mut zero_tail = ret42.clone();
    zero_tail.extend_from_slice(&[0u8; 33]);
    vec![
        ("CREATE", 1, ret42.clone()),
        ("CREATE2", 2, truncated_push.clone()),
        ("CREATE with a zero tail", 1, zero_tail.clone()),
        ("CREATE2 with a zero tail", 2, zero_tail),
        ("CREATE single STOP", 1, vec![0x00]),
        ("CREATE2 then call", 3, ret42),
    ]
}

fn run<DB>(db: DB, data: Vec<u8>) -> Vec<u8>
where
    DB: Database + DatabaseCommit,
    DB::Error: std::fmt::Debug,
{
    let mut evm = Evm::builder()
        .with_db(db)
        .with_spec_id(SpecId::CANCUN)
        .modify_cfg_env(|c| c.chain_id = 40204)
        .modify_tx_env(|tx| {
            tx.caller = RAddr::from(CALLER);
            tx.transact_to = TransactTo::Call(RAddr::from(FACTORY));
            tx.data = Bytes::from(data);
            tx.gas_limit = 5_000_000;
            tx.gas_price = RU256::ZERO;
            tx.nonce = None;
        })
        .build();
    match evm.transact_commit().expect("transaction runs") {
        ExecutionResult::Success { output, .. } => output.into_data().to_vec(),
        other => panic!("factory call failed: {other:?}"),
    }
}

fn reference() -> InMemoryDB {
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        RAddr::from(CALLER),
        AccountInfo {
            balance: RU256::from(10u64).pow(RU256::from(24u64)),
            ..Default::default()
        },
    );
    let code = Bytecode::new_raw(Bytes::from(factory_runtime()));
    db.insert_account_info(
        RAddr::from(FACTORY),
        AccountInfo {
            code_hash: code.hash_slow(),
            code: Some(code),
            nonce: 1,
            ..Default::default()
        },
    );
    db
}

fn citrate() -> Arc<StateDB> {
    let s = Arc::new(StateDB::new());
    s.accounts.set_balance(
        Address(CALLER),
        primitive_types::U256::from(10u64).pow(24u64.into()),
    );
    s.set_code(Address(FACTORY), factory_runtime());
    s.accounts.set_nonce(Address(FACTORY), 1);
    s
}

/// (code bytes, code hash) of `addr`, with "no code" as (empty, KECCAK_EMPTY).
fn ref_code(db: &InMemoryDB, addr: RAddr) -> (Vec<u8>, [u8; 32]) {
    match db.accounts.get(&addr) {
        Some(acc) if acc.info.code_hash != KECCAK_EMPTY => {
            let code = db
                .contracts
                .get(&acc.info.code_hash)
                .expect("reference code by hash");
            (code.original_bytes().to_vec(), acc.info.code_hash.0)
        }
        _ => (Vec::new(), KECCAK_EMPTY.0),
    }
}

fn citrate_code(s: &StateDB, addr: RAddr) -> (Vec<u8>, [u8; 32]) {
    let h = s.accounts.get_code_hash(&Address(addr.0 .0));
    if h.as_bytes().iter().all(|b| *b == 0) {
        return (Vec::new(), KECCAK_EMPTY.0);
    }
    let code = s.get_code(&h).expect("citrate code by hash");
    (code, *h.as_bytes())
}

/// A case whose stored code differs: (case, reference length, Citrate length,
/// description).
type Mismatch = (&'static str, usize, usize, String);

/// Every mismatch between the reference and Citrate, after running all cases.
fn mismatches(exact: bool) -> Vec<Mismatch> {
    let mut rdb = reference();
    let sdb = citrate();
    let mut out = Vec::new();
    for (what, m, runtime) in cases() {
        let data = mode(m, &init_for(&runtime));
        let r_ret = run(&mut rdb, data.clone());
        let mut adapter = StateDBAdapter::new(sdb.clone()).with_exact_create_code(exact);
        let c_ret = run(&mut adapter, data);
        assert_eq!(r_ret, c_ret, "{what}: both create at the same address");
        let mut a = [0u8; 20];
        a.copy_from_slice(&r_ret[12..32]);
        let child = RAddr::from(a);
        let (r_code, r_hash) = ref_code(&rdb, child);
        let (c_code, c_hash) = citrate_code(&sdb, child);
        // The reference's code hash is keccak of the bytes it stores.
        assert_eq!(
            r_hash,
            if r_code.is_empty() {
                KECCAK_EMPTY.0
            } else {
                keccak256(&r_code).0
            }
        );
        if (r_code.as_slice(), r_hash) != (c_code.as_slice(), c_hash) {
            let d = format!(
                "{what}: reference {} bytes 0x{}, citrate {} bytes 0x{}",
                r_code.len(),
                hex::encode(&r_hash[..4]),
                c_code.len(),
                hex::encode(&c_hash[..4]),
            );
            out.push((what, r_code.len(), c_code.len(), d));
        }
    }
    out
}

fn describe(d: &[Mismatch]) -> String {
    d.iter()
        .map(|m| m.3.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn created_code_matches_the_revm_reference() {
    let diffs = mismatches(true);
    assert!(
        diffs.is_empty(),
        "code storage diverges from revm:\n{}",
        describe(&diffs)
    );
}

#[test]
fn negative_control_the_padded_rule_is_detected() {
    let diffs = mismatches(false);
    // Every case differs, and by exactly the interpreter padding.
    assert_eq!(
        diffs.len(),
        cases().len(),
        "the comparator must flag the padded rule on every created contract:\n{}",
        describe(&diffs)
    );
    for (what, r_len, c_len, _) in &diffs {
        assert_eq!(*c_len, r_len + 33, "{what}: padded by 33 bytes");
    }
}
